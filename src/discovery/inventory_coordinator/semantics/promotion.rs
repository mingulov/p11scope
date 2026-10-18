//! SPDX-License-Identifier: GPL-3.0-or-later
//! One real admission validator over ordinary or privately staged storage.

use super::*;
use crate::discovery::caller_registry::CallerAdapter;

#[path = "promotion/capacity.rs"]
mod capacity;

/// This is only the storage used by the existing consume algorithm. Neither
/// implementation can substitute a different owner/scope/provider validator.
trait AdmissionStorage {
    fn binding(&self, caller: CallerId) -> Option<&SemanticCallerBinding>;
    fn binding_mut(&mut self, caller: CallerId) -> Option<&mut SemanticCallerBinding>;
    fn binding_count(&self) -> usize;
    fn binding_limit(&self) -> usize;
    fn provider_count(&self) -> usize;
    fn provider_limit(&self) -> usize;
    fn history(&self, caller: CallerId) -> Option<&SemanticAdmissionHistory>;
    fn history_mut(&mut self, caller: CallerId) -> Option<&mut SemanticAdmissionHistory>;
    fn history_count(&self) -> usize;
    fn insert_history(&mut self, caller: CallerId, history: SemanticAdmissionHistory);
    fn insert_binding(
        &mut self,
        binding: SemanticCallerBinding,
    ) -> Result<(), SemanticBindingRefusal>;
    fn take_successor(&mut self, caller: CallerId) -> Option<PublishedSemanticSuccessor>;
    fn insert_refused_successor(&mut self, caller: CallerId, successor: PublishedSemanticSuccessor);
}

impl AdmissionStorage for SemanticBindingSet {
    fn binding(&self, caller: CallerId) -> Option<&SemanticCallerBinding> {
        self.get(caller)
    }
    fn binding_mut(&mut self, caller: CallerId) -> Option<&mut SemanticCallerBinding> {
        self.index
            .get(&caller)
            .copied()
            .map(|at| &mut self.bindings[at])
    }
    fn binding_count(&self) -> usize {
        self.bindings.len()
    }
    fn binding_limit(&self) -> usize {
        self.limit
    }
    fn provider_count(&self) -> usize {
        SemanticBindingSet::provider_count(self)
    }
    fn provider_limit(&self) -> usize {
        self.provider_limit
    }
    fn history(&self, caller: CallerId) -> Option<&SemanticAdmissionHistory> {
        self.admission_images.get(&caller)
    }
    fn history_mut(&mut self, caller: CallerId) -> Option<&mut SemanticAdmissionHistory> {
        self.admission_images.get_mut(&caller)
    }
    fn history_count(&self) -> usize {
        self.admission_images.len()
    }
    fn insert_history(&mut self, caller: CallerId, history: SemanticAdmissionHistory) {
        self.admission_images.insert(caller, history);
    }
    fn insert_binding(
        &mut self,
        binding: SemanticCallerBinding,
    ) -> Result<(), SemanticBindingRefusal> {
        self.insert(binding)
    }
    fn take_successor(&mut self, caller: CallerId) -> Option<PublishedSemanticSuccessor> {
        self.successors.remove(&caller)
    }
    fn insert_refused_successor(
        &mut self,
        caller: CallerId,
        successor: PublishedSemanticSuccessor,
    ) {
        self.refused_successors.insert(caller, successor);
    }
}

/// Fixed storage for one privately consumed caller. It never aliases the live
/// binding/history maps and cannot retain another caller through this accessor.
struct SingleCallerStorage {
    caller: CallerId,
    binding: Option<SemanticCallerBinding>,
    history: Option<SemanticAdmissionHistory>,
    successor: Option<PublishedSemanticSuccessor>,
    refused_successor: Option<PublishedSemanticSuccessor>,
}

impl SingleCallerStorage {
    fn new(caller: CallerId) -> Self {
        Self {
            caller,
            binding: None,
            history: None,
            successor: None,
            refused_successor: None,
        }
    }
    fn check(&self, caller: CallerId) {
        assert_eq!(self.caller, caller);
    }
}

impl AdmissionStorage for SingleCallerStorage {
    fn binding(&self, caller: CallerId) -> Option<&SemanticCallerBinding> {
        self.check(caller);
        self.binding.as_ref()
    }
    fn binding_mut(&mut self, caller: CallerId) -> Option<&mut SemanticCallerBinding> {
        self.check(caller);
        self.binding.as_mut()
    }
    fn binding_count(&self) -> usize {
        usize::from(self.binding.is_some())
    }
    fn binding_limit(&self) -> usize {
        1
    }
    fn provider_count(&self) -> usize {
        self.binding
            .as_ref()
            .map_or(0, |binding| binding.providers.len)
    }
    fn provider_limit(&self) -> usize {
        1
    }
    fn history(&self, caller: CallerId) -> Option<&SemanticAdmissionHistory> {
        self.check(caller);
        self.history.as_ref()
    }
    fn history_mut(&mut self, caller: CallerId) -> Option<&mut SemanticAdmissionHistory> {
        self.check(caller);
        self.history.as_mut()
    }
    fn history_count(&self) -> usize {
        usize::from(self.history.is_some())
    }
    fn insert_history(&mut self, caller: CallerId, history: SemanticAdmissionHistory) {
        self.check(caller);
        assert!(self.history.is_none());
        self.history = Some(history);
    }
    fn insert_binding(
        &mut self,
        binding: SemanticCallerBinding,
    ) -> Result<(), SemanticBindingRefusal> {
        self.check(binding.caller);
        if self.binding.is_some() {
            return Err(SemanticBindingRefusal::Capacity);
        }
        self.binding = Some(binding);
        Ok(())
    }
    fn take_successor(&mut self, caller: CallerId) -> Option<PublishedSemanticSuccessor> {
        self.check(caller);
        self.successor.take()
    }
    fn insert_refused_successor(
        &mut self,
        caller: CallerId,
        successor: PublishedSemanticSuccessor,
    ) {
        self.check(caller);
        assert!(self.refused_successor.is_none());
        self.refused_successor = Some(successor);
    }
}

/// Resource reservation only: it grants no admission or activation authority.
/// Acquired before owner preparation so a provider-copy refusal still has paid
/// local storage for the real consumer's negative-first history.
pub(crate) struct PromotionAdmissionReservation {
    caller: CallerId,
    domain: NativeDomainId,
    pin: Arc<PidPin>,
    path_bytes: usize,
    storage: ResourceLease,
}

impl PromotionAdmissionReservation {
    pub(super) fn reserve(
        registry: &CallerRegistry,
        caller: CallerId,
        domain: NativeDomainId,
        pin: Arc<PidPin>,
        path_bytes: usize,
    ) -> Result<Self, SemanticBindingRefusal> {
        // Both candidate and cloned history can coexist through validation;
        // include their inline owner storage and both executable-path copies.
        let charge = std::mem::size_of::<StagedPromotionAdmission>()
            .checked_add(std::mem::size_of::<SemanticAdmissionCandidate>())
            .and_then(|bytes| {
                bytes.checked_add(
                    path_bytes
                        .checked_add(OWNED_ALLOCATION_PADDING)?
                        .checked_mul(2)?,
                )
            })
            .ok_or(SemanticBindingRefusal::Capacity)?;
        let storage = registry
            .reserve_semantic_storage(charge)
            .map_err(|_| SemanticBindingRefusal::Capacity)?;
        Ok(Self {
            caller,
            domain,
            pin,
            path_bytes,
            storage,
        })
    }

    pub(super) fn matches(&self, candidate: &SemanticAdmissionCandidate) -> bool {
        self.caller == candidate.caller
            && self.domain == candidate.domain
            && Arc::ptr_eq(&self.pin, &candidate.pin)
            && candidate
                .generation
                .exe
                .as_ref()
                .and_then(|exe| exe.path.as_ref())
                .map_or(0, String::len)
                <= self.path_bytes
    }
}

/// The original genuine receipt, accepted history, binding and refusal remain
/// private. Finite result inspection does not export H0/registration authority.
/// Dropping this value disposes only local custody; native cleanup is separate.
pub(crate) struct StagedPromotionAdmission {
    state: SingleCallerStorage,
    receipt: crate::semantic_capture::CurrentPartitionReceipt,
    result: Result<(), SemanticBindingRefusal>,
    reservation: PromotionAdmissionReservation,
}

impl StagedPromotionAdmission {
    pub(super) fn consume<Source: ProcessSource>(
        adapter: &CallerAdapter<Source>,
        registry: &CallerRegistry,
        reservation: PromotionAdmissionReservation,
        candidate: SemanticAdmissionCandidate,
        prepared: PreparedSemanticAdmission,
        permit: Option<crate::inspect_system::inventory_cgroup::CgroupAdmissionPermit<'_>>,
    ) -> Self {
        let mut state = SingleCallerStorage::new(candidate.caller);
        let (receipt, provider) = prepared.into_parts();
        let result = if reservation.matches(&candidate) {
            consume_in_storage(
                adapter, registry, &mut state, candidate, &receipt, provider, permit,
            )
        } else {
            Err(SemanticBindingRefusal::Capacity)
        };
        Self {
            state,
            receipt,
            result,
            reservation,
        }
    }

    pub(crate) fn result(&self) -> Result<(), SemanticBindingRefusal> {
        self.result
    }
}

impl std::fmt::Debug for StagedPromotionAdmission {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("StagedPromotionAdmission(<retained>)")
    }
}

/// Empty, paid destination storage. This value grants no semantic authority and
/// exposes no way to install a stage without the later genuine activation edge.
/// The eventual driver retains this one-slot capacity for the capture lifetime;
/// completed-A proof is required before reusing it for B. Buffers drop before
/// their charge, including on a failed partial reservation.
pub(crate) struct PromotionInstallCapacity {
    bindings: Vec<SemanticCallerBinding>,
    index: HashMap<CallerId, usize>,
    admission_images: HashMap<CallerId, SemanticAdmissionHistory>,
    storage: ResourceLease,
}

impl PromotionInstallCapacity {
    fn requested_bytes() -> Option<usize> {
        std::mem::size_of::<SemanticCallerBinding>()
            .checked_add(capacity::one_map_request::<CallerId, usize>()?)?
            .checked_add(capacity::one_map_request::<
                CallerId,
                SemanticAdmissionHistory,
            >()?)
    }

    pub(super) fn reserve(registry: &CallerRegistry) -> Result<Self, SemanticBindingRefusal> {
        let charge = Self::requested_bytes()
            .and_then(|bytes| bytes.checked_add(3 * OWNED_ALLOCATION_PADDING))
            .and_then(|bytes| bytes.checked_add(std::mem::size_of::<Self>()))
            .ok_or(SemanticBindingRefusal::Capacity)?;
        // Reserve the complete request before the FIRST allocation. A local
        // lease remains live while any partially constructed buffer is freed.
        let storage = registry
            .reserve_semantic_storage(charge)
            .map_err(|_| SemanticBindingRefusal::Capacity)?;
        let mut bindings = Vec::new();
        let mut index = HashMap::new();
        let mut admission_images = HashMap::new();
        bindings
            .try_reserve_exact(1)
            .map_err(|_| SemanticBindingRefusal::Capacity)?;
        index
            .try_reserve(1)
            .map_err(|_| SemanticBindingRefusal::Capacity)?;
        admission_images
            .try_reserve(1)
            .map_err(|_| SemanticBindingRefusal::Capacity)?;
        assert_eq!(bindings.capacity(), 1, "pinned initial Vec layout changed");
        assert_eq!(index.capacity(), 3, "pinned initial index layout changed");
        assert_eq!(
            admission_images.capacity(),
            3,
            "pinned initial history layout changed"
        );
        Ok(Self {
            bindings,
            index,
            admission_images,
            storage,
        })
    }
}

impl std::fmt::Debug for PromotionInstallCapacity {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("PromotionInstallCapacity(<reserved>)")
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn promotion_capacity_actual_admission_types_reserve_before_allocating() {
        let registry = CallerRegistry::new(RegistryLimits::default_limits());
        let before = registry.semantic_resource_snapshot().charged_bytes;
        let (capacity, allocations, bytes) = crate::test_alloc::count_allocs_during(|| {
            PromotionInstallCapacity::reserve(&registry).unwrap()
        });
        assert_eq!(allocations, 3);
        assert_eq!(bytes, PromotionInstallCapacity::requested_bytes().unwrap());
        assert_eq!(capacity.bindings.capacity(), 1);
        assert_eq!(capacity.index.capacity(), 3);
        assert_eq!(capacity.admission_images.capacity(), 3);
        let charged = registry.semantic_resource_snapshot().charged_bytes;
        assert_eq!(
            charged,
            before
                + bytes
                + 3 * OWNED_ALLOCATION_PADDING
                + std::mem::size_of::<PromotionInstallCapacity>()
        );
        let (second, allocations, second_bytes) = crate::test_alloc::count_allocs_during(|| {
            PromotionInstallCapacity::reserve(&registry).unwrap()
        });
        assert_eq!((allocations, second_bytes), (3, bytes));
        assert_eq!(
            registry.semantic_resource_snapshot().charged_bytes,
            before + 2 * (charged - before),
            "old and new physical storage retain independent charges"
        );
        drop(second);
        assert_eq!(registry.semantic_resource_snapshot().charged_bytes, charged);
        drop(capacity);
        assert_eq!(registry.semantic_resource_snapshot().charged_bytes, before);
    }

    #[test]
    fn promotion_capacity_budget_refuses_before_any_destination_allocation() {
        let mut registry = CallerRegistry::new(RegistryLimits::default_limits());
        let baseline = registry.semantic_resource_snapshot();
        registry.reference_semantic_resource_limit(baseline.charged_bytes);
        let (result, allocations, bytes) =
            crate::test_alloc::count_allocs_during(|| PromotionInstallCapacity::reserve(&registry));
        assert!(matches!(result, Err(SemanticBindingRefusal::Capacity)));
        assert_eq!((allocations, bytes), (0, 0));
        let after = registry.semantic_resource_snapshot();
        assert_eq!(after.charged_bytes, baseline.charged_bytes);
        assert_eq!(after.peak_charged_bytes, baseline.peak_charged_bytes);
        assert_eq!(after.refused, baseline.refused + 1);
    }
}

pub(super) fn consume<Source: ProcessSource>(
    adapter: &CallerAdapter<Source>,
    registry: &CallerRegistry,
    storage: &mut SemanticBindingSet,
    candidate: SemanticAdmissionCandidate,
    receipt: &crate::semantic_capture::CurrentPartitionReceipt,
    provider: Result<SemanticProviderTarget, SemanticRefusal>,
    permit: Option<crate::inspect_system::inventory_cgroup::CgroupAdmissionPermit<'_>>,
) -> Result<(), SemanticBindingRefusal> {
    consume_in_storage(
        adapter, registry, storage, candidate, receipt, provider, permit,
    )
}

fn consume_in_storage<Source: ProcessSource>(
    adapter: &CallerAdapter<Source>,
    registry: &CallerRegistry,
    storage: &mut impl AdmissionStorage,
    candidate: SemanticAdmissionCandidate,
    receipt: &crate::semantic_capture::CurrentPartitionReceipt,
    provider: Result<SemanticProviderTarget, SemanticRefusal>,
    permit: Option<crate::inspect_system::inventory_cgroup::CgroupAdmissionPermit<'_>>,
) -> Result<(), SemanticBindingRefusal> {
    let caller = candidate.caller;
    // The accepted H0 scan consumes the published handoff even when the
    // provider or final scope proof refuses positive admission below.
    let bridge = storage.take_successor(caller);
    let result = (|| {
        use SemanticBindingRefusal as Refusal;
        if candidate.from_successor != bridge.is_some() {
            return Err(Refusal::ImageUnproven(UnboundReason::ExecAmbiguous));
        }
        if let Some(bridge) = &bridge
            && (!bridge.matches(candidate.incarnation, &candidate.generation)
                || !bridge.custody.is_exact()
                || bridge.custody.domain != candidate.domain
                || !Arc::ptr_eq(&bridge.custody.pin, &candidate.pin))
        {
            return Err(Refusal::ImageUnproven(UnboundReason::ExecAmbiguous));
        }
        if receipt.original_pin().pid() != candidate.pin.pid()
            || receipt.original_pin().start_time() != candidate.generation.start_time
        {
            return Err(Refusal::NoLiveCaller);
        }
        if receipt.domain() != candidate.domain
            || !Arc::ptr_eq(&candidate.pin, receipt.original_pin())
            || candidate
                .expected_pin
                .as_ref()
                .is_some_and(|expected| !Arc::ptr_eq(expected, receipt.original_pin()))
        {
            return Err(Refusal::ImageUnproven(UnboundReason::ExecAmbiguous));
        }
        let observed = (receipt.domain(), receipt.image());
        if let Some(previous) = storage.history(caller) {
            if (previous.domain, previous.image) != observed
                || previous.incarnation != candidate.incarnation
                || previous.generation != candidate.generation
                || !Arc::ptr_eq(&previous.pin, receipt.original_pin())
            {
                return Err(Refusal::ImageUnproven(UnboundReason::ExecAmbiguous));
            }
        } else {
            if storage.history_count() >= storage.binding_limit() {
                return Err(Refusal::Capacity);
            }
            storage.insert_history(
                caller,
                SemanticAdmissionHistory {
                    domain: observed.0,
                    image: observed.1,
                    incarnation: candidate.incarnation,
                    generation: candidate.generation.clone(),
                    pin: receipt.original_pin().clone(),
                    initial_scope_cut: false,
                    pending_gap: None,
                },
            );
        }
        let guarded = match (candidate.scope, permit) {
            (AdmissionScope::Cgroup, Some(permit)) => {
                candidate.pin.pid() == permit.pid()
                    && candidate.generation == *permit.generation()
                    && permit.check()
                    && candidate.pin.still_the_same()
                    && receipt.original_pin().still_the_same()
                    && permit.finish_check()
            }
            (AdmissionScope::Pid(pid), None) if pid == candidate.pin.pid() => {
                candidate.pin.still_the_same() && receipt.original_pin().still_the_same()
            }
            (AdmissionScope::System, None) => {
                candidate.pin.still_the_same() && receipt.original_pin().still_the_same()
            }
            _ => false,
        };
        if !guarded {
            // H0 already accepted this exact original-Arc association,
            // even though no coordinator binding exists yet. A genuine
            // final-scope refusal must fence that association before old
            // unread returns can meet a later fresh coverage receipt.
            if candidate.scope == AdmissionScope::Cgroup && storage.binding(caller).is_none() {
                let history = storage
                    .history_mut(caller)
                    .expect("the accepted owner scan was recorded above");
                if !history.initial_scope_cut {
                    history.pending_gap = Some(PhysicalSemanticGap::adjudicated(
                        receipt.domain(),
                        receipt.image(),
                        receipt.original_pin().clone(),
                    ));
                    history.initial_scope_cut = true;
                }
            }
            return Err(Refusal::NoLiveCaller);
        }
        let record = adapter.record(caller).ok_or(Refusal::NoLiveCaller)?;
        if record.retired
            || record.incarnation != candidate.incarnation
            || record.pid != candidate.pin.pid()
            || record.start_time != candidate.generation.start_time
            || record.exe != candidate.generation.exe
            || adapter.live_id(record.pid) != Some(caller)
            || receipt.original_pin().pid() != candidate.pin.pid()
            || receipt.original_pin().start_time() != candidate.generation.start_time
        {
            return Err(Refusal::NoLiveCaller);
        }
        if let Some(existing) = storage.binding_mut(caller) {
            if existing.domain != receipt.domain() {
                return Err(Refusal::DomainConflict);
            }
            if existing.image != receipt.image()
                || !Arc::ptr_eq(&existing.pin, receipt.original_pin())
            {
                return Err(Refusal::ImageUnproven(UnboundReason::ExecAmbiguous));
            }
            if candidate.scope == AdmissionScope::Cgroup {
                // Re-arm negative loss tracking under this exact binding's
                // fresh scope proof. Provider refusal below must keep its
                // positive scope eligibility suspended.
                existing.suspension_cut = false;
            }
        }
        // Proven current membership ends the previous scope-loss episode
        // independently of provider permission. An expired owner receipt
        // still grants no positive authority, but a later genuine leave
        // must mint its own cut instead of reusing the old episode latch.
        if candidate.scope == AdmissionScope::Cgroup {
            storage
                .history_mut(caller)
                .expect("the scope proof retained its accepted owner scan")
                .initial_scope_cut = false;
        }
        let provider = provider.map_err(Refusal::OwnerRefused)?;
        let exact_reproof = storage.binding(caller).is_some_and(|binding| {
            binding
                .providers
                .iter()
                .any(|old| old.same_association(&provider))
        });
        if !exact_reproof && storage.provider_count() >= storage.provider_limit() {
            return Err(Refusal::Capacity);
        }
        if let Some(existing) = storage.binding_mut(caller) {
            existing.providers.insert(provider, registry)?;
            existing.scope_current = true;
            existing.suspension_cut = false;
            return Ok(());
        }
        if storage.binding_count() >= storage.binding_limit() {
            return Err(Refusal::Capacity);
        }
        let mut providers = SemanticProviderAssociations::new();
        providers.insert(provider, registry)?;
        storage.insert_binding(SemanticCallerBinding {
            caller,
            domain: receipt.domain(),
            image: receipt.image(),
            pin: receipt.original_pin().clone(),
            scope_current: true,
            suspension_cut: false,
            providers,
            #[cfg(test)]
            reference_module: None,
        })
    })();
    if let Err(reason) = result {
        if let Some(mut bridge) = bridge
            && storage.history(caller).is_none()
        {
            bridge.custody.refuse(reason);
            storage.insert_refused_successor(caller, bridge);
        }
    }
    result
}
