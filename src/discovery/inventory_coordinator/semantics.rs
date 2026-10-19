//! SPDX-License-Identifier: GPL-3.0-or-later
//! Sole subset minter over the coordinator's retained, accepted sources.

use super::*;

#[path = "semantics/finalizer.rs"]
mod finalizer;
#[path = "semantics/promotion.rs"]
mod promotion;
#[cfg(test)]
use crate::discovery::caller_registry::OsProcessSource;
use crate::discovery::caller_registry::instance_input::{
    AdmittedInstanceCall, CallEvidence, CallStanding, ConversionRefusal, InstanceReason,
    admit_call_from_evidence, admit_registration_from_coverage, finalize_invalidation,
    tail_loss_from_negative,
};
use crate::discovery::caller_registry::{CallerLifecycle, ModuleLifecycle};
use crate::discovery::instances::{MAX_INSTANCES, MAX_PENDING};
#[cfg(test)]
use crate::discovery::native_binding::CallerLookup;
use crate::inventory_promotion::lifecycle::{SelectedActivationProof, SessionNativeCompletion};
use crate::inventory_promotion::{PromotionPair, PromotionRefusal};
use crate::inventory_semantics::selected::ProvisionalSelectedLane;
use crate::inventory_semantics::{AttestedSemanticLane, LaneNegative, SemanticRefusal};
use crate::inventory_semantics::{PreparedSemanticAdmission, SemanticProviderTarget};
use crate::process::PidPin;
use crate::semantic_capture::{
    CurrentReceiptRefusal, Endpoint, InvalidationScope, PhysicalSemanticGap, TickOutcome,
};
use crate::semantics_edge::resources::{OWNED_ALLOCATION_PADDING, ResourceLease};
pub(super) use finalizer::SessionFinalizerState;
pub(crate) use finalizer::SessionH3Finalizer;
use p11scope_ebpf_common::ImageIdentity;
pub(crate) use promotion::{
    PromotionAdmissionReservation, PromotionInstallCapacity, StagedPromotionAdmission,
};
use std::collections::{BTreeMap, BTreeSet};
use std::sync::Arc;

/// Move-only. A plan or arbitrary Slot cannot construct this envelope.
pub(crate) struct AttestedSubset {
    plan: plan::AttachPlan,
    pins: PinnedObjects,
    required: BTreeMap<PinnedObjectId, BTreeSet<u32>>,
}

impl std::fmt::Debug for AttestedSubset {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("AttestedSubset(<retained>)")
    }
}

impl AttestedSubset {
    pub(crate) fn plan(&self) -> &plan::AttachPlan {
        &self.plan
    }
    pub(crate) fn pins(&self) -> &PinnedObjects {
        &self.pins
    }
    pub(crate) fn required(&self) -> &BTreeMap<PinnedObjectId, BTreeSet<u32>> {
        &self.required
    }

    /// Two mints must retain the same authorized closure and original opened
    /// files. Equal paths, object IDs or digests cannot replace that custody.
    pub(crate) fn same_retained_envelope(&self, other: &Self) -> bool {
        if self.plan != other.plan
            || self.required != other.required
            || self.required.is_empty()
            || self.plan.slots.is_empty()
            || self.pins.check_unchanged() != Ok(true)
            || other.pins.check_unchanged() != Ok(true)
        {
            return false;
        }
        self.plan.slots.iter().all(|slot| {
            let Some((ours, theirs)) = self
                .pins
                .file_for(slot.object)
                .zip(other.pins.file_for(slot.object))
            else {
                return false;
            };
            if !std::ptr::eq(ours, theirs) {
                return false;
            }
            self.pins
                .pinned()
                .find(|pin| pin.id == slot.object)
                .zip(other.pins.pinned().find(|pin| pin.id == slot.object))
                .is_some_and(|(ours, theirs)| {
                    !ours.sha256.is_empty()
                        && ours.key == theirs.key
                        && ours.sha256 == theirs.sha256
                        && ours.build_id == theirs.build_id
                })
        })
    }

    /// The watched endpoint must be this attested provider's physical
    /// file, with its retained whole-file digest. Paths and matching
    /// content in another inode cannot supply this association.
    pub(crate) fn proves_provider_module(
        &self,
        object: PinnedObjectId,
        module: &ModuleKey,
    ) -> bool {
        let ModuleKey::Physical {
            dev_major,
            dev_minor,
            ino,
            sha256: Some(sha256),
        } = module
        else {
            return false;
        };
        if !self.required.contains_key(&object) || sha256.is_empty() {
            return false;
        }
        let Some(pin) = self.pins.pinned().find(|pin| pin.id == object) else {
            return false;
        };
        pin.sha256 == sha256
            && self.pins.raw_keys_for(object).iter().any(|key| {
                key.device.major == *dev_major
                    && key.device.minor == *dev_minor
                    && key.inode == *ino
            })
    }

    /// Tests-only envelope: conversion tests script descriptor shapes
    /// (unauthorized, ambiguous, count-only) that `prepare` never admits,
    /// to pin the defense-in-depth refusals above the proven Slot paths.
    /// Production construction stays move-only.
    #[cfg(test)]
    pub(crate) fn scripted(
        plan: plan::AttachPlan,
        pins: PinnedObjects,
        required: BTreeMap<PinnedObjectId, BTreeSet<u32>>,
    ) -> Self {
        Self {
            plan,
            pins,
            required,
        }
    }
}

pub(crate) struct SubsetPreparation {
    pub(crate) subset: Option<AttestedSubset>,
    pub(crate) refusals: Vec<SemanticRefusal>,
}

/// Operator paths are input requests, not attestation receipts. Only this
/// owner may read them and prepare authority against retained Inventory facts.
pub(crate) struct SemanticInputs {
    paths: Vec<PathBuf>,
    retained: Option<RetainedInputs>,
}

struct RetainedInputs {
    inputs: Vec<ManifestInput>,
    refusals: Vec<SemanticRefusal>,
    requested: bool,
}

impl SemanticInputs {
    pub(crate) fn new(paths: Vec<PathBuf>) -> Self {
        Self {
            paths,
            retained: None,
        }
    }

    pub(crate) fn prepare(&mut self, engine: &Engine) -> SubsetPreparation {
        let retained = self.retained.get_or_insert_with(|| {
            let mut inputs = Vec::new();
            let mut refusals = Vec::new();
            let mut budget = CaptureWorkBudget::default();
            for path in &self.paths {
                let accepted = (|| -> Result<ManifestInput> {
                    let manifest = read_manifest_file(path)?;
                    let pinning = pin_manifest_objects_deferred_in_views_with_budget(
                        &manifest,
                        &engine.views,
                        &mut budget,
                    )
                    .map_err(|_| anyhow!("manifest pinning refused"))?;
                    Ok(ManifestInput {
                        path: path.clone(),
                        manifest,
                        pins: pinning.pins,
                        stale: pinning.stale,
                    })
                })();
                match accepted {
                    Ok(input) => inputs.push(input),
                    Err(_) => refusals.push(SemanticRefusal::ManifestInput),
                }
            }
            RetainedInputs {
                inputs,
                refusals,
                requested: !self.paths.is_empty(),
            }
        });
        prepare_retained_subset(engine, retained)
    }
}

/// Read explicit inputs against the Inventory owner's retained sources. The
/// physical plan and its source ownership are never rebuilt or modified.
#[cfg(test)]
pub(crate) fn prepare_attested_subset(engine: &Engine, paths: &[PathBuf]) -> SubsetPreparation {
    SemanticInputs::new(paths.to_vec()).prepare(engine)
}

fn prepare_retained_subset(engine: &Engine, inputs: &RetainedInputs) -> SubsetPreparation {
    // This Inventory owner does not admit live Detailed selection claims.
    // Enabling that Engine path also requires incorporating its retained
    // claims/table latches here before preparing fresh semantic authority.
    let mut pins = engine.pinned.clone();
    let mut manifests = engine.manifests.clone();
    let mut accepted_paths = Vec::new();
    let mut refusals = inputs.refusals.clone();
    let scanned: Vec<_> = engine
        .modules
        .iter()
        .map(|module| module.scanned.clone())
        .collect();
    for input in &inputs.inputs {
        let accepted = (|| -> Result<_> {
            let mut manifest = input.manifest.clone();
            let manifest_pins = &input.pins;
            // Scan fallback preserves counts but cannot attest a stale object.
            if !input.stale.is_empty() || manifest_pins.check_unchanged() != Ok(true) {
                bail!("manifest retained object unavailable");
            }
            let view = scan_view(&manifest, &scanned, &pins, manifest_pins);
            let scan_targets = view
                .as_ref()
                .and_then(|view| scanned_targets_without(&view.modules, &pins, &BTreeSet::new()));
            let own_targets = manifest_targets(&manifest, manifest_pins)
                .context("manifest targets unavailable")?;
            let outcome = corroborate(
                engine.counters.scan_unavailable.is_some(),
                view.as_ref().map(|view| view.agrees),
                scan_targets.as_ref().is_some_and(|targets| {
                    pins.exactly_same_targets(targets, manifest_pins, &own_targets)
                }),
                view.as_ref().is_some_and(|view| {
                    view.modules
                        .iter()
                        .all(|module| module.tables.iter().all(|table| table.entries.is_empty()))
                }),
            );
            if outcome == Corroboration::IdentityMismatch {
                bail!("manifest identity disagrees with retained scan");
            }
            retarget_to_pins(
                &mut manifest,
                view.as_ref().map_or(&[], |view| view.modules.as_slice()),
                &pins,
                manifest_pins,
            );
            let mut candidate = pins.clone();
            if !candidate.absorb(manifest_pins.clone()).is_empty()
                || candidate.check_unchanged() != Ok(true)
            {
                bail!("manifest pin union unavailable");
            }
            let provider = candidate
                .id_for_path(&manifest.module_path)
                .context("manifest provider unavailable")?;
            Ok((manifest, candidate, provider))
        })();
        match accepted {
            Ok((manifest, candidate, provider)) => {
                pins = candidate;
                manifests.push(manifest);
                accepted_paths.push(provider);
            }
            Err(_) => refusals.push(SemanticRefusal::ManifestInput),
        }
    }
    if accepted_paths.is_empty() {
        if !inputs.requested {
            refusals.push(SemanticRefusal::Unattested);
        }
        return SubsetPreparation {
            subset: None,
            refusals,
        };
    }
    let claims = plan::semantic_source_claims(&engine.modules, &manifests, &pins);
    let plan = plan::build_from_sources_for_policy_scoped(
        &engine.modules,
        &manifests,
        &pins,
        plan::AdmissionPolicy::detailed(),
        plan::AdmissionScope::Named,
    );
    let mut selected = BTreeSet::new();
    for provider in accepted_paths.into_iter().collect::<BTreeSet<_>>() {
        let complete = claims
            .providers
            .get(&provider)
            .zip(plan.modules.iter().find(|module| module.object == provider))
            .is_some_and(|(required, module)| {
                !claims.incomplete.contains(&provider)
                    && !required.is_empty()
                    && required.iter().all(|key| {
                        plan.slots.iter().any(|slot| {
                            slot.object == key.object
                                && slot.file_offset == key.file_offset
                                && slot.module_ids.contains(&module.id)
                        })
                    })
                    && plan.slots.iter().any(|slot| {
                        slot.module_ids.contains(&module.id)
                            && slot.descriptor_index != 0
                            && !claims.degraded.contains(&plan::AttachKey {
                                object: slot.object,
                                file_offset: slot.file_offset,
                            })
                    })
            });
        if complete {
            selected.insert(provider);
        } else {
            refusals.push(SemanticRefusal::IncompleteProvider);
        }
    }
    let selected_plan = if selected.is_empty() {
        None
    } else {
        match plan.attested_subset(&selected, &claims.degraded) {
            Ok(plan) if !plan.slots.is_empty() => Some(plan),
            _ => {
                refusals.push(SemanticRefusal::IncompleteProvider);
                None
            }
        }
    };
    let subset = selected_plan.map(|plan| {
        // Dense subset indices are allocated only after full source requirements
        // matched the admitted targets. No source index survives this step.
        let required = selected
            .into_iter()
            .map(|provider| {
                let keys = &claims.providers[&provider];
                let slots = plan
                    .slots
                    .iter()
                    .filter(|slot| {
                        keys.contains(&plan::AttachKey {
                            object: slot.object,
                            file_offset: slot.file_offset,
                        })
                    })
                    .map(|slot| slot.index)
                    .collect();
                (provider, slots)
            })
            .collect();
        AttestedSubset {
            plan,
            pins,
            required,
        }
    });
    SubsetPreparation { subset, refusals }
}

/// One accepted semantic caller: its physical provider associations bound to
/// the original retained caller custody (one original shared pidfd Arc)
/// and this Detailed domain's fresh full image. Move-only coordinator
/// proof: private fields, redacted Debug, no Clone/Default/from_parts.
/// Equal numeric cookies from other producers never satisfy this binding:
/// every ticket comparison carries its domain.
pub(crate) struct SemanticCallerBinding {
    caller: CallerId,
    domain: NativeDomainId,
    image: ImageIdentity,
    pin: Arc<PidPin>,
    scope_current: bool,
    suspension_cut: bool,
    providers: SemanticProviderAssociations,
    #[cfg(test)]
    reference_module: Option<ModuleKey>,
}

/// Exact requested slot allocation: reserve the full replacement while the
/// old box and its lease remain live. Geometric growth bounds retained spare
/// slots; each allocation's actual slice length is the charged capacity.
struct SemanticProviderAssociations {
    slots: Box<[Option<SemanticProviderTarget>]>,
    len: usize,
    capacity_lease: Option<ResourceLease>,
}

impl SemanticProviderAssociations {
    fn new() -> Self {
        Self {
            slots: Box::default(),
            len: 0,
            capacity_lease: None,
        }
    }

    fn iter(&self) -> impl Iterator<Item = &SemanticProviderTarget> {
        self.slots[..self.len].iter().map(|slot| {
            slot.as_ref()
                .expect("accepted provider slots are contiguous")
        })
    }

    fn capacity_charge(capacity: usize) -> Option<usize> {
        capacity
            .checked_mul(std::mem::size_of::<Option<SemanticProviderTarget>>())?
            .checked_add(OWNED_ALLOCATION_PADDING)
    }

    /// The caller checks the capture-wide association limit before growth.
    /// Exact reproof needs no additional slot and retains old proof until now.
    fn insert(
        &mut self,
        provider: SemanticProviderTarget,
        registry: &CallerRegistry,
    ) -> Result<(), SemanticBindingRefusal> {
        let existing = self.iter().position(|old| old.same_association(&provider));
        if let Some(at) = existing {
            self.slots[at] = Some(provider);
            return Ok(());
        }
        if self.iter().any(|old| old.conflicts_with(&provider)) {
            return Err(SemanticBindingRefusal::ModuleConflict);
        }
        if self.len >= MAX_INSTANCES {
            return Err(SemanticBindingRefusal::Capacity);
        }
        if self.len == self.slots.len() {
            let capacity = self
                .slots
                .len()
                .max(1)
                .checked_mul(if self.slots.is_empty() { 1 } else { 2 })
                .filter(|capacity| *capacity <= MAX_INSTANCES)
                .ok_or(SemanticBindingRefusal::Capacity)?;
            let charge = Self::capacity_charge(capacity).ok_or(SemanticBindingRefusal::Capacity)?;
            let lease = registry
                .reserve_semantic_storage(charge)
                .map_err(|_| SemanticBindingRefusal::Capacity)?;
            let mut allocation =
                Box::<[Option<SemanticProviderTarget>]>::new_uninit_slice(capacity);
            for slot in allocation.iter_mut() {
                slot.write(None);
            }
            // SAFETY: every element above is initialized to a valid None.
            let mut slots = unsafe { allocation.assume_init() };
            for (old, new) in self.slots.iter_mut().zip(slots.iter_mut()) {
                *new = old.take();
            }
            self.slots = slots; // free the old allocation before its charge
            self.capacity_lease = Some(lease);
        }
        self.slots[self.len] = Some(provider);
        self.len += 1;
        Ok(())
    }
}

impl std::fmt::Debug for SemanticCallerBinding {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("SemanticCallerBinding(<private>)")
    }
}

impl SemanticCallerBinding {
    pub(crate) fn caller(&self) -> CallerId {
        self.caller
    }
    pub(crate) fn provider_for_endpoint(
        &self,
        endpoint: Endpoint,
    ) -> Option<&SemanticProviderTarget> {
        self.providers
            .iter()
            .find(|provider| provider.matches(endpoint))
    }
    pub(crate) fn provider_for_file(&self, file_slot: u32) -> Option<&SemanticProviderTarget> {
        let mut providers = self
            .providers
            .iter()
            .filter(|provider| provider.has_file_slot(file_slot));
        let provider = providers.next()?;
        providers.next().is_none().then_some(provider)
    }

    /// Old algorithm fixtures have exactly one reference module, never
    /// production authority. Ambiguous real bindings cannot select a first.
    #[cfg(test)]
    pub(crate) fn reference_single_provider_module(&self) -> &ModuleKey {
        assert!(
            self.providers.len <= 1,
            "multiple providers require exact endpoint selection"
        );
        self.providers
            .iter()
            .next()
            .map(SemanticProviderTarget::module)
            .or(self.reference_module.as_ref())
            .expect("single-provider reference fixture")
    }

    /// Existing scripted reducer fixtures carry only this reference module.
    /// An actual owner binding can never fall back here on a bad endpoint.
    #[cfg(test)]
    pub(crate) fn reference_fixture_module(&self) -> Option<&ModuleKey> {
        if self.providers.len != 0 {
            assert!(self.reference_module.is_none());
            return None;
        }
        self.reference_module.as_ref()
    }
    pub(crate) fn domain(&self) -> NativeDomainId {
        self.domain
    }
    pub(crate) fn image(&self) -> ImageIdentity {
        self.image
    }
    /// The stable custody Arc, shared (never re-duplicated) with H0
    /// refresh/ticks and physical-gap episodes.
    pub(crate) fn pin(&self) -> Arc<PidPin> {
        self.pin.clone()
    }
    pub(crate) fn scope_current(&self) -> bool {
        self.scope_current
    }

    /// Tests-only binding: conversion tests script modules (including
    /// unidentified ones production proof refuses) that binding proof
    /// never accepts, to pin the conversion refusals above it.
    #[cfg(test)]
    pub(crate) fn scripted(
        caller: CallerId,
        module: ModuleKey,
        domain: NativeDomainId,
        image: ImageIdentity,
        pin: Arc<PidPin>,
    ) -> Self {
        Self {
            caller,
            domain,
            image,
            pin,
            scope_current: true,
            suspension_cut: false,
            providers: SemanticProviderAssociations::new(),
            reference_module: Some(module),
        }
    }
}

/// Finite semantic-binding refusal.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[cfg_attr(not(test), allow(dead_code))] // Task5 lane loop binds callers.
pub(crate) enum SemanticBindingRefusal {
    NoLiveCaller,
    MappingIncomplete,
    DomainConflict,
    ModuleConflict,
    OwnerRefused(SemanticRefusal),
    ImageUnproven(UnboundReason),
    Capacity,
}

impl SemanticBindingRefusal {
    pub(crate) const fn code(self) -> &'static str {
        match self {
            Self::NoLiveCaller => "no_live_caller",
            Self::MappingIncomplete => "mapping_incomplete",
            Self::DomainConflict => "domain_conflict",
            Self::ModuleConflict => "module_conflict",
            Self::OwnerRefused(reason) => reason.code(),
            Self::ImageUnproven(reason) => reason.code(),
            Self::Capacity => "capacity",
        }
    }
}

/// Accepted semantic bindings: one stable Arc per accepted caller, bounded
/// by H0's binding capacity. Contiguous storage doubles as the tick window:
/// a persistent cursor rotates a fair slice into place, so ticks never
/// service only a fixed prefix.
pub(crate) struct SemanticBindingSet {
    bindings: Vec<SemanticCallerBinding>,
    index: HashMap<CallerId, usize>,
    cursor: usize,
    limit: usize,
    provider_limit: usize,
    refresh_cursor: Option<(CallerId, PinnedObjectId)>,
    /// Refusal-only history across accepted owner scan / failed scope commit.
    /// A later Detailed exec cannot silently reuse the chosen scan-pinned
    /// incarnation merely because its executable pathname/inode stayed equal.
    admission_images: HashMap<CallerId, SemanticAdmissionHistory>,
    /// One move-only H0 custody reservation per successful physical successor.
    /// An accepted owner receipt consumes it, including a provider/scope refusal.
    successors: HashMap<CallerId, PublishedSemanticSuccessor>,
    /// Accepted receipts that could not retain canonical custody (for example
    /// a divergent H0 Arc or a full history) remain refusal-only for later execs.
    refused_successors: HashMap<CallerId, PublishedSemanticSuccessor>,
    /// The installed promotion capacity's storage charge (D5/1D): the
    /// pre-reserved destination collections installed below hold
    /// real allocations, so their lease moves here and lives as
    /// long as they do. Dropping the lease while the storage is
    /// alive would refund live bytes (transient underaccounting);
    /// the install replaces collections before replacing the lease.
    install_lease: Option<ResourceLease>,
}

/// Accepted-scan history is negative-only: its image can forbid a later join,
/// and its original Arc can be forwarded through an actual physical handoff.
/// Neither fact grants semantic permission to the successor. A failed initial
/// scope transaction may retain its sealed gap until the normal finalizer.
struct SemanticAdmissionHistory {
    domain: NativeDomainId,
    image: ImageIdentity,
    incarnation: u32,
    generation: crate::inspect_system::MemberGeneration,
    pin: Arc<PidPin>,
    initial_scope_cut: bool,
    pending_gap: Option<PhysicalSemanticGap>,
}

/// The original H0 Arc travels only through a retained physical handoff.
/// Refusal moves with it, so another exec cannot turn a known mismatch into
/// a newly duplicated, apparently unrelated candidate.
pub(super) struct SemanticHandoffCustody {
    origin: CallerId,
    domain: NativeDomainId,
    pin: Arc<PidPin>,
    refusal: Option<SemanticBindingRefusal>,
}

impl SemanticHandoffCustody {
    pub(super) fn is_exact(&self) -> bool {
        self.refusal.is_none()
    }

    fn refuse(&mut self, reason: SemanticBindingRefusal) {
        self.refusal.get_or_insert(reason);
    }
}

struct PublishedSemanticSuccessor {
    custody: SemanticHandoffCustody,
    incarnation: u32,
    generation: crate::inspect_system::MemberGeneration,
}

impl PublishedSemanticSuccessor {
    fn matches(
        &self,
        incarnation: u32,
        generation: &crate::inspect_system::MemberGeneration,
    ) -> bool {
        self.incarnation == incarnation && &self.generation == generation
    }
}

impl SemanticBindingSet {
    pub(crate) fn new() -> Self {
        Self {
            bindings: Vec::new(),
            index: HashMap::new(),
            cursor: 0,
            limit: MAX_INSTANCES,
            provider_limit: MAX_INSTANCES,
            refresh_cursor: None,
            admission_images: HashMap::new(),
            successors: HashMap::new(),
            refused_successors: HashMap::new(),
            install_lease: None,
        }
    }

    /// Install pre-reserved destination storage for a newly promoted
    /// domain (DR37 allocation-free install): the capacity's paid
    /// collections become this set's bindings, index and supported
    /// history, and its storage lease moves into `install_lease`.
    /// The set must be empty: any retained entries (however
    /// domain-keyed) refuse with the capacity unconsumed and the set
    /// untouched, so no other domain's entries are ever dropped by an
    /// install. Successor maps are not swapped (retire clears the old
    /// domain's; other domains' are preserved in place). Zero
    /// allocations: field moves only.
    #[cfg_attr(not(test), allow(dead_code))] // STAGED (DR37): called by install_selected_lane.
    pub(crate) fn install_capacity(
        &mut self,
        capacity: PromotionInstallCapacity,
    ) -> Result<(), PromotionInstallCapacity> {
        if self.bindings.is_empty() && self.index.is_empty() && self.admission_images.is_empty() {
            let (bindings, index, admission_images, storage) = capacity.into_storage();
            // Drop replaced (empty) collections before replacing the
            // lease: live bytes stay accounted until freed.
            self.bindings = bindings;
            self.index = index;
            self.admission_images = admission_images;
            self.cursor = 0;
            self.refresh_cursor = None;
            self.install_lease = Some(storage);
            Ok(())
        } else {
            Err(capacity)
        }
    }

    /// Retire one completed domain's entries (DR37 A→B): bindings,
    /// refusal-only history and successor reservations keyed to the
    /// domain are removed; every other domain's entries are
    /// preserved. Returns the removed caller ids so the coordinator
    /// can clear their transient tail markers too. The index is
    /// rebuilt (positions shift) and cursors clamped; installed
    /// storage keeps its lease (the maps stay installed with holes
    /// until the next install replaces them).
    #[cfg_attr(not(test), allow(dead_code))] // STAGED (DR37): called by retire_joint_domain.
    pub(crate) fn retire_domain(&mut self, domain: NativeDomainId) -> Vec<CallerId> {
        let mut removed = BTreeSet::new();
        for binding in &self.bindings {
            if binding.domain() == domain {
                removed.insert(binding.caller());
            }
        }
        for (caller, history) in &self.admission_images {
            if history.domain == domain {
                removed.insert(*caller);
            }
        }
        for (caller, successor) in self.successors.iter().chain(&self.refused_successors) {
            if successor.custody.domain == domain {
                removed.insert(*caller);
            }
        }
        if !removed.is_empty() {
            self.bindings.retain(|binding| binding.domain() != domain);
            self.index.clear();
            for (at, binding) in self.bindings.iter().enumerate() {
                self.index.insert(binding.caller(), at);
            }
            self.admission_images
                .retain(|_, history| history.domain != domain);
            self.successors
                .retain(|_, successor| successor.custody.domain != domain);
            self.refused_successors
                .retain(|_, successor| successor.custody.domain != domain);
            self.cursor = self.cursor.min(self.bindings.len());
            if self
                .refresh_cursor
                .is_some_and(|(caller, _)| removed.contains(&caller))
            {
                self.refresh_cursor = None;
            }
        }
        removed.into_iter().collect()
    }

    #[cfg(test)]
    pub(crate) fn len(&self) -> usize {
        self.bindings.len()
    }

    pub(crate) fn get(&self, caller: CallerId) -> Option<&SemanticCallerBinding> {
        self.index.get(&caller).map(|at| &self.bindings[*at])
    }

    /// The unique binding for one Detailed image, if accepted. Images are
    /// per-process exact, so at most one caller holds each.
    pub(crate) fn find_by_image(
        &self,
        domain: NativeDomainId,
        image: ImageIdentity,
    ) -> Option<&SemanticCallerBinding> {
        self.bindings
            .iter()
            .find(|binding| binding.domain() == domain && binding.image() == image)
    }

    /// Whether a bound caller holds this Detailed ticket: proven-image
    /// retention keys on it, so the map never outgrows the binding cap.
    fn has_ticket(&self, domain: NativeDomainId, ticket: u64) -> bool {
        self.bindings
            .iter()
            .any(|binding| binding.domain() == domain && binding.image().task_cookie == ticket)
    }

    #[cfg(test)]
    pub(crate) fn reference_limit(&mut self, limit: usize) {
        self.limit = limit.min(MAX_INSTANCES);
    }

    fn provider_count(&self) -> usize {
        self.bindings
            .iter()
            .map(|binding| binding.providers.len)
            .sum()
    }

    #[cfg(test)]
    pub(crate) fn reference_provider_limit(&mut self, limit: usize) {
        self.provider_limit = limit.min(MAX_INSTANCES);
    }

    fn insert(&mut self, binding: SemanticCallerBinding) -> Result<(), SemanticBindingRefusal> {
        debug_assert!(!self.index.contains_key(&binding.caller));
        if self.bindings.len() >= self.limit {
            return Err(SemanticBindingRefusal::Capacity);
        }
        self.index.insert(binding.caller, self.bindings.len());
        self.bindings.push(binding);
        Ok(())
    }

    /// Select the exact H0 Arc already owned by this incarnation, if any.
    /// A known successor or accepted scan never falls back to a fresh Arc on
    /// a domain, generation, or custody mismatch.
    fn candidate_custody(
        &self,
        caller: CallerId,
        incarnation: u32,
        generation: &crate::inspect_system::MemberGeneration,
        domain: NativeDomainId,
    ) -> Option<(Option<Arc<PidPin>>, bool)> {
        if self.refused_successors.contains_key(&caller) {
            return None;
        }
        if let Some(successor) = self.successors.get(&caller) {
            let custody = &successor.custody;
            return (successor.matches(incarnation, generation)
                && custody.is_exact()
                && custody.domain == domain
                && custody.pin.still_the_same())
            .then(|| (Some(custody.pin.clone()), true));
        }
        let binding = self.get(caller);
        let history = self.admission_images.get(&caller);
        if let (Some(binding), Some(history)) = (binding, history)
            && (binding.domain != history.domain || !Arc::ptr_eq(&binding.pin, &history.pin))
        {
            return None;
        }
        if let Some(history) = history {
            return (history.incarnation == incarnation
                && &history.generation == generation
                && history.domain == domain
                && history.pin.still_the_same())
            .then(|| (Some(history.pin.clone()), false));
        }
        if let Some(binding) = binding {
            return (binding.domain == domain && binding.pin.still_the_same())
                .then(|| (Some(binding.pin.clone()), false));
        }
        Some((None, false))
    }

    /// Move one canonical H0 lineage into the physical handoff. A middle
    /// incarnation that never scanned forwards its published token; an
    /// accepted-but-refused predecessor uses its retained receipt history.
    pub(super) fn take_handoff(
        &mut self,
        caller: CallerId,
        incarnation: u32,
        generation: &crate::inspect_system::MemberGeneration,
        pending_exact: usize,
    ) -> Option<SemanticHandoffCustody> {
        if let Some(successor) = self
            .successors
            .remove(&caller)
            .or_else(|| self.refused_successors.remove(&caller))
        {
            let matches = successor.matches(incarnation, generation);
            let mut custody = successor.custody;
            if !matches || !custody.pin.still_the_same() {
                custody.refuse(SemanticBindingRefusal::NoLiveCaller);
            }
            return Some(custody);
        }
        let binding = self.get(caller);
        let history = self.admission_images.get(&caller);
        let (domain, pin) = binding
            .map(|binding| (binding.domain, binding.pin.clone()))
            .or_else(|| history.map(|history| (history.domain, history.pin.clone())))?;
        let mut custody = SemanticHandoffCustody {
            origin: caller,
            domain,
            pin,
            refusal: None,
        };
        if let (Some(binding), Some(history)) = (binding, history)
            && (binding.domain != history.domain || !Arc::ptr_eq(&binding.pin, &history.pin))
        {
            custody.refuse(SemanticBindingRefusal::ImageUnproven(
                UnboundReason::ExecAmbiguous,
            ));
        }
        if history.is_some_and(|history| {
            history.incarnation != incarnation || &history.generation != generation
        }) || !custody.pin.still_the_same()
        {
            custody.refuse(SemanticBindingRefusal::NoLiveCaller);
        }
        if custody.is_exact()
            && pending_exact
                + self
                    .successors
                    .values()
                    .filter(|successor| successor.custody.is_exact())
                    .count()
                >= self.limit
        {
            custody.refuse(SemanticBindingRefusal::Capacity);
        }
        Some(custody)
    }

    /// Publish only after the physical retained-custody handoff succeeded.
    /// The destination identity is the actual newly minted or adopted caller.
    pub(super) fn publish_successor(
        &mut self,
        mut custody: SemanticHandoffCustody,
        destination: CallerId,
        pid: u32,
        incarnation: u32,
        generation: crate::inspect_system::MemberGeneration,
        pending_exact: usize,
    ) -> Option<SemanticBindingRefusal> {
        if custody.origin == destination
            || custody.pin.pid() != pid
            || custody.pin.start_time() != generation.start_time
            || !custody.pin.still_the_same()
        {
            custody.refuse(SemanticBindingRefusal::NoLiveCaller);
        }
        if let Some(binding) = self.index.get(&destination).copied() {
            let binding = &mut self.bindings[binding];
            if binding.domain != custody.domain || !Arc::ptr_eq(&binding.pin, &custody.pin) {
                binding.scope_current = false;
                binding.suspension_cut = false;
                custody.refuse(SemanticBindingRefusal::ImageUnproven(
                    UnboundReason::ExecAmbiguous,
                ));
            }
        }
        if self
            .admission_images
            .get(&destination)
            .is_some_and(|history| {
                history.incarnation != incarnation
                    || history.generation != generation
                    || history.domain != custody.domain
                    || !Arc::ptr_eq(&history.pin, &custody.pin)
            })
            || self.refused_successors.contains_key(&destination)
            || self.successors.contains_key(&destination)
        {
            custody.refuse(SemanticBindingRefusal::ImageUnproven(
                UnboundReason::ExecAmbiguous,
            ));
        }
        if custody.is_exact()
            && pending_exact
                + self
                    .successors
                    .values()
                    .filter(|successor| successor.custody.is_exact())
                    .count()
                >= self.limit
        {
            custody.refuse(SemanticBindingRefusal::Capacity);
        }
        let refusal = custody.refusal;
        self.successors.insert(
            destination,
            PublishedSemanticSuccessor {
                custody,
                incarnation,
                generation,
            },
        );
        refusal
    }

    pub(super) fn release_successor(&mut self, caller: CallerId) {
        self.successors.remove(&caller);
        self.refused_successors.remove(&caller);
    }

    pub(super) fn release_unused_successors(&mut self) {
        self.successors.clear();
        self.refused_successors.clear();
    }

    pub(super) fn release_dead_successors(&mut self) {
        self.successors
            .retain(|_, successor| successor.custody.pin.still_the_same());
        self.refused_successors
            .retain(|_, successor| successor.custody.pin.still_the_same());
    }

    /// Tests-only binding insert over the production insert: driver
    /// timing tests bind without the native proof (the bind proof is
    /// pinned by the custody tests); conversion still runs production.
    #[cfg(test)]
    pub(crate) fn insert_for_test(
        &mut self,
        binding: SemanticCallerBinding,
    ) -> Result<(), SemanticBindingRefusal> {
        self.insert(binding)
    }

    /// Up to MAX_PENDING bindings for one tick, from the persistent fair
    /// cursor. Every accepted binding is served in rotation.
    pub(crate) fn bindings_for_tick(&mut self) -> &[SemanticCallerBinding] {
        self.windowed(MAX_PENDING)
    }

    /// The bounded-selection primitive behind `bindings_for_tick`: up to
    /// `limit` bindings from the persistent fair cursor. Tests pin rotation
    /// with small limits; production always passes MAX_PENDING. Rotation is
    /// lazy: each call rotates by the previously consumed window, so every
    /// accepted binding is served in turn. A full-set window is
    /// order-neutral: it serves every binding without rotating storage or
    /// touching the cursor, so re-proof never steals the tick window's turn.
    pub(crate) fn windowed(&mut self, limit: usize) -> &[SemanticCallerBinding] {
        let len = self.bindings.len();
        if len == 0 || limit == 0 {
            return &[];
        }
        let take = limit.min(len);
        if take == len {
            return &self.bindings;
        }
        self.bindings.rotate_left(self.cursor % len);
        self.cursor = take;
        self.index.clear();
        for (at, binding) in self.bindings.iter().enumerate() {
            self.index.insert(binding.caller, at);
        }
        &self.bindings[..take]
    }
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum AdmissionScope {
    Pid(u32),
    System,
    Cgroup,
}

/// Sealed before owner I/O: one chosen incarnation and already-owned process
/// handle. Commit checks this candidate; it never chooses a caller by PID.
pub(crate) struct SemanticAdmissionCandidate {
    caller: CallerId,
    incarnation: u32,
    generation: crate::inspect_system::MemberGeneration,
    pin: Arc<PidPin>,
    domain: NativeDomainId,
    /// Present for an accepted prior receipt or a physical successor. H0
    /// must return this very Arc; only a first-ever scan may choose its own.
    expected_pin: Option<Arc<PidPin>>,
    from_successor: bool,
    scope: AdmissionScope,
}

pub(crate) struct SemanticRefreshAttempt {
    pub(crate) caller: CallerId,
    pub(crate) slot: u32,
    pub(crate) module: Option<ModuleKey>,
}

/// Why a proof-gated lane install refused. Every variant returns the
/// lane and capacity uninstalled; nothing half-installs.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum SelectedInstallRefusal {
    /// The proof names another binding than the held lane.
    BindingMismatch,
    /// The binding set still holds entries: install never drops
    /// another domain's state.
    BindingsOccupied,
}

/// A refused install, with full restitution: the proof that
/// authorized only the failed attempt, the uninstalled lane (for
/// genuine disposal) and the unconsumed capacity (refunded by drop),
/// plus the finite reason.
pub(crate) struct SelectedInstallFailure {
    pub(crate) proof: SelectedActivationProof,
    pub(crate) lane: ProvisionalSelectedLane,
    pub(crate) capacity: PromotionInstallCapacity,
    pub(crate) reason: SelectedInstallRefusal,
}

impl std::fmt::Debug for SelectedInstallFailure {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("SelectedInstallFailure")
            .field("reason", &self.reason)
            .finish_non_exhaustive()
    }
}

/// Why a domain retire refused. Every variant leaves the live
/// namespace untouched: pending work stays live, and a foreign
/// completion retires nothing.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum JointRetireRefusal {
    /// The completion names no live finalizer namespace.
    NotLiveDomain,
    /// A quantum or drop is still staged: drain first, then retire.
    PendingWork,
}

impl<Source: ProcessSource> InventoryCoordinator<Source> {
    /// Four exact mapped attested pairs, including every failed refresh.
    /// Selection scans bounded retained catalogs without allocating a caller
    /// cross-product. The cursor advances per caller/provider, including failure.
    pub(crate) fn semantic_refresh_attempts(
        &mut self,
        lane: &AttestedSemanticLane,
        eligible: Option<&BTreeSet<CallerId>>,
        mut charge: impl FnMut(usize) -> bool,
    ) -> Vec<SemanticRefreshAttempt> {
        if !charge(5) {
            return Vec::new();
        }
        let mut attempts = Vec::with_capacity(4);
        let mut selected = BTreeSet::new();
        for _ in 0..4 {
            let mut next = None;
            let mut wrap = None;
            for record in self.adapter.records().filter(|record| {
                !record.retired
                    && self.adapter.live_id(record.pid) == Some(record.id)
                    && eligible.is_none_or(|eligible| eligible.contains(&record.id))
            }) {
                if !charge(1) {
                    return attempts;
                }
                if !self
                    .registry
                    .edges_of(record.id)
                    .any(|edge| edge.mapping == MappingState::Mapped)
                {
                    continue;
                }
                for (object, slots) in lane.subset().required() {
                    if !charge(1) {
                        return attempts;
                    }
                    let key = (record.id, *object);
                    if selected.contains(&key) {
                        continue;
                    }
                    let Some(slot) = slots.first().copied() else {
                        continue;
                    };
                    let mut exhausted = false;
                    let module = self.registry.modules().find(|module| {
                        if !charge(1) {
                            exhausted = true;
                            return true;
                        }
                        lane.subset().proves_provider_module(*object, &module.key)
                            && self
                                .registry
                                .edge(record.id, module.id)
                                .is_some_and(|edge| edge.mapping == MappingState::Mapped)
                    });
                    if exhausted {
                        return attempts;
                    }
                    let module = module.map(|module| module.key.clone());
                    if module.is_none() {
                        continue;
                    }
                    // This catalog selector has no current Session file-slot
                    // proof. Refresh the chosen pair instead of treating an
                    // equal module (or any other bound provider) as that proof.
                    // The persistent pair cursor keeps already-bound A from
                    // starving B, including when a refresh refuses.
                    let item = (
                        key,
                        SemanticRefreshAttempt {
                            caller: record.id,
                            slot,
                            module,
                        },
                    );
                    if self
                        .semantic_bindings
                        .refresh_cursor
                        .is_none_or(|cursor| key > cursor)
                        && next.as_ref().is_none_or(|(old, _)| key < *old)
                    {
                        next = Some(item);
                    } else if wrap.as_ref().is_none_or(|(old, _)| key < *old) {
                        wrap = Some(item);
                    }
                }
            }
            let Some((key, attempt)) = next.or(wrap) else {
                break;
            };
            selected.insert(key);
            self.semantic_bindings.refresh_cursor = Some(key);
            attempts.push(attempt);
        }
        attempts
    }

    fn seal_semantic_candidate(
        &self,
        caller: CallerId,
        pin: &PidPin,
        scope: AdmissionScope,
        domain: NativeDomainId,
        required_generation: Option<&crate::inspect_system::MemberGeneration>,
        share_first_custody: impl FnOnce() -> Option<Arc<PidPin>>,
    ) -> Option<SemanticAdmissionCandidate> {
        let record = self.adapter.record(caller)?;
        if record.retired
            || self.adapter.live_id(record.pid) != Some(caller)
            || record.pid != pin.pid()
            || record.start_time.is_none()
            || record.start_time != pin.start_time()
            || record.exe.is_none()
            || !pin.still_the_same()
        {
            return None;
        }
        let generation = crate::inspect_system::MemberGeneration {
            start_time: record.start_time,
            exe: record.exe.clone(),
        };
        if required_generation.is_some_and(|required| required != &generation) {
            return None;
        }
        let (expected_pin, from_successor) = self.semantic_bindings.candidate_custody(
            caller,
            record.incarnation,
            &generation,
            domain,
        )?;
        if expected_pin.as_ref().is_some_and(|expected| {
            expected.pid() != pin.pid() || expected.start_time() != pin.start_time()
        }) {
            return None;
        }
        let pin = if let Some(expected) = &expected_pin {
            expected.clone()
        } else {
            // First admission shares Inventory's original allocation. Known
            // H0 custody remains the exact same Arc across retries.
            let shared = share_first_custody()?;
            if shared.pid() != pin.pid()
                || shared.start_time() != pin.start_time()
                || !shared.still_the_same()
                || !pin.still_the_same()
            {
                return None;
            }
            shared
        };
        Some(SemanticAdmissionCandidate {
            caller,
            incarnation: record.incarnation,
            generation,
            pin,
            domain,
            expected_pin,
            from_successor,
            scope,
        })
    }

    pub(crate) fn prepare_legacy_semantic_candidate(
        &self,
        caller: CallerId,
        domain: NativeDomainId,
    ) -> Option<SemanticAdmissionCandidate> {
        let scope = match self.engine.scope {
            Scope::Pid(pid) => AdmissionScope::Pid(pid),
            Scope::System => AdmissionScope::System,
            _ => return None,
        };
        let pin = self.adapter.semantic_custody_ref(caller)?;
        if matches!(scope, AdmissionScope::Pid(pid) if pid != pin.pid()) {
            return None;
        }
        self.seal_semantic_candidate(caller, pin, scope, domain, None, || {
            self.adapter.shared_semantic_custody(caller)
        })
    }

    pub(crate) fn prepare_scoped_semantic_candidate(
        &self,
        prepared: &crate::discovery::caller_registry::PreparedScopedCaller<Source::Pin>,
        domain: NativeDomainId,
    ) -> Option<SemanticAdmissionCandidate> {
        let caller = prepared.existing()?;
        let pin = self.adapter.scoped_semantic_custody_ref(prepared)?;
        self.seal_semantic_candidate(
            caller,
            pin,
            AdmissionScope::Cgroup,
            domain,
            Some(prepared.generation()),
            || self.adapter.scoped_shared_semantic_custody(prepared),
        )
    }

    /// Reserve before the SAME candidate factory clones generation identity.
    /// Looking up borrowed source facts and sharing the original Arc allocate
    /// no storage and grant no owner/provider authority.
    pub(crate) fn prepare_legacy_promotion_candidate(
        &self,
        caller: CallerId,
        domain: NativeDomainId,
    ) -> Result<(SemanticAdmissionCandidate, PromotionAdmissionReservation), SemanticBindingRefusal>
    {
        let record = self
            .adapter
            .record(caller)
            .ok_or(SemanticBindingRefusal::NoLiveCaller)?;
        let pin = self
            .adapter
            .shared_semantic_custody(caller)
            .ok_or(SemanticBindingRefusal::NoLiveCaller)?;
        let path_bytes = record
            .exe
            .as_ref()
            .and_then(|exe| exe.path.as_ref())
            .map_or(0, String::len);
        let reservation = PromotionAdmissionReservation::reserve(
            &self.registry,
            caller,
            domain,
            pin,
            path_bytes,
        )?;
        let candidate = self
            .prepare_legacy_semantic_candidate(caller, domain)
            .ok_or(SemanticBindingRefusal::NoLiveCaller)?;
        if !reservation.matches(&candidate) {
            return Err(SemanticBindingRefusal::NoLiveCaller);
        }
        Ok((candidate, reservation))
    }

    pub(crate) fn prepare_scoped_promotion_candidate(
        &self,
        prepared: &crate::discovery::caller_registry::PreparedScopedCaller<Source::Pin>,
        domain: NativeDomainId,
    ) -> Result<(SemanticAdmissionCandidate, PromotionAdmissionReservation), SemanticBindingRefusal>
    {
        let caller = prepared
            .existing()
            .ok_or(SemanticBindingRefusal::NoLiveCaller)?;
        let pin = self
            .adapter
            .scoped_shared_semantic_custody(prepared)
            .ok_or(SemanticBindingRefusal::NoLiveCaller)?;
        // The shared factory clones the current record before comparing it
        // with the preparation; size that actual copy even on a mismatch.
        let path_bytes = self
            .adapter
            .record(caller)
            .ok_or(SemanticBindingRefusal::NoLiveCaller)?
            .exe
            .as_ref()
            .and_then(|exe| exe.path.as_ref())
            .map_or(0, String::len);
        let reservation = PromotionAdmissionReservation::reserve(
            &self.registry,
            caller,
            domain,
            pin,
            path_bytes,
        )?;
        let candidate = self
            .prepare_scoped_semantic_candidate(prepared, domain)
            .ok_or(SemanticBindingRefusal::NoLiveCaller)?;
        if !reservation.matches(&candidate) {
            return Err(SemanticBindingRefusal::NoLiveCaller);
        }
        Ok((candidate, reservation))
    }

    pub(crate) fn reserve_promotion_install(
        &self,
    ) -> Result<PromotionInstallCapacity, SemanticBindingRefusal> {
        PromotionInstallCapacity::reserve(&self.registry)
    }

    /// Re-validate a taken promotion pair against live coordinator
    /// state (D10): the caller still known and unretired, its
    /// identity continuous with the resolved original, the provider
    /// module still loaded, and the caller/provider edge still
    /// mapped. Returns the live provider key for the subset's
    /// `proves_provider_module` check. An early filter only: unknown
    /// lifecycle evidence passes here, and the native permit
    /// validation stays the authority downstream.
    #[cfg_attr(not(test), allow(dead_code))] // STAGED (DR37): called by the driver before start.
    pub(crate) fn validate_selected_pair_liveness(
        &self,
        pair: PromotionPair,
        original: &Arc<PidPin>,
    ) -> Result<ModuleKey, PromotionRefusal> {
        let caller = CallerId(pair.caller());
        let provider = ModuleId(pair.provider());
        let Some(record) = self.adapter.record(caller) else {
            return Err(PromotionRefusal::UnknownCaller);
        };
        if record.retired
            || matches!(
                record.lifecycle,
                CallerLifecycle::Exited | CallerLifecycle::ExecRetired
            )
        {
            return Err(PromotionRefusal::CallerRetired);
        }
        if record.pid != original.pid()
            || record
                .start_time
                .is_some_and(|started| Some(started) != original.start_time())
        {
            return Err(PromotionRefusal::CallerChanged);
        }
        let Some(module) = self.registry.module(provider) else {
            return Err(PromotionRefusal::ProviderUnloaded);
        };
        if module.lifecycle == ModuleLifecycle::Unloaded || module.unloaded_observed {
            return Err(PromotionRefusal::ProviderUnloaded);
        }
        let paired = self
            .registry
            .edge(caller, provider)
            .is_some_and(|edge| edge.mapping == MappingState::Mapped);
        if !paired {
            return Err(PromotionRefusal::ProviderChanged);
        }
        Ok(module.key.clone())
    }

    /// The seal grant's association proof (D9): the namespace's first
    /// admitted call, borrowed for the per-quantum mint. `None`
    /// before the first admission finalizes: the seal then refuses,
    /// honestly without a grant.
    #[cfg_attr(not(test), allow(dead_code))] // STAGED (DR37/H8): called by the joint seal driver.
    pub(crate) fn seal_admission(&self) -> Option<&AdmittedInstanceCall> {
        self.semantic_finalizer
            .as_ref()
            .and_then(|state| state.seal_admission.as_ref())
    }

    /// Install a proof-gated promoted lane (DR37): the proof must
    /// name exactly the lane's binding (checked before any
    /// mutation), the pre-reserved capacity becomes the binding
    /// set's destination storage (refused when occupied, set
    /// untouched), and the sealed lane converts to live. Any
    /// refusal returns the lane and capacity uninstalled for
    /// genuine disposal; nothing half-installs. The proof is
    /// consumed by the install it authorized.
    #[cfg_attr(not(test), allow(dead_code))] // STAGED (DR37): called by the driver on install.
    pub(crate) fn install_selected_lane(
        &mut self,
        proof: SelectedActivationProof,
        lane: ProvisionalSelectedLane,
        capacity: PromotionInstallCapacity,
    ) -> Result<AttestedSemanticLane, SelectedInstallFailure> {
        if !proof.matches_lane(lane.activation_binding()) {
            return Err(SelectedInstallFailure {
                proof,
                lane,
                capacity,
                reason: SelectedInstallRefusal::BindingMismatch,
            });
        }
        if let Err(capacity) = self.semantic_bindings.install_capacity(capacity) {
            return Err(SelectedInstallFailure {
                proof,
                lane,
                capacity,
                reason: SelectedInstallRefusal::BindingsOccupied,
            });
        }
        let live = lane
            .into_live_lane(&proof)
            .expect("proof matches the held lane");
        drop(proof);
        Ok(live)
    }

    /// Retire one genuinely completed domain for the next (D5): the
    /// native completion names the live finalizer namespace, which
    /// must be quiescent (no staged quantum, no pending drop);
    /// pending work refuses and the namespace stays live. Retire
    /// removes the domain's bindings, refusal-only history and
    /// successor reservations (other domains' entries preserved),
    /// clears its tail markers, drops the finalizer namespace
    /// (including its seal admission: no cross-domain grant reuse),
    /// refuses the domain permanently, and `mem::replace`s the joint
    /// owner with a fresh one (the old ledger's exact charges refund
    /// by drop; no counter resets). Adapter positions are
    /// stream/Session-local and correctly restart; global counters
    /// never reset.
    ///
    /// GATED-SEAL carry: `h3_pending` evidence drops with the
    /// namespace while joint seals are gated (no seal coverage
    /// exists to preserve). The unification wave must require
    /// seal-drained evidence before retire.
    #[cfg_attr(not(test), allow(dead_code))] // STAGED (DR37): called by the driver on completion.
    pub(crate) fn retire_joint_domain(
        &mut self,
        completion: SessionNativeCompletion,
    ) -> Result<(), JointRetireRefusal> {
        let domain = completion.domain();
        let live = self
            .semantic_finalizer
            .as_ref()
            .is_some_and(|state| state.domain == domain);
        if !live {
            return Err(JointRetireRefusal::NotLiveDomain);
        }
        let quiescent = self
            .semantic_finalizer
            .as_ref()
            .is_some_and(|state| state.pending_semantic.is_none() && state.pending_drop.is_none());
        if !quiescent {
            return Err(JointRetireRefusal::PendingWork);
        }
        let removed = self.semantic_bindings.retire_domain(domain);
        self.proven_images
            .retain(|(image_domain, _), _| *image_domain != domain);
        for caller in &removed {
            self.tail_uncertain.remove(caller);
            self.complete_scanned.remove(caller);
            self.pending_adjudication.remove(caller);
        }
        self.semantic_finalizer = None;
        self.refused_semantic_domains.insert(domain);
        self.joint_capture =
            crate::semantics_objects::journal::joint_driver::JointCaptureOwner::new(
                crate::semantics_objects::journal::JournalLimits::policy(),
                self.registry.semantic_storage_reserver(),
            );
        Ok(())
    }

    /// Run the ordinary consumer against fixed private storage. No registry
    /// diagnostic, history, registration or binding is published by this call.
    pub(crate) fn stage_promotion_admission(
        &self,
        reservation: PromotionAdmissionReservation,
        candidate: SemanticAdmissionCandidate,
        prepared: PreparedSemanticAdmission,
        permit: Option<crate::inspect_system::inventory_cgroup::CgroupAdmissionPermit<'_>>,
    ) -> StagedPromotionAdmission {
        StagedPromotionAdmission::consume(
            &self.adapter,
            &self.registry,
            reservation,
            candidate,
            prepared,
            permit,
        )
    }

    /// Consume unchanged owner evidence under the exact current scope guard.
    /// All provider/owner I/O precedes this call. After the final guard, only
    /// retained-record matching and bounded insertion remain.
    pub(crate) fn consume_semantic_admission(
        &mut self,
        candidate: SemanticAdmissionCandidate,
        prepared: PreparedSemanticAdmission,
        permit: Option<crate::inspect_system::inventory_cgroup::CgroupAdmissionPermit<'_>>,
    ) -> (
        crate::semantic_capture::CurrentPartitionReceipt,
        Result<(), SemanticBindingRefusal>,
    ) {
        let (receipt, provider) = prepared.into_parts();
        let caller = candidate.caller;
        let requested_file = receipt.endpoint().file_slot;
        let provider_module = provider
            .as_ref()
            .ok()
            .and_then(|provider| self.registry.module_id_for(provider.module()));
        let result = promotion::consume(
            &self.adapter,
            &self.registry,
            &mut self.semantic_bindings,
            candidate,
            &receipt,
            provider,
            permit,
        );
        if let Err(reason) = result {
            self.semantic_admission_refused(caller, reason.code());
            if matches!(
                reason,
                SemanticBindingRefusal::Capacity
                    | SemanticBindingRefusal::OwnerRefused(SemanticRefusal::ProviderStorage)
            ) {
                // Keep the existing finite refusal diagnostic and add the
                // particular requested provider for resource/count refusal.
                // A refused copy owns no ModuleKey, so its sealed file slot
                // supplies bounded context without allocating identity first.
                self.registry.record_gap(RegistryGap {
                    caller: Some(caller),
                    module: provider_module,
                    pid: None,
                    subject: format!("semantic provider file {requested_file} admission refused"),
                    reason: reason.code().into(),
                    budget: None,
                });
            }
        }
        (receipt, result)
    }

    pub(crate) fn semantic_admission_refused(&mut self, caller: CallerId, reason: &str) {
        self.registry.record_gap(RegistryGap {
            caller: Some(caller),
            module: None,
            pid: None,
            subject: "semantic admission refused".into(),
            reason: reason.into(),
            budget: None,
        });
    }

    /// A failed fresh membership proof is a persistent suspension, not only
    /// a one-publication loss marker. History retains its original custody.
    pub(crate) fn suspend_semantic_scope_except(&mut self, allowed: &BTreeSet<CallerId>) {
        for binding in &mut self.semantic_bindings.bindings {
            if (binding.scope_current || !binding.suspension_cut)
                && !allowed.contains(&binding.caller)
            {
                binding.scope_current = false;
                binding.suspension_cut = false;
                self.registry.note_member_unscanned(binding.caller);
                self.tail_uncertain.insert(binding.caller);
            }
        }
    }
}

impl SemanticAdmissionCandidate {
    pub(crate) fn pin(&self) -> Arc<PidPin> {
        self.pin.clone()
    }
    pub(crate) fn pid(&self) -> u32 {
        self.pin.pid()
    }
}

#[cfg(test)]
impl InventoryCoordinator<OsProcessSource> {
    /// Bind one semantic caller through retained custody: the caller must
    /// be the live incarnation for its pid with its original pin, the
    /// Detailed domain must currently prove the full image through that
    /// same pin, and the caller's mapping of the target module must be
    /// completely established, bracketed by fresh same-custody queries.
    /// The original pidfd is duplicated once; re-proving the same binding
    /// reuses the stored Arc without another duplication.
    pub(crate) fn bind_semantic_caller(
        &mut self,
        caller: CallerId,
        module: ModuleKey,
        domain: NativeDomainId,
        image: ImageIdentity,
        identity: &mut dyn NativeIdentity<PidPin>,
    ) -> Result<(), SemanticBindingRefusal> {
        use SemanticBindingRefusal as Refusal;
        let pid = match self.checked_binding_pid(caller, &module, domain, image, identity)? {
            None => return Ok(()),
            Some(pid) => pid,
        };
        // The single duplication, only on the accept path: the stored Arc
        // is then shared with H0 refresh/ticks and gap episodes.
        let pin = self
            .adapter
            .live_pin(pid)
            .and_then(|(_, pin)| pin.try_clone().ok())
            .map(Arc::new)
            .ok_or(Refusal::ImageUnproven(UnboundReason::CallerExited))?;
        self.semantic_bindings.insert(SemanticCallerBinding {
            caller,
            domain,
            image,
            pin,
            scope_current: true,
            suspension_cut: false,
            providers: SemanticProviderAssociations::new(),
            reference_module: Some(module),
        })
    }

    /// Bind one semantic caller through H0 refresh custody: identical proof
    /// to [`bind_semantic_caller`](Self::bind_semantic_caller), but the
    /// stored Arc is the exact one the caller gives H0's `refresh_candidate`,
    /// never a re-duplication. H0's `ptr_eq` gates refuse any other Arc.
    /// Re-proof of an accepted binding keeps the stored Arc.
    pub(crate) fn bind_semantic_caller_with_pin(
        &mut self,
        caller: CallerId,
        module: ModuleKey,
        domain: NativeDomainId,
        image: ImageIdentity,
        identity: &mut dyn NativeIdentity<PidPin>,
        pin: Arc<PidPin>,
    ) -> Result<(), SemanticBindingRefusal> {
        match self.checked_binding_pid(caller, &module, domain, image, identity)? {
            None => Ok(()),
            Some(_) => self.semantic_bindings.insert(SemanticCallerBinding {
                caller,
                domain,
                image,
                pin,
                scope_current: true,
                suspension_cut: false,
                providers: SemanticProviderAssociations::new(),
                reference_module: Some(module),
            }),
        }
    }

    /// The shared bind check-and-prove prologue: the caller must be the
    /// live incarnation for its pid, with its original pin and a fully
    /// established mapping bracketed by fresh same-custody queries. An
    /// accepted binding re-proves in place (`None`: nothing to insert);
    /// otherwise the fresh proof passed for the returned pid.
    fn checked_binding_pid(
        &mut self,
        caller: CallerId,
        module: &ModuleKey,
        domain: NativeDomainId,
        image: ImageIdentity,
        identity: &mut dyn NativeIdentity<PidPin>,
    ) -> Result<Option<u32>, SemanticBindingRefusal> {
        use SemanticBindingRefusal as Refusal;
        // The live incarnation for its pid: a reused pid number names
        // another incarnation or none, never this binding.
        let pid = {
            let record = self.adapter.record(caller).ok_or(Refusal::NoLiveCaller)?;
            if record.retired {
                return Err(Refusal::NoLiveCaller);
            }
            record.pid
        };
        if self.adapter.live_id(pid) != Some(caller) {
            return Err(Refusal::NoLiveCaller);
        }
        // An accepted binding re-proves in place: the same domain, image
        // and module reuse the stored Arc. Anything else refuses: one
        // binding per caller mirrors H0's per-cookie association, so a
        // second module refuses rather than misattributing its calls.
        if let Some(existing) = self.semantic_bindings.get(caller) {
            if existing.domain() != domain {
                return Err(Refusal::DomainConflict);
            }
            if existing.image() != image {
                return Err(Refusal::ImageUnproven(UnboundReason::ExecAmbiguous));
            }
            if existing.reference_single_provider_module() != module {
                return Err(Refusal::ModuleConflict);
            }
            self.prove_binding(caller, pid, module, domain, image, identity)?;
            return Ok(None);
        }
        self.prove_binding(caller, pid, module, domain, image, identity)?;
        Ok(Some(pid))
    }

    /// Fresh proof for one binding: a proven current sighting in this
    /// Detailed domain through the live pin, a completely established
    /// mapping read, and a second fresh sighting bracketing that read.
    /// Every ticket comparison carries its domain, so equal numeric
    /// cookies from Inventory, foreign or other Detailed producers never
    /// satisfy this proof.
    fn prove_binding(
        &self,
        caller: CallerId,
        pid: u32,
        module: &ModuleKey,
        domain: NativeDomainId,
        image: ImageIdentity,
        identity: &mut dyn NativeIdentity<PidPin>,
    ) -> Result<(), SemanticBindingRefusal> {
        use SemanticBindingRefusal as Refusal;
        if matches!(module, ModuleKey::Unidentified { .. }) {
            return Err(Refusal::MappingIncomplete);
        }
        let request = CurrentBindingRequest {
            caller,
            pid,
            image: DomainCookie::new(domain, image.task_cookie),
            exec_id: image.exec_id,
        };
        let lookup = &self.adapter as &dyn CallerLookup<PidPin>;
        let sighted = self
            .binder
            .sight_current_binding(request, lookup, identity)
            .map_err(Refusal::ImageUnproven)?;
        match self.binder.check_current_binding(&sighted) {
            CurrentBindingCheck::Proven => {}
            CurrentBindingCheck::Pending => {
                return Err(Refusal::ImageUnproven(UnboundReason::EvidenceIncomplete));
            }
            CurrentBindingCheck::Rejected(reason) => {
                return Err(Refusal::ImageUnproven(reason));
            }
        }
        let mapped = self
            .registry
            .module_id_for(module)
            .and_then(|id| self.registry.edge(caller, id))
            .is_some_and(|edge| edge.mapping == MappingState::Mapped);
        if !mapped {
            return Err(Refusal::MappingIncomplete);
        }
        self.binder
            .sight_current_binding(request, lookup, identity)
            .map(|_| ())
            .map_err(Refusal::ImageUnproven)
    }
}

impl<Source: ProcessSource> InventoryCoordinator<Source> {
    /// Queue one owned lane batch for finalization: at most one ordinary
    /// collection quantum is owned at a time, then finalize/publish
    /// before another semantic collection. A refused collection records
    /// loss through the existing audited path, never silently.
    pub(crate) fn stage_semantic_batch(
        &mut self,
        batch: crate::inventory_semantics::SemanticBatch,
    ) {
        if self.refused_semantic_domains.contains(&batch.domain()) {
            self.registry.record_gap(RegistryGap {
                caller: None,
                module: None,
                pid: None,
                subject: "semantic batch refused for an ended domain".into(),
                reason: "the domain's semantic authority ended permanently; \
                     the batch was refused through the audited path"
                    .into(),
                budget: None,
            });
            self.record_semantic_drop(&batch);
            return;
        }
        let state = self
            .semantic_finalizer
            .get_or_insert_with(|| SessionFinalizerState::new(batch.domain()));
        if state.domain != batch.domain() {
            self.registry.record_gap(RegistryGap {
                caller: None,
                module: None,
                pid: None,
                subject: "semantic batch refused for another Session".into(),
                reason: "the retained Session has not completed; another domain cannot stage or change its finalizer namespace".into(),
                budget: None,
            });
            return;
        }
        if state.pending_semantic.is_some() {
            self.registry.record_gap(RegistryGap {
                caller: None,
                module: None,
                pid: None,
                subject: "semantic collection backpressure".into(),
                reason: "an earlier semantic quantum is still unpublished; \
                     finalize and publish before another semantic collection"
                    .into(),
                budget: None,
            });
            self.record_semantic_drop(&batch);
            return;
        }
        self.semantic_finalizer
            .as_mut()
            .expect("the matching Session state is retained")
            .pending_semantic = Some(batch);
    }

    /// Take the latest H3 disposition evidence for one seal audit
    /// (H8): minted by the actual finalizer per batch, genesis before
    /// the first or when no batch minted since the last take (the seal
    /// then waits for coverage). Taking consumes the pending slot; a
    /// loss barrier persists across takes until the seal voids it (see
    /// `acknowledge_h3_void`). The seal audit constructor calls this
    /// through [`H3EvidenceSource`](crate::semantics_objects::journal::H3EvidenceSource),
    /// so the seal never audits caller-supplied H3 evidence.
    #[cfg(test)]
    pub(crate) fn take_h3_disposition(
        &mut self,
    ) -> crate::semantics_objects::journal::H3DispositionEvidence {
        use crate::semantics_objects::journal::H3DispositionEvidence;
        self.semantic_finalizer
            .as_mut()
            .map(SessionFinalizerState::take_disposition)
            .unwrap_or_else(H3DispositionEvidence::genesis)
    }

    /// The seal's H3-loss acknowledgement: H0 positions below
    /// `voided_below` were voided by a seal that consumed the
    /// corresponding loss evidence, so barriers there release the next
    /// mint into Clean. Monotone; the joint seal tick forwards the
    /// seal failure's void report here.
    #[cfg(test)]
    pub(crate) fn acknowledge_h3_void(&mut self, voided_below: u64) {
        if let Some(state) = &mut self.semantic_finalizer {
            state.h3_acked_below = state.h3_acked_below.max(voided_below);
        }
    }

    /// Record one dropped semantic batch's disposition shadow: its
    /// minimum outcome position (plus exhaustion) joins the next
    /// derivation as shed, so dropped history never vanishes from H3
    /// accounting. Later drops overwrite earlier ones: H0 positions
    /// ascend, so the latest drop covers all previous ones.
    fn record_semantic_drop(&mut self, batch: &crate::inventory_semantics::SemanticBatch) {
        let Some(state) = self
            .semantic_finalizer
            .as_mut()
            .filter(|state| state.domain == batch.domain())
        else {
            // Foreign positions belong to a different H0 allocator. The gap
            // remains visible, but it must not become loss in this Session.
            return;
        };
        let floor = batch.min_outcome_position();
        let exhausted = batch.exhausted();
        if floor.is_some() || exhausted {
            state.pending_drop = Some((floor.unwrap_or(0), exhausted));
        }
    }

    /// The private semantic finalizer: consumes pending semantic batches,
    /// validates receipts through the lane owner, and alone constructs H2
    /// envelopes, staged negatives first, validated registrations second
    /// and eligible calls in original position order.
    pub(crate) fn finalize_semantic_batches(
        &mut self,
        lane: Option<&mut crate::inventory_semantics::AttestedSemanticLane>,
    ) {
        match lane {
            None => {
                // No validation authority: refuse unpublished batches loudly.
                // Tail bits drain uncut: the cut joins its own publication
                // or not at all, never a later one.
                std::mem::take(&mut self.tail_uncertain);
                if let Some(dropped) = self
                    .semantic_finalizer
                    .as_mut()
                    .and_then(|state| state.pending_semantic.take())
                {
                    self.registry.record_gap(RegistryGap {
                        caller: None,
                        module: None,
                        pid: None,
                        subject: "semantic batch dropped without lane authority".into(),
                        reason: "no lane validated the batch's receipts; the unpublished \
                             batch was dropped through the audited path"
                            .into(),
                        budget: None,
                    });
                    self.record_semantic_drop(&dropped);
                }
            }
            Some(lane) => self.finalize_with_lane(lane),
        }
    }

    /// Adjudicate the pending unscanned placeholders at the end of the
    /// commit's catalog work, before semantic inputs stage. A marker is
    /// suppressed only when a complete, same-custody caller/provider/
    /// full-image proof established continued authority in this same
    /// publication; every other marker becomes the real physical
    /// uncertainty plus tail semantic uncertainty. Markers already
    /// staged genuinely are consumed silently, never duplicated.
    pub(crate) fn adjudicate_provisional_unscanned(&mut self, publication_complete: bool) {
        let markers = std::mem::take(&mut self.pending_adjudication);
        for (caller, pid) in markers {
            if self.tail_uncertain.contains(&caller) {
                continue;
            }
            let live = self.adapter.live_id(pid) == Some(caller);
            if publication_complete && live && self.complete_scanned.contains(&caller) {
                continue;
            }
            self.registry.note_member_unscanned(caller);
            self.tail_uncertain.insert(caller);
        }
    }

    /// Assemble tail gaps for genuinely uncertain callers: one gap from a
    /// denied first admission's accepted H0 receipt, or from a bound caller's
    /// proven exact current image, plus affected domains for cut-failure
    /// handling. Genuine gaps before the first accepted H0 scan keep
    /// conservative refusal: no mint, no cut, audited disclosure, while
    /// the staged physical uncertainty stands on its own.
    fn assemble_tail_gaps(&mut self) -> (Vec<PhysicalSemanticGap>, Vec<NativeDomainId>) {
        let mut gaps = Vec::new();
        let mut domains = Vec::new();
        for history in self.semantic_bindings.admission_images.values_mut() {
            if let Some(gap) = history.pending_gap.take() {
                if self.refused_semantic_domains.contains(&history.domain) {
                    continue;
                }
                gaps.push(gap);
                if !domains.contains(&history.domain) {
                    domains.push(history.domain);
                }
            }
        }
        for caller in std::mem::take(&mut self.tail_uncertain) {
            let Some(binding) = self.semantic_bindings.get(caller) else {
                continue;
            };
            if !binding.scope_current && binding.suspension_cut {
                continue;
            }
            let domain = binding.domain();
            if self.refused_semantic_domains.contains(&domain) {
                continue;
            }
            let image = binding.image();
            let proven = self
                .proven_images
                .get(&(domain, image.task_cookie))
                .is_some_and(|exec| *exec == image.exec_id);
            if !proven {
                self.registry.record_gap(RegistryGap {
                    caller: Some(caller),
                    module: None,
                    pid: None,
                    subject: "semantic gap refused before first scan".into(),
                    reason: "no accepted H0 scan proves this image yet; the physical \
                         uncertainty stands without a semantic cut"
                        .into(),
                    budget: None,
                });
                continue;
            }
            gaps.push(PhysicalSemanticGap::adjudicated(
                domain,
                image,
                binding.pin(),
            ));
            if !binding.scope_current {
                let at = self.semantic_bindings.index[&caller];
                self.semantic_bindings.bindings[at].suspension_cut = true;
            }
            if !domains.contains(&domain) {
                domains.push(domain);
            }
        }
        (gaps, domains)
    }

    /// Record H0 association: a receipt's presence proves its scan was
    /// accepted, whether or not the receipt still validates fresh. The
    /// latest observed exec per ticket decides gap minting. Retention keys
    /// on live bindings (`assemble_tail_gaps` consults the binding first,
    /// so entries for unbound tickets are never read): the map stays
    /// bounded by the binding cap instead of growing per distinct scan.
    fn observe_proven_image(&mut self, receipt: &crate::semantic_capture::CurrentPartitionReceipt) {
        if !self
            .semantic_bindings
            .has_ticket(receipt.domain(), receipt.image().task_cookie)
        {
            return;
        }
        self.proven_images
            .entry((receipt.domain(), receipt.image().task_cookie))
            .and_modify(|exec| *exec = (*exec).max(receipt.image().exec_id))
            .or_insert(receipt.image().exec_id);
    }

    /// Test seam: record an accepted H0 scan the shell lane cannot run,
    /// so the adjudication and cut legs exercise downstream of it. It
    /// mirrors production retention exactly: only bound tickets persist.
    #[cfg(test)]
    pub(crate) fn reference_prove_image(&mut self, domain: NativeDomainId, image: ImageIdentity) {
        if !self.semantic_bindings.has_ticket(domain, image.task_cookie) {
            return;
        }
        self.proven_images
            .entry((domain, image.task_cookie))
            .and_modify(|exec| *exec = (*exec).max(image.exec_id))
            .or_insert(image.exec_id);
    }

    /// Test seam: mark tail uncertainty the cgroup adjudication would
    /// have staged, so the cut legs exercise downstream of it.
    #[cfg(test)]
    pub(crate) fn reference_mark_tail(&mut self, caller: CallerId) {
        self.tail_uncertain.insert(caller);
    }

    fn finalize_with_lane(&mut self, lane: &mut crate::inventory_semantics::AttestedSemanticLane) {
        let state = self
            .semantic_finalizer
            .get_or_insert_with(|| SessionFinalizerState::new(lane.domain()));
        if state.domain != lane.domain() {
            self.registry.record_gap(RegistryGap {
                caller: None,
                module: None,
                pid: None,
                subject: "semantic finalizer refused another Session".into(),
                reason: "the retained Session must complete before a fresh H0 namespace can be installed".into(),
                budget: None,
            });
            return;
        }
        // The tail cut joins this publication directly, ahead of the
        // pending ordinary quantum: its barrier fences every unpublished
        // positive below, including just-resolved and queued inputs.
        let (gaps, domains) = self.assemble_tail_gaps();
        let mut cut: Option<crate::inventory_semantics::SemanticBatch> = None;
        if !gaps.is_empty() {
            match lane.apply_physical_gaps(gaps) {
                Ok(batch) => {
                    if batch.domain() == lane.domain() {
                        cut = Some(batch);
                    } else {
                        self.registry.record_gap(RegistryGap {
                            caller: None,
                            module: None,
                            pid: None,
                            subject: "semantic cut refused for a foreign domain".into(),
                            reason: "the cut batch names another lane domain; it was \
                                 dropped through the audited path"
                                .into(),
                            budget: None,
                        });
                    }
                }
                Err(_) => {
                    // Cut failure permanently refuses new semantic
                    // authority in the affected domains; broad Inventory
                    // continues.
                    for domain in domains {
                        self.refused_semantic_domains.insert(domain);
                        self.registry.record_gap(RegistryGap {
                            caller: None,
                            module: None,
                            pid: None,
                            subject: "semantic authority ended for domain".into(),
                            reason: "the physical cut failed; new semantic authority \
                                 in this domain refuses permanently"
                                .into(),
                            budget: None,
                        });
                    }
                }
            }
        }
        // The cut's barrier fences the queued ordinary quantum too:
        // tokens resolve below it only as history, never as fresh
        // positives. The floor carries the cut's own endpoints, never
        // any token admitted by the finalization itself.
        let mut floor: Option<u64> = None;
        if let Some(cut) = cut {
            floor = cut.cut_barrier();
            self.finalize_batch(lane, cut, None);
        }
        if let Some(pending) = self
            .semantic_finalizer
            .as_mut()
            .and_then(|state| state.pending_semantic.take())
        {
            self.finalize_batch(lane, pending, floor);
        }
    }

    /// Finalize one owned batch: negatives (lane facts, then H0
    /// invalidations) stage first, validated registrations second, and
    /// eligible calls in original position order last. Refusals record
    /// finite gaps; the legacy reducer is never touched.
    fn finalize_batch(
        &mut self,
        lane: &mut crate::inventory_semantics::AttestedSemanticLane,
        batch: crate::inventory_semantics::SemanticBatch,
        floor: Option<u64>,
    ) {
        let domain = batch.domain();
        if self.refused_semantic_domains.contains(&domain) {
            self.registry.record_gap(RegistryGap {
                caller: None,
                module: None,
                pid: None,
                subject: "semantic batch refused for an ended domain".into(),
                reason: "the domain's semantic authority ended permanently; \
                     the batch was refused through the audited path"
                    .into(),
                budget: None,
            });
            self.record_semantic_drop(&batch);
            return;
        }
        if domain != lane.domain() {
            self.registry.record_gap(RegistryGap {
                caller: None,
                module: None,
                pid: None,
                subject: "semantic batch refused for a foreign domain".into(),
                reason: "the batch names another lane domain; it was dropped \
                     through the audited path without staging"
                    .into(),
                budget: None,
            });
            self.record_semantic_drop(&batch);
            return;
        }
        let observed_ns = batch.observed_ns();
        let batch_awaiting = batch.awaiting_floor();
        let batch_shed = batch.shed_floor();
        let batch_exhausted = batch.exhausted();
        let (outcomes, current, negatives) = batch.into_parts();
        // Receipts: presence proves H0 association either way; only the
        // lane owner's validation admits coverage.
        let mut coverages = Vec::new();
        let mut validation = crate::semantic_capture::TickReport::default();
        for receipt in &current {
            self.observe_proven_image(receipt);
            match lane.validate_current(receipt, &mut validation) {
                Ok(coverage) => coverages.push(coverage),
                Err(reason) => {
                    let code = match reason {
                        CurrentReceiptRefusal::Domain => "domain",
                        CurrentReceiptRefusal::Custody => "custody",
                        CurrentReceiptRefusal::Attachment => "attachment",
                        CurrentReceiptRefusal::Epoch => "epoch",
                        CurrentReceiptRefusal::Partition => "partition",
                        CurrentReceiptRefusal::Deadline => "deadline",
                        CurrentReceiptRefusal::Audit => "audit",
                        CurrentReceiptRefusal::Stopped => "stopped",
                    };
                    self.registry.record_gap(RegistryGap {
                        caller: None,
                        module: None,
                        pid: None,
                        subject: "semantic receipt refused".into(),
                        reason: code.into(),
                        budget: None,
                    });
                }
            }
        }
        // Validation audits can consume a fault and resolve pending calls
        // even when the receipt refuses. Preserve those owned outcomes in
        // this publication; every negative below precedes all positives,
        // including coverage validated before a later receipt's fault.
        // The two producers are independently bounded. Consume their
        // negatives directly into H2's bounded ledger instead of spending
        // call capacity on them or truncating distinct negative scopes.
        let validation_outcomes = validation.into_outcomes();
        // Negatives first: lane facts, then H0 invalidations. Only
        // domain-wide facts advance the conversion barrier; the registry's
        // staged-before-positive order enforces narrower scopes. A cut
        // floor from the same publication fences queued calls first.
        let mut barrier: Option<u64> = floor;
        for negative in &negatives {
            match tail_loss_from_negative(domain, negative) {
                Some(Ok(loss)) => {
                    if let LaneNegative::CutBarrier { ordinal } = *negative {
                        barrier = Some(barrier.map_or(ordinal, |at: u64| at.max(ordinal)));
                    }
                    self.registry.note_instance_semantic_loss(loss);
                }
                Some(Err(reason)) => self.conversion_gap(None, reason),
                None => {
                    let LaneNegative::CollectionRefused { reason } = negative else {
                        continue;
                    };
                    self.registry.record_gap(RegistryGap {
                        caller: None,
                        module: None,
                        pid: None,
                        subject: "semantic collection refused".into(),
                        reason: reason.code().into(),
                        budget: None,
                    });
                }
            }
        }
        let mut calls = Vec::new();
        let mut shed_calls = 0usize;
        // H3 disposition inputs collected across staging: every outcome
        // position this finalization disposes, the minimum shed
        // position, and whether any outcome lacked a position.
        let mut staged_positions: Vec<Option<u64>> = Vec::new();
        let mut shed_min: Option<u64> = None;
        let mut unpositioned = false;
        for outcome in outcomes.into_iter().chain(validation_outcomes) {
            match outcome {
                TickOutcome::Call(call) => {
                    let token = call.token();
                    match CallEvidence::from_routed(call) {
                        Some(evidence) => {
                            if calls.len() < MAX_INSTANCES {
                                staged_positions.push(Some(evidence.token()));
                                calls.push(evidence);
                            } else {
                                shed_calls += 1;
                                let at = evidence.token();
                                shed_min = Some(shed_min.map_or(at, |floor| floor.min(at)));
                            }
                        }
                        // Unjoined routes never stage: their positions
                        // are undisposable, so they shed.
                        None => match token {
                            Some(at) => {
                                shed_min = Some(shed_min.map_or(at, |floor| floor.min(at)));
                            }
                            None => unpositioned = true,
                        },
                    }
                }
                TickOutcome::Invalidation(invalidation) => {
                    staged_positions.push(invalidation.position());
                    let image = match invalidation.scope() {
                        InvalidationScope::ImageRetired(image) => Some(*image),
                        InvalidationScope::File { image, .. } => Some(*image),
                        InvalidationScope::InstancesRetired { image, .. } => Some(*image),
                        _ => None,
                    };
                    let binding =
                        image.and_then(|image| self.semantic_bindings.find_by_image(domain, image));
                    match finalize_invalidation(
                        invalidation.scope(),
                        invalidation.position(),
                        domain,
                        binding,
                        &coverages,
                    ) {
                        Ok((losses, retirements)) => {
                            if matches!(
                                invalidation.scope(),
                                InvalidationScope::CoverageFailed
                                    | InvalidationScope::AuthorityExhausted
                                    | InvalidationScope::FaultEra
                                    | InvalidationScope::Stopped
                            ) && let Some(at) = invalidation.position()
                            {
                                barrier = Some(barrier.map_or(at, |b: u64| b.max(at)));
                            }
                            for loss in losses {
                                self.registry.note_instance_semantic_loss(loss);
                            }
                            for retirement in retirements {
                                self.registry.retire_instance(retirement);
                            }
                        }
                        Err(reason) => self.conversion_gap(None, reason),
                    }
                }
                TickOutcome::Other(other) => {
                    // Non-call records carry no instance decision, but
                    // finalization still disposes their positions.
                    staged_positions.push(other.position());
                }
            }
        }
        if shed_calls != 0 {
            self.registry.record_gap(RegistryGap {
                caller: None,
                module: None,
                pid: None,
                subject: "semantic call outcome capacity".into(),
                reason: format!("{shed_calls} calls refused at the bounded finalization limit"),
                budget: Some(BudgetRefusal {
                    resource: "semantic_call_outcomes",
                    limit: MAX_INSTANCES,
                    requested: MAX_INSTANCES + shed_calls,
                }),
            });
        }
        // Validated registrations second: every covered id registers.
        // Conversion borrows end before staging mutates the registry.
        for coverage in &coverages {
            let staged: Vec<(
                CallerId,
                Result<
                    crate::discovery::caller_registry::instance_input::AdmittedInstance,
                    ConversionRefusal,
                >,
            )> = {
                let Some(binding) = self
                    .semantic_bindings
                    .find_by_image(coverage.domain(), coverage.image())
                else {
                    continue;
                };
                let caller = binding.caller();
                coverage
                    .instances()
                    .iter()
                    .map(|id| {
                        (
                            caller,
                            admit_registration_from_coverage(
                                coverage,
                                binding,
                                lane.subset(),
                                *id,
                                observed_ns,
                                None,
                            ),
                        )
                    })
                    .collect()
            };
            for (caller, result) in staged {
                match result {
                    Ok(input) => self.registry.note_instance(input),
                    Err(reason) => self.conversion_gap(Some(caller), reason),
                }
            }
        }
        // Eligible calls last, in original position order.
        #[cfg(test)]
        lane.note_conversion_barrier(barrier);
        calls.sort_by_key(CallEvidence::token);
        let subset = lane.subset();
        let staged: Vec<(
            Option<CallerId>,
            u64,
            Result<
                crate::discovery::caller_registry::instance_input::AdmittedInstanceCall,
                ConversionRefusal,
            >,
        )> = calls
            .into_iter()
            .map(|evidence| {
                let token = evidence.token();
                let found = self
                    .semantic_bindings
                    .find_by_image(evidence.domain(), evidence.image());
                let Some(binding) = found else {
                    return (None, token, Err(ConversionRefusal::Custody));
                };
                let caller = binding.caller();
                let coverage = coverages.iter().find(|coverage| {
                    binding.scope_current()
                        && coverage.domain() == evidence.domain()
                        && coverage.image() == evidence.image()
                        && coverage.instances().contains(&evidence.router())
                });
                // Joined is historical evidence: a call without same-batch
                // current proof (cached, quiet provider) still adds
                // history-only API returns under a disclosed reason, never
                // current continuity and never a re-proof.
                let standing = match coverage {
                    Some(coverage) => CallStanding::Current(coverage),
                    None => CallStanding::Historical(InstanceReason::SemanticLoss),
                };
                (
                    Some(caller),
                    token,
                    admit_call_from_evidence(evidence, binding, subset, standing, barrier),
                )
            })
            .collect();
        let mut first_admitted = None;
        for (caller, token, result) in staged {
            match result {
                Ok(input) => {
                    // D9: retain the quantum's first admission for the
                    // seal grant's association proof. The staged
                    // mutation below still consumes the original.
                    if first_admitted.is_none() {
                        first_admitted = Some(input.clone());
                    }
                    self.registry.observe_instance_semantic(input);
                }
                Err(reason) => {
                    // A refused call never stages and never retries: its
                    // position sheds rather than vanishing.
                    shed_min = Some(shed_min.map_or(token, |floor| floor.min(token)));
                    self.conversion_gap(caller, reason);
                }
            }
        }
        // H3 disposition (H8): mint completeness from this
        // finalization's complete state and store it for the seal.
        // Staged positions cover calls and invalidations alike; the
        // pending floor joins the batch's route-waiting floor with
        // unpublished and lane-stashed history; shed minima (batch,
        // finalizer, dropped) barrier as loss.
        let state = self
            .semantic_finalizer
            .as_mut()
            .expect("finalization retains the matching Session namespace");
        debug_assert_eq!(state.domain, lane.domain());
        // D9: first-ever admission per namespace; a set proof is the
        // Session-stable association, never refreshed per quantum.
        if state.seal_admission.is_none() {
            state.seal_admission = first_admitted;
        }
        if let Some((floor, exhausted)) = state.pending_drop.take() {
            shed_min = Some(shed_min.map_or(floor, |at| at.min(floor)));
            unpositioned = unpositioned || exhausted;
        }
        let unpublished = state
            .pending_semantic
            .as_ref()
            .and_then(|batch| batch.min_outcome_position())
            .into_iter()
            .chain(lane.stash_pending_floor())
            .min();
        let shed_floor = batch_shed.into_iter().chain(shed_min).min();
        let evidence =
            crate::semantics_objects::journal::H3DispositionEvidence::from_finalizer_batch(
                &negatives,
                &staged_positions,
                batch_awaiting,
                shed_floor,
                unpublished,
                batch_exhausted || unpositioned,
                &state.h3_last,
                state.h3_acked_below,
            );
        state.h3_last = evidence.clone();
        state.h3_pending = Some(evidence);
    }

    /// Finite conversion refusal through the audited path.
    fn conversion_gap(&mut self, caller: Option<CallerId>, reason: ConversionRefusal) {
        self.registry.record_gap(RegistryGap {
            caller,
            module: None,
            pid: None,
            subject: "semantic input refused".into(),
            reason: reason.code().into(),
            budget: None,
        });
    }
}

#[cfg(test)]
impl crate::semantics_objects::journal::H3EvidenceSource
    for InventoryCoordinator<crate::discovery::caller_registry::OsProcessSource>
{
    fn take_h3_disposition(&mut self) -> crate::semantics_objects::journal::H3DispositionEvidence {
        InventoryCoordinator::take_h3_disposition(self)
    }
}

#[cfg(test)]
impl crate::semantics_objects::journal::H3FinalizerPort
    for InventoryCoordinator<crate::discovery::caller_registry::OsProcessSource>
{
    fn acknowledge_h3_void(
        &mut self,
        acknowledgement: crate::semantics_objects::journal::H3VoidAcknowledgement,
    ) {
        // Legacy algorithm fixtures have independently constructed shell
        // lanes and adapter scenes. They do not claim Session qualification;
        // production has only the exact-pair borrowed port above.
        if let Some(state) = self.semantic_finalizer.as_mut() {
            let voided_below = acknowledgement.for_legacy_test();
            state.h3_acked_below = state.h3_acked_below.max(voided_below);
        }
    }
}

#[cfg(test)]
pub(crate) fn engine_for_test(
    manifests: Vec<Manifest>,
    modules: Vec<ReconciledModule>,
    pins: PinnedObjects,
) -> Engine {
    let budget = crate::capacity::inventory_endpoint_budget(None).unwrap();
    let mut engine = Engine::inventory(
        inventory_config(budget).unwrap(),
        Scope::Pid(std::process::id()),
        HookRegistry::builtin(),
        Vec::new(),
    )
    .unwrap();
    engine.plan = plan::build_from_sources_for_policy(
        &modules,
        &manifests,
        &pins,
        plan::AdmissionPolicy::Inventory(budget),
    );
    engine.manifests = manifests;
    engine.modules = modules;
    engine.pinned = pins;
    engine
}

#[cfg(test)]
mod binding_window_tests {
    use super::*;

    fn windowed_set(count: u32) -> SemanticBindingSet {
        let domain = NativeDomainId::mint();
        let pin = Arc::new(PidPin::test_proc_only(1234));
        let module = ModuleKey::physical(7, 7, 777, None, "/window/provider.so");
        let mut set = SemanticBindingSet::new();
        for index in 0..count {
            set.insert(SemanticCallerBinding::scripted(
                CallerId(index),
                module.clone(),
                domain,
                ImageIdentity {
                    task_cookie: u64::from(index),
                    exec_id: 1,
                },
                pin.clone(),
            ))
            .unwrap();
        }
        set
    }

    fn window_callers(set: &mut SemanticBindingSet, limit: usize) -> Vec<CallerId> {
        set.windowed(limit)
            .iter()
            .map(|binding| binding.caller())
            .collect()
    }

    #[test]
    fn windowed_rotation_serves_every_binding_within_full_cycle() {
        // 3:1 population/quantum: three 1024-windows must cover all 3072
        // bindings, so the last block is served within three windows.
        let mut set = windowed_set(3072);
        let mut served = std::collections::BTreeSet::new();
        for _ in 0..3 {
            served.extend(window_callers(&mut set, 1024));
        }
        assert!(
            served.contains(&CallerId(2048)),
            "block 2 starves: only {} of 3072 bindings served in 3 windows",
            served.len()
        );
        assert_eq!(served.len(), 3072);
    }

    #[test]
    fn windowed_full_set_is_order_neutral() {
        let mut set = windowed_set(8);
        assert_eq!(window_callers(&mut set, 2), vec![CallerId(0), CallerId(1)]);
        let all = window_callers(&mut set, 8);
        assert_eq!(
            all,
            (0..8).map(CallerId).collect::<Vec<_>>(),
            "the full window serves insertion order"
        );
        assert_eq!(
            window_callers(&mut set, 2),
            vec![CallerId(2), CallerId(3)],
            "rotation continues where it left off: the full window stole no turn"
        );
    }
}

#[cfg(test)]
mod finalizer_history_tests {
    //! Receiptless Joined calls are historical evidence: the finalizer
    //! admits them history-only instead of refusing coverage.
    use super::*;
    use crate::attach::capture::NativeDomainId;
    use crate::attach::{BackendSelection, Scope};
    use crate::discovery::caller_registry::instance_input::InstanceReason;
    use crate::discovery::caller_registry::{
        AdmissionState, ImageAuthority, ModuleInfo, OsProcessSource, RegistryLimits,
    };
    use crate::discovery::hooks::HookRegistry;
    use crate::discovery::instances::{
        CallFacts, EntryIp, EpochReading, InstanceId, InstanceRouter, MapRange, Route,
        RouterLimits, StableObservation,
    };
    use crate::inventory_semantics::{AttestedSemanticLane, LaneCoverage, SemanticBatch};
    use crate::semantic_capture::{Endpoint, RoutedCall, TickOutcome, TickReport};
    use p11scope_ebpf_common::instance::STAMP_VALID;
    use p11scope_ebpf_common::{Event, InstanceStamp, capture};
    use p11scope_manifest::identity::{inspect_file, mapping_file_key, open_object};
    use p11scope_manifest::manifest::*;

    struct HistoryFixture {
        dir: tempfile::TempDir,
        manifest: Manifest,
        pins: PinnedObjects,
    }

    impl HistoryFixture {
        fn new() -> Self {
            let dir = tempfile::tempdir().unwrap();
            let path = dir.path().join("provider.so");
            std::fs::copy("/bin/true", &path).unwrap();
            let file = open_object(&path).unwrap();
            let inspected = inspect_file(&file).unwrap();
            let mapping = mapping_file_key(&file).unwrap();
            let start = inspected
                .executable_ranges
                .iter()
                .find(|(a, b)| b - a > 2)
                .unwrap()
                .0;
            let offsets = [start, start + 1];
            let functions =
                match pkcs11_module::tables_for(pkcs11_module::Surface::LegacyFunctionList {
                    version: cryptoki_sys::CK_VERSION {
                        major: 2,
                        minor: 40,
                    },
                }) {
                    pkcs11_module::TableSet::Walk(spans) => spans
                        .iter()
                        .flat_map(|span| span.fields())
                        .map(|field| {
                            let resolution = match field.name {
                                "C_SignInit" => Resolution::Resolved {
                                    object: 0,
                                    file_offset: offsets[0],
                                },
                                "C_Sign" => Resolution::Resolved {
                                    object: 0,
                                    file_offset: offsets[1],
                                },
                                _ => Resolution::NullPointer,
                            };
                            FunctionRecord {
                                name: field.name.into(),
                                resolution,
                            }
                        })
                        .collect(),
                    _ => panic!("2.40 is a full standard table"),
                };
            let path = path.to_str().unwrap().to_string();
            let manifest = Manifest {
                schema: SCHEMA.into(),
                module_path: path.clone(),
                objects: vec![ObjectRecord {
                    id: 0,
                    path: path.clone(),
                    identity: inspected.identity.clone(),
                }],
                provenance_objects: vec![ProvenanceObject {
                    path,
                    device_major: mapping.device_major,
                    device_minor: mapping.device_minor,
                    inode: mapping.inode,
                    identity: inspected.identity,
                }],
                interface_list: Acquisition::Absent,
                surfaces: vec![SurfaceRecord {
                    source: SurfaceSource::LegacyFunctionList,
                    acquisition: Acquisition::Ok,
                    version: Some(Version {
                        major: 2,
                        minor: 40,
                    }),
                    walk: WalkOutcome::Full,
                    functions,
                }],
                vendor_interfaces: Vec::new(),
                alias_groups: Vec::new(),
                selection_evidence: Default::default(),
            };
            assert!(crate::manifest_input::validate_structure(&manifest).is_empty());
            let pinning =
                crate::discovery::identity::pin_manifest_objects_deferred(&manifest).unwrap();
            assert!(pinning.stale.is_empty());
            assert_eq!(pinning.pins.pinned().count(), 1);
            Self {
                dir,
                manifest,
                pins: pinning.pins,
            }
        }

        fn subset(&self) -> AttestedSubset {
            let path = self.dir.path().join("operator-input.json");
            std::fs::write(&path, serde_json::to_vec(&self.manifest).unwrap()).unwrap();
            let engine = engine_for_test(Vec::new(), Vec::new(), self.pins.clone());
            let prepared = prepare_attested_subset(&engine, &[path]);
            let subset = prepared.subset.expect("nonempty validated operator subset");
            assert_eq!(subset.plan().slots.len(), 2);
            subset
        }
    }

    #[test]
    fn selected_conversion_envelope_keeps_original_files_and_exact_closure() {
        let fixture = HistoryFixture::new();
        let attached = fixture.subset();
        let mut converted = fixture.subset();
        assert!(
            attached.same_retained_envelope(&converted),
            "fresh actual mints share the original retained files"
        );
        converted.plan.slots[0].file_offset += 1;
        assert!(
            !attached.same_retained_envelope(&converted),
            "a changed endpoint closure is refused"
        );
        let mut converted = fixture.subset();
        converted.required.values_mut().next().unwrap().clear();
        assert!(
            !attached.same_retained_envelope(&converted),
            "missing authorized slots are refused"
        );

        let path = fixture.dir.path().join("operator-input.json");
        let independent =
            crate::discovery::identity::pin_manifest_objects_deferred(&fixture.manifest).unwrap();
        let engine = engine_for_test(Vec::new(), Vec::new(), independent.pins);
        let independent = prepare_attested_subset(&engine, &[path]).subset.unwrap();
        assert_eq!(
            attached.plan, independent.plan,
            "same physical file and exact plan are insufficient alone"
        );
        assert_eq!(attached.required, independent.required);
        assert!(
            !attached.same_retained_envelope(&independent),
            "independent opening cannot substitute for original file Arc custody"
        );
    }

    fn router_ids(domain: NativeDomainId, count: usize) -> Vec<InstanceId> {
        let mut router = InstanceRouter::new(domain, RouterLimits::default());
        let ranges = (0..count)
            .map(|n| {
                let base = 0x7000_0000 + n as u64 * 0x10000;
                MapRange::new(base, base + 0x3000, 0, true)
            })
            .collect();
        router.observe_legacy(StableObservation {
            file_slot: 0,
            reading: EpochReading {
                cookie: 71,
                local: 1,
                global: 0,
                fault: 0,
                record_flags: 0,
                sticky: 0,
            },
            ranges,
            fence: 0,
        });
        (0..count)
            .map(|n| {
                let stamp = InstanceStamp {
                    epoch: 1,
                    file_slot_plus1: 1,
                    flags: STAMP_VALID,
                    ..InstanceStamp::default()
                };
                match router.route(CallFacts {
                    token: n as u64 + 1,
                    domain,
                    image: ImageIdentity {
                        task_cookie: 71,
                        exec_id: 0,
                    },
                    entry: stamp,
                    ret: stamp,
                    ip: EntryIp::new(0x7000_0000 + n as u64 * 0x10000 + 0x1000),
                    attached_offset: Some(0x1000),
                }) {
                    Route::Joined(id) => id,
                    other => panic!("fixture must route a real instance: {other:?}"),
                }
            })
            .collect()
    }

    #[test]
    fn receiptless_joined_call_admits_as_history() {
        let pid = std::process::id();
        let mut coordinator = InventoryCoordinator::new(
            Scope::Pid(pid),
            HookRegistry::builtin(),
            Vec::new(),
            OsProcessSource,
            RegistryLimits::default_limits(),
        )
        .unwrap();
        let caller = coordinator
            .adapter_mut()
            .admit(pid, ImageAuthority::ScanPinned, 50)
            .unwrap();
        let fixture = HistoryFixture::new();
        let pin = fixture.pins.pinned().next().unwrap();
        let module = ModuleKey::physical(
            pin.key.device.major,
            pin.key.device.minor,
            pin.key.inode,
            Some(pin.sha256.to_owned()),
            pin.path,
        );
        coordinator.registry_mut().note_mapping(
            caller,
            pid,
            ModuleInfo {
                path: "/task3/provider.so".into(),
                key: module.clone(),
                double_loaded: false,
                build_id: None,
                identity_source: Some("task3".into()),
                admission: AdmissionState::Admitted,
                admission_class: Some("exact".into()),
                admission_endpoints: Some(1),
                admission_reasons: Vec::new(),
            },
            60,
        );
        coordinator.commit_batch(false).unwrap();
        let mut lane =
            AttestedSemanticLane::start(fixture.subset(), &Scope::Pid(pid), BackendSelection::Auto)
                .expect("shell lane starts");
        let detailed = lane.domain();
        let image = ImageIdentity {
            task_cookie: 7,
            exec_id: 1,
        };
        coordinator
            .semantic_bindings_mut()
            .insert(SemanticCallerBinding::scripted(
                caller,
                module.clone(),
                detailed,
                image,
                Arc::new(PidPin::test_proc_only(pid)),
            ))
            .unwrap();
        let init_slot = lane
            .subset()
            .plan()
            .slots
            .iter()
            .find(|slot| slot.names.len() == 1 && slot.names[0] == "C_SignInit")
            .unwrap()
            .index;
        let slot = lane
            .subset()
            .plan()
            .slots
            .iter()
            .find(|slot| slot.index == init_slot)
            .unwrap();
        let endpoint = Endpoint {
            object: slot.object,
            file_slot: 0,
            offset: slot.file_offset,
        };
        let r0 = router_ids(detailed, 1)[0];
        // The instance registers through proven coverage first; the later
        // call arrives Joined but receiptless (cached, quiet provider).
        let coverage = LaneCoverage::scripted(detailed, image, endpoint, vec![r0]);
        let input = {
            let binding = coordinator.semantic_bindings().get(caller).unwrap();
            admit_registration_from_coverage(&coverage, binding, lane.subset(), r0, 100, None)
                .expect("scripted coverage registers")
        };
        coordinator.registry_mut().note_instance(input);
        coordinator.commit_batch(false).unwrap();
        let stamp = InstanceStamp {
            epoch: 1,
            file_slot_plus1: 1,
            flags: STAMP_VALID,
            ..InstanceStamp::default()
        };
        let routed = RoutedCall::scripted(
            detailed,
            crate::events::DecodedEventRecord {
                joint_resource: None,
                base: crate::semantic_capture::event_record_with_routing(
                    Event {
                        slot: init_slot,
                        session: 7,
                        mechanism: 0x000d,
                        capture: capture::MECHANISM_VALUE | capture::OUTPUT_NON_NULL,
                        rv: 0,
                        ts_ns: 110,
                        image,
                        ..Default::default()
                    },
                    stamp,
                    0x2200,
                ),
                object: None,
            },
            Route::Joined(r0),
            Some(endpoint),
            Some(1),
        );
        let batch = SemanticBatch::from_tick_report(
            detailed,
            TickReport::scripted(vec![TickOutcome::Call(routed)], Vec::new()),
            Vec::new(),
            130,
        )
        .unwrap();
        coordinator.stage_semantic_batch(batch);
        coordinator
            .commit_batch_with_semantics(false, Some(&mut lane))
            .unwrap();
        let gaps: Vec<(String, String)> = coordinator
            .registry()
            .gaps()
            .iter()
            .map(|gap| (gap.subject.clone(), gap.reason.clone()))
            .collect();
        assert!(
            !gaps.contains(&("semantic input refused".into(), "coverage".into())),
            "receiptless Joined is history, not a coverage refusal: {gaps:?}"
        );
        let rows: Vec<_> = coordinator
            .registry()
            .instance_semantic_edges()
            .map(|row| {
                (
                    row.api_returns,
                    row.historical_only_returns,
                    row.lossy,
                    row.semantics.as_ref().map(|s| s.started()).unwrap_or(0),
                    row.semantics.as_ref().map(|s| s.completed()).unwrap_or(0),
                )
            })
            .collect();
        assert_eq!(
            rows,
            vec![(Some(1), 1, true, 0, 0)],
            "the receiptless call counts history-only without starting a machine"
        );
        let reasons: Vec<InstanceReason> = coordinator
            .registry()
            .instance_semantic_edges()
            .next()
            .unwrap()
            .reasons
            .iter()
            .copied()
            .collect();
        assert!(
            reasons.contains(&InstanceReason::SemanticLoss),
            "history-only admission discloses its reason: {reasons:?}"
        );
    }

    #[test]
    fn finalizer_mints_h3_disposition_from_complete_state() {
        // C5: the actual finalizer derives H3 disposition from staged
        // outcomes plus route-waiting/unpublished floors — never a bare
        // maximum token — and the coordinator stores it for the seal.
        use crate::semantic_capture::Invalidation;
        use crate::semantics_objects::journal::H3DispositionEvidence;

        let pid = std::process::id();
        let mut coordinator = InventoryCoordinator::new(
            Scope::Pid(pid),
            HookRegistry::builtin(),
            Vec::new(),
            OsProcessSource,
            RegistryLimits::default_limits(),
        )
        .unwrap();
        let fixture = HistoryFixture::new();
        let mut lane =
            AttestedSemanticLane::start(fixture.subset(), &Scope::Pid(pid), BackendSelection::Auto)
                .expect("shell lane starts");
        let detailed = lane.domain();
        let commit = |coordinator: &mut InventoryCoordinator<OsProcessSource>,
                      lane: &mut AttestedSemanticLane,
                      report: TickReport| {
            let batch = SemanticBatch::from_tick_report(detailed, report, Vec::new(), 130).unwrap();
            coordinator.stage_semantic_batch(batch);
            coordinator
                .commit_batch_with_semantics(false, Some(lane))
                .unwrap();
            coordinator.take_h3_disposition()
        };
        let invalidation = |position: u64| {
            TickOutcome::Invalidation(Invalidation::scripted(
                detailed,
                crate::semantic_capture::InvalidationScope::CoverageFailed,
                Some(position),
            ))
        };
        // A later staged outcome while earlier routing pends: the
        // maximum is 2 but position 1 is undisposed, and the evidence
        // says so instead of claiming 2 disposed.
        let evidence = commit(
            &mut coordinator,
            &mut lane,
            TickReport::scripted_with_disposition(
                vec![invalidation(2)],
                Vec::new(),
                Some(1),
                None,
                false,
            ),
        );
        assert!(matches!(
            evidence,
            H3DispositionEvidence::Clean {
                staged_max: 2,
                pending_floor: Some(1),
            }
        ));
        // The maximum is monotone over previous evidence; the pending
        // floor is always the current one.
        let evidence = commit(
            &mut coordinator,
            &mut lane,
            TickReport::scripted_with_disposition(
                vec![invalidation(1)],
                Vec::new(),
                None,
                None,
                false,
            ),
        );
        assert!(matches!(
            evidence,
            H3DispositionEvidence::Clean {
                staged_max: 2,
                pending_floor: None,
            }
        ));
        // A shed position never certifies: the minimum shed is a loss
        // barrier, even above the staged maximum.
        let evidence = commit(
            &mut coordinator,
            &mut lane,
            TickReport::scripted_with_disposition(
                vec![invalidation(4)],
                Vec::new(),
                None,
                Some(9),
                false,
            ),
        );
        assert!(matches!(
            evidence,
            H3DispositionEvidence::StagedLoss { barrier: 9 }
        ));
    }

    #[test]
    fn finalizer_loss_persists_until_seal_acknowledges() {
        // Carryover 5 + N1: a minted loss barrier is never overwritten
        // by a later clean batch before the seal consumes it; only the
        // seal's explicit void acknowledgement releases the next mint
        // into Clean.
        use crate::semantic_capture::Invalidation;
        use crate::semantics_objects::journal::H3DispositionEvidence;

        let pid = std::process::id();
        let mut coordinator = InventoryCoordinator::new(
            Scope::Pid(pid),
            HookRegistry::builtin(),
            Vec::new(),
            OsProcessSource,
            RegistryLimits::default_limits(),
        )
        .unwrap();
        let fixture = HistoryFixture::new();
        let mut lane =
            AttestedSemanticLane::start(fixture.subset(), &Scope::Pid(pid), BackendSelection::Auto)
                .expect("shell lane starts");
        let detailed = lane.domain();
        let commit = |coordinator: &mut InventoryCoordinator<OsProcessSource>,
                      lane: &mut AttestedSemanticLane,
                      report: TickReport| {
            let batch = SemanticBatch::from_tick_report(detailed, report, Vec::new(), 130).unwrap();
            coordinator.stage_semantic_batch(batch);
            coordinator
                .commit_batch_with_semantics(false, Some(lane))
                .unwrap();
            coordinator.take_h3_disposition()
        };
        let invalidation = |position: u64| {
            TickOutcome::Invalidation(Invalidation::scripted(
                detailed,
                crate::semantic_capture::InvalidationScope::CoverageFailed,
                Some(position),
            ))
        };
        let loss = commit(
            &mut coordinator,
            &mut lane,
            TickReport::scripted_with_disposition(
                vec![invalidation(4)],
                Vec::new(),
                None,
                Some(9),
                false,
            ),
        );
        assert!(matches!(
            loss,
            H3DispositionEvidence::StagedLoss { barrier: 9 }
        ));
        // A later clean batch must not overwrite the unconsumed loss.
        let still = commit(
            &mut coordinator,
            &mut lane,
            TickReport::scripted_with_disposition(
                vec![invalidation(10)],
                Vec::new(),
                None,
                None,
                false,
            ),
        );
        assert!(
            matches!(still, H3DispositionEvidence::StagedLoss { barrier: 9 }),
            "unconsumed loss survives a clean batch: {still:?}"
        );
        // The seal's void acknowledgement releases the next mint into
        // Clean, restarting the maximum above the voided barrier.
        coordinator.acknowledge_h3_void(10);
        let released = commit(
            &mut coordinator,
            &mut lane,
            TickReport::scripted_with_disposition(
                vec![invalidation(11)],
                Vec::new(),
                None,
                None,
                false,
            ),
        );
        assert!(
            matches!(
                released,
                H3DispositionEvidence::Clean {
                    staged_max: 11,
                    pending_floor: None,
                }
            ),
            "acknowledged loss releases into Clean: {released:?}"
        );
    }

    // Namespace controls over the existing H3 algorithm fixture. The lane's
    // native I/O is substituted: these are not installed Session qualification.
    fn namespace_report(domain: NativeDomainId, position: u64) -> TickReport {
        TickReport::scripted_with_disposition(
            vec![TickOutcome::Invalidation(
                crate::semantic_capture::Invalidation::scripted(
                    domain,
                    crate::semantic_capture::InvalidationScope::CoverageFailed,
                    Some(position),
                ),
            )],
            Vec::new(),
            None,
            None,
            false,
        )
    }

    fn namespace_commit(
        coordinator: &mut InventoryCoordinator<OsProcessSource>,
        lane: &mut AttestedSemanticLane,
        position: u64,
    ) -> crate::semantics_objects::journal::H3DispositionEvidence {
        let batch = SemanticBatch::from_tick_report(
            lane.domain(),
            namespace_report(lane.domain(), position),
            Vec::new(),
            130,
        )
        .unwrap();
        coordinator.stage_semantic_batch(batch);
        coordinator
            .commit_batch_with_semantics(false, Some(lane))
            .unwrap();
        coordinator.take_h3_disposition()
    }

    #[test]
    fn h3_session_namespace_refuses_new_lane_before_old_completion() {
        use crate::semantics_objects::journal::H3DispositionEvidence;
        let pid = std::process::id();
        let mut coordinator = InventoryCoordinator::new(
            Scope::Pid(pid),
            HookRegistry::builtin(),
            Vec::new(),
            OsProcessSource,
            RegistryLimits::default_limits(),
        )
        .unwrap();
        let fixture = HistoryFixture::new();
        let mut a =
            AttestedSemanticLane::start(fixture.subset(), &Scope::Pid(pid), BackendSelection::Auto)
                .unwrap();
        let mut b =
            AttestedSemanticLane::start(fixture.subset(), &Scope::Pid(pid), BackendSelection::Auto)
                .unwrap();
        assert_ne!(a.domain(), b.domain());
        assert!(matches!(
            namespace_commit(&mut coordinator, &mut a, 9),
            H3DispositionEvidence::Clean {
                staged_max: 9,
                pending_floor: None
            }
        ));
        let foreign = namespace_commit(&mut coordinator, &mut b, 1);
        assert!(
            matches!(
                foreign,
                H3DispositionEvidence::Clean {
                    staged_max: 0,
                    pending_floor: None
                }
            ),
            "without complete-A proof B must not mint using A's numeric finalizer namespace: {foreign:?}"
        );
    }

    #[test]
    fn h3_session_namespace_foreign_drop_cannot_poison_active_lane() {
        use crate::semantics_objects::journal::H3DispositionEvidence;
        let pid = std::process::id();
        let mut coordinator = InventoryCoordinator::new(
            Scope::Pid(pid),
            HookRegistry::builtin(),
            Vec::new(),
            OsProcessSource,
            RegistryLimits::default_limits(),
        )
        .unwrap();
        let fixture = HistoryFixture::new();
        let mut a =
            AttestedSemanticLane::start(fixture.subset(), &Scope::Pid(pid), BackendSelection::Auto)
                .unwrap();
        let b =
            AttestedSemanticLane::start(fixture.subset(), &Scope::Pid(pid), BackendSelection::Auto)
                .unwrap();
        assert!(matches!(
            namespace_commit(&mut coordinator, &mut a, 3),
            H3DispositionEvidence::Clean {
                staged_max: 3,
                pending_floor: None
            }
        ));
        let batch = SemanticBatch::from_tick_report(
            b.domain(),
            namespace_report(b.domain(), 99),
            Vec::new(),
            130,
        )
        .unwrap();
        coordinator.stage_semantic_batch(batch);
        coordinator
            .commit_batch_with_semantics(false, Some(&mut a))
            .unwrap();
        let fresh = namespace_commit(&mut coordinator, &mut a, 4);
        assert!(
            matches!(
                fresh,
                H3DispositionEvidence::Clean {
                    staged_max: 4,
                    pending_floor: None
                }
            ),
            "foreign dropped work must not insert numeric loss into A's finalizer namespace: {fresh:?}"
        );
    }
}

#[cfg(test)]
mod promotion_lifecycle_tests {
    //! DR37 coordinator entries: pair liveness re-validates a taken
    //! pair against the live registry, install consumes a
    //! proof-gated lane plus pre-reserved capacity, and retire
    //! disposes a genuinely completed domain before the joint owner
    //! is replaced. The subset-shape precheck is pure (see the
    //! lifecycle module); the baseline agreement reuses the tested
    //! `matches_request`.
    use super::*;
    use crate::attach::Scope;
    use crate::attach::capture::NativeDomainId;
    use crate::discovery::caller_registry::{
        ImageAuthority, ModuleKey, OsProcessSource, RegistryLimits,
    };
    use crate::discovery::hooks::HookRegistry;
    use crate::inventory_promotion::lifecycle::SessionNativeCompletion;
    use crate::inventory_promotion::{PromotionPair, PromotionRefusal};
    use crate::inventory_semantics::SemanticBatch;
    use p11scope_ebpf_common::ImageIdentity;
    use std::collections::BTreeSet;

    fn image() -> ImageIdentity {
        ImageIdentity {
            task_cookie: 41,
            exec_id: 42,
        }
    }

    fn pin() -> Arc<PidPin> {
        Arc::new(PidPin::open(std::process::id()).expect("the test process pins itself"))
    }

    fn domain() -> NativeDomainId {
        NativeDomainId::try_mint().expect("test domain mints")
    }

    fn module_key(ino: u64) -> ModuleKey {
        ModuleKey::physical(8, 1, ino, Some(format!("sha-{ino}")), "/lib/x.so")
    }

    fn binding(caller: u32, dom: NativeDomainId) -> SemanticCallerBinding {
        SemanticCallerBinding::scripted(
            CallerId(caller),
            module_key(100 + caller as u64),
            dom,
            image(),
            pin(),
        )
    }

    fn coordinator() -> InventoryCoordinator<OsProcessSource> {
        InventoryCoordinator::new(
            Scope::Pid(std::process::id()),
            HookRegistry::builtin(),
            Vec::new(),
            OsProcessSource,
            RegistryLimits::default_limits(),
        )
        .expect("test coordinator builds")
    }

    fn charged(coordinator: &InventoryCoordinator<OsProcessSource>) -> usize {
        coordinator
            .registry
            .semantic_resource_snapshot()
            .charged_bytes
    }

    #[test]
    fn install_capacity_into_empty_set_moves_storage_and_lease() {
        let mut coordinator = coordinator();
        let before = charged(&coordinator);
        let capacity = coordinator
            .reserve_promotion_install()
            .expect("capacity reserves");
        let reserved = charged(&coordinator);
        assert!(
            reserved > before,
            "the reservation charges before install: {before} -> {reserved}"
        );
        coordinator.semantic_bindings.cursor = 5;
        coordinator
            .semantic_bindings
            .install_capacity(capacity)
            .expect("empty set installs");
        let set = &coordinator.semantic_bindings;
        assert_eq!(set.bindings.capacity(), 1);
        assert_eq!(set.index.capacity(), 3);
        // 7168, not MAX_INSTANCES: hashbrown bucket rounding, matching
        // the reservation-side assertion.
        assert_eq!(set.admission_images.capacity(), 7168);
        assert_eq!(set.cursor, 0, "install resets the fair-turn cursor");
        assert!(set.refresh_cursor.is_none());
        assert!(
            set.install_lease.is_some(),
            "the storage lease moves with the storage"
        );
        assert_eq!(
            charged(&coordinator),
            reserved,
            "install moves the charge, never duplicates or refunds it"
        );
    }

    #[test]
    fn install_capacity_refuses_occupied_set_untouched() {
        let mut coordinator = coordinator();
        coordinator
            .semantic_bindings
            .insert_for_test(binding(7, domain()))
            .expect("scripted binding inserts");
        let before = charged(&coordinator);
        let capacity = coordinator
            .reserve_promotion_install()
            .expect("capacity reserves");
        let reserved = charged(&coordinator);
        let returned = coordinator
            .semantic_bindings
            .install_capacity(capacity)
            .expect_err("occupied set refuses");
        assert_eq!(coordinator.semantic_bindings.len(), 1);
        assert!(
            coordinator.semantic_bindings.get(CallerId(7)).is_some(),
            "refused install keeps the retained binding"
        );
        assert!(coordinator.semantic_bindings.install_lease.is_none());
        drop(returned);
        assert_eq!(
            charged(&coordinator),
            before,
            "the refused capacity refunds by drop: {reserved} -> {}",
            charged(&coordinator)
        );
    }

    #[test]
    fn install_capacity_charges_zero_allocations() {
        let mut coordinator = coordinator();
        let capacity = coordinator
            .reserve_promotion_install()
            .expect("capacity reserves");
        let (installed, allocs, bytes) = crate::test_alloc::count_allocs_during(|| {
            coordinator.semantic_bindings.install_capacity(capacity)
        });
        installed.expect("empty set installs");
        assert_eq!(
            (allocs, bytes),
            (0, 0),
            "install moves storage, never grows"
        );
    }

    #[test]
    fn retire_domain_removes_only_the_retired_domain() {
        let mut set = SemanticBindingSet::new();
        let a = domain();
        let b = domain();
        set.insert_for_test(binding(1, a)).unwrap();
        set.insert_for_test(binding(2, a)).unwrap();
        set.insert_for_test(binding(3, b)).unwrap();
        set.admission_images.insert(
            CallerId(1),
            SemanticAdmissionHistory {
                domain: a,
                image: image(),
                incarnation: 1,
                generation: crate::inspect_system::MemberGeneration {
                    start_time: None,
                    exe: None,
                },
                pin: pin(),
                initial_scope_cut: false,
                pending_gap: None,
            },
        );
        set.admission_images.insert(
            CallerId(3),
            SemanticAdmissionHistory {
                domain: b,
                image: image(),
                incarnation: 1,
                generation: crate::inspect_system::MemberGeneration {
                    start_time: None,
                    exe: None,
                },
                pin: pin(),
                initial_scope_cut: false,
                pending_gap: None,
            },
        );
        let removed = set.retire_domain(a);
        assert_eq!(removed, vec![CallerId(1), CallerId(2)]);
        assert_eq!(set.len(), 1);
        assert!(set.get(CallerId(3)).is_some(), "B's binding survives");
        assert_eq!(set.index.get(&CallerId(3)), Some(&0), "index rebuilt");
        assert!(!set.admission_images.contains_key(&CallerId(1)));
        assert!(set.admission_images.contains_key(&CallerId(3)));
        assert!(set.retire_domain(a).is_empty(), "second retire is a no-op");
    }

    #[test]
    fn retire_joint_domain_refuses_foreign_completion() {
        let mut coordinator = coordinator();
        let before = charged(&coordinator);
        let err = coordinator
            .retire_joint_domain(SessionNativeCompletion::scripted(domain()))
            .expect_err("nothing live retires nothing");
        assert_eq!(err, JointRetireRefusal::NotLiveDomain);
        assert!(coordinator.semantic_finalizer.is_none());
        assert!(coordinator.refused_semantic_domains.is_empty());
        assert_eq!(charged(&coordinator), before);
    }

    #[test]
    fn retire_joint_domain_refuses_pending_work() {
        let mut coordinator = coordinator();
        let a = domain();
        let mut finalizer = SessionFinalizerState::new(a);
        finalizer.pending_drop = Some((7, false));
        coordinator.semantic_finalizer = Some(finalizer);
        let err = coordinator
            .retire_joint_domain(SessionNativeCompletion::scripted(a))
            .expect_err("pending work stays live");
        assert_eq!(err, JointRetireRefusal::PendingWork);
        let state = coordinator.semantic_finalizer.as_ref().expect("kept");
        assert_eq!(state.pending_drop, Some((7, false)));
        assert!(coordinator.refused_semantic_domains.is_empty());
    }

    #[test]
    fn retire_joint_domain_retires_namespace_and_replaces_owner() {
        let mut coordinator = coordinator();
        let a = domain();
        let b = domain();
        coordinator.semantic_finalizer = Some(SessionFinalizerState::new(a));
        coordinator
            .semantic_bindings
            .insert_for_test(binding(1, a))
            .unwrap();
        coordinator
            .semantic_bindings
            .insert_for_test(binding(3, b))
            .unwrap();
        coordinator.proven_images.insert((a, 9), 9);
        coordinator.proven_images.insert((b, 9), 9);
        coordinator.tail_uncertain.insert(CallerId(1));
        coordinator.complete_scanned.insert(CallerId(1));
        let clean = charged(&coordinator);
        coordinator
            .joint_capture
            .ledger_mut()
            .charge_h8open(0, 100)
            .expect("old ledger charges");
        let dirty = charged(&coordinator);
        assert!(
            dirty > clean,
            "the old ledger holds charges: {clean} -> {dirty}"
        );
        coordinator
            .retire_joint_domain(SessionNativeCompletion::scripted(a))
            .expect("quiescent A retires");
        assert!(coordinator.semantic_finalizer.is_none());
        assert!(coordinator.refused_semantic_domains.contains(&a));
        assert!(coordinator.semantic_bindings.get(CallerId(1)).is_none());
        assert!(coordinator.semantic_bindings.get(CallerId(3)).is_some());
        assert!(!coordinator.proven_images.contains_key(&(a, 9)));
        assert!(coordinator.proven_images.contains_key(&(b, 9)));
        assert!(!coordinator.tail_uncertain.contains(&CallerId(1)));
        assert!(!coordinator.complete_scanned.contains(&CallerId(1)));
        assert_eq!(
            charged(&coordinator),
            clean,
            "the replaced owner's exact charges refund, nothing else moves"
        );
        // A stays refused; B stages into the fresh namespace.
        coordinator.stage_semantic_batch(SemanticBatch::scripted(a, Vec::new(), 1));
        assert!(
            coordinator
                .semantic_finalizer
                .as_ref()
                .is_none_or(|state| state.pending_semantic.is_none()),
            "A never stages again"
        );
        coordinator.stage_semantic_batch(SemanticBatch::scripted(b, Vec::new(), 2));
        assert!(
            coordinator
                .semantic_finalizer
                .as_ref()
                .is_some_and(|state| state.domain == b && state.pending_semantic.is_some()),
            "B stages into a fresh namespace"
        );
    }

    /// Admit the test process itself through the real adapter path
    /// (/proc reads, no fixtures): reconcile, apply, then resolve.
    fn admit_self(coordinator: &mut InventoryCoordinator<OsProcessSource>) -> CallerId {
        let pid = std::process::id();
        let observed = BTreeSet::from([pid]);
        let events = coordinator.adapter_mut().reconcile(
            &observed,
            &mut |_| ImageAuthority::ScanPinned,
            100,
        );
        coordinator.apply_reconcile_events(&events, 100);
        coordinator
            .adapter()
            .live_id(pid)
            .expect("the live test process admits")
    }

    fn liveness_pair(caller: CallerId, module: ModuleId) -> PromotionPair {
        PromotionPair::new(caller.0, module.0)
    }

    #[test]
    fn pair_liveness_refuses_unknown_caller() {
        let coordinator = coordinator();
        let err = coordinator
            .validate_selected_pair_liveness(liveness_pair(CallerId(999), ModuleId(999)), &pin())
            .expect_err("unknown caller refuses");
        assert_eq!(err, PromotionRefusal::UnknownCaller);
    }

    #[test]
    fn pair_liveness_accepts_mapped_pair_with_continuous_pin() {
        let mut coordinator = coordinator();
        let caller = admit_self(&mut coordinator);
        let key = module_key(777);
        let module = coordinator
            .registry_mut()
            .scripted_module_edge(key.clone(), caller);
        let live = coordinator
            .validate_selected_pair_liveness(liveness_pair(caller, module), &pin())
            .expect("mapped pair with its own pin validates");
        assert_eq!(
            live, key,
            "the live provider key returns for the subset proof"
        );
        let record = coordinator.adapter().record(caller).expect("record");
        assert!(
            record.start_time.is_some(),
            "real admission observes start-time: the continuity check ran, not skipped"
        );
    }

    /// A spawned sleeper, reaped on drop: the retired-caller twin
    /// needs a genuine exit, which reconcile detects and retires.
    struct LiveChild(std::process::Child);

    impl LiveChild {
        fn spawn() -> Self {
            Self(
                std::process::Command::new("sleep")
                    .arg("120")
                    .stdin(std::process::Stdio::null())
                    .stdout(std::process::Stdio::null())
                    .spawn()
                    .expect("sleep spawns"),
            )
        }

        fn pid(&self) -> u32 {
            self.0.id()
        }

        fn kill_and_wait(&mut self) {
            self.0.kill().expect("sleeper dies");
            self.0.wait().expect("sleeper reaped");
        }
    }

    impl Drop for LiveChild {
        fn drop(&mut self) {
            let _ = self.0.kill();
            let _ = self.0.wait();
        }
    }

    #[test]
    fn pair_liveness_refuses_retired_caller() {
        let mut child = LiveChild::spawn();
        let mut coordinator = coordinator();
        let observed = BTreeSet::from([child.pid()]);
        let events = coordinator.adapter_mut().reconcile(
            &observed,
            &mut |_| ImageAuthority::ScanPinned,
            100,
        );
        coordinator.apply_reconcile_events(&events, 100);
        let caller = coordinator
            .adapter()
            .live_id(child.pid())
            .expect("the live child admits");
        child.kill_and_wait();
        let events = coordinator.adapter_mut().reconcile(
            &BTreeSet::new(),
            &mut |_| ImageAuthority::ScanPinned,
            200,
        );
        coordinator.apply_reconcile_events(&events, 200);
        let record = coordinator.adapter().record(caller).expect("record kept");
        assert!(record.retired, "reconcile retires the exited child");
        let err = coordinator
            .validate_selected_pair_liveness(liveness_pair(caller, ModuleId(999)), &pin())
            .expect_err("retired caller refuses");
        assert_eq!(err, PromotionRefusal::CallerRetired);
    }

    #[test]
    fn pair_liveness_refuses_changed_caller() {
        let mut coordinator = coordinator();
        let caller = admit_self(&mut coordinator);
        let parent = std::os::unix::process::parent_id();
        assert_ne!(parent, std::process::id(), "test has a distinct parent");
        let parent_pin = Arc::new(PidPin::open(parent).expect("parent pins"));
        let err = coordinator
            .validate_selected_pair_liveness(liveness_pair(caller, ModuleId(999)), &parent_pin)
            .expect_err("another pid's pin refuses");
        assert_eq!(err, PromotionRefusal::CallerChanged);
    }

    #[test]
    fn pair_liveness_refuses_unloaded_provider() {
        let mut coordinator = coordinator();
        let caller = admit_self(&mut coordinator);
        let err = coordinator
            .validate_selected_pair_liveness(liveness_pair(caller, ModuleId(999)), &pin())
            .expect_err("unknown module refuses");
        assert_eq!(err, PromotionRefusal::ProviderUnloaded);
    }

    #[test]
    fn pair_liveness_refuses_changed_provider() {
        let mut coordinator = coordinator();
        let caller = admit_self(&mut coordinator);
        // A live module edged to another caller: the provider exists
        // but is no longer this caller's pair.
        let module = coordinator
            .registry_mut()
            .scripted_module_edge(module_key(778), CallerId(999));
        let err = coordinator
            .validate_selected_pair_liveness(liveness_pair(caller, module), &pin())
            .expect_err("unpaired live module refuses");
        assert_eq!(err, PromotionRefusal::ProviderChanged);
    }
}
