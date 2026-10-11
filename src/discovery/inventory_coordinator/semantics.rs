//! SPDX-License-Identifier: GPL-3.0-or-later
//! Sole subset minter over the coordinator's retained, accepted sources.

use super::*;
use crate::discovery::caller_registry::OsProcessSource;
use crate::discovery::caller_registry::instance_input::{
    CallEvidence, CallStanding, ConversionRefusal, InstanceReason, admit_call_from_evidence,
    admit_registration_from_coverage, finalize_invalidation, tail_loss_from_negative,
};
use crate::discovery::instances::{MAX_INSTANCES, MAX_PENDING};
use crate::discovery::native_binding::CallerLookup;
use crate::inventory_semantics::{LaneNegative, SemanticRefusal};
use crate::process::PidPin;
use crate::semantic_capture::{
    CurrentReceiptRefusal, InvalidationScope, PhysicalSemanticGap, TickOutcome,
};
use p11scope_ebpf_common::ImageIdentity;
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

/// One accepted semantic caller: a CallerId and physical ModuleKey bound to
/// the original retained caller custody (one stable duplicated pidfd Arc)
/// and this Detailed domain's fresh full image. Move-only coordinator
/// proof: private fields, redacted Debug, no Clone/Default/from_parts.
/// Equal numeric cookies from other producers never satisfy this binding:
/// every ticket comparison carries its domain.
pub(crate) struct SemanticCallerBinding {
    caller: CallerId,
    module: ModuleKey,
    domain: NativeDomainId,
    image: ImageIdentity,
    pin: Arc<PidPin>,
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
    pub(crate) fn module(&self) -> &ModuleKey {
        &self.module
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
            module,
            domain,
            image,
            pin,
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
    ImageUnproven(UnboundReason),
    Capacity,
}

impl SemanticBindingRefusal {
    #[cfg_attr(
        not(test),
        expect(
            dead_code,
            reason = "bind/refresh refusals are currently silent; code() awaits Task6 refusal-visibility wiring"
        )
    )]
    pub(crate) const fn code(self) -> &'static str {
        match self {
            Self::NoLiveCaller => "no_live_caller",
            Self::MappingIncomplete => "mapping_incomplete",
            Self::DomainConflict => "domain_conflict",
            Self::ModuleConflict => "module_conflict",
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
}

impl SemanticBindingSet {
    pub(crate) fn new() -> Self {
        Self {
            bindings: Vec::new(),
            index: HashMap::new(),
            cursor: 0,
            limit: MAX_INSTANCES,
        }
    }

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

    fn insert(&mut self, binding: SemanticCallerBinding) -> Result<(), SemanticBindingRefusal> {
        debug_assert!(!self.index.contains_key(&binding.caller));
        if self.bindings.len() >= self.limit {
            return Err(SemanticBindingRefusal::Capacity);
        }
        self.index.insert(binding.caller, self.bindings.len());
        self.bindings.push(binding);
        Ok(())
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
            module,
            domain,
            image,
            pin,
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
                module,
                domain,
                image,
                pin,
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
            if existing.module() != module {
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
            return;
        }
        if self.pending_semantic.is_some() {
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
            return;
        }
        self.pending_semantic = Some(batch);
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
                if self.pending_semantic.take().is_some() {
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

    /// Assemble tail gaps for genuinely uncertain bound callers: one
    /// minted gap per bound caller with a proven H0 association for its
    /// exact current image, plus the affected domains for cut-failure
    /// handling. Genuine gaps before the first accepted H0 scan keep
    /// conservative refusal: no mint, no cut, audited disclosure, while
    /// the staged physical uncertainty stands on its own.
    fn assemble_tail_gaps(&mut self) -> (Vec<PhysicalSemanticGap>, Vec<NativeDomainId>) {
        let mut gaps = Vec::new();
        let mut domains = Vec::new();
        for caller in std::mem::take(&mut self.tail_uncertain) {
            let Some(binding) = self.semantic_bindings.get(caller) else {
                continue;
            };
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
        if let Some(pending) = self.pending_semantic.take() {
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
            return;
        }
        let observed_ns = batch.observed_ns();
        let (outcomes, current, negatives) = batch.into_parts();
        // Receipts: presence proves H0 association either way; only the
        // lane owner's validation admits coverage.
        let mut coverages = Vec::new();
        for receipt in &current {
            self.observe_proven_image(receipt);
            match lane.validate_current(receipt) {
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
        // Negatives first: lane facts, then H0 invalidations. The domain
        // maximum fences conversion as defense-in-depth; the registry's
        // staged-before-positive order enforces scope precision. A cut
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
        for outcome in outcomes {
            match outcome {
                TickOutcome::Call(call) => {
                    if let Some(evidence) = CallEvidence::from_routed(call) {
                        calls.push(evidence);
                    }
                }
                TickOutcome::Invalidation(invalidation) => {
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
                            if let Some(at) = invalidation.position() {
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
                TickOutcome::Other(_) => {}
            }
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
            Result<
                crate::discovery::caller_registry::instance_input::AdmittedInstanceCall,
                ConversionRefusal,
            >,
        )> = calls
            .into_iter()
            .map(|evidence| {
                let found = self
                    .semantic_bindings
                    .find_by_image(evidence.domain(), evidence.image());
                let Some(binding) = found else {
                    return (None, Err(ConversionRefusal::Custody));
                };
                let caller = binding.caller();
                let coverage = coverages.iter().find(|coverage| {
                    coverage.domain() == evidence.domain()
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
                    admit_call_from_evidence(evidence, binding, subset, standing, barrier),
                )
            })
            .collect();
        for (caller, result) in staged {
            match result {
                Ok(input) => self.registry.observe_instance_semantic(input),
                Err(reason) => self.conversion_gap(caller, reason),
            }
        }
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
    use p11scope_ebpf_common::{Event, EventRecord, InstanceContinuity, InstanceStamp, capture};
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
        let module = ModuleKey::physical(7, 7, 777, None, "/task3/provider.so");
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
        let fixture = HistoryFixture::new();
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
            admit_registration_from_coverage(&coverage, binding, r0, 100, None)
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
            EventRecord {
                event: Event {
                    slot: init_slot,
                    session: 7,
                    mechanism: 0x000d,
                    capture: capture::MECHANISM_VALUE | capture::OUTPUT_NON_NULL,
                    rv: 0,
                    ts_ns: 110,
                    image,
                    ..Default::default()
                },
                continuity: InstanceContinuity {
                    entry_stamp: stamp,
                    return_stamp: stamp,
                    entry_ip: 0x2200,
                },
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
}
