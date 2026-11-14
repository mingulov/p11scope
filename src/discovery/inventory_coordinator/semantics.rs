//! SPDX-License-Identifier: GPL-3.0-or-later
//! SPDX-FileCopyrightText: 2026 Denis Mingulov <denis@mingulov.com>
//! Sole subset minter over the coordinator's retained, accepted sources.

use super::*;
use crate::discovery::identity::pin_manifest_objects_deferred_in_views_with_prior;

#[path = "semantics/finalizer.rs"]
mod finalizer;
#[path = "semantics/joint.rs"]
mod joint;
pub(crate) use joint::CompletedJointFinish;
pub(crate) use joint::SealDiagnosis;
#[path = "semantics/promotion.rs"]
mod promotion;
#[cfg(test)]
use crate::discovery::caller_registry::OsProcessSource;
use crate::discovery::caller_registry::instance_input::{
    AdmittedInstanceCall, CallEvidence, CallStanding, ConversionRefusal, InstanceReason,
    RegistryInstanceId, admit_call_from_evidence, admit_registration_from_coverage,
    finalize_invalidation, tail_loss_from_negative,
};
use crate::discovery::caller_registry::{CallerLifecycle, ModuleLifecycle, module_init};
use crate::discovery::instances::{MAX_INSTANCES, MAX_PENDING, Route};
#[cfg(test)]
use crate::discovery::native_binding::CallerLookup;
use crate::inventory_promotion::lifecycle::{SelectedActivationProof, SessionNativeCompletion};
use crate::inventory_promotion::{PromotionPair, PromotionRefusal};
use crate::inventory_semantics::selected::ProvisionalSelectedLane;
use crate::inventory_semantics::{
    AdmissionPreparationError, AdmissionUnavailableSite, PreparedSemanticAdmission,
    SemanticProviderTarget,
};
use crate::inventory_semantics::{AttestedSemanticLane, LaneNegative, SemanticRefusal};
use crate::process::PidPin;
use crate::semantic_capture::{
    CurrentReceiptRefusal, Endpoint, InvalidationScope, PhysicalSemanticGap, TickOutcome,
    unjoined_shed_counts,
};
use crate::semantics_edge::resources::{OWNED_ALLOCATION_PADDING, ResourceLease};
pub(super) use finalizer::SessionFinalizerState;
pub(crate) use finalizer::{
    JointPublicationPorts, SessionAuditInput, SessionDisposedAuditInput, SessionH3Finalizer,
    UnauditedH3Take,
};
pub(super) use joint::JointCommitInput;
pub(crate) use joint::PreparedSemanticBatch;
use joint::{PendingSemanticBatch, PreparedAdmission, PreparedH3};
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
                .summary(slot.object)
                .zip(other.pins.summary(slot.object))
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
    ///
    /// The key-and-digest match below is a selector: the maps key is not
    /// unique, so a colliding file can pass it. Binding authority is the
    /// H0 receipt, which keeps only ranges whose `map_files` identity
    /// matches the observer's own self-mapping of the held fd.
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
        let Some(pin) = self.pins.summary(object) else {
            return false;
        };
        if pin.sha256 != sha256 {
            return false;
        }
        // A pre-6.8 overlay split also proves through the entry-carried
        // maps rendering; see `PinnedObjects::object_matches_key`.
        self.pins
            .object_matches_key(object, *dev_major, *dev_minor, *ino)
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

/// Find the retained provider object a live module key names, over the
/// merged post-acceptance pins (the same id space the subset carries:
/// matching pre-merge input pins would name the wrong objects).
/// Mirrors [`AttestedSubset::proves_provider_module`]: physical device
/// identity plus the retained whole-file digest. Paths and matching
/// content in another inode cannot supply this association.
fn provider_object_for_key(pins: &PinnedObjects, module: &ModuleKey) -> Option<PinnedObjectId> {
    let ModuleKey::Physical {
        dev_major,
        dev_minor,
        ino,
        sha256: Some(sha256),
    } = module
    else {
        return None;
    };
    if sha256.is_empty() {
        return None;
    }
    pins.pinned()
        .find(|pin| {
            pin.sha256 == sha256 && pins.object_matches_key(pin.id, *dev_major, *dev_minor, *ino)
        })
        .map(|pin| pin.id)
}

/// Joint-label pre-filter: whether a module key names this retained
/// provider object. The third mirror of
/// [`AttestedSubset::proves_provider_module`]: the SAME physical-key join
/// through the single [`PinnedObjects::object_matches_key`] predicate —
/// including the entry-carried maps rendering on a pre-6.8 overlay split —
/// so a split-proved binding labels identically at admission, labeling,
/// and selection. Key-only: a positive here still requires the full proof.
pub(crate) fn module_key_names_object(
    pins: &PinnedObjects,
    object: PinnedObjectId,
    key: &ModuleKey,
) -> bool {
    let ModuleKey::Physical {
        dev_major,
        dev_minor,
        ino,
        ..
    } = key
    else {
        return false;
    };
    pins.object_matches_key(object, *dev_major, *dev_minor, *ino)
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
    /// Already-retained `--prearm-module` pin usage (packet 6.13 round-3,
    /// finding 3), charged against the shared manifest+pre-arm budget when
    /// these manifests pin. Set by the coordinator before first use.
    prearm_prior: (usize, u64),
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
            prearm_prior: (0, 0),
        }
    }

    /// Records the run-retained pre-arm pin usage the manifest side must
    /// charge (packet 6.13 round-3, finding 3). The coordinator calls this
    /// from `set_prearm_pinning`, before any preparation memoizes.
    pub(crate) fn set_prearm_prior(&mut self, objects: usize, bytes: u64) {
        self.prearm_prior = (objects, bytes);
    }

    #[cfg(test)]
    pub(crate) fn prearm_prior(&self) -> (usize, u64) {
        self.prearm_prior
    }

    pub(crate) fn prepare(&mut self, engine: &Engine) -> SubsetPreparation {
        let retained = self.retained_or_load(engine);
        prepare_retained_subset(engine, retained)
    }

    /// The no-manifest scan mint (DEMO-4): seed the accepted set
    /// from the engine's scan-discovered providers and build the
    /// subset with scan authorization. Only meaningful when no
    /// manifest was requested; the driver owns that gate.
    /// `scan_sources` carries the latest catalog lowering's
    /// reconciled modules and aggregate pins (the current scanned
    /// tables in a live capture); without them the mint falls back
    /// to the engine's own scan snapshot.
    pub(crate) fn prepare_scan(
        &mut self,
        engine: &Engine,
        scan_sources: Option<(Vec<ReconciledModule>, PinnedObjects)>,
    ) -> SubsetPreparation {
        let retained = self.retained_or_load(engine);
        build_subset_from_accepted(
            engine,
            accept_retained_inputs(engine, retained, true, scan_sources),
            None,
            true,
        )
    }

    /// The memoized retained inputs, loaded once from the operator
    /// paths. Shared by the full mint and the selected restriction so
    /// both read the same retained files.
    fn retained_or_load(&mut self, engine: &Engine) -> &RetainedInputs {
        let (prior_objects, prior_bytes) = self.prearm_prior;
        self.retained.get_or_insert_with(|| {
            let mut inputs = Vec::new();
            let mut refusals = Vec::new();
            let mut budget = CaptureWorkBudget::default();
            for path in &self.paths {
                let accepted = (|| -> Result<(ManifestInput, bool)> {
                    let manifest = read_manifest_file(path)?;
                    let pinning = pin_manifest_objects_deferred_in_views_with_prior(
                        &manifest,
                        &engine.views,
                        &mut budget,
                        prior_objects,
                        prior_bytes,
                    )
                    .map_err(|_| anyhow!("manifest pinning refused"))?;
                    let skipped = !pinning.skipped.is_empty();
                    Ok((
                        ManifestInput {
                            path: path.clone(),
                            manifest,
                            pins: pinning.pins,
                            stale: pinning.stale,
                        },
                        skipped,
                    ))
                })();
                match accepted {
                    // Never-stop: per-object skips keep the good pins and
                    // record one manifest-input refusal for the bad objects.
                    Ok((input, true)) => {
                        inputs.push(input);
                        refusals.push(SemanticRefusal::ManifestInput);
                    }
                    Ok((input, false)) => inputs.push(input),
                    Err(_) => refusals.push(SemanticRefusal::ManifestInput),
                }
            }
            RetainedInputs {
                inputs,
                refusals,
                requested: !self.paths.is_empty(),
            }
        })
    }
}

/// Read explicit inputs against the Inventory owner's retained sources. The
/// physical plan and its source ownership are never rebuilt or modified.
#[cfg(test)]
pub(crate) fn prepare_attested_subset(engine: &Engine, paths: &[PathBuf]) -> SubsetPreparation {
    SemanticInputs::new(paths.to_vec()).prepare(engine)
}

fn prepare_retained_subset(engine: &Engine, inputs: &RetainedInputs) -> SubsetPreparation {
    build_subset_from_accepted(
        engine,
        accept_retained_inputs(engine, inputs, false, None),
        None,
        false,
    )
}

/// Test seam for the no-manifest scan mint, mirroring
/// [`prepare_attested_subset`] with no operator inputs.
#[cfg(test)]
pub(crate) fn prepare_scan_attested_subset(engine: &Engine) -> SubsetPreparation {
    SemanticInputs::new(Vec::new()).prepare_scan(engine, None)
}

/// Manifests accepted against the retained scan, before claims: the
/// merged pin union (the id space the subset carries), the attested
/// manifests, the accepted provider objects and the refusals so far.
struct AcceptedRetainedInputs {
    pins: PinnedObjects,
    manifests: Vec<Manifest>,
    accepted: BTreeSet<PinnedObjectId>,
    refusals: Vec<SemanticRefusal>,
    requested: bool,
    /// DEMO-4 scan mint only: modules reconciled from the current
    /// per-view scan inputs, replacing the creation-time
    /// `engine.modules` snapshot (empty in live `--system`
    /// captures) as the subset's source set.
    scan_modules: Option<Vec<ReconciledModule>>,
}

/// Whether two views' table lists disagree for the sole-table gate: same
/// count but different tables (file offset, version, entries or NULL holes).
/// Runtime addresses differ across views by ASLR, walks differ by decode
/// completeness (a partial walk must not poison a full one), and live,
/// manifest, extension and unpinned marks are monotonic observations — none
/// of those refute "exactly one table", so none participate here.
fn scanned_tables_disagree(a: &[ScannedTable], b: &[ScannedTable]) -> bool {
    if a.len() != b.len() {
        return true;
    }
    a.iter().zip(b.iter()).any(|(x, y)| {
        x.file_offset != y.file_offset
            || x.version != y.version
            || x.entries != y.entries
            || x.null_entries != y.null_entries
    })
}

fn accept_retained_inputs(
    engine: &Engine,
    inputs: &RetainedInputs,
    seed_scan: bool,
    scan_sources: Option<(Vec<ReconciledModule>, PinnedObjects)>,
) -> AcceptedRetainedInputs {
    // This Inventory owner does not admit live Detailed selection claims.
    // Enabling that Engine path also requires incorporating its retained
    // claims/table latches here before preparing fresh semantic authority.
    let mut pins = engine.pinned.clone();
    let mut manifests = engine.manifests.clone();
    let mut accepted = BTreeSet::new();
    let mut refusals = inputs.refusals.clone();
    let scanned: Vec<_> = engine
        .modules
        .iter()
        .map(|module| module.scanned.clone())
        .collect();
    for input in &inputs.inputs {
        let outcome = (|| -> Result<_> {
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
        match outcome {
            Ok((manifest, candidate, provider)) => {
                pins = candidate;
                manifests.push(manifest);
                accepted.insert(provider);
            }
            Err(_) => refusals.push(SemanticRefusal::ManifestInput),
        }
    }
    // DEMO-4 scan seed: with no manifest requested, every provider
    // in the *current* scan inputs is a candidate; completeness in
    // `build_subset_from_accepted` still decides which ones mint.
    // The creation-time `engine.modules` snapshot is empty in live
    // `--system` captures, so the modules and their pins come from
    // the engine's current scan snapshot (falling back to the
    // snapshot modules already retained when no scan input exists,
    // as in unit fixtures).
    let mut scan_modules = None;
    if seed_scan && !inputs.requested {
        // Current scanned tables come from the latest catalog
        // lowering when the coordinator stashed them (live
        // captures); otherwise fall back to the engine's own scan
        // snapshot and creation-time modules.
        let (modules, scan_pins) = match scan_sources {
            Some(sources) => sources,
            None => engine.scan_reconciled_snapshot(),
        };
        if modules.is_empty() {
            for module in &engine.modules {
                if pins.file_for(module.object).is_some() {
                    accepted.insert(module.object);
                }
            }
        } else {
            // One entry per provider object: a multi-process
            // browser maps one provider in several views, and the
            // completeness claim is per object — a partial walk in
            // one view must not poison a full walk of the same
            // tables in another. Keep a complete entry when one
            // exists (all tables full, no affecting unpinned
            // entries, matching the claims' completeness rule).
            let entry_complete = |module: &ReconciledModule| {
                module.scanned.tables.iter().all(|table| {
                    table.walk == "full"
                        && !table.unpinned.iter().any(|entry| {
                            crate::kinds::descriptor(&entry.subject).is_none_or(|descriptor| {
                                descriptor != p11scope_ebpf_common::SlotSemantics::COUNT_ONLY
                            })
                        })
                })
            };
            let mut by_object: std::collections::BTreeMap<_, ReconciledModule> =
                std::collections::BTreeMap::new();
            // Sticky per-object disagreement: once two views of an
            // object disagree (count or content), no later agreeing
            // view may OR the finished flag back.
            let mut disagreed: BTreeSet<PinnedObjectId> = BTreeSet::new();
            for module in modules {
                match by_object.entry(module.object) {
                    std::collections::btree_map::Entry::Vacant(slot) => {
                        slot.insert(module);
                    }
                    std::collections::btree_map::Entry::Occupied(mut slot) => {
                        let kept_tables = slot.get().scanned.tables.len();
                        let incoming_tables = module.scanned.tables.len();
                        if incoming_tables != kept_tables {
                            // Views disagree on table count: keep the maximum
                            // (fail closed for the sole-table gate, which
                            // needs exactly one), and clear the finished
                            // flag so the sole leg refuses even for 0-vs-1.
                            disagreed.insert(module.object);
                            if incoming_tables > kept_tables {
                                let mut kept = module;
                                kept.scanned.tables_scan_finished = false;
                                slot.insert(kept);
                            } else {
                                slot.get_mut().scanned.tables_scan_finished = false;
                            }
                        } else if scanned_tables_disagree(
                            &slot.get().scanned.tables,
                            &module.scanned.tables,
                        ) {
                            // Same count, different tables: keep the
                            // complete entry as before, but clear finished
                            // so the sole leg refuses the disagreement.
                            disagreed.insert(module.object);
                            if !entry_complete(slot.get()) && entry_complete(&module) {
                                let mut kept = module;
                                kept.scanned.tables_scan_finished = false;
                                slot.insert(kept);
                            } else {
                                slot.get_mut().scanned.tables_scan_finished = false;
                            }
                        } else {
                            // Agreeing views: keep the complete entry as
                            // before; finished when either view finished (a
                            // finished view proves exactly-one, and agreeing
                            // unfinished views do not refute it). The
                            // post-loop clear below keeps disagreement
                            // sticky against this OR.
                            let finished = slot.get().scanned.tables_scan_finished
                                || module.scanned.tables_scan_finished;
                            if !entry_complete(slot.get()) && entry_complete(&module) {
                                let mut kept = module;
                                kept.scanned.tables_scan_finished = finished;
                                slot.insert(kept);
                            } else {
                                slot.get_mut().scanned.tables_scan_finished = finished;
                            }
                        }
                    }
                }
            }
            for (object, module) in by_object.iter_mut() {
                if disagreed.contains(object) {
                    module.scanned.tables_scan_finished = false;
                }
            }
            let modules: Vec<_> = by_object.into_values().collect();
            for module in &modules {
                accepted.insert(module.object);
            }
            pins = scan_pins;
            scan_modules = Some(modules);
        }
    }
    AcceptedRetainedInputs {
        pins,
        manifests,
        accepted,
        refusals,
        requested: inputs.requested,
        scan_modules,
    }
}

/// Build the attested subset over accepted manifests: claims, the
/// rival-aware plan and the complete-provider selection, optionally
/// intersected with one clicked provider. `None` restriction is the
/// full mint, unchanged; `Some` restriction covers exactly the named
/// providers with identical claims, degraded handling and descriptor
/// decisions — a partition of the full closure, never a narrower
/// re-plan that could ignore rival claims.
fn build_subset_from_accepted(
    engine: &Engine,
    accepted: AcceptedRetainedInputs,
    restrict: Option<&BTreeSet<PinnedObjectId>>,
    scan_authorized: bool,
) -> SubsetPreparation {
    let AcceptedRetainedInputs {
        pins,
        manifests,
        accepted,
        mut refusals,
        requested,
        scan_modules,
    } = accepted;
    // The scan mint builds over the current scan-input modules
    // when it seeded them; every other mint keeps the retained
    // creation-time snapshot.
    let source_modules: &[ReconciledModule] = match &scan_modules {
        Some(modules) => modules,
        None => &engine.modules,
    };
    if accepted.is_empty() {
        // The scan mint retries per discovery pass: no provider
        // discovered yet is quiet, never a per-pass refusal.
        if !requested && !scan_authorized {
            refusals.push(SemanticRefusal::Unattested);
        }
        return SubsetPreparation {
            subset: None,
            refusals,
        };
    }
    let (claims, plan) = if scan_authorized {
        // Claims stay over the full source set: rival and
        // degraded keys from providers that can never mint still
        // degrade shared keys below. The subset *plan*, though,
        // is built only over providers the claims do not mark
        // incomplete. The Detailed slot space is small (512) and
        // admission is first-come whole-module, so a huge
        // never-mintable provider (the system p11-kit proxy:
        // ~410 capped endpoints, `known_prefix` walk) would
        // otherwise consume the budget ahead of a complete
        // provider and refuse it whole (fedora ff-late-2). An
        // incomplete provider keeps its counted refusal: it has
        // no plan module, exactly as when the budget refused it.
        let claims =
            plan::semantic_source_claims_scan_authorized(source_modules, &manifests, &pins);
        // A cross-object provider (required keys in another
        // object, the p11-kit trust shape) can never mint either
        // (refused below): keep it out of the plan too, so a huge
        // one cannot starve a complete provider of slots.
        let mintable: Vec<ReconciledModule> = source_modules
            .iter()
            .filter(|module| {
                !claims.incomplete.contains(&module.object)
                    && claims.providers.get(&module.object).is_none_or(|required| {
                        required.iter().all(|key| key.object == module.object)
                    })
            })
            .cloned()
            .collect();
        let plan = plan::build_from_sources_scan_authorized(&mintable, &manifests, &pins);
        (claims, plan)
    } else {
        (
            plan::semantic_source_claims(&engine.modules, &manifests, &pins),
            plan::build_from_sources_for_policy_scoped(
                &engine.modules,
                &manifests,
                &pins,
                plan::AdmissionPolicy::detailed(),
                plan::AdmissionScope::Named,
            ),
        )
    };
    let mut selected = BTreeSet::new();
    for provider in accepted {
        let complete = claims
            .providers
            .get(&provider)
            .zip(plan.modules.iter().find(|module| module.object == provider))
            .is_some_and(|(required, module)| {
                !claims.incomplete.contains(&provider)
                    // Scan mint only: a provider whose required
                    // keys live in another object (the p11-kit
                    // trust shim, whose table entries are
                    // implemented inside libp11-kit) can never
                    // pass the attested seal's per-provider
                    // instance check, and seeded here it would
                    // refuse the whole subset. Count it
                    // incomplete; manifest mints keep their
                    // operator-chosen semantics.
                    && (!scan_authorized
                        || required.iter().all(|key| key.object == provider))
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
    // A restriction intersects after completeness: an incomplete or
    // uncovered clicked provider yields no subset, never a partial
    // one. Complete-but-unselected providers stay silent (they are
    // neither incomplete nor selected).
    if let Some(only) = restrict {
        selected.retain(|provider| only.contains(provider));
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
    /// Registry module-find evaluations during selection (test count).
    #[cfg(test)]
    refresh_find_visits: u64,
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

/// The reason a binding names when its image is already refused in the
/// Joint journal: it stays S1.
pub(crate) const JOINT_IMAGE_REFUSED: &str = "joint_image_refused";

/// JK-18 note: calls already disclosed under `semantic calls unrouted`
/// before the first binding, later proven other callers' (no new loss).
pub(crate) const PRE_BINDING_OTHER_CALLERS: &str =
    "pre-binding unrouted calls resolved to other callers";

impl SemanticBindingSet {
    pub(crate) fn new() -> Self {
        Self {
            bindings: Vec::new(),
            index: HashMap::new(),
            cursor: 0,
            limit: MAX_INSTANCES,
            provider_limit: MAX_INSTANCES,
            refresh_cursor: None,
            #[cfg(test)]
            refresh_find_visits: 0,
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
    #[allow(clippy::result_large_err)] // DR37: cold path returning the refused capacity for genuine disposal.
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

    /// Accepted semantic bindings. The disclosure gap reports how many
    /// bindings existed when calls shed without a route.
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

    /// Whether an unrouted call's record proves a caller other than every
    /// bound Joint caller of its domain, so its lost position need not
    /// barrier their history. Fails closed: an unknown image (zero
    /// cookie), no bindings, any binding or admission history of another
    /// domain (a different ticket space), or a cookie equal to any bound
    /// or historically admitted image all keep the barrier. Tickets are
    /// per thread group and never reused within a domain, so a different
    /// nonzero cookie of the same domain is a different process; an exec
    /// keeps its cookie and therefore still matches.
    pub(crate) fn proves_unbound_caller(
        &self,
        domain: NativeDomainId,
        image: ImageIdentity,
    ) -> bool {
        let cookie = image.task_cookie;
        cookie != 0
            && !self.bindings.is_empty()
            && self.bindings.iter().all(|binding| {
                binding.domain() == domain
                    && binding.image().task_cookie != 0
                    && binding.image().task_cookie != cookie
            })
            && self
                .admission_images
                .values()
                .all(|history| history.domain == domain && history.image.task_cookie != cookie)
    }

    /// Whether an unrouted call of a journal-refused image proves a
    /// caller that can never hold Joint history, so its lost position
    /// need not barrier the bound Joint callers. A refused image's
    /// birth and attestation refuse permanently, so it never joins
    /// Joint; this covers the refused caller that later binds for S1,
    /// whose own binding and admission history then hold its cookie
    /// and defeat [`Self::proves_unbound_caller`]. Fails closed: the
    /// call's exact image must itself be refused, and every binding
    /// or admission history sharing its cookie must be refused too —
    /// an unrefused same-cookie image (an exec keeps the cookie)
    /// could own the call and keeps the barrier.
    pub(crate) fn proves_refused_other_caller(
        &self,
        domain: NativeDomainId,
        image: ImageIdentity,
        image_refused: impl Fn(ImageIdentity) -> bool,
    ) -> bool {
        let cookie = image.task_cookie;
        cookie != 0
            && !self.bindings.is_empty()
            && image_refused(image)
            && self.bindings.iter().all(|binding| {
                binding.domain() == domain
                    && binding.image().task_cookie != 0
                    && (binding.image().task_cookie != cookie || image_refused(binding.image()))
            })
            && self.admission_images.values().all(|history| {
                history.domain == domain
                    && (history.image.task_cookie != cookie || image_refused(history.image))
            })
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

/// A new binding whose image the Joint journal already refused (for
/// example a process whose earlier calls were shed as another caller's)
/// can never enter Joint: its refused history is a hole. It stays S1;
/// name that once, at the binding, so it never depends on a birth being
/// offered.
fn name_refused_image_binding(
    registry: &mut CallerRegistry,
    journal: &crate::semantics_objects::journal::JournalAdapter,
    caller: CallerId,
    image: ImageIdentity,
) {
    if journal.image_refused((image.task_cookie, image.exec_id)) {
        registry.record_gap(RegistryGap {
            caller: Some(caller),
            module: None,
            pid: None,
            subject: crate::inventory_present::JOINT_BIRTH_UNAVAILABLE_SUBJECT.into(),
            reason: JOINT_IMAGE_REFUSED.into(),
            budget: None,
        });
    }
}

/// One existing promotion/diagnostic consumer for owned refreshes and
/// borrowed collected Current receipts. Only these disjoint coordinator
/// fields are borrowed; the original receipt stays with its sole owner.
#[allow(clippy::too_many_arguments)] // Disjoint coordinator fields plus the original admission inputs.
fn consume_current_admission<Source: ProcessSource>(
    adapter: &CallerAdapter<Source>,
    registry: &mut CallerRegistry,
    journal: &crate::semantics_objects::journal::JournalAdapter,
    bindings: &mut SemanticBindingSet,
    candidate: SemanticAdmissionCandidate,
    receipt: &crate::semantic_capture::CurrentPartitionReceipt,
    provider: Result<SemanticProviderTarget, SemanticRefusal>,
    permit: Option<crate::inspect_system::inventory_cgroup::CgroupAdmissionPermit<'_>>,
) -> Result<(), SemanticBindingRefusal> {
    let caller = candidate.caller;
    let requested_file = receipt.endpoint().file_slot;
    let provider_module = provider
        .as_ref()
        .ok()
        .and_then(|provider| registry.module_id_for(provider.module()));
    let fresh = bindings.get(caller).is_none();
    let result = promotion::consume(
        adapter, registry, bindings, candidate, receipt, provider, permit,
    );
    if result.is_ok() && fresh {
        name_refused_image_binding(registry, journal, caller, receipt.image());
    }
    if let Err(reason) = result {
        // A provider-side Unavailable has exactly one source: the
        // provider-subject attachment check found no live owner (every
        // other provider error carries its own code). Name that site.
        let code = match reason {
            SemanticBindingRefusal::OwnerRefused(SemanticRefusal::Unavailable) => {
                AdmissionPreparationError::unavailable(
                    AdmissionUnavailableSite::ProviderSubjectUnavailable,
                )
                .to_string()
            }
            other => other.code().to_string(),
        };
        registry.record_gap(RegistryGap {
            caller: Some(caller),
            module: None,
            pid: None,
            subject: "semantic admission refused".into(),
            reason: code,
            budget: None,
        });
        if matches!(
            reason,
            SemanticBindingRefusal::Capacity
                | SemanticBindingRefusal::OwnerRefused(SemanticRefusal::ProviderStorage)
        ) {
            // A refused copy owns no ModuleKey. Preserve the original
            // bounded file context without allocating an identity first.
            registry.record_gap(RegistryGap {
                caller: Some(caller),
                module: provider_module,
                pid: None,
                subject: format!("semantic provider file {requested_file} admission refused"),
                reason: reason.code().into(),
                budget: None,
            });
        }
    }
    result
}

impl<Source: ProcessSource> InventoryCoordinator<Source> {
    /// Registry module-find evaluations during selection (test count).
    #[cfg(test)]
    pub(crate) fn semantic_refresh_find_visits(&self) -> u64 {
        self.semantic_bindings.refresh_find_visits
    }

    /// Four exact mapped attested pairs, including every failed refresh.
    /// The four picks share one registry scan through a bounded per-pair
    /// memo (freed per call); picks, cursor and charges match the unshared
    /// scan exactly. The cursor advances per caller/provider, including
    /// failure.
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
        // The registry, subset and edges are immutable for the whole call,
        // so a (record, object) module find resolves identically on every
        // pick. The first pick scans; later picks replay the recorded
        // outcome and its charge pattern instead of re-scanning the
        // registry (four full scans per call at scale). A pair the first
        // pick skipped simply scans live on first reach: still correct.
        let mut find_memo: BTreeMap<(CallerId, PinnedObjectId), (usize, Option<ModuleKey>)> =
            BTreeMap::new();
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
                    let module = if let Some((visits, module)) = find_memo
                        .get(&key)
                        .map(|(visits, module)| (*visits, module.clone()))
                    {
                        // Replay: identical charges, no registry scan.
                        for _ in 0..visits {
                            if !charge(1) {
                                return attempts;
                            }
                        }
                        module
                    } else {
                        let mut exhausted = false;
                        let mut visits = 0;
                        let module = self.registry.modules().find(|module| {
                            visits += 1;
                            #[cfg(test)]
                            {
                                self.semantic_bindings.refresh_find_visits =
                                    self.semantic_bindings.refresh_find_visits.saturating_add(1);
                            }
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
                        find_memo.insert(key, (visits, module.clone()));
                        module
                    };
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
        if self.adapter.leader_exit_pending(caller)
            || record.retired
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
    #[cfg_attr(not(test), allow(dead_code))] // Staged promotion path: exercised by the promotion staging tests; no production driver wires it yet.
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

    /// The original physical publication owns any cgroup completion. A
    /// collected Current may add a provider only under that SAME collection's
    /// actual member permit; PID/system keep their existing candidate path.
    fn prepare_current_promotion_candidate(
        &self,
        caller: CallerId,
        domain: NativeDomainId,
    ) -> Result<(SemanticAdmissionCandidate, PromotionAdmissionReservation), SemanticBindingRefusal>
    {
        if !matches!(self.engine.scope, Scope::Cgroup { .. }) {
            return self.prepare_legacy_promotion_candidate(caller, domain);
        }
        let record = self
            .adapter
            .record(caller)
            .ok_or(SemanticBindingRefusal::NoLiveCaller)?;
        let collection = &self
            .joint_publication
            .as_ref()
            .and_then(|pending| pending.completion.cgroup.as_ref())
            .ok_or(SemanticBindingRefusal::NoLiveCaller)?
            .0;
        let permit = collection
            .permit(record.pid)
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
            pin.clone(),
            path_bytes,
        )?;
        let candidate = self
            .seal_semantic_candidate(
                caller,
                &pin,
                AdmissionScope::Cgroup,
                domain,
                Some(permit.generation()),
                || self.adapter.shared_semantic_custody(caller),
            )
            .ok_or(SemanticBindingRefusal::NoLiveCaller)?;
        if !reservation.matches(&candidate) {
            return Err(SemanticBindingRefusal::NoLiveCaller);
        }
        Ok((candidate, reservation))
    }

    #[cfg_attr(not(test), allow(dead_code))] // Staged promotion path: exercised by the promotion staging tests; no production driver wires it yet.
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

    /// Mint the attested subset for one clicked provider (DR37
    /// resolver): the live module's physical key names exactly one
    /// retained provider object, and the restricted subset covers it
    /// with the same rival-aware plan build as the full mint. An
    /// unknown or unloaded module reports the provider axis; an
    /// uncovered, incomplete or non-physical provider reports no
    /// manifest permission. The resolver mints twice for the
    /// attach/convert pair; both share the retained envelope.
    pub(crate) fn prepare_selected_subset(
        &mut self,
        provider: ModuleId,
    ) -> Result<AttestedSubset, PromotionRefusal> {
        let module = self.registry.module(provider).filter(|module| {
            module.lifecycle != ModuleLifecycle::Unloaded && !module.unloaded_observed
        });
        let Some(module) = module else {
            return Err(PromotionRefusal::ProviderUnloaded);
        };
        let key = module.key.clone();
        let accepted = accept_retained_inputs(
            &self.engine,
            self.semantic_inputs.retained_or_load(&self.engine),
            false,
            None,
        );
        let object = provider_object_for_key(&accepted.pins, &key)
            .ok_or(PromotionRefusal::ManifestUnavailable)?;
        let restrict = BTreeSet::from([object]);
        build_subset_from_accepted(&self.engine, accepted, Some(&restrict), false)
            .subset
            .ok_or(PromotionRefusal::ManifestUnavailable)
    }

    /// Establish one taken request's original custody (DR37 resolver):
    /// the shared pidfd Arc plus the live incarnation the pre-view
    /// baseline binds. The record must exist, be unretired with a live
    /// lifecycle, and still hold shared custody; anything else fails
    /// closed. No continuity comparison happens here: this custody IS
    /// the expectation the downstream liveness re-check compares the
    /// live record against.
    pub(crate) fn prepare_selected_caller_custody(
        &self,
        caller: CallerId,
    ) -> Result<(Arc<PidPin>, u32), PromotionRefusal> {
        let record = self
            .adapter
            .record(caller)
            .ok_or(PromotionRefusal::UnknownCaller)?;
        if record.retired
            || matches!(
                record.lifecycle,
                CallerLifecycle::Exited | CallerLifecycle::ExecRetired
            )
        {
            return Err(PromotionRefusal::CallerRetired);
        }
        let pin = self
            .adapter
            .shared_semantic_custody(caller)
            .ok_or(PromotionRefusal::UnknownCaller)?;
        Ok((pin, record.incarnation))
    }

    /// The seal grant's association proof (D9): the namespace's first
    /// admitted call, borrowed for the per-quantum mint. `None`
    /// before the first admission finalizes: the seal then refuses,
    /// honestly without a grant.
    #[allow(dead_code)] // STAGED (DR37/H8): called by the joint seal driver; no test seals yet.
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
    #[allow(clippy::result_large_err)] // DR37: cold path returning the refused parts for genuine disposal.
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
        // The proof authorized exactly this install; its scope ends
        // here with the entry.
        Ok(live)
    }

    /// DR37 wind-down gate: whether the domain's finalizer namespace
    /// still holds unpublished work that needs its validating lane. A
    /// staged quantum always needs the lane (it still requires its
    /// audited finalization/drop). Staged h3 evidence does not hold
    /// this shared gate: every finalized batch stages it, and only the
    /// Joint seal audit takes it, so a legacy lane would never wind
    /// down; Joint lanes refuse retire on it through
    /// `retire_joint_domain_with_lane`. A drop
    /// shadow needs the lane only while the domain stays live: once
    /// the domain is permanently refused, its terminal loss is
    /// disposable without restoring positives, so the wind-down
    /// releases the lane and the retire below disposes the shadow
    /// with the namespace. Staged h9 ledger entries also need the
    /// lane: retiring replaces the joint owner they charge against.
    #[cfg_attr(not(test), allow(dead_code))] // STAGED (DR37): called by the driver wind-down.
    pub(crate) fn joint_domain_has_pending_work(&self, domain: NativeDomainId) -> bool {
        if self.joint_capture.ledger().staged() != 0 {
            return true;
        }
        self.semantic_finalizer.as_ref().is_some_and(|state| {
            state.domain == domain
                && (state.pending_semantic.is_some()
                    || (state.pending_drop.is_some()
                        && !self.refused_semantic_domains.contains(&domain)))
        })
    }

    /// Retire one genuinely completed domain for the next (D5): the
    /// native completion names the live finalizer namespace, which
    /// must be quiescent (no staged quantum, and no pending drop
    /// unless the domain is already permanently refused, whose
    /// terminal shadow disposes with the namespace without restoring
    /// positives); refused batches publish their terminal negatives
    /// at refusal, so existing claims are already unknown by
    /// disposal. Other pending work refuses and the namespace stays
    /// live. Every refusal hands the completion back with the reason:
    /// the source delivers once, so a retryable refusal preserves the
    /// authority required to retry. Retire removes the domain's bindings,
    /// refusal-only history and successor reservations (other
    /// domains' entries preserved), clears its tail markers, drops
    /// the finalizer namespace (including its seal admission: no
    /// cross-domain grant reuse), refuses the domain permanently, and
    /// `mem::replace`s the joint owner with a fresh one (the old
    /// ledger's exact charges refund by drop; no counter resets).
    /// Adapter positions are stream/Session-local and correctly
    /// restart; global counters never reset.
    ///
    /// Seal-drained callers retire through
    /// `retire_joint_domain_with_lane`, which refuses while h3
    /// evidence, staged h9 entries or the lane's joint frame are
    /// still live; this entry keeps the namespace-quiescence gate.
    /// Legacy lanes have no seal audit to drain h3, so their evidence
    /// drops with the namespace here, as before the Joint path.
    #[cfg_attr(not(test), allow(dead_code))] // STAGED (DR37): called by the driver on completion.
    pub(crate) fn retire_joint_domain(
        &mut self,
        completion: SessionNativeCompletion,
    ) -> Result<(), (SessionNativeCompletion, JointRetireRefusal)> {
        let domain = completion.domain();
        let live = self
            .semantic_finalizer
            .as_ref()
            .is_some_and(|state| state.domain == domain);
        if !live {
            return Err((completion, JointRetireRefusal::NotLiveDomain));
        }
        let quiescent = self.semantic_finalizer.as_ref().is_some_and(|state| {
            state.pending_semantic.is_none()
                && (state.pending_drop.is_none() || self.refused_semantic_domains.contains(&domain))
        });
        if !quiescent {
            return Err((completion, JointRetireRefusal::PendingWork));
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
        // Diagnostic-only (Task 0): the void counters are run-global
        // and never reset, so the replacement owner adopts them.
        let carried = self.joint_capture.adapter().joint_void_diagnosis();
        self.joint_capture =
            crate::semantics_objects::journal::joint_driver::JointCaptureOwner::new(
                crate::semantics_objects::journal::JournalLimits::policy(),
                self.registry.semantic_storage_reserver(),
            );
        self.joint_capture
            .adapter_mut()
            .carry_joint_void_counts(&carried);
        Ok(())
    }

    /// Seal-drained retirement: refuse `PendingWork`, returning the
    /// completion unchanged, while the joint ledger still stages h9
    /// entries, the validating lane still holds a joint frame, h3
    /// evidence is still staged, or the domain still has pending work. A drained domain
    /// delegates to `retire_joint_domain`, which reports a foreign
    /// completion as `NotLiveDomain`.
    #[cfg_attr(not(test), allow(dead_code))] // STAGED: the promotion driver wires the lane; tests exercise it.
    pub(crate) fn retire_joint_domain_with_lane(
        &mut self,
        lane: &AttestedSemanticLane,
        completion: SessionNativeCompletion,
    ) -> Result<(), (SessionNativeCompletion, JointRetireRefusal)> {
        let domain = completion.domain();
        let h3_pending = self
            .semantic_finalizer
            .as_ref()
            .is_some_and(|state| state.domain == domain && state.h3_pending.is_some());
        if self.joint_capture.ledger().staged() != 0
            || lane.has_joint_frame()
            || h3_pending
            || self.joint_domain_has_pending_work(domain)
        {
            return Err((completion, JointRetireRefusal::PendingWork));
        }
        self.retire_joint_domain(completion)
    }

    /// Run the ordinary consumer against fixed private storage. No registry
    /// diagnostic, history, registration or binding is published by this call.
    #[cfg_attr(not(test), allow(dead_code))] // Staged promotion path: exercised by the promotion staging tests; no production driver wires it yet.
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
        let result = consume_current_admission(
            &self.adapter,
            &mut self.registry,
            self.joint_capture.adapter(),
            &mut self.semantic_bindings,
            candidate,
            &receipt,
            provider,
            permit,
        );
        (receipt, result)
    }

    /// Record one failed admission preparation. A deferral (see
    /// `AdmissionPreparationError::is_deferral`) is a named non-loss
    /// note under `semantic admission deferred`; every other refusal
    /// stays the `semantic admission refused` loss gap.
    pub(crate) fn semantic_admission_prepare_failed(
        &mut self,
        caller: CallerId,
        reason: AdmissionPreparationError,
    ) {
        if !reason.is_deferral() {
            self.semantic_admission_refused(caller, &reason.to_string());
            return;
        }
        self.registry.record_gap(RegistryGap {
            caller: Some(caller),
            module: None,
            pid: None,
            subject: "semantic admission deferred".into(),
            reason: reason.to_string(),
            budget: None,
        });
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

    /// Tests-only shorthand for
    /// [`Self::record_scan_refusals_gap_with_overflow`] with zero
    /// overflow. Production always routes through the shared entry so
    /// the cap note cannot be dropped by a stale call site.
    #[cfg(test)]
    pub(crate) fn record_scan_refusals_gap(&mut self, counts: &[u64; 12]) {
        self.record_scan_refusals_gap_with_overflow(counts, 0);
    }

    /// One aggregate gap for lifetime semantic scan/refresh refusals,
    /// with per-reason finite labels and counts, plus an `(N not
    /// settled: ledger full)` note when `overflow` refusals counted
    /// past the settle-ledger cap. Nothing is recorded when no scan
    /// ever refused. Counts only; no pids, paths or payloads.
    pub(crate) fn record_scan_refusals_gap_with_overflow(
        &mut self,
        counts: &[u64; 12],
        overflow: u64,
    ) {
        let Some(reason) =
            crate::inventory_semantics::scan_refusals_gap_reason_with_overflow(counts, overflow)
        else {
            return;
        };
        self.registry.record_gap(RegistryGap {
            caller: None,
            module: None,
            pid: None,
            subject: "semantic scan refused".into(),
            reason,
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
        })?;
        name_refused_image_binding(
            &mut self.registry,
            self.joint_capture.adapter(),
            caller,
            image,
        );
        Ok(())
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
            Some(_) => {
                self.semantic_bindings.insert(SemanticCallerBinding {
                    caller,
                    domain,
                    image,
                    pin,
                    scope_current: true,
                    suspension_cut: false,
                    providers: SemanticProviderAssociations::new(),
                    reference_module: Some(module),
                })?;
                name_refused_image_binding(
                    &mut self.registry,
                    self.joint_capture.adapter(),
                    caller,
                    image,
                );
                Ok(())
            }
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

/// B17 leg-2 inventory view of the staged reload disclosure: the exact
/// router count snapshots plus one entry per affected module, sorted by
/// module with sorted instances. Renders as the top-level
/// `instance_reload_not_excluded` inventory object.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct InventoryReloadDisclosure {
    pub continued_across_global: u64,
    pub joined_across_global: u64,
    pub identities: Vec<InventoryReloadDisclosureIdentity>,
}

/// One affected module and its disclosed registered instances.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct InventoryReloadDisclosureIdentity {
    pub module: ModuleId,
    pub instances: Vec<RegistryInstanceId>,
}

impl<Source: ProcessSource> InventoryCoordinator<Source> {
    /// Borrow the actual retained classic batch without preparing or consuming it.
    #[cfg(test)]
    pub(crate) fn pending_semantic_batch_for_test(&self) -> Option<&SemanticBatch> {
        match self
            .semantic_finalizer
            .as_ref()?
            .pending_semantic
            .as_ref()?
        {
            PendingSemanticBatch::Collected(batch) => Some(batch),
            PendingSemanticBatch::Prepared(_) => None,
        }
    }

    /// Queue one owned lane batch for finalization: at most one ordinary
    /// collection quantum is owned at a time, then finalize/publish
    /// before another semantic collection. A refused collection records
    /// loss through the existing audited path, never silently.
    pub(crate) fn stage_semantic_batch(
        &mut self,
        mut batch: crate::inventory_semantics::SemanticBatch,
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
            self.stash_drop_shed(&batch, "ended_domain");
            self.publish_refused_batch_negatives(batch);
            return;
        }
        let domain = batch.domain();
        let namespace = self
            .semantic_finalizer
            .get_or_insert_with(|| SessionFinalizerState::new(domain));
        if namespace.domain != domain {
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
        let backpressure = namespace.pending_semantic.is_some();
        // B17 W2: drain the disclosure quadrant into the live namespace
        // ledger before any staging decision below. Same-domain
        // backpressure drops keep their disclosures (the router drained
        // each identity once); the refused and foreign returns above
        // drop theirs with the batch at the namespace boundary.
        // Identities shed past a cap are counted and named here, never
        // silent.
        let (disclosures, continued, joined, carried) = batch.take_reload_disclosures();
        self.drain_reload_disclosures_into_ledger(domain, disclosures, continued, joined, carried);
        if backpressure {
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
            self.stash_drop_shed(&batch, "backpressure");
            return;
        }
        self.semantic_finalizer
            .as_mut()
            .expect("the matching Session state is retained")
            .pending_semantic = Some(PendingSemanticBatch::Collected(batch));
    }

    /// Drain one batch's disclosure quadrant into the live namespace
    /// ledger, disclosing shed under the one vocabulary. Shared by
    /// staging (every same-domain batch, including backpressure
    /// drops) and the collected stop union (appended after staging):
    /// the ledger keeps the one cumulative disclosure-shed counter
    /// for the capture, and every drop lands under the same named
    /// gap with its cumulative total. Count snapshots stay exact.
    pub(crate) fn drain_reload_disclosures_into_ledger(
        &mut self,
        domain: NativeDomainId,
        disclosures: Vec<crate::semantic_capture::ReloadNotExcludedReport>,
        continued_across_global: u64,
        joined_across_global: u64,
        carried_shed: u32,
    ) {
        let namespace = self
            .semantic_finalizer
            .get_or_insert_with(|| SessionFinalizerState::new(domain));
        debug_assert_eq!(namespace.domain, domain);
        let shed = namespace.accumulate_reload_disclosures(
            disclosures,
            continued_across_global,
            joined_across_global,
            carried_shed,
        );
        if shed == 0 {
            return;
        }
        let cumulative = namespace.reload_shed;
        let reason = if carried_shed > 0 && shed == u64::from(carried_shed) {
            format!(
                "{shed} disclosed identities shed past accumulator caps upstream \
                 ({cumulative} shed this capture); the count snapshots stay exact"
            )
        } else if carried_shed > 0 {
            format!(
                "{shed} disclosed identities shed ({} past the ledger cap of {}, {} upstream) \
                 ({cumulative} shed this capture); the count snapshots stay exact",
                shed - u64::from(carried_shed),
                crate::discovery::instances::MAX_INSTANCES,
                carried_shed,
            )
        } else {
            format!(
                "{shed} disclosed identities shed past the ledger cap of {} \
                 ({cumulative} shed this capture); the count snapshots stay exact",
                crate::discovery::instances::MAX_INSTANCES,
            )
        };
        self.registry.record_gap(RegistryGap {
            caller: None,
            module: None,
            pid: None,
            subject: "reload disclosure identities shed".into(),
            reason,
            budget: None,
        });
    }

    /// B17 terminal projection of the namespace reload disclosure
    /// ledger into the profile-lane evidence: `None` only without a
    /// producer — an empty ledger with zero count snapshots (absent,
    /// never zero). Nonzero snapshots project even with an empty
    /// identities list: the router is the producer then, and exact
    /// counts with no identities is the honest mint-exhaustion shape.
    /// Else the per-identity entries in `(file_slot, ids)` order plus
    /// the latest count snapshots. The private image key never leaves
    /// the ledger. `evidence_for` calls this for the staged ledger
    /// its capture hands over; captures without one pass `None`.
    pub(crate) fn reload_not_excluded_evidence(
        &self,
    ) -> Option<crate::semantic_capture::InstanceReloadNotExcluded> {
        use crate::semantic_capture::{InstanceReloadNotExcluded, ReloadNotExcludedIdentity};
        let state = self.semantic_finalizer.as_ref()?;
        if state.reload_not_excluded.is_empty()
            && state.continued_across_global == 0
            && state.joined_across_global == 0
        {
            return None;
        }
        let mut identities: Vec<ReloadNotExcludedIdentity> = state
            .reload_not_excluded
            .values()
            .map(|(file_slot, ids)| ReloadNotExcludedIdentity {
                file_slot: *file_slot,
                ids: ids.clone(),
            })
            .collect();
        identities.sort_by(|a, b| (a.file_slot, &a.ids).cmp(&(b.file_slot, &b.ids)));
        Some(InstanceReloadNotExcluded {
            continued_across_global: state.continued_across_global,
            joined_across_global: state.joined_across_global,
            identities,
        })
    }

    /// B17 leg-2 inventory projection of the staged disclosure ledger:
    /// the exact router count snapshots plus one entry per affected
    /// module with the sorted registered instances, or `None` when the
    /// capture has no producer (same absent rule as
    /// [`Self::reload_not_excluded_evidence`]). Each router ID resolves
    /// through its registered instance, so the named module is always
    /// the one conversion recorded — never a second lookup that could
    /// disagree. Unregistered IDs are omitted, identities with nothing
    /// nameable are dropped, and the counts stay exact; no file slot,
    /// router ID, task cookie or exec ID leaves the ledger.
    pub(crate) fn reload_disclosure_for_inventory(&self) -> Option<InventoryReloadDisclosure> {
        let state = self.semantic_finalizer.as_ref()?;
        if state.reload_not_excluded.is_empty()
            && state.continued_across_global == 0
            && state.joined_across_global == 0
        {
            return None;
        }
        let mut groups: BTreeMap<ModuleId, BTreeSet<RegistryInstanceId>> = BTreeMap::new();
        for ((cookie, exec, _slot), (_entry_slot, ids)) in state.reload_not_excluded.iter() {
            if ids.is_empty() {
                continue;
            }
            let wanted: BTreeSet<u64> = ids.iter().copied().collect();
            let image = ImageIdentity {
                task_cookie: *cookie,
                exec_id: *exec,
            };
            for (router, instance, module) in self
                .registry
                .reload_disclosure_instances(state.domain, image)
            {
                if wanted.contains(&router) {
                    groups.entry(module).or_default().insert(instance);
                }
            }
        }
        Some(InventoryReloadDisclosure {
            continued_across_global: state.continued_across_global,
            joined_across_global: state.joined_across_global,
            identities: groups
                .into_iter()
                .map(|(module, instances)| InventoryReloadDisclosureIdentity {
                    module,
                    instances: instances.into_iter().collect(),
                })
                .collect(),
        })
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

    /// Publish one refused domain's terminal negatives without
    /// positives: capture loss must terminate existing operation claims
    /// as unknown before their validating namespace is disposed.
    /// Refusing future positives never discharges existing negatives,
    /// so a refused batch still stages its lane facts and H0
    /// invalidations through the same negative legs as normal
    /// finalization — with no receipt validation, no coverages
    /// (narrow exact retirements degrade to loss, never a silent
    /// revival), no calls and no registrations. The batch's drop
    /// shadow still records for H3 accounting.
    fn publish_refused_batch_negatives(
        &mut self,
        batch: crate::inventory_semantics::SemanticBatch,
    ) {
        self.record_semantic_drop(&batch);
        let domain = batch.domain();
        let (outcomes, _current, negatives) = batch.into_parts();
        for negative in &negatives {
            match tail_loss_from_negative(domain, negative) {
                Some(Ok(loss)) => {
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
        for outcome in outcomes {
            let TickOutcome::Invalidation(invalidation) = outcome else {
                // Calls and non-call records carry no negative: refused
                // positives never stage.
                continue;
            };
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
                &[],
            ) {
                Ok((losses, retirements)) => {
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

    /// Stash a same-domain refused batch's unjoined calls for the next
    /// finalize's shed count and disclosure gap. Joined calls stay
    /// joined (already counted); foreign-domain batches never stash
    /// (their calls were never collected here, so counting them would
    /// break collected == joined + shed).
    fn stash_drop_shed(
        &mut self,
        batch: &crate::inventory_semantics::SemanticBatch,
        drop: &'static str,
    ) {
        let counted = unjoined_shed_counts(batch.outcomes());
        if counted.is_empty() {
            return;
        }
        // Never recreate a namespace for a retired domain: without a
        // live same-domain namespace there is nowhere to flush to, and
        // a recreated one would refuse every later domain.
        let Some(state) = self
            .semantic_finalizer
            .as_mut()
            .filter(|state| state.domain == batch.domain())
        else {
            return;
        };
        let slot = state.pending_drop_shed.entry(drop).or_default();
        for (label, count) in counted {
            let cell = slot.entry(label).or_default();
            *cell = cell.saturating_add(count);
        }
    }

    /// Disclose stashed drop shed: one unrouted gap per drop label plus
    /// the stop-line count. Shared by stage-refused batches (stashed
    /// without a lane) and oversized reports (stashed without a
    /// registry): both flush at the next finalize with a lane.
    fn flush_drop_shed(&mut self, lane: &mut crate::inventory_semantics::AttestedSemanticLane) {
        let stashed: BTreeMap<&'static str, BTreeMap<&'static str, u64>> = self
            .semantic_finalizer
            .as_mut()
            .map(|state| std::mem::take(&mut state.pending_drop_shed))
            .unwrap_or_default();
        for (drop, counted) in stashed {
            self.publish_drop_shed(lane, drop, counted);
        }
        let oversized = lane.take_oversized_drop_shed();
        if !oversized.is_empty() {
            self.publish_drop_shed(lane, "oversized", oversized);
        }
    }

    fn publish_drop_shed(
        &mut self,
        lane: &mut crate::inventory_semantics::AttestedSemanticLane,
        drop: &'static str,
        counted: BTreeMap<&'static str, u64>,
    ) {
        let total: u64 = counted
            .values()
            .fold(0, |sum, count| sum.saturating_add(*count));
        if total == 0 {
            return;
        }
        let labels = counted
            .iter()
            .map(|(label, count)| format!("{label}={count}"))
            .collect::<Vec<_>>()
            .join(" ");
        self.registry.record_gap(RegistryGap {
            caller: None,
            module: None,
            pid: None,
            subject: "semantic calls unrouted".into(),
            reason: format!(
                "{total} calls shed from a dropped {drop} batch ({labels}) with {} bindings",
                self.semantic_bindings.len()
            ),
            budget: None,
        });
        lane.note_shed_calls(total);
    }

    /// Disclose an EVENTS ring-loss rise: exact counts on the stop
    /// line's `lost` term and the report's event-loss account, plus
    /// one named gap. Ring loss is never folded into shed, so the
    /// stop line keeps collected == joined + shed. The reason stays
    /// stable so repeat rises coalesce onto one gap row; the exact
    /// cumulative count lives in events_lost.
    fn disclose_events_ring_loss(
        &mut self,
        lane: &mut crate::inventory_semantics::AttestedSemanticLane,
        delta: u64,
    ) {
        lane.note_events_ring_loss(delta);
        self.registry.record_gap(RegistryGap {
            caller: None,
            module: None,
            pid: None,
            subject: "native capture events lost".into(),
            reason: "the EVENTS ring was full; the kernel refused records \
                 before the drain could read them \
                 (kernel reserve failures; exact count in events_lost)"
                .into(),
            budget: None,
        });
    }

    /// Poll the EVENTS ring-loss counter and disclose the outcome:
    /// a rise stages the named loss gap with exact counts; the
    /// first failed read stages one "loss unknown" gap. The single
    /// choke point for every commit, publish, hold and stop path,
    /// so a caller cannot poll a delta and drop it.
    pub(crate) fn poll_and_disclose_events_ring_loss(
        &mut self,
        lane: &mut crate::inventory_semantics::AttestedSemanticLane,
    ) {
        if let Some(delta) = lane.poll_events_ring_loss() {
            self.disclose_events_ring_loss(lane, delta);
        }
        if lane.take_events_loss_unknown() {
            self.registry.record_gap(RegistryGap {
                caller: None,
                module: None,
                pid: None,
                subject: "native capture events loss unknown".into(),
                reason: "the EVENTS ring-loss counter could not be read; events_lost may undercount until a later good read restores the exact cumulative total"
                    .into(),
                budget: None,
            });
        }
    }

    /// Resolve semantic batches a latched machine stranded behind
    /// its unfinished Joint publication, so the exit-hold abandon
    /// strands neither a Prepared blocker nor an unpublished batch.
    /// A Prepared batch drains S1-direct and mints its H3 (its calls
    /// already joined at H0, so nothing sheds); a Collected batch
    /// drops through the audited path (H3 shed shadow plus the
    /// immediate shed count, so collected == joined + shed holds on
    /// the stop line). Either would otherwise block every later
    /// finalization (Prepared) or vanish under the next stage
    /// (Collected).
    pub(crate) fn abandon_stranded_semantic_batches(
        &mut self,
        lane: &mut crate::inventory_semantics::AttestedSemanticLane,
    ) {
        let pending = self
            .semantic_finalizer
            .as_mut()
            .and_then(|state| state.pending_semantic.take());
        match pending {
            None => {}
            Some(PendingSemanticBatch::Collected(batch)) => {
                self.record_semantic_drop(&batch);
                let counted = crate::semantic_capture::unjoined_shed_counts(batch.outcomes());
                self.publish_drop_shed(lane, "abandoned", counted);
            }
            Some(PendingSemanticBatch::Prepared(mut prepared)) => {
                self.drain_prepared_s1(&mut prepared);
                self.finish_semantic_preparation(prepared, lane.stash_pending_floor());
            }
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
        if self.semantic_finalizer.as_ref().is_some_and(|state| {
            state
                .pending_semantic
                .as_ref()
                .is_some_and(PendingSemanticBatch::is_prepared)
        }) {
            // The original prepared inputs have their own explicit cursors.
            // Another finalization cannot consume them or mint their H3 early.
            return;
        }
        match lane {
            None => {
                // No validation authority: refuse unpublished batches loudly.
                // Tail bits drain uncut: the cut joins its own publication
                // or not at all, never a later one.
                std::mem::take(&mut self.tail_uncertain);
                if let Some(dropped) = self
                    .semantic_finalizer
                    .as_mut()
                    .and_then(SessionFinalizerState::take_collected)
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
                    // The staged batch is same-domain: its calls were
                    // collected by this lane, so their shed waits for the
                    // next finalize with a lane (collected == joined + shed).
                    self.stash_drop_shed(&dropped, "no_lane");
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
        Self::record_proven_image(&self.semantic_bindings, &mut self.proven_images, receipt);
    }

    fn record_proven_image(
        bindings: &SemanticBindingSet,
        observed: &mut HashMap<(NativeDomainId, u64), u64>,
        receipt: &crate::semantic_capture::CurrentPartitionReceipt,
    ) {
        if !bindings.has_ticket(receipt.domain(), receipt.image().task_cookie) {
            return;
        }
        observed
            .entry((receipt.domain(), receipt.image().task_cookie))
            .and_modify(|exec| *exec = (*exec).max(receipt.image().exec_id))
            .or_insert(receipt.image().exec_id);
    }

    /// Receipt presence is actual accepted H0 association, never current
    /// authority. Keep the stored move-only batch intact through the cut.
    fn observe_pending_h0_images(&mut self) {
        let Some(PendingSemanticBatch::Collected(batch)) = self
            .semantic_finalizer
            .as_ref()
            .and_then(|state| state.pending_semantic.as_ref())
        else {
            return;
        };
        for receipt in batch.current_receipts() {
            Self::record_proven_image(&self.semantic_bindings, &mut self.proven_images, receipt);
        }
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

    /// The original H0 cut is finalized before preparing ordinary admissions.
    /// Its actual barrier and loss remain in the one finalizer namespace.
    fn finalize_physical_tail(
        &mut self,
        lane: &mut AttestedSemanticLane,
        collected: Option<&mut crate::semantics_objects::journal::joint_driver::RawJointQuantum>,
    ) -> Option<u64> {
        // The tail cut joins this publication directly, ahead of the
        // pending ordinary quantum: its barrier fences every unpublished
        // positive below, including just-resolved and queued inputs.
        let (gaps, domains) = self.assemble_tail_gaps();
        let mut cut: Option<crate::inventory_semantics::SemanticBatch> = None;
        if !gaps.is_empty() {
            let publication = match collected {
                Some(raw) => lane.apply_physical_gaps_collected(gaps, raw),
                None => lane.apply_physical_gaps(gaps),
            };
            match publication {
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
        floor
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
        // Stashed drop shed flushes on the matching lane only: a foreign
        // lane never collected these calls.
        self.flush_drop_shed(lane);
        let floor = self.finalize_physical_tail(lane, None);
        if let Some(pending) = self
            .semantic_finalizer
            .as_mut()
            .and_then(SessionFinalizerState::take_collected)
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
        let Some(mut prepared) = self.prepare_semantic_batch(lane, batch, floor) else {
            return;
        };
        self.drain_prepared_s1(&mut prepared);
        self.finish_semantic_preparation(prepared, lane.stash_pending_floor());
    }

    fn prepare_semantic_batch(
        &mut self,
        lane: &mut crate::inventory_semantics::AttestedSemanticLane,
        batch: crate::inventory_semantics::SemanticBatch,
        floor: Option<u64>,
    ) -> Option<PreparedSemanticBatch> {
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
            let counted = unjoined_shed_counts(batch.outcomes());
            self.publish_refused_batch_negatives(batch);
            self.publish_drop_shed(lane, "ended_domain", counted);
            return None;
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
            return None;
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
            // A late provider can first appear in this SAME collected batch,
            // before its NoteMapping is applied. Borrow only the frozen
            // physical label, then use the actual owner validator and the
            // ordinary promotion consumer. The original Current/New never
            // leaves `current` and validation negatives have ONE report owner.
            let context = self
                .semantic_bindings
                .find_by_image(receipt.domain(), receipt.image())
                .filter(|binding| {
                    !self.adapter.leader_exit_pending(binding.caller())
                        && binding.provider_for_endpoint(receipt.endpoint()).is_none()
                })
                .and_then(|binding| {
                    self.registry
                        .joint_current_provider_module(receipt, binding, lane.subset())
                        .map(|module| (binding.caller(), module))
                });
            let admission = context.map(|(caller, module)| {
                (
                    caller,
                    self.prepare_current_promotion_candidate(caller, receipt.domain()),
                    module,
                )
            });
            let validated = match admission {
                Some((_, Ok((candidate, reservation)), module)) => {
                    let result = lane.validate_current_for_provider(
                        receipt,
                        Some(module),
                        &mut validation,
                        |bytes| self.registry.reserve_semantic_storage(bytes),
                    );
                    match result {
                        Ok((coverage, provider)) => {
                            // Only the retained original collection supplies a
                            // cgroup permit. The final consume rechecks it;
                            // neither a mapping label nor scope_current grants it.
                            let permit = self
                                .joint_publication
                                .as_ref()
                                .and_then(|pending| pending.completion.cgroup.as_ref())
                                .and_then(|(collection, _)| collection.permit(candidate.pid()));
                            let _ = consume_current_admission(
                                &self.adapter,
                                &mut self.registry,
                                self.joint_capture.adapter(),
                                &mut self.semantic_bindings,
                                candidate,
                                receipt,
                                provider,
                                permit,
                            );
                            // Candidate/path temporaries drop before their
                            // existing reservation; retained provider copies own
                            // their separate original leases.
                            drop(reservation);
                            Ok(coverage)
                        }
                        Err(reason) => {
                            drop(candidate);
                            drop(reservation);
                            Err(reason)
                        }
                    }
                }
                Some((caller, Err(reason), _)) => {
                    self.semantic_admission_refused(caller, reason.code());
                    lane.validate_current(receipt, &mut validation)
                }
                None => lane.validate_current(receipt, &mut validation),
            };
            match validated {
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
        // Unrouted sheds by finite reason label, for the aggregate gap
        // below. A Vec scan avoids new derives on the reason enums.
        let mut shed_reasons: Vec<(&'static str, u64)> = Vec::new();
        // Unrouted sheds whose records prove a caller other than every
        // bound Joint caller: disclosed under their own subject,
        // aggregated lane-wide across drains.
        let mut other_shed_reasons: Vec<(&'static str, u64)> = Vec::new();
        // JK-18: before the namespace's first binding, unrouted calls with
        // a known image are held (counted now, disclosed and disposed or
        // barriered when a binding or the stop resolves them).
        let holding = self.semantic_bindings.len() == 0
            && self
                .semantic_finalizer
                .as_ref()
                .is_some_and(|state| state.domain == domain && !state.bound_once);
        let mut stopped = false;
        // H3 disposition inputs collected across staging: every outcome
        // position this finalization disposes, the minimum shed
        // position, and whether any outcome lacked a position.
        let mut staged_positions: Vec<Option<u64>> = Vec::new();
        let mut shed_min: Option<u64> = None;
        let mut unpositioned = false;
        // Images whose shed calls proved another caller: the Joint journal
        // refuses them so their staging never holds a bound key's seal.
        let mut refuse_images: BTreeSet<(u64, u64)> = BTreeSet::new();
        // Shed-tap module resolutions cached per batch: one registry
        // scan per endpoint object, not per shed call.
        let mut init_objects: BTreeMap<PinnedObjectId, Option<ModuleId>> = BTreeMap::new();
        // JK-19b: shed-tainted images that bound/admitted within grace
        // lift their taint; their pre-bind sheds were sighted below any
        // future birth cut and stay first-observed / not attributed (the
        // Exec-to-attach fallback births above them). Expired entries
        // drop and stay refused. Only shed-taints ever lift;
        // contradiction taints and taint-overflow states never do.
        if let Some(state) = self
            .semantic_finalizer
            .as_mut()
            .filter(|state| state.domain == domain)
        {
            state.finalize_seq = state.finalize_seq.saturating_add(1);
            let seq = state.finalize_seq;
            let mut lift: Vec<(u64, u64)> = Vec::new();
            state.taint_lift.retain(|image, first| {
                // The lift needs the exact image (cookie and exec): a
                // process keeps its ticket across exec, so another
                // exec's binding or admission must never clear this
                // image's taint.
                let exact = ImageIdentity {
                    task_cookie: image.0,
                    exec_id: image.1,
                };
                let own = self
                    .semantic_bindings
                    .find_by_image(domain, exact)
                    .is_some()
                    || self
                        .semantic_bindings
                        .admission_images
                        .values()
                        .any(|history| history.domain == domain && history.image == exact);
                let expired = seq.saturating_sub(*first) >= finalizer::TAINT_LIFT_GRACE;
                if own && !expired {
                    lift.push(*image);
                    return false;
                }
                !expired
            });
            if !lift.is_empty() {
                let adapter = self.joint_capture.adapter_mut();
                for image in lift {
                    adapter.untaint_shed_image(image);
                }
            }
        }
        for outcome in outcomes.into_iter().chain(validation_outcomes) {
            match outcome {
                TickOutcome::Call(call) => {
                    let token = call.token();
                    // Read the route before the move: a shed call's
                    // reason is disclosed through the aggregate gap.
                    // (A Joined call without a token cannot stage
                    // either; production always positions Joined calls.)
                    let shed_reason = match call.route() {
                        Route::Joined(_) => None,
                        Route::Unknown(reason) => Some(reason.label()),
                        Route::Pending => Some("pending"),
                    };
                    // Only consulted for unjoined calls below: a record
                    // proving another caller than every bound Joint
                    // caller disposes its position instead of barriering
                    // their history. It stays shed and disclosed. The
                    // refused-image proof covers the other caller that
                    // bound for S1 after its refusal: refused in the
                    // journal it can never hold Joint history, so its
                    // later sheds are still not a Joint caller's loss.
                    let other_caller = (shed_reason.is_some() && call.domain() == domain && {
                        let adapter = self.joint_capture.adapter();
                        let refused = |image: ImageIdentity| {
                            adapter.image_refused((image.task_cookie, image.exec_id))
                        };
                        self.semantic_bindings
                            .proves_unbound_caller(domain, call.image())
                            || self.semantic_bindings.proves_refused_other_caller(
                                domain,
                                call.image(),
                                refused,
                            )
                    })
                    .then(|| (call.record().event.pid_tgid >> 32) as u32);
                    let call_image = call.image();
                    let cookie = call_image.task_cookie;
                    let call_pid = (call.record().event.pid_tgid >> 32) as u32;
                    // A shed `C_Initialize` still proves its module
                    // through its endpoint: read the tap facts before
                    // the consuming conversion below.
                    let shed_init = match (shed_reason.is_some(), call.endpoint()) {
                        (true, Some(endpoint)) => {
                            let event = &call.record().event;
                            Some((endpoint, event.slot, event.rv))
                        }
                        _ => None,
                    };
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
                        None => {
                            // The shed tap reads the shed without
                            // consuming its disclosure: a proven
                            // `C_Initialize` probe counts its return on
                            // the endpoint's module.
                            if let Some((endpoint, slot, rv)) = shed_init
                                && module_init::init_slot_for_shed(
                                    lane.subset().plan(),
                                    slot,
                                    &endpoint,
                                )
                                && let Some(module) = self.init_module_for_object(
                                    lane.subset(),
                                    endpoint.object,
                                    &mut init_objects,
                                )
                            {
                                self.registry.note_module_init(module, rv);
                            }
                            // JK-18: before the first binding, a positioned
                            // call with a known image is disclosed and
                            // counted as today, but only its barrier is
                            // held until a binding can judge its caller.
                            let mut held = false;
                            if holding
                                && other_caller.is_none()
                                && cookie != 0
                                && let (Some(at), Some(label)) = (token, shed_reason)
                            {
                                let state = self
                                    .semantic_finalizer
                                    .as_mut()
                                    .expect("holding needs the live namespace");
                                held = state.pre_binding.hold(
                                    (cookie, call_image.exec_id),
                                    at,
                                    label,
                                    call_pid,
                                );
                                if !held {
                                    // Overflow: everything held barriers
                                    // now, and this call with it.
                                    let flushed = state.pre_binding.take();
                                    shed_min = Some(
                                        shed_min
                                            .map_or(flushed.min, |floor| floor.min(flushed.min)),
                                    );
                                }
                            }
                            let reasons = if other_caller.is_some() {
                                &mut other_shed_reasons
                            } else {
                                &mut shed_reasons
                            };
                            if let Some(label) = shed_reason {
                                match reasons.iter_mut().find(|(known, _)| *known == label) {
                                    Some((_, count)) => *count += 1,
                                    None => reasons.push((label, 1u64)),
                                }
                            }
                            match (token, other_caller) {
                                // Another caller's lost call is disposed
                                // for the bound callers' history.
                                (Some(at), Some(_)) => {
                                    staged_positions.push(Some(at));
                                    refuse_images.insert((cookie, call_image.exec_id));
                                }
                                // Provisionally disposed: no bound key can
                                // seal yet, and a pending floor here would
                                // stall the publication that admits the
                                // first binding. The first binding's
                                // finalize barriers it late if it cannot
                                // prove another caller.
                                (Some(at), None) if held => staged_positions.push(Some(at)),
                                (Some(at), None) => {
                                    shed_min = Some(shed_min.map_or(at, |floor| floor.min(at)));
                                }
                                (None, _) => unpositioned = true,
                            }
                        }
                    }
                }
                TickOutcome::Invalidation(invalidation) => {
                    stopped |= matches!(invalidation.scope(), InvalidationScope::Stopped);
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
        // Resolve the pre-binding hold at the first finalize that sees a
        // binding (or as loss at a stop before any binding). Any seal of a
        // bound key needs that finalize first, so the late barrier reaches
        // every seal that could certify past a held position.
        let bound = self.semantic_bindings.len() != 0;
        let mut resolved_other: Option<finalizer::PreBindingHold> = None;
        if let Some(state) = self
            .semantic_finalizer
            .as_mut()
            .filter(|state| state.domain == domain)
        {
            if bound {
                state.bound_once = true;
            }
            if bound || stopped {
                let held = state.pre_binding.take();
                if !held.is_empty() {
                    // Each held cookie resolves at the first binding:
                    // the bound caller's own (a binding or admission
                    // history holds it) dispose without barrier or
                    // refusal — the journal already disposed those
                    // records as fenced loss before any key existed;
                    // a provably other caller's dispose and refuse its
                    // image; anything else (unknown against this
                    // binding set) still barriers, fail closed.
                    let mut resolved = bound;
                    let mut any_own = false;
                    let mut other_images: Vec<(u64, u64)> = Vec::new();
                    if bound {
                        for (cookie, exec) in &held.images {
                            let own = self.semantic_bindings.has_ticket(domain, *cookie)
                                || self.semantic_bindings.admission_images.values().any(
                                    |history| {
                                        history.domain == domain
                                            && history.image.task_cookie == *cookie
                                    },
                                );
                            if own {
                                any_own = true;
                            } else if self.semantic_bindings.proves_unbound_caller(
                                domain,
                                ImageIdentity {
                                    task_cookie: *cookie,
                                    exec_id: 0,
                                },
                            ) {
                                other_images.push((*cookie, *exec));
                            } else {
                                resolved = false;
                            }
                        }
                    }
                    if resolved {
                        refuse_images.extend(other_images);
                        // The resolution NOTE keeps its exact
                        // other-caller meaning (and count) only when
                        // the whole hold was other callers'.
                        if !any_own {
                            resolved_other = Some(held);
                        }
                    } else {
                        shed_min = Some(shed_min.map_or(held.min, |floor| floor.min(held.min)));
                    }
                }
            }
        }
        // JK-19: a process S1 proved to be another caller is refused in the
        // Joint journal: its staged entries drop and it never gains Joint
        // authority later (a later binding stays S1, named). An image the
        // journal already keys is left alone; its staging keeps holding
        // the seal, which the no-progress bound ends by name.
        // JK-19b: freshly shed-tainted images additionally stay eligible
        // to lift their taint by binding within grace. Already-refused
        // images (contradiction taints, earlier sheds) never enter: only
        // shed taints ever lift. Past the cap, new taints simply never
        // lift (fail closed).
        if !refuse_images.is_empty() {
            let mut fresh: Vec<(u64, u64)> = Vec::new();
            {
                let adapter = self.joint_capture.adapter();
                for image in &refuse_images {
                    if !adapter.image_refused(*image) {
                        fresh.push(*image);
                    }
                }
            }
            {
                let adapter = self.joint_capture.adapter_mut();
                for image in &refuse_images {
                    adapter.refuse_other_caller_image(*image);
                }
            }
            if !fresh.is_empty()
                && let Some(state) = self
                    .semantic_finalizer
                    .as_mut()
                    .filter(|state| state.domain == domain)
            {
                let seq = state.finalize_seq;
                for image in fresh {
                    if state.taint_lift.len() >= crate::discovery::instances::MAX_PENDING {
                        break;
                    }
                    state.taint_lift.insert(image, seq);
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
        if !shed_reasons.is_empty() {
            let total: u64 = shed_reasons.iter().map(|(_, count)| count).sum();
            let labels: Vec<(String, u64)> = shed_reasons
                .iter()
                .map(|(label, count)| (label.to_string(), *count))
                .collect();
            // Aggregated: repeated drains sum into one counted row
            // per (subject, bindings), never one row per drain.
            self.registry.record_aggregated_unrouted(
                "semantic calls unrouted".into(),
                total,
                labels,
                self.semantic_bindings.len(),
            );
            lane.note_shed_calls(total);
        }
        if !other_shed_reasons.is_empty() {
            let total: u64 = other_shed_reasons.iter().map(|(_, count)| count).sum();
            let labels: Vec<(String, u64)> = other_shed_reasons
                .iter()
                .map(|(label, count)| (label.to_string(), *count))
                .collect();
            self.registry.note_foreign_unrouted_calls(total);
            // Aggregated lane-wide: the per-drain single-owner
            // attribution is transient; the summed row names no
            // caller so every drain lands in one row.
            self.registry.record_aggregated_unrouted(
                "semantic calls unrouted from other callers".into(),
                total,
                labels,
                self.semantic_bindings.len(),
            );
            lane.note_shed_calls(total);
        }
        // Pre-binding sheds were disclosed (and counted) when shed; the
        // first binding proved them other callers', so their barrier is
        // released. Say so: a note, never a second count.
        if let Some(held) = resolved_other {
            let total: u64 = held.labels.iter().map(|(_, count)| count).sum();
            let caller = held
                .pid
                .flatten()
                .and_then(|pid| self.adapter.live_id(pid))
                .filter(|caller| self.semantic_bindings.get(*caller).is_none());
            self.registry.record_gap(RegistryGap {
                caller,
                module: None,
                pid: None,
                subject: PRE_BINDING_OTHER_CALLERS.into(),
                reason: format!(
                    "{total} calls shed before the first binding came from callers other than the {} bound callers; their history is kept",
                    self.semantic_bindings.len()
                ),
                budget: None,
            });
        }
        // Validated registrations second: every covered id registers.
        // Conversion borrows end before staging mutates the registry.
        let registration_start = self.registry.begin_joint_registrations();
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
                    .filter(|binding| !self.adapter.leader_exit_pending(binding.caller()))
                else {
                    continue;
                };
                let caller = binding.caller();
                // A retained image's calls were first observed at its
                // drain, passes before this batch: stamp the registration
                // then, so a fully joined post-attach burst does not
                // disclose a boundary gap it never crossed. Never postdate.
                let observed = lane
                    .retained_registration_ns(binding.image())
                    .map_or(observed_ns, |drained| drained.min(observed_ns));
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
                                observed,
                                None,
                            ),
                        )
                    })
                    .collect()
            };
            for (caller, result) in staged {
                self.apply_staged_registration(caller, result);
            }
        }
        let registrations = self.registry.end_joint_registrations(registration_start);
        // Eligible calls last, in original position order.
        #[cfg(test)]
        lane.note_conversion_barrier(barrier);
        calls.sort_by_key(CallEvidence::token);
        let subset = lane.subset();
        // Joined init taps collected across conversion, applied
        // below: the map borrows the registry it would tap.
        let mut init_taps: Vec<(ModuleId, u64)> = Vec::new();
        // (image, file) per current admission: armed on the lane's
        // router after staging, so the key's next continued
        // observation mints the birth quantum the sighting slice
        // wasted. Kept beside the staged batch (the closure below
        // only borrows the lane through `subset`).
        let mut admitted_marks: Vec<(ImageIdentity, u32)> = Vec::new();
        // Diagnostic-only funnel beside the marks: admissions that
        // found no binding for their image. Counted here, armed on
        // the lane's router after staging like the marks.
        let mut binding_misses: u64 = 0;
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
                // A refused Joined `C_Initialize` still counts its
                // return on the endpoint's module: read the tap facts
                // before the consuming conversion below, mirroring the
                // shed tap.
                let joined_init = evidence.refused_init_facts();
                let found = self
                    .semantic_bindings
                    .find_by_image(evidence.domain(), evidence.image());
                let (caller, converted) = match found {
                    None => {
                        binding_misses = binding_misses.saturating_add(1);
                        (None, Err(ConversionRefusal::Custody))
                    }
                    Some(binding) => {
                        let caller = binding.caller();
                        if self.adapter.leader_exit_pending(caller) {
                            (Some(caller), Err(ConversionRefusal::Custody))
                        } else {
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
                            let admitted = admit_call_from_evidence(
                                evidence, binding, subset, standing, barrier,
                            );
                            // Current admissions only: historical calls never
                            // seal, so they arm no mint.
                            if admitted.is_ok()
                                && let Some(coverage) = coverage
                            {
                                admitted_marks
                                    .push((coverage.image(), coverage.endpoint().file_slot));
                            }
                            (Some(caller), admitted)
                        }
                    }
                };
                match converted.as_ref() {
                    // A converted `C_Initialize` taps the module roll-up:
                    // conversion proved the caller binding, the attested
                    // slot name and the provider module.
                    Ok(admitted) if admitted.s1_facts().function == module_init::C_INITIALIZE => {
                        if let Some(module) =
                            self.registry.module_id_for(admitted.provider_module())
                        {
                            init_taps.push((module, admitted.s1_facts().rv));
                        }
                    }
                    // A refused `C_Initialize` taps under the shed
                    // proof standard: the attested slot names it and the
                    // endpoint proves the module. The tap reads the
                    // refusal without consuming its disclosure: the
                    // staged entry still sheds with a conversion gap.
                    Err(_)
                        if let Some((endpoint, slot, rv)) = joined_init
                            && module_init::init_slot_for_shed(subset.plan(), slot, &endpoint)
                            && let Some(module) = self.init_module_for_object(
                                subset,
                                endpoint.object,
                                &mut init_objects,
                            ) =>
                    {
                        init_taps.push((module, rv));
                    }
                    _ => {}
                }
                (caller, token, converted)
            })
            .collect();
        for (module, rv) in init_taps {
            self.registry.note_module_init(module, rv);
        }
        for (image, file) in admitted_marks {
            lane.mark_admitted_for(image, file);
        }
        lane.note_admission_binding_misses_for(binding_misses);
        Some(PreparedSemanticBatch::new(
            domain,
            staged.into_iter().map(PreparedAdmission::new).collect(),
            current,
            registrations,
            PreparedH3 {
                negatives,
                staged_positions,
                awaiting_floor: batch_awaiting,
                shed_floor: batch_shed.into_iter().chain(shed_min).min(),
                exhausted: batch_exhausted || unpositioned,
            },
        ))
    }

    fn finish_semantic_preparation(
        &mut self,
        prepared: PreparedSemanticBatch,
        stash_pending_floor: Option<u64>,
    ) {
        let mut h3 = prepared.into_h3();
        let state = self
            .semantic_finalizer
            .as_mut()
            .expect("finalization retains the matching Session namespace");
        if let Some((floor, exhausted)) = state.pending_drop.take() {
            h3.shed_floor = Some(h3.shed_floor.map_or(floor, |at| at.min(floor)));
            h3.exhausted = h3.exhausted || exhausted;
        }
        let unpublished = state
            .pending_semantic
            .as_ref()
            .and_then(PendingSemanticBatch::min_outcome_position)
            .into_iter()
            .chain(stash_pending_floor)
            .min();
        let evidence =
            crate::semantics_objects::journal::H3DispositionEvidence::from_finalizer_batch(
                &h3.negatives,
                &h3.staged_positions,
                h3.awaiting_floor,
                h3.shed_floor,
                unpublished,
                h3.exhausted,
                &state.h3_last,
                state.h3_acked_below,
            );
        state.h3_last = evidence.clone();
        state.h3_pending = Some(evidence);
    }

    /// Apply one staged registration: admissions stage for commit,
    /// refusals mark the caller refused and disclose through the
    /// audited path, so the terminal counts never call the caller a
    /// timing miss.
    fn apply_staged_registration(
        &mut self,
        caller: CallerId,
        result: Result<
            crate::discovery::caller_registry::instance_input::AdmittedInstance,
            ConversionRefusal,
        >,
    ) {
        match result {
            Ok(input) => self.registry.note_instance(input),
            Err(reason) => {
                self.registry.note_registration_refused(caller);
                self.conversion_gap(Some(caller), reason);
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

    /// Latch the run's semantic seal on the registry: the driver
    /// calls this on the sealed arms, so init evidence and the
    /// honest absence wording exist only past the seal.
    pub(crate) fn note_semantic_sealed(&mut self) {
        self.registry.set_semantic_sealed();
    }

    /// Resolve a shed endpoint's object to its registry module
    /// through the conversion predicate (physical key plus retained
    /// digest), cached per batch in `cache`.
    fn init_module_for_object(
        &self,
        subset: &AttestedSubset,
        object: PinnedObjectId,
        cache: &mut BTreeMap<PinnedObjectId, Option<ModuleId>>,
    ) -> Option<ModuleId> {
        if let Some(known) = cache.get(&object) {
            return *known;
        }
        let module = self
            .registry
            .modules()
            .find(|record| subset.proves_provider_module(object, &record.key))
            .map(|record| record.id);
        cache.insert(object, module);
        module
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
        vec![],
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

    #[test]
    fn only_a_different_cookie_of_the_bound_domain_proves_another_caller() {
        let domain = NativeDomainId::mint();
        let image = |task_cookie| ImageIdentity {
            task_cookie,
            exec_id: 1,
        };
        let empty = SemanticBindingSet::new();
        assert!(
            !empty.proves_unbound_caller(domain, image(5)),
            "no bound caller: nothing to prove against, keep the barrier"
        );
        let unknown_bound = windowed_set(3);
        let bound = unknown_bound.bindings[0].domain();
        assert!(
            !unknown_bound.proves_unbound_caller(bound, image(99)),
            "a bound caller without a known image could own any call"
        );
        let mut set = SemanticBindingSet::new();
        for cookie in 1..=3u64 {
            set.insert(SemanticCallerBinding::scripted(
                CallerId(cookie as u32),
                ModuleKey::physical(7, 7, 777, None, "/window/provider.so"),
                bound,
                image(cookie),
                Arc::new(PidPin::test_proc_only(1234)),
            ))
            .unwrap();
        }
        assert!(set.proves_unbound_caller(bound, image(99)));
        assert!(
            !set.proves_unbound_caller(bound, image(0)),
            "an unknown image could be the bound caller"
        );
        assert!(
            !set.proves_unbound_caller(bound, image(2)),
            "the bound caller's own image barriers"
        );
        assert!(
            !set.proves_unbound_caller(
                bound,
                ImageIdentity {
                    task_cookie: 2,
                    exec_id: 9,
                }
            ),
            "an exec keeps the cookie and still matches"
        );
        assert!(
            !set.proves_unbound_caller(domain, image(99)),
            "a binding of another domain is another ticket space"
        );
        // Admission history is part of the proof: a same-domain history
        // with another cookie keeps the proof, one holding the call's
        // cookie or one from another domain barriers.
        let history = |domain, cookie| SemanticAdmissionHistory {
            domain,
            image: image(cookie),
            incarnation: 1,
            generation: crate::inspect_system::MemberGeneration {
                start_time: None,
                exe: None,
            },
            pin: Arc::new(PidPin::test_proc_only(1234)),
            initial_scope_cut: false,
            pending_gap: None,
        };
        set.admission_images
            .insert(CallerId(20), history(bound, 55));
        assert!(
            set.proves_unbound_caller(bound, image(99)),
            "a different same-domain history keeps the proof"
        );
        set.admission_images
            .insert(CallerId(21), history(bound, 99));
        assert!(
            !set.proves_unbound_caller(bound, image(99)),
            "a history entry holding the call's cookie could be that caller"
        );
        set.admission_images.remove(&CallerId(21));
        set.admission_images
            .insert(CallerId(22), history(domain, 56));
        assert!(
            !set.proves_unbound_caller(bound, image(99)),
            "a history entry of another domain is another ticket space"
        );
    }

    fn refused_proof_image(task_cookie: u64, exec_id: u64) -> ImageIdentity {
        ImageIdentity {
            task_cookie,
            exec_id,
        }
    }

    fn refused_proof_history(
        domain: NativeDomainId,
        task_cookie: u64,
        exec_id: u64,
    ) -> SemanticAdmissionHistory {
        SemanticAdmissionHistory {
            domain,
            image: refused_proof_image(task_cookie, exec_id),
            incarnation: 1,
            generation: crate::inspect_system::MemberGeneration {
                start_time: None,
                exe: None,
            },
            pin: Arc::new(PidPin::test_proc_only(1234)),
            initial_scope_cut: false,
            pending_gap: None,
        }
    }

    fn refused_proof_bind(
        set: &mut SemanticBindingSet,
        caller: u32,
        domain: NativeDomainId,
        task_cookie: u64,
        exec_id: u64,
    ) {
        set.insert(SemanticCallerBinding::scripted(
            CallerId(caller),
            ModuleKey::physical(7, 7, 777, None, "/window/provider.so"),
            domain,
            refused_proof_image(task_cookie, exec_id),
            Arc::new(PidPin::test_proc_only(1234)),
        ))
        .unwrap();
    }

    #[test]
    fn refused_proof_needs_every_same_cookie_history_refused() {
        // The candidate (77, 3) and its exec successor (77, 9) are
        // refused; an older same-cookie exec (77, 5) stays unrefused.
        // One unrefused same-cookie admission-history entry must fail
        // the proof even when the same-cookie binding is refused.
        let domain = NativeDomainId::mint();
        let refused =
            |candidate: ImageIdentity| candidate.task_cookie == 77 && candidate.exec_id != 5;
        let mut set = SemanticBindingSet::new();
        refused_proof_bind(&mut set, 1, domain, 77, 9);
        set.admission_images
            .insert(CallerId(20), refused_proof_history(domain, 77, 9));
        assert!(
            set.proves_refused_other_caller(domain, refused_proof_image(77, 3), refused),
            "a refused candidate with every same-cookie binding and history refused proves"
        );
        set.admission_images
            .insert(CallerId(21), refused_proof_history(domain, 77, 5));
        assert!(
            !set.proves_refused_other_caller(domain, refused_proof_image(77, 3), refused),
            "one unrefused same-cookie history entry keeps the barrier"
        );
        // Same verdict without any same-cookie binding: the history
        // alone blocks.
        let mut lone = SemanticBindingSet::new();
        refused_proof_bind(&mut lone, 2, domain, 41, 1);
        lone.admission_images
            .insert(CallerId(20), refused_proof_history(domain, 77, 5));
        assert!(
            !lone.proves_refused_other_caller(domain, refused_proof_image(77, 3), refused),
            "an unrefused same-cookie history blocks with no same-cookie binding"
        );
    }

    #[test]
    fn refused_proof_needs_the_candidate_image_refused() {
        // Every same-cookie binding and history entry is refused, but
        // the shed's own image (77, 3) is not: the proof must fail, so
        // the shed barriers instead of disposing.
        let domain = NativeDomainId::mint();
        let refused = |candidate: ImageIdentity| candidate == refused_proof_image(77, 9);
        let mut set = SemanticBindingSet::new();
        refused_proof_bind(&mut set, 1, domain, 77, 9);
        set.admission_images
            .insert(CallerId(20), refused_proof_history(domain, 77, 9));
        assert!(
            !set.proves_refused_other_caller(domain, refused_proof_image(77, 3), refused),
            "an unrefused candidate never proves, however refused its cookie-mates are"
        );
        assert!(
            set.proves_refused_other_caller(domain, refused_proof_image(77, 9), refused),
            "the refused image itself still proves against the same set"
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

    /// A structurally valid 512-object manifest over 512 distinct real
    /// files (same bytes, distinct inodes): the object-cap twin's input.
    fn wide_manifest(dir: &std::path::Path) -> Manifest {
        let base = dir.join("obj-000.so");
        std::fs::copy("/bin/true", &base).unwrap();
        let file = open_object(&base).unwrap();
        let inspected = inspect_file(&file).unwrap();
        let mut objects = Vec::new();
        let mut provenance = Vec::new();
        for i in 0..512u32 {
            let path = dir.join(format!("obj-{i:03}.so"));
            if i > 0 {
                std::fs::copy(&base, &path).unwrap();
            }
            let spelling = path.to_str().unwrap().to_string();
            let open = open_object(&path).unwrap();
            let key = mapping_file_key(&open).unwrap();
            objects.push(ObjectRecord {
                id: i,
                path: spelling.clone(),
                identity: inspected.identity.clone(),
            });
            provenance.push(ProvenanceObject {
                path: spelling,
                device_major: key.device_major,
                device_minor: key.device_minor,
                inode: key.inode,
                identity: inspected.identity.clone(),
            });
        }
        Manifest {
            schema: SCHEMA.into(),
            module_path: objects[0].path.clone(),
            objects,
            provenance_objects: provenance,
            interface_list: Acquisition::Absent,
            surfaces: vec![SurfaceRecord {
                source: SurfaceSource::LegacyFunctionList,
                acquisition: Acquisition::Ok,
                version: Some(Version {
                    major: 2,
                    minor: 40,
                }),
                walk: WalkOutcome::Full,
                functions: vec![FunctionRecord {
                    name: "C_Initialize".into(),
                    resolution: Resolution::NullPointer,
                }],
            }],
            vendor_interfaces: vec![],
            alias_groups: vec![],
            selection_evidence: Default::default(),
        }
    }

    #[test]
    fn semantic_manifest_pinning_charges_retained_prearm_objects() {
        // Packet 6.13 round-3 (re-audit finding 3, N+1 with both input
        // classes): one real retained pre-arm pin plus a 512-object
        // manifest exceeds the shared 512-object budget — the semantic
        // reader refuses at pinning, before opening anything.
        let dir = tempfile::tempdir().unwrap();
        let prearm_path = dir.path().join("prearm-real.so");
        std::fs::copy("/bin/true", &prearm_path).unwrap();
        let prearm = crate::discovery::identity::pin_prearm_objects_in_views_with_budget(
            std::slice::from_ref(&prearm_path),
            &[],
            None,
            0,
            0,
            &mut crate::discovery::scan::CaptureWorkBudget::default(),
        )
        .expect("one real pre-arm pin");
        let prior_objects = prearm.pins.pinned().count();
        let prior_bytes = prearm.pins.pinned_object_bytes();
        assert_eq!(prior_objects, 1);

        let wide_dir = tempfile::tempdir().unwrap();
        let manifest = wide_manifest(wide_dir.path());
        assert_eq!(manifest.objects.len(), 512);
        assert!(
            crate::manifest_input::validate_structure(&manifest).is_empty(),
            "the N+1 manifest is structurally valid, so only the budget can refuse it"
        );
        let input = wide_dir.path().join("operator-input.json");
        std::fs::write(&input, serde_json::to_vec(&manifest).unwrap()).unwrap();
        // The engine pins the first object independently, mirroring how
        // `subset` attests: pinning success must be reachable, so only
        // the budget refusal distinguishes the charged run.
        let first = crate::discovery::identity::pin_manifest_objects_deferred(&Manifest {
            objects: manifest.objects[..1].to_vec(),
            provenance_objects: manifest.provenance_objects[..1].to_vec(),
            ..manifest.clone()
        })
        .expect("the first wide object pins alone");
        let engine = engine_for_test(Vec::new(), Vec::new(), first.pins);
        let mut charged = SemanticInputs::new(vec![input]);
        charged.set_prearm_prior(prior_objects, prior_bytes);
        let refused = charged.prepare(&engine);
        assert_eq!(
            refused.refusals,
            vec![SemanticRefusal::ManifestInput],
            "1 retained + 512 manifest objects exceed the shared cap"
        );
        // Control: a small manifest with the same retained usage attests —
        // the charge refuses only the over-budget input.
        let small = HistoryFixture::new();
        let small_input = small.dir.path().join("operator-input.json");
        std::fs::write(&small_input, serde_json::to_vec(&small.manifest).unwrap()).unwrap();
        let small_engine = engine_for_test(Vec::new(), Vec::new(), small.pins.clone());
        let mut charged_small = SemanticInputs::new(vec![small_input]);
        charged_small.set_prearm_prior(prior_objects, prior_bytes);
        let accepted = charged_small.prepare(&small_engine);
        assert!(
            !accepted.refusals.contains(&SemanticRefusal::ManifestInput),
            "a small manifest with retained usage still pins"
        );
        assert!(
            accepted.subset.is_some(),
            "the charged small manifest attests like any other operator input"
        );
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
        receiptless_joined_case(false, false);
    }

    #[test]
    fn pending_leader_exit_refuses_receiptless_semantic_history() {
        receiptless_joined_case(true, false);
    }

    #[test]
    fn pending_leader_exit_refuses_already_prepared_admission() {
        receiptless_joined_case(true, true);
    }

    fn receiptless_joined_case(pending_exit: bool, already_prepared: bool) {
        let pid = std::process::id();
        let mut coordinator = InventoryCoordinator::new(
            Scope::Pid(pid),
            HookRegistry::builtin(),
            Vec::new(),
            vec![],
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
        if already_prepared {
            coordinator
                .prepare_staged_semantic_batch(&mut lane, None)
                .unwrap();
        }
        if pending_exit {
            coordinator.adapter.mark_leader_exit_pending(caller, true);
        }
        if already_prepared {
            coordinator.dispose_prepared_claims_s1();
            while coordinator.stage_next_prepared_admission(false, true) {}
            assert!(coordinator.finish_prepared_semantic_batch(&lane));
        }
        coordinator
            .commit_batch_with_semantics(false, Some(&mut lane))
            .unwrap();
        if pending_exit {
            let refused: u64 = coordinator
                .registry()
                .gaps()
                .iter()
                .zip(coordinator.registry().gap_repeats())
                .filter(|(gap, _)| {
                    gap.caller == Some(caller)
                        && gap.subject == "semantic input refused"
                        && gap.reason == "custody"
                })
                .map(|(_, count)| *count)
                .sum();
            let api: u64 = coordinator
                .registry()
                .instance_semantic_edges()
                .map(|row| row.api_returns.unwrap_or(0))
                .sum();
            let historical: u64 = coordinator
                .registry()
                .instance_semantic_edges()
                .map(|row| row.historical_only_returns)
                .sum();
            assert_eq!(
                (api, historical, refused),
                (0, 0, 1),
                "the one raw joined call is conserved as custody refusal, with no semantic positive"
            );
            return;
        }
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

    /// A staged registration refusal marks the caller refused and
    /// still discloses through the audited path; an admission marks
    /// nothing.
    #[test]
    fn staged_registration_refusal_marks_the_caller_refused() {
        use crate::discovery::caller_registry::instance_input::{
            AdmittedInstance, ConversionRefusal, InstanceKey,
        };
        let pid = std::process::id();
        let mut coordinator = InventoryCoordinator::new(
            Scope::Pid(pid),
            HookRegistry::builtin(),
            Vec::new(),
            vec![],
            OsProcessSource,
            RegistryLimits::default_limits(),
        )
        .unwrap();
        let caller = coordinator
            .adapter_mut()
            .admit(pid, ImageAuthority::ScanPinned, 50)
            .unwrap();
        let domain = NativeDomainId::mint();
        let key = InstanceKey::scripted(
            domain,
            ImageIdentity {
                task_cookie: 7,
                exec_id: 1,
            },
            InstanceId::from_raw(11),
            ModuleKey::physical(7, 7, 777, None, "/staged/provider.so"),
        );
        coordinator.apply_staged_registration(caller, Ok(AdmittedInstance::scripted(key, caller)));
        assert!(
            !coordinator.registry().registration_refused(caller),
            "an admitted registration marks nothing"
        );
        coordinator.apply_staged_registration(caller, Err(ConversionRefusal::Custody));
        assert!(
            coordinator.registry().registration_refused(caller),
            "a refused registration marks its caller"
        );
        coordinator.commit_batch(false).unwrap();
        assert!(
            coordinator.registry().gaps().iter().any(|gap| {
                gap.caller == Some(caller)
                    && gap.subject == "semantic input refused"
                    && gap.reason == "custody"
            }),
            "the refusal still discloses through the audited path"
        );
    }

    fn drop_test_lanes() -> (
        InventoryCoordinator<OsProcessSource>,
        AttestedSemanticLane,
        NativeDomainId,
    ) {
        let pid = std::process::id();
        let coordinator = InventoryCoordinator::new(
            Scope::Pid(pid),
            HookRegistry::builtin(),
            Vec::new(),
            vec![],
            OsProcessSource,
            RegistryLimits::default_limits(),
        )
        .unwrap();
        let fixture = HistoryFixture::new();
        let lane =
            AttestedSemanticLane::start(fixture.subset(), &Scope::Pid(pid), BackendSelection::Auto)
                .expect("shell lane starts");
        let domain = lane.domain();
        (coordinator, lane, domain)
    }

    fn drop_test_batch(domain: NativeDomainId, routes: Vec<Route>) -> SemanticBatch {
        let outcomes = routes
            .into_iter()
            .enumerate()
            .map(|(n, route)| {
                let stamp = InstanceStamp::default();
                TickOutcome::Call(RoutedCall::scripted(
                    domain,
                    crate::events::DecodedEventRecord {
                        joint_resource: None,
                        base: crate::semantic_capture::event_record_with_routing(
                            Event::default(),
                            stamp,
                            0x2200,
                        ),
                        object: None,
                    },
                    route,
                    None,
                    Some(n as u64 + 1),
                ))
            })
            .collect();
        SemanticBatch::from_tick_report(
            domain,
            TickReport::scripted(outcomes, Vec::new()),
            Vec::new(),
            130,
        )
        .unwrap()
    }

    fn unrouted_gap_reasons(
        coordinator: &InventoryCoordinator<OsProcessSource>,
    ) -> Vec<(String, u64)> {
        let registry = coordinator.registry();
        registry
            .gaps()
            .iter()
            .zip(registry.gap_repeats().iter())
            .filter(|(gap, _)| gap.subject == "semantic calls unrouted")
            .map(|(gap, repeats)| (gap.reason.clone(), *repeats))
            .collect()
    }

    #[test]
    fn stage_ended_domain_drop_counts_unjoined_calls_into_shed() {
        use crate::discovery::instances::UnknownReason;
        // A batch refused at staging for an ended domain still sheds its
        // unjoined calls with the drop label at the next commit: joined
        // calls stay joined (already counted), unknown and pending calls
        // shed once with their route labels.
        let (mut coordinator, mut lane, domain) = drop_test_lanes();
        // The stash needs the domain's live namespace: the shed waits
        // there for the commit flush.
        coordinator.semantic_finalizer = Some(SessionFinalizerState::new(domain));
        let batch = drop_test_batch(
            domain,
            vec![
                Route::Joined(InstanceId::from_raw(1)),
                Route::Unknown(UnknownReason::Unobserved),
                Route::Unknown(UnknownReason::Unobserved),
                Route::Unknown(UnknownReason::Evicted),
                Route::Pending,
            ],
        );
        coordinator.refused_semantic_domains.insert(domain);
        coordinator.stage_semantic_batch(batch);
        assert_eq!(
            lane.shed_calls_disclosed(),
            0,
            "the staged drop waits for the commit flush"
        );
        coordinator
            .commit_batch_with_semantics(false, Some(&mut lane))
            .unwrap();
        assert_eq!(
            lane.shed_calls_disclosed(),
            4,
            "the three unknown plus the pending call shed once"
        );
        assert_eq!(
            unrouted_gap_reasons(&coordinator),
            vec![(
                "4 calls shed from a dropped ended_domain batch (evicted=1 pending=1 unobserved=2) with 0 bindings"
                    .to_string(),
                1
            )],
            "the drop shed keeps its drop label and route labels"
        );
    }

    #[test]
    fn abandon_stranded_collected_batch_drops_through_the_audited_path() {
        use crate::discovery::instances::UnknownReason;
        // A Collected batch stranded by the latched machine drops
        // through the audited path at abandon: its H3 shed shadow
        // lands immediately and its unjoined calls shed once with
        // the abandon label, so the stop-line identity holds without
        // a later commit.
        let (mut coordinator, mut lane, domain) = drop_test_lanes();
        coordinator.semantic_finalizer = Some(SessionFinalizerState::new(domain));
        let batch = drop_test_batch(
            domain,
            vec![
                Route::Joined(InstanceId::from_raw(1)),
                Route::Unknown(UnknownReason::Unobserved),
                Route::Pending,
            ],
        );
        coordinator.stage_semantic_batch(batch);
        assert!(
            coordinator.joint_domain_has_pending_work(domain),
            "the staged batch pends its finalization"
        );
        coordinator.abandon_stranded_semantic_batches(&mut lane);
        // The drop shadow is real pending H3 work for the next mint
        // (its barrier voids there), so pending-work stays true by
        // design; the shadow and shed below prove the take consumed
        // this batch itself.
        assert_eq!(
            coordinator
                .semantic_finalizer
                .as_ref()
                .expect("the namespace survives the abandon")
                .pending_drop,
            Some((1, false)),
            "the drop shadows the batch's lowest position"
        );
        assert_eq!(
            lane.shed_calls_disclosed(),
            2,
            "the unknown plus the pending call shed once; the joined call stays joined"
        );
        coordinator
            .commit_batch_with_semantics(false, Some(&mut lane))
            .unwrap();
        assert_eq!(
            unrouted_gap_reasons(&coordinator),
            vec![(
                "2 calls shed from a dropped abandoned batch (pending=1 unobserved=1) with 0 bindings"
                    .to_string(),
                1
            )],
            "the drop shed keeps its abandon label and route labels"
        );
    }

    #[test]
    fn stray_batch_for_retired_domain_creates_no_namespace() {
        use crate::discovery::instances::UnknownReason;
        // A stray batch for a retired domain is refused through the
        // audited path without recreating a finalizer namespace: with
        // no live namespace the stash has nowhere to flush to, so
        // nothing is retained — and a later domain stages unrefused.
        let (mut coordinator, _lane, domain_a) = drop_test_lanes();
        coordinator.semantic_finalizer = Some(SessionFinalizerState::new(domain_a));
        coordinator
            .retire_joint_domain(
                crate::inventory_promotion::lifecycle::SessionNativeCompletion::scripted(domain_a),
            )
            .expect("quiescent A retires");
        assert!(coordinator.semantic_finalizer.is_none());
        assert!(coordinator.refused_semantic_domains.contains(&domain_a));
        let stray = drop_test_batch(
            domain_a,
            vec![
                Route::Unknown(UnknownReason::Unobserved),
                Route::Unknown(UnknownReason::Unobserved),
            ],
        );
        coordinator.stage_semantic_batch(stray);
        assert!(
            coordinator.semantic_finalizer.is_none(),
            "the stray batch recreates no namespace for the retired domain"
        );
        // Gaps stage at refusal and publish at commit.
        coordinator.commit_batch(false).unwrap();
        let subjects: Vec<String> = coordinator
            .registry()
            .gaps()
            .iter()
            .map(|gap| gap.subject.clone())
            .collect();
        assert!(
            subjects.contains(&"semantic batch refused for an ended domain".to_string()),
            "the stray refusal stays disclosed, got {subjects:?}"
        );
        // A later domain stages into a fresh namespace, unrefused.
        let domain_b = NativeDomainId::try_mint().expect("test domain mints");
        coordinator.stage_semantic_batch(drop_test_batch(
            domain_b,
            vec![Route::Joined(InstanceId::from_raw(1))],
        ));
        let state = coordinator
            .semantic_finalizer
            .as_ref()
            .expect("the later domain stages");
        assert_eq!(state.domain, domain_b);
        assert!(state.pending_semantic.is_some(), "B's batch stages");
        coordinator.commit_batch(false).unwrap();
        let subjects: Vec<String> = coordinator
            .registry()
            .gaps()
            .iter()
            .map(|gap| gap.subject.clone())
            .collect();
        assert!(
            !subjects
                .iter()
                .any(|subject| subject == "semantic batch refused for another Session"),
            "the later domain is not refused, got {subjects:?}"
        );
    }

    #[test]
    fn stage_backpressure_drop_counts_unjoined_calls_into_shed() {
        use crate::discovery::instances::UnknownReason;
        // A batch dropped for backpressure sheds its unjoined calls with
        // the drop label when the occupying batch commits.
        let (mut coordinator, mut lane, domain) = drop_test_lanes();
        let occupying = SemanticBatch::scripted(domain, Vec::new(), 120);
        let dropped = drop_test_batch(
            domain,
            vec![
                Route::Unknown(UnknownReason::Unobserved),
                Route::Unknown(UnknownReason::Unobserved),
            ],
        );
        coordinator.stage_semantic_batch(occupying);
        coordinator.stage_semantic_batch(dropped);
        coordinator
            .commit_batch_with_semantics(false, Some(&mut lane))
            .unwrap();
        assert_eq!(
            lane.shed_calls_disclosed(),
            2,
            "the backpressure drop sheds its unknown calls once"
        );
        assert_eq!(
            unrouted_gap_reasons(&coordinator),
            vec![(
                "2 calls shed from a dropped backpressure batch (unobserved=2) with 0 bindings"
                    .to_string(),
                1
            )],
            "the drop shed keeps its drop label"
        );
    }

    #[test]
    fn prepare_ended_domain_drop_counts_unjoined_calls_into_shed() {
        use crate::discovery::instances::UnknownReason;
        // A batch staged while live but finalized after its domain ended
        // sheds its unjoined calls directly at preparation.
        let (mut coordinator, mut lane, domain) = drop_test_lanes();
        let batch = drop_test_batch(
            domain,
            vec![
                Route::Joined(InstanceId::from_raw(1)),
                Route::Unknown(UnknownReason::Unobserved),
                Route::Pending,
            ],
        );
        coordinator.stage_semantic_batch(batch);
        coordinator.refused_semantic_domains.insert(domain);
        coordinator
            .commit_batch_with_semantics(false, Some(&mut lane))
            .unwrap();
        assert_eq!(
            lane.shed_calls_disclosed(),
            2,
            "the refused preparation sheds unknown plus pending once"
        );
        assert_eq!(
            unrouted_gap_reasons(&coordinator),
            vec![(
                "2 calls shed from a dropped ended_domain batch (pending=1 unobserved=1) with 0 bindings"
                    .to_string(),
                1
            )],
            "the drop shed keeps its drop label and route labels"
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
            vec![],
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
            vec![],
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
            vec![],
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
            vec![],
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

    /// One unrouted call whose record carries `cookie` as its image.
    fn unrouted_call(domain: NativeDomainId, cookie: u64, position: u64) -> TickOutcome {
        use crate::discovery::instances::UnknownReason;
        let event = Event {
            pid_tgid: (4242u64 << 32) | 4242,
            image: ImageIdentity {
                task_cookie: cookie,
                exec_id: 3,
            },
            ..Event::default()
        };
        TickOutcome::Call(RoutedCall::scripted(
            domain,
            crate::events::DecodedEventRecord {
                joint_resource: None,
                base: crate::semantic_capture::event_record_with_routing(
                    event,
                    InstanceStamp::default(),
                    0x2200,
                ),
                object: None,
            },
            Route::Unknown(UnknownReason::Unobserved),
            None,
            Some(position),
        ))
    }

    /// Calls disclosed by every unrouted gap, whatever its subject.
    fn unrouted_gap_calls(coordinator: &InventoryCoordinator<OsProcessSource>) -> u64 {
        let registry = coordinator.registry();
        registry
            .gaps()
            .iter()
            .zip(registry.gap_repeats().iter())
            .filter(|(gap, _)| gap.subject.starts_with("semantic calls unrouted"))
            .map(|(gap, repeats)| {
                let count: u64 = gap
                    .reason
                    .split_whitespace()
                    .next()
                    .and_then(|first| first.parse().ok())
                    .expect("unrouted gaps lead with their call count");
                count * repeats
            })
            .sum()
    }

    #[test]
    fn unrouted_calls_of_a_provably_other_caller_keep_the_bound_history() {
        use crate::semantic_capture::Invalidation;
        use crate::semantics_objects::journal::H3DispositionEvidence;
        // A bound Joint caller holds image cookie 41. Unrouted calls whose
        // record proves another caller (a different nonzero cookie of the
        // same domain) are still shed and disclosed, but no longer stand
        // as an H3 loss barrier for the bound caller. An unknown image
        // (cookie 0) or the bound caller's own image still barriers.
        const BOUND: u64 = 41;
        for (cookie, other) in [(77u64, true), (0, false), (BOUND, false)] {
            let (mut coordinator, mut lane, domain) = drop_test_lanes();
            coordinator
                .semantic_bindings
                .insert(SemanticCallerBinding::scripted(
                    CallerId(9),
                    ModuleKey::physical(7, 7, 777, None, "/bound/provider.so"),
                    domain,
                    ImageIdentity {
                        task_cookie: BOUND,
                        exec_id: 1,
                    },
                    Arc::new(PidPin::test_proc_only(1234)),
                ))
                .unwrap();
            let report = TickReport::scripted_with_disposition(
                vec![
                    TickOutcome::Invalidation(Invalidation::scripted(
                        domain,
                        crate::semantic_capture::InvalidationScope::CoverageFailed,
                        Some(1),
                    )),
                    unrouted_call(domain, cookie, 2),
                    unrouted_call(domain, cookie, 3),
                ],
                Vec::new(),
                None,
                None,
                false,
            );
            let batch = SemanticBatch::from_tick_report(domain, report, Vec::new(), 130).unwrap();
            coordinator.stage_semantic_batch(batch);
            coordinator
                .commit_batch_with_semantics(false, Some(&mut lane))
                .unwrap();
            let evidence = coordinator.take_h3_disposition();
            if other {
                assert!(
                    matches!(
                        evidence,
                        H3DispositionEvidence::Clean {
                            staged_max: 3,
                            pending_floor: None
                        }
                    ),
                    "another caller's unrouted calls leave the bound history whole: {evidence:?}"
                );
            } else {
                assert!(
                    matches!(evidence, H3DispositionEvidence::StagedLoss { barrier: 2 }),
                    "an unknown or bound image still barriers (cookie {cookie}): {evidence:?}"
                );
            }
            // The published loss is the same either way: both calls are
            // shed and disclosed.
            assert_eq!(lane.shed_calls_disclosed(), 2, "cookie {cookie}");
            assert_eq!(unrouted_gap_calls(&coordinator), 2, "cookie {cookie}");
            // Only a provably other caller's sheds count as foreign
            // for the key-operation unattributed counters.
            assert_eq!(
                coordinator.registry().foreign_unrouted_calls(),
                if other { 2 } else { 0 },
                "cookie {cookie}"
            );
        }
    }

    #[test]
    fn two_unrouted_drains_aggregate_into_one_counted_row() {
        // Per-drain unrouted sheds used to land one gap row per
        // distinct shed count; repeated drains now sum into one
        // counted row per (subject, bindings).
        const BOUND: u64 = 41;
        let (mut coordinator, mut lane, domain) = drop_test_lanes();
        coordinator
            .semantic_bindings
            .insert(SemanticCallerBinding::scripted(
                CallerId(9),
                ModuleKey::physical(7, 7, 777, None, "/bound/provider.so"),
                domain,
                ImageIdentity {
                    task_cookie: BOUND,
                    exec_id: 1,
                },
                Arc::new(PidPin::test_proc_only(1234)),
            ))
            .unwrap();
        for (base_ns, positions) in [(130u64, vec![2u64, 3]), (140, vec![4, 5, 6])] {
            let outcomes: Vec<TickOutcome> = positions
                .into_iter()
                .map(|position| unrouted_call(domain, 77, position))
                .collect();
            let report =
                TickReport::scripted_with_disposition(outcomes, Vec::new(), None, None, false);
            let batch =
                SemanticBatch::from_tick_report(domain, report, Vec::new(), base_ns).unwrap();
            coordinator.stage_semantic_batch(batch);
            coordinator
                .commit_batch_with_semantics(false, Some(&mut lane))
                .unwrap();
        }
        // Both drains shed other-caller calls with one binding: one
        // row, 2 + 3 = 5 calls.
        let rows: Vec<_> = coordinator
            .registry()
            .gaps()
            .iter()
            .filter(|gap| gap.subject == "semantic calls unrouted from other callers")
            .collect();
        assert_eq!(rows.len(), 1, "{:?}", coordinator.registry().gaps());
        assert!(
            rows[0].reason.starts_with("5 calls shed without a route ("),
            "summed: {}",
            rows[0].reason
        );
        assert_eq!(unrouted_gap_calls(&coordinator), 5);
    }

    /// One unrouted call with an explicit exec id.
    fn unrouted_call_exec(
        domain: NativeDomainId,
        cookie: u64,
        exec_id: u64,
        position: u64,
    ) -> TickOutcome {
        use crate::discovery::instances::UnknownReason;
        let event = Event {
            pid_tgid: (4242u64 << 32) | 4242,
            image: ImageIdentity {
                task_cookie: cookie,
                exec_id,
            },
            ..Event::default()
        };
        TickOutcome::Call(RoutedCall::scripted(
            domain,
            crate::events::DecodedEventRecord {
                joint_resource: None,
                base: crate::semantic_capture::event_record_with_routing(
                    event,
                    InstanceStamp::default(),
                    0x2200,
                ),
                object: None,
            },
            Route::Unknown(UnknownReason::Unobserved),
            None,
            Some(position),
        ))
    }

    fn bind_image(
        coordinator: &mut InventoryCoordinator<OsProcessSource>,
        domain: NativeDomainId,
        caller: u32,
        image: ImageIdentity,
    ) {
        coordinator
            .semantic_bindings
            .insert(SemanticCallerBinding::scripted(
                CallerId(caller),
                ModuleKey::physical(7, 7, 777, None, "/bound/provider.so"),
                domain,
                image,
                Arc::new(PidPin::test_proc_only(1234)),
            ))
            .unwrap();
    }

    fn admit_history(
        coordinator: &mut InventoryCoordinator<OsProcessSource>,
        domain: NativeDomainId,
        caller: u32,
        image: ImageIdentity,
    ) {
        coordinator.semantic_bindings.admission_images.insert(
            CallerId(caller),
            SemanticAdmissionHistory {
                domain,
                image,
                incarnation: 1,
                generation: crate::inspect_system::MemberGeneration {
                    start_time: None,
                    exe: None,
                },
                pin: Arc::new(PidPin::test_proc_only(1234)),
                initial_scope_cut: false,
                pending_gap: None,
            },
        );
    }

    #[test]
    fn refused_other_caller_sheds_after_its_own_binding_keep_the_bound_history() {
        use crate::semantics_objects::journal::H3DispositionEvidence;
        // The live intruder shape: a foreign caller's first unrouted
        // calls prove it another caller; tainted at once, its lift
        // window expires unbound, so its image stays refused in the
        // journal and it can never join Joint. It then binds (S1 only,
        // named). A later unrouted
        // call of that same image is still provably not the bound Joint
        // caller's: it must dispose, not barrier, even though its own
        // binding and admission history now hold its cookie.
        let (mut coordinator, mut lane, domain) = drop_test_lanes();
        let foreign = ImageIdentity {
            task_cookie: 77,
            exec_id: 3,
        };
        bind_image(
            &mut coordinator,
            domain,
            9,
            ImageIdentity {
                task_cookie: 41,
                exec_id: 1,
            },
        );
        let first = commit_outcomes(
            &mut coordinator,
            &mut lane,
            domain,
            vec![
                invalidation_at(
                    domain,
                    crate::semantic_capture::InvalidationScope::CoverageFailed,
                    1,
                ),
                unrouted_call(domain, 77, 2),
                unrouted_call(domain, 77, 3),
            ],
        );
        assert!(
            matches!(
                first,
                H3DispositionEvidence::Clean {
                    staged_max: 3,
                    pending_floor: None
                }
            ),
            "the unbound foreign sheds dispose as before: {first:?}"
        );
        // JK-19b: the foreign sheds dispose AND taint at once.
        // Quiet batches past the bounded grace expire the lift window,
        // and only then is the never-bound image permanently refused
        // (a late bind no longer lifts).
        for position in 10u64..30u64 {
            commit_outcomes(
                &mut coordinator,
                &mut lane,
                domain,
                vec![invalidation_at(
                    domain,
                    crate::semantic_capture::InvalidationScope::CoverageFailed,
                    position,
                )],
            );
        }
        assert!(
            coordinator
                .joint_capture
                .adapter()
                .image_refused((foreign.task_cookie, foreign.exec_id)),
            "the foreign image is refused in the journal once its grace expires unbound"
        );
        bind_image(&mut coordinator, domain, 10, foreign);
        admit_history(&mut coordinator, domain, 10, foreign);
        let second = commit_outcomes(
            &mut coordinator,
            &mut lane,
            domain,
            vec![
                invalidation_at(
                    domain,
                    crate::semantic_capture::InvalidationScope::CoverageFailed,
                    4,
                ),
                unrouted_call(domain, 77, 5),
            ],
        );
        // staged_max rode to 29 on the grace batches above; the point
        // stands: the refused shed disposes with no barrier floor.
        assert!(
            matches!(
                second,
                H3DispositionEvidence::Clean {
                    staged_max: 29,
                    pending_floor: None
                }
            ),
            "a refused caller's later shed must not barrier the bound history: {second:?}"
        );
        // Every shed is still shed and disclosed, under the
        // other-callers subject; the totals do not move.
        assert_eq!(lane.shed_calls_disclosed(), 3);
        assert_eq!(unrouted_gap_calls(&coordinator), 3);
        assert_eq!(unrouted_subject_calls(&coordinator, OTHER), 3);
        assert_eq!(unrouted_subject_calls(&coordinator, BLOCKING), 0);
    }

    #[test]
    fn bound_other_caller_without_a_refusal_still_barriers() {
        use crate::semantics_objects::journal::H3DispositionEvidence;
        // Twin: a second bound caller that was never refused in the
        // journal could still hold Joint history, so its unrouted call
        // is a bound caller's own loss and barriers as today.
        let (mut coordinator, mut lane, domain) = drop_test_lanes();
        bind_image(
            &mut coordinator,
            domain,
            9,
            ImageIdentity {
                task_cookie: 41,
                exec_id: 1,
            },
        );
        bind_image(
            &mut coordinator,
            domain,
            10,
            ImageIdentity {
                task_cookie: 77,
                exec_id: 3,
            },
        );
        let evidence = commit_outcomes(
            &mut coordinator,
            &mut lane,
            domain,
            vec![
                invalidation_at(
                    domain,
                    crate::semantic_capture::InvalidationScope::CoverageFailed,
                    1,
                ),
                unrouted_call(domain, 77, 2),
            ],
        );
        assert!(
            matches!(evidence, H3DispositionEvidence::StagedLoss { barrier: 2 }),
            "an unrefused bound caller's shed still barriers: {evidence:?}"
        );
        assert_eq!(lane.shed_calls_disclosed(), 1);
        assert_eq!(unrouted_subject_calls(&coordinator, BLOCKING), 1);
    }

    #[test]
    fn refused_image_sheds_still_barrier_beside_an_unrefused_same_cookie_binding() {
        use crate::semantics_objects::journal::H3DispositionEvidence;
        // Twin: the refused image (77, exec 3) sheds again, but an
        // unrefused binding now holds the same cookie at a later exec.
        // An exec keeps the cookie, so that binding could own the
        // call: fail closed and barrier.
        let (mut coordinator, mut lane, domain) = drop_test_lanes();
        bind_image(
            &mut coordinator,
            domain,
            9,
            ImageIdentity {
                task_cookie: 41,
                exec_id: 1,
            },
        );
        let first = commit_outcomes(
            &mut coordinator,
            &mut lane,
            domain,
            vec![
                invalidation_at(
                    domain,
                    crate::semantic_capture::InvalidationScope::CoverageFailed,
                    1,
                ),
                unrouted_call(domain, 77, 2),
            ],
        );
        assert!(
            matches!(
                first,
                H3DispositionEvidence::Clean {
                    staged_max: 2,
                    pending_floor: None
                }
            ),
            "the unbound foreign shed disposes and refuses its image: {first:?}"
        );
        bind_image(
            &mut coordinator,
            domain,
            10,
            ImageIdentity {
                task_cookie: 77,
                exec_id: 9,
            },
        );
        let second = commit_outcomes(
            &mut coordinator,
            &mut lane,
            domain,
            vec![unrouted_call_exec(domain, 77, 3, 5)],
        );
        assert!(
            matches!(second, H3DispositionEvidence::StagedLoss { barrier: 5 }),
            "a same-cookie unrefused binding could own the shed: {second:?}"
        );
        assert_eq!(lane.shed_calls_disclosed(), 2);
    }

    #[test]
    fn refused_other_caller_shed_beside_an_unknown_shed_still_barriers() {
        use crate::semantics_objects::journal::H3DispositionEvidence;
        // Twin: in one batch, a refused caller's shed disposes while
        // an unknown-image shed (cookie 0) still barriers at its own
        // position. Forgiving the foreign position never forgives an
        // unknown one beside it.
        let (mut coordinator, mut lane, domain) = drop_test_lanes();
        let foreign = ImageIdentity {
            task_cookie: 77,
            exec_id: 3,
        };
        bind_image(
            &mut coordinator,
            domain,
            9,
            ImageIdentity {
                task_cookie: 41,
                exec_id: 1,
            },
        );
        commit_outcomes(
            &mut coordinator,
            &mut lane,
            domain,
            vec![
                invalidation_at(
                    domain,
                    crate::semantic_capture::InvalidationScope::CoverageFailed,
                    1,
                ),
                unrouted_call(domain, 77, 2),
            ],
        );
        // JK-19b: expire the lift window before the S1-only bind, so
        // the bind does not lift and the later shed below still
        // exercises the refused-image disposal path.
        for position in 10u64..30u64 {
            commit_outcomes(
                &mut coordinator,
                &mut lane,
                domain,
                vec![invalidation_at(
                    domain,
                    crate::semantic_capture::InvalidationScope::CoverageFailed,
                    position,
                )],
            );
        }
        bind_image(&mut coordinator, domain, 10, foreign);
        let evidence = commit_outcomes(
            &mut coordinator,
            &mut lane,
            domain,
            vec![unrouted_call(domain, 77, 5), unrouted_call(domain, 0, 6)],
        );
        assert!(
            matches!(evidence, H3DispositionEvidence::StagedLoss { barrier: 6 }),
            "the unknown shed barriers at its own position: {evidence:?}"
        );
        assert_eq!(lane.shed_calls_disclosed(), 3);
        assert_eq!(unrouted_gap_calls(&coordinator), 3);
    }

    #[test]
    fn shed_taint_lifts_when_image_binds_within_grace() {
        use crate::semantics_objects::journal::H3DispositionEvidence;
        // JK-19b healthy twin (browser-bootstrap): background bound
        // (41); a new image (77) sheds before it binds. Its sheds
        // dispose AND taint at once (today's timing, so bound seals
        // never wait). It binds within grace, so its shed-taint lifts
        // and its later shed barriers as its own loss.
        let (mut coordinator, mut lane, domain) = drop_test_lanes();
        bind_image(
            &mut coordinator,
            domain,
            9,
            ImageIdentity {
                task_cookie: 41,
                exec_id: 1,
            },
        );
        let first = commit_outcomes(
            &mut coordinator,
            &mut lane,
            domain,
            vec![
                invalidation_at(
                    domain,
                    crate::semantic_capture::InvalidationScope::CoverageFailed,
                    1,
                ),
                unrouted_call(domain, 77, 2),
                unrouted_call(domain, 77, 3),
            ],
        );
        assert!(
            matches!(
                first,
                H3DispositionEvidence::Clean {
                    staged_max: 3,
                    pending_floor: None
                }
            ),
            "shed-tainted sheds dispose without barrier: {first:?}"
        );
        assert!(
            coordinator.joint_capture.adapter().image_refused((77, 3)),
            "shed-taints still land at once"
        );
        bind_image(
            &mut coordinator,
            domain,
            10,
            ImageIdentity {
                task_cookie: 77,
                exec_id: 3,
            },
        );
        let second = commit_outcomes(
            &mut coordinator,
            &mut lane,
            domain,
            vec![
                invalidation_at(
                    domain,
                    crate::semantic_capture::InvalidationScope::CoverageFailed,
                    4,
                ),
                unrouted_call(domain, 77, 5),
            ],
        );
        assert!(
            !coordinator.joint_capture.adapter().image_refused((77, 3)),
            "binding within grace lifts the shed-taint"
        );
        assert!(
            matches!(second, H3DispositionEvidence::StagedLoss { barrier: 5 }),
            "the bound image's own shed barriers as its loss: {second:?}"
        );
    }

    #[test]
    fn shed_taint_stays_when_image_binds_after_grace() {
        // JK-19b expiry pin: background bound (41); a new image (77)
        // sheds (tainted at once) and never binds within grace. A late
        // bind after expiry does NOT lift: fail closed, today's outcome.
        let (mut coordinator, mut lane, domain) = drop_test_lanes();
        bind_image(
            &mut coordinator,
            domain,
            9,
            ImageIdentity {
                task_cookie: 41,
                exec_id: 1,
            },
        );
        commit_outcomes(
            &mut coordinator,
            &mut lane,
            domain,
            vec![
                invalidation_at(
                    domain,
                    crate::semantic_capture::InvalidationScope::CoverageFailed,
                    1,
                ),
                unrouted_call(domain, 77, 2),
            ],
        );
        assert!(
            coordinator.joint_capture.adapter().image_refused((77, 3)),
            "shed-taints still land at once"
        );
        let mut position = 10u64;
        for _ in 0..32u64 {
            commit_outcomes(
                &mut coordinator,
                &mut lane,
                domain,
                vec![invalidation_at(
                    domain,
                    crate::semantic_capture::InvalidationScope::CoverageFailed,
                    position,
                )],
            );
            position += 1;
        }
        bind_image(
            &mut coordinator,
            domain,
            10,
            ImageIdentity {
                task_cookie: 77,
                exec_id: 3,
            },
        );
        commit_outcomes(
            &mut coordinator,
            &mut lane,
            domain,
            vec![invalidation_at(
                domain,
                crate::semantic_capture::InvalidationScope::CoverageFailed,
                position,
            )],
        );
        assert!(
            coordinator.joint_capture.adapter().image_refused((77, 3)),
            "a bind after grace expiry never lifts"
        );
    }

    #[test]
    fn review_shed_taint_wrong_exec_binding_stays_refused() {
        // JK-19b F2: a binding for another exec of the same process must
        // not lift a never-bound image's shed-taint. Background (41, 1)
        // bound; image (77, 3) sheds (tainted at once); exec 4 of cookie
        // 77 binds; a finalize within grace must leave (77, 3) refused.
        let (mut coordinator, mut lane, domain) = drop_test_lanes();
        bind_image(
            &mut coordinator,
            domain,
            9,
            ImageIdentity {
                task_cookie: 41,
                exec_id: 1,
            },
        );
        commit_outcomes(
            &mut coordinator,
            &mut lane,
            domain,
            vec![
                invalidation_at(
                    domain,
                    crate::semantic_capture::InvalidationScope::CoverageFailed,
                    1,
                ),
                unrouted_call(domain, 77, 2),
            ],
        );
        assert!(
            coordinator.joint_capture.adapter().image_refused((77, 3)),
            "shed-taints still land at once"
        );
        bind_image(
            &mut coordinator,
            domain,
            10,
            ImageIdentity {
                task_cookie: 77,
                exec_id: 4,
            },
        );
        commit_outcomes(
            &mut coordinator,
            &mut lane,
            domain,
            vec![invalidation_at(
                domain,
                crate::semantic_capture::InvalidationScope::CoverageFailed,
                10,
            )],
        );
        assert!(
            coordinator.joint_capture.adapter().image_refused((77, 3)),
            "a binding of exec 4 must not lift never-bound exec 3"
        );
    }

    #[test]
    fn review_shed_taint_wrong_exec_history_stays_refused() {
        // JK-19b F2 twin, other ownership branch: admission history for
        // another exec of the same process must not lift a never-bound
        // image's shed-taint either.
        let (mut coordinator, mut lane, domain) = drop_test_lanes();
        bind_image(
            &mut coordinator,
            domain,
            9,
            ImageIdentity {
                task_cookie: 41,
                exec_id: 1,
            },
        );
        commit_outcomes(
            &mut coordinator,
            &mut lane,
            domain,
            vec![
                invalidation_at(
                    domain,
                    crate::semantic_capture::InvalidationScope::CoverageFailed,
                    1,
                ),
                unrouted_call(domain, 77, 2),
            ],
        );
        assert!(
            coordinator.joint_capture.adapter().image_refused((77, 3)),
            "shed-taints still land at once"
        );
        admit_history(
            &mut coordinator,
            domain,
            10,
            ImageIdentity {
                task_cookie: 77,
                exec_id: 4,
            },
        );
        commit_outcomes(
            &mut coordinator,
            &mut lane,
            domain,
            vec![invalidation_at(
                domain,
                crate::semantic_capture::InvalidationScope::CoverageFailed,
                10,
            )],
        );
        assert!(
            coordinator.joint_capture.adapter().image_refused((77, 3)),
            "admission history of exec 4 must not lift never-bound exec 3"
        );
    }

    /// Gap reasons by subject for the two unrouted subjects.
    fn unrouted_subject_calls(
        coordinator: &InventoryCoordinator<OsProcessSource>,
        subject: &str,
    ) -> u64 {
        let registry = coordinator.registry();
        registry
            .gaps()
            .iter()
            .zip(registry.gap_repeats().iter())
            .filter(|(gap, _)| gap.subject == subject)
            .map(|(gap, repeats)| {
                let count: u64 = gap
                    .reason
                    .split_whitespace()
                    .next()
                    .and_then(|first| first.parse().ok())
                    .unwrap();
                count * repeats
            })
            .sum()
    }

    fn bind_cookie(
        coordinator: &mut InventoryCoordinator<OsProcessSource>,
        domain: NativeDomainId,
        cookie: u64,
    ) {
        coordinator
            .semantic_bindings
            .insert(SemanticCallerBinding::scripted(
                CallerId(9),
                ModuleKey::physical(7, 7, 777, None, "/bound/provider.so"),
                domain,
                ImageIdentity {
                    task_cookie: cookie,
                    exec_id: 1,
                },
                Arc::new(PidPin::test_proc_only(1234)),
            ))
            .unwrap();
    }

    fn commit_outcomes(
        coordinator: &mut InventoryCoordinator<OsProcessSource>,
        lane: &mut AttestedSemanticLane,
        domain: NativeDomainId,
        outcomes: Vec<TickOutcome>,
    ) -> crate::semantics_objects::journal::H3DispositionEvidence {
        let report = TickReport::scripted_with_disposition(outcomes, Vec::new(), None, None, false);
        let batch = SemanticBatch::from_tick_report(domain, report, Vec::new(), 130).unwrap();
        coordinator.stage_semantic_batch(batch);
        coordinator
            .commit_batch_with_semantics(false, Some(lane))
            .unwrap();
        coordinator.take_h3_disposition()
    }

    fn invalidation_at(
        domain: NativeDomainId,
        scope: crate::semantic_capture::InvalidationScope,
        position: u64,
    ) -> TickOutcome {
        TickOutcome::Invalidation(crate::semantic_capture::Invalidation::scripted(
            domain,
            scope,
            Some(position),
        ))
    }

    const BLOCKING: &str = "semantic calls unrouted";
    const OTHER: &str = "semantic calls unrouted from other callers";
    const NOTE: &str = PRE_BINDING_OTHER_CALLERS;

    /// Pre-binding hold: `cookies` are two unrouted calls at positions 2
    /// and 3 before any binding exists; then the first binding (cookie
    /// `bound`) appears and a quiet batch resolves the hold. Returns the
    /// evidence before and after the binding.
    fn pre_binding_case(
        cookies: [u64; 2],
        bound: u64,
        limit: Option<usize>,
    ) -> (
        InventoryCoordinator<OsProcessSource>,
        AttestedSemanticLane,
        crate::semantics_objects::journal::H3DispositionEvidence,
        crate::semantics_objects::journal::H3DispositionEvidence,
    ) {
        use crate::semantic_capture::InvalidationScope;
        let (mut coordinator, mut lane, domain) = drop_test_lanes();
        coordinator.semantic_finalizer = Some(SessionFinalizerState::new(domain));
        if let Some(limit) = limit {
            coordinator
                .semantic_finalizer
                .as_mut()
                .unwrap()
                .reference_pre_binding_limit(limit);
        }
        let before = commit_outcomes(
            &mut coordinator,
            &mut lane,
            domain,
            vec![
                invalidation_at(domain, InvalidationScope::CoverageFailed, 1),
                unrouted_call(domain, cookies[0], 2),
                unrouted_call(domain, cookies[1], 3),
            ],
        );
        assert_eq!(lane.shed_calls_disclosed(), 2, "held calls count at once");
        bind_cookie(&mut coordinator, domain, bound);
        let after = commit_outcomes(
            &mut coordinator,
            &mut lane,
            domain,
            vec![invalidation_at(
                domain,
                InvalidationScope::CoverageFailed,
                4,
            )],
        );
        assert_eq!(lane.shed_calls_disclosed(), 2, "resolution never recounts");
        let total = unrouted_subject_calls(&coordinator, BLOCKING)
            + unrouted_subject_calls(&coordinator, OTHER);
        assert_eq!(total, 2, "every held call is disclosed exactly once");
        (coordinator, lane, before, after)
    }

    #[test]
    fn pre_binding_unrouted_calls_of_another_caller_are_forgiven_at_the_first_binding() {
        use crate::semantics_objects::journal::H3DispositionEvidence;
        let (coordinator, _lane, before, after) = pre_binding_case([77, 78], 41, None);
        assert!(
            matches!(
                before,
                H3DispositionEvidence::Clean {
                    staged_max: 3,
                    pending_floor: None
                }
            ),
            "held positions are provisionally disposed, never barriered before a binding: {before:?}"
        );
        assert!(
            matches!(
                after,
                H3DispositionEvidence::Clean {
                    staged_max: 4,
                    pending_floor: None
                }
            ),
            "the first binding proves another caller: {after:?}"
        );
        // Disclosed at once as shed, then noted as other callers'.
        assert_eq!(unrouted_subject_calls(&coordinator, BLOCKING), 2);
        assert_eq!(unrouted_subject_calls(&coordinator, NOTE), 2);
    }

    #[test]
    fn pre_binding_unrouted_calls_matching_the_first_binding_dispose_without_barrier() {
        use crate::semantics_objects::journal::H3DispositionEvidence;
        // The bound caller's own pre-binding sheds were already
        // disposed as fenced loss in the journal before any key
        // existed; at its binding they dispose here too (never a
        // barrier, never a refusal of its own image). The other
        // caller's sheds in the same hold still resolve as other
        // callers'. Shed totals are unchanged: both calls stay
        // disclosed under the blocking subject from shed time.
        let (coordinator, _lane, _before, after) = pre_binding_case([77, 41], 41, None);
        assert!(
            matches!(
                after,
                H3DispositionEvidence::Clean {
                    staged_max: 4,
                    pending_floor: None
                }
            ),
            "own pre-binding sheds dispose at the binding: {after:?}"
        );
        assert_eq!(unrouted_subject_calls(&coordinator, BLOCKING), 2);
        assert_eq!(unrouted_subject_calls(&coordinator, NOTE), 0);
        // Pure own-cookie hold: same disposal, and the other-caller
        // subject never sees the bound caller's own sheds.
        let (coordinator, _lane, _before, after) = pre_binding_case([41, 41], 41, None);
        assert!(
            matches!(
                after,
                H3DispositionEvidence::Clean {
                    staged_max: 4,
                    pending_floor: None
                }
            ),
            "pure own pre-binding sheds dispose at the binding: {after:?}"
        );
        assert_eq!(unrouted_subject_calls(&coordinator, BLOCKING), 2);
        assert_eq!(unrouted_subject_calls(&coordinator, OTHER), 0);
        assert_eq!(unrouted_subject_calls(&coordinator, NOTE), 0);
    }

    #[test]
    fn pre_binding_unrouted_calls_without_an_image_barrier_at_once() {
        use crate::semantics_objects::journal::H3DispositionEvidence;
        let (coordinator, _lane, before, after) = pre_binding_case([0, 77], 41, None);
        assert!(
            matches!(before, H3DispositionEvidence::StagedLoss { barrier: 2 }),
            "an unknown image is never held: {before:?}"
        );
        assert!(
            matches!(after, H3DispositionEvidence::StagedLoss { barrier: 2 }),
            "the unknown call's barrier stands after the binding: {after:?}"
        );
        // Only the call with a known, different image is noted.
        assert_eq!(unrouted_subject_calls(&coordinator, BLOCKING), 2);
        assert_eq!(unrouted_subject_calls(&coordinator, NOTE), 1);
    }

    #[test]
    fn pre_binding_hold_overflow_barriers() {
        use crate::semantics_objects::journal::H3DispositionEvidence;
        let (coordinator, _lane, before, _after) = pre_binding_case([77, 78], 41, Some(1));
        assert!(
            matches!(before, H3DispositionEvidence::StagedLoss { barrier: 2 }),
            "past the hold limit everything held barriers: {before:?}"
        );
        assert_eq!(unrouted_subject_calls(&coordinator, BLOCKING), 2);
        assert_eq!(unrouted_subject_calls(&coordinator, NOTE), 0);
    }

    #[test]
    fn pre_binding_hold_resolves_as_loss_when_the_lane_stops_unbound() {
        use crate::semantic_capture::InvalidationScope;
        use crate::semantics_objects::journal::H3DispositionEvidence;
        let (mut coordinator, mut lane, domain) = drop_test_lanes();
        coordinator.semantic_finalizer = Some(SessionFinalizerState::new(domain));
        commit_outcomes(
            &mut coordinator,
            &mut lane,
            domain,
            vec![
                invalidation_at(domain, InvalidationScope::CoverageFailed, 1),
                unrouted_call(domain, 77, 2),
            ],
        );
        assert_eq!(
            unrouted_subject_calls(&coordinator, BLOCKING),
            1,
            "a held call is disclosed at once"
        );
        let stopped = commit_outcomes(
            &mut coordinator,
            &mut lane,
            domain,
            vec![invalidation_at(domain, InvalidationScope::Stopped, 3)],
        );
        assert!(
            matches!(stopped, H3DispositionEvidence::StagedLoss { barrier: 2 }),
            "{stopped:?}"
        );
        assert_eq!(unrouted_subject_calls(&coordinator, BLOCKING), 1);
        assert_eq!(unrouted_subject_calls(&coordinator, NOTE), 0);
        assert_eq!(lane.shed_calls_disclosed(), 1);
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
    use crate::attach::BackendSelection;
    use crate::attach::Scope;
    use crate::attach::capture::NativeDomainId;
    use crate::discovery::caller_registry::{
        ImageAuthority, ModuleKey, OsProcessSource, RegistryLimits,
    };
    use crate::discovery::hooks::HookRegistry;
    use crate::fixture_guard::DieWithParent as _;
    use crate::inventory_promotion::lifecycle::SessionNativeCompletion;
    use crate::inventory_promotion::{PromotionPair, PromotionRefusal};
    use crate::inventory_semantics::AttestedSemanticLane;
    use crate::inventory_semantics::SemanticBatch;
    use p11scope_ebpf_common::ImageIdentity;
    use std::collections::{BTreeMap, BTreeSet};

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
            vec![],
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
    #[allow(clippy::result_large_err)] // The closure must return the real install result, large Err included.
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
        let foreign = domain();
        let before = charged(&coordinator);
        let (completion, err) = coordinator
            .retire_joint_domain(SessionNativeCompletion::scripted(foreign))
            .expect_err("nothing live retires nothing");
        assert_eq!(err, JointRetireRefusal::NotLiveDomain);
        assert_eq!(completion.domain(), foreign);
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
        let (completion, err) = coordinator
            .retire_joint_domain(SessionNativeCompletion::scripted(a))
            .expect_err("pending work stays live");
        assert_eq!(err, JointRetireRefusal::PendingWork);
        assert_eq!(completion.domain(), a, "the refusal hands the proof back");
        let state = coordinator.semantic_finalizer.as_ref().expect("kept");
        assert_eq!(state.pending_drop, Some((7, false)));
        assert!(coordinator.refused_semantic_domains.is_empty());
    }

    #[test]
    fn retire_joint_domain_carries_void_counters() {
        // Task 0: retiring the live domain replaces the joint owner, but
        // the diagnostic void counters are run-global (never reset): the
        // new owner shows the old owner's counts. The seed below uses the
        // carry itself, but the assertion compares against literals, so
        // a retire that dropped the counters reads zeros and fails.
        let mut coordinator = coordinator();
        let a = domain();
        coordinator.semantic_finalizer = Some(SessionFinalizerState::new(a));
        let carried = crate::semantics_objects::journal::JointVoidDiagnosis {
            break_dispose: 3,
            break_ingest: 5,
            void_audit: 7,
            void_resync: 11,
            seal_below_fence: 13,
            keys_total: 0,
            keys_refused: 0,
            keys_tainted: 0,
            keys_pending: 0,
        };
        coordinator
            .joint_capture_mut()
            .adapter_mut()
            .carry_joint_void_counts(&carried);
        coordinator
            .retire_joint_domain(SessionNativeCompletion::scripted(a))
            .expect("quiescent A retires");
        let after = coordinator.joint_capture().adapter().joint_void_diagnosis();
        assert_eq!(
            (
                after.break_dispose,
                after.break_ingest,
                after.void_audit,
                after.void_resync,
                after.seal_below_fence
            ),
            (3, 5, 7, 11, 13),
            "retirement carries the void counters to the new owner"
        );
    }

    #[test]
    fn retire_joint_domain_disposes_refused_drop_shadow_without_positives() {
        // Terminal loss stays disposable: a refused domain's drop
        // shadow retires instead of stranding, without restoring
        // positives. Fails pre-fix refusing PendingWork forever.
        let mut coordinator = coordinator();
        let a = domain();
        let mut finalizer = SessionFinalizerState::new(a);
        finalizer.pending_drop = Some((7, false));
        coordinator.semantic_finalizer = Some(finalizer);
        coordinator.refused_semantic_domains.insert(a);
        assert!(
            !coordinator.joint_domain_has_pending_work(a),
            "a refused shadow needs no lane"
        );
        coordinator
            .retire_joint_domain(SessionNativeCompletion::scripted(a))
            .expect("the refused shadow disposes");
        assert!(coordinator.semantic_finalizer.is_none());
        assert!(coordinator.refused_semantic_domains.contains(&a));
        coordinator.stage_semantic_batch(crate::inventory_semantics::SemanticBatch::scripted(
            a,
            Vec::new(),
            1,
        ));
        assert!(
            coordinator.semantic_finalizer.is_none(),
            "no positive authority returns"
        );
    }

    #[test]
    fn retire_joint_domain_still_holds_staged_quantum_when_refused() {
        // Staged quanta still need their audited drop before disposal,
        // even for refused domains: only the terminal shadow is
        // disposable, never an unpublished batch.
        let mut coordinator = coordinator();
        let a = domain();
        let mut finalizer = SessionFinalizerState::new(a);
        finalizer.pending_semantic =
            Some(crate::inventory_semantics::SemanticBatch::scripted(a, Vec::new(), 1).into());
        coordinator.semantic_finalizer = Some(finalizer);
        coordinator.refused_semantic_domains.insert(a);
        assert!(
            coordinator.joint_domain_has_pending_work(a),
            "a staged quantum still needs its lane"
        );
        let (completion, err) = coordinator
            .retire_joint_domain(SessionNativeCompletion::scripted(a))
            .expect_err("an unpublished batch stays live");
        assert_eq!(err, JointRetireRefusal::PendingWork);
        assert_eq!(completion.domain(), a);
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

    /// One scripted slot forms a shell lane: no Session, maps or
    /// cursor, and no joint frame until the test seam sets one.
    fn shell_lane() -> AttestedSemanticLane {
        use crate::discovery::identity::{PinnedObjectId, PinnedObjects};
        use crate::plan::{AttachPlan, Slot};
        use p11scope_ebpf_common::SlotSemantics;
        let slot = Slot {
            index: 0,
            descriptor_index: 0,
            object: PinnedObjectId(7),
            object_path: "joint-retire-test".into(),
            file_offset: 0x1000,
            names: vec!["C_Sign".into()],
            aliased: false,
            semantics: SlotSemantics::COUNT_ONLY,
            semantic_authorized: false,
            semantic_ambiguous: false,
            fork_safe: false,
            module_ids: Vec::new(),
        };
        let plan = AttachPlan::from_slots(vec![slot]);
        let subset = AttestedSubset::scripted(plan, PinnedObjects::empty(), BTreeMap::new());
        AttestedSemanticLane::start(
            subset,
            &Scope::Pid(std::process::id()),
            BackendSelection::Auto,
        )
        .expect("one scripted slot forms a shell lane")
    }

    #[test]
    fn retire_joint_domain_with_lane_refuses_h3_pending_and_returns_completion() {
        use crate::semantics_objects::journal::H3DispositionEvidence;
        let mut coordinator = coordinator();
        let a = domain();
        let lane = shell_lane();
        assert!(!lane.has_joint_frame(), "a shell lane starts frameless");
        let mut finalizer = SessionFinalizerState::new(a);
        finalizer.h3_pending = Some(H3DispositionEvidence::genesis());
        coordinator.semantic_finalizer = Some(finalizer);
        assert!(
            !coordinator.joint_domain_has_pending_work(a),
            "h3 evidence does not hold the shared wind-down gate"
        );
        let (completion, err) = coordinator
            .retire_joint_domain_with_lane(&lane, SessionNativeCompletion::scripted(a))
            .expect_err("h3 evidence stays live");
        assert_eq!(err, JointRetireRefusal::PendingWork);
        assert_eq!(completion.domain(), a, "the refusal hands the proof back");
        assert!(
            coordinator
                .semantic_finalizer
                .as_ref()
                .is_some_and(|state| state.h3_pending.is_some()),
            "the evidence stays staged"
        );
        assert!(coordinator.refused_semantic_domains.is_empty());
        // Drain the evidence; the retained proof retires on retry.
        coordinator
            .semantic_finalizer
            .as_mut()
            .expect("kept")
            .h3_pending = None;
        coordinator
            .retire_joint_domain_with_lane(&lane, completion)
            .expect("drained evidence retires");
        assert!(coordinator.semantic_finalizer.is_none());
        assert!(coordinator.refused_semantic_domains.contains(&a));
    }

    #[test]
    fn retire_joint_domain_with_lane_refuses_staged_h9() {
        let mut coordinator = coordinator();
        let a = domain();
        let lane = shell_lane();
        assert!(!lane.has_joint_frame(), "a shell lane starts frameless");
        coordinator.semantic_finalizer = Some(SessionFinalizerState::new(a));
        coordinator
            .joint_capture
            .ledger_mut()
            .charge(7, 64)
            .expect("one h9 entry stages");
        assert_eq!(coordinator.joint_capture.ledger().staged(), 1);
        assert!(
            coordinator.joint_domain_has_pending_work(a),
            "a staged h9 entry needs its lane"
        );
        let (completion, err) = coordinator
            .retire_joint_domain_with_lane(&lane, SessionNativeCompletion::scripted(a))
            .expect_err("staged h9 stays live");
        assert_eq!(err, JointRetireRefusal::PendingWork);
        assert_eq!(completion.domain(), a, "the refusal hands the proof back");
        assert_eq!(
            coordinator.joint_capture.ledger().staged(),
            1,
            "the staged entry survives the refusal"
        );
        assert!(coordinator.semantic_finalizer.is_some(), "namespace kept");
        assert!(coordinator.refused_semantic_domains.is_empty());
        // Drain the ledger; the retained proof retires on retry.
        coordinator.joint_capture.ledger_mut().release(7, 64);
        assert_eq!(coordinator.joint_capture.ledger().staged(), 0);
        coordinator
            .retire_joint_domain_with_lane(&lane, completion)
            .expect("a drained ledger retires");
        assert!(coordinator.semantic_finalizer.is_none());
        assert!(coordinator.refused_semantic_domains.contains(&a));
    }

    #[test]
    fn retire_joint_domain_with_lane_refuses_retained_joint_frame() {
        let mut coordinator = coordinator();
        let a = domain();
        let mut lane = shell_lane();
        lane.set_test_joint_frame(true);
        assert!(lane.has_joint_frame(), "the seam retains a frame");
        coordinator.semantic_finalizer = Some(SessionFinalizerState::new(a));
        assert!(
            !coordinator.joint_domain_has_pending_work(a),
            "the frame lives on the lane, not the coordinator"
        );
        let (completion, err) = coordinator
            .retire_joint_domain_with_lane(&lane, SessionNativeCompletion::scripted(a))
            .expect_err("a retained frame stays live");
        assert_eq!(err, JointRetireRefusal::PendingWork);
        assert_eq!(completion.domain(), a, "the refusal hands the proof back");
        assert!(coordinator.semantic_finalizer.is_some(), "namespace kept");
        assert!(coordinator.refused_semantic_domains.is_empty());
        // Drop the frame; the retained proof retires on retry.
        lane.set_test_joint_frame(false);
        coordinator
            .retire_joint_domain_with_lane(&lane, completion)
            .expect("a frameless lane retires");
        assert!(coordinator.semantic_finalizer.is_none());
        assert!(coordinator.refused_semantic_domains.contains(&a));
    }

    #[test]
    fn retire_joint_domain_with_lane_retires_when_drained() {
        let mut coordinator = coordinator();
        let a = domain();
        let lane = shell_lane();
        assert!(!lane.has_joint_frame(), "a shell lane starts frameless");
        coordinator.semantic_finalizer = Some(SessionFinalizerState::new(a));
        assert_eq!(coordinator.joint_capture.ledger().staged(), 0);
        assert!(!coordinator.joint_domain_has_pending_work(a));
        coordinator
            .retire_joint_domain_with_lane(&lane, SessionNativeCompletion::scripted(a))
            .expect("a drained domain retires");
        assert!(coordinator.semantic_finalizer.is_none());
        assert!(coordinator.refused_semantic_domains.contains(&a));
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
                    .die_with_parent()
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

    /// DR37 resolver-permission twins: the selected subset mints the
    /// rival-aware full plan, then covers exactly the clicked provider.
    /// Two real provider fixtures (two manifests, two pinned files)
    /// prove the restriction partitions the full closure instead of
    /// rebuilding a narrower plan.
    struct SelectedProviderFixture {
        dir: tempfile::TempDir,
        manifest: p11scope_manifest::manifest::Manifest,
        pins: crate::discovery::identity::PinnedObjects,
    }

    impl SelectedProviderFixture {
        fn new() -> Self {
            use p11scope_manifest::identity::{inspect_file, mapping_file_key, open_object};
            use p11scope_manifest::manifest::*;
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

        fn write_manifest(&self, name: &str) -> std::path::PathBuf {
            let path = self.dir.path().join(name);
            std::fs::write(&path, serde_json::to_vec(&self.manifest).unwrap()).unwrap();
            path
        }

        fn module_key(&self) -> ModuleKey {
            let pin = self.pins.pinned().next().expect("fixture pins one object");
            ModuleKey::physical(
                pin.key.device.major,
                pin.key.device.minor,
                pin.key.inode,
                Some(pin.sha256.to_owned()),
                pin.path,
            )
        }
    }

    #[test]
    fn manifest_pinning_records_probe_rendered_split_key() {
        use crate::discovery::identity::test_fixture::FakeSelfMappingProbe;
        use p11scope_manifest::maps::{Device, ObjectKey};
        let fixture = SelectedProviderFixture::new();
        let fd_key = fixture
            .pins
            .pinned()
            .next()
            .expect("fixture pins one object")
            .key;
        // A pre-6.8 overlay split: the kernel renders this exact fd at a
        // different device than the mount table resolves.
        let split = ObjectKey {
            device: Device {
                major: fd_key.device.major,
                minor: fd_key.device.minor.wrapping_add(1),
            },
            inode: fd_key.inode,
        };
        assert_ne!(split, fd_key, "the test needs a genuine split");
        let mut budget = CaptureWorkBudget::default();
        let probe = FakeSelfMappingProbe::new(true, Some(split));
        let pinning =
            crate::discovery::identity::pin_manifest_objects_deferred_in_views_with_probe(
                &fixture.manifest,
                &[],
                &mut budget,
                &probe,
                0,
                0,
            )
            .expect("split pinning succeeds");
        assert_eq!(probe.overlay_checks.get(), 1);
        assert_eq!(probe.probes.get(), 1);
        let pin = pinning.pins.pinned().next().expect("one object");
        let id = pin.id;
        assert_eq!(pin.key, fd_key, "the mount-table key stays primary");
        // The probe rendering rides on the entry: the join matches the
        // split key, while the raw keys still hold only the fd key (no
        // second manifest raw was added for the rendering).
        assert!(
            pinning.pins.object_matches_key(
                id,
                split.device.major,
                split.device.minor,
                split.inode
            ),
            "the join matches the entry-carried probe rendering"
        );
        assert!(
            !pinning.pins.raw_keys_for(id).contains(&split),
            "the rendering is not a second raw key"
        );
        // The split must not add a second manifest raw: `id_for_path`
        // resolves exactly one raw per path, and a second raw refuses
        // the whole semantic subset ("manifest targets unavailable").
        let path = pin.path.to_owned();
        let sha256 = pin.sha256.to_owned();
        assert_eq!(
            pinning.pins.id_for_path(&path),
            Some(id),
            "the record path still resolves through one manifest raw"
        );
        // End to end: a module keyed by the split maps key proves against
        // the manifest pin, exactly as on a consistent filesystem.
        let subset = AttestedSubset {
            plan: plan::AttachPlan::from_slots(vec![]),
            pins: pinning.pins,
            required: BTreeMap::from([(id, BTreeSet::new())]),
        };
        let module = ModuleKey::physical(
            split.device.major,
            split.device.minor,
            split.inode,
            Some(sha256.clone()),
            &path,
        );
        assert!(
            subset.proves_provider_module(id, &module),
            "the split maps key proves the provider"
        );
        let fd_module = ModuleKey::physical(
            fd_key.device.major,
            fd_key.device.minor,
            fd_key.inode,
            Some(sha256.clone()),
            &path,
        );
        assert!(
            subset.proves_provider_module(id, &fd_module),
            "the fd key still proves the provider"
        );
        // The documented mirror resolves the split key to the same
        // object: admission, labeling, and selection must agree.
        assert_eq!(
            provider_object_for_key(&subset.pins, &module),
            Some(id),
            "the mirror finds the split-keyed provider"
        );
        assert_eq!(
            provider_object_for_key(&subset.pins, &fd_module),
            Some(id),
            "the mirror keeps finding the fd-keyed provider"
        );
        // A module on the split device but with a DIFFERENT inode must NOT
        // prove: the rendering only names this exact fd's inode, and a
        // recycled inode naming another file is the recorded identity trap.
        let reused_inode = split.inode.wrapping_add(1);
        assert_ne!(
            reused_inode, fd_key.inode,
            "the test needs a genuinely different inode"
        );
        let reused = ModuleKey::physical(
            split.device.major,
            split.device.minor,
            reused_inode,
            Some(sha256.clone()),
            &path,
        );
        assert!(
            !subset.proves_provider_module(id, &reused),
            "a split-device module with a different inode must not prove the provider"
        );
        assert_eq!(
            provider_object_for_key(&subset.pins, &reused),
            None,
            "the mirror refuses the reused inode too"
        );
        // A module on the split key with a DIFFERENT digest must NOT prove:
        // the sha256 conjunct is what keeps a same-key impostor out. The
        // digest stays non-empty so only the equality conjunct refuses.
        let wrong_digest = format!("{sha256}x");
        assert_ne!(
            wrong_digest, sha256,
            "the test needs a genuinely different digest"
        );
        let impostor = ModuleKey::physical(
            split.device.major,
            split.device.minor,
            split.inode,
            Some(wrong_digest),
            &path,
        );
        assert!(
            !subset.proves_provider_module(id, &impostor),
            "a split-keyed module with a different digest must not prove the provider"
        );
        assert_eq!(
            provider_object_for_key(&subset.pins, &impostor),
            None,
            "the mirror refuses the wrong digest too"
        );
    }

    #[test]
    fn manifest_pinning_without_a_split_keeps_the_fd_key_only() {
        use crate::discovery::identity::test_fixture::FakeSelfMappingProbe;
        use p11scope_manifest::maps::{Device, ObjectKey};
        let fixture = SelectedProviderFixture::new();
        let fd_key = fixture
            .pins
            .pinned()
            .next()
            .expect("fixture pins one object")
            .key;
        // An inconclusive probe on overlayfs: the kernel renders nothing
        // usable, so the pin must stay fd-only instead of fabricating a
        // maps rendering.
        let absent = ObjectKey {
            device: Device {
                major: fd_key.device.major,
                minor: fd_key.device.minor.wrapping_add(1),
            },
            inode: fd_key.inode,
        };
        assert_ne!(absent, fd_key, "the test needs a genuine non-key");
        let mut budget = CaptureWorkBudget::default();
        let probe = FakeSelfMappingProbe::new(true, None);
        let pinning =
            crate::discovery::identity::pin_manifest_objects_deferred_in_views_with_probe(
                &fixture.manifest,
                &[],
                &mut budget,
                &probe,
                0,
                0,
            )
            .expect("pinning succeeds without a split");
        assert_eq!(probe.overlay_checks.get(), 1);
        assert_eq!(probe.probes.get(), 1);
        let pin = pinning.pins.pinned().next().expect("one object");
        let id = pin.id;
        assert_eq!(pin.key, fd_key, "the mount-table key stays primary");
        // No fabricated maps rendering rides the entry: the join must not
        // match the absent key, and the absent key must file no raw either.
        // Uses only the surviving join accessors, not the summary mirror.
        assert!(
            !pinning.pins.object_matches_key(
                id,
                absent.device.major,
                absent.device.minor,
                absent.inode
            ),
            "no fabricated maps rendering joins the entry"
        );
        assert!(
            !pinning.pins.raw_keys_for(id).contains(&absent),
            "the absent key files no raw either"
        );
        let path = pin.path.to_owned();
        let sha256 = pin.sha256.to_owned();
        assert_eq!(
            pinning.pins.id_for_path(&path),
            Some(id),
            "the record path still resolves through one manifest raw"
        );
        let subset = AttestedSubset {
            plan: plan::AttachPlan::from_slots(vec![]),
            pins: pinning.pins,
            required: BTreeMap::from([(id, BTreeSet::new())]),
        };
        let fd_module = ModuleKey::physical(
            fd_key.device.major,
            fd_key.device.minor,
            fd_key.inode,
            Some(sha256.clone()),
            &path,
        );
        assert!(
            subset.proves_provider_module(id, &fd_module),
            "the fd key still proves the provider"
        );
        let absent_module = ModuleKey::physical(
            absent.device.major,
            absent.device.minor,
            absent.inode,
            Some(sha256),
            &path,
        );
        assert!(
            !subset.proves_provider_module(id, &absent_module),
            "no maps key proves without a probed rendering"
        );
        assert_eq!(
            provider_object_for_key(&subset.pins, &absent_module),
            None,
            "the mirror finds no unprobed maps key"
        );
    }

    #[test]
    fn manifest_pinning_inconclusive_probe_records_the_unproven_maps_note() {
        use crate::discovery::identity::test_fixture::FakeSelfMappingProbe;
        let fixture = SelectedProviderFixture::new();
        let fd_key = fixture
            .pins
            .pinned()
            .next()
            .expect("fixture pins one object")
            .key;
        // An inconclusive probe on overlayfs (budget spent, mmap failure):
        // the pin stays fd-primary and carries the named unproven note, so
        // a caller the rendering would have bound never stays unbound
        // silently.
        let mut budget = CaptureWorkBudget::default();
        let probe = FakeSelfMappingProbe::new(true, None);
        let pinning =
            crate::discovery::identity::pin_manifest_objects_deferred_in_views_with_probe(
                &fixture.manifest,
                &[],
                &mut budget,
                &probe,
                0,
                0,
            )
            .expect("pinning succeeds with an inconclusive probe");
        assert_eq!(probe.overlay_checks.get(), 1);
        assert_eq!(probe.probes.get(), 1);
        let pin = pinning.pins.pinned().next().expect("one object");
        assert_eq!(pin.key, fd_key, "the mount-table key stays primary");
        assert_eq!(
            pin.note,
            Some(crate::discovery::identity::PROBED_MAPS_UNPROVEN_NOTE),
            "the inconclusive probe discloses the unproven rendering"
        );
    }

    #[test]
    fn manifest_pinning_agreeing_probe_records_no_maps_note() {
        use crate::discovery::identity::test_fixture::FakeSelfMappingProbe;
        let fixture = SelectedProviderFixture::new();
        let fd_key = fixture
            .pins
            .pinned()
            .next()
            .expect("fixture pins one object")
            .key;
        // The kernel renders this exact fd at its own key: the probe ran
        // and agreed, so the pin discloses nothing.
        let mut budget = CaptureWorkBudget::default();
        let probe = FakeSelfMappingProbe::new(true, Some(fd_key));
        let pinning =
            crate::discovery::identity::pin_manifest_objects_deferred_in_views_with_probe(
                &fixture.manifest,
                &[],
                &mut budget,
                &probe,
                0,
                0,
            )
            .expect("pinning succeeds with an agreeing probe");
        assert_eq!(probe.overlay_checks.get(), 1);
        assert_eq!(probe.probes.get(), 1);
        let pin = pinning.pins.pinned().next().expect("one object");
        assert_eq!(pin.key, fd_key, "the mount-table key stays primary");
        assert_eq!(
            pin.note, None,
            "an agreeing probe leaves the pin without a note"
        );
    }

    #[test]
    fn manifest_pinning_split_key_labels_through_the_joint_prefilter() {
        use crate::discovery::identity::test_fixture::FakeSelfMappingProbe;
        use p11scope_manifest::maps::{Device, ObjectKey};
        let fixture = SelectedProviderFixture::new();
        let fd_key = fixture
            .pins
            .pinned()
            .next()
            .expect("fixture pins one object")
            .key;
        // The same pre-6.8 overlay split as the proof test: the kernel
        // renders this exact fd at a different device than the mount
        // table resolves.
        let split = ObjectKey {
            device: Device {
                major: fd_key.device.major,
                minor: fd_key.device.minor.wrapping_add(1),
            },
            inode: fd_key.inode,
        };
        assert_ne!(split, fd_key, "the test needs a genuine split");
        let mut budget = CaptureWorkBudget::default();
        let probe = FakeSelfMappingProbe::new(true, Some(split));
        let pinning =
            crate::discovery::identity::pin_manifest_objects_deferred_in_views_with_probe(
                &fixture.manifest,
                &[],
                &mut budget,
                &probe,
                0,
                0,
            )
            .expect("split pinning succeeds");
        let pin = pinning.pins.pinned().next().expect("one object");
        let id = pin.id;
        let path = pin.path.to_owned();
        let sha256 = pin.sha256.to_owned();
        // The joint-label pre-filter is the third mirror of the provider
        // proof: it names the split-keyed module exactly like the fd-keyed
        // one, through the same join predicate.
        let split_module = ModuleKey::physical(
            split.device.major,
            split.device.minor,
            split.inode,
            Some(sha256.clone()),
            &path,
        );
        assert!(
            module_key_names_object(&pinning.pins, id, &split_module),
            "the pre-filter names the split-keyed module"
        );
        let fd_module = ModuleKey::physical(
            fd_key.device.major,
            fd_key.device.minor,
            fd_key.inode,
            Some(sha256),
            &path,
        );
        assert!(
            module_key_names_object(&pinning.pins, id, &fd_module),
            "the pre-filter keeps naming the fd-keyed module"
        );
        // ... but neither a recycled inode on the split device nor a key
        // without comparable file identity.
        let reused = ModuleKey::physical(
            split.device.major,
            split.device.minor,
            split.inode.wrapping_add(1),
            Some(pin.sha256.to_owned()),
            &path,
        );
        assert!(
            !module_key_names_object(&pinning.pins, id, &reused),
            "the pre-filter refuses a different inode on the split device"
        );
        let unidentified = ModuleKey::Unidentified { path };
        assert!(
            !module_key_names_object(&pinning.pins, id, &unidentified),
            "the pre-filter refuses a key without file identity"
        );
    }

    #[test]
    fn selected_subset_partitions_the_rival_aware_plan() {
        let first = SelectedProviderFixture::new();
        let second = SelectedProviderFixture::new();
        let key_a = first.module_key();
        let key_b = second.module_key();
        assert_ne!(key_a, key_b, "two fixtures pin distinct provider files");
        let mut coordinator = coordinator();
        coordinator.set_semantic_manifests(vec![
            first.write_manifest("a.json"),
            second.write_manifest("b.json"),
        ]);
        let caller = admit_self(&mut coordinator);
        let module_a = coordinator
            .registry_mut()
            .scripted_module_edge(key_a.clone(), caller);
        let module_b = coordinator
            .registry_mut()
            .scripted_module_edge(key_b.clone(), caller);
        // The full mint covers both providers...
        let full = coordinator
            .prepare_semantic_subset()
            .subset
            .expect("both manifests attest");
        assert_eq!(
            full.required().len(),
            2,
            "the full closure covers both providers"
        );
        // ...and each restriction partitions it exactly.
        let only_a = coordinator
            .prepare_selected_subset(module_a)
            .expect("clicked provider A mints");
        let only_b = coordinator
            .prepare_selected_subset(module_b)
            .expect("clicked provider B mints");
        assert_eq!(only_a.required().len(), 1);
        assert_eq!(only_b.required().len(), 1);
        let object_a = *only_a.required().keys().next().unwrap();
        let object_b = *only_b.required().keys().next().unwrap();
        assert_ne!(object_a, object_b);
        assert!(only_a.proves_provider_module(object_a, &key_a));
        assert!(only_b.proves_provider_module(object_b, &key_b));
        assert!(
            !only_a.proves_provider_module(object_a, &key_b),
            "the foreign key proves nothing here"
        );
        // Slot closure partitions the rival-aware plan: same endpoints,
        // no overlap, nothing invented.
        let endpoints = |subset: &AttestedSubset| {
            subset
                .plan()
                .slots
                .iter()
                .map(|slot| (slot.object, slot.file_offset))
                .collect::<BTreeSet<_>>()
        };
        let all = endpoints(&full);
        let part_a = endpoints(&only_a);
        let part_b = endpoints(&only_b);
        assert_eq!(part_a.intersection(&part_b).count(), 0);
        assert_eq!(part_a.union(&part_b).copied().collect::<BTreeSet<_>>(), all);
        // Double mints share the retained envelope, like lane startup.
        let again_a = coordinator
            .prepare_selected_subset(module_a)
            .expect("second mint");
        assert!(only_a.same_retained_envelope(&again_a));
    }

    #[test]
    fn selected_subset_refuses_uncovered_and_unloaded_providers() {
        let fixture = SelectedProviderFixture::new();
        let mut coordinator = coordinator();
        coordinator.set_semantic_manifests(vec![fixture.write_manifest("a.json")]);
        let caller = admit_self(&mut coordinator);
        // A live module whose key no retained manifest pins: no
        // permission covers the pair.
        let foreign = coordinator
            .registry_mut()
            .scripted_module_edge(module_key(999), caller);
        let err = coordinator
            .prepare_selected_subset(foreign)
            .expect_err("uncovered provider refuses");
        assert_eq!(err, PromotionRefusal::ManifestUnavailable);
        // An unknown module never reaches the permission lookup.
        let err = coordinator
            .prepare_selected_subset(ModuleId(999))
            .expect_err("unknown module refuses");
        assert_eq!(err, PromotionRefusal::ProviderUnloaded);
        // Neither does a non-physical module key: retained
        // permissions are physical-file-keyed.
        let unidentified = coordinator
            .registry_mut()
            .scripted_module_edge(ModuleKey::physical(0, 0, 0, None, "/nowhere/x.so"), caller);
        let err = coordinator
            .prepare_selected_subset(unidentified)
            .expect_err("non-physical key refuses");
        assert_eq!(err, PromotionRefusal::ManifestUnavailable);
    }

    #[test]
    fn selected_custody_establishes_live_original() {
        let mut coordinator = coordinator();
        let caller = admit_self(&mut coordinator);
        let (original, incarnation) = coordinator
            .prepare_selected_caller_custody(caller)
            .expect("live caller establishes custody");
        assert_eq!(original.pid(), std::process::id());
        let record = coordinator.adapter().record(caller).expect("record");
        assert_eq!(incarnation, record.incarnation);
        assert!(
            !original.original_exited().expect("exit reads"),
            "the established original is live"
        );
    }

    #[test]
    fn selected_custody_refuses_unknown_and_retired() {
        let mut coordinator = coordinator();
        let err = coordinator
            .prepare_selected_caller_custody(CallerId(999))
            .err()
            .expect("unknown caller refuses");
        assert_eq!(err, PromotionRefusal::UnknownCaller);
        let mut child = LiveChild::spawn();
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
        assert!(
            coordinator
                .adapter()
                .record(caller)
                .expect("record kept")
                .retired,
            "reconcile retires the exited child"
        );
        let err = coordinator
            .prepare_selected_caller_custody(caller)
            .err()
            .expect("retired caller refuses");
        assert_eq!(err, PromotionRefusal::CallerRetired);
    }
}

#[cfg(test)]
mod module_init_seam_tests {
    //! The per-module `C_Initialize` roll-up taps joined (converted)
    //! and shed (unrouted) Events at the finalizer: a converted OK
    //! counts, an unrouted failure counts with its rv, and
    //! non-init or unattributable sheds tap nothing.
    use super::*;
    use crate::attach::capture::NativeDomainId;
    use crate::attach::{BackendSelection, Scope};
    use crate::discovery::caller_registry::module_init::{C_INITIALIZE, ModuleInitRollup};
    use crate::discovery::caller_registry::{
        AdmissionState, ImageAuthority, ModuleInfo, RegistryLimits,
    };
    use crate::discovery::hooks::HookRegistry;
    use crate::discovery::identity::PinnedObjectId;
    use crate::discovery::instances::{InstanceId, UnknownReason};
    use crate::inventory_semantics::SemanticBatch;
    use crate::semantic_capture::{RoutedCall, TickReport};
    use p11scope_ebpf_common::{Event, InstanceStamp};
    use pkcs11_types::CkRv;
    use std::sync::Arc;

    /// A scripted subset with two authorized single-named slots over
    /// one real pinned object: `C_Initialize` plus a `C_Sign`
    /// negative control. The registry module key comes from the same
    /// pin, exactly like the manifest rig, so the subset proves it.
    struct InitFixture {
        subset: AttestedSubset,
        object: PinnedObjectId,
        module: ModuleKey,
        init_slot: u32,
        other_slot: u32,
        file_offset: u64,
        other_offset: u64,
    }

    impl InitFixture {
        fn new() -> Self {
            use p11scope_manifest::identity::{inspect_file, mapping_file_key, open_object};
            let path = crate::discovery::identity::test_fixture::small_owned_object();
            let file = open_object(path).unwrap();
            let inspected = inspect_file(&file).unwrap();
            let mapping = mapping_file_key(&file).unwrap();
            let key = p11scope_manifest::maps::ObjectKey {
                device: p11scope_manifest::maps::Device {
                    major: mapping.device_major,
                    minor: mapping.device_minor,
                },
                inode: mapping.inode,
            };
            let sha256 = inspected.identity.sha256.as_deref().unwrap().to_owned();
            let path_str = path.to_str().unwrap().to_owned();
            let pins = crate::discovery::identity::test_fixture::real_scan_pin(
                path,
                Some(key),
                mapping.mount_id,
                &sha256,
            );
            let pin = pins.pinned().next().unwrap();
            let object = pin.id;
            let module = ModuleKey::physical(
                pin.key.device.major,
                pin.key.device.minor,
                pin.key.inode,
                Some(pin.sha256.to_owned()),
                pin.path,
            );
            let slot = |index: u32, name: &str, file_offset: u64| crate::plan::Slot {
                index,
                descriptor_index: crate::kinds::function_id(name).unwrap() + 1,
                object,
                object_path: path_str.clone(),
                file_offset,
                names: vec![name.into()],
                aliased: false,
                semantics: crate::kinds::descriptor(name).unwrap(),
                semantic_authorized: true,
                semantic_ambiguous: false,
                fork_safe: true,
                module_ids: vec![crate::plan::ModuleId(0)],
            };
            let plan = crate::plan::AttachPlan::from_slots(vec![
                slot(0, C_INITIALIZE, 0x1000),
                slot(1, "C_Sign", 0x2000),
            ]);
            let subset = AttestedSubset::scripted(
                plan,
                pins,
                std::collections::BTreeMap::from([(object, std::collections::BTreeSet::from([0]))]),
            );
            Self {
                subset,
                object,
                module,
                init_slot: 0,
                other_slot: 1,
                file_offset: 0x1000,
                other_offset: 0x2000,
            }
        }

        fn endpoint(&self) -> Endpoint {
            Endpoint {
                object: self.object,
                file_slot: 0,
                offset: self.file_offset,
            }
        }

        /// The endpoint matching the `C_Sign` slot exactly: the
        /// non-init negative differs from a tapping shed by name
        /// alone.
        fn other_endpoint(&self) -> Endpoint {
            Endpoint {
                object: self.object,
                file_slot: 0,
                offset: self.other_offset,
            }
        }
    }

    fn coordinator() -> InventoryCoordinator<OsProcessSource> {
        InventoryCoordinator::new(
            Scope::Pid(std::process::id()),
            HookRegistry::builtin(),
            Vec::new(),
            vec![],
            OsProcessSource,
            RegistryLimits::default_limits(),
        )
        .expect("test coordinator builds")
    }

    /// One routed call record over `slot` with return `rv`.
    fn routed_call(
        domain: NativeDomainId,
        slot: u32,
        rv: u64,
        route: Route,
        endpoint: Option<Endpoint>,
        token: Option<u64>,
    ) -> TickOutcome {
        TickOutcome::Call(RoutedCall::scripted(
            domain,
            crate::events::DecodedEventRecord {
                joint_resource: None,
                base: crate::semantic_capture::event_record_with_routing(
                    Event {
                        slot,
                        rv,
                        image: ImageIdentity {
                            task_cookie: 7,
                            exec_id: 1,
                        },
                        ..Default::default()
                    },
                    InstanceStamp::default(),
                    0x2200,
                ),
                object: None,
            },
            route,
            endpoint,
            token,
        ))
    }

    /// Calls disclosed by every unrouted gap, whatever its subject.
    fn unrouted_gap_calls(coordinator: &InventoryCoordinator<OsProcessSource>) -> u64 {
        let registry = coordinator.registry();
        registry
            .gaps()
            .iter()
            .zip(registry.gap_repeats().iter())
            .filter(|(gap, _)| gap.subject.starts_with("semantic calls unrouted"))
            .map(|(gap, repeats)| {
                let count: u64 = gap
                    .reason
                    .split_whitespace()
                    .next()
                    .and_then(|first| first.parse().ok())
                    .expect("unrouted gaps lead with their call count");
                count * repeats
            })
            .sum()
    }

    /// Calls refused at staged conversion, whatever the caller: the
    /// tap reads the refusal without consuming its disclosure.
    fn conversion_refused_gap_calls(
        coordinator: &InventoryCoordinator<OsProcessSource>,
        reason: &str,
    ) -> u64 {
        let registry = coordinator.registry();
        registry
            .gaps()
            .iter()
            .zip(registry.gap_repeats().iter())
            .filter(|(gap, _)| gap.subject == "semantic input refused" && gap.reason == reason)
            .map(|(_, repeats)| *repeats)
            .sum()
    }

    #[test]
    fn module_init_rollup_counts_joined_initialize() {
        let pid = std::process::id();
        let mut coordinator = coordinator();
        let caller = coordinator
            .adapter_mut()
            .admit(pid, ImageAuthority::ScanPinned, 50)
            .unwrap();
        let fixture = InitFixture::new();
        coordinator.registry_mut().note_mapping(
            caller,
            pid,
            ModuleInfo {
                path: "/init/provider.so".into(),
                key: fixture.module.clone(),
                double_loaded: false,
                build_id: None,
                identity_source: Some("init-fixture".into()),
                admission: AdmissionState::Admitted,
                admission_class: Some("exact".into()),
                admission_endpoints: Some(1),
                admission_reasons: Vec::new(),
            },
            60,
        );
        coordinator.commit_batch(false).unwrap();
        let endpoint = fixture.endpoint();
        let module = fixture.module.clone();
        let mut lane =
            AttestedSemanticLane::start(fixture.subset, &Scope::Pid(pid), BackendSelection::Auto)
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
        let module_id = coordinator
            .registry()
            .module_id_for(&module)
            .expect("mapped module resolves");
        let routed = routed_call(
            detailed,
            fixture.init_slot,
            CkRv::OK.0,
            Route::Joined(InstanceId::from_raw(11)),
            Some(endpoint),
            Some(1),
        );
        let batch = SemanticBatch::from_tick_report(
            detailed,
            TickReport::scripted(vec![routed], Vec::new()),
            Vec::new(),
            130,
        )
        .unwrap();
        coordinator.stage_semantic_batch(batch);
        coordinator
            .commit_batch_with_semantics(false, Some(&mut lane))
            .unwrap();
        assert_eq!(
            coordinator.registry().module_init_rollup(module_id),
            ModuleInitRollup {
                calls: 1,
                ok: 1,
                already_initialized: 0,
                last_error_rv: None,
            },
            "a converted C_Initialize OK taps the module roll-up"
        );
        assert_eq!(
            unrouted_gap_calls(&coordinator),
            0,
            "the joined call sheds nowhere"
        );
    }

    #[test]
    fn module_init_rollup_counts_shed_initialize() {
        let pid = std::process::id();
        let mut coordinator = coordinator();
        let caller = coordinator
            .adapter_mut()
            .admit(pid, ImageAuthority::ScanPinned, 50)
            .unwrap();
        let fixture = InitFixture::new();
        coordinator.registry_mut().note_mapping(
            caller,
            pid,
            ModuleInfo {
                path: "/init/provider.so".into(),
                key: fixture.module.clone(),
                double_loaded: false,
                build_id: None,
                identity_source: Some("init-fixture".into()),
                admission: AdmissionState::Admitted,
                admission_class: Some("exact".into()),
                admission_endpoints: Some(1),
                admission_reasons: Vec::new(),
            },
            60,
        );
        coordinator.commit_batch(false).unwrap();
        let endpoint = fixture.endpoint();
        let module = fixture.module.clone();
        let mut lane =
            AttestedSemanticLane::start(fixture.subset, &Scope::Pid(pid), BackendSelection::Auto)
                .expect("shell lane starts");
        let detailed = lane.domain();
        let module_id = coordinator
            .registry()
            .module_id_for(&module)
            .expect("mapped module resolves");
        // No binding: the short-lived caller's C_Initialize sheds
        // unrouted, but its endpoint still proves the module.
        let routed = routed_call(
            detailed,
            fixture.init_slot,
            CkRv::GENERAL_ERROR.0,
            Route::Unknown(UnknownReason::Unobserved),
            Some(endpoint),
            Some(2),
        );
        let batch = SemanticBatch::from_tick_report(
            detailed,
            TickReport::scripted(vec![routed], Vec::new()),
            Vec::new(),
            130,
        )
        .unwrap();
        coordinator.stage_semantic_batch(batch);
        coordinator
            .commit_batch_with_semantics(false, Some(&mut lane))
            .unwrap();
        assert_eq!(
            coordinator.registry().module_init_rollup(module_id),
            ModuleInitRollup {
                calls: 1,
                ok: 0,
                already_initialized: 0,
                last_error_rv: Some(CkRv::GENERAL_ERROR.0),
            },
            "an unrouted C_Initialize failure taps the module roll-up"
        );
        assert_eq!(
            unrouted_gap_calls(&coordinator),
            1,
            "the tap reads the shed without consuming its disclosure"
        );
    }

    #[test]
    fn module_init_rollup_ignores_shed_non_initialize() {
        let pid = std::process::id();
        let mut coordinator = coordinator();
        let caller = coordinator
            .adapter_mut()
            .admit(pid, ImageAuthority::ScanPinned, 50)
            .unwrap();
        let fixture = InitFixture::new();
        coordinator.registry_mut().note_mapping(
            caller,
            pid,
            ModuleInfo {
                path: "/init/provider.so".into(),
                key: fixture.module.clone(),
                double_loaded: false,
                build_id: None,
                identity_source: Some("init-fixture".into()),
                admission: AdmissionState::Admitted,
                admission_class: Some("exact".into()),
                admission_endpoints: Some(1),
                admission_reasons: Vec::new(),
            },
            60,
        );
        coordinator.commit_batch(false).unwrap();
        // A fully matching `C_Sign` endpoint: only the name refuses
        // the tap.
        let endpoint = fixture.other_endpoint();
        let module = fixture.module.clone();
        let mut lane =
            AttestedSemanticLane::start(fixture.subset, &Scope::Pid(pid), BackendSelection::Auto)
                .expect("shell lane starts");
        let detailed = lane.domain();
        let module_id = coordinator
            .registry()
            .module_id_for(&module)
            .expect("mapped module resolves");
        let routed = routed_call(
            detailed,
            fixture.other_slot,
            CkRv::GENERAL_ERROR.0,
            Route::Unknown(UnknownReason::Unobserved),
            Some(endpoint),
            Some(2),
        );
        let batch = SemanticBatch::from_tick_report(
            detailed,
            TickReport::scripted(vec![routed], Vec::new()),
            Vec::new(),
            130,
        )
        .unwrap();
        coordinator.stage_semantic_batch(batch);
        coordinator
            .commit_batch_with_semantics(false, Some(&mut lane))
            .unwrap();
        assert_eq!(
            coordinator.registry().module_init_rollup(module_id),
            ModuleInitRollup::default(),
            "an unrouted non-init shed taps nothing"
        );
        assert_eq!(unrouted_gap_calls(&coordinator), 1);
    }

    #[test]
    fn module_init_rollup_ignores_shed_unknown_object() {
        let pid = std::process::id();
        let mut coordinator = coordinator();
        let caller = coordinator
            .adapter_mut()
            .admit(pid, ImageAuthority::ScanPinned, 50)
            .unwrap();
        let fixture = InitFixture::new();
        coordinator.registry_mut().note_mapping(
            caller,
            pid,
            ModuleInfo {
                path: "/init/provider.so".into(),
                key: fixture.module.clone(),
                double_loaded: false,
                build_id: None,
                identity_source: Some("init-fixture".into()),
                admission: AdmissionState::Admitted,
                admission_class: Some("exact".into()),
                admission_endpoints: Some(1),
                admission_reasons: Vec::new(),
            },
            60,
        );
        coordinator.commit_batch(false).unwrap();
        let mut endpoint = fixture.endpoint();
        let module = fixture.module.clone();
        let mut lane =
            AttestedSemanticLane::start(fixture.subset, &Scope::Pid(pid), BackendSelection::Auto)
                .expect("shell lane starts");
        let detailed = lane.domain();
        let module_id = coordinator
            .registry()
            .module_id_for(&module)
            .expect("mapped module resolves");
        endpoint.object = PinnedObjectId(999);
        let routed = routed_call(
            detailed,
            fixture.init_slot,
            CkRv::GENERAL_ERROR.0,
            Route::Unknown(UnknownReason::Unobserved),
            Some(endpoint),
            Some(2),
        );
        let batch = SemanticBatch::from_tick_report(
            detailed,
            TickReport::scripted(vec![routed], Vec::new()),
            Vec::new(),
            130,
        )
        .unwrap();
        coordinator.stage_semantic_batch(batch);
        coordinator
            .commit_batch_with_semantics(false, Some(&mut lane))
            .unwrap();
        assert_eq!(
            coordinator.registry().module_init_rollup(module_id),
            ModuleInitRollup::default(),
            "a shed whose endpoint proves no module taps nothing"
        );
        assert_eq!(unrouted_gap_calls(&coordinator), 1);
    }

    #[test]
    fn module_init_rollup_counts_refused_joined_initialize() {
        let pid = std::process::id();
        let mut coordinator = coordinator();
        let caller = coordinator
            .adapter_mut()
            .admit(pid, ImageAuthority::ScanPinned, 50)
            .unwrap();
        let fixture = InitFixture::new();
        coordinator.registry_mut().note_mapping(
            caller,
            pid,
            ModuleInfo {
                path: "/init/provider.so".into(),
                key: fixture.module.clone(),
                double_loaded: false,
                build_id: None,
                identity_source: Some("init-fixture".into()),
                admission: AdmissionState::Admitted,
                admission_class: Some("exact".into()),
                admission_endpoints: Some(1),
                admission_reasons: Vec::new(),
            },
            60,
        );
        coordinator.commit_batch(false).unwrap();
        let endpoint = fixture.endpoint();
        let module = fixture.module.clone();
        let mut lane =
            AttestedSemanticLane::start(fixture.subset, &Scope::Pid(pid), BackendSelection::Auto)
                .expect("shell lane starts");
        let detailed = lane.domain();
        let module_id = coordinator
            .registry()
            .module_id_for(&module)
            .expect("mapped module resolves");
        // No binding: the Joined call refuses custody at conversion,
        // but its endpoint still proves the module.
        let routed = routed_call(
            detailed,
            fixture.init_slot,
            CkRv::GENERAL_ERROR.0,
            Route::Joined(InstanceId::from_raw(11)),
            Some(endpoint),
            Some(2),
        );
        let batch = SemanticBatch::from_tick_report(
            detailed,
            TickReport::scripted(vec![routed], Vec::new()),
            Vec::new(),
            130,
        )
        .unwrap();
        coordinator.stage_semantic_batch(batch);
        coordinator
            .commit_batch_with_semantics(false, Some(&mut lane))
            .unwrap();
        assert_eq!(
            coordinator.registry().module_init_rollup(module_id),
            ModuleInitRollup {
                calls: 1,
                ok: 0,
                already_initialized: 0,
                last_error_rv: Some(CkRv::GENERAL_ERROR.0),
            },
            "a conversion-refused Joined C_Initialize taps the module roll-up"
        );
        assert_eq!(
            conversion_refused_gap_calls(&coordinator, "custody"),
            1,
            "the tap reads the refusal without consuming its disclosure"
        );
        assert_eq!(
            unrouted_gap_calls(&coordinator),
            0,
            "the joined call sheds nowhere unrouted"
        );
    }

    #[test]
    fn module_init_rollup_ignores_refused_joined_non_initialize() {
        let pid = std::process::id();
        let mut coordinator = coordinator();
        let caller = coordinator
            .adapter_mut()
            .admit(pid, ImageAuthority::ScanPinned, 50)
            .unwrap();
        let fixture = InitFixture::new();
        coordinator.registry_mut().note_mapping(
            caller,
            pid,
            ModuleInfo {
                path: "/init/provider.so".into(),
                key: fixture.module.clone(),
                double_loaded: false,
                build_id: None,
                identity_source: Some("init-fixture".into()),
                admission: AdmissionState::Admitted,
                admission_class: Some("exact".into()),
                admission_endpoints: Some(1),
                admission_reasons: Vec::new(),
            },
            60,
        );
        coordinator.commit_batch(false).unwrap();
        // A fully matching `C_Sign` endpoint: only the name refuses
        // the tap.
        let endpoint = fixture.other_endpoint();
        let module = fixture.module.clone();
        let mut lane =
            AttestedSemanticLane::start(fixture.subset, &Scope::Pid(pid), BackendSelection::Auto)
                .expect("shell lane starts");
        let detailed = lane.domain();
        let module_id = coordinator
            .registry()
            .module_id_for(&module)
            .expect("mapped module resolves");
        let routed = routed_call(
            detailed,
            fixture.other_slot,
            CkRv::GENERAL_ERROR.0,
            Route::Joined(InstanceId::from_raw(11)),
            Some(endpoint),
            Some(2),
        );
        let batch = SemanticBatch::from_tick_report(
            detailed,
            TickReport::scripted(vec![routed], Vec::new()),
            Vec::new(),
            130,
        )
        .unwrap();
        coordinator.stage_semantic_batch(batch);
        coordinator
            .commit_batch_with_semantics(false, Some(&mut lane))
            .unwrap();
        assert_eq!(
            coordinator.registry().module_init_rollup(module_id),
            ModuleInitRollup::default(),
            "a conversion-refused Joined non-init taps nothing"
        );
        assert_eq!(
            conversion_refused_gap_calls(&coordinator, "custody"),
            1,
            "the refusal still discloses"
        );
    }
}
