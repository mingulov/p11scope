//! SPDX-License-Identifier: GPL-3.0-or-later

//! Inventory-only ownership and reconciliation preparation. This component does
//! not attach probes, publish capture output, or schedule work; the I3/I4b
//! coordinator (`inventory_coordinator`) owns the scan window, drives
//! scan→reconcile→publish through `commit_inventory_reconciliation`, and
//! revalidates every prepared candidate at its publication boundary.

use super::*;
use crate::capacity::InventoryBudget;
use crate::discovery::scan::{DiscoveryPolicy, InventoryDiscoveryLimits};
use p11scope_ebpf_common::{ImageIdentity, image_pair_matches};
use std::sync::Arc;

/// Counted retained resources, separate from the renewable scan work budget.
/// Each owner can retain at most one ProcessView/pidfd. Claim references count
/// pin, table, and target references; these are not allocator/RSS byte estimates.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct InventoryOwnerLimits {
    owners: usize,
    scan_leases: usize,
    claim_references: usize,
}

impl InventoryOwnerLimits {
    pub(crate) fn new(owners: usize, scan_leases: usize, claim_references: usize) -> Result<Self> {
        if owners == 0 || scan_leases == 0 || claim_references == 0 {
            bail!("inventory owner, scan-lease, and claim-reference limits must be non-zero");
        }
        if owners > u32::MAX as usize || scan_leases > owners {
            bail!("inventory owner limits exceed the owner ID space or scan-lease ownership");
        }
        Ok(Self {
            owners,
            scan_leases,
            claim_references,
        })
    }
}

#[derive(Debug, Clone, Copy)]
pub(crate) struct InventoryDiscoveryConfig {
    work: InventoryDiscoveryLimits,
    owners: InventoryOwnerLimits,
    admission: InventoryBudget,
}

impl InventoryDiscoveryConfig {
    pub(crate) fn new(
        work: InventoryDiscoveryLimits,
        owners: InventoryOwnerLimits,
        admission: InventoryBudget,
    ) -> Self {
        Self {
            work,
            owners,
            admission,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum ImageCheck {
    Exact,
    Changed,
    Unavailable,
}

/// The adapter must query the same capture's native identity domain and verify
/// both lifetime ticket and exec ID for this exact retained process. A pidfd,
/// start time, maps equality, or missing query row cannot implement `Exact`.
/// Implementations may consume a batched native result; missing/stale results
/// must be Unavailable. This trait supplies no successful production adapter.
pub(crate) trait ImageGuard {
    fn check(&mut self, view: &ProcessView, expected: ImageIdentity) -> ImageCheck;
}

pub(crate) struct UnavailableImageGuard;

impl ImageGuard for UnavailableImageGuard {
    fn check(&mut self, _: &ProcessView, _: ImageIdentity) -> ImageCheck {
        ImageCheck::Unavailable
    }
}

/// Opaque until the native lifecycle adapter can prove an exact old/new image
/// transition. No PID or ordinary refresh API can construct this proof.
/// Constructed only by the privileged native lane; the scan lane retires
/// suspected execs through exe-identity comparison instead.
#[allow(dead_code)] // Privileged native lane constructs the proof; matching is live.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct ExecProof {
    owner: ProcessViewId,
    old: ImageIdentity,
    new: ImageIdentity,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum RefreshCause {
    LoaderHint,
    Periodic,
    /// No event transport exists on the coordinator's synchronous path;
    /// the privileged live lane constructs this on session recovery.
    #[allow(dead_code)] // Privileged live lane only; matching is live.
    TransportRecovery(u64),
    ScopeRecheck,
    /// Unconstructible until the native lifecycle adapter proves an
    /// exact old/new image transition (see `ExecProof`).
    #[allow(dead_code)] // Privileged native lane only; matching is live.
    ValidatedExec(ExecProof),
}

#[derive(Debug)]
struct Owner {
    image: ImageIdentity,
    revision: u64,
    requested_epoch: u64,
    serviced_epoch: u64,
    last_complete_revision: Option<u64>,
    dirty: u8,
    recovery_epoch: u64,
    image_state: ImageCheck,
}

pub(super) struct InventoryState {
    config: InventoryDiscoveryConfig,
    domain: Arc<()>,
    reservations: BTreeSet<ProcessViewId>,
    owners: BTreeMap<ProcessViewId, Owner>,
    leases: BTreeMap<ProcessViewId, u64>,
    next_lease: u64,
}

impl InventoryState {
    fn new(config: InventoryDiscoveryConfig) -> Self {
        Self {
            config,
            domain: Arc::new(()),
            reservations: BTreeSet::new(),
            owners: BTreeMap::new(),
            leases: BTreeMap::new(),
            next_lease: 0,
        }
    }

    pub(super) fn reserve_owner(&mut self, next: &mut u32) -> Result<ProcessViewId> {
        let used = self
            .owners
            .len()
            .checked_add(self.reservations.len())
            .ok_or_else(|| anyhow!("inventory owner occupancy overflow"))?;
        if used >= self.config.owners.owners {
            bail!(
                "inventory retained-owner capacity {} is exhausted",
                self.config.owners.owners
            );
        }
        let advanced = next
            .checked_add(1)
            .ok_or_else(|| anyhow!("process view ID space exhausted"))?;
        let id = ProcessViewId(*next);
        self.reservations.insert(id);
        *next = advanced;
        Ok(id)
    }

    pub(super) fn release_reservation(&mut self, id: ProcessViewId) {
        // Retained owners and claims never retire through scratch cancellation.
        if !self.leases.contains_key(&id) {
            self.reservations.remove(&id);
        }
    }

    pub(super) fn require_reserved_or_retained(&self, id: ProcessViewId) -> Result<()> {
        if self.reservations.contains(&id) || self.owners.contains_key(&id) {
            Ok(())
        } else {
            bail!("inventory owner ID was not reserved in this engine")
        }
    }
}

#[must_use = "release the scan lease explicitly on completion or cancellation"]
pub(crate) struct ScanLease {
    domain: Arc<()>,
    owner: ProcessViewId,
    serial: u64,
}

struct ReceiptIdentity {
    domain: Arc<()>,
    owner: ProcessViewId,
    image: ImageIdentity,
    revision: u64,
    requested_epoch: u64,
}

pub(crate) struct VerifiedAdditions {
    identity: ReceiptIdentity,
    modules: Vec<ScannedModule>,
    pins: PinnedObjects,
}

pub(crate) struct VerifiedAbsence(VerifiedAdditions);

pub(crate) enum ScanReceipt {
    Complete(VerifiedAbsence),
    AdditionsOnly(VerifiedAdditions),
    Deferred {
        owner: ProcessViewId,
        reason: &'static str,
    },
    Unavailable {
        owner: ProcessViewId,
        reason: String,
    },
}

/// Preparation owns its pins and desired plan, not kernel links or use evidence.
/// Fields are private so legacy `apply_candidate(Session)` cannot be selected by
/// a consumer without an explicit new integration seam.
pub(crate) struct PreparedReconciliation {
    identity: ReceiptIdentity,
    complete: bool,
    candidate: LiveCandidate,
}

#[cfg(test)]
impl PreparedReconciliation {
    pub(super) fn candidate(&self) -> &LiveCandidate {
        &self.candidate
    }
}

impl Engine {
    pub(crate) fn inventory(
        config: InventoryDiscoveryConfig,
        scope: Scope,
        hooks: HookRegistry,
        module_hints: Vec<PathBuf>,
    ) -> Result<Self> {
        let mut engine = Self::empty();
        engine.plan = plan::AttachPlan::from_slots_with_policy(
            Vec::new(),
            plan::AdmissionPolicy::Inventory(config.admission),
        )
        .map_err(anyhow::Error::msg)?;
        engine.budget = CaptureWorkBudget::for_inventory(config.work);
        engine.inventory = Some(InventoryState::new(config));
        engine.scope = scope;
        engine.hooks = hooks;
        engine.module_hints = module_hints;
        engine.inventory_state()?;
        Ok(engine)
    }

    pub(super) fn inventory_state(&self) -> Result<&InventoryState> {
        let state = self
            .inventory
            .as_ref()
            .ok_or_else(|| anyhow!("engine is not Inventory"))?;
        if self.plan.admission_policy() != plan::AdmissionPolicy::Inventory(state.config.admission)
            || self.budget.policy() != DiscoveryPolicy::Inventory(state.config.work)
        {
            bail!("inventory discovery/admission policy mismatch");
        }
        Ok(state)
    }

    fn inventory_scope_contains(&self, pid: u32) -> bool {
        match &self.scope {
            Scope::Pid(expected) => pid == *expected,
            Scope::System => true,
            Scope::Cgroup { .. } => scope_pids(&self.scope).0.contains(&pid),
        }
    }

    /// Reserve before opening. Failure releases occupancy but burns the ID.
    /// Exact image authority is mandatory even for a still-live pidfd.
    pub(crate) fn open_inventory_owner(
        &mut self,
        pid: u32,
        image: ImageIdentity,
        guard: &mut dyn ImageGuard,
    ) -> Result<ProcessViewId> {
        self.inventory_state()?;
        if image.task_cookie == 0 || !self.inventory_scope_contains(pid) {
            bail!("inventory owner lacks image identity or current scope membership");
        }
        let id = self.allocate_view_id()?;
        let opened = (|| {
            let view = ProcessView::open(id, pid).map_err(anyhow::Error::msg)?;
            if guard.check(&view, image) != ImageCheck::Exact || !view.still_the_same() {
                bail!("inventory exact-image authority unavailable or changed");
            }
            Ok(view)
        })();
        let view = match opened {
            Ok(view) => view,
            Err(error) => {
                self.release_view_id(id);
                return Err(error);
            }
        };
        let state = self.inventory.as_mut().expect("checked Inventory state");
        state.reservations.remove(&id);
        state.owners.insert(
            id,
            Owner {
                image,
                revision: 0,
                requested_epoch: 0,
                serviced_epoch: 0,
                last_complete_revision: None,
                dirty: 0,
                recovery_epoch: 0,
                image_state: ImageCheck::Exact,
            },
        );
        self.views.push(view);
        Ok(id)
    }

    pub(crate) fn acquire_inventory_scan(&mut self, owner: ProcessViewId) -> Result<ScanLease> {
        let state = self.inventory_state()?;
        state.require_reserved_or_retained(owner)?;
        if state.leases.contains_key(&owner)
            || state.leases.len() >= state.config.owners.scan_leases
        {
            bail!("inventory active scan-lease capacity is exhausted or owner already has a lease");
        }
        let state = self.inventory.as_mut().expect("checked Inventory state");
        let serial = state
            .next_lease
            .checked_add(1)
            .ok_or_else(|| anyhow!("inventory lease serial exhausted"))?;
        state.next_lease = serial;
        state.leases.insert(owner, serial);
        Ok(ScanLease {
            domain: state.domain.clone(),
            owner,
            serial,
        })
    }

    pub(crate) fn release_inventory_scan(&mut self, lease: &ScanLease) -> Result<()> {
        self.require_inventory_lease(lease)?;
        self.inventory
            .as_mut()
            .expect("checked Inventory state")
            .leases
            .remove(&lease.owner);
        Ok(())
    }

    fn require_inventory_lease(&self, lease: &ScanLease) -> Result<()> {
        let state = self.inventory_state()?;
        if !Arc::ptr_eq(&state.domain, &lease.domain)
            || state.leases.get(&lease.owner) != Some(&lease.serial)
        {
            bail!("inventory scan lease is stale or belongs to another engine");
        }
        Ok(())
    }

    pub(crate) fn request_inventory_refresh(
        &mut self,
        owner: ProcessViewId,
        cause: RefreshCause,
    ) -> Result<()> {
        self.inventory_state()?;
        // The native proof/terminal retirement adapter is deliberately not
        // implemented here. Generic hints never set legacy retirement intents.
        if matches!(cause, RefreshCause::ValidatedExec(_)) {
            bail!("validated exec retirement requires the native lifecycle adapter");
        }
        let owner = self
            .inventory
            .as_mut()
            .expect("checked Inventory state")
            .owners
            .get_mut(&owner)
            .ok_or_else(|| anyhow!("inventory refresh owner is not retained"))?;
        let epoch = owner
            .requested_epoch
            .checked_add(1)
            .ok_or_else(|| anyhow!("inventory refresh epoch exhausted"))?;
        let bit = match cause {
            RefreshCause::LoaderHint => 1,
            RefreshCause::Periodic => 2,
            RefreshCause::TransportRecovery(epoch) => {
                owner.recovery_epoch = owner.recovery_epoch.max(epoch);
                4
            }
            RefreshCause::ScopeRecheck => 8,
            RefreshCause::ValidatedExec(_) => unreachable!("refused above"),
        };
        owner.requested_epoch = epoch;
        owner.dirty |= bit;
        Ok(())
    }

    fn check_inventory_image(
        &mut self,
        identity: &ReceiptIdentity,
        guard: &mut dyn ImageGuard,
    ) -> Result<()> {
        let state = self.inventory_state()?;
        let owner = state
            .owners
            .get(&identity.owner)
            .ok_or_else(|| anyhow!("inventory receipt owner is no longer retained"))?;
        if !Arc::ptr_eq(&state.domain, &identity.domain)
            || owner.revision != identity.revision
            || !image_pair_matches(owner.image, identity.image)
        {
            bail!("inventory receipt belongs to another owner, image, or claim revision");
        }
        if owner.image_state == ImageCheck::Changed {
            bail!("inventory owner image was already invalidated; existing claims retained");
        }
        let view = self
            .views
            .iter()
            .find(|view| view.id() == identity.owner)
            .ok_or_else(|| anyhow!("inventory owner has no retained lifetime pin"))?;
        let checked = if view.still_the_same() && self.inventory_scope_contains(view.pid()) {
            guard.check(view, identity.image)
        } else {
            ImageCheck::Unavailable
        };
        self.inventory
            .as_mut()
            .expect("checked Inventory state")
            .owners
            .get_mut(&identity.owner)
            .expect("checked owner")
            .image_state = checked;
        if checked != ImageCheck::Exact {
            bail!("inventory exact-image authority is {checked:?}; existing claims retained");
        }
        Ok(())
    }

    fn inventory_receipt_identity(&self, owner: ProcessViewId) -> Result<ReceiptIdentity> {
        let state = self.inventory_state()?;
        let record = state
            .owners
            .get(&owner)
            .ok_or_else(|| anyhow!("inventory scan owner is not retained"))?;
        Ok(ReceiptIdentity {
            domain: state.domain.clone(),
            owner,
            image: record.image,
            revision: record.revision,
            requested_epoch: record.requested_epoch,
        })
    }

    /// Transitional synchronous scanner seam. The caller owns the I4a window
    /// and lease. Future continuations must preserve this same final bracket;
    /// independently partial receipts cannot be combined into absence authority.
    pub(crate) fn scan_inventory_owner(
        &mut self,
        lease: &ScanLease,
        guard: &mut dyn ImageGuard,
    ) -> Result<ScanReceipt> {
        self.scan_inventory_owner_with(lease, guard, scan_process_view)
    }

    pub(super) fn scan_inventory_owner_with(
        &mut self,
        lease: &ScanLease,
        guard: &mut dyn ImageGuard,
        scan: impl FnOnce(
            &ScanRequest<'_>,
            &ProcessView,
            &mut CaptureWorkBudget,
        ) -> std::result::Result<ScanOutcome, String>,
    ) -> Result<ScanReceipt> {
        self.require_inventory_lease(lease)?;
        let identity = self.inventory_receipt_identity(lease.owner)?;
        self.check_inventory_image(&identity, guard)?;
        let view = self
            .views
            .iter()
            .find(|view| view.id() == lease.owner)
            .expect("checked retained view");
        let before_refusals = self.budget.refusal_counts();
        let mut counters = DiscoveryCounters::default();
        let result = scan_and_pin_with(
            view,
            &self.module_hints,
            &self.hooks,
            &mut self.budget,
            &mut counters,
            false,
            &mut self.stage_timings,
            scan,
        );
        let pinning_complete = self.budget.stopped_reason().is_none()
            && before_refusals == self.budget.refusal_counts()
            && counters.object_skips.is_empty();
        self.absorb_scan_counters(counters);
        self.check_inventory_image(&identity, guard)?;
        match result {
            Ok((modules, pins, complete)) => {
                if !pins.check_unchanged().map_err(anyhow::Error::msg)? {
                    bail!("inventory scan pins changed; existing claims retained");
                }
                let additions = VerifiedAdditions {
                    identity,
                    modules,
                    pins,
                };
                Ok(if complete && pinning_complete {
                    ScanReceipt::Complete(VerifiedAbsence(additions))
                } else {
                    ScanReceipt::AdditionsOnly(additions)
                })
            }
            Err(error) => Ok(ScanReceipt::Unavailable {
                owner: lease.owner,
                reason: format!("{error:#}"),
            }),
        }
    }

    pub(crate) fn prepare_inventory_reconciliation(
        &mut self,
        receipt: ScanReceipt,
        guard: &mut dyn ImageGuard,
    ) -> Result<PreparedReconciliation> {
        let (facts, complete) = match receipt {
            ScanReceipt::Complete(VerifiedAbsence(facts)) => (facts, true),
            ScanReceipt::AdditionsOnly(facts) => (facts, false),
            ScanReceipt::Deferred { owner, reason } => {
                bail!("inventory scan deferred for owner {}: {reason}", owner.0)
            }
            ScanReceipt::Unavailable { owner, reason } => {
                bail!("inventory scan unavailable for owner {}: {reason}", owner.0)
            }
        };
        self.check_inventory_image(&facts.identity, guard)?;
        let id = facts.identity.owner;
        let view = self
            .views
            .iter()
            .find(|view| view.id() == id)
            .expect("checked retained view");
        if facts
            .modules
            .iter()
            .any(|module| module.view != id || module.mount_namespace != view.mount_namespace())
        {
            bail!("inventory scan facts name a different retained owner");
        }
        if !facts.pins.check_unchanged().map_err(anyhow::Error::msg)?
            || !self.view_pins_unchanged(id)
        {
            bail!("inventory reconciliation pins changed or unavailable; existing claims retained");
        }
        let mut pins = self.pinned.clone();
        let preserve: Vec<_> = if complete {
            Vec::new()
        } else {
            // Preserve every prior physical claimant and raw alias while
            // refreshing this owner's pin references. Appending pin vectors
            // would charge identical partial observations repeatedly; derived
            // table/target claims are rebuilt below from the full module union.
            pins.view_claims(id)
                .into_iter()
                .flat_map(|claims| {
                    claims
                        .pins
                        .iter()
                        .chain(&claims.tables)
                        .chain(claims.targets.iter().map(|(object, _)| object))
                })
                .copied()
                .collect::<BTreeSet<_>>()
                .into_iter()
                .collect()
        };
        let skips = pins.replace_view_pins(id, facts.pins, &preserve);
        if !skips.is_empty() {
            bail!("inventory reconciliation pin identity refused; existing claims retained");
        }
        let mut modules: Vec<_> = self
            .modules
            .iter()
            .filter(|module| !complete || module.scanned.view != id)
            .map(|module| module.scanned.clone())
            .collect();
        for module in facts.modules {
            merge_scanned_module(&mut modules, module);
        }
        pins.reset_scan_pin_claims();
        let candidate = self.live_candidate(pins, modules, Vec::new())?;
        let claim_count = self.views.iter().try_fold(0usize, |total, view| {
            let Some(claims) = candidate.pinned.view_claims(view.id()) else {
                return Ok(total);
            };
            total
                .checked_add(claims.pins.len())
                .and_then(|n| n.checked_add(claims.tables.len()))
                .and_then(|n| n.checked_add(claims.targets.len()))
                .ok_or_else(|| anyhow!("inventory claim-reference count overflow"))
        })?;
        if claim_count > self.inventory_state()?.config.owners.claim_references {
            bail!("inventory retained claim-reference capacity is exhausted");
        }
        self.check_inventory_image(&facts.identity, guard)?;
        Ok(PreparedReconciliation {
            identity: facts.identity,
            complete,
            candidate,
        })
    }

    /// I3 must call again at publication, including after any asynchronous work.
    /// Passing preparation alone conveys no permission to publish changed links.
    pub(crate) fn revalidate_inventory_reconciliation(
        &mut self,
        prepared: &PreparedReconciliation,
        guard: &mut dyn ImageGuard,
    ) -> Result<()> {
        self.check_inventory_image(&prepared.identity, guard)?;
        if !prepared
            .candidate
            .pinned
            .check_unchanged()
            .map_err(anyhow::Error::msg)?
        {
            bail!("prepared inventory pins changed; existing claims retained");
        }
        Ok(())
    }

    /// Last claim revision for which `owner` committed a complete receipt,
    /// if any. Absence authority (module unload, edge end by rescan)
    /// requires a complete commit; partial receipts only add.
    pub(crate) fn inventory_last_complete(&self, owner: ProcessViewId) -> Result<Option<u64>> {
        Ok(self
            .inventory_state()?
            .owners
            .get(&owner)
            .ok_or_else(|| anyhow!("inventory owner is no longer retained"))?
            .last_complete_revision)
    }

    /// Owner bookkeeping snapshot for tests: refresh epochs, dirty
    /// causes, image state, and the last complete revision. Production
    /// learns the same facts through commit receipts.
    #[cfg(test)]
    pub(crate) fn inventory_owner_epochs(
        &self,
        owner: ProcessViewId,
    ) -> Result<InventoryOwnerEpochs> {
        let owner = self
            .inventory_state()?
            .owners
            .get(&owner)
            .ok_or_else(|| anyhow!("inventory owner is no longer retained"))?;
        Ok(InventoryOwnerEpochs {
            requested: owner.requested_epoch,
            serviced: owner.serviced_epoch,
            dirty: owner.dirty,
            image_state: owner.image_state,
            complete: owner.last_complete_revision,
        })
    }
}

/// Owner bookkeeping snapshot (see `inventory_owner_epochs`).
#[cfg(test)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct InventoryOwnerEpochs {
    pub requested: u64,
    pub serviced: u64,
    pub dirty: u8,
    pub image_state: ImageCheck,
    pub complete: Option<u64>,
}

/// What one inventory commit concluded.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct InventoryCommit {
    pub owner: ProcessViewId,
    pub complete: bool,
    pub serviced_epoch: u64,
    /// A refresh was requested after the committed receipt was prepared:
    /// the owner stays dirty and the coordinator must scan again.
    pub refresh_pending: bool,
    pub changed: bool,
}

impl Engine {
    /// The explicit integration seam preparation was built for. I3
    /// revalidates at this publication boundary — including after any
    /// asynchronous work the coordinator ran since preparation — and then
    /// the candidate becomes the engine's exact current state: pins,
    /// modules, plan, corroboration. No session exists on this path, so no
    /// link can attach: the plan commits as facts (admission verdicts
    /// feed the caller registry), never as attach work. Owner
    /// bookkeeping closes the serviced epoch; requests that arrived after
    /// preparation stay pending.
    pub(crate) fn commit_inventory_reconciliation(
        &mut self,
        prepared: PreparedReconciliation,
        guard: &mut dyn ImageGuard,
    ) -> Result<InventoryCommit> {
        self.revalidate_inventory_reconciliation(&prepared, guard)?;
        self.inventory_state()?;
        self.preflight_candidate_publication(&prepared.candidate)?;
        let PreparedReconciliation {
            identity,
            complete,
            mut candidate,
        } = prepared;
        record_object_skips(&mut candidate.plan, &self.counters.object_skips);
        let changed = candidate.plan != self.plan;
        self.pinned = candidate.pinned;
        self.modules = candidate.modules;
        self.plan = candidate.plan;
        // The commit replaces the whole publication input set even when
        // the plan compares equal, so it dirties the inputs
        // unconditionally — the batch tail republishes on the revision.
        self.note_facts_mutated();
        for binding in self.selection_bindings.values_mut() {
            if let Some(module) = self
                .plan
                .modules
                .iter()
                .find(|module| module.object == binding.object)
            {
                binding.provider = module.id;
            }
        }
        self.counters.corroboration = candidate.corroboration;
        self.counters.manifest_fallbacks = candidate.manifest_fallbacks;
        self.selection_claims = candidate.selection_claims;
        self.selection_tables = candidate.selection_tables;
        let state = self.inventory.as_mut().expect("checked Inventory state");
        let owner = state
            .owners
            .get_mut(&identity.owner)
            .ok_or_else(|| anyhow!("inventory owner is no longer retained"))?;
        if owner.serviced_epoch > identity.requested_epoch {
            bail!("inventory owner serviced a refresh newer than the committed receipt");
        }
        owner.serviced_epoch = identity.requested_epoch;
        let refresh_pending = owner.requested_epoch != owner.serviced_epoch;
        if !refresh_pending {
            owner.dirty = 0;
        }
        if complete {
            owner.last_complete_revision = Some(identity.revision);
        }
        Ok(InventoryCommit {
            owner: identity.owner,
            complete,
            serviced_epoch: owner.serviced_epoch,
            refresh_pending,
            changed,
        })
    }
}

#[cfg(test)]
#[path = "inventory_owner_tests.rs"]
mod tests;
