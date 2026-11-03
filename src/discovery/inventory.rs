//! SPDX-License-Identifier: GPL-3.0-or-later

//! Inventory-only ownership and reconciliation preparation. This component does
//! not attach probes, publish capture output, or schedule work; the I3/I4b
//! coordinator (`inventory_coordinator`) owns the scan window, drives
//! scan→reconcile→publish through `commit_inventory_reconciliation`, and
//! revalidates every prepared candidate at its publication boundary.

use super::*;
use crate::capacity::InventoryBudget;
use crate::discovery::native_binding::BoundImage;
use crate::discovery::scan::{DiscoveryPolicy, InventoryDiscoveryLimits};
use crate::process::PidPin;
use std::sync::Arc;

#[path = "inventory/image_guard.rs"]
pub(crate) mod image_guard;
// Packet 2 preparation consumes this; packet-1 production only stores the types.
#[cfg_attr(not(test), allow(unused_imports))]
pub(crate) use image_guard::FreshImageGuard;

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
/// Only a fresh current-image observation of the retained pin answers
/// `Exact`; missing, stale, failed, or foreign-provenance results are
/// `Unavailable`, and only a well-formed observation of the correct
/// original in the correct domain may report `Changed`. Cached binder
/// state is never currency evidence.
pub(crate) trait ImageGuard {
    fn check(&mut self, view: &ProcessView, expected: BoundImage) -> ImageCheck;
}

pub(crate) struct UnavailableImageGuard;

impl ImageGuard for UnavailableImageGuard {
    fn check(&mut self, _: &ProcessView, _: BoundImage) -> ImageCheck {
        ImageCheck::Unavailable
    }
}

/// An exact old/new image transition of one owner's task. No PID or
/// ordinary refresh API can construct this proof: it is built only from an
/// [`ExecTransition`], which only the native binder constructs (a later
/// exec sequence under one task cookie, or a changed leader task, under the
/// incarnation's held pidfd). The scan lane retires suspected execs through
/// exe-identity comparison instead.
///
/// [`ExecTransition`]: crate::discovery::native_binding::ExecTransition
#[allow(dead_code)] // The fields are evidence for the native lifecycle adapter.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct ExecProof {
    owner: ProcessViewId,
    transition: crate::discovery::native_binding::ExecTransition,
}

impl ExecProof {
    pub(crate) fn from_transition(
        owner: ProcessViewId,
        transition: crate::discovery::native_binding::ExecTransition,
    ) -> Self {
        Self { owner, transition }
    }
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
    /// A natively proven exact image transition (see `ExecProof`).
    #[allow(dead_code)] // The proof is evidence for the native lifecycle adapter.
    ValidatedExec(ExecProof),
}

/// Dirty-cause bit for a natively proven exec invalidation (H6 slice 2).
/// LoaderHint/Periodic/TransportRecovery/ScopeRecheck hold bits 1/2/4/8; an
/// ended owner never services again, so this bit stays set as the marker.
const EXEC_INVALIDATED_DIRTY: u8 = 16;

#[derive(Debug)]
struct Owner {
    image: BoundImage,
    /// Provisional record for the scoped commit path: staged before
    /// the final membership sample, inert until the permit-backed
    /// activation commit flips it. Staged records grant no receipt
    /// authority and publish nothing; anything still staged at a
    /// failure releases instead of activating.
    staged: bool,
    /// An active owner whose scoped refresh candidate is being
    /// prepared for the permit-backed commit: the scope check defers
    /// to that proof exactly like a staged provisional, generic
    /// commit entries refuse the record while the flag stands, and
    /// every abandon path clears it. Never set together with
    /// `staged`.
    scoped_refresh: bool,
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
    image: BoundImage,
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

/// A prepared reconciliation whose provider pins were validated before
/// the final membership sample, sealed for the pure permit-backed
/// apply. Constructible only through
/// [`Engine::preflight_scoped_reconciliation`], which completes the
/// pin validation I/O the generic commit re-runs at its boundary.
/// The scoped apply trusts this evidence and performs no provider
/// I/O; the generic path keeps its own revalidation contract.
pub(crate) struct PreflightedReconciliation {
    prepared: PreparedReconciliation,
}

impl Engine {
    pub(crate) fn inventory(
        config: InventoryDiscoveryConfig,
        scope: Scope,
        hooks: HookRegistry,
        module_hints: Vec<PathBuf>,
        excludes: Vec<PathBuf>,
    ) -> Result<Self> {
        let mut engine = Self::empty();
        engine.plan = plan::AttachPlan::from_slots_with_policy(
            Vec::new(),
            plan::AdmissionPolicy::Inventory(config.admission),
        )
        .map_err(anyhow::Error::msg)?;
        engine.budget = CaptureWorkBudget::for_inventory(config.work);
        engine.budget.set_excludes(excludes);
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
            // Native owner reads/refresh do not yet fit inside the cgroup
            // transaction bracket. Only the scoped scan-pinned path may
            // admit; never walk membership again here or inherit a PID.
            Scope::Cgroup { .. } => false,
        }
    }

    /// Reserve before opening. Failure releases occupancy but burns the ID.
    /// Exact image authority is mandatory even for a still-live pidfd.
    pub(crate) fn open_inventory_owner(
        &mut self,
        pid: u32,
        image: BoundImage,
        guard: &mut dyn ImageGuard,
    ) -> Result<ProcessViewId> {
        self.note_graph_inputs_mutated();
        self.inventory_state()?;
        // An invalid expected image cannot be manufactured: the only
        // production factory builds from a settled binder association, and
        // the scripted constructor refuses zero. Only scope still refuses.
        if !self.inventory_scope_contains(pid) {
            bail!("inventory owner lacks image identity or current scope membership");
        }
        let id = self.allocate_view_id()?;
        let opened = (|| {
            // This owner is opened before the coordinator's scan checkpoint.
            // Keep the prior bounded leader-metadata path; cold discovery is
            // paid by its scan collection and falls back there explicitly.
            let view = ProcessView::open_warm_only(id, pid).map_err(anyhow::Error::msg)?;
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
                staged: false,
                scoped_refresh: false,
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

    /// Provision one staged (provisional) owner for the scoped commit
    /// path: reserve, insert a staged record that grants no authority,
    /// and open its warm view. The record's scope proof arrives only
    /// with the permit-backed activation commit; until then the owner
    /// is inert (no receipt authority, no publication) and must either
    /// activate or release within the same commit. Returns the staged
    /// id with its retained pin for the preparation's observation.
    pub(crate) fn provision_staged_owner(
        &mut self,
        pid: u32,
        image: BoundImage,
    ) -> Result<(ProcessViewId, Arc<PidPin>)> {
        self.note_graph_inputs_mutated();
        self.inventory_state()?;
        // No scope gate here: the staged record is provisional and
        // grants nothing. `inventory_scope_contains` is not weakened;
        // the permit-backed proof gates activation instead.
        let id = self.allocate_view_id()?;
        let view = match ProcessView::open_warm_only(id, pid) {
            Ok(view) => view,
            Err(error) => {
                self.release_view_id(id);
                return Err(anyhow::Error::msg(error));
            }
        };
        let pin = Arc::clone(view.retained_pin_arc());
        let state = self.inventory.as_mut().expect("checked Inventory state");
        state.reservations.remove(&id);
        state.owners.insert(
            id,
            Owner {
                image,
                staged: true,
                scoped_refresh: false,
                revision: 0,
                requested_epoch: 0,
                serviced_epoch: 0,
                last_complete_revision: None,
                dirty: 0,
                recovery_epoch: 0,
                image_state: ImageCheck::Unavailable,
            },
        );
        self.views.push(view);
        Ok((id, pin))
    }

    /// Activate one staged owner under the permit-backed proof: pure
    /// commit work only. Validates the staged view's pid and liveness
    /// against the proof, commits the preflighted reconciliation (the
    /// image revalidates through the passed guard — the commit's
    /// replay guard over the stored observation — while the provider
    /// pins stand on their pre-sample preflight evidence, with no new
    /// provider I/O), flips the record to active, and releases the
    /// scan lease. A refused activation releases the staged record,
    /// view, reservation, and lease as well: nothing staged survives
    /// a failure.
    pub(crate) fn activate_staged_owner(
        &mut self,
        owner: ProcessViewId,
        preflighted: PreflightedReconciliation,
        lease: &ScanLease,
        proof: &crate::discovery::caller_registry::ScopedOwnerProof<'_>,
        guard: &mut dyn ImageGuard,
    ) -> Result<InventoryCommit> {
        self.note_graph_inputs_mutated();
        if !self
            .inventory_state()?
            .owners
            .get(&owner)
            .is_some_and(|record| record.staged)
        {
            bail!("inventory owner is not a staged provisional");
        }
        let view = self
            .views
            .iter()
            .find(|view| view.id() == owner)
            .ok_or_else(|| anyhow!("staged inventory owner has no retained view"))?;
        if view.pid() != proof.pid() || !view.still_the_same() {
            let error = anyhow!("staged owner liveness or pid changed at activation commit");
            return match self.abandon_staged_owner(owner, lease) {
                Ok(()) => Err(error),
                Err(abandon) => Err(anyhow!(
                    "{error:#}; staged release also failed: {abandon:#}"
                )),
            };
        }
        // The record stays staged through the commit: the staged scope
        // exception carries it, and a failed commit releases below.
        let commit = match self.commit_preflighted_reconciliation_scoped(preflighted, guard) {
            Ok(commit) => commit,
            Err(error) => {
                return match self.abandon_staged_owner(owner, lease) {
                    Ok(()) => Err(error),
                    Err(abandon) => Err(anyhow!(
                        "{error:#}; staged release also failed: {abandon:#}"
                    )),
                };
            }
        };
        self.inventory
            .as_mut()
            .expect("checked Inventory state")
            .owners
            .get_mut(&owner)
            .expect("committed staged owner")
            .staged = false;
        self.release_inventory_scan(lease)?;
        Ok(commit)
    }

    /// Release one staged provisional owner that cannot commit: the
    /// staged record, its view, and its ID occupancy. Refuses active
    /// (non-staged) owners: retained owners are never removed here.
    pub(crate) fn release_staged_owner(&mut self, owner: ProcessViewId) -> Result<()> {
        self.note_graph_inputs_mutated();
        self.inventory_state()?;
        let state = self.inventory.as_mut().expect("checked Inventory state");
        if !state.owners.get(&owner).is_some_and(|record| record.staged) {
            bail!(
                "inventory owner is not a staged provisional; retained owners are never released"
            );
        }
        state.owners.remove(&owner);
        self.views.retain(|view| view.id() != owner);
        self.release_view_id(owner);
        Ok(())
    }

    fn abandon_staged_owner(&mut self, owner: ProcessViewId, lease: &ScanLease) -> Result<()> {
        let lease_result = self.release_inventory_scan(lease);
        let staged_result = self.release_staged_owner(owner);
        match (lease_result, staged_result) {
            (Ok(()), Ok(())) => Ok(()),
            (Err(error), Ok(())) => Err(error),
            (Ok(()), Err(error)) => Err(error),
            (Err(first), Err(second)) => Err(anyhow!("{first:#}; and {second:#}")),
        }
    }

    /// Begin one scoped refresh of an active owner: mark the record
    /// as a scoped-refresh candidate (its scope proof now defers to
    /// the permit-backed refresh commit) and return its proven image
    /// with the retained view pin for the fresh observation. Refuses
    /// staged provisionals, leased owners, owners whose image
    /// already changed, and a second concurrent begin; a refused
    /// begin sets nothing.
    pub(crate) fn begin_scoped_owner_refresh(
        &mut self,
        owner: ProcessViewId,
    ) -> Result<(BoundImage, Arc<PidPin>)> {
        self.note_graph_inputs_mutated();
        let state = self.inventory_state()?;
        let record = state
            .owners
            .get(&owner)
            .ok_or_else(|| anyhow!("scoped refresh owner is not retained"))?;
        if record.staged {
            bail!("scoped refresh names a staged provisional; only active owners refresh");
        }
        if record.scoped_refresh {
            bail!("scoped refresh is already in progress for this owner");
        }
        if record.image_state == ImageCheck::Changed {
            bail!("scoped refresh owner image already changed; existing claims retained");
        }
        if state.leases.contains_key(&owner) {
            bail!("scoped refresh owner already holds a scan lease");
        }
        let image = record.image;
        let pin = Arc::clone(
            self.views
                .iter()
                .find(|view| view.id() == owner)
                .ok_or_else(|| anyhow!("scoped refresh owner has no retained view"))?
                .retained_pin_arc(),
        );
        self.inventory
            .as_mut()
            .expect("checked Inventory state")
            .owners
            .get_mut(&owner)
            .expect("checked refresh owner")
            .scoped_refresh = true;
        Ok((image, pin))
    }

    /// Abandon one prepared scoped refresh that cannot commit: clear
    /// the candidate flag and release the scan lease when one was
    /// acquired. The owner and its prior facts stand; only the
    /// prepared candidate dies. A record that is already gone (a
    /// racing release) abandons quietly, like lease release would.
    pub(crate) fn abandon_scoped_owner_refresh(
        &mut self,
        owner: ProcessViewId,
        lease: Option<&ScanLease>,
    ) -> Result<()> {
        if let Some(state) = self.inventory.as_mut()
            && let Some(record) = state.owners.get_mut(&owner)
        {
            record.scoped_refresh = false;
        }
        match lease {
            Some(lease) => self.release_inventory_scan(lease),
            None => Ok(()),
        }
    }

    /// Commit one prepared scoped refresh under the permit-backed
    /// proof: bounded pure work only, mirroring
    /// `activate_staged_owner` without the staged flip or any
    /// authority installation. Validates the retained view's pid and
    /// liveness against the proof and commits the preflighted
    /// reconciliation through the passed replay guard over the
    /// stored observation (no provider I/O). The candidate flag
    /// clears and the scan lease releases on every path; a refused
    /// commit retains the owner and its prior facts.
    pub(crate) fn commit_scoped_owner_refresh(
        &mut self,
        owner: ProcessViewId,
        preflighted: PreflightedReconciliation,
        lease: &ScanLease,
        proof: &crate::discovery::caller_registry::ScopedOwnerProof<'_>,
        guard: &mut dyn ImageGuard,
    ) -> Result<InventoryCommit> {
        self.note_graph_inputs_mutated();
        let result = (|| {
            if !self
                .inventory_state()?
                .owners
                .get(&owner)
                .is_some_and(|record| !record.staged && record.scoped_refresh)
            {
                bail!("inventory owner is not an active scoped refresh candidate");
            }
            let view = self
                .views
                .iter()
                .find(|view| view.id() == owner)
                .ok_or_else(|| anyhow!("scoped refresh owner has no retained view"))?;
            if view.pid() != proof.pid() || !view.still_the_same() {
                bail!("scoped refresh owner liveness or pid changed at refresh commit");
            }
            self.commit_preflighted_reconciliation_scoped(preflighted, guard)
        })();
        let release = self.abandon_scoped_owner_refresh(owner, Some(lease));
        match (result, release) {
            (Ok(commit), Ok(())) => Ok(commit),
            (Err(error), _) => Err(error),
            (Ok(_), Err(error)) => Err(error),
        }
    }

    /// Release one active scoped owner (suspend teardown): rebuild
    /// the remaining owners' facts as the new current state, then
    /// drop the owner record, its view, and its ID occupancy, so
    /// owners-map, view-ID, and claim-reference capacity all return.
    /// Refuses staged provisionals (they release through the staged
    /// path) and leased owners; a refused release changes nothing
    /// (the candidate rebuild is fallible before any mutation).
    pub(crate) fn release_scoped_owner(&mut self, owner: ProcessViewId) -> Result<()> {
        self.note_graph_inputs_mutated();
        self.inventory_state()?;
        {
            let state = self.inventory.as_ref().expect("checked Inventory state");
            let record = state
                .owners
                .get(&owner)
                .ok_or_else(|| anyhow!("scoped release owner is not retained"))?;
            if record.staged {
                bail!(
                    "scoped release names a staged provisional; staged owners release through the staged path"
                );
            }
            if state.leases.contains_key(&owner) {
                bail!("scoped release owner holds a scan lease; release refused");
            }
        }
        let mut pinned = self.pinned.clone();
        pinned.remove_view(owner);
        let modules: Vec<_> = self
            .modules
            .iter()
            .filter(|module| module.scanned.view != owner)
            .map(|module| module.scanned.clone())
            .collect();
        let mut candidate = self.live_candidate(pinned, modules, Vec::new())?;
        self.preflight_candidate_publication(&candidate)?;
        record_object_skips(
            &mut candidate.plan,
            &self.counters.object_skips,
            &mut self.capture_facts.visible_history_mut().scan_gap_tombstones,
        );
        self.pinned = candidate.pinned;
        self.modules = candidate.modules;
        self.plan = candidate.plan;
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
        state.owners.remove(&owner);
        state.leases.remove(&owner);
        self.views.retain(|view| view.id() != owner);
        self.release_view_id(owner);
        Ok(())
    }

    /// The proven image an active owner was retained under (suspend
    /// cancels exactly this installed authority).
    pub(crate) fn inventory_owner_image(&self, owner: ProcessViewId) -> Result<BoundImage> {
        Ok(self
            .inventory_state()?
            .owners
            .get(&owner)
            .ok_or_else(|| anyhow!("inventory owner is no longer retained"))?
            .image)
    }

    /// Whether the owner's checked image already ended (`Changed`):
    /// the coordinator routes such owners to suspend instead of any
    /// further scan.
    pub(crate) fn inventory_owner_image_changed(&self, owner: ProcessViewId) -> Result<bool> {
        Ok(self
            .inventory_state()?
            .owners
            .get(&owner)
            .ok_or_else(|| anyhow!("inventory owner is no longer retained"))?
            .image_state
            == ImageCheck::Changed)
    }

    /// Refresh epochs for candidate ordering: (requested, serviced).
    /// A serviced epoch behind the requested one is a pending
    /// refresh.
    pub(crate) fn inventory_refresh_epochs(&self, owner: ProcessViewId) -> Result<(u64, u64)> {
        let record = self
            .inventory_state()?
            .owners
            .get(&owner)
            .ok_or_else(|| anyhow!("inventory owner is no longer retained"))?;
        Ok((record.requested_epoch, record.serviced_epoch))
    }

    /// Whether any owner still carries the scoped-refresh candidate
    /// flag: the coordinator asserts this is false at each scoped
    /// publication's end, so a missed abandon path cannot strand an
    /// owner behind the generic-commit refusal.
    pub(crate) fn scoped_refresh_in_progress(&self) -> bool {
        self.inventory
            .as_ref()
            .is_some_and(|state| state.owners.values().any(|record| record.scoped_refresh))
    }

    pub(crate) fn acquire_inventory_scan(&mut self, owner: ProcessViewId) -> Result<ScanLease> {
        let state = self.inventory_state()?;
        state.require_reserved_or_retained(owner)?;
        if state
            .owners
            .get(&owner)
            .is_some_and(|record| record.image_state == ImageCheck::Changed)
        {
            bail!(
                "inventory owner image ended; the owner retains its history but scans nothing new"
            );
        }
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
        self.note_graph_inputs_mutated();
        self.inventory_state()?;
        // A natively proven image transition invalidates the proved old
        // owner through the adapter below. Generic hints never set legacy
        // retirement intents.
        if let RefreshCause::ValidatedExec(proof) = cause {
            return self.invalidate_owner_for_exec(owner, proof);
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

    /// The native lifecycle adapter for a proved old incarnation: its scan
    /// lease, checked revision and current image end here, before
    /// publication, while every committed claim stays retained. This assigns
    /// no Detailed cookie and grants no new exact result — the successor's
    /// exact authority comes only from its own validated admission. Proving
    /// an already ended owner is idempotent; a proof naming another owner
    /// is refused and changes nothing.
    fn invalidate_owner_for_exec(&mut self, owner: ProcessViewId, proof: ExecProof) -> Result<()> {
        if proof.owner != owner {
            bail!("validated exec proof names another inventory owner; nothing was invalidated");
        }
        let state = self.inventory.as_mut().expect("checked Inventory state");
        let record = state
            .owners
            .get_mut(&owner)
            .ok_or_else(|| anyhow!("inventory refresh owner is not retained"))?;
        if record.image_state == ImageCheck::Changed {
            return Ok(());
        }
        state.leases.remove(&owner);
        record.revision = record.revision.checked_add(1).ok_or_else(|| {
            anyhow!("inventory owner revision exhausted; existing claims retained")
        })?;
        record.image_state = ImageCheck::Changed;
        record.requested_epoch = record.requested_epoch.checked_add(1).ok_or_else(|| {
            anyhow!("inventory refresh epoch exhausted; existing claims retained")
        })?;
        record.dirty |= EXEC_INVALIDATED_DIRTY;
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
            || owner.image != identity.image
        {
            bail!("inventory receipt belongs to another owner, image, or claim revision");
        }
        if owner.image_state == ImageCheck::Changed {
            bail!("inventory owner image was already invalidated; existing claims retained");
        }
        // A staged provisional defers its scope proof to the
        // permit-backed activation commit; it publishes nothing
        // before. An active scoped-refresh candidate defers the same
        // way to its permit-backed refresh commit.
        // `inventory_scope_contains` itself is not weakened.
        let staged_provisional = owner.staged || owner.scoped_refresh;
        let view = self
            .views
            .iter()
            .find(|view| view.id() == identity.owner)
            .ok_or_else(|| anyhow!("inventory owner has no retained lifetime pin"))?;
        let scope_ok = staged_provisional || self.inventory_scope_contains(view.pid());
        let checked = if view.still_the_same() && scope_ok {
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
        self.note_graph_inputs_mutated();
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
        self.note_graph_inputs_mutated();
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

    /// Exhaust one owner's checked claim revision (H6 slice 2 tests): the
    /// next validated-exec invalidation must refuse permanently at this
    /// boundary with history intact. Unreachable in production except by
    /// counter exhaustion.
    #[cfg(test)]
    pub(crate) fn test_exhaust_owner_revision(&mut self, owner: ProcessViewId) -> Result<()> {
        self.inventory_state()?;
        self.inventory
            .as_mut()
            .expect("checked Inventory state")
            .owners
            .get_mut(&owner)
            .ok_or_else(|| anyhow!("inventory owner is no longer retained"))?
            .revision = u64::MAX;
        Ok(())
    }

    /// Staged-owner counts for the activation twins: (owners
    /// including staged provisionals, reservations, active scan
    /// leases). A refused commit leaves all three at their
    /// pre-commit values.
    #[cfg(test)]
    pub(crate) fn inventory_staged_counts_for_test(&self) -> Result<(usize, usize, usize)> {
        let state = self.inventory_state()?;
        Ok((
            state.owners.len(),
            state.reservations.len(),
            state.leases.len(),
        ))
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
        self.note_graph_inputs_mutated();
        self.refuse_scoped_refresh_owner(prepared.identity.owner)?;
        self.revalidate_inventory_reconciliation(&prepared, guard)?;
        self.commit_validated_reconciliation(prepared)
    }

    /// A scoped-refresh candidate publishes only through its
    /// permit-backed proof entry: generic commit entries refuse it
    /// while the flag stands, before any boundary check can mutate
    /// its image state.
    fn refuse_scoped_refresh_owner(&self, owner: ProcessViewId) -> Result<()> {
        if self
            .inventory_state()?
            .owners
            .get(&owner)
            .is_some_and(|record| record.scoped_refresh)
        {
            bail!(
                "inventory owner is a scoped refresh candidate; only the permit-backed refresh commit may publish it"
            );
        }
        Ok(())
    }

    /// Seal a prepared reconciliation for the scoped permit-backed
    /// apply: complete the provider pin validation (held-fd fstat)
    /// here, before the final membership sample, and retain the held
    /// FDs with the prepared evidence. The coordinator calls this at
    /// the end of its pre-sample preparation; the apply trusts the
    /// seal and performs no provider I/O. A changed or unreadable
    /// pin refuses here, before anything commits.
    pub(crate) fn preflight_scoped_reconciliation(
        prepared: PreparedReconciliation,
    ) -> Result<PreflightedReconciliation> {
        if !prepared
            .candidate
            .pinned
            .check_unchanged()
            .map_err(anyhow::Error::msg)?
        {
            bail!("prepared inventory pins changed; existing claims retained");
        }
        Ok(PreflightedReconciliation { prepared })
    }

    /// The scoped permit-backed apply for a preflighted
    /// reconciliation: bounded pure work only. Revalidates the owner
    /// image, identity, revision, and liveness through the passed
    /// guard (the commit's replay guard over the stored observation),
    /// then applies the candidate. The provider pins stand on their
    /// pre-sample preflight seal — no `check_unchanged` runs here —
    /// while the generic entry above keeps its own boundary check.
    // No generic caller remains: activation and refresh commit
    // through their proof entries below. The entry stays as the
    // refusal boundary any future generic caller must cross.
    #[allow(dead_code)]
    pub(crate) fn commit_preflighted_reconciliation(
        &mut self,
        preflighted: PreflightedReconciliation,
        guard: &mut dyn ImageGuard,
    ) -> Result<InventoryCommit> {
        self.note_graph_inputs_mutated();
        self.refuse_scoped_refresh_owner(preflighted.prepared.identity.owner)?;
        self.commit_preflighted_reconciliation_scoped(preflighted, guard)
    }

    /// The scoped apply itself, reached only through the
    /// permit-backed activation and refresh proof entries (the
    /// generic entry above refuses scoped-refresh candidates).
    fn commit_preflighted_reconciliation_scoped(
        &mut self,
        preflighted: PreflightedReconciliation,
        guard: &mut dyn ImageGuard,
    ) -> Result<InventoryCommit> {
        self.note_graph_inputs_mutated();
        self.check_inventory_image(&preflighted.prepared.identity, guard)?;
        self.commit_validated_reconciliation(preflighted.prepared)
    }

    /// Apply a reconciliation whose boundary checks already passed:
    /// fallible eligibility first, then the exact-state swap and
    /// owner bookkeeping. Shared by the generic commit (which
    /// revalidates pins at its boundary) and the scoped apply (whose
    /// pins stand on the pre-sample preflight seal).
    fn commit_validated_reconciliation(
        &mut self,
        prepared: PreparedReconciliation,
    ) -> Result<InventoryCommit> {
        self.inventory_state()?;
        self.preflight_candidate_publication(&prepared.candidate)?;
        let PreparedReconciliation {
            identity,
            complete,
            mut candidate,
        } = prepared;
        record_object_skips(
            &mut candidate.plan,
            &self.counters.object_skips,
            &mut self.capture_facts.visible_history_mut().scan_gap_tombstones,
        );
        let changed = candidate.plan != self.plan;
        // Fallible eligibility before any fact mutation: a stale or
        // retired receipt refuses here and replaces nothing.
        {
            let state = self.inventory.as_ref().expect("checked Inventory state");
            let owner = state
                .owners
                .get(&identity.owner)
                .ok_or_else(|| anyhow!("inventory owner is no longer retained"))?;
            if owner.serviced_epoch > identity.requested_epoch {
                bail!("inventory owner serviced a refresh newer than the committed receipt");
            }
        }
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
        // Eligibility was proved before the swap, which cannot retire the
        // owner, so closing the serviced epoch cannot fail.
        let state = self.inventory.as_mut().expect("checked Inventory state");
        let owner = state
            .owners
            .get_mut(&identity.owner)
            .expect("checked retained owner");
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
