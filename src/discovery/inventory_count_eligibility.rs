//! SPDX-License-Identifier: GPL-3.0-or-later
//! Bounded current ownership, separate from retained historical membership.
use crate::discovery::caller_registry::{
    AdmissionState, CallerId, CallerRegistry, MappingState, ModuleKey, RegistryLimits,
};
use crate::discovery::inventory_attach_set::{
    AttachRevision, CountMembershipCursor, CountMembershipItem, InventoryAttachSet,
};
use crate::inspect_system::CompleteMemberScan;
use std::collections::{BTreeMap, BTreeSet, VecDeque};
use std::ops::Bound::{Excluded, Included, Unbounded};
use std::ops::Deref;
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};

#[derive(Clone, Copy, PartialEq, Eq)]
pub(super) struct OwnershipEpoch(pub(super) u64);

#[derive(Clone)]
pub(super) enum CurrentCandidates {
    Unknown,
    Shared,
    Sole {
        module: ModuleKey,
        epoch: OwnershipEpoch,
        scan: Arc<OwnershipScan>,
    },
}

/// One collected receipt, with fixed metadata filled by bounded comparison.
/// Retained pair references share this allocation; they never copy its path.
pub(super) struct OwnershipScan {
    complete: CompleteMemberScan,
    revision: AttachRevision,
    comparison: AtomicU64,
}
impl Deref for OwnershipScan {
    type Target = CompleteMemberScan;
    fn deref(&self) -> &Self::Target {
        &self.complete
    }
}
impl OwnershipScan {
    pub(super) fn equivalent(&self, other: &Self) -> bool {
        let comparison = self.comparison.load(Ordering::Relaxed);
        comparison != 0
            && comparison == other.comparison.load(Ordering::Relaxed)
            && self.revision == other.revision
            && self.generation() == other.generation()
    }
}

/// A borrowed, fixed view of the caller's existing receipt ownership. It does
/// not retain a catalog, copy a path or walk the observed module list.
pub(super) struct ReceiptView<'a> {
    receipts: [Option<&'a Arc<OwnershipScan>>; 3],
    active: Option<&'a Arc<OwnershipScan>>,
}
#[derive(Clone, Copy, PartialEq, Eq)]
pub(super) enum ReceiptDisposition {
    Retained,
    Obsolete,
}
/// Meter the fixed receipt-resolution operations in both capture and service.
/// The service reserves its proven upper bound before touching pair state.
pub(super) struct ReceiptWork {
    pub(super) visits: usize,
}
impl ReceiptWork {
    pub(super) fn new() -> Self {
        // Indexed caller view and current per-object candidate lookups.
        Self { visits: 2 }
    }
    pub(super) fn visit(&mut self) {
        self.spend(1);
    }
    pub(super) fn spend(&mut self, count: usize) {
        self.visits += count;
    }
}
impl ReceiptView<'_> {
    #[cfg(test)]
    pub(super) fn receipts(&self) -> impl Iterator<Item = &Arc<OwnershipScan>> {
        self.receipts.into_iter().flatten()
    }
    pub(super) fn disposition(
        &self,
        scan: &Arc<OwnershipScan>,
        work: &mut ReceiptWork,
    ) -> ReceiptDisposition {
        for receipt in self.receipts {
            work.visit();
            if receipt.is_some_and(|receipt| Arc::ptr_eq(receipt, scan)) {
                return ReceiptDisposition::Retained;
            }
        }
        work.visit();
        if self.active.is_some_and(|active| scan.equivalent(active)) {
            // Completed equivalent receipts can leave all three positions.
            // Their original read remains valid without a historical Arc chain.
            ReceiptDisposition::Retained
        } else {
            ReceiptDisposition::Obsolete
        }
    }
}

pub(super) struct RecoveryWorkBudget {
    pub(super) visited: usize,
    pub(super) queries: usize,
    limit: usize,
}
impl RecoveryWorkBudget {
    pub(super) fn new() -> Self {
        Self {
            visited: 0,
            queries: 0,
            limit: 128,
        }
    }
    pub(super) fn remaining(&self) -> usize {
        self.limit.saturating_sub(self.visited)
    }
    pub(super) fn visit(&mut self) -> bool {
        self.spend(1)
    }
    pub(super) fn spend(&mut self, count: usize) -> bool {
        let Some(next) = self
            .visited
            .checked_add(count)
            .filter(|next| *next <= self.limit)
        else {
            return false;
        };
        self.visited = next;
        true
    }
    pub(super) fn limit_visits(&mut self, limit: usize) {
        self.limit = limit.min(128);
    }
    pub(super) fn query(&mut self) -> bool {
        if self.queries >= 4 {
            return false;
        }
        self.queries += 1;
        true
    }
}

struct Observation {
    modules: Vec<ModuleKey>,
    scan: Arc<OwnershipScan>,
    cursor: usize,
    equal: bool,
    authoritative: bool,
}
struct CleanupObservation {
    modules: Vec<ModuleKey>,
    cells: usize,
}
struct CallerObservation {
    seen_pass: Option<u64>,
    queued_revision: Option<AttachRevision>,
    live: bool,
    valid: bool,
    epoch: Option<u64>,
    last_authority_failure: u64,
    newest_accepted_post: u64,
    /// Existing summaries that consumed the active observation before it can
    /// be replaced. This cursor advances only through completed results.
    classified_after: Option<u32>,
    active: Option<Observation>,
    processing: Option<Observation>,
    waiting: Option<Observation>,
}
impl CallerObservation {
    fn revoke(&mut self) {
        let established = self.last_authority_failure != 0
            || self
                .active
                .as_ref()
                .is_some_and(|active| active.authoritative);
        self.valid = false;
        self.classified_after = None;
        self.epoch = self.epoch.and_then(|epoch| epoch.checked_add(1));
        if established || self.epoch.is_none() || !self.live {
            self.last_authority_failure = self.epoch.unwrap_or(u64::MAX);
        }
    }
}
#[derive(Default)]
struct ObjectMembers {
    modules: BTreeSet<ModuleKey>,
    unknown: bool,
}
struct MembershipIndex {
    revision: AttachRevision,
    cursor: Option<CountMembershipCursor>,
    complete: bool,
    refused: bool,
    unknown: bool,
    /// Sticky across rebuilds, including when every affected summary lags.
    /// Zero is no failure; otherwise this is the failed revision plus one.
    last_authority_failure: u64,
    cells: usize,
    objects: BTreeMap<u32, ObjectMembers>,
}
impl MembershipIndex {
    fn new(revision: AttachRevision, last_authority_failure: u64) -> Self {
        Self {
            revision,
            cursor: None,
            complete: false,
            refused: false,
            unknown: false,
            last_authority_failure,
            cells: 0,
            objects: BTreeMap::new(),
        }
    }
    fn note_failure(&mut self) {
        self.last_authority_failure = self.last_authority_failure.max(
            self.revision
                .sequence()
                .and_then(|revision| revision.checked_add(1))
                .unwrap_or(u64::MAX),
        );
    }
}
struct CandidateSummary {
    caller_epoch: Option<u64>,
    revision: Option<AttachRevision>,
    index_after: Option<ModuleKey>,
    observation_cursor: usize,
    candidate: Option<ModuleKey>,
    shared: bool,
    finished: bool,
    epoch: Option<u64>,
    result: CurrentCandidates,
    result_caller_epoch: Option<u64>,
    ordinary_sequence: u64,
}
impl CandidateSummary {
    fn new() -> Self {
        Self {
            caller_epoch: None,
            revision: None,
            index_after: None,
            observation_cursor: 0,
            candidate: None,
            shared: false,
            finished: false,
            epoch: Some(0),
            result: CurrentCandidates::Unknown,
            result_caller_epoch: None,
            ordinary_sequence: 1,
        }
    }
    fn restart(&mut self, caller_epoch: Option<u64>, revision: AttachRevision) {
        self.caller_epoch = caller_epoch;
        self.revision = Some(revision);
        self.index_after = None;
        self.observation_cursor = 0;
        self.candidate = None;
        self.shared = false;
        self.finished = false;
    }

    fn unconsumed_failure(&self, caller_failure: u64, index_failure: u64) -> bool {
        (caller_failure != 0
            && self
                .result_caller_epoch
                .is_none_or(|epoch| epoch < caller_failure))
            || match &self.result {
                CurrentCandidates::Sole { scan, .. } => scan
                    .revision
                    .sequence()
                    .is_none_or(|revision| revision < index_failure),
                _ => self.result_caller_epoch.is_none() && index_failure != 0,
            }
    }

    fn classified(&self, caller_epoch: Option<u64>, revision: AttachRevision) -> bool {
        self.result_caller_epoch.is_some()
            && self.result_caller_epoch == caller_epoch
            && match &self.result {
                CurrentCandidates::Sole { scan, .. } => scan.revision == revision,
                // These completed results already revoked continuity. A later
                // bounded retry may be unfinished without undoing that fact.
                CurrentCandidates::Unknown | CurrentCandidates::Shared => true,
            }
    }

    /// Commit invalidation before replacing the completed result/provenance.
    fn finish(
        &mut self,
        result: CurrentCandidates,
        caller_epoch: Option<u64>,
        caller_failure: u64,
        index_failure: u64,
    ) {
        let first_sole = self.result_caller_epoch.is_none()
            && self.ordinary_sequence == 1
            && !self.finished
            && matches!(self.result, CurrentCandidates::Unknown)
            && matches!(result, CurrentCandidates::Sole { .. });
        let same = match (&self.result, &result) {
            (
                CurrentCandidates::Sole {
                    module: old,
                    scan: old_scan,
                    ..
                },
                CurrentCandidates::Sole { module, scan, .. },
            ) => old == module && old_scan.generation() == scan.generation(),
            (CurrentCandidates::Unknown, CurrentCandidates::Unknown)
            | (CurrentCandidates::Shared, CurrentCandidates::Shared) => {
                self.result_caller_epoch.is_some()
            }
            _ => false,
        };
        if caller_epoch.is_none() {
            self.ordinary_sequence = 0;
        } else if self.ordinary_sequence != 0
            && (self.unconsumed_failure(caller_failure, index_failure) || !(same || first_sole))
        {
            self.ordinary_sequence = self.ordinary_sequence.checked_add(1).unwrap_or(0);
        }
        self.finished = true;
        self.result = result;
        self.result_caller_epoch = caller_epoch;
    }
}

/// Borrowed invalidation metadata, never a selected epoch or proof.
pub(super) struct OrdinaryView<'a> {
    pub(super) candidate: Option<&'a CurrentCandidates>,
    pub(super) sequence: u64,
    pub(super) startup: bool,
    pub(super) initial_metadata_refused: bool,
    origin_after: Option<u64>,
}
impl OrdinaryView<'_> {
    pub(super) fn checkpoint(&self, original_pre: u64) -> u64 {
        if self.startup || self.origin_after.is_some_and(|post| original_pre > post) {
            self.sequence
        } else {
            0
        }
    }
}

pub(super) struct CountOwnership {
    limits: RegistryLimits,
    pass: Option<u64>,
    callers: BTreeMap<CallerId, CallerObservation>,
    associations: usize,
    cleanup: VecDeque<CleanupObservation>,
    observations_pending: BTreeSet<CallerId>,
    observation_after: Option<CallerId>,
    index: Option<MembershipIndex>,
    stale_index: Option<MembershipIndex>,
    summaries: BTreeMap<(CallerId, u32), CandidateSummary>,
    summary_after: Option<(CallerId, u32)>,
}
impl CountOwnership {
    pub(super) fn new(limits: RegistryLimits) -> Self {
        Self {
            limits,
            pass: Some(0),
            callers: BTreeMap::new(),
            associations: 0,
            cleanup: VecDeque::new(),
            observations_pending: BTreeSet::new(),
            observation_after: None,
            index: None,
            stale_index: None,
            summaries: BTreeMap::new(),
            summary_after: None,
        }
    }
    pub(super) fn begin_catalog_pass(&mut self) {
        self.pass = self.pass.and_then(|pass| pass.checked_add(1));
    }
    fn discard(&mut self, observation: Observation) {
        if !observation.modules.is_empty() {
            let cells = observation.modules.len();
            self.cleanup.push_back(CleanupObservation {
                modules: observation.modules,
                cells,
            });
        }
    }
    /// Input is the already bounded, ordered catalog projection, moved once.
    pub(super) fn queue_observation(
        &mut self,
        caller: CallerId,
        modules: Vec<ModuleKey>,
        complete: Option<CompleteMemberScan>,
    ) -> bool {
        if !self.callers.contains_key(&caller) && self.callers.len() >= self.limits.max_callers {
            return false;
        }
        let slot = self.callers.entry(caller).or_insert(CallerObservation {
            seen_pass: None,
            queued_revision: None,
            live: true,
            valid: false,
            epoch: Some(0),
            last_authority_failure: 0,
            newest_accepted_post: 0,
            classified_after: None,
            active: None,
            processing: None,
            waiting: None,
        });
        if slot
            .seen_pass
            .is_some_and(|seen| Some(seen) != self.pass && seen.checked_add(1) != self.pass)
        {
            slot.revoke();
        }
        slot.seen_pass = self.pass;
        slot.queued_revision = self.index.as_ref().map(|index| index.revision);
        if !slot.live
            || self.pass.is_none()
            || slot.queued_revision.is_none()
            || complete.is_none()
            || self
                .associations
                .checked_add(modules.len())
                .is_none_or(|cells| cells > self.limits.max_edges)
        {
            slot.revoke();
            // Existing accepted storage remains charged until bounded cleanup.
            let processing = slot.processing.take();
            let waiting = slot.waiting.take();
            let active = slot.active.take();
            self.observations_pending.remove(&caller);
            for observation in [processing, waiting, active].into_iter().flatten() {
                self.discard(observation);
            }
            return complete.is_none();
        }
        let scan = Arc::new(OwnershipScan {
            complete: complete.expect("checked receipt"),
            revision: slot.queued_revision.expect("checked membership revision"),
            comparison: AtomicU64::new(0),
        });
        let equal = slot.active.as_ref().is_some_and(|active| {
            active.modules.len() == modules.len() && active.scan.generation() == scan.generation()
        });
        self.associations += modules.len();
        let observation = Observation {
            modules,
            scan,
            cursor: 0,
            equal,
            authoritative: true,
        };
        let discarded = if slot.processing.is_some() {
            slot.waiting.replace(observation)
        } else {
            slot.processing = Some(observation);
            None
        };
        self.observations_pending.insert(caller);
        if let Some(discarded) = discarded {
            self.discard(discarded);
        }
        true
    }
    pub(super) fn forget_live(&mut self, caller: CallerId) {
        if let Some(slot) = self.callers.get_mut(&caller) {
            slot.live = false;
            slot.revoke();
            let discarded = [
                slot.active.take(),
                slot.processing.take(),
                slot.waiting.take(),
            ];
            self.observations_pending.remove(&caller);
            for observation in discarded.into_iter().flatten() {
                self.discard(observation);
            }
        }
    }
    pub(super) fn deferred(&self, caller: CallerId, object: u32) -> bool {
        self.callers.get(&caller).is_some_and(|slot| {
            slot.live
                && slot.seen_pass == self.pass
                && (slot.processing.is_some()
                    || slot.waiting.is_some()
                    || (slot.valid
                        && (self
                            .index
                            .as_ref()
                            .is_some_and(|index| !index.complete && !index.refused)
                            || self
                                .summaries
                                .get(&(caller, object))
                                .is_some_and(|summary| {
                                    !summary.finished
                                        || summary.caller_epoch != slot.epoch
                                        || summary.revision
                                            != self.index.as_ref().map(|index| index.revision)
                                }))))
        })
    }
    /// A queued receipt can retain an early count bracket while its bounded
    /// membership work waits. It proves no sole owner by itself.
    pub(super) fn supporting_scan(&self, caller: CallerId) -> Option<Arc<OwnershipScan>> {
        let slot = self
            .callers
            .get(&caller)
            .filter(|slot| slot.live && slot.seen_pass == self.pass && self.pass.is_some())?;
        slot.waiting
            .as_ref()
            .or(slot.processing.as_ref())
            .or(slot.active.as_ref().filter(|_| slot.valid))
            .filter(|observation| {
                Some(observation.scan.revision) == slot.queued_revision
                    && slot.queued_revision == self.index.as_ref().map(|index| index.revision)
            })
            .map(|observation| observation.scan.clone())
    }
    pub(super) fn receipt_view(&self, caller: CallerId) -> ReceiptView<'_> {
        let Some(slot) = self
            .callers
            .get(&caller)
            .filter(|slot| slot.live && slot.seen_pass == self.pass && self.pass.is_some())
        else {
            return ReceiptView {
                receipts: [None; 3],
                active: None,
            };
        };
        ReceiptView {
            receipts: [
                slot.active
                    .as_ref()
                    .filter(|_| slot.valid)
                    .map(|entry| &entry.scan),
                slot.processing.as_ref().map(|entry| &entry.scan),
                slot.waiting.as_ref().map(|entry| &entry.scan),
            ],
            active: slot
                .active
                .as_ref()
                .filter(|_| slot.valid)
                .map(|entry| &entry.scan),
        }
    }
    pub(super) fn invalidate_memberships(&mut self, revision: AttachRevision) {
        if self
            .index
            .as_ref()
            .is_some_and(|index| index.revision == revision)
        {
            return;
        }
        let failure = self
            .index
            .as_ref()
            .map_or(0, |index| index.last_authority_failure);
        if let Some(index) = self.index.take().filter(|index| index.cells > 0) {
            // Construction cannot overlap deferred reclamation, so there is one stale replacement.
            debug_assert!(self.stale_index.is_none());
            self.stale_index = Some(index);
        }
        self.index = Some(MembershipIndex::new(revision, failure));
    }
    pub(super) fn register_pair(&mut self, caller: CallerId, object: u32) -> bool {
        if self.summaries.contains_key(&(caller, object)) {
            return true;
        }
        if self.summaries.len() >= self.limits.max_edges {
            return false;
        }
        self.summaries
            .insert((caller, object), CandidateSummary::new());
        if let Some(slot) = self.callers.get_mut(&caller)
            && slot.classified_after.is_some_and(|after| object <= after)
        {
            // A new retained summary cannot hide behind an already checked
            // prefix of the accepted observation's classification barrier.
            slot.classified_after = None;
        }
        true
    }

    /// Three bounded lookups also provide ordinary continuity and origin. A
    /// newly registered summary has no completed owner yet; its first result
    /// can only preserve the token for Sole, never for Shared/Unknown.
    pub(super) fn ordinary_view(&self, caller: CallerId, object: u32) -> OrdinaryView<'_> {
        let mut view = OrdinaryView {
            candidate: None,
            sequence: 0,
            startup: false,
            initial_metadata_refused: false,
            origin_after: None,
        };
        let Some(summary) = self.summaries.get(&(caller, object)) else {
            return view;
        };
        let slot = self.callers.get(&caller);
        let index = self.index.as_ref();
        view.initial_metadata_refused = summary.ordinary_sequence == 1
            && summary.result_caller_epoch.is_none()
            && !summary.finished
            && self.pass.is_some()
            && slot.is_some_and(|slot| {
                slot.live
                    && slot.epoch.is_some()
                    && slot.newest_accepted_post == 0
                    && slot.last_authority_failure == 0
                    && slot.active.is_none()
                    && slot.processing.is_none()
                    && slot.waiting.is_none()
            })
            && index.is_some_and(|index| {
                index.refused && !index.unknown && index.revision.sequence().is_some()
            });
        let startup = summary.ordinary_sequence == 1
            && summary.result_caller_epoch.is_none()
            && !summary.finished
            && self.pass.is_some()
            && slot.is_none_or(|slot| {
                slot.live
                    && slot.epoch.is_some()
                    && self.pass.is_some()
                    && slot.newest_accepted_post == 0
                    && slot.last_authority_failure == 0
                    && slot.active.is_none()
                    && slot.processing.is_none()
                    && slot.waiting.is_none()
            })
            && index.is_none_or(|index| {
                !index.refused && !index.unknown && index.last_authority_failure == 0
            });
        if startup {
            view.sequence = 1;
            view.startup = true;
            return view;
        }
        let Some(slot) = slot.filter(|slot| {
            slot.live
                && slot.valid
                && slot.epoch.is_some()
                && slot.seen_pass == self.pass
                && self.pass.is_some()
                && slot.processing.is_none()
                && slot.waiting.is_none()
        }) else {
            return view;
        };
        let Some(index) = index.filter(|index| {
            index.complete
                && !index.refused
                && !index.unknown
                && slot.queued_revision == Some(index.revision)
        }) else {
            return view;
        };
        if summary.finished
            && summary.caller_epoch == slot.epoch
            && summary.revision == Some(index.revision)
        {
            view.candidate = Some(&summary.result);
        }
        let initial = summary.result_caller_epoch.is_none()
            && !summary.finished
            && summary.ordinary_sequence == 1;
        if (initial || matches!(view.candidate, Some(CurrentCandidates::Sole { .. })))
            && !summary
                .unconsumed_failure(slot.last_authority_failure, index.last_authority_failure)
        {
            view.sequence = summary.ordinary_sequence;
            // Equivalent receipts retain the earliest active scan. The newest
            // fully accepted receipt's POST is still required at first staging.
            view.origin_after = Some(slot.newest_accepted_post);
        }
        view
    }
    fn known_candidates(&self, caller: CallerId, object: u32) -> Option<&CurrentCandidates> {
        let slot = self.callers.get(&caller).filter(|slot| {
            slot.live
                && slot.valid
                && slot.epoch.is_some()
                && slot.seen_pass == self.pass
                && self.pass.is_some()
                && slot.processing.is_none()
                && slot.waiting.is_none()
        })?;
        let index = self
            .index
            .as_ref()
            .filter(|index| index.complete && !index.refused && !index.unknown)?;
        if slot.queued_revision != Some(index.revision) {
            return None;
        }
        self.summaries
            .get(&(caller, object))
            .filter(|summary| {
                summary.finished
                    && summary.caller_epoch == slot.epoch
                    && summary.revision == Some(index.revision)
            })
            .map(|summary| &summary.result)
    }
    pub(super) fn candidates(&self, caller: CallerId, object: u32) -> CurrentCandidates {
        self.known_candidates(caller, object)
            .cloned()
            .unwrap_or(CurrentCandidates::Unknown)
    }
    /// Borrow the existing indexed result without cloning a module/path for
    /// every already-processed native update.
    #[cfg(test)]
    pub(super) fn sole(
        &self,
        caller: CallerId,
        object: u32,
    ) -> Option<(&ModuleKey, OwnershipEpoch)> {
        match self.known_candidates(caller, object)? {
            CurrentCandidates::Sole { module, epoch, .. } => Some((module, *epoch)),
            _ => None,
        }
    }
    pub(super) fn advance(
        &mut self,
        attach: &InventoryAttachSet,
        registry: &CallerRegistry,
        budget: &mut RecoveryWorkBudget,
    ) {
        self.invalidate_memberships(attach.count_revision());
        let total_limit = budget.limit;
        budget.limit_visits((budget.visited + 16).min(total_limit));
        while budget.remaining() > 0 {
            if let Some(cleanup) = self.cleanup.front_mut() {
                budget.visit();
                cleanup.modules.pop();
                // Vec retains its buffer until reclamation completes. Keep all
                // reserved cells charged, even after individual keys were freed.
                if cleanup.modules.is_empty() {
                    self.associations -= cleanup.cells;
                    self.cleanup.pop_front();
                }
                continue;
            }
            if let Some(index) = &mut self.stale_index {
                if let Some((&object, members)) = index.objects.first_key_value() {
                    budget.visit();
                    if members.modules.is_empty() {
                        index.objects.remove(&object);
                    } else {
                        index
                            .objects
                            .get_mut(&object)
                            .expect("indexed object")
                            .modules
                            .pop_first();
                    }
                    index.cells -= 1;
                    continue;
                }
                self.stale_index = None;
                continue;
            }
            break;
        }
        budget.limit_visits(total_limit);
        let rebuilding_allowed = self.stale_index.is_none();
        if let Some(index) = self
            .index
            .as_mut()
            .filter(|index| rebuilding_allowed && !index.complete && !index.refused)
        {
            // Reserve the cursor's two retained keys and a replacement clone, plus the transient
            // page and the worst-case new index cells it can introduce.
            let spare = self
                .limits
                .max_edges
                .saturating_sub(index.cells.saturating_add(3));
            let limit = (budget.remaining().min(16) / 2).min(spare / 2);
            if limit == 0 {
                if spare < 2 && budget.visit() {
                    index.refused = true;
                    index.note_failure();
                }
            } else {
                match attach.count_membership_page(index.cursor.take(), index.revision, limit) {
                    Err(_) => {
                        budget.visit();
                        index.refused = true;
                        index.note_failure();
                    }
                    Ok(page) => {
                        // Reading a page and folding its items into the index both visit them.
                        budget.spend(page.visited * 2);
                        for item in page.items {
                            match item {
                                CountMembershipItem::Endpoint { object, unknown } => {
                                    let is_new = !index.objects.contains_key(&object.index());
                                    index.objects.entry(object.index()).or_default().unknown |=
                                        unknown;
                                    index.cells += usize::from(is_new);
                                }
                                CountMembershipItem::Module { object, module } => {
                                    let key = ModuleKey::physical(
                                        module.object.device.major,
                                        module.object.device.minor,
                                        module.object.inode,
                                        Some(module.sha256),
                                        "",
                                    );
                                    let is_new = !index.objects.contains_key(&object.index());
                                    let members = index.objects.entry(object.index()).or_default();
                                    index.cells += usize::from(is_new)
                                        + usize::from(members.modules.insert(key));
                                }
                                CountMembershipItem::Unknown => {
                                    index.unknown = true;
                                    index.note_failure();
                                }
                                CountMembershipItem::Skipped => {}
                            }
                        }
                        index.cursor = page.cursor;
                        index.complete = index.cursor.is_none();
                    }
                }
            }
        }
        // One association comparison per turn, rotating over caller headers.
        budget.limit_visits((budget.visited + 16).min(total_limit));
        while budget.remaining() >= 4 && !self.observations_pending.is_empty() {
            let next = self
                .observation_after
                .and_then(|after| {
                    self.observations_pending
                        .range((Excluded(after), Unbounded))
                        .next()
                        .copied()
                })
                .or_else(|| self.observations_pending.first().copied());
            let caller = next.expect("pending caller");
            self.observation_after = Some(caller);
            budget.visit();
            let slot = self
                .callers
                .get_mut(&caller)
                .expect("retained caller header");
            let observation = slot.processing.as_mut().expect("processing observation");
            if observation.cursor < observation.modules.len() {
                budget.spend(2);
                let key = &observation.modules[observation.cursor];
                observation.authoritative &= matches!(
                    key,
                    ModuleKey::Physical {
                        sha256: Some(_),
                        ..
                    }
                ) && registry
                    .module_id_for(key)
                    .and_then(|id| registry.module(id))
                    .is_some_and(|record| record.admission == AdmissionState::Admitted);
                observation.equal &= slot
                    .active
                    .as_ref()
                    .is_some_and(|active| active.modules.get(observation.cursor) == Some(key));
                observation.cursor += 1;
                continue;
            }
            if let Some(active) = slot.active.as_ref().filter(|_| slot.valid) {
                // Do not erase an accepted observation before every retained
                // caller/object summary consumes it. One charged seek/check
                // per turn advances a bounded cursor; summary work below does
                // the actual classification, even while newer work is queued.
                budget.spend(2);
                let after = slot
                    .classified_after
                    .map_or(Included((caller, 0)), |object| Excluded((caller, object)));
                if let Some((&(_, object), summary)) = self
                    .summaries
                    .range((after, Included((caller, u32::MAX))))
                    .next()
                {
                    if summary.classified(slot.epoch, active.scan.revision) {
                        slot.classified_after = Some(object);
                    }
                    continue;
                }
            }
            let mut observation = slot.processing.take().expect("completed observation");
            budget.visit();
            if observation.authoritative {
                slot.newest_accepted_post = slot
                    .newest_accepted_post
                    .max(observation.scan.finished_ns());
            }
            let failed_authority = !observation.authoritative;
            let old = if observation.equal && slot.valid && observation.authoritative {
                observation
                    .scan
                    .comparison
                    .store(slot.epoch.unwrap_or(0), Ordering::Relaxed);
                let active = slot.active.as_mut().expect("equal valid observation");
                if active.scan.revision != observation.scan.revision {
                    // Equality preserves the caller epoch. A new membership
                    // revision still needs its own collected receipt: a later
                    // Shared→Sole result cannot borrow the earlier scan.
                    std::mem::swap(&mut active.scan, &mut observation.scan);
                    slot.classified_after = None;
                }
                Some(observation)
            } else {
                slot.epoch = slot.epoch.and_then(|epoch| epoch.checked_add(1));
                slot.classified_after = None;
                observation.scan.comparison.store(
                    slot.epoch
                        .filter(|_| observation.authoritative)
                        .unwrap_or(0),
                    Ordering::Relaxed,
                );
                observation.cursor = 0;
                slot.active.replace(observation)
            };
            slot.valid = slot.live
                && slot.epoch.is_some()
                && slot
                    .active
                    .as_ref()
                    .is_some_and(|active| active.authoritative);
            if failed_authority || slot.epoch.is_none() {
                slot.last_authority_failure = slot.epoch.unwrap_or(u64::MAX);
            }
            if let Some(mut waiting) = slot.waiting.take() {
                waiting.equal = slot.active.as_ref().is_some_and(|active| {
                    active.modules.len() == waiting.modules.len()
                        && active.scan.generation() == waiting.scan.generation()
                });
                slot.processing = Some(waiting);
            } else {
                self.observations_pending.remove(&caller);
            }
            if let Some(old) = old {
                self.discard(old);
            }
        }
        budget.limit_visits(total_limit);
        let Some(index) = self
            .index
            .as_ref()
            .filter(|index| index.complete || index.refused)
        else {
            return;
        };
        // Seek, never restart an uncharged prefix; each intersection/lookup costs visits.
        while budget.remaining() >= 5 && !self.summaries.is_empty() {
            let next = self
                .summary_after
                .and_then(|after| {
                    self.summaries
                        .range((Excluded(after), Unbounded))
                        .next()
                        .map(|(&key, _)| key)
                })
                .or_else(|| self.summaries.first_key_value().map(|(&key, _)| key));
            let Some(key @ (caller, object)) = next else {
                break;
            };
            self.summary_after = Some(key);
            // Seek/caller lookup plus the constant failure/origin guards.
            budget.spend(3);
            let caller_slot = self.callers.get(&caller);
            let Some(slot) =
                caller_slot.filter(|slot| slot.live && slot.valid && slot.seen_pass == self.pass)
            else {
                if caller_slot
                    .is_none_or(|slot| !slot.live || !slot.valid || slot.seen_pass != self.pass)
                {
                    // An invalid caller cannot retain an obsolete summary's
                    // receipt forever. Reclaim one indexed summary per turn;
                    // pending healthy observations preserve comparison history.
                    let summary = self.summaries.get_mut(&key).expect("retained pair summary");
                    let startup = summary.ordinary_sequence == 1
                        && summary.result_caller_epoch.is_none()
                        && !summary.finished
                        && self.pass.is_some()
                        && caller_slot.is_none_or(|slot| {
                            slot.live
                                && slot.epoch.is_some()
                                && self.pass.is_some()
                                && slot.newest_accepted_post == 0
                                && slot.last_authority_failure == 0
                                && slot.active.is_none()
                        })
                        && index.last_authority_failure == 0;
                    if !startup {
                        summary.finish(
                            CurrentCandidates::Unknown,
                            caller_slot.and_then(|slot| slot.epoch),
                            caller_slot.map_or(u64::MAX, |slot| slot.last_authority_failure),
                            index.last_authority_failure,
                        );
                    }
                }
                continue;
            };
            let summary = self.summaries.get_mut(&key).expect("retained pair summary");
            if summary.caller_epoch != slot.epoch || summary.revision != Some(index.revision) {
                summary.restart(slot.epoch, index.revision);
            }
            if summary.finished
                && !matches!(summary.result, CurrentCandidates::Unknown)
                && !index.refused
                && !index.unknown
            {
                continue;
            }
            if summary.finished {
                summary.restart(slot.epoch, index.revision);
            }
            let Some(members) = index.objects.get(&object).filter(|members| {
                !members.unknown
                    && !index.unknown
                    && !index.refused
                    && slot
                        .active
                        .as_ref()
                        .is_some_and(|active| active.scan.revision == index.revision)
            }) else {
                summary.finish(
                    CurrentCandidates::Unknown,
                    slot.epoch,
                    slot.last_authority_failure,
                    index.last_authority_failure,
                );
                continue;
            };
            let observation = slot.active.as_ref().expect("valid active observation");
            let next_module = match &summary.index_after {
                Some(after) => members.modules.range((Excluded(after), Unbounded)).next(),
                None => members.modules.first(),
            };
            if let Some(module) = next_module {
                budget.spend(2);
                let observed = observation.modules.get(summary.observation_cursor);
                match observed.map(|observed| module.cmp(observed)) {
                    Some(std::cmp::Ordering::Greater) => {
                        summary.observation_cursor += 1;
                    }
                    Some(std::cmp::Ordering::Equal) => {
                        let valid = registry
                            .module_id_for(module)
                            .and_then(|id| registry.module(id).zip(registry.edge(caller, id)))
                            .is_some_and(|(module, edge)| {
                                module.admission == AdmissionState::Admitted
                                    && edge.mapping == MappingState::Mapped
                                    && !edge.double_loaded
                            });
                        if !valid {
                            summary.finish(
                                CurrentCandidates::Unknown,
                                slot.epoch,
                                slot.last_authority_failure,
                                index.last_authority_failure,
                            );
                            continue;
                        }
                        if summary.candidate.is_some() {
                            summary.shared = true;
                        } else {
                            summary.candidate = Some(module.clone());
                        }
                        summary.observation_cursor += 1;
                        summary.index_after = Some(module.clone());
                    }
                    _ => {
                        summary.index_after = Some(module.clone());
                    }
                }
                continue;
            }
            summary.index_after = None;
            let result = if summary.shared {
                CurrentCandidates::Shared
            } else if let Some(module) = summary.candidate.take() {
                // A changed observed candidate set, not a newer timestamp, defines the epoch.
                let unchanged = summary.result_caller_epoch == slot.epoch
                    && matches!(&summary.result, CurrentCandidates::Sole { module: old, scan, .. } if old == &module && scan.generation() == observation.scan.generation());
                if !unchanged {
                    summary.epoch = summary.epoch.and_then(|epoch| epoch.checked_add(1));
                }
                summary.epoch.map_or(CurrentCandidates::Unknown, |epoch| {
                    CurrentCandidates::Sole {
                        module,
                        epoch: OwnershipEpoch(epoch),
                        scan: observation.scan.clone(),
                    }
                })
            } else {
                CurrentCandidates::Unknown
            };
            summary.finish(
                result,
                slot.epoch,
                slot.last_authority_failure,
                index.last_authority_failure,
            );
            summary.candidate = None;
        }
    }

    #[cfg(test)]
    pub(super) fn ordinary_sequence(&self, caller: CallerId, object: u32) -> u64 {
        self.summaries
            .get(&(caller, object))
            .map_or(0, |summary| summary.ordinary_sequence)
    }
    #[cfg(test)]
    pub(super) fn index_failure(&self) -> u64 {
        self.index
            .as_ref()
            .map_or(0, |index| index.last_authority_failure)
    }
    #[cfg(test)]
    pub(super) fn newest_accepted_post(&self, caller: CallerId) -> u64 {
        self.callers
            .get(&caller)
            .map_or(0, |slot| slot.newest_accepted_post)
    }
    #[cfg(test)]
    pub(super) fn state_layouts() -> (usize, usize, usize) {
        (
            std::mem::size_of::<CandidateSummary>(),
            std::mem::size_of::<CallerObservation>(),
            std::mem::size_of::<MembershipIndex>(),
        )
    }
    #[cfg(test)]
    pub(super) fn retained_cells(&self) -> (usize, usize, usize) {
        let cells = |index: &MembershipIndex| {
            index.cells
                + index
                    .cursor
                    .as_ref()
                    .map_or(0, CountMembershipCursor::retained_keys)
        };
        (
            self.associations,
            self.index.as_ref().map_or(0, cells) + self.stale_index.as_ref().map_or(0, cells),
            self.summaries.len(),
        )
    }
    #[cfg(test)]
    pub(super) fn exhaust_epochs(&mut self) {
        for slot in self.callers.values_mut() {
            slot.epoch = Some(u64::MAX);
        }
        for summary in self.summaries.values_mut() {
            summary.epoch = Some(u64::MAX);
            summary.ordinary_sequence = u64::MAX;
        }
        self.pass = Some(u64::MAX);
    }
}
