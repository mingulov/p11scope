//! The paid leaf surface the recovery cursor drives the journal through.
//!
//! [`JournalLeaves`] wraps the adapter behind a field private to this
//! module, so [`crate::semantics_objects::recovery_cursor`] (a sibling of
//! the journal, which cannot see the adapter's fields) reaches journal
//! state only through the methods below. Each method that reads or
//! mutates a leaf consumes a [`Paid`] unit and does exactly that one
//! leaf's work (one entry, refused begin, key or claimant row, plus the
//! constant indexed lookups that decide it). A decision that reads an
//! identity's claims consumes a [`ClaimsPaid`], which only
//! [`JournalLeaves::claim_probe`] mints after paying for every claim read
//! it covers. Unpaid methods read no leaf: O(1) metadata and bulk frees.

use std::collections::{BTreeMap, BTreeSet, VecDeque};

use super::ConsumptionOrdinal;
use super::{
    AbandonDisposition, CallAttribution, CallIdentity, JournalAdapter, JournalDomainKey,
    JournalDomainProof, JournalNativeKey, ProbeDeposit, RecoveryMode, RefCut, RetainedMember,
    ScopedRecovery, StagedShape, StagingLedger, TaintCause, abandon_disposition,
    abandonment_disposes_per_call, disposes_unclaimable_original, identity_of_begin,
    shape_of_entry,
};
use crate::semantics_objects::ObjectDomain;
use crate::semantics_objects::credit::{Credit, Paid};
use crate::semantics_objects::state::DomainRetirement;

/// The recovery cursor's only handle on the journal adapter.
pub(in crate::semantics_objects) struct JournalLeaves<'a> {
    adapter: &'a mut JournalAdapter,
}

/// A claim-reading decision's prepaid credit: minted only by
/// [`JournalLeaves::claim_probe`] after every claim read it covers was
/// debited.
#[must_use = "a paid claim decision is spent on that decision"]
pub(in crate::semantics_objects) struct ClaimsPaid {
    _sealed: (),
}

/// One claim probe's outcome.
pub(in crate::semantics_objects) enum ClaimProbe {
    /// The decision fits; its reads are paid.
    Fits(ClaimsPaid),
    /// It does not fit what is left of this slice: resume next slice
    /// (nothing was decided).
    Yield,
    /// It can never fit one credit: the caller fails closed.
    Never,
}

/// One classified staged member (open entry or refused begin).
pub(in crate::semantics_objects) enum Classified {
    Keep,
    Wipe,
    /// Stuck image, unconverted: wipe unless a healthy claimant names
    /// it, which needs a paid claim decision.
    Check(StagedShape),
}

/// One preservation read of a wiped open entry.
pub(in crate::semantics_objects) enum PreserveRead {
    /// Gone, bounded, or disposed per call: settled.
    Settled,
    /// An effect-free unbounded abandonment with no negative return on
    /// the entry: disposal depends on the queued claims' returns.
    Check {
        shape: StagedShape,
        function: u32,
        image: (u64, u64),
        /// Whether the abandonment leaves a capable frame: a doom
        /// grounded in one never mints a fresh incarnation past it.
        capable: bool,
    },
    /// An unbounded abandonment that keeps continuing effects: decide.
    Unbounded {
        image: (u64, u64),
        shape: StagedShape,
        /// Whether the abandonment leaves a capable frame: a doom
        /// grounded in one never mints a fresh incarnation past it.
        capable: bool,
    },
}

/// One wipe visit of an open entry.
pub(in crate::semantics_objects) enum WipeOpen {
    /// Gone or wiped.
    Done,
    /// An unterminated effect-free abandoned entry: whether its late
    /// terminal is excused depends on the queued claims' returns. Not yet
    /// removed.
    Check { shape: StagedShape, function: u32 },
}

/// One visit of the doomed key's image's open entries.
pub(in crate::semantics_objects) enum DoomOpen {
    Skip,
    Dropped,
    /// Unconverted entry of the key's image: dropped only when it
    /// attributes to the key (a paid claim decision).
    Check(StagedShape),
}

/// Which refused begins a compaction drops.
pub(in crate::semantics_objects) enum RefusedDrop<'r> {
    Images(&'r BTreeSet<(u64, u64)>),
    Identities(&'r BTreeSet<CallIdentity>),
    Tainted,
    /// Exactly this member (a decided attribution).
    This(bool),
}

/// One all-key fence visit.
pub(in crate::semantics_objects) struct FenceAllVisit {
    pub(in crate::semantics_objects) key: JournalDomainKey,
    pub(in crate::semantics_objects) scope: ObjectDomain,
    pub(in crate::semantics_objects) retire: Option<DomainRetirement>,
    pub(in crate::semantics_objects) count_unregistered: bool,
}

/// One S1-only subject visit.
pub(in crate::semantics_objects) enum S1Subject {
    None,
    Domain(ObjectDomain),
    /// The subject's key is gone: its image tainted conservatively.
    Fallback,
}

/// The unit an S1-only disposal is paid with.
pub(in crate::semantics_objects) enum S1DisposePaid {
    /// The own-claim check fit: the claim is consumed.
    Claims(ClaimsPaid),
    /// The own-claim check can never fit one credit.
    Plain(Paid),
}

/// One claim-store drop step.
pub(in crate::semantics_objects) enum ClaimsStep {
    Done,
    /// The identity is settled: the cursor passes it.
    Visited(CallIdentity),
    /// The identity's image is tainted: drop its queues next.
    Enter(CallIdentity),
    /// One claimant queue dropped.
    Removed,
    Yield,
}

impl<'a> JournalLeaves<'a> {
    pub(super) fn new(adapter: &'a mut JournalAdapter) -> Self {
        Self { adapter }
    }

    #[cfg(test)]
    fn visit(&self) {
        self.adapter
            .test_leaf_visits
            .set(self.adapter.test_leaf_visits.get() + 1);
    }

    #[cfg(not(test))]
    fn visit(&self) {}

    /// The staging ledger (accounting only: every operation the cursor
    /// can reach is a constant-time charge or release).
    pub(in crate::semantics_objects) fn ledger(&mut self) -> &mut StagingLedger {
        &mut self.adapter.ledger
    }

    // ---- Claims --------------------------------------------------------

    /// The one debit-before-read cost probe for a decision over one
    /// identity's claims (and, for live-set decisions, one image's key
    /// list). It runs right after the paid read of the staged row the
    /// decision is about, whose unit covers the constant indexed lookup of
    /// that row's claim map (its claimant count). Each further read is
    /// paid before it happens: one unit per claimant, covering its row,
    /// its queue length and its first queued claim; one per further
    /// queued claim; and, for a live-set decision, the key-list build plus
    /// each claimant's live-set lookup. Units accumulate in `deposit`
    /// across slices, so a decision dearer than one tick still completes;
    /// one dearer than one credit fails closed ([`ClaimProbe::Never`]).
    pub(in crate::semantics_objects) fn claim_probe(
        &self,
        shape: &StagedShape,
        image: Option<(u64, u64)>,
        deposit: &mut ProbeDeposit,
        credit: &mut Credit<'_>,
    ) -> ClaimProbe {
        let keys = image
            .and_then(|image| self.adapter.image_keys.get(&image))
            .map_or(0, Vec::len);
        if deposit.named.is_some()
            && (deposit.claims_seen != self.adapter.claim_counts || deposit.keys_seen != keys)
        {
            // The claim set moved since this decision was priced.
            *deposit = ProbeDeposit::default();
        }
        let claimants = self.adapter.claims.get(&shape.identity);
        let named = match deposit.named {
            Some(named) => named,
            None => {
                let named = claimants.map_or(0, BTreeMap::len);
                if named > super::SCOPED_RECOVERY_SLICE {
                    return ClaimProbe::Never;
                }
                *deposit = ProbeDeposit {
                    paid: 0,
                    named: Some(named),
                    total: None,
                    claims_seen: self.adapter.claim_counts,
                    keys_seen: keys,
                };
                named
            }
        };
        // One unit per claimant before its queue length is read.
        if !Self::fill(deposit, named, credit) {
            return ClaimProbe::Yield;
        }
        let total = match deposit.total {
            Some(total) => total,
            None => {
                let queued = claimants.map_or(0, |claimants| {
                    claimants
                        .values()
                        .map(VecDeque::len)
                        .fold(0, usize::saturating_add)
                });
                let live = if keys == 0 {
                    0
                } else {
                    keys.saturating_add(named.saturating_mul(keys))
                };
                let total = named
                    .saturating_add(queued.saturating_sub(named))
                    .saturating_add(live);
                if total > super::SCOPED_RECOVERY_SLICE {
                    *deposit = ProbeDeposit::default();
                    return ClaimProbe::Never;
                }
                deposit.total = Some(total);
                total
            }
        };
        if !Self::fill(deposit, total, credit) {
            return ClaimProbe::Yield;
        }
        *deposit = ProbeDeposit::default();
        ClaimProbe::Fits(ClaimsPaid { _sealed: () })
    }

    /// Pay toward a deposit target, one unit at a time; false when the
    /// slice ran out first (the deposit keeps what it paid).
    fn fill(deposit: &mut ProbeDeposit, target: usize, credit: &mut Credit<'_>) -> bool {
        while deposit.paid < target {
            let Some(_unit) = credit.pay() else {
                return false;
            };
            deposit.paid += 1;
        }
        true
    }

    /// Count the identity's queued claims a paid decision reads (test
    /// instrumentation only: the probe already paid one unit per claim).
    fn visit_claims(&self, shape: &StagedShape) {
        if let Some(claimants) = self.adapter.claims.get(&shape.identity) {
            for _ in claimants.values().flatten() {
                self.visit();
            }
        }
    }

    /// Whether a live key outside `stuck` claims this shape (a scoped
    /// wipe keeps such entries).
    pub(in crate::semantics_objects) fn healthy_claimant(
        &self,
        shape: &StagedShape,
        stuck: &[JournalDomainKey],
        _paid: ClaimsPaid,
    ) -> bool {
        self.visit_claims(shape);
        self.adapter.has_healthy_claimant(shape, stuck)
    }

    /// Whether every queued claim on this identity reports a return that
    /// leaves no lifecycle effect (the claim half of
    /// [`JournalAdapter::abandonment_disposes_here`]).
    pub(in crate::semantics_objects) fn queued_returns_neutral(
        &self,
        shape: &StagedShape,
        function: u32,
        _paid: ClaimsPaid,
    ) -> bool {
        self.visit_claims(shape);
        self.adapter
            .queued_returns_neutral(&shape.identity, function)
    }

    /// The live claimants naming `shape` within one completed basis.
    pub(in crate::semantics_objects) fn claimants_live_in(
        &self,
        shape: &StagedShape,
        live: &BTreeSet<JournalDomainKey>,
        _paid: ClaimsPaid,
    ) -> Vec<JournalDomainKey> {
        self.visit_claims(shape);
        self.adapter
            .claimants_naming(shape)
            .map(|claimants| {
                claimants
                    .iter()
                    .filter(|(key, ordinals)| !ordinals.is_empty() && live.contains(key))
                    .map(|(key, _)| *key)
                    .collect()
            })
            .unwrap_or_default()
    }

    /// Whether a staged shape attributes to `key` against the image's
    /// live set as it stands (stop) or a frozen live set (doom),
    /// whose per-claimant lookup is indexed: the probe for a frozen-set
    /// decision is priced without the image's key list.
    pub(in crate::semantics_objects) fn attributes_to(
        &self,
        key: JournalDomainKey,
        shape: &StagedShape,
        frozen_live: Option<&BTreeSet<JournalDomainKey>>,
        _paid: ClaimsPaid,
    ) -> bool {
        if shape.identity.image != key.image() {
            return false;
        }
        self.visit_claims(shape);
        let attribution = match frozen_live {
            Some(live) => self
                .adapter
                .attribute_call_by(key, shape, |claimant| live.contains(claimant)),
            None => {
                let live = self.adapter.live_keys_for_image(key.image());
                self.adapter.attribute_call(key, shape, &live)
            }
        };
        attribution == CallAttribution::Mine
    }

    // ---- Classification ------------------------------------------------

    /// Classify the open entry after `after` (one unit): its native key
    /// and class, or `None` when the map exhausts.
    pub(in crate::semantics_objects) fn classify_open(
        &self,
        after: Option<JournalNativeKey>,
        recovery: &ScopedRecovery,
        _paid: Paid,
    ) -> Option<(JournalNativeKey, Classified)> {
        let (native, entry) = super::next_after(&self.adapter.open, after)?;
        self.visit();
        if recovery.stream {
            return Some((native, Classified::Wipe));
        }
        let barrier = entry.converted_ticket.is_none()
            && entry.begin_ordinal <= recovery.upper
            && !self.adapter.image_keys.contains_key(&entry.image);
        if barrier {
            return Some((native, Classified::Wipe));
        }
        let class = match entry.converted_for {
            Some(converted) if recovery.scope.domains.contains(&converted) => Classified::Wipe,
            Some(_) => Classified::Keep,
            None if recovery.scope.images.contains(&entry.image) => {
                Classified::Check(shape_of_entry(entry))
            }
            None => Classified::Keep,
        };
        Some((native, class))
    }

    /// Classify the refused begin at `index` (one unit), or `None` past
    /// the end.
    pub(in crate::semantics_objects) fn classify_refused(
        &self,
        index: usize,
        recovery: &ScopedRecovery,
        _paid: Paid,
    ) -> Option<(CallIdentity, Classified)> {
        let refused = self.adapter.refused.get(index)?;
        self.visit();
        let identity = refused.identity();
        if recovery.stream {
            return Some((identity, Classified::Wipe));
        }
        let barrier =
            refused.cut <= recovery.upper && !self.adapter.image_keys.contains_key(&refused.image);
        let class = if barrier {
            Classified::Wipe
        } else if recovery.scope.images.contains(&refused.image) {
            Classified::Check(refused.shape())
        } else {
            Classified::Keep
        };
        Some((identity, class))
    }

    /// The refused-begin count (O(1) metadata).
    pub(in crate::semantics_objects) fn refused_len(&self) -> usize {
        self.adapter.refused.len()
    }

    // ---- Preservation --------------------------------------------------

    /// Read one wiped open entry for preservation (one unit).
    pub(in crate::semantics_objects) fn preserve_read(
        &self,
        native: JournalNativeKey,
        _paid: Paid,
    ) -> PreserveRead {
        let Some(entry) = self.adapter.open.get(&native) else {
            return PreserveRead::Settled;
        };
        self.visit();
        let Some(staged) = entry.abandon.as_ref().filter(|staged| {
            abandon_disposition(staged.abandon.reason())
                == Some(AbandonDisposition::UnboundedInvalidation)
        }) else {
            return PreserveRead::Settled;
        };
        let shape = shape_of_entry(entry);
        let capable = !JournalAdapter::abandon_proves_frame_dead(staged.abandon.reason());
        if abandonment_disposes_per_call(entry.function) && !entry.negative_return {
            return PreserveRead::Check {
                shape,
                function: entry.function,
                image: entry.image,
                capable,
            };
        }
        PreserveRead::Unbounded {
            image: entry.image,
            shape,
            capable,
        }
    }

    /// First touch of an image's basis (one unit): whether the image is
    /// keyed and its key-list length, frozen for the basis.
    pub(in crate::semantics_objects) fn image_key_extent(
        &self,
        image: (u64, u64),
        _paid: Paid,
    ) -> (bool, usize) {
        self.visit();
        let listed = self.adapter.image_keys.get(&image);
        (listed.is_some(), listed.map_or(0, Vec::len))
    }

    /// The image's key at `index` and whether it is live (one unit).
    pub(in crate::semantics_objects) fn image_key_at(
        &self,
        image: (u64, u64),
        index: usize,
        _paid: Paid,
    ) -> Option<(JournalDomainKey, bool)> {
        self.visit();
        let key = *self.adapter.image_keys.get(&image)?.get(index)?;
        Some((key, self.adapter.key_is_live(key)))
    }

    /// Mark one decided image taint (one unit).
    pub(in crate::semantics_objects) fn taint_unclaimed_image(
        &mut self,
        image: (u64, u64),
        _paid: Paid,
    ) {
        self.visit();
        // Unaccounted abandonments evidence unknown continuing
        // effects: the taint never lifts, even once fenced.
        self.adapter
            .taint_image_mark(image, TaintCause::UnclaimedInvalidation, None);
    }

    /// Refuse one decided abandoned key (one unit) unless its image's
    /// taint blocks past the void's fence: the refusal publishes now,
    /// and its held model domain's retirement is returned for the
    /// shared budget. A fenced quarantine never excuses the doom (the
    /// taint may lift while the negative evidence must stand).
    /// `capable` tells whether any grounding abandonment leaves a
    /// capable frame (no fresh incarnation ever mints past those).
    pub(in crate::semantics_objects) fn doom_abandoned_key(
        &mut self,
        key: JournalDomainKey,
        fence: u64,
        capable: bool,
        _paid: Paid,
    ) -> Option<DomainRetirement> {
        self.visit();
        if self.adapter.image_taint_blocks(key.image(), fence) {
            return None;
        }
        self.refuse_key(key, fence, capable)
    }

    /// Refuse one key (publishing first) and return its held model
    /// domain's abandonment. `died_at` evidences the refusal (the
    /// void's upper for preserved dooms, the consumption point
    /// otherwise) and `capable` whether a capable frame grounds it,
    /// for incarnation fencing.
    fn refuse_key(
        &mut self,
        key: JournalDomainKey,
        died_at: u64,
        capable: bool,
    ) -> Option<DomainRetirement> {
        let lived = self.adapter.key_is_live(key);
        let (era, registered) = {
            let state = self.adapter.keys.get_mut(&key).expect("refused key");
            state.refused = true;
            (state.era, state.model_registered)
        };
        self.adapter.note_refused_mark(key, died_at, capable);
        self.adapter.claims_prune_dirty |= lived;
        registered.then(|| {
            DomainRetirement::abandon(ObjectDomain::sealed(&JournalDomainProof { key, era }))
        })
    }

    /// Whether taint-overflow key marks are still owed (O(1)).
    pub(in crate::semantics_objects) fn overflow_owed(&self) -> bool {
        !self.adapter.taint_overflow_pending.is_empty()
    }

    /// One owed taint-overflow step (one unit): mark one key, or close
    /// one finished image, or wrap the cursor.
    pub(in crate::semantics_objects) fn overflow_step(&mut self, paid: Paid) {
        self.visit();
        self.adapter.taint_overflow_step(paid);
    }

    // ---- Drains, fences, wipes -----------------------------------------

    /// Visit the open entry after `after` (one unit), dropping it when
    /// its image is a decided taint: absence recorded, census and
    /// custody released, void-wiped. `None` when the map exhausts.
    pub(in crate::semantics_objects) fn taint_drain_open(
        &mut self,
        after: Option<JournalNativeKey>,
        taint: &BTreeSet<(u64, u64)>,
        _paid: Paid,
    ) -> Option<JournalNativeKey> {
        let (native, entry) = super::next_after(&self.adapter.open, after)?;
        self.visit();
        if taint.contains(&entry.image) {
            let (image, function, begin_ordinal) =
                (entry.image, entry.function, entry.begin_ordinal);
            self.adapter.note_derived_absence(image, native, function);
            self.drop_open(native);
            self.adapter.void_wiped.insert(native, begin_ordinal);
        }
        Some(native)
    }

    /// Remove one open entry, releasing its census membership and
    /// custody exactly once.
    fn drop_open(&mut self, native: JournalNativeKey) -> Option<super::OpenEntry> {
        let removed = self.adapter.take_open(native)?;
        if removed.converted_ticket.is_none() {
            self.adapter.retained_member_dec(
                identity_of_begin(&removed.begin),
                RetainedMember::Open(native),
            );
        }
        self.adapter.ledger.release_h8open(removed.begin_ordinal);
        Some(removed)
    }

    /// Compact the refused begin at `read` toward `write` (one unit):
    /// dropped members leave the census, kept ones shift down.
    pub(in crate::semantics_objects) fn compact_refused(
        &mut self,
        read: usize,
        write: &mut usize,
        rule: RefusedDrop<'_>,
        _paid: Paid,
    ) {
        self.visit();
        let refused = self.adapter.refused[read];
        let dropped = match rule {
            RefusedDrop::Images(images) => images.contains(&refused.image),
            RefusedDrop::Identities(identities) => identities.contains(&refused.identity()),
            RefusedDrop::Tainted => self.adapter.is_tainted(refused.image),
            RefusedDrop::This(drop) => drop,
        };
        if dropped {
            self.adapter.retained_refused_dec(&refused);
        } else {
            if *write != read {
                self.adapter.refused[*write] = refused;
            }
            *write += 1;
        }
    }

    /// Drop the compacted tail (a bulk free).
    pub(in crate::semantics_objects) fn truncate_refused(&mut self, write: usize) {
        self.adapter.refused.truncate(write);
    }

    /// Drop every claim and the retained census (bulk frees, stream
    /// recoveries only).
    pub(in crate::semantics_objects) fn clear_claims_and_census(&mut self) {
        self.adapter.claims.clear();
        self.adapter.claim_counts = 0;
        self.adapter.retained_counts.clear();
    }

    /// Fence one stuck domain key (one unit) at the recovery's upper,
    /// returning its held domain's voided-interval retirement.
    pub(in crate::semantics_objects) fn fence_scoped_key(
        &mut self,
        key: JournalDomainKey,
        upper: u64,
        _paid: Paid,
    ) -> Option<DomainRetirement> {
        self.visit();
        let state = self.adapter.keys.get_mut(&key)?;
        state.void_fence = state.void_fence.max(upper);
        if !state.model_registered {
            return None;
        }
        let domain = ObjectDomain::sealed(&JournalDomainProof {
            key,
            era: state.era,
        });
        Some(DomainRetirement::void(
            domain,
            RefCut::sealed(ConsumptionOrdinal(upper)),
        ))
    }

    /// Fence (or, for an unlocalized refusal, refuse) the key after
    /// `after` (one unit): bootstrap pins clear, its scope domain and
    /// held-domain retirement are returned. `None` when the table
    /// exhausts.
    pub(in crate::semantics_objects) fn fence_all_key(
        &mut self,
        after: Option<JournalDomainKey>,
        mode: RecoveryMode,
        upper: u64,
        _paid: Paid,
    ) -> Option<FenceAllVisit> {
        let key = super::next_after(&self.adapter.keys, after).map(|(key, _)| key)?;
        self.visit();
        if mode == RecoveryMode::RefuseAll {
            let lived = self.adapter.key_is_live(key);
            let state = self.adapter.keys.get_mut(&key).expect("refused key");
            state.bootstraps.clear();
            let scope = JournalDomainProof {
                key,
                era: state.era,
            }
            .domain();
            let mut retire = None;
            if !state.refused {
                state.refused = true;
                if state.model_registered {
                    retire = Some(DomainRetirement::abandon(scope));
                }
                self.adapter.claims_prune_dirty |= lived;
            }
            // Unlocalized disposal evidences stream corruption:
            // unknown effects from live frames never mint past it.
            self.adapter
                .note_refused_mark(key, self.adapter.consumed_through, true);
            return Some(FenceAllVisit {
                key,
                scope,
                retire,
                count_unregistered: false,
            });
        }
        let state = self.adapter.keys.get_mut(&key).expect("fenced key");
        state.void_fence = state.void_fence.max(upper);
        let pending_unregistered = state.bootstraps.is_empty() && !state.model_registered;
        state.bootstraps.clear();
        let scope = JournalDomainProof {
            key,
            era: state.era,
        }
        .domain();
        let retire = state
            .model_registered
            .then(|| DomainRetirement::void(scope, RefCut::sealed(ConsumptionOrdinal(upper))));
        Some(FenceAllVisit {
            key,
            scope,
            retire,
            count_unregistered: pending_unregistered
                && mode
                    == (RecoveryMode::AuditVoid {
                        count_unregistered: true,
                    }),
        })
    }

    /// Wipe one classified open entry (one unit). An unterminated
    /// effect-free abandoned entry whose excuse depends on its queued
    /// claims is returned unwiped for a paid decision.
    pub(in crate::semantics_objects) fn wipe_open(
        &mut self,
        native: JournalNativeKey,
        _paid: Paid,
    ) -> WipeOpen {
        let Some(entry) = self.adapter.open.get(&native) else {
            return WipeOpen::Done;
        };
        self.visit();
        let unterminated =
            entry.end.is_none() && !entry.begin.no_end() && entry.corroborated_return.is_none();
        let unbounded = entry.abandon.is_some_and(|staged| {
            abandon_disposition(staged.abandon.reason())
                == Some(AbandonDisposition::UnboundedInvalidation)
        });
        if unterminated
            && unbounded
            && abandonment_disposes_per_call(entry.function)
            && !entry.negative_return
        {
            return WipeOpen::Check {
                shape: shape_of_entry(entry),
                function: entry.function,
            };
        }
        let excused = unterminated
            && entry.abandon.is_none()
            && disposes_unclaimable_original(entry.function);
        self.apply_wipe_open(native, excused);
        WipeOpen::Done
    }

    /// Wipe one open entry whose excuse was decided (one unit).
    pub(in crate::semantics_objects) fn wipe_open_decided(
        &mut self,
        native: JournalNativeKey,
        excused: bool,
        _paid: Paid,
    ) {
        self.visit();
        self.apply_wipe_open(native, excused);
    }

    fn apply_wipe_open(&mut self, native: JournalNativeKey, excused: bool) {
        let Some(entry) = self.drop_open(native) else {
            return;
        };
        // Effect-free wiped BEGINs excuse their late terminals at ingest
        // (their void-wipe evidence routes them to plain S1); anything
        // else taints fail-closed there.
        if excused {
            self.adapter
                .note_derived_absence(entry.image, native, entry.function);
        }
        self.adapter.void_wiped.insert(native, entry.begin_ordinal);
    }

    // ---- Stop and scope ------------------------------------------------

    /// The open entry after `after` and the key it converted for (one
    /// unit), or `None` when the map exhausts.
    pub(in crate::semantics_objects) fn open_converted_for(
        &self,
        after: Option<JournalNativeKey>,
        _paid: Paid,
    ) -> Option<(JournalNativeKey, Option<JournalDomainKey>)> {
        let (native, entry) = super::next_after(&self.adapter.open, after)?;
        self.visit();
        Some((native, entry.converted_for))
    }

    /// The refused begin at `index`: its image and shape (one unit).
    pub(in crate::semantics_objects) fn refused_at(
        &self,
        index: usize,
        _paid: Paid,
    ) -> Option<((u64, u64), StagedShape)> {
        let refused = self.adapter.refused.get(index)?;
        self.visit();
        Some((refused.image, refused.shape()))
    }

    /// The key after `after` and its scope domain (one unit), or `None`
    /// when the table exhausts.
    pub(in crate::semantics_objects) fn key_after(
        &self,
        after: Option<JournalDomainKey>,
        _paid: Paid,
    ) -> Option<(JournalDomainKey, ObjectDomain)> {
        let (key, state) = super::next_after(&self.adapter.keys, after)?;
        self.visit();
        Some((
            key,
            JournalDomainProof {
                key,
                era: state.era,
            }
            .domain(),
        ))
    }

    /// Refuse one stopped key (one unit) and return its domain's
    /// abandonment (a stop abandons held and unheld domains alike: the
    /// model names the unheld one's gap).
    pub(in crate::semantics_objects) fn stop_refuse_key(
        &mut self,
        key: JournalDomainKey,
        _paid: Paid,
    ) -> DomainRetirement {
        self.visit();
        let era = self.adapter.keys[&key].era;
        let lived = self.adapter.key_is_live(key);
        let died_at = self.adapter.consumed_through;
        self.adapter
            .keys
            .get_mut(&key)
            .expect("stopped key")
            .refused = true;
        self.adapter.note_refused_mark(key, died_at, false);
        self.adapter.claims_prune_dirty |= lived;
        DomainRetirement::abandon(ObjectDomain::sealed(&JournalDomainProof { key, era }))
    }

    /// Drop staged custody whole (bulk frees; one unit, as before).
    pub(in crate::semantics_objects) fn stop_clear(&mut self, _paid: Paid) {
        self.adapter.clear_open();
        self.adapter.ledger.release_all_h8open();
        self.adapter.refused.clear();
        self.adapter.retained_counts.clear();
        self.adapter.retained_census_drift = false;
    }

    /// Close one finished recovery (O(1) bookkeeping): a stream break
    /// invalidates and records its void cut; a drift reset follows every
    /// census-touching mode.
    pub(in crate::semantics_objects) fn finish(
        &mut self,
        mode: RecoveryMode,
        stream: bool,
        upper: u64,
    ) {
        match mode {
            RecoveryMode::Break => {
                self.adapter.retained_census_drift = false;
                if stream {
                    self.adapter.invalidated = true;
                    self.adapter.voided_through = self.adapter.voided_through.max(upper);
                }
            }
            RecoveryMode::AuditVoid { .. } | RecoveryMode::RefuseAll => {
                self.adapter.retained_census_drift = false;
            }
            RecoveryMode::Stop
            | RecoveryMode::ScopeOnly
            | RecoveryMode::Doom
            | RecoveryMode::LocalRaw
            | RecoveryMode::S1Only => {}
        }
    }

    // ---- Seal-time doom ------------------------------------------------

    /// Visit the open entry after `after` for the doomed key (one unit):
    /// skip other images, drop entries already converted for the key,
    /// and return unconverted entries of its image for a paid
    /// attribution.
    pub(in crate::semantics_objects) fn doom_open(
        &mut self,
        after: Option<JournalNativeKey>,
        key: JournalDomainKey,
        _paid: Paid,
    ) -> Option<(JournalNativeKey, DoomOpen)> {
        let (native, entry) = super::next_after(&self.adapter.open, after)?;
        self.visit();
        if entry.image != key.image() {
            return Some((native, DoomOpen::Skip));
        }
        if entry.converted_for == Some(key) {
            self.drop_open(native);
            return Some((native, DoomOpen::Dropped));
        }
        if entry.converted_ticket.is_some() {
            return Some((native, DoomOpen::Skip));
        }
        Some((native, DoomOpen::Check(shape_of_entry(entry))))
    }

    /// Visit the refused begin at `read` for the doomed key (one unit):
    /// another image's member is kept (compacted toward `write`); one of
    /// the key's image is returned for a paid attribution.
    pub(in crate::semantics_objects) fn doom_refused_visit(
        &mut self,
        read: usize,
        write: &mut usize,
        key: JournalDomainKey,
        _paid: Paid,
    ) -> Option<StagedShape> {
        self.visit();
        let refused = self.adapter.refused[read];
        if refused.image == key.image() {
            return Some(refused.shape());
        }
        if *write != read {
            self.adapter.refused[*write] = refused;
        }
        *write += 1;
        None
    }

    /// Drop one open entry the paid attribution assigned to the doomed
    /// key (one unit).
    pub(in crate::semantics_objects) fn drop_open_decided(
        &mut self,
        native: JournalNativeKey,
        _paid: Paid,
    ) {
        self.visit();
        self.drop_open(native);
    }

    // ---- Localized raw refusal -----------------------------------------

    /// Refuse the key after `after` when its image is tainted (one
    /// unit): its scope domain when affected, and its held domain's
    /// abandonment when it newly refuses.
    pub(in crate::semantics_objects) fn raw_key(
        &mut self,
        after: Option<JournalDomainKey>,
        _paid: Paid,
    ) -> Option<(
        JournalDomainKey,
        Option<ObjectDomain>,
        Option<DomainRetirement>,
    )> {
        let key = super::next_after(&self.adapter.keys, after).map(|(key, _)| key)?;
        self.visit();
        if !self.adapter.is_tainted(key.image()) {
            return Some((key, None, None));
        }
        let state = &self.adapter.keys[&key];
        let scope = JournalDomainProof {
            key,
            era: state.era,
        }
        .domain();
        if state.refused {
            return Some((key, Some(scope), None));
        }
        // Disposed raw content is unknown effects from a live stream:
        // the refusal never mints past it.
        let died_at = self.adapter.consumed_through;
        Some((key, Some(scope), self.refuse_key(key, died_at, true)))
    }

    /// Drop the open entry after `after` when its image is tainted (one
    /// unit).
    pub(in crate::semantics_objects) fn raw_open(
        &mut self,
        after: Option<JournalNativeKey>,
        _paid: Paid,
    ) -> Option<JournalNativeKey> {
        let (native, entry) = super::next_after(&self.adapter.open, after)?;
        self.visit();
        if self.adapter.is_tainted(entry.image) {
            self.drop_open(native);
        }
        Some(native)
    }

    /// Drop tainted images' claims: with no `current` identity, visit the
    /// identity after `after` (one unit) and enter it when its image is
    /// tainted; inside an identity, drop one claimant queue per unit.
    pub(in crate::semantics_objects) fn raw_claims_step(
        &mut self,
        after: Option<CallIdentity>,
        current: Option<CallIdentity>,
        credit: &mut Credit<'_>,
    ) -> ClaimsStep {
        let Some(identity) = current else {
            let Some(identity) = super::next_after(&self.adapter.claims, after).map(|(id, _)| id)
            else {
                return ClaimsStep::Done;
            };
            let Some(_unit) = credit.pay() else {
                return ClaimsStep::Yield;
            };
            self.visit();
            return if self.adapter.is_tainted(identity.image) {
                ClaimsStep::Enter(identity)
            } else {
                ClaimsStep::Visited(identity)
            };
        };
        let first = self
            .adapter
            .claims
            .get(&identity)
            .and_then(|claimants| claimants.keys().next().copied());
        let Some(claimant) = first else {
            // Every queue dropped: the emptied identity leaves (O(1)).
            self.adapter.claims.remove(&identity);
            return ClaimsStep::Visited(identity);
        };
        let Some(_unit) = credit.pay() else {
            return ClaimsStep::Yield;
        };
        self.visit();
        let queue = self
            .adapter
            .claims
            .get_mut(&identity)
            .and_then(|claimants| claimants.remove(&claimant))
            .expect("visited claimant");
        self.adapter.claim_counts -= queue.len();
        ClaimsStep::Removed
    }

    // ---- S1-only originals ---------------------------------------------

    /// The S1-only subject after `after` in the retained index (one
    /// unit): its retained domain, or a conservative image taint when its
    /// key is gone.
    pub(in crate::semantics_objects) fn s1_subject(
        &mut self,
        after: Option<JournalNativeKey>,
        _paid: Paid,
    ) -> Option<(JournalNativeKey, S1Subject)> {
        let native = super::next_member_after(&self.adapter.s1only_open, after)?;
        self.visit();
        let Some(key) = self
            .adapter
            .open
            .get(&native)
            .and_then(|entry| entry.s1only_subject)
        else {
            return Some((native, S1Subject::None));
        };
        match self.adapter.keys.get(&key) {
            Some(state) => Some((
                native,
                S1Subject::Domain(
                    JournalDomainProof {
                        key,
                        era: state.era,
                    }
                    .domain(),
                ),
            )),
            None => {
                self.adapter.promote_image_taint(key.image());
                Some((native, S1Subject::Fallback))
            }
        }
    }

    /// The key after `after` and, when its image is tainted, its domain
    /// (one unit).
    pub(in crate::semantics_objects) fn tainted_key_domain(
        &self,
        after: Option<JournalDomainKey>,
        _paid: Paid,
    ) -> Option<(JournalDomainKey, Option<ObjectDomain>)> {
        let (key, state) = super::next_after(&self.adapter.keys, after)?;
        self.visit();
        let domain = self.adapter.is_tainted(key.image()).then(|| {
            JournalDomainProof {
                key,
                era: state.era,
            }
            .domain()
        });
        Some((key, domain))
    }

    /// Refuse the key after `after` when its domain is in the frozen
    /// union (one unit), returning its held domain's abandonment when it
    /// newly refuses.
    pub(in crate::semantics_objects) fn s1_refuse_key(
        &mut self,
        after: Option<JournalDomainKey>,
        union: &[ObjectDomain],
        _paid: Paid,
    ) -> Option<(JournalDomainKey, Option<DomainRetirement>)> {
        let (key, state) = super::next_after(&self.adapter.keys, after)?;
        self.visit();
        let domain = JournalDomainProof {
            key,
            era: state.era,
        }
        .domain();
        if union.binary_search(&domain).is_err() {
            return Some((key, None));
        }
        if state.refused {
            return Some((key, None));
        }
        // An S1-only bulk refusal marks history unproven, never
        // invalid: fresh proof past a void re-proves it.
        let died_at = self.adapter.consumed_through;
        Some((key, self.refuse_key(key, died_at, false)))
    }

    /// The S1-only subject after `after` (one unit): its shape when it
    /// stands for disposal. Only a subject whose key this negative refused
    /// (or whose key is gone, its image tainted) disposes; a subject
    /// retained after the union froze waits for its own negative.
    pub(in crate::semantics_objects) fn s1_dispose_read(
        &self,
        after: Option<JournalNativeKey>,
        _paid: Paid,
    ) -> Option<(JournalNativeKey, Option<StagedShape>)> {
        let native = super::next_member_after(&self.adapter.s1only_open, after)?;
        self.visit();
        let shape = self
            .adapter
            .open
            .get(&native)
            .filter(|entry| {
                entry.s1only_subject.is_some_and(|key| {
                    self.adapter
                        .keys
                        .get(&key)
                        .is_none_or(|state| state.refused)
                })
            })
            .map(shape_of_entry);
        Some((native, shape))
    }

    /// Dispose one exact S1-only original with its own claim (a paid
    /// claim decision), or, when that claim set can never fit one
    /// credit, without consuming it (one paid unit; its key is refused,
    /// so the claim can never convert).
    pub(in crate::semantics_objects) fn s1_dispose(
        &mut self,
        native: JournalNativeKey,
        paid: S1DisposePaid,
    ) {
        self.visit();
        let with_claim = match paid {
            S1DisposePaid::Claims(_claims) => true,
            S1DisposePaid::Plain(_unit) => false,
        };
        self.adapter.dispose_s1only_original(native, with_claim);
    }
}
