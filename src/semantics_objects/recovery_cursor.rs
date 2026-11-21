//! SPDX-License-Identifier: GPL-3.0-or-later
//! SPDX-FileCopyrightText: 2026 Denis Mingulov <denis@mingulov.com>
//! The bounded recovery cursors: sliced voids, deferred adapter
//! rejections and model domain retirements.
//!
//! This module holds no journal adapter and no model: it drives them only
//! through [`JournalLeaves`] and [`ModelLeaves`], whose fields are private
//! to their owning modules and whose leaf accessors each consume a
//! [`Paid`](super::credit::Paid) unit (or a probe-minted claim decision). Every phase here is a
//! resumable cursor: it debits before each read, yields with its resume
//! position when the slice is spent, and persists a read that awaits its
//! claim decision (and a decided verdict that awaits its unit), so one
//! slice never needs more than one probe's worth of credit to progress.

use std::collections::{BTreeMap, BTreeSet};

use super::credit::Credit;
use super::journal::leaves::{
    ClaimProbe, ClaimsStep, Classified, DoomOpen, JournalLeaves, PreserveRead, RefusedDrop,
    S1DisposePaid, S1Subject, WipeOpen,
};
use super::journal::{
    CallIdentity, CheckedRead, JournalDomainKey, JournalNativeKey, PreservedBasis, ScopedRecovery,
    ScopedRecoveryPhase, StagingLedger, StopVisit,
};
use super::state::{
    DetachedAfter, DomainRetirement, ModelLeaves, PendingAfter, RetireKind, RetireStage,
};
use super::{ObjectDomain, ObjectEffects};

/// Advance one domain retirement by at most the credit's units, one
/// model row per unit. Stage changes that read no row are free. Returns
/// true when it completed.
pub(in crate::semantics_objects) fn retire_step(
    model: &mut ModelLeaves<'_>,
    ledger: &mut StagingLedger,
    retirement: &mut DomainRetirement,
    effects: &mut ObjectEffects,
    credit: &mut Credit<'_>,
) -> bool {
    loop {
        match retirement.stage {
            RetireStage::Done => return true,
            RetireStage::DeferredPending(_) | RetireStage::DeferredDetached(_)
                if !model.deferred_owed(retirement) =>
            {
                retirement.stage = RetireStage::Bindings;
                continue;
            }
            RetireStage::Releases if !model.releases_owed() => {
                retirement.stage = RetireStage::Finish;
                continue;
            }
            _ => {}
        }
        let Some(paid) = credit.pay() else {
            return false;
        };
        retirement.stage = match retirement.stage {
            RetireStage::Start => {
                if model.start(retirement, effects, paid) {
                    RetireStage::Views(None)
                } else {
                    RetireStage::Done
                }
            }
            RetireStage::Views(after) => {
                match model.retire_next_view(retirement, after, effects, paid) {
                    Some(key) => RetireStage::Views(Some(key)),
                    None => RetireStage::Sessions {
                        after: None,
                        clearing: None,
                    },
                }
            }
            RetireStage::Sessions {
                after,
                clearing: None,
            } => match model.next_live_session(retirement.domain, after, paid) {
                Some(session) => RetireStage::Sessions {
                    after,
                    clearing: Some(session),
                },
                None => RetireStage::DeferredPending(PendingAfter::default()),
            },
            RetireStage::Sessions {
                after,
                clearing: Some((handle, session)),
            } => {
                if model.clear_or_end_session(retirement, session, effects, paid) {
                    RetireStage::Sessions {
                        after: Some(handle),
                        clearing: None,
                    }
                } else {
                    RetireStage::Sessions {
                        after,
                        clearing: Some((handle, session)),
                    }
                }
            }
            RetireStage::DeferredPending(after) => {
                match model.deferred_pending_step(retirement, after, paid) {
                    Some(next) => RetireStage::DeferredPending(next),
                    None => RetireStage::DeferredDetached(DetachedAfter::default()),
                }
            }
            RetireStage::DeferredDetached(after) => {
                match model.deferred_detached_step(retirement, after, paid) {
                    Some(next) => RetireStage::DeferredDetached(next),
                    None => RetireStage::Bindings,
                }
            }
            RetireStage::Bindings => {
                if model.clear_next_binding(retirement.domain, paid) {
                    RetireStage::Bindings
                } else {
                    match retirement.kind {
                        RetireKind::Abandon => RetireStage::FenceCalls(None),
                        RetireKind::Void(_) => RetireStage::Releases,
                    }
                }
            }
            RetireStage::FenceCalls(after) => {
                match model.fence_next_call(retirement.domain, after, paid) {
                    Some(key) => RetireStage::FenceCalls(Some(key)),
                    None => RetireStage::RemoveCalls(None),
                }
            }
            RetireStage::RemoveCalls(after) => {
                match model.remove_next_call(retirement.domain, after, ledger, paid) {
                    Some(key) => RetireStage::RemoveCalls(Some(key)),
                    None => RetireStage::Releases,
                }
            }
            RetireStage::Releases => {
                model.release_next_deferred(ledger, paid);
                RetireStage::Releases
            }
            RetireStage::Finish => {
                model.finish(retirement, effects, ledger, paid);
                RetireStage::Done
            }
            RetireStage::Done => RetireStage::Done,
        };
    }
}

/// Drive the recovery's standing model retirement, if any, under the
/// slice. Returns true when none stands (or it just completed).
fn drive_retirement(
    journal: &mut JournalLeaves<'_>,
    model: &mut ModelLeaves<'_>,
    recovery: &mut ScopedRecovery,
    credit: &mut Credit<'_>,
) -> bool {
    let Some(retirement) = recovery.model_retire.as_mut() else {
        return true;
    };
    let done = retire_step(
        model,
        journal.ledger(),
        retirement,
        &mut recovery.effects,
        credit,
    );
    if done {
        recovery.model_retire = None;
    }
    done
}

/// Run one slice of a recovery. Returns true when the recovery completed.
pub(in crate::semantics_objects) fn run_slice(
    journal: &mut JournalLeaves<'_>,
    model: &mut ModelLeaves<'_>,
    recovery: &mut ScopedRecovery,
    credit: &mut Credit<'_>,
) -> bool {
    if credit.left() == 0 {
        return false;
    }
    loop {
        let finished = match recovery.phase {
            ScopedRecoveryPhase::ClassifyOpen { after } => {
                classify_open(journal, recovery, after, credit)
            }
            ScopedRecoveryPhase::ClassifyRefused { index } => {
                classify_refused(journal, recovery, index, credit)
            }
            ScopedRecoveryPhase::Preserve { after } => preserve(journal, recovery, after, credit),
            ScopedRecoveryPhase::PreserveTaint { after } => {
                preserve_taint(journal, recovery, after, credit)
            }
            ScopedRecoveryPhase::PreserveDoom { after } => {
                preserve_doom(journal, model, recovery, after, credit)
            }
            ScopedRecoveryPhase::OverflowDrain => overflow_drain(journal, recovery, credit),
            ScopedRecoveryPhase::TaintDrainOpen { after } => {
                taint_drain_open(journal, recovery, after, credit)
            }
            ScopedRecoveryPhase::TaintDrainRefused { read, write } => {
                taint_drain_refused(journal, recovery, read, write, credit)
            }
            ScopedRecoveryPhase::Fence { index } => fence(journal, model, recovery, index, credit),
            ScopedRecoveryPhase::FenceAll { after } => {
                fence_all(journal, model, recovery, after, credit)
            }
            ScopedRecoveryPhase::WipeOpen { after } => wipe_open(journal, recovery, after, credit),
            ScopedRecoveryPhase::WipeRefused { read, write } => {
                wipe_refused(journal, recovery, read, write, credit)
            }
            ScopedRecoveryPhase::StopOpen { after } => stop_open(journal, recovery, after, credit),
            ScopedRecoveryPhase::StopRefused { index } => {
                stop_refused(journal, recovery, index, credit)
            }
            ScopedRecoveryPhase::StopKeys { after, visiting } => {
                stop_keys(journal, model, recovery, after, visiting, credit)
            }
            ScopedRecoveryPhase::StopClear => stop_clear(journal, recovery, credit),
            ScopedRecoveryPhase::ScopeAll { after } => scope_all(journal, recovery, after, credit),
            ScopedRecoveryPhase::DoomOpen { after } => doom_open(journal, recovery, after, credit),
            ScopedRecoveryPhase::DoomRefused { read, write } => {
                doom_refused(journal, recovery, read, write, credit)
            }
            ScopedRecoveryPhase::RawKeys { after } => {
                raw_keys(journal, model, recovery, after, credit)
            }
            ScopedRecoveryPhase::RawOpen { after } => raw_open(journal, recovery, after, credit),
            ScopedRecoveryPhase::RawRefused { read, write } => {
                raw_refused(journal, recovery, read, write, credit)
            }
            ScopedRecoveryPhase::RawClaims { after, current } => {
                raw_claims(journal, recovery, after, current, credit)
            }
            ScopedRecoveryPhase::S1Subjects { after } => {
                s1_subjects(journal, recovery, after, credit)
            }
            ScopedRecoveryPhase::S1Tainted { after } => {
                s1_tainted(journal, recovery, after, credit)
            }
            ScopedRecoveryPhase::S1Refuse { after } => {
                s1_refuse(journal, model, recovery, after, credit)
            }
            ScopedRecoveryPhase::S1Dispose { after } => {
                s1_dispose(journal, recovery, after, credit)
            }
            ScopedRecoveryPhase::Retire => {
                if drive_retirement(journal, model, recovery, credit) {
                    recovery.phase = ScopedRecoveryPhase::Done;
                    true
                } else {
                    false
                }
            }
            ScopedRecoveryPhase::Done => {
                journal.finish(recovery.mode, recovery.stream, recovery.upper);
                return true;
            }
        };
        if !finished || credit.left() == 0 {
            return false;
        }
    }
}

fn classify_open(
    journal: &mut JournalLeaves<'_>,
    recovery: &mut ScopedRecovery,
    mut after: Option<JournalNativeKey>,
    credit: &mut Credit<'_>,
) -> bool {
    loop {
        let (native, class) = match recovery.check.take() {
            Some(read) => (
                read.native.expect("checked open"),
                Classified::Check(read.shape),
            ),
            None => {
                let Some(paid) = credit.pay() else {
                    recovery.phase = ScopedRecoveryPhase::ClassifyOpen { after };
                    return false;
                };
                let Some(read) = journal.classify_open(after, recovery, paid) else {
                    recovery.phase = ScopedRecoveryPhase::ClassifyRefused { index: 0 };
                    return true;
                };
                read
            }
        };
        let wipe = match class {
            Classified::Keep => false,
            Classified::Wipe => true,
            // A claim set too large to decide wipes (fail closed: the
            // named loss, never a stuck recovery).
            Classified::Check(shape) => {
                match journal.claim_probe(&shape, None, &mut recovery.deposit, credit) {
                    ClaimProbe::Fits(paid) => {
                        !journal.healthy_claimant(&shape, &recovery.scope.domains, paid)
                    }
                    ClaimProbe::Never => true,
                    ClaimProbe::Yield => {
                        recovery.check = Some(CheckedRead::open(native, shape));
                        recovery.phase = ScopedRecoveryPhase::ClassifyOpen { after };
                        return false;
                    }
                }
            }
        };
        if wipe {
            recovery.wiped_open.insert(native);
        }
        after = Some(native);
    }
}

fn classify_refused(
    journal: &mut JournalLeaves<'_>,
    recovery: &mut ScopedRecovery,
    mut index: usize,
    credit: &mut Credit<'_>,
) -> bool {
    loop {
        let (identity, class) = match recovery.check.take() {
            Some(read) => (
                read.identity.expect("checked refused"),
                Classified::Check(read.shape),
            ),
            None => {
                let Some(paid) = credit.pay() else {
                    recovery.phase = ScopedRecoveryPhase::ClassifyRefused { index };
                    return false;
                };
                let Some(read) = journal.classify_refused(index, recovery, paid) else {
                    recovery.phase = ScopedRecoveryPhase::Preserve { after: None };
                    return true;
                };
                read
            }
        };
        let wipe = match class {
            Classified::Keep => false,
            Classified::Wipe => true,
            Classified::Check(shape) => {
                match journal.claim_probe(&shape, None, &mut recovery.deposit, credit) {
                    ClaimProbe::Fits(paid) => {
                        !journal.healthy_claimant(&shape, &recovery.scope.domains, paid)
                    }
                    ClaimProbe::Never => true,
                    ClaimProbe::Yield => {
                        recovery.check = Some(CheckedRead::refused(identity, shape));
                        recovery.phase = ScopedRecoveryPhase::ClassifyRefused { index };
                        return false;
                    }
                }
            }
        };
        if wipe {
            recovery.wiped_refused.insert(identity);
        }
        index += 1;
    }
}

/// Decide preservation for wiped opens past the cursor: every erased
/// unbounded abandonment names its doomed incarnation or its tainted
/// image, against one fixed per-image liveness basis. Decisions collect
/// only; a separate bounded pass applies them.
fn preserve(
    journal: &mut JournalLeaves<'_>,
    recovery: &mut ScopedRecovery,
    mut decided: Option<JournalNativeKey>,
    credit: &mut Credit<'_>,
) -> bool {
    loop {
        let Some(native) = next_member(&recovery.wiped_open, decided) else {
            recovery.phase = ScopedRecoveryPhase::PreserveTaint { after: None };
            return true;
        };
        // The entry's read and disposal decision persist across yields.
        let (image, shape) = match recovery.decided.take() {
            Some(read) => (read.image, read.shape),
            None => {
                let read = match recovery.check.take() {
                    Some(read) => PreserveRead::Check {
                        shape: read.shape,
                        function: read.function,
                        image: read.image,
                    },
                    None => {
                        let Some(paid) = credit.pay() else {
                            recovery.phase = ScopedRecoveryPhase::Preserve { after: decided };
                            return false;
                        };
                        journal.preserve_read(native, paid)
                    }
                };
                match read {
                    PreserveRead::Settled => {
                        decided = Some(native);
                        continue;
                    }
                    PreserveRead::Unbounded { image, shape } => (image, shape),
                    PreserveRead::Check {
                        shape,
                        function,
                        image,
                    } => {
                        // Undecidable disposal keeps the doom (fail closed).
                        let disposes = match journal.claim_probe(
                            &shape,
                            None,
                            &mut recovery.deposit,
                            credit,
                        ) {
                            ClaimProbe::Fits(paid) => {
                                journal.queued_returns_neutral(&shape, function, paid)
                            }
                            ClaimProbe::Never => false,
                            ClaimProbe::Yield => {
                                recovery.check =
                                    Some(CheckedRead::preserve(native, shape, function, image));
                                recovery.phase = ScopedRecoveryPhase::Preserve { after: decided };
                                return false;
                            }
                        };
                        if disposes {
                            decided = Some(native);
                            continue;
                        }
                        (image, shape)
                    }
                }
            }
        };
        recovery.decided = Some(CheckedRead::preserve(native, shape, 0, image));
        if !basis_step(journal, &mut recovery.preserve_basis, image, credit) {
            recovery.phase = ScopedRecoveryPhase::Preserve { after: decided };
            return false;
        }
        let basis = recovery
            .preserve_basis
            .get(&image)
            .expect("completed basis");
        let (doomed, tainted) = if basis.live.len() >= 2 {
            // A shared image's decision reads the identity's claims; one
            // that can never fit one credit taints the image (a counted,
            // named loss).
            match journal.claim_probe(&shape, None, &mut recovery.deposit, credit) {
                ClaimProbe::Yield => {
                    recovery.phase = ScopedRecoveryPhase::Preserve { after: decided };
                    return false;
                }
                ClaimProbe::Never => (Vec::new(), true),
                ClaimProbe::Fits(paid) => {
                    let claimants = journal.claimants_live_in(&shape, &basis.live, paid);
                    let tainted = claimants.is_empty();
                    (claimants, tainted)
                }
            }
        } else {
            // A sole or keyless image decides from the completed basis
            // alone; the decision still costs its unit. A basis that
            // completed on the slice's last unit yields here and decides
            // next slice (never an underflow).
            let Some(paid) = credit.pay() else {
                recovery.phase = ScopedRecoveryPhase::Preserve { after: decided };
                return false;
            };
            drop(paid);
            match basis.live.len() {
                1 => (basis.live.iter().copied().collect(), false),
                _ => (Vec::new(), !basis.keyed),
            }
        };
        recovery.decided = None;
        if tainted {
            recovery.preserve_taint.insert(image);
        }
        recovery.preserve_doomed.extend(doomed);
        decided = Some(native);
    }
}

/// Advance one image's preservation basis: first touch freezes the
/// key-list membership and extent (one unit), then each examined key
/// (one unit) appends when live. Returns true when it completed.
fn basis_step(
    journal: &JournalLeaves<'_>,
    bases: &mut BTreeMap<(u64, u64), PreservedBasis>,
    image: (u64, u64),
    credit: &mut Credit<'_>,
) -> bool {
    if let std::collections::btree_map::Entry::Vacant(slot) = bases.entry(image) {
        let Some(paid) = credit.pay() else {
            return false;
        };
        let (keyed, frozen_len) = journal.image_key_extent(image, paid);
        slot.insert(PreservedBasis::frozen(keyed, frozen_len));
    }
    let basis = bases.get_mut(&image).expect("basis");
    while !basis.done {
        if basis.next >= basis.frozen_len {
            basis.done = true;
            break;
        }
        let Some(paid) = credit.pay() else {
            return false;
        };
        if let Some((key, live)) = journal.image_key_at(image, basis.next, paid)
            && live
        {
            basis.live.insert(key);
        }
        basis.next += 1;
    }
    true
}

fn preserve_taint(
    journal: &mut JournalLeaves<'_>,
    recovery: &mut ScopedRecovery,
    mut after: Option<(u64, u64)>,
    credit: &mut Credit<'_>,
) -> bool {
    loop {
        let Some(image) = next_member(&recovery.preserve_taint, after) else {
            recovery.phase = ScopedRecoveryPhase::PreserveDoom { after: None };
            return true;
        };
        let Some(paid) = credit.pay() else {
            recovery.phase = ScopedRecoveryPhase::PreserveTaint { after };
            return false;
        };
        journal.taint_unclaimed_image(image, paid);
        after = Some(image);
    }
}

fn preserve_doom(
    journal: &mut JournalLeaves<'_>,
    model: &mut ModelLeaves<'_>,
    recovery: &mut ScopedRecovery,
    mut after: Option<JournalDomainKey>,
    credit: &mut Credit<'_>,
) -> bool {
    loop {
        if !drive_retirement(journal, model, recovery, credit) || credit.left() == 0 {
            recovery.phase = ScopedRecoveryPhase::PreserveDoom { after };
            return false;
        }
        let Some(key) = next_member(&recovery.preserve_doomed, after) else {
            recovery.phase = ScopedRecoveryPhase::OverflowDrain;
            return true;
        };
        let paid = credit.pay().expect("credit left");
        after = Some(key);
        if recovery.doomed_done.insert(key) {
            recovery.model_retire = journal.doom_abandoned_key(key, paid);
        } else {
            drop(paid);
        }
    }
}

fn overflow_drain(
    journal: &mut JournalLeaves<'_>,
    recovery: &mut ScopedRecovery,
    credit: &mut Credit<'_>,
) -> bool {
    while journal.overflow_owed() {
        let Some(paid) = credit.pay() else {
            recovery.phase = ScopedRecoveryPhase::OverflowDrain;
            return false;
        };
        journal.overflow_step(paid);
    }
    recovery.phase = if !recovery.preserve_taint.is_empty() {
        ScopedRecoveryPhase::TaintDrainOpen { after: None }
    } else if recovery.stream {
        ScopedRecoveryPhase::FenceAll { after: None }
    } else {
        ScopedRecoveryPhase::Fence { index: 0 }
    };
    true
}

fn taint_drain_open(
    journal: &mut JournalLeaves<'_>,
    recovery: &mut ScopedRecovery,
    mut after: Option<JournalNativeKey>,
    credit: &mut Credit<'_>,
) -> bool {
    loop {
        let Some(paid) = credit.pay() else {
            recovery.phase = ScopedRecoveryPhase::TaintDrainOpen { after };
            return false;
        };
        match journal.taint_drain_open(after, &recovery.preserve_taint, paid) {
            Some(native) => after = Some(native),
            None => {
                recovery.phase = ScopedRecoveryPhase::TaintDrainRefused { read: 0, write: 0 };
                return true;
            }
        }
    }
}

fn taint_drain_refused(
    journal: &mut JournalLeaves<'_>,
    recovery: &mut ScopedRecovery,
    mut read: usize,
    mut write: usize,
    credit: &mut Credit<'_>,
) -> bool {
    while read < journal.refused_len() {
        let Some(paid) = credit.pay() else {
            recovery.phase = ScopedRecoveryPhase::TaintDrainRefused { read, write };
            return false;
        };
        journal.compact_refused(
            read,
            &mut write,
            RefusedDrop::Images(&recovery.preserve_taint),
            paid,
        );
        read += 1;
    }
    journal.truncate_refused(write);
    recovery.phase = if recovery.stream {
        ScopedRecoveryPhase::FenceAll { after: None }
    } else {
        ScopedRecoveryPhase::Fence { index: 0 }
    };
    true
}

fn fence(
    journal: &mut JournalLeaves<'_>,
    model: &mut ModelLeaves<'_>,
    recovery: &mut ScopedRecovery,
    mut index: usize,
    credit: &mut Credit<'_>,
) -> bool {
    loop {
        if !drive_retirement(journal, model, recovery, credit) || credit.left() == 0 {
            recovery.phase = ScopedRecoveryPhase::Fence { index };
            return false;
        }
        let Some(key) = recovery.scope.domains.get(index).copied() else {
            recovery.phase = ScopedRecoveryPhase::WipeOpen { after: None };
            return true;
        };
        let paid = credit.pay().expect("credit left");
        index += 1;
        if let Some(retirement) = journal.fence_scoped_key(key, recovery.upper, paid) {
            recovery.model_retire = Some(retirement);
        }
    }
}

fn fence_all(
    journal: &mut JournalLeaves<'_>,
    model: &mut ModelLeaves<'_>,
    recovery: &mut ScopedRecovery,
    mut after: Option<JournalDomainKey>,
    credit: &mut Credit<'_>,
) -> bool {
    loop {
        if !drive_retirement(journal, model, recovery, credit) || credit.left() == 0 {
            recovery.phase = ScopedRecoveryPhase::FenceAll { after };
            return false;
        }
        let paid = credit.pay().expect("credit left");
        let Some(visit) = journal.fence_all_key(after, recovery.mode, recovery.upper, paid) else {
            recovery.phase = ScopedRecoveryPhase::WipeOpen { after: None };
            return true;
        };
        after = Some(visit.key);
        if visit.count_unregistered {
            // Unregistered pending keys never sealed, so the fence
            // records no model gap for them: an H3 loss counts one named
            // loss per such key, degrading per key.
            model.count_unregistered_loss();
        }
        recovery.stream_scope.push(visit.scope);
        if let Some(retirement) = visit.retire {
            recovery.model_retire = Some(retirement);
        }
    }
}

fn wipe_open(
    journal: &mut JournalLeaves<'_>,
    recovery: &mut ScopedRecovery,
    mut after: Option<JournalNativeKey>,
    credit: &mut Credit<'_>,
) -> bool {
    loop {
        let Some(native) = next_member(&recovery.wiped_open, after) else {
            recovery.phase = ScopedRecoveryPhase::WipeRefused { read: 0, write: 0 };
            return true;
        };
        if let Some(excused) = recovery.verdict.take() {
            let Some(paid) = credit.pay() else {
                recovery.verdict = Some(excused);
                recovery.phase = ScopedRecoveryPhase::WipeOpen { after };
                return false;
            };
            journal.wipe_open_decided(native, excused, paid);
            after = Some(native);
            continue;
        }
        let checked = match recovery.check.take() {
            Some(read) => read,
            None => {
                let Some(paid) = credit.pay() else {
                    recovery.phase = ScopedRecoveryPhase::WipeOpen { after };
                    return false;
                };
                match journal.wipe_open(native, paid) {
                    WipeOpen::Done => {
                        after = Some(native);
                        continue;
                    }
                    WipeOpen::Check { shape, function } => {
                        CheckedRead::preserve(native, shape, function, (0, 0))
                    }
                }
            }
        };
        // An undecidable excuse leaves the late terminal to taint at
        // ingest (fail closed).
        recovery.verdict = Some(
            match journal.claim_probe(&checked.shape, None, &mut recovery.deposit, credit) {
                ClaimProbe::Fits(paid) => {
                    journal.queued_returns_neutral(&checked.shape, checked.function, paid)
                }
                ClaimProbe::Never => false,
                ClaimProbe::Yield => {
                    recovery.check = Some(checked);
                    recovery.phase = ScopedRecoveryPhase::WipeOpen { after };
                    return false;
                }
            },
        );
    }
}

fn wipe_refused(
    journal: &mut JournalLeaves<'_>,
    recovery: &mut ScopedRecovery,
    mut read: usize,
    mut write: usize,
    credit: &mut Credit<'_>,
) -> bool {
    while read < journal.refused_len() {
        let Some(paid) = credit.pay() else {
            recovery.phase = ScopedRecoveryPhase::WipeRefused { read, write };
            return false;
        };
        journal.compact_refused(
            read,
            &mut write,
            RefusedDrop::Identities(&recovery.wiped_refused),
            paid,
        );
        read += 1;
    }
    journal.truncate_refused(write);
    // A stream recovery additionally drops every claim and the retained
    // census itself, like the synchronous staged void it replaces.
    if recovery.stream {
        journal.clear_claims_and_census();
    }
    recovery.phase = ScopedRecoveryPhase::Done;
    true
}

fn stop_open(
    journal: &mut JournalLeaves<'_>,
    recovery: &mut ScopedRecovery,
    mut after: Option<JournalNativeKey>,
    credit: &mut Credit<'_>,
) -> bool {
    loop {
        let Some(paid) = credit.pay() else {
            recovery.phase = ScopedRecoveryPhase::StopOpen { after };
            return false;
        };
        let Some((native, converted)) = journal.open_converted_for(after, paid) else {
            recovery.phase = ScopedRecoveryPhase::StopRefused { index: 0 };
            return true;
        };
        if let Some(key) = converted {
            recovery.stop_tracked.insert(key);
        }
        after = Some(native);
    }
}

fn stop_refused(
    journal: &mut JournalLeaves<'_>,
    recovery: &mut ScopedRecovery,
    mut index: usize,
    credit: &mut Credit<'_>,
) -> bool {
    loop {
        let Some(paid) = credit.pay() else {
            recovery.phase = ScopedRecoveryPhase::StopRefused { index };
            return false;
        };
        let Some((image, _)) = journal.refused_at(index, paid) else {
            recovery.phase = ScopedRecoveryPhase::StopKeys {
                after: None,
                visiting: None,
            };
            return true;
        };
        recovery.stop_refused.entry(image).or_default().push(index);
        index += 1;
    }
}

/// Stop: decide and refuse keys in key order. A key is tracked when an
/// open entry converted for it, or when one of its image's refused begins
/// attributes to it against the live set as it stands at that key.
fn stop_keys(
    journal: &mut JournalLeaves<'_>,
    model: &mut ModelLeaves<'_>,
    recovery: &mut ScopedRecovery,
    mut after: Option<JournalDomainKey>,
    mut visiting: Option<StopVisit>,
    credit: &mut Credit<'_>,
) -> bool {
    loop {
        if !drive_retirement(journal, model, recovery, credit) || credit.left() == 0 {
            recovery.phase = ScopedRecoveryPhase::StopKeys { after, visiting };
            return false;
        }
        let mut visit = match visiting {
            Some(visit) => visit,
            None => {
                let paid = credit.pay().expect("credit left");
                let Some((key, _)) = journal.key_after(after, paid) else {
                    recovery.phase = ScopedRecoveryPhase::StopClear;
                    return true;
                };
                StopVisit {
                    key,
                    at: 0,
                    tracked: recovery.stop_tracked.contains(&key),
                }
            }
        };
        let image = visit.key.image();
        let members = recovery.stop_refused.get(&image).map_or(0, Vec::len);
        while !visit.tracked && visit.at < members {
            let shape = match recovery.check.take() {
                Some(read) => read.shape,
                None => {
                    let Some(paid) = credit.pay() else {
                        recovery.phase = ScopedRecoveryPhase::StopKeys {
                            after,
                            visiting: Some(visit),
                        };
                        return false;
                    };
                    let index = recovery.stop_refused[&image][visit.at];
                    match journal.refused_at(index, paid) {
                        Some((_, shape)) => shape,
                        None => {
                            visit.at += 1;
                            continue;
                        }
                    }
                }
            };
            // An attribution too large to decide tracks the key (fail
            // closed: the key refuses).
            match journal.claim_probe(&shape, Some(image), &mut recovery.deposit, credit) {
                ClaimProbe::Fits(paid) => {
                    if journal.attributes_to(visit.key, &shape, None, paid) {
                        visit.tracked = true;
                    } else {
                        visit.at += 1;
                    }
                }
                ClaimProbe::Never => visit.tracked = true,
                ClaimProbe::Yield => {
                    recovery.check = Some(CheckedRead::refused_shape(shape));
                    recovery.phase = ScopedRecoveryPhase::StopKeys {
                        after,
                        visiting: Some(visit),
                    };
                    return false;
                }
            }
        }
        if visit.tracked {
            let Some(paid) = credit.pay() else {
                visit.at = members;
                recovery.phase = ScopedRecoveryPhase::StopKeys {
                    after,
                    visiting: Some(visit),
                };
                return false;
            };
            recovery.model_retire = Some(journal.stop_refuse_key(visit.key, paid));
        }
        after = Some(visit.key);
        visiting = None;
    }
}

fn stop_clear(
    journal: &mut JournalLeaves<'_>,
    recovery: &mut ScopedRecovery,
    credit: &mut Credit<'_>,
) -> bool {
    let Some(paid) = credit.pay() else {
        recovery.phase = ScopedRecoveryPhase::StopClear;
        return false;
    };
    journal.stop_clear(paid);
    recovery.phase = if recovery.collect_scope {
        ScopedRecoveryPhase::ScopeAll { after: None }
    } else {
        ScopedRecoveryPhase::Done
    };
    true
}

fn scope_all(
    journal: &mut JournalLeaves<'_>,
    recovery: &mut ScopedRecovery,
    mut after: Option<JournalDomainKey>,
    credit: &mut Credit<'_>,
) -> bool {
    loop {
        let Some(paid) = credit.pay() else {
            recovery.phase = ScopedRecoveryPhase::ScopeAll { after };
            return false;
        };
        let Some((key, domain)) = journal.key_after(after, paid) else {
            recovery.phase = ScopedRecoveryPhase::Done;
            return true;
        };
        recovery.stream_scope.push(domain);
        after = Some(key);
    }
}

/// Seal-time doom: drop the doomed key's image's staged opens that
/// converted for it or attribute to it against the live set frozen at
/// the decision.
fn doom_open(
    journal: &mut JournalLeaves<'_>,
    recovery: &mut ScopedRecovery,
    mut after: Option<JournalNativeKey>,
    credit: &mut Credit<'_>,
) -> bool {
    let key = recovery.doom_key.expect("doom rejection");
    loop {
        if let Some(drop) = recovery.verdict.take() {
            let native = recovery.verdict_at.take().expect("decided open");
            if drop {
                let Some(paid) = credit.pay() else {
                    recovery.verdict = Some(drop);
                    recovery.verdict_at = Some(native);
                    recovery.phase = ScopedRecoveryPhase::DoomOpen { after };
                    return false;
                };
                journal.drop_open_decided(native, paid);
            }
            after = Some(native);
            continue;
        }
        let checked = match recovery.check.take() {
            Some(read) => read,
            None => {
                let Some(paid) = credit.pay() else {
                    recovery.phase = ScopedRecoveryPhase::DoomOpen { after };
                    return false;
                };
                match journal.doom_open(after, key, paid) {
                    None => {
                        recovery.phase = ScopedRecoveryPhase::DoomRefused { read: 0, write: 0 };
                        return true;
                    }
                    Some((native, DoomOpen::Skip | DoomOpen::Dropped)) => {
                        after = Some(native);
                        continue;
                    }
                    Some((native, DoomOpen::Check(shape))) => CheckedRead::open(native, shape),
                }
            }
        };
        let native = checked.native.expect("checked open");
        // The frozen live set is indexed, so only the identity's own
        // claims price the decision. A row drops only when the paid
        // attribution proves it the doomed key's; one whose claims are
        // too many to decide stays staged (a sibling's history is never
        // dropped on uncertainty; the doom's own scope is unchanged).
        let drop = match journal.claim_probe(&checked.shape, None, &mut recovery.deposit, credit) {
            ClaimProbe::Fits(paid) => {
                journal.attributes_to(key, &checked.shape, Some(&recovery.doom_live), paid)
            }
            ClaimProbe::Never => false,
            ClaimProbe::Yield => {
                recovery.check = Some(checked);
                recovery.phase = ScopedRecoveryPhase::DoomOpen { after };
                return false;
            }
        };
        recovery.verdict = Some(drop);
        recovery.verdict_at = Some(native);
    }
}

fn doom_refused(
    journal: &mut JournalLeaves<'_>,
    recovery: &mut ScopedRecovery,
    mut read: usize,
    mut write: usize,
    credit: &mut Credit<'_>,
) -> bool {
    let key = recovery.doom_key.expect("doom rejection");
    while read < journal.refused_len() {
        if let Some(drop) = recovery.verdict.take() {
            let Some(paid) = credit.pay() else {
                recovery.verdict = Some(drop);
                recovery.phase = ScopedRecoveryPhase::DoomRefused { read, write };
                return false;
            };
            journal.compact_refused(read, &mut write, RefusedDrop::This(drop), paid);
            read += 1;
            continue;
        }
        let shape = match recovery.check.take() {
            Some(checked) => checked.shape,
            None => {
                let Some(paid) = credit.pay() else {
                    recovery.phase = ScopedRecoveryPhase::DoomRefused { read, write };
                    return false;
                };
                match journal.doom_refused_visit(read, &mut write, key, paid) {
                    Some(shape) => shape,
                    None => {
                        read += 1;
                        continue;
                    }
                }
            }
        };
        recovery.verdict = Some(
            match journal.claim_probe(&shape, None, &mut recovery.deposit, credit) {
                ClaimProbe::Fits(paid) => {
                    journal.attributes_to(key, &shape, Some(&recovery.doom_live), paid)
                }
                // Undecidable: kept, as for the staged originals above.
                ClaimProbe::Never => false,
                ClaimProbe::Yield => {
                    recovery.check = Some(CheckedRead::refused_shape(shape));
                    recovery.phase = ScopedRecoveryPhase::DoomRefused { read, write };
                    return false;
                }
            },
        );
    }
    journal.truncate_refused(write);
    recovery.phase = ScopedRecoveryPhase::Retire;
    true
}

fn raw_keys(
    journal: &mut JournalLeaves<'_>,
    model: &mut ModelLeaves<'_>,
    recovery: &mut ScopedRecovery,
    mut after: Option<JournalDomainKey>,
    credit: &mut Credit<'_>,
) -> bool {
    loop {
        if !drive_retirement(journal, model, recovery, credit) || credit.left() == 0 {
            recovery.phase = ScopedRecoveryPhase::RawKeys { after };
            return false;
        }
        let paid = credit.pay().expect("credit left");
        let Some((key, scope, retirement)) = journal.raw_key(after, paid) else {
            recovery.phase = ScopedRecoveryPhase::RawOpen { after: None };
            return true;
        };
        after = Some(key);
        if let Some(domain) = scope {
            recovery.stream_scope.push(domain);
        }
        if let Some(retirement) = retirement {
            recovery.model_retire = Some(retirement);
        }
    }
}

fn raw_open(
    journal: &mut JournalLeaves<'_>,
    recovery: &mut ScopedRecovery,
    mut after: Option<JournalNativeKey>,
    credit: &mut Credit<'_>,
) -> bool {
    loop {
        let Some(paid) = credit.pay() else {
            recovery.phase = ScopedRecoveryPhase::RawOpen { after };
            return false;
        };
        match journal.raw_open(after, paid) {
            Some(native) => after = Some(native),
            None => {
                recovery.phase = ScopedRecoveryPhase::RawRefused { read: 0, write: 0 };
                return true;
            }
        }
    }
}

fn raw_refused(
    journal: &mut JournalLeaves<'_>,
    recovery: &mut ScopedRecovery,
    mut read: usize,
    mut write: usize,
    credit: &mut Credit<'_>,
) -> bool {
    while read < journal.refused_len() {
        let Some(paid) = credit.pay() else {
            recovery.phase = ScopedRecoveryPhase::RawRefused { read, write };
            return false;
        };
        journal.compact_refused(read, &mut write, RefusedDrop::Tainted, paid);
        read += 1;
    }
    journal.truncate_refused(write);
    recovery.phase = ScopedRecoveryPhase::RawClaims {
        after: None,
        current: None,
    };
    true
}

fn raw_claims(
    journal: &mut JournalLeaves<'_>,
    recovery: &mut ScopedRecovery,
    mut after: Option<CallIdentity>,
    mut current: Option<CallIdentity>,
    credit: &mut Credit<'_>,
) -> bool {
    loop {
        match journal.raw_claims_step(after, current, credit) {
            ClaimsStep::Done => {
                recovery.phase = ScopedRecoveryPhase::Retire;
                return true;
            }
            ClaimsStep::Visited(identity) => {
                after = Some(identity);
                current = None;
            }
            ClaimsStep::Enter(identity) => current = Some(identity),
            ClaimsStep::Removed => {}
            ClaimsStep::Yield => {
                recovery.phase = ScopedRecoveryPhase::RawClaims { after, current };
                return false;
            }
        }
    }
}

fn s1_subjects(
    journal: &mut JournalLeaves<'_>,
    recovery: &mut ScopedRecovery,
    mut after: Option<JournalNativeKey>,
    credit: &mut Credit<'_>,
) -> bool {
    loop {
        let Some(paid) = credit.pay() else {
            recovery.phase = ScopedRecoveryPhase::S1Subjects { after };
            return false;
        };
        let Some((native, subject)) = journal.s1_subject(after, paid) else {
            recovery.phase = ScopedRecoveryPhase::S1Tainted { after: None };
            return true;
        };
        after = Some(native);
        match subject {
            S1Subject::None => {}
            S1Subject::Domain(domain) => sorted_insert(&mut recovery.stream_scope, domain),
            S1Subject::Fallback => recovery.image_fallback = true,
        }
    }
}

fn s1_tainted(
    journal: &mut JournalLeaves<'_>,
    recovery: &mut ScopedRecovery,
    mut after: Option<JournalDomainKey>,
    credit: &mut Credit<'_>,
) -> bool {
    loop {
        let Some(paid) = credit.pay() else {
            recovery.phase = ScopedRecoveryPhase::S1Tainted { after };
            return false;
        };
        let Some((key, domain)) = journal.tainted_key_domain(after, paid) else {
            recovery.phase = ScopedRecoveryPhase::S1Refuse { after: None };
            return true;
        };
        after = Some(key);
        if let Some(domain) = domain {
            // Independent image/overflow evidence keeps its full union.
            recovery.image_fallback = true;
            sorted_insert(&mut recovery.stream_scope, domain);
        }
    }
}

fn s1_refuse(
    journal: &mut JournalLeaves<'_>,
    model: &mut ModelLeaves<'_>,
    recovery: &mut ScopedRecovery,
    mut after: Option<JournalDomainKey>,
    credit: &mut Credit<'_>,
) -> bool {
    loop {
        if !drive_retirement(journal, model, recovery, credit) || credit.left() == 0 {
            recovery.phase = ScopedRecoveryPhase::S1Refuse { after };
            return false;
        }
        let paid = credit.pay().expect("credit left");
        let Some((key, retirement)) = journal.s1_refuse_key(after, &recovery.stream_scope, paid)
        else {
            recovery.phase = ScopedRecoveryPhase::S1Dispose { after: None };
            return true;
        };
        after = Some(key);
        if let Some(retirement) = retirement {
            recovery.model_retire = Some(retirement);
        }
    }
}

fn s1_dispose(
    journal: &mut JournalLeaves<'_>,
    recovery: &mut ScopedRecovery,
    mut after: Option<JournalNativeKey>,
    credit: &mut Credit<'_>,
) -> bool {
    loop {
        let checked = match recovery.check.take() {
            Some(read) => read,
            None => {
                let Some(paid) = credit.pay() else {
                    recovery.phase = ScopedRecoveryPhase::S1Dispose { after };
                    return false;
                };
                match journal.s1_dispose_read(after, paid) {
                    None => {
                        recovery.phase = ScopedRecoveryPhase::Retire;
                        return true;
                    }
                    Some((native, None)) => {
                        after = Some(native);
                        continue;
                    }
                    Some((native, Some(shape))) => CheckedRead::open(native, shape),
                }
            }
        };
        let native = checked.native.expect("checked subject");
        // A decided "never fits" persists (`verdict`), so the disposal's
        // own unit is owed, not the probe again.
        let paid = if recovery.verdict.is_some() {
            let unit = credit.pay().map(S1DisposePaid::Plain);
            if unit.is_some() {
                recovery.verdict = None;
            }
            unit
        } else {
            match journal.claim_probe(&checked.shape, None, &mut recovery.deposit, credit) {
                ClaimProbe::Fits(paid) => Some(S1DisposePaid::Claims(paid)),
                // The own-claim check can never fit one credit: the
                // original still disposes for one unit, leaving its claim
                // (its key is refused, so the claim can never convert).
                ClaimProbe::Never => match credit.pay() {
                    Some(unit) => Some(S1DisposePaid::Plain(unit)),
                    None => {
                        recovery.verdict = Some(false);
                        None
                    }
                },
                ClaimProbe::Yield => None,
            }
        };
        let Some(paid) = paid else {
            recovery.check = Some(checked);
            recovery.phase = ScopedRecoveryPhase::S1Dispose { after };
            return false;
        };
        journal.s1_dispose(native, paid);
        after = Some(native);
    }
}

/// The first member of an ordered cursor-owned set past `after` (cursor
/// memory, not a journal leaf).
fn next_member<T: Ord + Copy>(set: &BTreeSet<T>, after: Option<T>) -> Option<T> {
    match after {
        None => set.iter().next().copied(),
        Some(last) => set
            .range((std::ops::Bound::Excluded(last), std::ops::Bound::Unbounded))
            .next()
            .copied(),
    }
}

/// Sorted unique insertion into the failure scope (prepaid at the key
/// count by the audit preflight).
fn sorted_insert(scope: &mut Vec<ObjectDomain>, domain: ObjectDomain) {
    if let Err(at) = scope.binary_search(&domain) {
        scope.insert(at, domain);
    }
}
