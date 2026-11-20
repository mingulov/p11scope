//! The paid model-row surface a domain retirement is driven through.
//!
//! [`ModelLeaves`] wraps the model state behind a field private to this
//! module, so [`crate::semantics_objects::recovery_cursor`] reaches model
//! rows only through the methods below. Each method that reads or
//! mutates a row consumes one [`Paid`] unit and does exactly that row's
//! work: one view, one live session, one binding, one deferred origin, one
//! call ticket or one queued charge release. Nested rows (a session's
//! bindings, the deferred origins naming its views) are never visited as
//! part of another row's unit.

use std::collections::BTreeSet;

use super::{
    Binding, DeferredInput, DomainRetirement, Lifetime, ModelState, ObjectEffects, ObjectGap,
    RetireKind, SessionEnd,
};
use crate::semantics_objects::credit::Paid;
use crate::semantics_objects::journal::StagingLedger;
use crate::semantics_objects::{
    CallKey, ObjectDomain, ObjectHandle, ObjectId, SessionHandle, SessionIncarnation,
};

/// The recovery cursor's only handle on the model rows.
pub(in crate::semantics_objects) struct ModelLeaves<'a> {
    state: &'a mut ModelState,
}

/// Resume position in the pending deferred-origin table.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub(in crate::semantics_objects) struct PendingAfter(Option<(SessionIncarnation, u32)>);

/// Resume position in the detached deferred-origin table.
#[derive(Clone, Copy, PartialEq, Eq, Default)]
pub(in crate::semantics_objects) struct DetachedAfter(Option<super::DetachedKey>);

impl std::fmt::Debug for DetachedAfter {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        // The key carries raw scope words: name the position only.
        f.write_str(if self.0.is_some() {
            "DetachedAfter(..)"
        } else {
            "DetachedAfter(start)"
        })
    }
}

impl<'a> ModelLeaves<'a> {
    pub(super) fn new(state: &'a mut ModelState) -> Self {
        Self { state }
    }

    fn charge(&mut self, _paid: Paid) {
        #[cfg(test)]
        {
            self.state.test_retire_units += 1;
        }
    }

    /// Count one voided pending key that holds no model domain (an O(1)
    /// counter: no row is read).
    pub(in crate::semantics_objects) fn count_unregistered_loss(&mut self) {
        self.state.count_unregistered_loss();
    }

    /// Open a retirement (one unit): an abandonment names its loss; an
    /// unheld domain names its gap and the retirement ends; a held one
    /// publishes its refusal (bootstrap and initialization cleared).
    /// Returns whether rows remain to retire.
    pub(in crate::semantics_objects) fn start(
        &mut self,
        retirement: &DomainRetirement,
        effects: &mut ObjectEffects,
        paid: Paid,
    ) -> bool {
        self.charge(paid);
        let domain = retirement.domain;
        if matches!(retirement.kind, RetireKind::Abandon) {
            self.state.gap(ObjectGap::Loss);
        }
        if let Err(unheld) = self.state.held(domain) {
            self.state.gap_effect(effects, unheld);
            return false;
        }
        let state = self.state.domains.get_mut(&domain).expect("held domain");
        state.bootstrap = None;
        state.initialized = false;
        true
    }

    /// Retire the live view behind the binding after `after` (one unit):
    /// its deferred-input loss is recorded for the deferred pass, not
    /// scanned here. `None` when the bindings exhaust.
    pub(in crate::semantics_objects) fn retire_next_view(
        &mut self,
        retirement: &mut DomainRetirement,
        after: Option<(SessionIncarnation, ObjectHandle)>,
        effects: &mut ObjectEffects,
        paid: Paid,
    ) -> Option<(SessionIncarnation, ObjectHandle)> {
        self.charge(paid);
        let bindings = &self.state.domains[&retirement.domain].bindings;
        let (key, binding) = match after {
            None => bindings.iter().next(),
            Some(last) => bindings
                .range((std::ops::Bound::Excluded(last), std::ops::Bound::Unbounded))
                .next(),
        }
        .map(|(key, binding)| (*key, *binding))?;
        if let Binding::View(id) = binding
            && self
                .state
                .end_view_with(id, Lifetime::Retired(retirement.reason()), effects, false)
        {
            retirement.retired.insert(id);
        }
        Some(key)
    }

    /// The live session after `after` (one unit).
    pub(in crate::semantics_objects) fn next_live_session(
        &mut self,
        domain: ObjectDomain,
        after: Option<SessionHandle>,
        paid: Paid,
    ) -> Option<(SessionHandle, SessionIncarnation)> {
        self.charge(paid);
        let live = &self.state.domains[&domain].live_sessions;
        match after {
            None => live.iter().next(),
            Some(last) => live
                .range((std::ops::Bound::Excluded(last), std::ops::Bound::Unbounded))
                .next(),
        }
        .map(|(handle, session)| (*handle, *session))
    }

    /// Clear one remaining binding of a retiring session, or, when none
    /// remains, end the session (one unit either way). Returns whether the
    /// session ended. Its deferred origins dispose in the deferred pass.
    pub(in crate::semantics_objects) fn clear_or_end_session(
        &mut self,
        retirement: &mut DomainRetirement,
        session: SessionIncarnation,
        effects: &mut ObjectEffects,
        paid: Paid,
    ) -> bool {
        self.charge(paid);
        let domain = retirement.domain;
        let low = (session, ObjectHandle(0));
        let high = (session, ObjectHandle(u64::MAX));
        let remaining = self.state.domains[&domain]
            .bindings
            .range(low..=high)
            .next()
            .map(|((_, handle), binding)| (*handle, *binding));
        if let Some((handle, binding)) = remaining {
            if let Binding::View(id) = binding
                && self.state.end_view_with(
                    id,
                    Lifetime::Retired(ObjectGap::SessionClosed),
                    effects,
                    false,
                )
            {
                retirement.retired.insert(id);
            }
            if self.state.domains[&domain]
                .bindings
                .contains_key(&(session, handle))
            {
                self.state.set_binding(domain, session, handle, None);
            }
            return false;
        }
        if self.state.end_session_with(
            session,
            SessionEnd::Uncertain(retirement.reason()),
            effects,
            false,
        ) {
            retirement.ended.insert(session);
        }
        true
    }

    /// Whether the deferred pass has anything to do (O(1) metadata).
    pub(in crate::semantics_objects) fn deferred_owed(
        &self,
        retirement: &DomainRetirement,
    ) -> bool {
        (!retirement.retired.is_empty() || !retirement.ended.is_empty())
            && !(self.state.deferred_pending.is_empty() && self.state.deferred_detached.is_empty())
    }

    /// Apply the retirement's view losses and session disposals to the
    /// pending deferred origin after `after` (one unit). `None` when the
    /// table exhausts.
    pub(in crate::semantics_objects) fn deferred_pending_step(
        &mut self,
        retirement: &DomainRetirement,
        after: PendingAfter,
        paid: Paid,
    ) -> Option<PendingAfter> {
        self.charge(paid);
        let pending = &self.state.deferred_pending;
        let key = match after.0 {
            None => pending.keys().next(),
            Some(last) => pending
                .range((std::ops::Bound::Excluded(last), std::ops::Bound::Unbounded))
                .next()
                .map(|(key, _)| key),
        }
        .copied()?;
        if retirement.ended.contains(&key.0) {
            let record = self
                .state
                .deferred_pending
                .remove(&key)
                .expect("visited origin");
            self.state.deferred_releases.push(record.ticket.0);
        } else if let Some(record) = self.state.deferred_pending.get_mut(&key) {
            for input in record.inputs.iter_mut() {
                lose_retired_input(input, &retirement.retired);
            }
        }
        Some(PendingAfter(Some(key)))
    }

    /// Apply the retirement's view losses and session disposals to the
    /// detached deferred origin after `after` (one unit). `None` when the
    /// table exhausts.
    pub(in crate::semantics_objects) fn deferred_detached_step(
        &mut self,
        retirement: &DomainRetirement,
        after: DetachedAfter,
        paid: Paid,
    ) -> Option<DetachedAfter> {
        self.charge(paid);
        let detached = &self.state.deferred_detached;
        let key = match after.0 {
            None => detached.keys().next(),
            Some(last) => detached
                .range((std::ops::Bound::Excluded(last), std::ops::Bound::Unbounded))
                .next()
                .map(|(key, _)| key),
        }
        .copied()?;
        let record = self
            .state
            .deferred_detached
            .get_mut(&key)
            .expect("visited origin");
        if record
            .origin
            .session
            .is_some_and(|session| retirement.ended.contains(&session))
        {
            let record = self
                .state
                .deferred_detached
                .remove(&key)
                .expect("visited origin");
            self.state.deferred_releases.push(record.origin.ticket.0);
        } else {
            for input in record.origin.inputs.iter_mut() {
                lose_retired_input(input, &retirement.retired);
            }
            if record
                .holder
                .is_some_and(|holder| retirement.ended.contains(&holder))
            {
                record.holder = None;
            }
        }
        Some(DetachedAfter(Some(key)))
    }

    /// Clear the domain's first leftover binding (one unit). Returns
    /// whether one cleared.
    pub(in crate::semantics_objects) fn clear_next_binding(
        &mut self,
        domain: ObjectDomain,
        paid: Paid,
    ) -> bool {
        self.charge(paid);
        let Some((session, handle)) = self.state.domains[&domain].bindings.keys().next().copied()
        else {
            return false;
        };
        self.state.set_binding(domain, session, handle, None);
        true
    }

    fn call_after(
        &self,
        domain: ObjectDomain,
        after: Option<CallKey>,
    ) -> Option<(CallKey, super::CallToken)> {
        let keys = &self.state.domains[&domain].keys;
        match after {
            None => keys.iter().next(),
            Some(last) => keys
                .range((std::ops::Bound::Excluded(last), std::ops::Bound::Unbounded))
                .next(),
        }
        .map(|(key, token)| (*key, *token))
    }

    /// Fence the domain's call after `after` (one unit).
    pub(in crate::semantics_objects) fn fence_next_call(
        &mut self,
        domain: ObjectDomain,
        after: Option<CallKey>,
        paid: Paid,
    ) -> Option<CallKey> {
        self.charge(paid);
        let (key, token) = self.call_after(domain, after)?;
        self.state.fence(token);
        Some(key)
    }

    /// Remove the domain's call after `after` and release its ticket (one
    /// unit).
    pub(in crate::semantics_objects) fn remove_next_call(
        &mut self,
        domain: ObjectDomain,
        after: Option<CallKey>,
        ledger: &mut StagingLedger,
        paid: Paid,
    ) -> Option<CallKey> {
        self.charge(paid);
        let (key, token) = self.call_after(domain, after)?;
        self.state.remove_call(token, ledger);
        Some(key)
    }

    /// Whether disposed deferred charges still wait for release (O(1)).
    pub(in crate::semantics_objects) fn releases_owed(&self) -> bool {
        !self.state.deferred_releases.is_empty()
    }

    /// Release one queued deferred charge (one unit).
    pub(in crate::semantics_objects) fn release_next_deferred(
        &mut self,
        ledger: &mut StagingLedger,
        paid: Paid,
    ) {
        self.charge(paid);
        if let Some(ticket) = self.state.deferred_releases.pop() {
            ledger.release_deferred(ticket);
        }
    }

    /// Close the retirement (one unit): every row already retired, so
    /// this is the closing proof bookkeeping only (generation, fence
    /// floor; a void also names its lost outcome and raises the fence).
    pub(in crate::semantics_objects) fn finish(
        &mut self,
        retirement: &DomainRetirement,
        effects: &mut ObjectEffects,
        ledger: &mut StagingLedger,
        paid: Paid,
    ) {
        self.charge(paid);
        let domain = retirement.domain;
        self.state
            .void_bootstrap(domain, retirement.reason(), effects, ledger);
        if let RetireKind::Void(upper) = retirement.kind {
            self.state.gap(ObjectGap::OutcomeLost);
            if let Some(state) = self.state.domains.get_mut(&domain) {
                state.fence_floor = super::max_opt(state.fence_floor, Some(upper.0));
            }
        }
    }
}

/// A frozen deferred input naming a view this retirement retired can
/// never redeem a receipt (the same mark the view's own end makes).
fn lose_retired_input(input: &mut DeferredInput, retired: &BTreeSet<ObjectId>) {
    if let DeferredInput::Frozen { object, lost, .. } = input
        && retired.contains(object)
    {
        *lost = true;
    }
}
