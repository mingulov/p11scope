//! SPDX-License-Identifier: GPL-3.0-or-later
//! Per-module `C_Initialize` roll-up: observed init returns since the
//! semantic lane sealed, from joined (converted) and shed (unrouted)
//! Events. Counts are exact observations, never claims: a zero says
//! "no `C_Initialize` seen since the semantic lane started", never
//! "never initialised" — the call may have run before the seal. The
//! verdict is `unknown` when the lane never sealed or when event loss
//! may have hidden evidence; observed `CKR_OK` or
//! `CKR_CRYPTOKI_ALREADY_INITIALIZED` (0x191) proves initialised even
//! then. New aggregation over already-captured function and return
//! fields: no argv, env, keys, PINs or payloads.

/// The attested slot name this roll-up counts.
pub(crate) const C_INITIALIZE: &str = "C_Initialize";

/// Registry gap subjects that void an init verdict: the EVENTS ring
/// refused records before the drain read them, or its loss counter
/// could not be read (events may be missing without a count).
pub(crate) const NATIVE_EVENTS_LOST: &str = "native capture events lost";
pub(crate) const NATIVE_EVENTS_LOSS_UNKNOWN: &str = "native capture events loss unknown";

/// Observed `C_Initialize` returns for one module since the lane
/// sealed. Exact observations (saturating); absence of a call here
/// never proves the call never ran.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub(crate) struct ModuleInitRollup {
    /// Tapped init returns, joined plus shed.
    pub calls: u64,
    /// Returns equal to `CKR_OK`.
    pub ok: u64,
    /// Returns equal to `CKR_CRYPTOKI_ALREADY_INITIALIZED`.
    pub already_initialized: u64,
    /// The most recently observed return that was neither OK nor
    /// already-initialized, if any.
    pub last_error_rv: Option<u64>,
}

impl ModuleInitRollup {
    /// Fold one observed init return into the roll-up.
    pub(crate) fn note(&mut self, _rv: u64) {
        // RED stub: replaced by the counting implementation.
    }
}

/// The closed init verdict vocabulary: observed proof, observed
/// failure, honest absence, or unknown. Never a guessed state.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum InitStatus {
    Initialised,
    Failed,
    Unseen,
    Unknown,
}

impl InitStatus {
    /// The serialized status word.
    pub(crate) const fn label(self) -> &'static str {
        // RED stub: replaced by the real vocabulary.
        let _ = self;
        "stub"
    }
}

/// One module's init verdict: the status plus the rendered detail
/// line (shared by JSON and text).
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct InitVerdict {
    pub status: InitStatus,
    pub detail: String,
}

/// Judge the roll-up: proof first (observations stand even under
/// loss), then the lane/loss gates fail closed, then observed
/// failures, and finally the honest absence wording. `sealed` is the
/// run's semantic-seal latch, `loss` the run's EVENTS-loss signal.
pub(crate) fn verdict(_rollup: &ModuleInitRollup, _sealed: bool, _loss: bool) -> InitVerdict {
    // RED stub: replaced by the real precedence.
    InitVerdict {
        status: InitStatus::Unseen,
        detail: "stub".into(),
    }
}

/// Whether a shed call's slot proves a `C_Initialize` probe: the
/// attested plan names exactly `C_Initialize` here, authorized and
/// unambiguous, and the endpoint's object and offset match the
/// slot's. Mirrors the conversion slot checks, minus the caller
/// binding a shed call never has.
pub(crate) fn init_slot_for_shed(
    _plan: &crate::plan::AttachPlan,
    _slot_index: u32,
    _endpoint: &crate::semantic_capture::Endpoint,
) -> bool {
    // RED stub: replaced by the real predicate.
    false
}

#[cfg(test)]
mod tests {
    use super::*;
    use pkcs11_types::CkRv;

    fn rollup_of(
        calls: u64,
        ok: u64,
        already: u64,
        last_error_rv: Option<u64>,
    ) -> ModuleInitRollup {
        ModuleInitRollup {
            calls,
            ok,
            already_initialized: already,
            last_error_rv,
        }
    }

    #[test]
    fn init_rollup_counts_ok_already_and_errors() {
        let mut rollup = ModuleInitRollup::default();
        rollup.note(CkRv::OK.0);
        rollup.note(CkRv::CRYPTOKI_ALREADY_INITIALIZED.0);
        rollup.note(CkRv::GENERAL_ERROR.0);
        rollup.note(CkRv::OK.0);
        assert_eq!(
            rollup,
            rollup_of(4, 2, 1, Some(CkRv::GENERAL_ERROR.0)),
            "every tapped return counts once, in its own class"
        );
    }

    #[test]
    fn init_rollup_keeps_the_last_error() {
        let mut rollup = ModuleInitRollup::default();
        rollup.note(CkRv::GENERAL_ERROR.0);
        rollup.note(CkRv::DEVICE_ERROR.0);
        rollup.note(CkRv::OK.0);
        assert_eq!(rollup.calls, 3);
        assert_eq!(rollup.last_error_rv, Some(CkRv::DEVICE_ERROR.0));
    }

    #[test]
    fn init_rollup_saturates_at_u64_max() {
        let mut rollup = rollup_of(u64::MAX, u64::MAX, 0, None);
        rollup.note(CkRv::OK.0);
        assert_eq!(rollup.calls, u64::MAX);
        assert_eq!(rollup.ok, u64::MAX);
    }

    #[test]
    fn init_verdict_ok_is_initialised() {
        let judged = verdict(
            &rollup_of(2, 1, 0, Some(CkRv::GENERAL_ERROR.0)),
            true,
            false,
        );
        assert_eq!(judged.status, InitStatus::Initialised);
        assert_eq!(judged.status.label(), "initialised");
        assert!(
            judged.detail.contains("CKR_OK"),
            "the OK proof names its return: {}",
            judged.detail
        );
    }

    #[test]
    fn init_verdict_already_initialized_is_initialised() {
        assert_eq!(CkRv::CRYPTOKI_ALREADY_INITIALIZED.0, 0x191);
        let judged = verdict(&rollup_of(1, 0, 1, None), true, false);
        assert_eq!(judged.status, InitStatus::Initialised);
        assert!(
            judged.detail.contains("CKR_CRYPTOKI_ALREADY_INITIALIZED"),
            "0x191 counts as initialised, named exactly: {}",
            judged.detail
        );
    }

    #[test]
    fn init_verdict_ok_beats_other_observations() {
        let judged = verdict(
            &rollup_of(3, 1, 1, Some(CkRv::GENERAL_ERROR.0)),
            true,
            false,
        );
        assert_eq!(judged.status, InitStatus::Initialised);
        assert!(judged.detail.contains("CKR_OK"), "{}", judged.detail);
    }

    #[test]
    fn init_verdict_failures_name_the_rv() {
        let judged = verdict(
            &rollup_of(2, 0, 0, Some(CkRv::GENERAL_ERROR.0)),
            true,
            false,
        );
        assert_eq!(judged.status, InitStatus::Failed);
        assert_eq!(judged.status.label(), "failed");
        assert_eq!(
            judged.detail, "seen, C_Initialize failed (CKR_GENERAL_ERROR)",
            "a failing rv names the provider with its CKR name"
        );
    }

    #[test]
    fn init_verdict_unregistered_error_uses_hex() {
        let judged = verdict(&rollup_of(1, 0, 0, Some(0x7fff_ffff)), true, false);
        assert_eq!(judged.status, InitStatus::Failed);
        assert_eq!(judged.detail, "seen, C_Initialize failed (0x7fffffff)");
    }

    #[test]
    fn init_verdict_unsealed_is_unknown_unavailable() {
        let judged = verdict(&ModuleInitRollup::default(), false, false);
        assert_eq!(judged.status, InitStatus::Unknown);
        assert_eq!(judged.status.label(), "unknown");
        assert_eq!(judged.detail, "semantic lane unavailable");
    }

    #[test]
    fn init_verdict_loss_is_unknown() {
        let judged = verdict(&ModuleInitRollup::default(), true, true);
        assert_eq!(judged.status, InitStatus::Unknown);
        assert_eq!(
            judged.detail,
            "event loss may have hidden C_Initialize calls"
        );
    }

    #[test]
    fn init_verdict_failures_under_loss_are_unknown() {
        // Observed failures stay visible as counts, but the verdict
        // cannot rule out a lost OK.
        let judged = verdict(&rollup_of(2, 0, 0, Some(CkRv::GENERAL_ERROR.0)), true, true);
        assert_eq!(judged.status, InitStatus::Unknown);
    }

    #[test]
    fn init_verdict_proof_stands_under_loss() {
        let judged = verdict(&rollup_of(1, 1, 0, None), true, true);
        assert_eq!(judged.status, InitStatus::Initialised);
        let judged = verdict(&rollup_of(1, 0, 1, None), true, true);
        assert_eq!(judged.status, InitStatus::Initialised);
    }

    #[test]
    fn init_verdict_unsealed_observations_are_unknown() {
        // Fail closed: observations without a seal cannot happen in
        // production (taps flow only through finalize), so a
        // scripted contradiction reads unknown, never failed.
        let judged = verdict(
            &rollup_of(1, 0, 0, Some(CkRv::GENERAL_ERROR.0)),
            false,
            false,
        );
        assert_eq!(judged.status, InitStatus::Unknown);
    }

    #[test]
    fn init_verdict_zero_sealed_clean_reports_unseen_wording() {
        let judged = verdict(&ModuleInitRollup::default(), true, false);
        assert_eq!(judged.status, InitStatus::Unseen);
        assert_eq!(judged.status.label(), "unseen");
        assert_eq!(
            judged.detail, "no C_Initialize seen since the semantic lane started",
            "zero init calls word the absence, never 'never initialised'"
        );
    }

    /// One scripted slot over one pinned object, for the shed-tap
    /// predicate twins.
    fn init_plan(mutate: impl FnOnce(&mut crate::plan::Slot)) -> crate::plan::AttachPlan {
        use crate::discovery::identity::PinnedObjectId;
        let mut slot = crate::plan::Slot {
            index: 0,
            descriptor_index: crate::kinds::function_id(C_INITIALIZE).unwrap() + 1,
            object: PinnedObjectId(3),
            object_path: "/init/provider.so".into(),
            file_offset: 0x1000,
            names: vec![C_INITIALIZE.into()],
            aliased: false,
            semantics: crate::kinds::descriptor(C_INITIALIZE).unwrap(),
            semantic_authorized: true,
            semantic_ambiguous: false,
            fork_safe: true,
            module_ids: vec![crate::plan::ModuleId(0)],
        };
        mutate(&mut slot);
        crate::plan::AttachPlan::from_slots(vec![slot])
    }

    fn init_endpoint() -> crate::semantic_capture::Endpoint {
        use crate::discovery::identity::PinnedObjectId;
        crate::semantic_capture::Endpoint {
            object: PinnedObjectId(3),
            file_slot: 0,
            offset: 0x1000,
        }
    }

    #[test]
    fn shed_predicate_accepts_single_named_authorized_initialize() {
        let plan = init_plan(|_| {});
        assert!(
            init_slot_for_shed(&plan, 0, &init_endpoint()),
            "an authorized single-named C_Initialize probe taps its shed calls"
        );
    }

    #[test]
    fn shed_predicate_rejects_other_functions() {
        let plan = init_plan(|slot| slot.names = vec!["C_Sign".into()]);
        assert!(!init_slot_for_shed(&plan, 0, &init_endpoint()));
    }

    #[test]
    fn shed_predicate_rejects_aliased_slots() {
        let plan = init_plan(|slot| {
            slot.names = vec![C_INITIALIZE.into(), "C_Other".into()];
            slot.aliased = true;
        });
        assert!(!init_slot_for_shed(&plan, 0, &init_endpoint()));
    }

    #[test]
    fn shed_predicate_rejects_ambiguous_slots() {
        let plan = init_plan(|slot| slot.semantic_ambiguous = true);
        assert!(!init_slot_for_shed(&plan, 0, &init_endpoint()));
    }

    #[test]
    fn shed_predicate_rejects_unauthorized_slots() {
        let plan = init_plan(|slot| slot.semantic_authorized = false);
        assert!(!init_slot_for_shed(&plan, 0, &init_endpoint()));
    }

    #[test]
    fn shed_predicate_rejects_count_only_slots() {
        let plan = init_plan(|slot| {
            slot.semantics = p11scope_ebpf_common::SlotSemantics::COUNT_ONLY;
        });
        assert!(!init_slot_for_shed(&plan, 0, &init_endpoint()));
    }

    #[test]
    fn shed_predicate_rejects_object_mismatch() {
        use crate::discovery::identity::PinnedObjectId;
        let plan = init_plan(|_| {});
        let mut endpoint = init_endpoint();
        endpoint.object = PinnedObjectId(9);
        assert!(!init_slot_for_shed(&plan, 0, &endpoint));
        let mut endpoint = init_endpoint();
        endpoint.offset = 0x2000;
        assert!(!init_slot_for_shed(&plan, 0, &endpoint));
    }

    #[test]
    fn shed_predicate_rejects_unknown_slot_index() {
        let plan = init_plan(|_| {});
        assert!(!init_slot_for_shed(&plan, 99, &init_endpoint()));
    }
}
