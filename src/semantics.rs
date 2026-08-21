//! Semantic state machine: turns a stream of completed `Event`s into
//! meaning — mechanisms, session lifecycle, logins, per-function counts —
//! while pseudonymizing every session handle as it is consumed. Raw
//! handles live only in the in-memory maps below; no accessor on `State`
//! returns one.

use crate::attach::CapturePolicy;
use crate::plan::{AttachPlan, ModuleId};
#[cfg(test)]
use p11scope_ebpf_common::MECH_NONE;
use p11scope_ebpf_common::{
    Event, FUNCTION_NONE, LATENCY_BUCKETS, SESSION_NONE, USER_TYPE_NONE, bucket_of, capture,
    direct, event_type, lifecycle, operation, semantic_flags, shape, transition,
};
use pkcs11_proxy_ng_types::CkRv;
use std::collections::{BTreeMap, BTreeSet};

/// Aggregate stats for one mechanism id, kept **verbatim** as `u64` —
/// vendor ids like `0x80001042` must survive unchanged.
#[derive(Debug, Clone, PartialEq, Default)]
pub struct MechStat {
    pub calls: u64,
    pub errors: u64,
    pub buckets: [u64; LATENCY_BUCKETS],
    pub total_ns: u64,
    pub max_ns: u64,
    /// Operation categories (`"sign"`, `"encrypt"`, ...) this mechanism id
    /// was seen initializing, derived from the `*Init` function name(s)
    /// at the slot that recorded it. A set, not a scalar: the same
    /// mechanism id can legally serve more than one operation kind.
    pub ops: BTreeSet<String>,
    /// Distinct decoded parameter combinations observed on `*Init` calls
    /// for this mechanism, keyed by `(shape code, p0, p1, p2)` with each
    /// combination's occurrence count. A map, not a single "latest" or
    /// averaged value: migration assessment needs the actual combos a
    /// mechanism was driven with, not a summary that could hide a
    /// weaker one. Only entries whose decode applied (`shape !=
    /// shape::NONE`) are recorded here.
    pub param_combos: BTreeMap<(u32, u64, u64, u64), u64>,
    /// `*Init` calls for this mechanism whose parameter decode did not
    /// apply (`Event::shape == shape::NONE`). Combined with
    /// `param_combos` being non-empty (this mechanism id *did* decode
    /// successfully at least once this capture), a nonzero count here is
    /// evidence of an inconsistent/failed decode on some calls — see
    /// `State::shape_decode_failures`. When `param_combos` is empty this
    /// mechanism simply has no decodable shape (or none observed), which
    /// is not a failure.
    pub init_no_shape: u64,
}

#[cfg(test)]
mod corrective_tests {
    use super::*;
    use crate::plan::{AttachPlan, Slot};

    fn plan(names: &[&str]) -> AttachPlan {
        plan_with_fork(names, false)
    }

    /// Every slot in these single-module plans belongs to `ModuleId(0)`.
    fn sess(handle: u64) -> SessionRef {
        SessionRef {
            module: crate::plan::ModuleId(0),
            handle,
        }
    }

    fn plan_with_fork(names: &[&str], fork_safe: bool) -> AttachPlan {
        let mut plan = AttachPlan::from_slots(
            names
                .iter()
                .enumerate()
                .map(|(index, name)| Slot {
                    index: index as u32,
                    descriptor_index: crate::kinds::function_id(name).unwrap() + 1,
                    object: crate::plan::TEST_PINNED_OBJECT,
                    object_path: "/opt/p11.so".into(),
                    file_offset: index as u64 * 16,
                    names: vec![(*name).into()],
                    aliased: false,
                    semantics: crate::kinds::descriptor(name).unwrap(),
                    semantic_authorized: true,
                    semantic_ambiguous: false,
                    fork_safe,
                    module_ids: vec![crate::plan::ModuleId(0)],
                })
                .collect(),
        );
        plan.entries_seen = names.len();
        plan
    }

    fn event(plan: &AttachPlan, name: &str, session: u64, rv: u64) -> Event {
        let slot = plan
            .slots
            .iter()
            .find(|slot| slot.names == [name])
            .unwrap()
            .index;
        Event {
            ts_ns: 100,
            duration_ns: 10,
            pid_tgid: 100u64 << 32,
            session,
            mechanism: MECH_NONE,
            rv,
            slot,
            capture: capture::MECHANISM_NONE | capture::OUTPUT_NON_NULL,
            target_function: FUNCTION_NONE,
            ..Event::default()
        }
    }

    fn mechanism(plan: &AttachPlan, name: &str, session: u64, mechanism: u64, rv: u64) -> Event {
        Event {
            mechanism,
            capture: capture::MECHANISM_VALUE | capture::OUTPUT_NON_NULL,
            ..event(plan, name, session, rv)
        }
    }

    fn open(plan: &AttachPlan, session: u64, slot_id: u64) -> Event {
        Event {
            slot_id,
            ..event(plan, "C_OpenSession", session, CkRv::OK.0)
        }
    }

    #[test]
    fn concurrent_operations_and_unrelated_calls_never_cross_attribute() {
        let p = plan(&[
            "C_SignInit",
            "C_DigestInit",
            "C_Sign",
            "C_DigestUpdate",
            "C_GenerateRandom",
        ]);
        let mut state = State::new(&p);
        state.observe(&mechanism(&p, "C_SignInit", 7, 0x101, 0));
        state.observe(&mechanism(&p, "C_DigestInit", 7, 0x250, 0));
        state.observe(&event(&p, "C_GenerateRandom", 7, 0));
        state.observe(&event(&p, "C_Sign", 7, 0));
        state.observe(&event(&p, "C_DigestUpdate", 7, 0));

        assert_eq!(state.mechanisms()[&0x101].calls, 2);
        assert_eq!(state.mechanisms()[&0x250].calls, 2);
        assert_eq!(state.orphan_ops(), 0);
        assert!(!state.active_ops.contains_key(&(
            ProcessKey::from_pid(100),
            sess(7),
            operation::SIGN
        )));
        assert!(state.active_ops.contains_key(&(
            ProcessKey::from_pid(100),
            sess(7),
            operation::DIGEST
        )));
    }

    #[test]
    fn object_search_and_close_all_follow_their_own_lifecycle() {
        let p = plan(&[
            "C_OpenSession",
            "C_SignInit",
            "C_FindObjectsInit",
            "C_FindObjectsFinal",
            "C_SignFinal",
            "C_CloseAllSessions",
        ]);
        let mut state = State::new(&p);
        state.observe(&open(&p, 10, 1));
        state.observe(&open(&p, 20, 2));
        state.observe(&mechanism(&p, "C_SignInit", 10, 0x101, 0));
        state.observe(&event(&p, "C_FindObjectsInit", 10, 0));
        state.observe(&event(&p, "C_FindObjectsFinal", 10, 0));
        state.observe(&event(&p, "C_SignFinal", 10, 0));
        let mut close_all = event(&p, "C_CloseAllSessions", SESSION_NONE, 0);
        close_all.slot_id = 1;
        state.observe(&close_all);

        assert_eq!(state.mechanisms()[&0x101].calls, 2);
        assert_eq!(state.sessions().closed, 1);
        // Slot 0 is this plan's C_OpenSession.
        assert!(state.session_pseudonym(100, 0, 10).is_none());
        assert!(state.session_pseudonym(100, 0, 20).is_some());
    }

    #[test]
    fn init_null_unreadable_and_failure_rules_are_distinct() {
        let p = plan(&["C_SignInit", "C_Sign", "C_MessageSignInit"]);
        let process = ProcessKey::from_pid(100);
        let mut state = State::new(&p);
        state.observe(&mechanism(&p, "C_SignInit", 7, 0x101, 0));
        state.observe(&mechanism(
            &p,
            "C_SignInit",
            7,
            0x102,
            CkRv::OPERATION_ACTIVE.0,
        ));
        assert_eq!(
            state.active_ops[&(process, sess(7), operation::SIGN)].mechanism,
            0x101
        );

        let null_failed = Event {
            capture: capture::MECHANISM_NULL,
            ..event(&p, "C_SignInit", 7, CkRv::ARGUMENTS_BAD.0)
        };
        state.observe(&null_failed);
        assert!(
            state
                .active_ops
                .contains_key(&(process, sess(7), operation::SIGN))
        );

        let null_ok = Event {
            capture: capture::MECHANISM_NULL,
            ..event(&p, "C_SignInit", 7, 0)
        };
        state.observe(&null_ok);
        assert!(
            !state
                .active_ops
                .contains_key(&(process, sess(7), operation::SIGN))
        );

        state.observe(&mechanism(&p, "C_SignInit", 7, 0x103, 0));
        let unreadable = Event {
            capture: capture::MECHANISM_UNREADABLE,
            ..event(&p, "C_SignInit", 7, 0)
        };
        state.observe(&unreadable);
        assert!(
            !state
                .active_ops
                .contains_key(&(process, sess(7), operation::SIGN))
        );

        let invalid_null = Event {
            capture: capture::MECHANISM_NULL,
            ..event(&p, "C_MessageSignInit", 7, 0)
        };
        state.observe(&invalid_null);
        assert_eq!(state.semantic_evidence().semantic_capture_failures, 1);
    }

    #[test]
    fn output_and_update_termination_buckets_match_the_standard_contract() {
        let p = plan(&[
            "C_VerifyInit",
            "C_Verify",
            "C_VerifyRecoverInit",
            "C_VerifyRecover",
            "C_EncryptInit",
            "C_EncryptUpdate",
            "C_DigestInit",
            "C_DigestKey",
            "C_SignInit",
            "C_SignUpdate",
            "C_DigestEncryptUpdate",
        ]);
        let process = ProcessKey::from_pid(100);
        let mut state = State::new(&p);

        state.observe(&mechanism(&p, "C_VerifyInit", 7, 1, 0));
        state.observe(&event(&p, "C_Verify", 7, CkRv::BUFFER_TOO_SMALL.0));
        assert!(
            !state
                .active_ops
                .contains_key(&(process, sess(7), operation::VERIFY))
        );

        state.observe(&mechanism(&p, "C_VerifyRecoverInit", 7, 2, 0));
        let query = Event {
            capture: capture::OUTPUT_NULL,
            ..event(&p, "C_VerifyRecover", 7, 0)
        };
        state.observe(&query);
        assert!(
            state
                .active_ops
                .contains_key(&(process, sess(7), operation::VERIFY_RECOVER))
        );
        state.observe(&event(&p, "C_VerifyRecover", 7, 0));
        assert!(
            !state
                .active_ops
                .contains_key(&(process, sess(7), operation::VERIFY_RECOVER))
        );

        state.observe(&mechanism(&p, "C_EncryptInit", 7, 3, 0));
        state.observe(&event(&p, "C_EncryptUpdate", 7, CkRv::BUFFER_TOO_SMALL.0));
        assert!(
            state
                .active_ops
                .contains_key(&(process, sess(7), operation::ENCRYPT))
        );

        state.observe(&mechanism(&p, "C_DigestInit", 7, 4, 0));
        state.observe(&event(&p, "C_DigestKey", 7, CkRv::KEY_HANDLE_INVALID.0));
        assert!(
            state
                .active_ops
                .contains_key(&(process, sess(7), operation::DIGEST))
        );

        state.observe(&mechanism(&p, "C_SignInit", 7, 5, 0));
        state.observe(&event(&p, "C_SignUpdate", 7, CkRv::DATA_LEN_RANGE.0));
        assert!(
            !state
                .active_ops
                .contains_key(&(process, sess(7), operation::SIGN))
        );

        state.observe(&mechanism(&p, "C_SignInit", 7, 5, 0));
        state.observe(&event(
            &p,
            "C_DigestEncryptUpdate",
            7,
            CkRv::GENERAL_ERROR.0,
        ));
        assert!(
            state
                .active_ops
                .contains_key(&(process, sess(7), operation::DIGEST))
        );
        assert!(
            state
                .active_ops
                .contains_key(&(process, sess(7), operation::ENCRYPT))
        );
    }

    #[test]
    fn direct_key_mechanisms_and_keypair_template_roles_are_independent() {
        let names = [
            "C_GenerateKey",
            "C_GenerateKeyPair",
            "C_WrapKey",
            "C_UnwrapKey",
            "C_DeriveKey",
            "C_EncapsulateKey",
            "C_DecapsulateKey",
            "C_WrapKeyAuthenticated",
            "C_UnwrapKeyAuthenticated",
        ];
        let p = plan(&names);
        let mut state =
            State::with_policy(&p, crate::attach::CapturePolicy::UnsafeUnvalidatedMetadata);
        for (index, name) in names.iter().enumerate() {
            let mut ev = mechanism(&p, name, 7, 0x8000_0000 + index as u64, 0);
            if *name == "C_GenerateKeyPair" {
                ev.attr_types[0] = 0x104;
                ev.attr_count = 1;
                ev.attr_total = 1;
                ev.attr_types1[0] = 0x108;
                ev.attr_count1 = 1;
                ev.attr_total1 = 1;
            }
            state.observe(&ev);
        }
        assert_eq!(state.mechanisms().len(), names.len());
        assert!(state.active_ops.is_empty());
        assert_eq!(state.templates()[&(1, 0)].role, Some("public"));
        assert_eq!(state.templates()[&(1, 1)].role, Some("private"));
        assert!(state.templates()[&(1, 0)].attr_types.contains(&0x104));
        assert!(state.templates()[&(1, 1)].attr_types.contains(&0x108));
    }

    #[test]
    fn authentication_cancel_restore_and_reconciliation_are_explicit_evidence() {
        let p = plan(&[
            "C_OpenSession",
            "C_SignInit",
            "C_Sign",
            "C_Login",
            "C_Logout",
            "C_SessionCancel",
            "C_SetOperationState",
        ]);
        let process = ProcessKey::from_pid(100);
        let mut state = State::new(&p);
        state.observe(&open(&p, 7, 3));
        state.observe(&mechanism(&p, "C_SignInit", 7, 1, 0));

        let mut failed_login = event(&p, "C_Login", 7, CkRv::PIN_INCORRECT.0);
        failed_login.user_type = 1;
        state.observe(&failed_login);
        assert!(state.logins().is_empty());
        assert!(
            state
                .active_ops
                .contains_key(&(process, sess(7), operation::SIGN))
        );

        let mut context_login = event(&p, "C_Login", 7, 0);
        context_login.user_type = 2;
        state.observe(&context_login);
        assert!(
            state
                .active_ops
                .contains_key(&(process, sess(7), operation::SIGN))
        );

        let mut cancel = event(&p, "C_SessionCancel", 7, CkRv::OPERATION_CANCEL_FAILED.0);
        cancel.flags = CKF_SIGN | CKF_DIGEST;
        state.observe(&cancel);
        assert!(
            !state
                .active_ops
                .contains_key(&(process, sess(7), operation::SIGN))
        );
        assert_eq!(state.semantic_evidence().session_cancel_ambiguities, 1);

        state.observe(&mechanism(&p, "C_SignInit", 7, 2, 0));
        state.observe(&event(&p, "C_SetOperationState", 7, 0));
        assert!(
            !state
                .active_ops
                .contains_key(&(process, sess(7), operation::SIGN))
        );
        assert_eq!(state.semantic_evidence().operation_state_imports, 1);

        state.observe(&mechanism(&p, "C_SignInit", 7, 3, 0));
        state.observe(&event(&p, "C_Sign", 7, CkRv::OPERATION_NOT_INITIALIZED.0));
        assert_eq!(state.semantic_evidence().state_reconciliations, 1);

        state.observe(&mechanism(&p, "C_SignInit", 7, 4, 0));
        let mut login = event(&p, "C_Login", 7, 0);
        login.user_type = 1;
        state.observe(&login);
        assert_eq!(state.logins()[&1], 1);
        assert_eq!(state.semantic_evidence().auth_state_ambiguities, 1);
    }

    #[test]
    fn close_finalize_pid_reuse_and_fork_copy_only_proven_state() {
        let p = plan_with_fork(
            &["C_OpenSession", "C_SignInit", "C_Sign", "C_Finalize"],
            true,
        );
        let parent = ProcessKey {
            pid: 100,
            generation: 1,
        };
        let child = ProcessKey {
            pid: 101,
            generation: 1,
        };
        let reused = ProcessKey {
            pid: 100,
            generation: 2,
        };
        let mut state = State::new(&p);
        state.observe_process(parent, &open(&p, 7, 3));
        state.observe_process(parent, &mechanism(&p, "C_SignInit", 7, 1, 0));
        state.fork_process(parent, child);
        state.observe_process(child, &event(&p, "C_Sign", 7, 0));
        assert_eq!(state.sessions().inherited, 1);
        assert_eq!(state.mechanisms()[&1].calls, 2);

        state.observe_process(reused, &event(&p, "C_Finalize", SESSION_NONE, 0));
        assert!(state.session_pseudonym_process(parent, 0, 7).is_none());

        let unsafe_plan = plan_with_fork(&["C_OpenSession", "C_SignInit", "C_Sign"], false);
        let mut unsafe_state = State::new(&unsafe_plan);
        unsafe_state.observe_process(parent, &open(&unsafe_plan, 7, 3));
        unsafe_state.observe_process(parent, &mechanism(&unsafe_plan, "C_SignInit", 7, 1, 0));
        unsafe_state.fork_process(parent, child);
        unsafe_state.observe_process(child, &event(&unsafe_plan, "C_Sign", 7, 0));
        assert_eq!(unsafe_state.semantic_evidence().fork_state_ambiguities, 1);
    }

    /// `close_finalize_pid_reuse_and_fork_copy_only_proven_state` observes
    /// `C_Finalize` as a *reused* pid, so the pid-reuse hook retires the state
    /// before `apply_lifecycle` ever sees the event. This one reaches the
    /// FINALIZE arm itself: one module finalizing clears its own state.
    #[test]
    fn finalize_retires_the_finalizing_modules_own_state() {
        let p = plan(&[
            "C_OpenSession",
            "C_SignInit",
            "C_FindObjectsInit",
            "C_AsyncGetID",
            "C_Finalize",
        ]);
        let process = ProcessKey::from_pid(100);
        let mut state = State::new(&p);
        state.observe(&open(&p, 7, 3));
        state.observe(&mechanism(&p, "C_SignInit", 7, 1, 0));
        // An async id detached from its session: still joinable, until the
        // module that issued it finalizes.
        state.observe(&event(&p, "C_FindObjectsInit", 7, CkRv::PENDING.0));
        let mut get_id = event(&p, "C_AsyncGetID", 7, CkRv::OK.0);
        get_id.target_function = crate::kinds::function_id("C_FindObjectsInit").unwrap();
        get_id.async_value = 42;
        state.observe(&get_id);
        assert!(state.has_process_state(process));
        assert_eq!(state.pending_at_end(), 1);

        state.observe(&event(&p, "C_Finalize", SESSION_NONE, 0));
        assert!(!state.has_process_state(process));
        assert_eq!(state.sessions().closed, 1);
        assert_eq!(
            state.pending_at_end(),
            0,
            "the module's async ids die with its Cryptoki, not at capture end"
        );
    }

    /// `detached` is keyed by module, and a `ModuleId` is plan-global: every
    /// process mapping the same provider shares it. One process finalizing
    /// that provider says nothing about another process's async operations.
    #[test]
    fn one_processs_finalize_leaves_another_processs_async_state() {
        let p = plan(&[
            "C_OpenSession",
            "C_CloseSession",
            "C_FindObjectsInit",
            "C_AsyncGetID",
            "C_AsyncJoin",
            "C_AsyncComplete",
            "C_Finalize",
        ]);
        let find_init = crate::kinds::function_id("C_FindObjectsInit").unwrap();
        let a = ProcessKey::from_pid(100);
        let b = ProcessKey::from_pid(200);
        let mut state = State::new(&p);

        // B detaches an async operation, then closes the session holding it:
        // the record is now floating — joinable, owned by no session.
        state.observe_process(b, &open(&p, 9, 3));
        state.observe_process(b, &event(&p, "C_FindObjectsInit", 9, CkRv::PENDING.0));
        let mut get_id = event(&p, "C_AsyncGetID", 9, CkRv::OK.0);
        get_id.target_function = find_init;
        get_id.async_value = 42;
        state.observe_process(b, &get_id);
        state.observe_process(b, &event(&p, "C_CloseSession", 9, 0));
        assert_eq!(state.pending_at_end(), 1);

        // A finalizes the same provider in its own process. A floating record
        // names no session, so only the record's own process tells them apart.
        state.observe_process(a, &open(&p, 5, 3));
        state.observe_process(a, &event(&p, "C_Finalize", SESSION_NONE, 0));
        assert_eq!(
            state.pending_at_end(),
            1,
            "B's detached operation is not A's to finalize"
        );
        assert!(state.has_process_state(b), "a joinable id is live state");

        // B re-joins it into a new session and completes it, instead of
        // counting an orphan.
        state.observe_process(b, &open(&p, 11, 3));
        let mut join = event(&p, "C_AsyncJoin", 11, CkRv::OK.0);
        join.target_function = find_init;
        join.async_value = 42;
        state.observe_process(b, &join);
        let mut complete = event(&p, "C_AsyncComplete", 11, CkRv::OK.0);
        complete.target_function = find_init;
        complete.async_value = CkRv::OK.0;
        state.observe_process(b, &complete);
        assert_eq!(state.semantic_evidence().async_orphans, 0);
        assert_eq!(state.pending_at_end(), 0);
    }

    /// A successful `C_AsyncJoin` *assigns* the joining process/session (spec
    /// §"Successful `C_AsyncJoin` assigns the joining process/session"), and
    /// the lookup key is process-blind, so custody can legitimately move
    /// between processes. Custody has to move whole: the record's process must
    /// follow its owner, or the previous holder still gets to destroy it.
    #[test]
    fn a_cross_process_join_moves_custody_off_the_previous_holder() {
        let p = plan(&[
            "C_OpenSession",
            "C_CloseSession",
            "C_FindObjectsInit",
            "C_AsyncGetID",
            "C_AsyncJoin",
            "C_AsyncComplete",
            "C_Finalize",
        ]);
        let find_init = crate::kinds::function_id("C_FindObjectsInit").unwrap();
        let a = ProcessKey::from_pid(100);
        let b = ProcessKey::from_pid(200);
        let mut state = State::new(&p);

        // B detaches an async id, then closes the session holding it.
        state.observe_process(b, &open(&p, 9, 3));
        state.observe_process(b, &event(&p, "C_FindObjectsInit", 9, CkRv::PENDING.0));
        let mut get_id = event(&p, "C_AsyncGetID", 9, CkRv::OK.0);
        get_id.target_function = find_init;
        get_id.async_value = 42;
        state.observe_process(b, &get_id);
        state.observe_process(b, &event(&p, "C_CloseSession", 9, 0));
        assert!(state.has_process_state(b), "B still holds the floating id");

        // A joins it. That hands custody over — B keeps nothing.
        state.observe_process(a, &open(&p, 5, 3));
        let mut join = event(&p, "C_AsyncJoin", 5, CkRv::OK.0);
        join.target_function = find_init;
        join.async_value = 42;
        state.observe_process(a, &join);
        assert!(
            !state.has_process_state(b),
            "the join moved the id off B, so B holds nothing"
        );

        // So B finalizing its own library cannot tear down A's operation.
        state.observe_process(b, &event(&p, "C_Finalize", SESSION_NONE, 0));
        assert_eq!(
            state.pending_at_end(),
            1,
            "A's adopted operation is not B's to finalize"
        );

        let mut complete = event(&p, "C_AsyncComplete", 5, CkRv::OK.0);
        complete.target_function = find_init;
        complete.async_value = CkRv::OK.0;
        state.observe_process(a, &complete);
        assert_eq!(state.semantic_evidence().async_orphans, 0);
        assert_eq!(state.pending_at_end(), 0);
    }

    /// The other half of the same trade: a floating id belonging to the
    /// process that finalizes *is* dropped, because a later `C_Initialize`
    /// there could mint the same key and `C_AsyncJoin` a dead operation.
    #[test]
    fn finalize_drops_its_own_processs_floating_async_ids() {
        let p = plan(&[
            "C_OpenSession",
            "C_CloseSession",
            "C_FindObjectsInit",
            "C_AsyncGetID",
            "C_Finalize",
        ]);
        let process = ProcessKey::from_pid(100);
        let mut state = State::new(&p);
        state.observe(&open(&p, 9, 3));
        state.observe(&event(&p, "C_FindObjectsInit", 9, CkRv::PENDING.0));
        let mut get_id = event(&p, "C_AsyncGetID", 9, CkRv::OK.0);
        get_id.target_function = crate::kinds::function_id("C_FindObjectsInit").unwrap();
        get_id.async_value = 42;
        state.observe(&get_id);
        state.observe(&event(&p, "C_CloseSession", 9, 0));
        assert_eq!(state.pending_at_end(), 1);
        assert!(state.has_process_state(process));

        state.observe(&event(&p, "C_Finalize", SESSION_NONE, 0));
        assert_eq!(state.pending_at_end(), 0);
        assert!(!state.has_process_state(process));
    }

    #[test]
    fn process_retirement_clears_state_without_a_recorded_open() {
        let p = plan_with_fork(
            &[
                "C_OpenSession",
                "C_CloseSession",
                "C_SignInit",
                "C_FindObjectsInit",
            ],
            false,
        );
        let parent = ProcessKey {
            pid: 100,
            generation: 1,
        };
        let child = ProcessKey {
            pid: 101,
            generation: 1,
        };
        let exiting_child = ProcessKey {
            pid: 102,
            generation: 1,
        };
        let mut state = State::new(&p);

        // A capture can begin after the application opened these sessions.
        state.observe_process(parent, &mechanism(&p, "C_SignInit", 7, 1, 0));
        state.observe_process(parent, &event(&p, "C_FindObjectsInit", 8, 0));
        state.observe_process(parent, &open(&p, 9, 3));
        state.fork_process(parent, child);
        state.fork_process(parent, exiting_child);
        assert!(state.has_process_state(parent));
        assert!(state.has_process_state(child));
        assert!(state.has_process_state(exiting_child));

        // Closing an unproven inherited session clears its ambiguity too.
        state.observe_process(child, &event(&p, "C_CloseSession", 9, 0));
        assert!(!state.has_process_state(child));

        state.retire_process(parent);
        state.retire_process(exiting_child);
        assert!(!state.has_process_state(parent));
        assert!(!state.has_process_state(exiting_child));
    }

    #[test]
    fn async_pending_complete_detach_join_and_open_apply_once() {
        let p = plan(&[
            "C_OpenSession",
            "C_CloseSession",
            "C_SignInit",
            "C_SignFinal",
            "C_AsyncComplete",
            "C_AsyncGetID",
            "C_AsyncJoin",
        ]);
        let process = ProcessKey::from_pid(100);
        let mut state = State::new(&p);

        let mut pending_open = open(&p, 7, 3);
        pending_open.rv = CkRv::PENDING.0;
        pending_open.capture |= capture::ASYNC_SESSION;
        state.observe(&pending_open);
        assert_eq!(state.pending_at_end(), 1);
        let mut complete_open = event(&p, "C_AsyncComplete", 7, 0);
        complete_open.target_function = crate::kinds::function_id("C_OpenSession").unwrap();
        complete_open.async_value = CkRv::OK.0;
        state.observe(&complete_open);
        assert_eq!(state.sessions().opened, 1);
        assert_eq!(state.sessions().async_opened, 1);

        let mut pending_init = mechanism(&p, "C_SignInit", 7, 0x101, CkRv::PENDING.0);
        pending_init.ts_ns = 200;
        state.observe(&pending_init);
        let mut complete_init = event(&p, "C_AsyncComplete", 7, 0);
        complete_init.target_function = crate::kinds::function_id("C_SignInit").unwrap();
        // CK_ASYNC_DATA.ulValue is an output size, not the completed CK_RV.
        complete_init.async_value = CkRv::GENERAL_ERROR.0;
        complete_init.ts_ns = 300;
        state.observe(&complete_init);
        assert!(
            state
                .active_ops
                .contains_key(&(process, sess(7), operation::SIGN))
        );

        let mut pending_final = event(&p, "C_SignFinal", 7, CkRv::PENDING.0);
        pending_final.ts_ns = 400;
        state.observe(&pending_final);
        let mut get_id = event(&p, "C_AsyncGetID", 7, 0);
        get_id.target_function = crate::kinds::function_id("C_SignFinal").unwrap();
        get_id.async_value = 42;
        state.observe(&get_id);
        state.observe(&event(&p, "C_CloseSession", 7, 0));

        state.observe(&open(&p, 8, 3));
        let mut join = event(&p, "C_AsyncJoin", 8, 0);
        join.target_function = crate::kinds::function_id("C_SignFinal").unwrap();
        join.async_value = 42;
        state.observe(&join);
        let mut complete_final = event(&p, "C_AsyncComplete", 8, 0);
        complete_final.target_function = crate::kinds::function_id("C_SignFinal").unwrap();
        complete_final.async_value = CkRv::OK.0;
        complete_final.ts_ns = 500;
        state.observe(&complete_final);
        assert_eq!(state.pending_at_end(), 0);
        assert!(
            !state
                .active_ops
                .contains_key(&(process, sess(8), operation::SIGN))
        );

        state.observe(&complete_final);
        assert_eq!(state.semantic_evidence().async_orphans, 1);
    }

    #[test]
    fn async_complete_uses_its_return_value_and_consumes_failed_completions() {
        let p = plan(&["C_SignInit", "C_AsyncComplete"]);
        let process = ProcessKey::from_pid(100);
        let mut state = State::new(&p);

        state.observe(&mechanism(&p, "C_SignInit", 7, 0x101, CkRv::PENDING.0));
        let mut complete = event(&p, "C_AsyncComplete", 7, CkRv::GENERAL_ERROR.0);
        complete.target_function = crate::kinds::function_id("C_SignInit").unwrap();
        complete.async_value = CkRv::OK.0;
        state.observe(&complete);

        assert_eq!(state.pending_at_end(), 0);
        assert!(
            !state
                .active_ops
                .contains_key(&(process, sess(7), operation::SIGN))
        );
        assert_eq!(state.mechanisms()[&0x101].errors, 1);
    }

    #[test]
    fn session_cancel_removes_detached_find_init() {
        let p = plan(&[
            "C_OpenSession",
            "C_FindObjectsInit",
            "C_AsyncGetID",
            "C_SessionCancel",
        ]);
        let mut state = State::new(&p);
        state.observe(&open(&p, 7, 3));
        state.observe(&event(&p, "C_FindObjectsInit", 7, CkRv::PENDING.0));

        let mut get_id = event(&p, "C_AsyncGetID", 7, CkRv::OK.0);
        get_id.target_function = crate::kinds::function_id("C_FindObjectsInit").unwrap();
        get_id.async_value = 42;
        state.observe(&get_id);
        assert_eq!(state.pending_at_end(), 1);

        let mut cancel = event(&p, "C_SessionCancel", 7, CkRv::OK.0);
        cancel.flags = CKF_FIND_OBJECTS;
        state.observe(&cancel);
        assert_eq!(state.pending_at_end(), 0);
    }

    #[test]
    fn conclusive_find_objects_error_clears_search_presence() {
        let p = plan(&["C_FindObjectsInit", "C_FindObjects"]);
        let process = ProcessKey::from_pid(100);
        let mut state = State::new(&p);
        state.observe(&event(&p, "C_FindObjectsInit", 7, CkRv::OK.0));
        assert!(state.find_active.contains(&(process, sess(7))));

        state.observe(&event(
            &p,
            "C_FindObjects",
            7,
            CkRv::OPERATION_NOT_INITIALIZED.0,
        ));
        assert!(!state.find_active.contains(&(process, sess(7))));
        assert_eq!(state.semantic_evidence().state_reconciliations, 1);
    }

    #[test]
    fn hostile_semantic_cardinality_is_bounded_and_reported() {
        let p = plan(&[
            "C_OpenSession",
            "C_SignInit",
            "C_GenerateKey",
            "C_Login",
            "C_FindObjectsInit",
        ]);
        let mut state = State::with_limit(&p, 12);
        for value in 0..100u64 {
            let mut opened = open(&p, value + 1, value);
            opened.cgroup_id = value;
            state.observe(&opened);

            let mut init = mechanism(&p, "C_SignInit", value + 1, value, 0);
            init.shape = shape::RSA_PKCS_PSS;
            init.p0 = value;
            state.observe(&init);

            let mut template = mechanism(&p, "C_GenerateKey", value + 1, value, 0);
            template.attr_types[0] = value;
            template.attr_count = 1;
            template.attr_total = 1;
            state.observe(&template);

            let mut login = event(&p, "C_Login", value + 1, 0);
            login.user_type = value as u32;
            state.observe(&login);
            state.observe(&event(&p, "C_FindObjectsInit", value + 1, 0));
        }

        assert!(state.semantic_evidence().semantic_state_drops > 0);
        assert!(
            state.retained_dynamic_keys() <= 12,
            "retained {} keys",
            state.retained_dynamic_keys()
        );
    }
}

/// Aggregate stats for one template-bearing operation (`C_FindObjectsInit`,
/// `C_CreateObject`, `C_GenerateKey`, ...), keyed by attach slot — the same
/// grouping `functions[]` uses, so an aliased slot's calls stay one entry.
/// Carries only what the application *asked for*: attribute types and the
/// policy-boolean allowlist observed on those templates, never a value
/// beyond the allowlisted booleans, and never the key's effective policy
/// (see module docs on the requested-vs-effective distinction).
#[derive(Debug, Clone, PartialEq, Default)]
pub struct TemplateStat {
    /// Every distinct function name resolving to this slot.
    pub names: Vec<String>,
    pub aliased: bool,
    /// `public`/`private` for the two C_GenerateKeyPair templates.
    pub role: Option<&'static str>,
    /// Union of attribute *types* requested across every observed call.
    pub attr_types: BTreeSet<u64>,
    /// Bit set (`attr_bool` positions) => this policy-boolean attribute
    /// was observed present-and-true on at least one call.
    pub bools_true: u32,
    /// Bit set => observed present-and-false on at least one call.
    /// Independent of `bools_true`: a bit can be set in both when
    /// different calls asked for different values, and that is
    /// legitimate, distinguishable evidence, not an error.
    pub bools_false: u32,
    /// True when any observed call had `attr_total > attr_count`: either
    /// the template had more entries than the capture's per-event cap
    /// (`MAX_ATTRS`), or the in-kernel walk stopped early on a
    /// `bpf_probe_read_user` failure (an unreadable `pTemplate`/entry) —
    /// both leave `attr_count` short of `attr_total`, and this field does
    /// not distinguish which. Either way it is lost evidence: some
    /// attribute types the application requested were not captured.
    pub truncated: bool,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct SessionStats {
    pub opened: u64,
    pub inherited: u64,
    pub closed: u64,
    pub async_opened: u64,
    pub peak_concurrent: u64,
}

/// Calls/errors attributed to one mechanism id, scoped to one cgroup — a
/// `CgroupStat::mechanisms` entry. Deliberately a smaller sibling of
/// `MechStat`, not that type reused: per-cgroup breakdown only needs to
/// answer "how much of this cgroup's traffic used this mechanism", not
/// carry its own latency histogram or parameter combos (those stay
/// capture-wide in `State::mechanisms`, the single source for them).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct MechCallStat {
    pub calls: u64,
    pub errors: u64,
}

/// Aggregate stats for one `cgroup_id` — a directory inode number
/// (`docs/privacy/allowlist-v1.md`'s `cgroup_id` entry). Exists so one
/// node-wide attach over a cgroup shared by several containers/pods (e.g.
/// two containers sharing one overlay2 image layer, hence one inode) can
/// still be split back out per container in the report.
#[derive(Debug, Clone, PartialEq, Default)]
pub struct CgroupStat {
    /// Every event observed with this `cgroup_id`, regardless of kind —
    /// the same "every completed call" scope `functions[].calls` uses at
    /// the top level. Not expected to equal the sum of `mechanisms[]`
    /// below, for the same reason `mechanisms[].calls` doesn't sum to
    /// `functions[].calls` capture-wide: session-scoped operational calls
    /// are attributed by mechanism, not every event names one.
    pub calls: u64,
    pub errors: u64,
    /// Mechanism id -> calls/errors seen from this cgroup — the subset of
    /// `calls` above that a mechanism could be attributed to (an `*Init`
    /// call, or a later operational call on a session with an active
    /// mechanism).
    pub mechanisms: BTreeMap<u64, MechCallStat>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub struct ProcessKey {
    pub pid: u32,
    pub generation: u64,
}

impl ProcessKey {
    pub const fn from_pid(pid: u32) -> Self {
        Self { pid, generation: 0 }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct SemanticEvidence {
    pub state_reconciliations: u64,
    pub session_cancel_ambiguities: u64,
    pub session_cancel_unknown_flags: u64,
    pub operation_state_imports: u64,
    pub auth_state_ambiguities: u64,
    pub semantic_capture_failures: u64,
    pub async_target_failures: u64,
    pub async_orphans: u64,
    pub async_duplicates: u64,
    pub async_evictions: u64,
    pub fork_state_ambiguities: u64,
    /// New semantic keys refused after the bounded per-capture budget was
    /// exhausted. Aggregate kernel counts remain authoritative.
    pub semantic_state_drops: u64,
}

/// Reserved module id for a slot no single module owns — unknown, or claimed
/// by two or more modules. Ambiguous slots are `COUNT_ONLY`, so they emit no
/// session-scoped events; the reserved id exists so that if one ever did, its
/// handles could not alias a real module's.
const MODULE_UNRESOLVED: ModuleId = ModuleId(u32::MAX);

/// A session handle scoped to the module that issued it. A PKCS#11 proxy and
/// the backend provider it loads live in one process and each hand out their
/// own handle space, so the proxy's handle 5 is not the backend's handle 5.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
struct SessionRef {
    module: ModuleId,
    handle: u64,
}

#[derive(Clone)]
struct SlotMeta {
    names: Vec<String>,
    aliased: bool,
    semantics: p11scope_ebpf_common::SlotSemantics,
    function_id: Option<u32>,
    fork_safe: bool,
    module: ModuleId,
    module_ids: Vec<ModuleId>,
}

impl SlotMeta {
    fn session(&self, handle: u64) -> SessionRef {
        SessionRef {
            module: self.module,
            handle,
        }
    }
}

/// The one predicate every scoped query and sweep runs on: the `ProcessKey`
/// always has to match, and `Some(module)` narrows it to the handles that one
/// module issued. Defined once so `has_scope_state` and `retire_scope` cannot
/// drift into disagreeing about what "this scope's state" means.
fn scoped(
    process: ProcessKey,
    module: Option<ModuleId>,
) -> impl Fn(&ProcessKey, &SessionRef) -> bool {
    move |owner, session| *owner == process && module.is_none_or(|id| session.module == id)
}

/// The same scoping question for the async-id map, which is keyed by module
/// and carries its process on the record rather than in the key. Separate
/// because the key shape differs; shared between the query and the sweep for
/// the same reason `scoped` is.
fn scoped_detached(
    process: ProcessKey,
    module: Option<ModuleId>,
) -> impl Fn(&ModuleId, &Detached) -> bool {
    move |id, detached| detached.process == process && module.is_none_or(|m| *id == m)
}

#[derive(Clone, Copy)]
struct SessionInfo {
    pseudonym: u64,
    slot: u64,
    fork_safe: bool,
}

#[derive(Clone, Copy)]
struct Binding {
    mechanism: u64,
    fork_safe: bool,
}

#[derive(Clone)]
struct Pending {
    event: Event,
    meta: SlotMeta,
    started_ns: u64,
    sequence: u64,
}

#[derive(Clone)]
struct Detached {
    pending: Pending,
    /// The session currently holding this async id. `None` means detached and
    /// joinable — `C_AsyncJoin` re-adopts it into another session — which is a
    /// live state, not a dead one.
    owner: Option<(ProcessKey, SessionRef)>,
    /// The process holding the id — the one that issued it, or the one a
    /// `C_AsyncJoin` handed it to. The map key is `(ModuleId, ...)` and a
    /// `ModuleId` is plan-global, so without this a floating record could not
    /// be told apart from another process's.
    ///
    /// Invariant: `owner.is_some() => owner.0 == process`. Both write sites —
    /// the `ASYNC_GET_ID` insert and the `ASYNC_JOIN` assignment — set the two
    /// together; `owner` is only ever cleared to `None`, never reassigned to a
    /// different process on its own.
    process: ProcessKey,
}

const OPERATIONS: [(u16, &str); 11] = [
    (operation::DIGEST, "digest"),
    (operation::SIGN, "sign"),
    (operation::VERIFY, "verify"),
    (operation::ENCRYPT, "encrypt"),
    (operation::DECRYPT, "decrypt"),
    (operation::SIGN_RECOVER, "sign_recover"),
    (operation::VERIFY_RECOVER, "verify_recover"),
    (operation::MESSAGE_ENCRYPT, "message_encrypt"),
    (operation::MESSAGE_DECRYPT, "message_decrypt"),
    (operation::MESSAGE_SIGN, "message_sign"),
    (operation::MESSAGE_VERIFY, "message_verify"),
];

const CKF_MESSAGE_ENCRYPT: u64 = 0x0000_0002;
const CKF_MESSAGE_DECRYPT: u64 = 0x0000_0004;
const CKF_MESSAGE_SIGN: u64 = 0x0000_0008;
const CKF_MESSAGE_VERIFY: u64 = 0x0000_0010;
const CKF_FIND_OBJECTS: u64 = 0x0000_0040;
const CKF_ENCRYPT: u64 = 0x0000_0100;
const CKF_DECRYPT: u64 = 0x0000_0200;
const CKF_DIGEST: u64 = 0x0000_0400;
const CKF_SIGN: u64 = 0x0000_0800;
const CKF_SIGN_RECOVER: u64 = 0x0000_1000;
const CKF_VERIFY: u64 = 0x0000_2000;
const CKF_VERIFY_RECOVER: u64 = 0x0000_4000;
const CKF_GENERATE: u64 = 0x0000_8000;
const CKF_GENERATE_KEY_PAIR: u64 = 0x0001_0000;
const CKF_WRAP: u64 = 0x0002_0000;
const CKF_UNWRAP: u64 = 0x0004_0000;
const CKF_DERIVE: u64 = 0x0008_0000;
const CKF_ENCAPSULATE: u64 = 0x1000_0000;
const CKF_DECAPSULATE: u64 = 0x2000_0000;
const KNOWN_CANCEL_FLAGS: u64 = CKF_MESSAGE_ENCRYPT
    | CKF_MESSAGE_DECRYPT
    | CKF_MESSAGE_SIGN
    | CKF_MESSAGE_VERIFY
    | CKF_FIND_OBJECTS
    | CKF_ENCRYPT
    | CKF_DECRYPT
    | CKF_DIGEST
    | CKF_SIGN
    | CKF_SIGN_RECOVER
    | CKF_VERIFY
    | CKF_VERIFY_RECOVER
    | CKF_GENERATE
    | CKF_GENERATE_KEY_PAIR
    | CKF_WRAP
    | CKF_UNWRAP
    | CKF_DERIVE
    | CKF_ENCAPSULATE
    | CKF_DECAPSULATE;
const MAX_PENDING: usize = 16_384;
const MAX_STATE_KEYS: usize = 16_384;

fn pid_of(ev: &Event) -> u32 {
    (ev.pid_tgid >> 32) as u32
}

fn operation_bits(mask: u16) -> impl Iterator<Item = (u16, &'static str)> {
    OPERATIONS
        .into_iter()
        .filter(move |(bit, _)| mask & bit != 0)
}

fn direct_name(value: u8) -> Option<&'static str> {
    match value {
        direct::GENERATE_KEY => Some("generate_key"),
        direct::GENERATE_KEY_PAIR => Some("generate_key_pair"),
        direct::WRAP => Some("wrap"),
        direct::UNWRAP => Some("unwrap"),
        direct::DERIVE => Some("derive"),
        direct::ENCAPSULATE => Some("encapsulate"),
        direct::DECAPSULATE => Some("decapsulate"),
        direct::WRAP_AUTHENTICATED => Some("wrap_authenticated"),
        direct::UNWRAP_AUTHENTICATED => Some("unwrap_authenticated"),
        _ => None,
    }
}

fn direct_cancel_flag(value: u8) -> u64 {
    match value {
        direct::GENERATE_KEY => CKF_GENERATE,
        direct::GENERATE_KEY_PAIR => CKF_GENERATE_KEY_PAIR,
        direct::WRAP | direct::WRAP_AUTHENTICATED => CKF_WRAP,
        direct::UNWRAP | direct::UNWRAP_AUTHENTICATED => CKF_UNWRAP,
        direct::DERIVE => CKF_DERIVE,
        direct::ENCAPSULATE => CKF_ENCAPSULATE,
        direct::DECAPSULATE => CKF_DECAPSULATE,
        _ => 0,
    }
}

fn cancel_operation_mask(flags: u64) -> u16 {
    let mut mask = 0;
    for (flag, operation) in [
        (CKF_MESSAGE_ENCRYPT, operation::MESSAGE_ENCRYPT),
        (CKF_MESSAGE_DECRYPT, operation::MESSAGE_DECRYPT),
        (CKF_MESSAGE_SIGN, operation::MESSAGE_SIGN),
        (CKF_MESSAGE_VERIFY, operation::MESSAGE_VERIFY),
        (CKF_ENCRYPT, operation::ENCRYPT),
        (CKF_DECRYPT, operation::DECRYPT),
        (CKF_DIGEST, operation::DIGEST),
        (CKF_SIGN, operation::SIGN),
        (CKF_SIGN_RECOVER, operation::SIGN_RECOVER),
        (CKF_VERIFY, operation::VERIFY),
        (CKF_VERIFY_RECOVER, operation::VERIFY_RECOVER),
    ] {
        if flags & flag != 0 {
            mask |= operation;
        }
    }
    mask
}

enum MechanismCapture {
    Absent,
    Null,
    Unreadable,
    Value(u64),
}

fn mechanism_capture(ev: &Event) -> MechanismCapture {
    match ev.capture & capture::MECHANISM_MASK {
        capture::MECHANISM_NULL => MechanismCapture::Null,
        capture::MECHANISM_UNREADABLE => MechanismCapture::Unreadable,
        capture::MECHANISM_VALUE => MechanismCapture::Value(ev.mechanism),
        _ => MechanismCapture::Absent,
    }
}

/// Pseudonymized semantic state. Raw handles and async ids remain private map keys.
pub struct State {
    policy: CapturePolicy,
    slots: Vec<Option<SlotMeta>>,
    current_process: BTreeMap<u32, ProcessKey>,
    next_pseudonym: BTreeMap<ProcessKey, u64>,
    open: BTreeMap<(ProcessKey, SessionRef), SessionInfo>,
    active_ops: BTreeMap<(ProcessKey, SessionRef, u16), Binding>,
    find_active: BTreeSet<(ProcessKey, SessionRef)>,
    inherited_ambiguous: BTreeSet<(ProcessKey, SessionRef)>,
    pending: BTreeMap<(ProcessKey, SessionRef, u32), Pending>,
    /// Async ids are only unique within one module's PKCS#11 slot, so the
    /// issuing module is part of the key here too.
    detached: BTreeMap<(ModuleId, u64, u32, u64), Detached>,
    sequence: u64,
    mechanisms: BTreeMap<u64, MechStat>,
    templates: BTreeMap<(u32, u8), TemplateStat>,
    logins: BTreeMap<u32, u64>,
    sessions: SessionStats,
    cgroups: BTreeMap<u64, CgroupStat>,
    orphan_ops: u64,
    unmatched_closes: u64,
    evidence: SemanticEvidence,
    mech_shapes: BTreeMap<u64, u32>,
    state_key_limit: usize,
    state_keys: usize,
}

fn slot_metadata(plan: &AttachPlan) -> Vec<Option<SlotMeta>> {
    let mut slots = Vec::new();
    for slot in &plan.slots {
        let index = slot.index as usize;
        if index >= slots.len() {
            slots.resize_with(index + 1, || None);
        }
        if !plan.is_active(slot.index) {
            continue;
        }
        slots[index] = Some(SlotMeta {
            names: slot.names.clone(),
            aliased: slot.aliased,
            semantics: plan.effective_semantics(slot),
            function_id: (slot.names.len() == 1)
                .then(|| crate::kinds::function_id(&slot.names[0]))
                .flatten(),
            fork_safe: slot.fork_safe,
            module: plan.module_of_slot(slot.index).unwrap_or(MODULE_UNRESOLVED),
            module_ids: slot.module_ids.clone(),
        });
    }
    slots
}

fn slot_semantics_changed(previous: &SlotMeta, next: Option<&SlotMeta>) -> bool {
    let Some(next) = next else {
        return true;
    };
    previous.semantics != next.semantics
        || previous.function_id != next.function_id
        || previous.fork_safe != next.fork_safe
        || previous.module != next.module
        || previous.module_ids != next.module_ids
}

impl State {
    pub fn new(plan: &AttachPlan) -> Self {
        Self::with_policy(plan, CapturePolicy::Allowlisted)
    }

    pub fn with_policy(plan: &AttachPlan, policy: CapturePolicy) -> Self {
        Self::with_key_limit(plan, policy, MAX_STATE_KEYS)
    }

    #[cfg(test)]
    fn with_limit(plan: &AttachPlan, limit: usize) -> Self {
        Self::with_key_limit(plan, CapturePolicy::Allowlisted, limit)
    }

    fn with_key_limit(plan: &AttachPlan, policy: CapturePolicy, state_key_limit: usize) -> Self {
        Self {
            policy,
            slots: slot_metadata(plan),
            current_process: BTreeMap::new(),
            next_pseudonym: BTreeMap::new(),
            open: BTreeMap::new(),
            active_ops: BTreeMap::new(),
            find_active: BTreeSet::new(),
            inherited_ambiguous: BTreeSet::new(),
            pending: BTreeMap::new(),
            detached: BTreeMap::new(),
            sequence: 0,
            mechanisms: BTreeMap::new(),
            templates: BTreeMap::new(),
            logins: BTreeMap::new(),
            sessions: SessionStats::default(),
            cgroups: BTreeMap::new(),
            orphan_ops: 0,
            unmatched_closes: 0,
            evidence: SemanticEvidence::default(),
            mech_shapes: BTreeMap::new(),
            state_key_limit,
            state_keys: 0,
        }
    }

    /// Replaces the plan snapshot used for future events. A descriptor or
    /// ownership change invalidates any semantic state that the old slot may
    /// have produced, so it is purged before this method returns.
    pub fn sync_plan(&mut self, plan: &AttachPlan) {
        let slots = slot_metadata(plan);
        let mut affected = BTreeSet::new();
        for (index, previous) in self.slots.iter().enumerate() {
            let Some(previous) = previous else {
                continue;
            };
            let next = slots.get(index).and_then(Option::as_ref);
            if slot_semantics_changed(previous, next) {
                affected.extend(previous.module_ids.iter().copied());
                if let Some(next) = next {
                    affected.extend(next.module_ids.iter().copied());
                }
            }
        }
        self.slots = slots;
        self.purge_modules(&affected);
    }

    /// Removes state attached to the listed modules across every observed
    /// process without manufacturing close/reconciliation events. The derived
    /// semantic aggregates are intentionally cleared too: they lack a module
    /// dimension, so retaining them could preserve facts from a downgraded
    /// descriptor. Kernel aggregate counters remain in their BPF maps.
    pub fn purge_modules(&mut self, modules: &BTreeSet<ModuleId>) {
        if modules.is_empty() {
            return;
        }
        self.evidence.state_reconciliations += 1;
        let mut processes = BTreeSet::new();
        processes.extend(self.current_process.values().copied());
        processes.extend(self.next_pseudonym.keys().copied());
        processes.extend(self.open.keys().map(|(process, _)| *process));
        processes.extend(self.active_ops.keys().map(|(process, _, _)| *process));
        processes.extend(self.find_active.iter().map(|(process, _)| *process));
        processes.extend(self.inherited_ambiguous.iter().map(|(process, _)| *process));
        processes.extend(self.pending.keys().map(|(process, _, _)| *process));
        processes.extend(self.detached.values().map(|detached| detached.process));
        for process in processes {
            for module in modules {
                self.clear_scope(process, Some(*module), false);
            }
        }
        self.mechanisms.clear();
        self.templates.clear();
        self.logins.clear();
        self.cgroups.clear();
        self.sessions = SessionStats::default();
        self.orphan_ops = 0;
        self.unmatched_closes = 0;
    }

    // ponytail: admissions are a monotonic per-capture budget. Replace with
    // counted eviction only if long captures routinely exhaust 16K keys.
    fn admit(&mut self, new_keys: usize) -> bool {
        if new_keys == 0 {
            return true;
        }
        match self.state_keys.checked_add(new_keys) {
            Some(total) if total <= self.state_key_limit => {
                self.state_keys = total;
                true
            }
            _ => {
                self.evidence.semantic_state_drops += 1;
                false
            }
        }
    }

    #[cfg(test)]
    fn retained_dynamic_keys(&self) -> usize {
        self.current_process.len()
            + self.next_pseudonym.len()
            + self.open.len()
            + self.active_ops.len()
            + self.find_active.len()
            + self.inherited_ambiguous.len()
            + self.mechanisms.len()
            + self
                .mechanisms
                .values()
                .map(|stat| stat.param_combos.len())
                .sum::<usize>()
            + self.templates.len()
            + self
                .templates
                .values()
                .map(|stat| stat.attr_types.len())
                .sum::<usize>()
            + self.logins.len()
            + self.cgroups.len()
            + self
                .cgroups
                .values()
                .map(|stat| stat.mechanisms.len())
                .sum::<usize>()
    }

    pub fn set_mech_shapes(&mut self, mech_shapes: BTreeMap<u64, u32>) {
        self.mech_shapes = mech_shapes;
    }

    pub fn observe(&mut self, ev: &Event) {
        if ev.event_type == event_type::FORK {
            self.fork_process(
                ProcessKey::from_pid(pid_of(ev)),
                ProcessKey::from_pid(ev.session as u32),
            );
            return;
        }
        let process = self
            .current_process
            .get(&pid_of(ev))
            .copied()
            .unwrap_or_else(|| ProcessKey::from_pid(pid_of(ev)));
        self.observe_process(process, ev);
    }

    pub fn observe_process(&mut self, process: ProcessKey, ev: &Event) {
        let previous = self.current_process.get(&process.pid).copied();
        if previous != Some(process) && self.admit(usize::from(previous.is_none())) {
            if let Some(old) = previous {
                self.retire_process(old);
            }
            self.current_process.insert(process.pid, process);
        }
        let meta = self.slots.get(ev.slot as usize).and_then(Clone::clone);
        if !self.cgroups.contains_key(&ev.cgroup_id) && self.admit(1) {
            self.cgroups.insert(ev.cgroup_id, CgroupStat::default());
        }
        if let Some(cg) = self.cgroups.get_mut(&ev.cgroup_id) {
            cg.calls += 1;
            if ev.rv != CkRv::OK.0 && ev.rv != CkRv::PENDING.0 {
                cg.errors += 1;
            }
        }
        let Some(meta) = meta else { return };
        if meta.semantics == p11scope_ebpf_common::SlotSemantics::COUNT_ONLY {
            return;
        }

        if ev.session != SESSION_NONE
            && self
                .inherited_ambiguous
                .remove(&(process, meta.session(ev.session)))
        {
            self.evidence.fork_state_ambiguities += 1;
        }
        if matches!(
            meta.semantics.lifecycle,
            lifecycle::ASYNC_COMPLETE | lifecycle::ASYNC_GET_ID | lifecycle::ASYNC_JOIN
        ) {
            self.observe_async(process, ev);
            return;
        }
        if ev.rv == CkRv::PENDING.0 {
            self.queue_pending(process, ev, meta);
            return;
        }
        self.apply_completed(process, ev, &meta, false);
    }

    fn apply_completed(
        &mut self,
        process: ProcessKey,
        ev: &Event,
        meta: &SlotMeta,
        was_pending: bool,
    ) {
        self.observe_templates(ev, meta);
        if (meta.semantics.transition == transition::INITIALIZE
            || meta.semantics.direct != direct::NONE)
            && (self.policy.uses_unsafe_decoders() || was_pending || ev.rv == CkRv::OK.0)
        {
            self.record_requested_mechanism(ev, meta);
        }
        if meta.semantics.lifecycle == lifecycle::LOGIN
            && ev.rv == CkRv::OK.0
            && ev.user_type != USER_TYPE_NONE
        {
            if !self.logins.contains_key(&ev.user_type) && self.admit(1) {
                self.logins.insert(ev.user_type, 0);
            }
            if let Some(calls) = self.logins.get_mut(&ev.user_type) {
                *calls += 1;
            }
        }
        if self.reconcile_conclusive(process, ev, meta) {
            return;
        }
        self.apply_lifecycle(process, ev, meta);
        if meta.semantics.transition == transition::INITIALIZE {
            self.apply_init(process, ev, meta);
        } else if meta.semantics.direct == direct::NONE && meta.semantics.operations != 0 {
            self.apply_operations(process, ev, meta);
        }
    }

    fn record_requested_mechanism(&mut self, ev: &Event, meta: &SlotMeta) {
        let MechanismCapture::Value(mechanism) = mechanism_capture(ev) else {
            return;
        };
        if !self.mechanisms.contains_key(&mechanism) && self.admit(1) {
            self.mechanisms.insert(mechanism, MechStat::default());
        }
        let Some(stat) = self.mechanisms.get_mut(&mechanism) else {
            return;
        };
        record_call(stat, ev);
        stat.ops
            .extend(operation_bits(meta.semantics.operations).map(|(_, name)| name.to_string()));
        if let Some(name) = direct_name(meta.semantics.direct) {
            stat.ops.insert(name.to_string());
        }
        if self.policy.uses_unsafe_decoders() {
            let combo = (ev.shape, ev.p0, ev.p1, ev.p2);
            if ev.shape == shape::NONE {
                stat.init_no_shape += 1;
            } else if stat.param_combos.contains_key(&combo) {
                *stat.param_combos.get_mut(&combo).unwrap() += 1;
            } else {
                let _ = stat;
                if self.admit(1) {
                    self.mechanisms
                        .get_mut(&mechanism)
                        .unwrap()
                        .param_combos
                        .insert(combo, 1);
                }
            }
        }
        self.record_cgroup_mechanism(ev.cgroup_id, mechanism, ev.rv);
    }

    fn apply_init(&mut self, process: ProcessKey, ev: &Event, meta: &SlotMeta) {
        if ev.rv != CkRv::OK.0 || ev.session == SESSION_NONE {
            return;
        }
        for (operation, _) in operation_bits(meta.semantics.operations) {
            let key = (process, meta.session(ev.session), operation);
            match mechanism_capture(ev) {
                MechanismCapture::Value(mechanism) => {
                    if self.active_ops.contains_key(&key) || self.admit(1) {
                        self.active_ops.insert(
                            key,
                            Binding {
                                mechanism,
                                fork_safe: meta.fork_safe,
                            },
                        );
                    }
                }
                MechanismCapture::Null => {
                    self.active_ops.remove(&key);
                    if meta.semantics.semantic_flags & semantic_flags::NULL_MECHANISM_CANCEL == 0 {
                        self.evidence.semantic_capture_failures += 1;
                    }
                }
                MechanismCapture::Unreadable | MechanismCapture::Absent => {
                    self.active_ops.remove(&key);
                }
            }
        }
    }

    fn apply_operations(&mut self, process: ProcessKey, ev: &Event, meta: &SlotMeta) {
        let mut mechanisms = BTreeSet::new();
        for (operation, _) in operation_bits(meta.semantics.operations) {
            match self
                .active_ops
                .get(&(process, meta.session(ev.session), operation))
            {
                Some(binding) => {
                    mechanisms.insert(binding.mechanism);
                }
                None => self.orphan_ops += 1,
            }
        }
        for mechanism in mechanisms {
            if !self.mechanisms.contains_key(&mechanism) && self.admit(1) {
                self.mechanisms.insert(mechanism, MechStat::default());
            }
            if let Some(stat) = self.mechanisms.get_mut(&mechanism) {
                record_call(stat, ev);
            }
            self.record_cgroup_mechanism(ev.cgroup_id, mechanism, ev.rv);
        }

        let retain = match meta.semantics.transition {
            transition::CONTINUE => ev.rv == CkRv::OK.0,
            transition::UPDATE_WITH_OUTPUT => {
                ev.rv == CkRv::OK.0 || ev.rv == CkRv::BUFFER_TOO_SMALL.0
            }
            transition::FINISH_WITH_OUTPUT => {
                ev.rv == CkRv::BUFFER_TOO_SMALL.0
                    || (ev.rv == CkRv::OK.0
                        && ev.capture & capture::OUTPUT_MASK == capture::OUTPUT_NULL)
            }
            transition::FINISH_ALWAYS => false,
            transition::RETAIN_ALWAYS => true,
            transition::FINISH_ON_SUCCESS => ev.rv != CkRv::OK.0,
            _ => true,
        };
        if !retain {
            for (operation, _) in operation_bits(meta.semantics.operations) {
                self.active_ops
                    .remove(&(process, meta.session(ev.session), operation));
            }
        }
    }

    fn reconcile_conclusive(&mut self, process: ProcessKey, ev: &Event, meta: &SlotMeta) -> bool {
        if ev.rv == CkRv::OPERATION_NOT_INITIALIZED.0 {
            let mut changed = false;
            for (operation, _) in operation_bits(meta.semantics.operations) {
                changed |= self
                    .active_ops
                    .remove(&(process, meta.session(ev.session), operation))
                    .is_some();
            }
            if matches!(
                meta.semantics.lifecycle,
                lifecycle::FIND_OPERATION | lifecycle::FIND_FINAL
            ) {
                changed |= self
                    .find_active
                    .remove(&(process, meta.session(ev.session)));
            }
            self.evidence.state_reconciliations += u64::from(changed);
            return true;
        }
        if matches!(ev.rv, 0x0000_00b0 | 0x0000_00b3) {
            let changed = self.retire_session(process, meta.session(ev.session));
            self.evidence.state_reconciliations += u64::from(changed);
            return true;
        }
        if ev.rv == CkRv::CRYPTOKI_NOT_INITIALIZED.0 {
            // One library says it was never initialized or is already
            // finalized. That is news about the module that answered, not
            // about any other module sharing the process — and an ambiguous
            // slot, whose module is `MODULE_UNRESOLVED`, gets to destroy
            // nothing rather than everything.
            let changed = self.retire_scope(process, Some(meta.module)) > 0;
            self.evidence.state_reconciliations += u64::from(changed);
            return true;
        }
        false
    }

    fn apply_lifecycle(&mut self, process: ProcessKey, ev: &Event, meta: &SlotMeta) {
        let session = meta.session(ev.session);
        match meta.semantics.lifecycle {
            lifecycle::OPEN_SESSION if ev.rv == CkRv::OK.0 && ev.session != SESSION_NONE => {
                if self.retire_session(process, session) {
                    self.evidence.state_reconciliations += 1;
                }
                let async_session = ev.capture & capture::ASYNC_SESSION != 0;
                self.sessions.opened += 1;
                self.sessions.async_opened += u64::from(async_session);
                let counter_new = !self.next_pseudonym.contains_key(&process);
                if self.admit(1 + usize::from(counter_new)) {
                    let counter = self.next_pseudonym.entry(process).or_default();
                    *counter += 1;
                    self.open.insert(
                        (process, session),
                        SessionInfo {
                            pseudonym: *counter,
                            slot: ev.slot_id,
                            fork_safe: meta.fork_safe,
                        },
                    );
                    self.update_peak();
                }
            }
            lifecycle::CLOSE_SESSION if ev.rv == CkRv::OK.0 => {
                if !self.retire_session(process, session) {
                    self.unmatched_closes += 1;
                }
            }
            lifecycle::CLOSE_ALL_SESSIONS if ev.rv == CkRv::OK.0 => {
                // Only this module's sessions on that PKCS#11 slot id: another
                // module in the same process numbers its slots independently.
                let owned = scoped(process, Some(meta.module));
                let sessions: Vec<SessionRef> = self
                    .open
                    .iter()
                    .filter(|((owner, open), info)| owned(owner, open) && info.slot == ev.slot_id)
                    .map(|((_, open), _)| *open)
                    .collect();
                for session in sessions {
                    self.retire_session(process, session);
                }
            }
            lifecycle::FINALIZE if ev.rv == CkRv::OK.0 => {
                // C_Finalize ends this module's Cryptoki. Another module in the
                // same process keeps its own sessions and operations.
                self.retire_scope(process, Some(meta.module));
            }
            lifecycle::LOGIN => self.apply_auth(process, ev, meta),
            lifecycle::LOGOUT => self.apply_auth(process, ev, meta),
            lifecycle::FIND_INIT if ev.rv == CkRv::OK.0 => {
                let key = (process, session);
                if self.find_active.contains(&key) || self.admit(1) {
                    self.find_active.insert(key);
                }
            }
            lifecycle::FIND_FINAL if ev.rv == CkRv::OK.0 => {
                self.find_active.remove(&(process, session));
            }
            lifecycle::SESSION_CANCEL => self.apply_session_cancel(process, ev, session),
            lifecycle::SET_OPERATION_STATE if ev.rv == CkRv::OK.0 => {
                self.clear_operations(process, session, u16::MAX);
                self.evidence.operation_state_imports += 1;
            }
            _ => {}
        }
    }

    fn apply_auth(&mut self, process: ProcessKey, ev: &Event, meta: &SlotMeta) {
        let context_specific = meta.names.iter().any(|name| name == "C_Login")
            && ev.user_type == 2
            && ev.rv == CkRv::OK.0;
        if context_specific {
            return;
        }
        if ev.rv != CkRv::OK.0 && ev.rv != CkRv::PIN_LOCKED.0 {
            return;
        }
        let Some(slot) = self
            .open
            .get(&(process, meta.session(ev.session)))
            .map(|info| info.slot)
        else {
            return;
        };
        // The login applies to this module's sessions on that PKCS#11 slot;
        // another module's identically numbered slot is a different token.
        let owned = scoped(process, Some(meta.module));
        let sessions: Vec<SessionRef> = self
            .open
            .iter()
            .filter(|((owner, open), info)| owned(owner, open) && info.slot == slot)
            .map(|((_, open), _)| *open)
            .collect();
        let mut changed = false;
        for session in sessions {
            changed |= self.clear_session_state(process, session);
        }
        self.evidence.auth_state_ambiguities += u64::from(changed);
    }

    fn apply_session_cancel(&mut self, process: ProcessKey, ev: &Event, session: SessionRef) {
        if ev.flags & !KNOWN_CANCEL_FLAGS != 0 {
            self.evidence.session_cancel_unknown_flags += 1;
        }
        let selected = (ev.flags & KNOWN_CANCEL_FLAGS).count_ones();
        if ev.rv == CkRv::OPERATION_CANCEL_FAILED.0 && selected > 1 {
            self.clear_selected(process, session, ev.flags);
            self.evidence.session_cancel_ambiguities += 1;
        } else if ev.rv == CkRv::OK.0 {
            self.clear_selected(process, session, ev.flags);
        }
    }

    fn clear_selected(&mut self, process: ProcessKey, session: SessionRef, flags: u64) {
        self.clear_operations(process, session, cancel_operation_mask(flags));
        if flags & CKF_FIND_OBJECTS != 0 {
            self.find_active.remove(&(process, session));
        }
        self.pending.retain(|(owner, handle, _), pending| {
            !(*owner == process
                && *handle == session
                && (pending.meta.semantics.operations & cancel_operation_mask(flags) != 0
                    || direct_cancel_flag(pending.meta.semantics.direct) & flags != 0
                    || (pending.meta.semantics.lifecycle == lifecycle::FIND_INIT
                        && flags & CKF_FIND_OBJECTS != 0)))
        });
        self.detached.retain(|_, detached| {
            let selected_owner = detached.owner == Some((process, session));
            !(selected_owner
                && (detached.pending.meta.semantics.operations & cancel_operation_mask(flags) != 0
                    || direct_cancel_flag(detached.pending.meta.semantics.direct) & flags != 0
                    || (detached.pending.meta.semantics.lifecycle == lifecycle::FIND_INIT
                        && flags & CKF_FIND_OBJECTS != 0)))
        });
    }

    fn observe_async(&mut self, process: ProcessKey, ev: &Event) {
        if ev.target_function == FUNCTION_NONE {
            self.evidence.async_target_failures += 1;
            return;
        }
        if ev.capture & capture::ASYNC_VALUE_UNREADABLE != 0 {
            self.evidence.async_target_failures += 1;
            return;
        }
        let Some(meta) = self.slots.get(ev.slot as usize).and_then(Clone::clone) else {
            return;
        };
        let session = meta.session(ev.session);
        match meta.semantics.lifecycle {
            lifecycle::ASYNC_COMPLETE => {
                if ev.rv == CkRv::PENDING.0 {
                    return;
                }
                let key = (process, session, ev.target_function);
                let pending = self.pending.remove(&key).or_else(|| {
                    let detached_key = self.detached.iter().find_map(|(key, value)| {
                        (value.owner == Some((process, session))
                            && value.pending.meta.function_id == Some(ev.target_function))
                        .then_some(*key)
                    });
                    detached_key.and_then(|key| self.detached.remove(&key).map(|d| d.pending))
                });
                let Some(pending) = pending else {
                    self.evidence.async_orphans += 1;
                    return;
                };
                let mut completed = pending.event;
                completed.session = ev.session;
                completed.rv = ev.rv;
                completed.ts_ns = ev.ts_ns;
                completed.duration_ns = ev.ts_ns.saturating_sub(pending.started_ns);
                if completed.rv == CkRv::PENDING.0 {
                    self.queue_pending(process, &completed, pending.meta);
                } else {
                    self.apply_completed(process, &completed, &pending.meta, true);
                }
            }
            lifecycle::ASYNC_GET_ID if ev.rv == CkRv::OK.0 => {
                let key = (process, session, ev.target_function);
                let Some(pending) = self.pending.remove(&key) else {
                    self.evidence.async_orphans += 1;
                    return;
                };
                let Some(slot) = self.open.get(&(process, session)).map(|info| info.slot) else {
                    self.evidence.async_target_failures += 1;
                    return;
                };
                if self
                    .detached
                    .insert(
                        (session.module, slot, ev.target_function, ev.async_value),
                        Detached {
                            pending,
                            owner: Some((process, session)),
                            process,
                        },
                    )
                    .is_some()
                {
                    self.evidence.async_duplicates += 1;
                }
            }
            lifecycle::ASYNC_JOIN if ev.rv == CkRv::OK.0 => {
                let Some(slot) = self.open.get(&(process, session)).map(|info| info.slot) else {
                    self.evidence.async_target_failures += 1;
                    return;
                };
                match self.detached.get_mut(&(
                    session.module,
                    slot,
                    ev.target_function,
                    ev.async_value,
                )) {
                    Some(detached) => {
                        // A successful join *assigns* the joining
                        // process/session, so custody moves whole: leaving
                        // `process` behind would let the previous holder's
                        // C_Finalize destroy an operation it no longer owns.
                        detached.owner = Some((process, session));
                        detached.process = process;
                    }
                    None => self.evidence.async_orphans += 1,
                }
            }
            _ => {}
        }
    }

    fn queue_pending(&mut self, process: ProcessKey, ev: &Event, meta: SlotMeta) {
        let Some(function_id) = meta.function_id else {
            self.evidence.async_target_failures += 1;
            return;
        };
        if meta.semantics.lifecycle == lifecycle::OPEN_SESSION && ev.session == SESSION_NONE {
            self.evidence.async_target_failures += 1;
            return;
        }
        self.sequence = self.sequence.wrapping_add(1);
        let key = (process, meta.session(ev.session), function_id);
        let pending = Pending {
            event: *ev,
            meta,
            started_ns: ev.ts_ns.saturating_sub(ev.duration_ns),
            sequence: self.sequence,
        };
        if self.pending.insert(key, pending).is_some() {
            self.evidence.async_duplicates += 1;
        }
        self.evict_pending_if_needed();
    }

    fn evict_pending_if_needed(&mut self) {
        if self.pending.len() + self.detached.len() <= MAX_PENDING {
            return;
        }
        let pending = self
            .pending
            .iter()
            .min_by_key(|(_, value)| value.sequence)
            .map(|(k, _)| *k);
        let detached = self
            .detached
            .iter()
            .min_by_key(|(_, value)| value.pending.sequence)
            .map(|(k, value)| (*k, value.pending.sequence));
        match (pending, detached) {
            (Some(key), Some((detached_key, detached_sequence))) => {
                if self.pending[&key].sequence <= detached_sequence {
                    self.pending.remove(&key);
                } else {
                    self.detached.remove(&detached_key);
                }
            }
            (Some(key), None) => {
                self.pending.remove(&key);
            }
            (None, Some((key, _))) => {
                self.detached.remove(&key);
            }
            (None, None) => return,
        }
        self.evidence.async_evictions += 1;
    }

    fn observe_templates(&mut self, ev: &Event, meta: &SlotMeta) {
        if !self.policy.uses_unsafe_decoders() {
            return;
        }
        if meta.semantics.template0_arg != p11scope_ebpf_common::ARG_NONE {
            self.record_template(
                ev.slot,
                0,
                if meta.semantics.template1_arg != p11scope_ebpf_common::ARG_NONE {
                    Some("public")
                } else {
                    None
                },
                meta,
                &ev.attr_types,
                ev.attr_count,
                ev.attr_total,
                ev.attr_bools,
                ev.attr_bools_seen,
            );
        }
        if meta.semantics.template1_arg != p11scope_ebpf_common::ARG_NONE {
            self.record_template(
                ev.slot,
                1,
                Some("private"),
                meta,
                &ev.attr_types1,
                ev.attr_count1,
                ev.attr_total1,
                ev.attr_bools1,
                ev.attr_bools_seen1,
            );
        }
    }

    #[allow(clippy::too_many_arguments)]
    fn record_template(
        &mut self,
        slot: u32,
        index: u8,
        role: Option<&'static str>,
        meta: &SlotMeta,
        types: &[u64; p11scope_ebpf_common::MAX_ATTRS],
        count: u32,
        total: u32,
        bools: u32,
        bools_seen: u32,
    ) {
        let key = (slot, index);
        if !self.templates.contains_key(&key) {
            if !self.admit(1) {
                return;
            }
            self.templates.insert(
                key,
                TemplateStat {
                    names: meta.names.clone(),
                    aliased: meta.aliased,
                    role,
                    ..Default::default()
                },
            );
        }
        let missing: BTreeSet<u64> = types[..(count as usize).min(types.len())]
            .iter()
            .copied()
            .filter(|attr_type| !self.templates[&key].attr_types.contains(attr_type))
            .collect();
        let add_types = missing.is_empty() || self.admit(missing.len());
        let stat = self.templates.get_mut(&key).unwrap();
        if add_types {
            stat.attr_types.extend(missing);
        }
        stat.bools_true |= bools & bools_seen;
        stat.bools_false |= bools_seen & !bools;
        stat.truncated |= total > count;
    }

    fn record_cgroup_mechanism(&mut self, cgroup_id: u64, mechanism: u64, rv: u64) {
        let Some(cgroup) = self.cgroups.get(&cgroup_id) else {
            return;
        };
        let exists = cgroup.mechanisms.contains_key(&mechanism);
        if !exists && !self.admit(1) {
            return;
        }
        let stat = self
            .cgroups
            .get_mut(&cgroup_id)
            .unwrap()
            .mechanisms
            .entry(mechanism)
            .or_default();
        stat.calls += 1;
        if rv != CkRv::OK.0 && rv != CkRv::PENDING.0 {
            stat.errors += 1;
        }
    }

    fn clear_operations(&mut self, process: ProcessKey, session: SessionRef, mask: u16) -> bool {
        let before = self.active_ops.len();
        self.active_ops.retain(|(owner, handle, operation), _| {
            !(*owner == process && *handle == session && mask & *operation != 0)
        });
        self.active_ops.len() != before
    }

    fn clear_session_state(&mut self, process: ProcessKey, session: SessionRef) -> bool {
        let mut changed = self.clear_operations(process, session, u16::MAX);
        changed |= self.find_active.remove(&(process, session));
        changed |= self.inherited_ambiguous.remove(&(process, session));
        let pending_before = self.pending.len();
        self.pending
            .retain(|(owner, handle, _), _| !(*owner == process && *handle == session));
        changed |= self.pending.len() != pending_before;
        for detached in self.detached.values_mut() {
            if detached.owner == Some((process, session)) {
                detached.owner = None;
                changed = true;
            }
        }
        changed
    }

    fn retire_session(&mut self, process: ProcessKey, session: SessionRef) -> bool {
        let existed = self.open.remove(&(process, session)).is_some();
        self.clear_session_state(process, session);
        if existed {
            self.sessions.closed += 1;
        }
        existed
    }

    pub fn retire_process(&mut self, process: ProcessKey) -> u64 {
        self.retire_scope(process, None)
    }

    /// Drops session-scoped state for `process`. `None` retires the whole
    /// process — every module's state, plus the process-scoped bookkeeping —
    /// which is what a process exit or a pid reuse means. `Some(id)` retires
    /// one module's Cryptoki (`C_Finalize`, or a call answering
    /// `CKR_CRYPTOKI_NOT_INITIALIZED`) and leaves every other module in that
    /// same process untouched.
    ///
    /// Returns whether *this scope* held any state before the sweep, so a
    /// module-scoped call cannot report a reconciliation on the strength of
    /// another module's live state.
    fn clear_scope(
        &mut self,
        process: ProcessKey,
        module: Option<ModuleId>,
        count_closed: bool,
    ) -> u64 {
        let had_state = self.has_scope_state(process, module);
        let owned = scoped(process, module);
        let sessions: Vec<SessionRef> = self
            .open
            .keys()
            .filter(|(owner, session)| owned(owner, session))
            .map(|(_, session)| *session)
            .collect();
        for session in &sessions {
            let existed = self.open.remove(&(process, *session)).is_some();
            self.clear_session_state(process, *session);
            if existed && count_closed {
                self.sessions.closed += 1;
            }
        }
        // Sessions the capture never saw opening leave state behind that no
        // `retire_session` above could have reached.
        self.active_ops
            .retain(|(owner, session, _), _| !owned(owner, session));
        self.find_active
            .retain(|(owner, session)| !owned(owner, session));
        self.inherited_ambiguous
            .retain(|(owner, session)| !owned(owner, session));
        self.pending
            .retain(|(owner, session, _), _| !owned(owner, session));
        // Async ids die with the Cryptoki that issued them, adopted or
        // floating: a later C_Initialize in this process could mint an
        // identical (module, slot, function, value) key, and C_AsyncJoin would
        // adopt a dead operation. Scoped by the record's own process, so
        // another process's ids for the same module are untouched.
        let owned_id = scoped_detached(process, module);
        self.detached
            .retain(|(id, ..), detached| !owned_id(id, detached));
        if module.is_none() {
            // Pseudonym numbering is per process and must not restart while
            // another module's sessions are still live under it.
            self.next_pseudonym.remove(&process);
            if self.current_process.get(&process.pid) == Some(&process) {
                self.current_process.remove(&process.pid);
            }
        }
        u64::from(had_state)
    }

    fn retire_scope(&mut self, process: ProcessKey, module: Option<ModuleId>) -> u64 {
        self.clear_scope(process, module, true)
    }

    pub fn fork_process(&mut self, parent: ProcessKey, child: ProcessKey) {
        if !self.current_process.contains_key(&child.pid) && !self.admit(1) {
            return;
        }
        self.current_process.insert(child.pid, child);
        // Inherits every module's sessions; each carries its own module along.
        let sessions: Vec<(SessionRef, SessionInfo)> = self
            .open
            .iter()
            .filter(|((owner, _), _)| *owner == parent)
            .map(|((_, session), info)| (*session, *info))
            .collect();
        for (session, info) in sessions {
            if !info.fork_safe {
                let key = (child, session);
                if self.inherited_ambiguous.contains(&key) || self.admit(1) {
                    self.inherited_ambiguous.insert(key);
                }
                continue;
            }
            let open_key = (child, session);
            let needed = usize::from(!self.next_pseudonym.contains_key(&child))
                + usize::from(!self.open.contains_key(&open_key));
            if !self.admit(needed) {
                continue;
            }
            let counter = self.next_pseudonym.entry(child).or_default();
            *counter += 1;
            self.open.insert(
                open_key,
                SessionInfo {
                    pseudonym: *counter,
                    ..info
                },
            );
            self.sessions.inherited += 1;
            for ((owner, handle, operation), binding) in self.active_ops.clone() {
                if owner == parent && handle == session {
                    if binding.fork_safe {
                        let key = (child, session, operation);
                        if self.active_ops.contains_key(&key) || self.admit(1) {
                            self.active_ops.insert(key, binding);
                        }
                    } else {
                        let key = (child, session);
                        if self.inherited_ambiguous.contains(&key) || self.admit(1) {
                            self.inherited_ambiguous.insert(key);
                        }
                    }
                }
            }
            if self.find_active.contains(&(parent, session)) {
                let key = (child, session);
                if self.find_active.contains(&key) || self.admit(1) {
                    self.find_active.insert(key);
                }
            }
        }
        self.update_peak();
    }

    fn update_peak(&mut self) {
        self.sessions.peak_concurrent = self.sessions.peak_concurrent.max(self.open.len() as u64);
    }

    /// Pseudonym for the raw handle `raw` as issued by the module attached at
    /// `slot`. Two modules in one process may both issue handle 5; each keeps
    /// its own pseudonym, drawn from one per-process sequence so the rendered
    /// numbers stay distinct.
    pub fn session_pseudonym(&self, pid: u32, slot: u32, raw: u64) -> Option<u64> {
        let process = self
            .current_process
            .get(&pid)
            .copied()
            .unwrap_or_else(|| ProcessKey::from_pid(pid));
        self.session_pseudonym_process(process, slot, raw)
    }

    pub fn session_pseudonym_process(
        &self,
        process: ProcessKey,
        slot: u32,
        raw: u64,
    ) -> Option<u64> {
        let module = self
            .slots
            .get(slot as usize)
            .and_then(Option::as_ref)
            .map_or(MODULE_UNRESOLVED, |meta| meta.module);
        self.open
            .get(&(
                process,
                SessionRef {
                    module,
                    handle: raw,
                },
            ))
            .map(|info| info.pseudonym)
    }

    pub fn mechanisms(&self) -> &BTreeMap<u64, MechStat> {
        &self.mechanisms
    }
    pub fn templates(&self) -> &BTreeMap<(u32, u8), TemplateStat> {
        &self.templates
    }
    pub fn sessions(&self) -> SessionStats {
        self.sessions
    }
    pub fn logins(&self) -> &BTreeMap<u32, u64> {
        &self.logins
    }
    pub fn cgroups(&self) -> &BTreeMap<u64, CgroupStat> {
        &self.cgroups
    }
    pub fn orphan_ops(&self) -> u64 {
        self.orphan_ops
    }
    pub fn unmatched_closes(&self) -> u64 {
        self.unmatched_closes
    }
    pub fn semantic_evidence(&self) -> SemanticEvidence {
        self.evidence
    }
    pub fn pending_at_end(&self) -> u64 {
        (self.pending.len() + self.detached.len()) as u64
    }
    pub fn has_process_state(&self, process: ProcessKey) -> bool {
        self.has_scope_state(process, None)
    }

    /// Whether `process` still holds session-scoped state. `Some(id)` asks
    /// about one module's state only. Shares both `scoped` (session-keyed
    /// maps) and `scoped_detached` (the module-keyed async ids) with
    /// `retire_scope`, so the question and the sweep that answers it cannot
    /// disagree.
    fn has_scope_state(&self, process: ProcessKey, module: Option<ModuleId>) -> bool {
        let owned = scoped(process, module);
        let owned_id = scoped_detached(process, module);
        self.open
            .keys()
            .any(|(owner, session)| owned(owner, session))
            || self
                .active_ops
                .keys()
                .any(|(owner, session, _)| owned(owner, session))
            || self
                .find_active
                .iter()
                .any(|(owner, session)| owned(owner, session))
            || self
                .pending
                .keys()
                .any(|(owner, session, _)| owned(owner, session))
            // A floating async id is live state — it is still joinable — and
            // now attributable, so it counts.
            || self
                .detached
                .iter()
                .any(|((id, ..), record)| owned_id(id, record))
            || self
                .inherited_ambiguous
                .iter()
                .any(|(owner, session)| owned(owner, session))
    }
    pub fn pid_has_process_state(&self, pid: u32) -> bool {
        self.current_process
            .get(&pid)
            .is_some_and(|process| self.has_process_state(*process))
    }
    pub fn templates_truncated(&self) -> bool {
        self.templates.values().any(|t| t.truncated)
    }
    pub fn mech_shapes(&self) -> &BTreeMap<u64, u32> {
        &self.mech_shapes
    }

    pub fn shape_decode_failures(&self) -> u64 {
        if !self.policy.uses_unsafe_decoders() {
            return 0;
        }
        self.mechanisms
            .iter()
            .filter(|(id, stat)| !stat.param_combos.is_empty() || self.mech_shapes.contains_key(id))
            .map(|(_, stat)| stat.init_no_shape)
            .sum()
    }

    pub fn total_shape_decode_failures(&self) -> u64 {
        if !self.policy.uses_unsafe_decoders() {
            return 0;
        }
        self.mechanisms
            .iter()
            .filter(|(id, stat)| stat.param_combos.is_empty() && self.mech_shapes.contains_key(id))
            .count() as u64
    }
}

fn record_call(stat: &mut MechStat, ev: &Event) {
    stat.calls += 1;
    if ev.rv != 0 {
        stat.errors += 1;
    }
    stat.buckets[bucket_of(ev.duration_ns) as usize] += 1;
    stat.total_ns += ev.duration_ns;
    stat.max_ns = stat.max_ns.max(ev.duration_ns);
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::plan::Slot;

    mod fnkind {
        pub const INIT_WITH_MECH: u32 = 1;
        pub const OPEN_SESSION: u32 = 2;
        pub const SESSION_ARG0: u32 = 3;
        pub const LOGIN: u32 = 4;
        pub const TEMPLATE_ARG1: u32 = 5;
    }

    fn pid_tgid(pid: u32) -> u64 {
        ((pid as u64) << 32) | 0xABCD
    }

    fn ev(
        pid: u32,
        slot: u32,
        _kind: u32,
        session: u64,
        mechanism: u64,
        rv: u64,
        duration_ns: u64,
    ) -> Event {
        Event {
            ts_ns: 0,
            duration_ns,
            pid_tgid: pid_tgid(pid),
            cgroup_id: 0,
            session,
            mechanism,
            capture: if mechanism == MECH_NONE {
                capture::MECHANISM_NONE
            } else {
                capture::MECHANISM_VALUE
            },
            rv,
            p0: 0,
            p1: 0,
            p2: 0,
            slot,
            user_type: USER_TYPE_NONE,
            shape: 0,
            attr_types: [0; 8],
            attr_count: 0,
            attr_total: 0,
            attr_bools: 0,
            attr_bools_seen: 0,
            ..Event::default()
        }
    }

    fn login_ev(pid: u32, user_type: u32) -> Event {
        Event {
            ts_ns: 0,
            duration_ns: 10,
            pid_tgid: pid_tgid(pid),
            cgroup_id: 0,
            session: SESSION_NONE,
            mechanism: MECH_NONE,
            rv: 0,
            p0: 0,
            p1: 0,
            p2: 0,
            slot: 5,
            user_type,
            shape: 0,
            attr_types: [0; 8],
            attr_count: 0,
            attr_total: 0,
            attr_bools: 0,
            attr_bools_seen: 0,
            ..Event::default()
        }
    }

    fn slot(index: u32, names: &[&str], _kind: u32) -> Slot {
        let names = names.iter().map(|s| s.to_string()).collect::<Vec<_>>();
        let aliased = names.len() >= 2;
        let (descriptor_index, semantic_ambiguous) = crate::kinds::descriptor_index(&names);
        let semantics = crate::kinds::DESCRIPTORS[descriptor_index as usize];
        Slot {
            index,
            descriptor_index,
            object: crate::plan::TEST_PINNED_OBJECT,
            object_path: "/opt/p11.so".into(),
            file_offset: index as u64 * 0x10,
            names,
            aliased,
            semantics,
            semantic_authorized: true,
            semantic_ambiguous,
            fork_safe: false,
            module_ids: vec![crate::plan::ModuleId(0)],
        }
    }

    // Slot layout shared by the tests below:
    // 0 C_OpenSession   1 C_CloseSession   2 C_SignInit
    // 3 C_Sign          4 C_SignFinal      5 C_Login
    // 6 C_FindObjectsInit (template)
    fn test_plan() -> AttachPlan {
        let mut plan = AttachPlan::from_slots(vec![
            slot(0, &["C_OpenSession"], fnkind::OPEN_SESSION),
            slot(1, &["C_CloseSession"], fnkind::SESSION_ARG0),
            slot(2, &["C_SignInit"], fnkind::INIT_WITH_MECH),
            slot(3, &["C_Sign"], fnkind::SESSION_ARG0),
            slot(4, &["C_SignFinal"], fnkind::SESSION_ARG0),
            slot(5, &["C_Login"], fnkind::LOGIN),
            slot(6, &["C_FindObjectsInit"], fnkind::TEMPLATE_ARG1),
        ]);
        plan.entries_seen = 7;
        plan
    }

    #[test]
    fn unverified_count_only_slot_creates_no_semantic_state() {
        let mut plan = test_plan();
        plan.slots.truncate(1);
        plan.slots[0].semantic_authorized = false;
        plan.slots[0].semantics = p11scope_ebpf_common::SlotSemantics::COUNT_ONLY;
        plan.slots[0].descriptor_index = 0;
        plan.entries_seen = 1;
        let mut state = State::new(&plan);
        let hostile = Event {
            slot: 0,
            pid_tgid: pid_tgid(100),
            cgroup_id: 7,
            session: 0xdead_beef,
            mechanism: 0x1087,
            capture: capture::MECHANISM_VALUE,
            user_type: 1,
            shape: shape::GCM,
            p0: 0xa11c_e000_0000_0001,
            p1: 0xa11c_e000_0000_0002,
            p2: 0xa11c_e000_0000_0003,
            attr_types: [0x100; 8],
            attr_count: 8,
            attr_total: 9,
            attr_bools: 0xff,
            attr_bools_seen: 0xff,
            rv: CkRv::PENDING.0,
            ..Event::default()
        };

        state.observe(&hostile);

        assert_eq!(state.cgroups()[&7].calls, 1, "aggregate evidence remains");
        assert!(state.mechanisms().is_empty());
        assert_eq!(state.sessions(), SessionStats::default());
        assert!(state.logins().is_empty());
        assert!(state.templates().is_empty());
        assert_eq!(state.pending_at_end(), 0);
    }

    /// An `*Init` event carrying a decoded (or not-decoded) parameter shape.
    fn ev_shape(
        pid: u32,
        session: u64,
        mechanism: u64,
        rv: u64,
        shape_code: u32,
        params: (u64, u64, u64),
    ) -> Event {
        let (p0, p1, p2) = params;
        Event {
            ts_ns: 0,
            duration_ns: 10,
            pid_tgid: pid_tgid(pid),
            cgroup_id: 0,
            session,
            mechanism,
            capture: capture::MECHANISM_VALUE,
            rv,
            p0,
            p1,
            p2,
            slot: 2,
            user_type: USER_TYPE_NONE,
            shape: shape_code,
            attr_types: [0; 8],
            attr_count: 0,
            attr_total: 0,
            attr_bools: 0,
            attr_bools_seen: 0,
            ..Event::default()
        }
    }

    /// A `C_FindObjectsInit`-shaped template event on slot 6.
    fn ev_template(
        pid: u32,
        attr_types: &[u64],
        attr_total: u32,
        attr_bools: u32,
        attr_bools_seen: u32,
    ) -> Event {
        let mut types = [0u64; 8];
        for (i, &t) in attr_types.iter().enumerate() {
            types[i] = t;
        }
        Event {
            ts_ns: 0,
            duration_ns: 10,
            pid_tgid: pid_tgid(pid),
            cgroup_id: 0,
            session: 10,
            mechanism: MECH_NONE,
            rv: 0,
            p0: 0,
            p1: 0,
            p2: 0,
            slot: 6,
            user_type: USER_TYPE_NONE,
            shape: 0,
            attr_types: types,
            attr_count: attr_types.len() as u32,
            attr_total,
            attr_bools,
            attr_bools_seen,
            ..Event::default()
        }
    }

    #[test]
    fn open_close_balance_and_peak_concurrent() {
        let mut s = State::new(&test_plan());
        s.observe(&ev(100, 0, fnkind::OPEN_SESSION, 10, MECH_NONE, 0, 5)); // open A
        s.observe(&ev(100, 0, fnkind::OPEN_SESSION, 20, MECH_NONE, 0, 5)); // open B
        s.observe(&ev(100, 1, fnkind::SESSION_ARG0, 10, MECH_NONE, 0, 5)); // close A

        let stats = s.sessions();
        assert_eq!(stats.opened, 2);
        assert_eq!(stats.closed, 1);
        assert_eq!(stats.peak_concurrent, 2, "both sessions were open at once");
        assert_eq!(s.unmatched_closes(), 0);
    }

    #[test]
    fn close_without_matching_open_is_unmatched_evidence() {
        let mut s = State::new(&test_plan());
        s.observe(&ev(100, 1, fnkind::SESSION_ARG0, 99, MECH_NONE, 0, 5)); // close, never opened

        assert_eq!(s.unmatched_closes(), 1);
        assert_eq!(
            s.sessions().closed,
            0,
            "an unmatched close must not inflate the balance"
        );
    }

    #[test]
    fn init_then_operational_call_attributes_to_same_mechanism() {
        let mut s = State::new(&test_plan());
        s.observe(&ev(100, 0, fnkind::OPEN_SESSION, 10, MECH_NONE, 0, 5));
        s.observe(&ev(100, 2, fnkind::INIT_WITH_MECH, 10, 0x250, 0, 100)); // C_SignInit
        s.observe(&ev(100, 3, fnkind::SESSION_ARG0, 10, MECH_NONE, 0, 200)); // C_Sign

        let m = s.mechanisms().get(&0x250).expect("mechanism recorded");
        assert_eq!(m.calls, 2, "the init call and the following op both count");
        assert_eq!(m.errors, 0);
        assert_eq!(m.buckets.iter().sum::<u64>(), 2);
        assert_eq!(s.orphan_ops(), 0);
    }

    #[test]
    fn operational_call_with_no_active_init_is_orphan() {
        let mut s = State::new(&test_plan());
        s.observe(&ev(100, 0, fnkind::OPEN_SESSION, 10, MECH_NONE, 0, 5));
        s.observe(&ev(100, 3, fnkind::SESSION_ARG0, 10, MECH_NONE, 0, 200)); // C_Sign, no prior Init

        assert_eq!(s.orphan_ops(), 1);
        assert!(
            s.mechanisms().is_empty(),
            "an orphan op names no mechanism — never a guess"
        );
    }

    #[test]
    fn init_records_op_and_exact_latency_totals() {
        let mut s = State::new(&test_plan());
        s.observe(&ev(100, 2, fnkind::INIT_WITH_MECH, 10, 0x250, 0, 100)); // C_SignInit, 100ns
        s.observe(&ev(100, 2, fnkind::INIT_WITH_MECH, 10, 0x250, 0, 300)); // C_SignInit again, 300ns

        let m = s.mechanisms().get(&0x250).unwrap();
        assert_eq!(m.ops.iter().collect::<Vec<_>>(), vec!["sign"]);
        assert_eq!(m.total_ns, 400);
        assert_eq!(m.max_ns, 300);
    }

    #[test]
    fn init_with_failed_mechanism_read_clears_the_stale_binding() {
        let mut s = State::new(&test_plan());
        s.observe(&ev(100, 0, fnkind::OPEN_SESSION, 10, MECH_NONE, 0, 5));
        s.observe(&ev(100, 2, fnkind::INIT_WITH_MECH, 10, 0x250, 0, 100)); // C_SignInit binds 0x250
        // A second Init whose pMechanism read failed (kernel reports
        // MECH_NONE) must drop that binding, not leave 0x250 bound.
        s.observe(&ev(100, 2, fnkind::INIT_WITH_MECH, 10, MECH_NONE, 0, 10));
        s.observe(&ev(100, 3, fnkind::SESSION_ARG0, 10, MECH_NONE, 0, 50)); // C_Sign

        assert_eq!(
            s.orphan_ops(),
            1,
            "must not inherit the stale 0x250 binding"
        );
        let m = s.mechanisms().get(&0x250).unwrap();
        assert_eq!(m.calls, 1, "only the first, successful Init is recorded");
    }

    #[test]
    fn failed_init_records_the_mechanism_but_does_not_bind_the_operation() {
        let mut s = State::with_policy(
            &test_plan(),
            crate::attach::CapturePolicy::UnsafeUnvalidatedMetadata,
        );
        s.observe(&ev(100, 0, fnkind::OPEN_SESSION, 10, MECH_NONE, 0, 5));
        s.observe(&ev(100, 2, fnkind::INIT_WITH_MECH, 10, 0x250, 0, 100)); // C_SignInit succeeds, binds 0x250
        // This deliberately reverses the old single-binding workaround:
        // a failed Init leaves the provider's existing operation intact.
        s.observe(&ev(100, 2, fnkind::INIT_WITH_MECH, 10, 0x251, 7, 10)); // C_SignInit fails, rv=7
        s.observe(&ev(100, 3, fnkind::SESSION_ARG0, 10, MECH_NONE, 0, 50)); // C_Sign

        assert_eq!(
            s.orphan_ops(),
            0,
            "a failed Init preserves the active binding"
        );
        let m250 = s.mechanisms().get(&0x250).unwrap();
        assert_eq!(
            m250.calls, 2,
            "the later Sign remains attributed to the active operation"
        );
        let m251 = s
            .mechanisms()
            .get(&0x251)
            .expect("the failed attempt is still evidence");
        assert_eq!(m251.calls, 1);
        assert_eq!(m251.errors, 1);
    }

    #[test]
    fn policy_output_safe_rejected_init_is_not_a_mechanism_request() {
        let mut s = State::with_policy(&test_plan(), crate::attach::CapturePolicy::Allowlisted);
        let rejected = Event {
            mechanism: 0x251,
            rv: CkRv::ARGUMENTS_BAD.0,
            capture: capture::MECHANISM_VALUE,
            ..ev(100, 2, fnkind::INIT_WITH_MECH, 10, MECH_NONE, 0, 10)
        };
        s.observe(&rejected);

        assert!(s.mechanisms().is_empty());
    }

    #[test]
    fn policy_output_unsafe_rejected_init_keeps_legacy_request_attribution() {
        let mut s = State::with_policy(
            &test_plan(),
            crate::attach::CapturePolicy::UnsafeUnvalidatedMetadata,
        );
        let rejected = Event {
            mechanism: 0x251,
            rv: CkRv::ARGUMENTS_BAD.0,
            capture: capture::MECHANISM_VALUE,
            ..ev(100, 2, fnkind::INIT_WITH_MECH, 10, MECH_NONE, 0, 10)
        };
        s.observe(&rejected);

        assert_eq!(s.mechanisms()[&0x251].errors, 1);
    }

    #[test]
    fn policy_output_safe_mode_does_not_record_disabled_metadata() {
        let mut s = State::with_policy(&test_plan(), crate::attach::CapturePolicy::Allowlisted);
        s.observe(&ev_shape(
            100,
            10,
            0x1087,
            CkRv::OK.0,
            shape::GCM,
            (12, 0, 128),
        ));
        s.observe(&ev_template(
            100,
            &[0x01],
            1,
            p11scope_ebpf_common::attr_bool::TOKEN,
            p11scope_ebpf_common::attr_bool::TOKEN,
        ));

        assert!(s.templates().is_empty());
        assert!(s.mechanisms()[&0x1087].param_combos.is_empty());
        assert_eq!(s.shape_decode_failures(), 0);
        assert_eq!(s.total_shape_decode_failures(), 0);
    }

    #[test]
    fn vendor_mechanism_id_survives_verbatim() {
        let mut s = State::new(&test_plan());
        let vendor_id: u64 = 0x80001042;
        s.observe(&ev(100, 2, fnkind::INIT_WITH_MECH, 10, vendor_id, 0, 100));

        assert!(s.mechanisms().contains_key(&vendor_id));
        assert_eq!(format!("{vendor_id:#x}"), "0x80001042");
    }

    #[test]
    fn two_pids_do_not_share_pseudonyms_or_session_state() {
        let mut s = State::new(&test_plan());
        // Same raw handle value (5), different pids — must not collide.
        s.observe(&ev(100, 0, fnkind::OPEN_SESSION, 5, MECH_NONE, 0, 5));
        s.observe(&ev(200, 0, fnkind::OPEN_SESSION, 5, MECH_NONE, 0, 5));

        assert_eq!(s.sessions().opened, 2);
        assert_eq!(s.sessions().peak_concurrent, 2);
        // Each pid gets its own first-seen numbering, independently.
        assert_eq!(s.session_pseudonym(100, 0, 5), Some(1));
        assert_eq!(s.session_pseudonym(200, 0, 5), Some(1));

        // Closing pid 100's session must not touch pid 200's.
        s.observe(&ev(100, 1, fnkind::SESSION_ARG0, 5, MECH_NONE, 0, 5));
        assert_eq!(s.sessions().closed, 1);
        assert_eq!(s.unmatched_closes(), 0);

        // A second close from pid 100 on the same (already-closed) handle
        // is unmatched — it must not borrow pid 200's still-open session.
        s.observe(&ev(100, 1, fnkind::SESSION_ARG0, 5, MECH_NONE, 0, 5));
        assert_eq!(s.unmatched_closes(), 1);

        s.observe(&ev(200, 1, fnkind::SESSION_ARG0, 5, MECH_NONE, 0, 5));
        assert_eq!(s.sessions().closed, 2);
        assert_eq!(
            s.unmatched_closes(),
            1,
            "pid 200's valid close must not be miscounted"
        );
    }

    #[test]
    fn final_call_clears_the_active_operation() {
        let mut s = State::new(&test_plan());
        s.observe(&ev(100, 0, fnkind::OPEN_SESSION, 10, MECH_NONE, 0, 5));
        s.observe(&ev(100, 2, fnkind::INIT_WITH_MECH, 10, 0x250, 0, 100)); // C_SignInit
        s.observe(&ev(100, 4, fnkind::SESSION_ARG0, 10, MECH_NONE, 0, 50)); // C_SignFinal
        // No Init in between — this must now be an orphan.
        s.observe(&ev(100, 3, fnkind::SESSION_ARG0, 10, MECH_NONE, 0, 50)); // C_Sign

        let m = s.mechanisms().get(&0x250).unwrap();
        assert_eq!(m.calls, 2, "init + final, not the post-final orphan");
        assert_eq!(s.orphan_ops(), 1);
    }

    #[test]
    fn login_records_user_type_counts_only() {
        let mut s = State::new(&test_plan());
        s.observe(&login_ev(100, 1));
        s.observe(&login_ev(100, 0));
        s.observe(&login_ev(100, 1));

        assert_eq!(s.logins().get(&1), Some(&2));
        assert_eq!(s.logins().get(&0), Some(&1));
    }

    #[test]
    fn distinct_param_combos_are_recorded_with_their_own_counts() {
        let mut s = State::with_policy(
            &test_plan(),
            crate::attach::CapturePolicy::UnsafeUnvalidatedMetadata,
        );
        // Same mechanism, same combo, twice.
        s.observe(&ev_shape(
            100,
            10,
            0x0D,
            0,
            shape::RSA_PKCS_PSS,
            (0x270, 1, 32),
        ));
        s.observe(&ev_shape(
            100,
            10,
            0x0D,
            0,
            shape::RSA_PKCS_PSS,
            (0x270, 1, 32),
        ));
        // Same mechanism, a different salt length: a distinct combo, not an
        // average or a "latest wins" overwrite.
        s.observe(&ev_shape(
            100,
            10,
            0x0D,
            0,
            shape::RSA_PKCS_PSS,
            (0x270, 1, 64),
        ));

        let m = s.mechanisms().get(&0x0D).unwrap();
        assert_eq!(m.param_combos.len(), 2, "two distinct combos, not merged");
        assert_eq!(
            m.param_combos.get(&(shape::RSA_PKCS_PSS, 0x270, 1, 32)),
            Some(&2)
        );
        assert_eq!(
            m.param_combos.get(&(shape::RSA_PKCS_PSS, 0x270, 1, 64)),
            Some(&1)
        );
        assert_eq!(m.init_no_shape, 0);
    }

    #[test]
    fn shape_decode_failures_only_count_mechanisms_that_decoded_at_least_once() {
        let mut s = State::with_policy(
            &test_plan(),
            crate::attach::CapturePolicy::UnsafeUnvalidatedMetadata,
        );
        // Mechanism 0x1087 (GCM) decodes once, then fails to decode once —
        // the failure is now interesting evidence.
        s.observe(&ev_shape(100, 10, 0x1087, 0, shape::GCM, (12, 0, 128)));
        s.observe(&ev_shape(100, 10, 0x1087, 0, shape::NONE, (0, 0, 0)));
        // Mechanism 0x9999 never decodes at all — an ordinary id-only
        // mechanism, not a failure.
        s.observe(&ev_shape(100, 10, 0x9999, 0, shape::NONE, (0, 0, 0)));

        assert_eq!(s.shape_decode_failures(), 1);
        let gcm = s.mechanisms().get(&0x1087).unwrap();
        assert_eq!(gcm.init_no_shape, 1);
        let unshaped = s.mechanisms().get(&0x9999).unwrap();
        assert_eq!(unshaped.init_no_shape, 1);
        assert!(unshaped.param_combos.is_empty());
    }

    #[test]
    fn total_decode_failure_is_invisible_without_mech_shapes_but_visible_with_it() {
        let mut s = State::with_policy(
            &test_plan(),
            crate::attach::CapturePolicy::UnsafeUnvalidatedMetadata,
        );
        // 0x1087 has a published GCM shape, but every observed call fails
        // to decode — the total-failure case Finding 1 flagged.
        s.observe(&ev_shape(100, 10, 0x1087, 0, shape::NONE, (0, 0, 0)));
        s.observe(&ev_shape(100, 10, 0x1087, 0, shape::NONE, (0, 0, 0)));

        // Without set_mech_shapes, this mechanism looks identical to an
        // ordinary id-only mechanism — the old, narrower signal.
        assert_eq!(s.shape_decode_failures(), 0);
        assert_eq!(s.total_shape_decode_failures(), 0);

        // Once the published-shape set is known, both counters see it.
        s.set_mech_shapes(BTreeMap::from([(0x1087, shape::GCM)]));
        assert_eq!(s.shape_decode_failures(), 2, "both failed calls now count");
        assert_eq!(
            s.total_shape_decode_failures(),
            1,
            "one mechanism id, wholly failed — the completeness-gating count"
        );
    }

    #[test]
    fn mechanism_with_no_published_shape_never_counts_as_a_total_failure() {
        let mut s = State::with_policy(
            &test_plan(),
            crate::attach::CapturePolicy::UnsafeUnvalidatedMetadata,
        );
        s.observe(&ev_shape(100, 10, 0x9999, 0, shape::NONE, (0, 0, 0)));
        // 0x9999 is not in the diagnostic shape set at all.
        s.set_mech_shapes(BTreeMap::from([(0x1087, shape::GCM)]));

        assert_eq!(s.total_shape_decode_failures(), 0);
        assert_eq!(s.shape_decode_failures(), 0);
    }

    #[test]
    fn template_attribute_types_and_policy_booleans_render_the_tristate_unambiguously() {
        use p11scope_ebpf_common::attr_bool;

        let mut s = State::with_policy(
            &test_plan(),
            crate::attach::CapturePolicy::UnsafeUnvalidatedMetadata,
        );
        // Call 1: CKA_TOKEN (0x01) true, CKA_PRIVATE (0x02) present-but-false.
        s.observe(&ev_template(
            100,
            &[0x01, 0x02],
            2,
            attr_bool::TOKEN,
            attr_bool::TOKEN | attr_bool::PRIVATE,
        ));
        // Call 2: CKA_SIGN (0x108) never appears at all — must stay absent
        // from both true and false, not default to false.
        s.observe(&ev_template(
            100,
            &[0x01],
            1,
            attr_bool::TOKEN,
            attr_bool::TOKEN,
        ));

        let t = s.templates().get(&(6, 0)).expect("slot 6 recorded");
        assert_eq!(t.names, vec!["C_FindObjectsInit".to_string()]);
        assert!(!t.aliased);
        assert_eq!(t.attr_types, BTreeSet::from([0x01, 0x02]));
        assert_eq!(
            t.bools_true & attr_bool::TOKEN,
            attr_bool::TOKEN,
            "seen and true"
        );
        assert_eq!(
            t.bools_false & attr_bool::PRIVATE,
            attr_bool::PRIVATE,
            "seen and false"
        );
        assert_eq!(
            t.bools_true & attr_bool::SIGN,
            0,
            "never present — not true"
        );
        assert_eq!(
            t.bools_false & attr_bool::SIGN,
            0,
            "never present — not false either"
        );
        assert!(!t.truncated);
    }

    #[test]
    fn template_truncation_is_recorded_per_call_and_surfaced_by_the_aggregate_accessor() {
        let mut s = State::with_policy(
            &test_plan(),
            crate::attach::CapturePolicy::UnsafeUnvalidatedMetadata,
        );
        assert!(!s.templates_truncated(), "nothing observed yet");

        // attr_total (10) > attr_count (8, the MAX_ATTRS cap already applied
        // by ev_template's slice length) — a template longer than the cap.
        s.observe(&ev_template(100, &[0x01; 8], 10, 0, 0));

        assert!(s.templates_truncated());
        let t = s.templates().get(&(6, 0)).unwrap();
        assert!(t.truncated);
    }

    /// Sets `cgroup_id` on an already-built event — every other test
    /// helper hardcodes `cgroup_id: 0` since they predate this field
    /// mattering to anything.
    fn with_cgroup(mut e: Event, cgroup_id: u64) -> Event {
        e.cgroup_id = cgroup_id;
        e
    }

    #[test]
    fn two_cgroups_produce_two_separate_breakdown_entries() {
        let mut s = State::with_policy(
            &test_plan(),
            crate::attach::CapturePolicy::UnsafeUnvalidatedMetadata,
        );
        // Two containers sharing one node-wide attach: same mechanism,
        // different cgroup ids, must not collapse into one entry.
        s.observe(&with_cgroup(
            ev(100, 2, fnkind::INIT_WITH_MECH, 10, 0x250, 0, 100),
            111,
        )); // C_SignInit, cgroup 111
        s.observe(&with_cgroup(
            ev(100, 3, fnkind::SESSION_ARG0, 99, MECH_NONE, 0, 50),
            111,
        )); // C_Sign on a different, never-Init'd session -- orphan, no mechanism
        s.observe(&with_cgroup(
            ev(200, 2, fnkind::INIT_WITH_MECH, 20, 0x251, 7, 30),
            222,
        )); // C_SignInit, cgroup 222, fails

        assert_eq!(s.cgroups().len(), 2, "two distinct cgroup ids, two entries");

        let cg111 = s.cgroups().get(&111).expect("cgroup 111 present");
        assert_eq!(cg111.calls, 2, "both events observed under cgroup 111");
        assert_eq!(cg111.errors, 0);
        let m111 = cg111
            .mechanisms
            .get(&0x250)
            .expect("mechanism 0x250 attributed to cgroup 111");
        assert_eq!(m111.calls, 1, "only the Init call names a mechanism here");
        assert_eq!(m111.errors, 0);

        let cg222 = s.cgroups().get(&222).expect("cgroup 222 present");
        assert_eq!(cg222.calls, 1);
        assert_eq!(
            cg222.errors, 1,
            "the failed Init counts as an error at the cgroup level too"
        );
        let m222 = cg222
            .mechanisms
            .get(&0x251)
            .expect("mechanism 0x251 attributed to cgroup 222");
        assert_eq!(m222.calls, 1);
        assert_eq!(m222.errors, 1);
    }

    #[test]
    fn one_shared_cgroup_produces_one_breakdown_entry() {
        let mut s = State::new(&test_plan());
        s.observe(&with_cgroup(
            ev(100, 0, fnkind::OPEN_SESSION, 10, MECH_NONE, 0, 5),
            111,
        ));
        s.observe(&with_cgroup(
            ev(100, 2, fnkind::INIT_WITH_MECH, 10, 0x250, 0, 100),
            111,
        )); // C_SignInit
        s.observe(&with_cgroup(
            ev(100, 3, fnkind::SESSION_ARG0, 10, MECH_NONE, 0, 200),
            111,
        )); // C_Sign, attributed to 0x250

        assert_eq!(s.cgroups().len(), 1, "one cgroup id, one entry");
        let cg = s.cgroups().get(&111).unwrap();
        assert_eq!(
            cg.calls, 3,
            "every observed event, not just mechanism-attributed ones"
        );
        assert_eq!(cg.errors, 0);
        assert_eq!(cg.mechanisms.len(), 1);
        let m = cg.mechanisms.get(&0x250).unwrap();
        assert_eq!(
            m.calls, 2,
            "the init call and the following op both attributed"
        );
        assert_eq!(m.errors, 0);
    }

    #[test]
    fn sync_plan_purges_every_process_for_a_slot_downgraded_to_count_only() {
        let mut plan = test_plan();
        plan.slots[1].module_ids = vec![ModuleId(1)];
        let mut state = State::new(&plan);
        let first = ProcessKey::from_pid(100);
        let second = ProcessKey::from_pid(200);
        state.observe_process(first, &ev(100, 0, fnkind::OPEN_SESSION, 1, MECH_NONE, 0, 1));
        state.observe_process(
            second,
            &ev(200, 0, fnkind::OPEN_SESSION, 2, MECH_NONE, 0, 1),
        );
        let second_module_session = SessionRef {
            module: ModuleId(1),
            handle: 9,
        };
        state.open.insert(
            (second, second_module_session),
            SessionInfo {
                pseudonym: 1,
                slot: 1,
                fork_safe: false,
            },
        );
        assert!(state.has_process_state(first));
        assert!(state.has_process_state(second));

        plan.slots[0].descriptor_index = 0;
        plan.slots[0].semantics = p11scope_ebpf_common::SlotSemantics::COUNT_ONLY;
        plan.slots[0].semantic_authorized = false;
        plan.slots[0].semantic_ambiguous = true;
        plan.slots[0].module_ids = vec![ModuleId(0), ModuleId(1)];
        state.sync_plan(&plan);

        assert!(!state.has_process_state(first));
        assert!(!state.has_process_state(second));
        assert!(
            !state.open.contains_key(&(second, second_module_session)),
            "a newly ambiguous co-owner's prior process state is purged too"
        );
        assert!(state.mechanisms().is_empty());
        assert!(state.templates().is_empty());
        assert!(state.logins().is_empty());
        assert_eq!(state.semantic_evidence().state_reconciliations, 1);
    }

    #[test]
    fn sync_plan_treats_sticky_module_ambiguity_as_count_only() {
        let mut plan = test_plan();
        let descriptor = plan.slots[0].descriptor_index;
        let mut state = State::new(&plan);
        let process = ProcessKey::from_pid(100);
        state.observe_process(
            process,
            &ev(100, 0, fnkind::OPEN_SESSION, 1, MECH_NONE, 0, 1),
        );
        assert!(state.has_process_state(process));

        let mut shared = plan.slots.clone();
        shared[0].module_ids.push(ModuleId(1));
        let candidate = AttachPlan::from_slots(shared);
        assert!(plan.latch_ambiguity_from(&candidate));
        state.sync_plan(&plan);

        assert_eq!(plan.slots[0].descriptor_index, descriptor);
        assert_ne!(
            plan.slots[0].semantics,
            p11scope_ebpf_common::SlotSemantics::COUNT_ONLY
        );
        assert_eq!(
            state.slots[0].as_ref().unwrap().semantics,
            p11scope_ebpf_common::SlotSemantics::COUNT_ONLY
        );
        assert!(!state.has_process_state(process));
        state.observe_process(
            process,
            &ev(100, 0, fnkind::OPEN_SESSION, 2, MECH_NONE, 0, 2),
        );
        assert!(
            !state.has_process_state(process),
            "the still-attached old cookie is consumed without semantic state"
        );
    }
}
