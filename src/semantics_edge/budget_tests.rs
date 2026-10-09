//! SPDX-License-Identifier: GPL-3.0-or-later
//! Before-growth boundaries over the actual production reducer and pool.

use super::*;
use resources::*;

#[path = "../../build_support/semantic_rustc.rs"]
mod semantic_rustc;

#[test]
fn native_semantic_resource_compiler_metadata_guard() {
    let valid = format!(
        "rustc1.98.1\nrelease: {}\ncommit-hash: {}\nhost: x86_64-unknown-linux-gnu\n",
        semantic_rustc::RELEASE,
        semantic_rustc::COMMIT
    );
    assert!(semantic_rustc::validate_metadata(&valid).is_ok());
    assert!(
        semantic_rustc::validate_metadata(&valid.replace("release: 1.98.1", "release: 1.99.0"))
            .is_err()
    );
    assert!(
        semantic_rustc::validate_metadata(&valid.replace(semantic_rustc::COMMIT, "wrong-commit"))
            .is_err()
    );
    assert!(semantic_rustc::validate_metadata("rustc1.98.1\nrelease: 1.98.1\n").is_err());
    assert!(semantic_rustc::validate_metadata(&(valid + "release: 1.98.1\n")).is_err());
}

fn pool(persistent: usize) -> SemanticResourcePool {
    SemanticResourcePool::reference_limit(SEMANTIC_TRANSITION_SCRATCH + persistent)
}

fn facts(name: &str, session: u64) -> SemanticCall {
    SemanticCall {
        function: name.into(),
        session,
        mechanism: 0x1087,
        capture: capture::MECHANISM_VALUE | capture::OUTPUT_NON_NULL,
        ..SemanticCall::default()
    }
}

fn unknown_init(session: u64) -> SemanticCall {
    SemanticCall {
        capture: capture::MECHANISM_UNREADABLE,
        ..facts("C_SignInit", session)
    }
}

fn sign_history_charge() -> usize {
    MECHANISM_CHARGE
        + CATEGORY_CHARGE
        + FUNCTION_CHARGE
        + "C_SignInit".len()
        + OWNED_ALLOCATION_PADDING
        + RETURN_CHARGE
}

#[test]
fn native_semantic_resource_n_and_n_plus_one() {
    for open in [true, false] {
        let item = if open {
            OPEN_BINDING_CHARGE
        } else {
            ACTIVE_MACHINE_CHARGE
        };
        let resources = pool(REDUCER_BASE_CHARGE + 3 * item);
        let mut edge = EdgeSemantics::with_resources(&resources).unwrap();
        for session in 1..=3 {
            let call = if open {
                facts("C_OpenSession", session)
            } else {
                unknown_init(session)
            };
            assert_eq!(edge.observe_with_resources(&call), Ok(0));
        }
        let before = edge.resource_usage();
        assert_eq!(
            if open {
                before.open_bindings
            } else {
                before.active_machines
            },
            3
        );
        let call = if open {
            facts("C_OpenSession", 4)
        } else {
            unknown_init(4)
        };
        let refused = edge.observe_with_resources(&call);
        assert!(
            refused.is_err(),
            "a fourth actual key must refuse before growth"
        );
        let after = edge.resource_usage();
        assert_eq!((after.open_bindings, after.active_machines), (0, 0));
        assert_eq!(resources.snapshot().refused, 1);
        assert_eq!(
            resources.snapshot().peak_charged_bytes,
            resources.snapshot().limit_bytes
        );
        assert_eq!(
            resources.snapshot().charged_bytes,
            SEMANTIC_TRANSITION_SCRATCH + REDUCER_BASE_CHARGE
        );
        if !open {
            assert_eq!((edge.started(), edge.unknown()), (3, 3));
        }
    }
}

#[test]
fn native_semantic_resource_release_preserves_history() {
    let first = sign_history_charge();
    let final_function = FUNCTION_CHARGE + "C_Sign".len() + OWNED_ALLOCATION_PADDING;
    let resources = pool(2 * REDUCER_BASE_CHARGE + first + final_function + ACTIVE_MACHINE_CHARGE);
    let mut edge = EdgeSemantics::with_resources(&resources).unwrap();
    let mut sibling = EdgeSemantics::with_resources(&resources).unwrap();
    edge.observe_with_resources(&facts("C_SignInit", 1))
        .unwrap();
    edge.observe_with_resources(&facts("C_Sign", 1)).unwrap();
    assert_eq!((edge.started(), edge.completed()), (1, 1));
    assert_eq!(edge.resource_usage().provenance_functions, 2);
    assert_eq!(
        resources.snapshot().charged_bytes,
        SEMANTIC_TRANSITION_SCRATCH + 2 * REDUCER_BASE_CHARGE + first + final_function
    );
    sibling.observe_with_resources(&unknown_init(2)).unwrap();
    assert_eq!(sibling.started(), 1);
    assert_eq!(
        resources.snapshot().charged_bytes,
        resources.snapshot().limit_bytes
    );
    sibling.invalidate();
    assert_eq!(edge.mechanisms()[&0x1087].calls, 2);
    assert_eq!(edge.resource_usage().provenance_functions, 2);
    assert_eq!(
        resources.snapshot().charged_bytes,
        SEMANTIC_TRANSITION_SCRATCH + 2 * REDUCER_BASE_CHARGE + first + final_function
    );
    drop(sibling);
    assert_eq!(
        resources.snapshot().charged_bytes,
        SEMANTIC_TRANSITION_SCRATCH + REDUCER_BASE_CHARGE + first + final_function
    );
    drop(edge);
    assert_eq!(
        resources.snapshot().charged_bytes,
        SEMANTIC_TRANSITION_SCRATCH
    );
}

#[test]
fn native_semantic_resource_never_pre_refunds_expected_completion() {
    let resources = pool(REDUCER_BASE_CHARGE + sign_history_charge() + ACTIVE_MACHINE_CHARGE);
    let mut edge = EdgeSemantics::with_resources(&resources).unwrap();
    edge.observe_with_resources(&facts("C_SignInit", 1))
        .unwrap();
    assert_eq!(edge.started(), 1);
    assert!(
        edge.observe_with_resources(&facts("C_Sign", 1)).is_err(),
        "the new provenance allocation must reserve before the active machine is removed"
    );
    assert_eq!(
        (edge.started(), edge.completed(), edge.unknown()),
        (1, 0, 1)
    );
    assert_eq!(edge.mechanisms()[&0x1087].calls, 1);
    assert_eq!(edge.resource_usage().provenance_functions, 1);
    // The skipped affecting input clears current authority, but the now
    // released live allowance can admit a separately fresh operation.
    edge.observe_with_resources(&facts("C_SignInit", 2))
        .unwrap();
    assert_eq!(edge.started(), 2);
}

#[test]
fn native_semantic_resource_async_lease_moves_once() {
    let asynchronous = ASYNC_FACT_CHARGE
        + "C_SignEncryptUpdate".len()
        + OWNED_ALLOCATION_PADDING
        + 4 * std::mem::size_of::<(u16, Option<u64>)>()
        + OWNED_ALLOCATION_PADDING;
    let resources = pool(REDUCER_BASE_CHARGE + OPEN_BINDING_CHARGE + asynchronous);
    let mut edge = EdgeSemantics::with_resources(&resources).unwrap();
    edge.observe_with_resources(&facts("C_OpenSession", 1))
        .unwrap();
    edge.observe_with_resources(&SemanticCall {
        rv: CkRv::PENDING.0,
        ..facts("C_SignEncryptUpdate", 1)
    })
    .unwrap();
    assert_eq!(edge.resource_usage().pending_calls, 1);
    let pending_charge = resources.snapshot().charged_bytes;
    assert_eq!(pending_charge, resources.snapshot().limit_bytes);
    edge.observe_with_resources(&SemanticCall {
        target_function: crate::kinds::function_id("C_SignEncryptUpdate").unwrap(),
        async_value: 91,
        ..facts("C_AsyncGetID", 1)
    })
    .unwrap();
    assert_eq!(
        (
            edge.resource_usage().pending_calls,
            edge.resource_usage().detached_calls
        ),
        (0, 1)
    );
    assert_eq!(resources.snapshot().charged_bytes, pending_charge);
    edge.observe_with_resources(&facts("C_CloseSession", 1))
        .unwrap();
    assert_eq!(edge.resource_usage().detached_calls, 1);
    assert_eq!(
        resources.snapshot().charged_bytes,
        pending_charge - OPEN_BINDING_CHARGE
    );
    edge.observe_with_resources(&facts("C_OpenSession", 2))
        .unwrap();
    edge.observe_with_resources(&SemanticCall {
        target_function: crate::kinds::function_id("C_SignEncryptUpdate").unwrap(),
        async_value: 91,
        ..facts("C_AsyncJoin", 2)
    })
    .unwrap();
    edge.observe_with_resources(&SemanticCall {
        target_function: crate::kinds::function_id("C_SignEncryptUpdate").unwrap(),
        ..facts("C_AsyncComplete", 2)
    })
    .unwrap();
    assert_eq!(edge.resource_usage().detached_calls, 0);
    assert_eq!(
        resources.snapshot().charged_bytes,
        SEMANTIC_TRANSITION_SCRATCH + REDUCER_BASE_CHARGE + OPEN_BINDING_CHARGE
    );
}

#[test]
fn native_semantic_resource_async_complete_preflights_original_call() {
    let asynchronous = ASYNC_FACT_CHARGE
        + "C_SignInit".len()
        + OWNED_ALLOCATION_PADDING
        + 4 * std::mem::size_of::<(u16, Option<u64>)>()
        + OWNED_ALLOCATION_PADDING;
    let resources = pool(REDUCER_BASE_CHARGE + asynchronous);
    let mut edge = EdgeSemantics::with_resources(&resources).unwrap();
    edge.observe_with_resources(&SemanticCall {
        rv: CkRv::PENDING.0,
        ..facts("C_SignInit", 1)
    })
    .unwrap();
    assert_eq!(
        (edge.started(), edge.resource_usage().pending_calls),
        (0, 1)
    );
    assert!(
        edge.observe_with_resources(&SemanticCall {
            target_function: crate::kinds::function_id("C_SignInit").unwrap(),
            ..facts("C_AsyncComplete", 1)
        })
        .is_err(),
        "completion must reserve the retained Init's mechanism/machine/provenance effects"
    );
    assert_eq!(edge.started(), 0);
    assert_eq!(edge.resource_usage().mechanisms, 0);
    assert_eq!(edge.resource_usage().pending_calls, 0);
}

#[test]
fn native_semantic_resource_invalidation_does_not_allocate() {
    let resources = pool(REDUCER_BASE_CHARGE + sign_history_charge() + ACTIVE_MACHINE_CHARGE);
    let mut edge = EdgeSemantics::with_resources(&resources).unwrap();
    edge.observe_with_resources(&facts("C_SignInit", 1))
        .unwrap();
    assert_eq!(edge.started(), 1);
    let (_, allocations, bytes) = crate::test_alloc::count_allocs_during(|| edge.invalidate());
    assert_eq!((allocations, bytes), (0, 0));
    assert_eq!((edge.unknown(), edge.resource_usage().mechanisms), (1, 1));
}

#[test]
fn native_semantic_resource_whole_drop_refunds_after_payload_destruction() {
    let resources = SemanticResourcePool::default();
    let mut edge = EdgeSemantics::with_resources(&resources).unwrap();
    let init = facts("C_SignInit", 1);
    let open = facts("C_OpenSession", 1);
    let pending = SemanticCall {
        rv: CkRv::PENDING.0,
        ..facts("C_SignEncryptUpdate", 1)
    };
    let (_, peak) = crate::test_alloc::requested_peak_during(|| {
        edge.observe_with_resources(&open).unwrap();
        edge.observe_with_resources(&init).unwrap();
        edge.observe_with_resources(&pending).unwrap();
        assert_eq!(
            (
                edge.resource_usage().active_machines,
                edge.resource_usage().pending_calls
            ),
            (1, 1)
        );
        resources::observe_refunds(
            || drop(edge),
            |bytes| {
                if bytes >= REDUCER_BASE_CHARGE {
                    let state = crate::test_alloc::armed_requested_snapshot();
                    assert!(!state.incomplete);
                    assert_eq!(state.failed_requests, 0);
                    assert_eq!(
                        (state.live_bytes, state.live_blocks),
                        (0, 0),
                        "actual nodes, provenance strings and async payload must be freed before whole-owner refund"
                    );
                }
            },
        );
    });
    assert!(!peak.incomplete);
    assert_eq!(
        (peak.live_bytes, peak.live_blocks, peak.failed_requests),
        (0, 0, 0)
    );
    assert_eq!(
        resources.snapshot().charged_bytes,
        SEMANTIC_TRANSITION_SCRATCH
    );
}

#[test]
fn native_semantic_resource_close_all_sessions_scratch_peak() {
    let resources = SemanticResourcePool::default();
    let mut edge = EdgeSemantics::with_resources(&resources).unwrap();
    for session in 1..=MAX_EDGE_ACTIVE_OPS as u64 {
        edge.observe_with_resources(&unknown_init(session)).unwrap();
    }
    for offset in 1..=MAX_EDGE_SESSIONS as u64 {
        edge.observe_with_resources(&facts("C_OpenSession", 10_000 + offset))
            .unwrap();
    }
    for offset in 1..=MAX_EDGE_PENDING as u64 {
        edge.observe_with_resources(&SemanticCall {
            rv: CkRv::PENDING.0,
            ..facts("C_SignEncryptUpdate", 20_000 + offset)
        })
        .unwrap();
    }
    let before = edge.resource_usage();
    assert_eq!(
        (
            before.open_bindings,
            before.active_machines,
            before.pending_calls
        ),
        (1024, 2048, 256)
    );
    // Distinct, disjoint raw sessions force all2304 potential owners into
    // the actual production collect/sort/bulk-build path.
    assert_eq!(
        edge.active
            .keys()
            .map(|(session, _)| *session)
            .chain(edge.pending.keys().map(|(session, _)| *session))
            .collect::<BTreeSet<_>>()
            .len(),
        2304
    );
    let close = facts("C_CloseAllSessions", SESSION_NONE);
    let (_, peak) = crate::test_alloc::requested_peak_during(|| {
        edge.observe_with_resources(&close).unwrap();
    });
    assert!(!peak.incomplete);
    assert_eq!(
        (peak.live_bytes, peak.live_blocks, peak.failed_requests),
        (0, 0, 0)
    );
    assert!(peak.peak_bytes <= SEMANTIC_TRANSITION_SCRATCH);
    assert!(peak.realloc_overlap_bytes <= SEMANTIC_TRANSITION_SCRATCH);
    assert_eq!(edge.resource_usage(), S1Occupancy::default());
    assert_eq!(edge.unknown(), MAX_EDGE_ACTIVE_OPS as u64);
    assert_eq!(
        resources.snapshot().charged_bytes,
        SEMANTIC_TRANSITION_SCRATCH + REDUCER_BASE_CHARGE
    );
    eprintln!(
        "S1_SCRATCH_ROW close_all_2304 live_peak={} realloc_overlap={} persistent_before={} persistent_after={}",
        peak.peak_bytes,
        peak.realloc_overlap_bytes,
        REDUCER_BASE_CHARGE
            + 1024 * OPEN_BINDING_CHARGE
            + 2048 * ACTIVE_MACHINE_CHARGE
            + 256
                * EdgeSemantics::async_charge(
                    &facts("C_SignEncryptUpdate", 1),
                    &crate::kinds::descriptor("C_SignEncryptUpdate").unwrap()
                ),
        REDUCER_BASE_CHARGE
    );
}

#[test]
fn native_semantic_resource_concentrated_owner_scratch_peak() {
    let resources = SemanticResourcePool::default();
    let mut edge = EdgeSemantics::with_resources(&resources).unwrap();
    edge.observe_with_resources(&facts("C_OpenSession", 1))
        .unwrap();
    for field in pkcs11_module::FUNCTION_LIST_FIELDS
        .iter()
        .chain(pkcs11_module::FUNCTION_LIST_3_0_EXTRA_FIELDS)
        .chain(pkcs11_module::FUNCTION_LIST_3_2_EXTRA_FIELDS)
    {
        if crate::kinds::descriptor(field.name).unwrap().transition == transition::INITIALIZE {
            edge.observe_with_resources(&SemanticCall {
                capture: capture::MECHANISM_UNREADABLE,
                ..facts(field.name, 1)
            })
            .unwrap();
        }
    }
    // All currently supported operation categories on one real session.
    assert_eq!(edge.resource_usage().active_machines, 11);
    // Two canonical Init names establish the same operation category;
    // its replacement is genuine pre-close evidence, not scratch cleanup.
    assert_eq!(edge.cancelled(), 1);
    let cancellations_before_close = edge.cancelled();
    for async_value in 1..=MAX_EDGE_PENDING as u64 {
        edge.observe_with_resources(&SemanticCall {
            rv: CkRv::PENDING.0,
            ..facts("C_SignEncryptUpdate", 1)
        })
        .unwrap();
        edge.observe_with_resources(&SemanticCall {
            target_function: crate::kinds::function_id("C_SignEncryptUpdate").unwrap(),
            async_value,
            ..facts("C_AsyncGetID", 1)
        })
        .unwrap();
    }
    assert_eq!(edge.resource_usage().detached_calls, 256);
    let close = facts("C_CloseSession", 1);
    let (_, peak) =
        crate::test_alloc::requested_peak_during(|| edge.observe_with_resources(&close).unwrap());
    assert!(!peak.incomplete);
    assert_eq!(
        (peak.live_bytes, peak.live_blocks, peak.failed_requests),
        (0, 0, 0)
    );
    assert!(peak.realloc_overlap_bytes <= resources::SCRATCH_PROVEN_BYTES);
    assert_eq!(
        (edge.cancelled(), edge.resource_usage().active_machines),
        (cancellations_before_close + 11, 0)
    );
    assert_eq!(edge.resource_usage().detached_calls, 256);
    assert!(edge.detached.values().all(|id| id.owner.is_none()));
    let (_, cleanup) = crate::test_alloc::requested_peak_during(|| edge.invalidate());
    assert!(!cleanup.incomplete);
    assert_eq!(
        (
            cleanup.peak_bytes,
            cleanup.live_blocks,
            cleanup.failed_requests
        ),
        (0, 0, 0)
    );
    assert_eq!(
        resources.snapshot().charged_bytes,
        SEMANTIC_TRANSITION_SCRATCH + REDUCER_BASE_CHARGE
    );
    eprintln!(
        "S1_SCRATCH_ROW concentrated_owner machines11 async256 live_peak={} realloc_overlap={}",
        peak.peak_bytes, peak.realloc_overlap_bytes
    );
    eprintln!(
        "S1_RESOURCE_TYPES EdgeSemantics={} PendingCall={} AsyncId={} ResourceLease={}",
        std::mem::size_of::<EdgeSemantics>(),
        std::mem::size_of::<PendingCall>(),
        std::mem::size_of::<AsyncId>(),
        std::mem::size_of::<ResourceLease>()
    );
}
