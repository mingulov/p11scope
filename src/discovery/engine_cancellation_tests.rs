//! SPDX-License-Identifier: GPL-3.0-or-later
//! Cancellation-adjacent generation-loss diagnostics through the actual Engine.

use super::*;

#[test]
fn named_generation_loss_keeps_enqueue_witness_after_later_cancellation() {
    let (_fixture, mut engine, mut session) = continuity_route();
    let view = engine.views[0].id();
    let pid = engine.views[0].pid();
    let mut pending = PendingViewRetirements::new();
    // An existing loss must remain a loss even when the next retained-pin
    // observation is Current and cancellation subsequently closes mutation.
    let enqueue_line = line!() + 1;
    engine.queue_retirement(view, RetirementCause::GenerationLost, &mut pending);
    engine.set_cancel_flag(Arc::new(std::sync::atomic::AtomicBool::new(true)));
    session
        .pid_continuity
        .as_mut()
        .unwrap()
        .borrow_mut()
        .stop_word = p11scope_ebpf_common::STOP_GATE_STOP;
    let error = engine
        .apply_quiesced_discovery(&mut session, Vec::new(), 0)
        .unwrap_err()
        .to_string();
    assert!(error.contains("the named process generation changed during live discovery"));
    assert!(
        error.contains(&format!("view={} pid={pid}", view.0)),
        "{error}"
    );
    assert!(
        error.contains(&format!("enqueue_line={enqueue_line}")),
        "{error}"
    );
    assert!(
        error.contains("incoming=GenerationLost previous=None"),
        "{error}"
    );
    assert!(error.contains("original=Current"), "{error}");
    assert!(error.contains("cancel_at_enqueue=false"), "{error}");
    assert!(
        error.contains("cancel_now=true mutation_stopped=true"),
        "{error}"
    );
    assert!(!engine.expected_target_exit());
}

#[test]
fn named_cancellation_with_current_original_does_not_invent_generation_loss() {
    let (_fixture, mut engine, mut session) = continuity_route();
    engine.set_cancel_flag(Arc::new(std::sync::atomic::AtomicBool::new(true)));
    session
        .pid_continuity
        .as_mut()
        .unwrap()
        .borrow_mut()
        .stop_word = p11scope_ebpf_common::STOP_GATE_STOP;
    engine
        .apply_quiesced_discovery(&mut session, Vec::new(), 0)
        .unwrap();
    assert!(engine.views[0].still_the_same());
    assert!(
        !engine
            .retirement_intents
            .values()
            .any(|cause| *cause == RetirementCause::GenerationLost)
    );
}
