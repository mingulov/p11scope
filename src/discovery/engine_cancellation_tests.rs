//! SPDX-License-Identifier: GPL-3.0-or-later
//! Cancellation-adjacent generation-loss diagnostics through the actual Engine.

use super::*;

#[test]
fn named_contradicted_loss_report_defers_without_bail() {
    let (_fixture, mut engine, mut session) = continuity_route();
    let view = engine.views[0].id();
    assert!(
        engine.views[0].still_the_same(),
        "precondition: the fixture child is a live current generation"
    );
    // E17 midfinal correction: a loss report the retained pin contradicts
    // (it re-reads Current for this live child) is declined with a partial
    // mark — never recorded as fatal sticky loss — even when cancellation
    // subsequently closes mutation. Recording it bailed the terminal drain
    // with zero COUNT/EVIDENCE records for a healthy capture.
    let mut pending = PendingViewRetirements::new();
    engine.queue_retirement(view, RetirementCause::GenerationLost, &mut pending);
    assert!(
        pending.is_empty(),
        "a declined report queues nothing: {pending:?}"
    );
    assert!(
        !engine.retirement_intents.contains_key(&view),
        "a declined report records no intent: {:?}",
        engine.retirement_intents
    );
    assert!(
        engine.counters.object_skips.iter().any(|skip| skip.reason
            == "a stale generation report was contradicted or unprovable on pin recheck; retirement deferred"),
        "the deferral is marked: {:?}",
        engine.counters.object_skips
    );
    engine.set_cancel_flag(Arc::new(std::sync::atomic::AtomicBool::new(true)));
    session
        .pid_continuity
        .as_mut()
        .unwrap()
        .borrow_mut()
        .stop_word = p11scope_ebpf_common::STOP_GATE_STOP;
    engine
        .apply_quiesced_discovery(&mut session, Vec::new(), 0)
        .expect("a contradicted report must not abort the batch");
    assert!(
        !engine
            .retirement_intents
            .values()
            .any(|cause| *cause == RetirementCause::GenerationLost),
        "no loss is invented: {:?}",
        engine.retirement_intents
    );
    assert_eq!(engine.views.len(), 1, "the live view stays retained");
    assert!(!engine.expected_target_exit());
}

#[test]
fn recorded_named_loss_still_fails_closed() {
    let (_fixture, mut engine, mut session) = continuity_route();
    let view = engine.views[0].id();
    // Defense in depth: if a loss intent is ever recorded (no production
    // queue path records one without positive evidence anymore), the
    // named capture still fails closed instead of publishing over it.
    engine
        .retirement_intents
        .insert(view, RetirementCause::GenerationLost);
    let error = engine
        .apply_quiesced_discovery(&mut session, Vec::new(), 0)
        .unwrap_err()
        .to_string();
    assert!(
        error.contains("the named process generation changed during live discovery"),
        "{error}"
    );
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
