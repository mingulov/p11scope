//! SPDX-License-Identifier: GPL-3.0-or-later
//! The native completion adjudicator mints only joined evidence: joined
//! detach, proven Q, a backlog-free terminal drain with no
//! reserved-but-uncommitted head, and the minting Session's retained
//! EVENTS identity. The live Session observation wiring mints through the
//! same constructor after the same fail-fast gates.
use super::NativeCompletionMint;
use super::SessionNativeCompletion;
use super::stopped_attachment_admission;
use super::terminal_poll_verdict;
use crate::events::{
    EventDrain, EventsDomain, PendingHeadRecords, ScriptedRecords, TERMINAL_DRAIN_BOUND,
    event_drain_positions, events_head_pending, poll_events_to_position,
};
use p11scope_ebpf_common::Event;
use std::ops::ControlFlow;

fn evidence(
    detach_complete: bool,
    quiescent: bool,
    backlog: bool,
) -> anyhow::Result<SessionNativeCompletion> {
    SessionNativeCompletion::from_joined_evidence(
        detach_complete,
        quiescent,
        backlog,
        false,
        7,
        1,
        3,
        42,
        true,
        11,
    )
}

fn sample_event() -> Event {
    Event {
        ts_ns: 1,
        duration_ns: 2,
        pid_tgid: 3,
        cgroup_id: 4,
        session: 5,
        mechanism: 6,
        rv: 7,
        p0: 0,
        p1: 0,
        p2: 0,
        slot: 8,
        user_type: 10,
        shape: 0,
        attr_types: [0; 8],
        attr_count: 0,
        attr_total: 0,
        attr_bools: 0,
        attr_bools_seen: 0,
        ..Event::default()
    }
}

#[test]
fn joined_evidence_mints_with_exact_counts() {
    let completion = evidence(true, true, false).expect("joined evidence mints");
    assert_eq!(completion.terminal_events(), 7);
    assert_eq!(completion.terminal_malformed(), 1);
    assert_eq!(completion.scrubbed_objects(), 3);
    assert_eq!(completion.detach_wall_ms(), 42);
    assert!(completion.selected_terminal());
    assert_eq!(completion.events_id(), 11);
}

#[test]
fn empty_scrub_and_ordinary_session_still_mint() {
    // The completed scrub and the joined detach are the proof, not the
    // counts: nothing retained, and no selection, mint honestly.
    let completion = SessionNativeCompletion::from_joined_evidence(
        true, true, false, false, 0, 0, 0, 0, false, 11,
    )
    .expect("empty joined evidence mints");
    assert_eq!(completion.terminal_events(), 0);
    assert_eq!(completion.scrubbed_objects(), 0);
    assert!(!completion.selected_terminal());
}

#[test]
fn unjoined_detach_refuses() {
    let error = evidence(false, true, false).expect_err("unjoined detach refuses");
    assert!(
        format!("{error:#}").contains("joined producer detach"),
        "unexpected refusal: {error:#}"
    );
}

#[test]
fn unproven_quiescence_refuses() {
    let error = evidence(true, false, false).expect_err("unproven Q refuses");
    assert!(
        format!("{error:#}").contains("proven quiescence"),
        "unexpected refusal: {error:#}"
    );
}

#[test]
fn terminal_backlog_refuses() {
    let error = evidence(true, true, true).expect_err("terminal backlog refuses");
    assert!(
        format!("{error:#}").contains("backlog"),
        "unexpected refusal: {error:#}"
    );
}

#[test]
fn reserved_head_refuses() {
    // A reserved-but-uncommitted EVENTS head reads empty through the
    // unbounded poll; the positions verdict refuses it by name.
    let error = SessionNativeCompletion::from_joined_evidence(
        true, true, false, true, 0, 0, 0, 0, false, 11,
    )
    .expect_err("reserved head refuses");
    assert!(
        format!("{error:#}").contains("reserved but uncommitted"),
        "unexpected refusal: {error:#}"
    );
}

#[test]
fn empty_read_with_unread_positions_is_pending() {
    // The unbounded poll maps a Pending head to `None` (the false-empty);
    // positions expose the unread bytes, and the mint's exact verdict
    // helper reports the head the adjudicator refuses.
    let mut pending = EventDrain::over(PendingHeadRecords {
        consumer: 0,
        producer: 8,
    });
    assert!(
        !pending.poll(Some(8), |_| ControlFlow::Continue(())),
        "the unbounded poll reads a reserved head as empty"
    );
    assert!(
        events_head_pending(&pending),
        "positions still show the unread head"
    );
    let verdict = terminal_poll_verdict(&mut EventDrain::over(PendingHeadRecords {
        consumer: 0,
        producer: 8,
    }));
    assert!(!verdict.backlog);
    assert!(verdict.head_pending, "the mint verdict keeps the head");
    assert_eq!(verdict.terminal_events, 0);

    // The clean control: a truly empty ring reads empty at both layers.
    let mut clean = EventDrain::over(PendingHeadRecords {
        consumer: 8,
        producer: 8,
    });
    assert!(!clean.poll(Some(8), |_| ControlFlow::Continue(())));
    assert!(!events_head_pending(&clean));
    let verdict = terminal_poll_verdict(&mut EventDrain::over(ScriptedRecords::events([], 0)));
    assert!(!verdict.backlog);
    assert!(!verdict.head_pending);
    assert_eq!(verdict.terminal_events, 0);

    // The same head below a proven-Q stop is the bounded drain's
    // ungated-writer signature, not a clean boundary.
    let mut bounded = EventDrain::over(PendingHeadRecords {
        consumer: 0,
        producer: 8,
    });
    let error = poll_events_to_position(&mut bounded, 8, Some(8), |_| ControlFlow::Continue(()))
        .expect_err("a BUSY head below the stop fails the bounded drain");
    assert!(
        format!("{error:#}").contains("ungated writer before Q"),
        "unexpected failure: {error:#}"
    );
}

#[test]
fn join_gates_refuse_before_consumption() {
    // `join_gates` is the exact check `mint_native_completion` runs
    // before its terminal poll: refusal precedes consumption, so a
    // refused mint leaves the backlog whole for the retry.
    let error = SessionNativeCompletion::join_gates(false, true)
        .expect_err("unjoined detach refuses fail-fast");
    assert!(
        format!("{error:#}").contains("joined producer detach"),
        "unexpected refusal: {error:#}"
    );
    let error =
        SessionNativeCompletion::join_gates(true, false).expect_err("unproven Q refuses fail-fast");
    assert!(
        format!("{error:#}").contains("proven quiescence"),
        "unexpected refusal: {error:#}"
    );
    SessionNativeCompletion::join_gates(true, true).expect("joined gates pass");
}

#[test]
fn refused_mint_leaves_backlog_whole_for_retry() {
    // The mint's order over a scripted backlog, through its real
    // helpers: a Q-false attempt refuses at the fail-fast with the
    // consumer untouched, so the retry's terminal poll sees the whole
    // backlog — the completion accounts every record, never a split tail.
    let mut drain = EventDrain::over(ScriptedRecords::events(
        [sample_event(), sample_event(), sample_event()],
        3,
    ));
    let before = event_drain_positions(&drain);
    assert!(
        SessionNativeCompletion::join_gates(true, false).is_err(),
        "the refused attempt never reaches the poll"
    );
    assert_eq!(
        event_drain_positions(&drain).consumer,
        before.consumer,
        "refusal consumes nothing"
    );
    SessionNativeCompletion::join_gates(true, true).expect("retry gates pass");
    let verdict = terminal_poll_verdict(&mut drain);
    assert!(!verdict.backlog);
    assert!(!verdict.head_pending);
    assert_eq!(verdict.terminal_events, 3);
    let after = event_drain_positions(&drain);
    assert_eq!(
        after.consumer, after.producer,
        "the retry drained the whole backlog: no split for a later mint"
    );
}

#[test]
fn post_drain_backlog_refusal_poisons_the_retry() {
    // 65,537 queued valid records, through the mint's real helpers in
    // the mint's order. Attempt 1's terminal poll eats the 65,536-record
    // bound and reports backlog; the pre-scrub refusal fires before any
    // scrub and poisons the mint. Attempt 2 refuses at admission without
    // polling — the leftover tail is never drained, never minted as
    // terminal_events=1 over the forgotten attempt 1.
    let mut drain = EventDrain::over(ScriptedRecords::events(
        (0..=TERMINAL_DRAIN_BOUND).map(|_| sample_event()),
        TERMINAL_DRAIN_BOUND + 1,
    ));
    let mut mint = NativeCompletionMint::default();
    mint.admit().expect("first attempt admitted");
    let verdict = terminal_poll_verdict(&mut drain);
    assert!(verdict.backlog, "the bound-exceeded drain reports backlog");
    assert_eq!(verdict.terminal_events, TERMINAL_DRAIN_BOUND as u64);
    assert_eq!(verdict.terminal_malformed, 0);
    assert!(
        verdict.head_pending,
        "the leftover tail also shows as a pending head"
    );
    let error =
        SessionNativeCompletion::refuse_drain_verdict(verdict.backlog, verdict.head_pending)
            .expect_err("known drain failure refuses before the scrub");
    assert!(
        format!("{error:#}").contains("backlog"),
        "the backlog refusal keeps its name and priority: {error:#}"
    );
    mint.record_destructive_failure();
    // Attempt 2 refuses at admission: the consumer never moves, the tail
    // stays queued, nothing mints.
    let before = event_drain_positions(&drain);
    let error = mint.admit().expect_err("poisoned mint refuses the retry");
    assert!(
        format!("{error:#}").contains("prior mint attempt"),
        "unexpected refusal: {error:#}"
    );
    assert_eq!(
        event_drain_positions(&drain).consumer,
        before.consumer,
        "terminal refusal consumes nothing further"
    );
    assert_eq!(drain.source().remaining(), 1);
    // The hole being closed, pinned: without the poison, the retry's
    // verdict would mint terminal_events=1 over forgotten attempt 1.
    let retry = terminal_poll_verdict(&mut drain);
    assert!(!retry.backlog);
    assert_eq!(retry.terminal_events, 1);
}

#[test]
fn bound_exact_drain_refusal_poisons_the_clean_retry() {
    // The boundary twin: exactly the bound queued. Attempt 1 eats all
    // 65,536 and still reports backlog (the quantum was reached); the
    // pre-scrub refusal poisons the mint, so the retry cannot mint the
    // clean zero-event completion its empty verdict would otherwise allow.
    let mut drain = EventDrain::over(ScriptedRecords::events(
        (0..TERMINAL_DRAIN_BOUND).map(|_| sample_event()),
        TERMINAL_DRAIN_BOUND,
    ));
    let mut mint = NativeCompletionMint::default();
    mint.admit().expect("first attempt admitted");
    let verdict = terminal_poll_verdict(&mut drain);
    assert!(
        verdict.backlog,
        "the quantum-reached drain reports backlog even with nothing left"
    );
    assert_eq!(verdict.terminal_events, TERMINAL_DRAIN_BOUND as u64);
    assert!(
        !verdict.head_pending,
        "every record consumed, positions meet"
    );
    let error =
        SessionNativeCompletion::refuse_drain_verdict(verdict.backlog, verdict.head_pending)
            .expect_err("known drain failure refuses before the scrub");
    assert!(
        format!("{error:#}").contains("backlog"),
        "unexpected refusal: {error:#}"
    );
    mint.record_destructive_failure();
    let before = event_drain_positions(&drain);
    let error = mint.admit().expect_err("poisoned mint refuses the retry");
    assert!(
        format!("{error:#}").contains("prior mint attempt"),
        "unexpected refusal: {error:#}"
    );
    assert_eq!(
        event_drain_positions(&drain).consumer,
        before.consumer,
        "terminal refusal consumes nothing further"
    );
    assert_eq!(drain.source().remaining(), 0);
    // The hole being closed, pinned: without the poison, the retry's
    // empty verdict would mint the clean zero-event completion.
    let retry = terminal_poll_verdict(&mut drain);
    assert!(!retry.backlog);
    assert!(!retry.head_pending);
    assert_eq!(retry.terminal_events, 0);
}

#[test]
fn reserved_head_refuses_before_scrub_by_name() {
    // The pre-scrub check refuses a reserved head by its own name — the
    // diagnostic a scrub error used to preempt when adjudication ran last.
    let error = SessionNativeCompletion::refuse_drain_verdict(false, true)
        .expect_err("reserved head refuses before the scrub");
    assert!(
        format!("{error:#}").contains("reserved but uncommitted"),
        "unexpected refusal: {error:#}"
    );
}

#[test]
fn stopped_attachment_fence_refuses_fresh_links() {
    // The fence every post-static link path calls before touching BPF:
    // stopping or detached refuses by path name; a running session
    // admits. (Recovery is a new Session; the saved completion's joined
    // detach stays authoritative — never silently invalidated.)
    for path in ["dynamic", "diagnostic"] {
        let error = stopped_attachment_admission(true, path)
            .expect_err("stopped session refuses fresh attachment");
        let message = format!("{error:#}");
        assert!(
            message.contains(&format!("{path} attachment refused"))
                && message.contains("stopping or detached"),
            "unexpected refusal: {message}"
        );
        stopped_attachment_admission(false, path).expect("running session admits");
    }
}

#[test]
fn completion_binds_minting_events_domain() {
    // The single-session binding the DR37 1C/1F promotion lane re-checks:
    // the completion binds its minting domain and refuses a foreign one.
    let completion = evidence(true, true, false).expect("joined evidence mints");
    assert!(completion.binds_events(&EventsDomain::test_standin(11)));
    assert!(!completion.binds_events(&EventsDomain::test_standin(12)));
}

#[test]
fn completion_minter_manufactures_nothing_for_unknown_domain() {
    // DR37 A→B: the production minter polls genuine disposal only.
    // An unknown domain (nothing wound down) polls pending — never a
    // manufactured completion.
    use crate::inventory_promotion::lifecycle::NativeCompletionSource as _;
    let mut minter = super::NativeCompletionMinter::new();
    let domain = crate::attach::capture::NativeDomainId::try_mint().expect("mint domain");
    assert!(
        minter.poll_completion(domain).is_none(),
        "an unknown domain polls pending"
    );
}
