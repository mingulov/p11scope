//! SPDX-License-Identifier: GPL-3.0-or-later
//! The native completion adjudicator mints only joined evidence: joined
//! detach, proven Q, a backlog-free terminal drain with no
//! reserved-but-uncommitted head, and the minting Session's retained
//! EVENTS identity. The live Session observation wiring mints through the
//! same constructor after the same fail-fast gates.
use super::SessionNativeCompletion;
use super::stopped_attachment_admission;
use super::terminal_poll_verdict;
use crate::events::{
    EventDrain, EventsDomain, PendingHeadRecords, ScriptedRecords, event_drain_positions,
    events_head_pending, poll_events_to_position,
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
