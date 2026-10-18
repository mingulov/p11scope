//! SPDX-License-Identifier: GPL-3.0-or-later
//! The native completion adjudicator mints only joined evidence: joined
//! detach, proven Q and a backlog-free terminal drain. The live Session
//! observation wiring mints through the same constructor.
use super::SessionNativeCompletion;

fn evidence(
    detach_complete: bool,
    quiescent: bool,
    backlog: bool,
) -> anyhow::Result<SessionNativeCompletion> {
    SessionNativeCompletion::from_joined_evidence(
        detach_complete,
        quiescent,
        backlog,
        7,
        1,
        3,
        42,
        true,
    )
}

#[test]
fn joined_evidence_mints_with_exact_counts() {
    let completion = evidence(true, true, false).expect("joined evidence mints");
    assert_eq!(completion.terminal_events(), 7);
    assert_eq!(completion.terminal_malformed(), 1);
    assert_eq!(completion.scrubbed_objects(), 3);
    assert_eq!(completion.detach_wall_ms(), 42);
    assert!(completion.selected_terminal());
}

#[test]
fn empty_scrub_and_ordinary_session_still_mint() {
    // The completed scrub and the joined detach are the proof, not the
    // counts: nothing retained, and no selection, mint honestly.
    let completion =
        SessionNativeCompletion::from_joined_evidence(true, true, false, 0, 0, 0, 0, false)
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
