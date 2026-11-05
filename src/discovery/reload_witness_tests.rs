//! SPDX-License-Identifier: GPL-3.0-or-later
//! B17 minimum same-address reload witness (6.12b, D4 R2-D4-1..7):
//! router-seam twins for the named continuation marker.
//!
//! A global-only continuation (local epoch, mapping, storage and absence
//! checks all unchanged; only the per-file global epoch moved) keeps the
//! current [`InstanceId`]s with [`ObserveOutcome::Continued`] — and now
//! qualifies them: the router latches a sticky per-entry taint, counts
//! the observation and every call joining through a tainted entry, and
//! yields the affected identity once through
//! [`InstanceRouter::take_reload_not_excluded`] for the
//! `instance_reload_not_excluded` disclosure. The silent old-ID keep is a
//! safety violation; the keep must be named.
//!
//! The marker discloses undecidability, not a reload: a multi-threaded
//! same-address unload+reload between two scans advances only the global
//! epoch (the native witness globalizes exactly this case), which reads
//! identically to foreign churn afterward. Self-reload vs foreign churn
//! cannot be told apart here; full distinction is 7.01's job.
//!
//! Healthy/failure twins: every marked-continuation case has a mint twin
//! (local move, proven absence, storage_null move, mapping change over a
//! tainted entry all mint untainted IDs) and a never-mark twin
//! (same-triple, mint, fault/stale/retired/capacity outcomes).

use super::*;
use crate::attach::capture::NativeDomainId;
use p11scope_ebpf_common::ImageIdentity;
use p11scope_ebpf_common::InstanceStamp;
use p11scope_ebpf_common::instance::STAMP_VALID;

fn domain() -> NativeDomainId {
    static DOMAIN: std::sync::OnceLock<NativeDomainId> = std::sync::OnceLock::new();
    *DOMAIN.get_or_init(NativeDomainId::mint)
}

fn image(task_cookie: u64, exec_id: u64) -> ImageIdentity {
    ImageIdentity {
        task_cookie,
        exec_id,
    }
}

const COOKIE: u64 = 0x51;
const FILE: u32 = 3;
const BASE_A: u64 = 0x7f00_0000_0000;
const BASE_B: u64 = 0x7f10_0000_0000;
const TEXT: u64 = 0x2000;

/// One shared-object load: r-- at offset 0, r-x text at 0x1000, rw data.
fn load(base: u64) -> Vec<MapRange> {
    vec![
        MapRange::new(base, base + 0x1000, 0, false),
        MapRange::new(base + 0x1000, base + 0x3000, 0x1000, true),
        MapRange::new(base + 0x3000, base + 0x4000, 0x3000, false),
    ]
}

fn observation(local: u64, global: u64, fault: u64, ranges: Vec<MapRange>) -> StableObservation {
    StableObservation {
        file_slot: FILE,
        reading: EpochReading {
            cookie: COOKIE,
            local,
            record_flags: 0,
            global,
            fault,
            sticky: 0,
        },
        ranges,
        fence: 0,
    }
}

fn stamp(local: u32, global: u32, fault: u32) -> InstanceStamp {
    InstanceStamp {
        epoch: local,
        global,
        fault,
        file_slot_plus1: (FILE + 1) as u16,
        flags: STAMP_VALID,
    }
}

fn call(token: u64, stamp: InstanceStamp, ip: u64) -> CallFacts {
    CallFacts {
        token,
        domain: domain(),
        image: image(COOKIE, 0),
        entry: stamp,
        ret: stamp,
        ip: EntryIp::new(ip),
        attached_offset: Some(ip & 0xfff | TEXT),
    }
}

/// The IP of the attached endpoint (file offset TEXT) in the load at `base`.
fn ip_in(base: u64) -> u64 {
    base + TEXT
}

fn router() -> InstanceRouter {
    InstanceRouter::new(domain(), RouterLimits::default())
}

fn joined(route: Route) -> InstanceId {
    match route {
        Route::Joined(id) => id,
        other => panic!("expected a join, got {other:?}"),
    }
}

/// Drain the W1 notifications, asserting the single expected entry.
fn noted_once(router: &mut InstanceRouter, id: InstanceId) {
    let notified = router.take_reload_not_excluded();
    assert_eq!(notified.len(), 1, "one identity disclosed");
    assert_eq!(notified[0].image, image(COOKIE, 0));
    assert_eq!(notified[0].file_slot, FILE);
    assert_eq!(notified[0].ids, vec![id]);
}

#[test]
fn b17_disclosure_label_is_frozen() {
    assert_eq!(RELOAD_NOT_EXCLUDED_LABEL, "instance_reload_not_excluded");
}

#[test]
fn b17_global_only_continuation_keeps_id_with_named_marker() {
    // Healthy twin: the keep is named, never silent. Outcome stays
    // `Continued` (the acceptance match is untouched), the ID is the same,
    // no mint happens — and the drain yields the identity exactly once
    // with the subset counter set.
    let mut r = router();
    assert_eq!(
        r.observe_legacy(observation(2, 0, 0, load(BASE_A))).0,
        ObserveOutcome::New
    );
    let old = joined(r.route(call(1, stamp(2, 0, 0), ip_in(BASE_A))));
    assert!(r.take_reload_not_excluded().is_empty());
    assert_eq!(
        r.observe_legacy(observation(2, 1, 0, load(BASE_A))).0,
        ObserveOutcome::Continued
    );
    let same = joined(r.route(call(2, stamp(2, 1, 0), ip_in(BASE_A))));
    assert_eq!(old, same);
    assert_eq!(r.instances_minted(), 1, "no unconditional mint");
    noted_once(&mut r, old);
    assert_eq!(r.counters().continued, 1);
    assert_eq!(r.counters().continued_across_global, 1);
    assert_eq!(r.counters().joined, 2);
    assert_eq!(r.counters().joined_across_global, 1);
}

#[test]
fn b17_marker_is_sticky_across_same_triple_scan() {
    // A same-triple re-scan refreshes the tainted entry in place: it must
    // neither clear the taint nor re-yield the disclosure.
    let mut r = router();
    r.observe_legacy(observation(2, 0, 0, load(BASE_A)));
    let old = joined(r.route(call(1, stamp(2, 0, 0), ip_in(BASE_A))));
    r.observe_legacy(observation(2, 1, 0, load(BASE_A)));
    noted_once(&mut r, old);
    assert_eq!(
        r.observe_legacy(observation(2, 1, 0, load(BASE_A))).0,
        ObserveOutcome::Continued
    );
    assert!(
        r.take_reload_not_excluded().is_empty(),
        "drain must not re-yield"
    );
    assert_eq!(r.counters().continued, 2);
    assert_eq!(r.counters().continued_across_global, 1);
    // Late calls through the tainted entry stay joined and counted: the
    // taint survived into historical presentation.
    assert_eq!(joined(r.route(call(2, stamp(2, 1, 0), ip_in(BASE_A)))), old);
    assert_eq!(r.counters().joined_across_global, 1);
}

#[test]
fn b17_second_global_churn_counts_but_does_not_reyield() {
    // Every global-only observation counts; the identity discloses once.
    let mut r = router();
    r.observe_legacy(observation(2, 0, 0, load(BASE_A)));
    let old = joined(r.route(call(1, stamp(2, 0, 0), ip_in(BASE_A))));
    assert_eq!(
        r.observe_legacy(observation(2, 1, 0, load(BASE_A))).0,
        ObserveOutcome::Continued
    );
    noted_once(&mut r, old);
    assert_eq!(
        r.observe_legacy(observation(2, 2, 0, load(BASE_A))).0,
        ObserveOutcome::Continued
    );
    assert_eq!(joined(r.route(call(2, stamp(2, 2, 0), ip_in(BASE_A)))), old);
    assert!(r.take_reload_not_excluded().is_empty());
    assert_eq!(r.counters().continued, 2);
    assert_eq!(r.counters().continued_across_global, 2);
    assert_eq!(r.instances_minted(), 1);
}

#[test]
fn b17_same_triple_continuation_never_marks() {
    // The marker fires only on the global-only arm: same-triple scans
    // continue silently (nothing undecidable happened).
    let mut r = router();
    r.observe_legacy(observation(2, 0, 0, load(BASE_A)));
    for token in 1..5 {
        assert_eq!(
            r.observe_legacy(observation(2, 0, 0, load(BASE_A))).0,
            ObserveOutcome::Continued
        );
        joined(r.route(call(token, stamp(2, 0, 0), ip_in(BASE_A))));
    }
    assert!(r.take_reload_not_excluded().is_empty());
    assert_eq!(r.counters().continued, 4);
    assert_eq!(r.counters().continued_across_global, 0);
    assert_eq!(r.counters().joined_across_global, 0);
}

#[test]
fn b17_unknown_storage_still_marks() {
    // Unknown storage on either side keeps the legacy continuation rule —
    // and the continuation is still a global-only arm take, so it marks.
    let mut r = router();
    assert_eq!(r.storage_seen_for(image(COOKIE, 0), FILE), None);
    r.observe_legacy(observation(2, 0, 0, load(BASE_A)));
    let old = joined(r.route(call(1, stamp(2, 0, 0), ip_in(BASE_A))));
    assert_eq!(
        r.observe_legacy(observation(2, 1, 0, load(BASE_A))).0,
        ObserveOutcome::Continued
    );
    noted_once(&mut r, old);
    assert_eq!(r.counters().continued_across_global, 1);
}

#[test]
fn b17_local_move_over_tainted_mints_untainted() {
    // Failure twin: a witness-attributed reload (local move) mints a fresh
    // ID even over a tainted entry — and the new entry is untainted while
    // the old tainted history still joins and counts.
    let mut r = router();
    r.observe_legacy(observation(2, 0, 0, load(BASE_A)));
    let old = joined(r.route(call(1, stamp(2, 0, 0), ip_in(BASE_A))));
    r.observe_legacy(observation(2, 1, 0, load(BASE_A)));
    noted_once(&mut r, old);
    assert_eq!(
        r.observe_legacy(observation(3, 1, 0, load(BASE_A))).0,
        ObserveOutcome::New
    );
    let new = joined(r.route(call(2, stamp(3, 1, 0), ip_in(BASE_A))));
    assert_ne!(old, new);
    assert!(new > old, "IDs are monotonic, never reused");
    assert_eq!(r.counters().joined_across_global, 0);
    // History is not rewritten: late calls stamped at the tainted epochs
    // still join the old ID, and count as tainted joins.
    assert_eq!(joined(r.route(call(3, stamp(2, 1, 0), ip_in(BASE_A)))), old);
    assert_eq!(r.counters().joined_across_global, 1);
    assert!(r.take_reload_not_excluded().is_empty());
}

#[test]
fn b17_absence_over_tainted_mints() {
    // A scan that proved the module unmapped breaks even tainted
    // continuity: the reload mints instead of continuing.
    let mut r = router();
    r.observe_legacy(observation(2, 0, 0, load(BASE_A)));
    let old = joined(r.route(call(1, stamp(2, 0, 0), ip_in(BASE_A))));
    r.observe_legacy(observation(2, 1, 0, load(BASE_A)));
    noted_once(&mut r, old);
    r.note_proven_absence(image(COOKIE, 0), FILE);
    assert_eq!(
        r.observe_legacy(observation(2, 2, 0, load(BASE_A))).0,
        ObserveOutcome::New
    );
    let new = joined(r.route(call(2, stamp(2, 2, 0), ip_in(BASE_A))));
    assert_ne!(old, new);
    assert_eq!(r.counters().joined_across_global, 0);
}

#[test]
fn b17_storage_null_move_over_tainted_mints() {
    // A moved storage_null counter fails closed toward a mint even when
    // the epochs alone would continue a tainted entry.
    let mut r = router();
    r.note_storage_null(Some(5));
    r.observe_legacy(observation(2, 0, 0, load(BASE_A)));
    let old = joined(r.route(call(1, stamp(2, 0, 0), ip_in(BASE_A))));
    assert_eq!(
        r.observe_legacy(observation(2, 1, 0, load(BASE_A))).0,
        ObserveOutcome::Continued
    );
    noted_once(&mut r, old);
    r.note_storage_null(Some(6));
    assert_eq!(
        r.observe_legacy(observation(2, 2, 0, load(BASE_A))).0,
        ObserveOutcome::New
    );
    let new = joined(r.route(call(2, stamp(2, 2, 0), ip_in(BASE_A))));
    assert_ne!(old, new);
    assert_eq!(r.counters().continued_across_global, 1);
    assert_eq!(r.counters().joined_across_global, 0);
}

#[test]
fn b17_mapping_change_over_tainted_mints() {
    // A real remap over a tainted entry mints: the marker never launders
    // a mapping change into continuity.
    let mut r = router();
    r.observe_legacy(observation(2, 0, 0, load(BASE_A)));
    let old = joined(r.route(call(1, stamp(2, 0, 0), ip_in(BASE_A))));
    r.observe_legacy(observation(2, 1, 0, load(BASE_A)));
    noted_once(&mut r, old);
    assert_eq!(
        r.observe_legacy(observation(2, 2, 0, load(BASE_B))).0,
        ObserveOutcome::New
    );
    let new = joined(r.route(call(2, stamp(2, 2, 0), ip_in(BASE_B))));
    assert_ne!(old, new);
    assert_eq!(r.counters().joined_across_global, 0);
}

#[test]
fn b17_foreign_churn_stays_joined_without_mint() {
    // No unconditional mint: repeated global-only churn keeps joining the
    // one instance while every observation counts and discloses once.
    let mut r = router();
    r.observe_legacy(observation(2, 0, 0, load(BASE_A)));
    let old = joined(r.route(call(1, stamp(2, 0, 0), ip_in(BASE_A))));
    for global in 1u32..5 {
        let token = u64::from(global) + 1;
        assert_eq!(
            r.observe_legacy(observation(2, u64::from(global), 0, load(BASE_A)))
                .0,
            ObserveOutcome::Continued
        );
        assert_eq!(
            joined(r.route(call(token, stamp(2, global, 0), ip_in(BASE_A)))),
            old
        );
    }
    assert_eq!(r.instances_minted(), 1);
    assert_eq!(r.counters().continued, 4);
    assert_eq!(r.counters().continued_across_global, 4);
    assert_eq!(r.counters().joined, 5);
    assert_eq!(r.counters().joined_across_global, 4);
    noted_once(&mut r, old);
}

#[test]
fn b17_threaded_reload_stamp_joins_tainted() {
    // Disclosed-guess pin: a call stamped after the global churn — the
    // shape a threaded same-address reload leaves (local unchanged,
    // global moved, mapping same) — joins the continued ID, and the join
    // counts as tainted. The join is the documented guess, now disclosed.
    let mut r = router();
    r.observe_legacy(observation(2, 0, 0, load(BASE_A)));
    let old = joined(r.route(call(1, stamp(2, 0, 0), ip_in(BASE_A))));
    r.observe_legacy(observation(2, 1, 0, load(BASE_A)));
    assert_eq!(joined(r.route(call(2, stamp(2, 1, 0), ip_in(BASE_A)))), old);
    assert_eq!(r.counters().joined, 2);
    assert_eq!(r.counters().joined_across_global, 1);
    noted_once(&mut r, old);
}

#[test]
fn b17_delayed_pre_churn_call_does_not_count_tainted() {
    // The taint attaches to the matched entry, not the numeric ID: a
    // delayed call stamped at the pre-churn (untainted) epochs joins the
    // same ID without counting as a tainted join.
    let mut r = router();
    r.observe_legacy(observation(2, 0, 0, load(BASE_A)));
    let old = joined(r.route(call(1, stamp(2, 0, 0), ip_in(BASE_A))));
    r.observe_legacy(observation(2, 1, 0, load(BASE_A)));
    noted_once(&mut r, old);
    assert_eq!(joined(r.route(call(2, stamp(2, 0, 0), ip_in(BASE_A)))), old);
    assert_eq!(r.counters().joined, 2);
    assert_eq!(r.counters().joined_across_global, 0);
}

#[test]
fn b17_pending_call_resolving_through_tainted_counts() {
    // Pending resolution counts like a direct route: the call waited for
    // the post-churn observation and joined through the tainted entry.
    let mut r = router();
    r.observe_legacy(observation(2, 0, 0, load(BASE_A)));
    let old = joined(r.route(call(1, stamp(2, 0, 0), ip_in(BASE_A))));
    assert_eq!(
        r.route(call(2, stamp(2, 1, 0), ip_in(BASE_A))),
        Route::Pending
    );
    let (outcome, resolved) = r.observe_legacy(observation(2, 1, 0, load(BASE_A)));
    assert_eq!(outcome, ObserveOutcome::Continued);
    assert_eq!(resolved, vec![(2, Route::Joined(old))]);
    assert_eq!(r.counters().joined, 2);
    assert_eq!(r.counters().joined_across_global, 1);
    noted_once(&mut r, old);
}

#[test]
fn b17_refusing_outcomes_never_mark() {
    // Never on mint, fault/stale/retired/capacity: only the taken
    // continuation arm marks.
    let mut r = router();
    r.observe_legacy(observation(2, 0, 0, load(BASE_A)));
    let _old = joined(r.route(call(1, stamp(2, 0, 0), ip_in(BASE_A))));
    // A mint first: no mark.
    assert_eq!(
        r.observe_legacy(observation(3, 0, 0, load(BASE_A))).0,
        ObserveOutcome::New
    );
    assert!(r.take_reload_not_excluded().is_empty());
    assert_eq!(r.counters().continued_across_global, 0);
    // A stale era next: no mark.
    r.audit(1, 0, 0);
    assert_eq!(
        r.observe_legacy(observation(3, 0, 0, load(BASE_A))).0,
        ObserveOutcome::StaleEra
    );
    assert!(r.take_reload_not_excluded().is_empty());
    // A retired image next (fresh fence and era, so the refusal is the
    // retirement, not staleness): no mark.
    r.retire_image(image(COOKIE, 0));
    let mut retired = observation(3, 1, 1, load(BASE_A));
    retired.fence = r.fence();
    assert_eq!(r.observe_legacy(retired).0, ObserveOutcome::Retired);
    assert!(r.take_reload_not_excluded().is_empty());
    assert_eq!(r.counters().continued_across_global, 0);
    assert_eq!(r.counters().joined_across_global, 0);
}

#[test]
fn b17_receipt_gate_inputs_unchanged_for_tainted() {
    // Semantic-capture neighbor proxy: the acceptance match consumes
    // `Continued` (pinned above) and the current-partition receipt consumes
    // `current_instances` + `current_partition_matches`. Both must keep
    // working over a tainted continuation, so unchanged capture code keeps
    // refreshing bindings and minting receipts for it.
    let mut r = router();
    r.observe_legacy(observation(2, 0, 0, load(BASE_A)));
    let old = joined(r.route(call(1, stamp(2, 0, 0), ip_in(BASE_A))));
    assert_eq!(
        r.observe_legacy(observation(2, 1, 0, load(BASE_A))).0,
        ObserveOutcome::Continued
    );
    noted_once(&mut r, old);
    let ids = r.current_instances(domain(), image(COOKIE, 0), FILE);
    assert_eq!(ids, vec![old]);
    assert!(r.current_partition_matches(
        domain(),
        image(COOKIE, 0),
        FILE,
        crate::attach::image_query::CompleteEpochs {
            local: 2,
            global: 1,
            fault: 0,
            sticky: 0,
            record_flags: 0,
        },
        r.fence(),
        &ids,
    ));
}

/// Production-path twins: the same marker through sealed full-image scans
/// (`observe`, not `observe_legacy`).
mod full_image {
    use super::*;
    use crate::attach::image_query::{CompleteEpochs, ImageScanProof, acquire_test_scan};

    fn seal(
        owner: NativeDomainId,
        identity: ImageIdentity,
        local: u64,
        global: u64,
        fault: u64,
        fence: u64,
    ) -> ImageScanProof {
        acquire_test_scan(
            owner,
            identity,
            FILE,
            CompleteEpochs {
                local,
                global,
                fault,
                sticky: 0,
                record_flags: 0,
            },
            load(BASE_A),
            fence,
        )
        .expect("nonempty stable acquisition")
    }

    fn facts(
        token: u64,
        owner: NativeDomainId,
        identity: ImageIdentity,
        local: u32,
        global: u32,
        fault: u32,
    ) -> CallFacts {
        CallFacts {
            token,
            domain: owner,
            image: identity,
            entry: stamp(local, global, fault),
            ret: stamp(local, global, fault),
            ip: EntryIp::new(ip_in(BASE_A)),
            attached_offset: Some(TEXT),
        }
    }

    #[test]
    fn b17_sealed_global_only_continuation_marks() {
        let mut r = router();
        let identity = image(COOKIE, 10);
        assert_eq!(
            r.observe(seal(domain(), identity, 1, 0, 0, 0)).0,
            ObserveOutcome::New
        );
        let old = joined(r.route(facts(1, domain(), identity, 1, 0, 0)));
        assert!(r.take_reload_not_excluded().is_empty());
        assert_eq!(
            r.observe(seal(domain(), identity, 1, 1, 0, 0)).0,
            ObserveOutcome::Continued
        );
        assert_eq!(joined(r.route(facts(2, domain(), identity, 1, 1, 0))), old);
        assert_eq!(r.instances_minted(), 1);
        let notified = r.take_reload_not_excluded();
        assert_eq!(notified.len(), 1);
        assert_eq!(notified[0].image, identity);
        assert_eq!(notified[0].file_slot, FILE);
        assert_eq!(notified[0].ids, vec![old]);
        assert_eq!(r.counters().continued_across_global, 1);
        assert_eq!(r.counters().joined_across_global, 1);
    }

    #[test]
    fn b17_sealed_local_move_mints_untainted() {
        let mut r = router();
        let identity = image(COOKIE, 10);
        r.observe(seal(domain(), identity, 1, 0, 0, 0));
        let old = joined(r.route(facts(1, domain(), identity, 1, 0, 0)));
        r.observe(seal(domain(), identity, 1, 1, 0, 0));
        assert_eq!(r.take_reload_not_excluded().len(), 1);
        assert_eq!(
            r.observe(seal(domain(), identity, 2, 1, 0, 0)).0,
            ObserveOutcome::New
        );
        let new = joined(r.route(facts(2, domain(), identity, 2, 1, 0)));
        assert_ne!(old, new);
        assert_eq!(r.counters().joined_across_global, 0);
        assert!(r.take_reload_not_excluded().is_empty());
    }
}
