//! SPDX-License-Identifier: GPL-3.0-or-later
//! Router and scan-protocol regressions for Task 3 Stage A.

use super::*;
use p11scope_ebpf_common::InstanceStamp;
use p11scope_ebpf_common::instance::{
    STAMP_LOCAL_FAULT, STAMP_NO_FILE, STAMP_NO_TASK, STAMP_OVERFLOW, STAMP_SHARED_MM, STAMP_VALID,
};

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

fn reading(local: u64, global: u64, fault: u64) -> EpochReading {
    EpochReading {
        cookie: COOKIE,
        local,
        record_flags: 0,
        global,
        fault,
        sticky: 0,
    }
}

fn observation(local: u64, global: u64, fault: u64, ranges: Vec<MapRange>) -> StableObservation {
    StableObservation {
        file_slot: FILE,
        reading: reading(local, global, fault),
        ranges,
        // Acquired at fence 0 (no audit yet); post-audit acceptances use
        // `fresh` to stamp the router's current fence instead.
        fence: 0,
    }
}

/// A scan acquired now: stamps the router's current publication fence, as
/// the capture loop does before scanning. Pre-reset cached scans keep
/// their old stamp and observe as `StaleEra`.
fn fresh(router: &InstanceRouter, mut observation: StableObservation) -> StableObservation {
    observation.fence = router.fence();
    observation
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

fn observation_for(cookie: u64, local: u64, ranges: Vec<MapRange>) -> StableObservation {
    StableObservation {
        file_slot: FILE,
        reading: EpochReading {
            cookie,
            local,
            record_flags: 0,
            global: 0,
            fault: 0,
            sticky: 0,
        },
        ranges,
        fence: 0,
    }
}

fn call_for(token: u64, cookie: u64, stamp: InstanceStamp, ip: u64) -> CallFacts {
    CallFacts {
        token,
        domain: domain(),
        image: image(cookie, 0),
        entry: stamp,
        ret: stamp,
        ip: EntryIp::new(ip),
        attached_offset: Some(ip & 0xfff | TEXT),
    }
}

fn joined(route: Route) -> InstanceId {
    match route {
        Route::Joined(id) => id,
        other => panic!("expected a join, got {other:?}"),
    }
}

/// These tests use the production proof consumer and the owning scan protocol,
/// unlike the legacy scalar epoch fixtures below. The I/O script supplies
/// stable reads; identity, range, epoch and original-fence checks remain real.
mod full_image {
    use super::*;
    use crate::attach::image_query::{CompleteEpochs, ImageScanProof, acquire_test_scan};

    fn seal(
        owner: NativeDomainId,
        identity: ImageIdentity,
        local: u64,
        fault: u64,
        fence: u64,
    ) -> ImageScanProof {
        acquire_test_scan(
            owner,
            identity,
            FILE,
            CompleteEpochs {
                local,
                global: 0,
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
        fault: u32,
    ) -> CallFacts {
        CallFacts {
            token,
            domain: owner,
            image: identity,
            entry: stamp(local, 0, fault),
            ret: stamp(local, 0, fault),
            ip: EntryIp::new(ip_in(BASE_A)),
            attached_offset: Some(TEXT),
        }
    }

    #[test]
    fn stable_full_image_seal_joins_nonempty_supported_load() {
        let mut r = router();
        let identity = image(COOKIE, 10);
        assert_eq!(
            r.observe(seal(domain(), identity, 1, 0, 0)).0,
            ObserveOutcome::New
        );
        let first = joined(r.route(facts(1, domain(), identity, 1, 0)));
        assert_eq!(
            r.observe(seal(domain(), identity, 1, 0, 0)).0,
            ObserveOutcome::Continued
        );
        assert_eq!(joined(r.route(facts(2, domain(), identity, 1, 0))), first);
        assert_eq!(r.instances_minted(), 1);
        assert_eq!(r.ranges_retained(), 3);
    }

    #[test]
    fn same_cookie_exec_images_never_share_instance() {
        let mut r = router();
        let old = image(COOKIE, 10);
        let successor = image(COOKIE, 11);
        r.observe(seal(domain(), old, 1, 0, 0));
        let old_id = joined(r.route(facts(1, domain(), old, 1, 0)));
        assert_eq!(
            r.observe(seal(domain(), successor, 1, 0, 0)).0,
            ObserveOutcome::New
        );
        let new_id = joined(r.route(facts(2, domain(), successor, 1, 0)));
        assert_ne!(old_id, new_id);
        assert_eq!(joined(r.route(facts(3, domain(), old, 1, 0))), old_id);
    }

    #[test]
    fn retired_exec_allows_same_cookie_successor() {
        let mut r = router();
        let old = image(COOKIE, 10);
        let successor = image(COOKIE, 11);
        r.observe(seal(domain(), old, 1, 0, 0));
        let old_id = joined(r.route(facts(1, domain(), old, 1, 0)));
        assert_eq!(r.route(facts(2, domain(), old, 2, 0)), Route::Pending);
        assert_eq!(r.route(facts(3, domain(), successor, 2, 0)), Route::Pending);
        assert_eq!(
            r.retire_image(old),
            vec![(2, Route::Unknown(UnknownReason::Retired))],
        );
        assert_eq!(r.pending_len(), 1);
        let (outcome, resolved) = r.observe(seal(domain(), successor, 2, 0, r.fence()));
        assert_eq!(outcome, ObserveOutcome::New);
        assert_eq!(resolved.len(), 1);
        assert_eq!(resolved[0].0, 3);
        let successor_id = joined(resolved[0].1);
        assert_ne!(successor_id, old_id);
        assert_eq!(
            joined(r.route(facts(4, domain(), successor, 2, 0))),
            successor_id
        );
    }

    #[test]
    fn old_scan_after_exec_never_revives() {
        let mut r = router();
        let old = image(COOKIE, 10);
        let successor = image(COOKIE, 11);
        r.observe(seal(domain(), old, 1, 0, 0));
        let old_id = joined(r.route(facts(1, domain(), old, 1, 0)));
        let cached = seal(domain(), old, 1, 0, r.fence());
        r.retire_image(old);
        assert_eq!(r.observe(cached).0, ObserveOutcome::Retired);
        assert_eq!(
            r.route(facts(2, domain(), old, 1, 0)),
            Route::Unknown(UnknownReason::Retired)
        );
        assert_eq!(
            r.observe(seal(domain(), successor, 1, 0, r.fence())).0,
            ObserveOutcome::New
        );
        assert_ne!(joined(r.route(facts(3, domain(), successor, 1, 0))), old_id);
        assert_eq!(
            r.observe(seal(domain(), old, 1, 0, r.fence())).0,
            ObserveOutcome::Retired
        );
    }

    #[test]
    fn equal_cookie_foreign_domain_refuses() {
        let mut r = router();
        let identity = image(COOKIE, 10);
        r.observe(seal(domain(), identity, 1, 0, 0));
        let own_id = joined(r.route(facts(1, domain(), identity, 1, 0)));
        let before = (
            r.instances_minted(),
            r.ranges_retained(),
            r.pending_len(),
            r.counters().joined,
        );
        let foreign = NativeDomainId::mint();
        assert_ne!(foreign, domain());
        assert_eq!(
            r.route(facts(2, foreign, identity, 1, 0)),
            Route::Unknown(UnknownReason::ForeignDomain)
        );
        assert_eq!(
            (
                r.instances_minted(),
                r.ranges_retained(),
                r.pending_len(),
                r.counters().joined
            ),
            before
        );
        assert_eq!(joined(r.route(facts(3, domain(), identity, 1, 0))), own_id);
    }

    #[test]
    fn out_of_range_file_stamp_refuses_before_pending_capacity() {
        let mut r = router();
        let identity = image(COOKIE, 10);
        r.observe(seal(domain(), identity, 1, 0, 0));
        let own_id = joined(r.route(facts(1, domain(), identity, 1, 0)));
        let mut invalid = facts(2, domain(), identity, 1, 0);
        invalid.entry.file_slot_plus1 = (instance::FILE_SLOTS + 1) as u16;
        invalid.ret = invalid.entry;
        assert_eq!(r.route(invalid), Route::Unknown(UnknownReason::NoFile));
        assert_eq!(r.pending_len(), 0);
        assert_eq!(r.instances_minted(), 1);
        assert_eq!(joined(r.route(facts(3, domain(), identity, 1, 0))), own_id);
    }

    #[test]
    fn foreign_domain_seal_never_resolves_pending() {
        let mut r = router();
        let identity = image(COOKIE, 10);
        assert_eq!(r.route(facts(1, domain(), identity, 1, 0)), Route::Pending);
        let foreign = NativeDomainId::mint();
        let before = r.counters();
        assert_eq!(
            r.observe(seal(foreign, identity, 1, 0, r.fence())),
            (ObserveOutcome::ForeignDomain, Vec::new()),
        );
        assert_eq!(r.instances_minted(), 0);
        assert_eq!(r.ranges_retained(), 0);
        assert_eq!(r.pending_len(), 1);
        assert_eq!(r.counters(), before);
        let (outcome, resolved) = r.observe(seal(domain(), identity, 1, 0, r.fence()));
        assert_eq!(outcome, ObserveOutcome::New);
        assert_eq!(resolved.len(), 1);
        assert_eq!(resolved[0].0, 1);
        assert_eq!(
            joined(r.route(facts(2, domain(), identity, 1, 0))),
            joined(resolved[0].1)
        );
    }

    #[test]
    fn retirement_eviction_cannot_reopen_ended_image() {
        let mut r = InstanceRouter::new(
            domain(),
            RouterLimits {
                retired_cookies: 1,
                ..RouterLimits::default()
            },
        );
        let ended = image(COOKIE, 10);
        let successor = image(COOKIE, 11);
        let other = image(COOKIE + 1, 3);
        r.observe(seal(domain(), ended, 1, 0, 0));
        r.observe(seal(domain(), other, 1, 0, 0));
        joined(r.route(facts(1, domain(), other, 1, 0)));
        // This old seal already reads the next kernel fault. Its original
        // router fence still predates the audit and may never be restamped.
        let cached = seal(domain(), ended, 1, 1, r.fence());
        r.retire_image(ended);
        r.retire_image(image(COOKIE + 2, 1));
        r.audit(1, 0, 0);
        assert_eq!(r.observe(cached).0, ObserveOutcome::StaleEra);
        assert_eq!(
            r.observe(seal(domain(), ended, 1, 1, r.fence())).0,
            ObserveOutcome::Retired
        );
        assert_eq!(
            r.route(facts(2, domain(), ended, 1, 1)),
            Route::Unknown(UnknownReason::Retired)
        );
        assert_eq!(
            r.observe(seal(domain(), successor, 1, 1, r.fence())).0,
            ObserveOutcome::New
        );
        joined(r.route(facts(3, domain(), successor, 1, 1)));
        assert_eq!(
            r.observe(seal(domain(), other, 1, 1, r.fence())).0,
            ObserveOutcome::New
        );
        joined(r.route(facts(4, domain(), other, 1, 1)));
    }

    #[test]
    fn retirement_overflow_never_poisons_an_unrelated_fresh_cookie() {
        let mut r = InstanceRouter::new(
            domain(),
            RouterLimits {
                retired_cookies: 1,
                ..RouterLimits::default()
            },
        );
        let ended = image(COOKIE, 1_000_000);
        let fresh = image(COOKIE + 1, 0);
        r.observe(seal(domain(), ended, 1, 0, 0));
        joined(r.route(facts(1, domain(), ended, 1, 0)));
        r.retire_image(ended);
        r.retire_image(image(COOKIE + 2, 2));
        r.audit(1, 0, 0);
        assert_eq!(
            r.observe(seal(domain(), ended, 1, 1, r.fence())).0,
            ObserveOutcome::Retired
        );
        assert_eq!(
            r.observe(seal(domain(), fresh, 1, 1, r.fence())).0,
            ObserveOutcome::New
        );
        joined(r.route(facts(2, domain(), fresh, 1, 1)));
    }

    #[test]
    fn retirement_overflow_preserves_another_cookies_low_exec_successor() {
        let mut r = InstanceRouter::new(
            domain(),
            RouterLimits {
                retired_cookies: 1,
                ..RouterLimits::default()
            },
        );
        let high = image(COOKIE, 1_000_000);
        let old = image(COOKIE + 1, 3);
        let successor = image(COOKIE + 1, 4);
        r.observe(seal(domain(), old, 1, 0, 0));
        let old_id = joined(r.route(facts(1, domain(), old, 1, 0)));
        r.retire_image(high);
        r.retire_image(old);
        r.audit(1, 0, 0);
        assert_eq!(
            r.observe(seal(domain(), high, 1, 1, r.fence())).0,
            ObserveOutcome::Retired
        );
        assert_eq!(
            r.observe(seal(domain(), old, 1, 1, r.fence())).0,
            ObserveOutcome::Retired
        );
        assert_eq!(
            r.observe(seal(domain(), successor, 1, 1, r.fence())).0,
            ObserveOutcome::New
        );
        assert_ne!(joined(r.route(facts(2, domain(), successor, 1, 1))), old_id);
    }

    #[test]
    fn pending_expiry_and_retirement_are_image_scoped() {
        let mut r = router();
        let old = image(COOKIE, 10);
        let successor = image(COOKIE, 11);
        let other = image(COOKIE + 1, 2);
        for (token, identity) in [(1, old), (2, successor), (3, other)] {
            assert_eq!(
                r.route(facts(token, domain(), identity, 1, 0)),
                Route::Pending
            );
        }
        assert_eq!(
            r.expire_image(old),
            vec![(1, Route::Unknown(UnknownReason::Unobserved))]
        );
        assert!(r.expire_image(old).is_empty());
        assert_eq!(r.pending_len(), 2);
        let (_, successor_calls) = r.observe(seal(domain(), successor, 1, 0, 0));
        assert_eq!(successor_calls.len(), 1);
        assert_eq!(successor_calls[0].0, 2);
        joined(successor_calls[0].1);
        let (_, other_calls) = r.observe(seal(domain(), other, 1, 0, 0));
        assert_eq!(other_calls.len(), 1);
        assert_eq!(other_calls[0].0, 3);
        joined(other_calls[0].1);
        assert_eq!(r.pending_len(), 0);
    }

    #[test]
    fn sealed_original_fence_cannot_be_restamped() {
        let mut r = router();
        let identity = image(COOKIE, 10);
        r.observe(seal(domain(), identity, 1, 0, 0));
        joined(r.route(facts(1, domain(), identity, 1, 0)));
        let cached = seal(domain(), identity, 1, 1, r.fence());
        r.audit(1, 0, 0);
        assert_eq!(r.fence(), 1);
        assert_eq!(r.observe(cached).0, ObserveOutcome::StaleEra);
        assert_eq!(
            r.observe(seal(domain(), identity, 1, 1, r.fence())).0,
            ObserveOutcome::New
        );
        joined(r.route(facts(2, domain(), identity, 1, 1)));
    }

    #[test]
    fn exhausted_fence_never_reuses_zero_authority() {
        let mut r = router();
        let identity = image(COOKIE, 10);
        r.observe(seal(domain(), identity, 1, 0, 0));
        joined(r.route(facts(1, domain(), identity, 1, 0)));
        let cached_zero = seal(domain(), identity, 1, 1, 0);
        r.fence = u64::MAX;
        r.audit(1, 0, 0);
        assert_eq!(
            r.fence(),
            u64::MAX,
            "exhaustion must not wrap the retained authority"
        );
        assert_eq!(r.observe(cached_zero).0, ObserveOutcome::StaleEra);
        assert_eq!(
            r.route(facts(2, domain(), identity, 1, 1)),
            Route::Unknown(UnknownReason::AuthorityExhausted)
        );
    }

    #[test]
    fn fault_outside_stamp_width_permanently_refuses() {
        let mut r = router();
        let identity = image(COOKIE, 10);
        r.observe(seal(domain(), identity, 1, 0, 0));
        joined(r.route(facts(1, domain(), identity, 1, 0)));
        r.audit(u64::from(u32::MAX) + 1, 0, 0);
        assert_eq!(
            r.route(facts(2, domain(), identity, 1, 0)),
            Route::Unknown(UnknownReason::AuthorityExhausted)
        );
        r.audit(0, 0, 0);
        assert_eq!(
            r.observe(seal(domain(), identity, 1, 0, r.fence())).0,
            ObserveOutcome::StaleEra
        );
        assert_eq!(
            r.route(facts(3, domain(), identity, 1, 0)),
            Route::Unknown(UnknownReason::AuthorityExhausted)
        );
    }

    #[test]
    fn decreasing_fault_never_reopens_a_completed_era() {
        let mut r = router();
        let identity = image(COOKIE, 10);
        r.audit(1, 0, 0);
        r.observe(seal(domain(), identity, 1, 1, r.fence()));
        joined(r.route(facts(1, domain(), identity, 1, 1)));
        r.audit(0, 0, 0);
        assert_eq!(
            r.observe(seal(domain(), identity, 1, 0, r.fence())).0,
            ObserveOutcome::StaleEra
        );
        assert_eq!(
            r.route(facts(2, domain(), identity, 1, 0)),
            Route::Unknown(UnknownReason::AuthorityExhausted)
        );
    }
}

#[test]
fn same_epochs_under_unrelated_churn_keep_one_instance() {
    let mut r = router();
    assert_eq!(
        r.observe_legacy(observation(2, 0, 0, load(BASE_A))).0,
        ObserveOutcome::New
    );
    let first = joined(r.route(call(1, stamp(2, 0, 0), ip_in(BASE_A))));
    // Unrelated churn never reaches the hooks: later scans see the same
    // epochs and ranges, so continuity holds and no new ID is minted.
    for token in 2..50 {
        assert_eq!(
            r.observe_legacy(observation(2, 0, 0, load(BASE_A))).0,
            ObserveOutcome::Continued
        );
        assert_eq!(
            joined(r.route(call(token, stamp(2, 0, 0), ip_in(BASE_A)))),
            first
        );
    }
    assert_eq!(r.instances_minted(), 1);
}

#[test]
fn any_epoch_move_mints_a_new_instance_and_keeps_the_old_join() {
    for moved in [(3, 0, 0), (2, 1, 0)] {
        let mut r = router();
        r.observe_legacy(observation(2, 0, 0, load(BASE_A)));
        let old = joined(r.route(call(1, stamp(2, 0, 0), ip_in(BASE_A))));
        r.observe_legacy(observation(moved.0, moved.1, moved.2, load(BASE_A)));
        let new = joined(r.route(call(
            2,
            stamp(moved.0 as u32, moved.1 as u32, moved.2 as u32),
            ip_in(BASE_A),
        )));
        assert_ne!(old, new, "{moved:?}");
        // A late completion stamped at the old epochs still names the old
        // incarnation: it ran while that mapping existed.
        assert_eq!(joined(r.route(call(3, stamp(2, 0, 0), ip_in(BASE_A)))), old);
    }
}

#[test]
fn same_address_reload_never_revives_the_old_instance() {
    let mut r = router();
    r.observe_legacy(observation(2, 0, 0, load(BASE_A)));
    let before = joined(r.route(call(1, stamp(2, 0, 0), ip_in(BASE_A))));
    // dlclose (unmap: +k bumps) and dlopen at the same address (map: +m):
    // identical ranges, different epochs.
    r.observe_legacy(observation(9, 0, 0, load(BASE_A)));
    let after = joined(r.route(call(2, stamp(9, 0, 0), ip_in(BASE_A))));
    assert_ne!(before, after);
    assert!(after > before, "IDs are monotonic, never reused");
}

#[test]
fn dlmopen_siblings_route_to_separate_instances() {
    let mut r = router();
    let mut both = load(BASE_A);
    both.extend(load(BASE_B));
    r.observe_legacy(observation(4, 0, 0, both));
    let a = joined(r.route(call(1, stamp(4, 0, 0), ip_in(BASE_A))));
    let b = joined(r.route(call(2, stamp(4, 0, 0), ip_in(BASE_B))));
    assert_ne!(a, b);
    assert_eq!(joined(r.route(call(3, stamp(4, 0, 0), ip_in(BASE_A)))), a);
    assert_eq!(r.instances_minted(), 2);
}

#[test]
fn every_refusal_flag_and_straddle_is_unknown() {
    let mut r = router();
    r.observe_legacy(observation(2, 0, 0, load(BASE_A)));
    let cases = [
        (STAMP_SHARED_MM, UnknownReason::SharedMm),
        (STAMP_OVERFLOW, UnknownReason::Overflow),
        (STAMP_LOCAL_FAULT, UnknownReason::LocalFault),
        (STAMP_NO_FILE, UnknownReason::NoFile),
        (STAMP_NO_TASK, UnknownReason::Unstamped),
    ];
    for (flag, reason) in cases {
        let mut flagged = stamp(2, 0, 0);
        flagged.flags |= flag;
        assert_eq!(
            r.route(call(1, flagged, ip_in(BASE_A))),
            Route::Unknown(reason)
        );
    }
    let unstamped = InstanceStamp::default();
    assert_eq!(
        r.route(call(2, unstamped, ip_in(BASE_A))),
        Route::Unknown(UnknownReason::Unstamped)
    );
    let mut straddle = call(3, stamp(2, 0, 0), ip_in(BASE_A));
    straddle.ret = stamp(3, 0, 0);
    assert_eq!(r.route(straddle), Route::Unknown(UnknownReason::Straddle));
}

#[test]
fn unknown_reasons_follow_documented_precedence() {
    let mut r = router();
    r.observe_legacy(observation(2, 0, 0, load(BASE_A)));
    // A refusal flag on the return stamp only surfaces as Straddle: entry
    // flags gate the flag reasons, and the halves differ.
    let mut ret_only = call(1, stamp(2, 0, 0), ip_in(BASE_A));
    ret_only.ret.flags |= STAMP_SHARED_MM;
    assert_eq!(r.route(ret_only), Route::Unknown(UnknownReason::Straddle));
    // Per-call facts beat the ambient era: a flagged call from a stale era
    // reports its flag.
    let mut flagged = stamp(2, 0, 9);
    flagged.flags |= STAMP_OVERFLOW;
    assert_eq!(
        r.route(call(2, flagged, ip_in(BASE_A))),
        Route::Unknown(UnknownReason::Overflow)
    );
    // The ambient era beats process state: a stale-era call from a retired
    // process reports FaultEra.
    r.retire_process(COOKIE);
    assert_eq!(
        r.route(call(3, stamp(2, 0, 9), ip_in(BASE_A))),
        Route::Unknown(UnknownReason::FaultEra)
    );
}

#[test]
fn representable_epochs_compare_without_a_wrapping_window() {
    let mut r = router();
    r.observe_legacy(observation(0x8000_0001, 0, 0, load(BASE_A)));
    // More than 2^31 behind is still older: complete representable epochs
    // compare directly, without truncation or a wrapping-window ambiguity.
    assert_eq!(
        r.route(call(1, stamp(0, 0, 0), ip_in(BASE_A))),
        Route::Unknown(UnknownReason::Unobserved)
    );
    assert_eq!(r.pending_len(), 0);
    // Just behind the newest observation: older, unobservable, unknown.
    assert_eq!(
        r.route(call(2, stamp(0x8000_0000, 0, 0), ip_in(BASE_A))),
        Route::Unknown(UnknownReason::Unobserved)
    );
}

#[test]
fn offset_arithmetic_overflow_cannot_join() {
    let mut r = router();
    let mut ranges = load(BASE_A);
    ranges.push(MapRange::new(u64::MAX - 0xfff, u64::MAX, u64::MAX, true));
    r.observe_legacy(observation(2, 0, 0, ranges));
    // `ip - start + file_offset` wraps; the wrapped value must refuse.
    let ip = u64::MAX - 0x100;
    let wrapped = ip.wrapping_sub(u64::MAX - 0xfff).wrapping_add(u64::MAX);
    let mut facts = call(1, stamp(2, 0, 0), ip);
    facts.attached_offset = Some(wrapped);
    assert_eq!(
        r.route(facts),
        Route::Unknown(UnknownReason::OffsetMismatch)
    );
}

#[test]
fn capacity_refusals_leave_no_zero_counts() {
    let mut r = InstanceRouter::new(
        domain(),
        RouterLimits {
            ranges: 6,
            ..RouterLimits::default()
        },
    );
    let mut both = load(BASE_A);
    both.extend(load(BASE_B));
    r.observe_legacy(observation(2, 0, 0, both));
    assert_eq!(
        r.observe_legacy(observation(3, 0, 0, load(BASE_A))).0,
        ObserveOutcome::RangeCapacity
    );
    assert!(
        !r.unknown_counts()
            .contains_key(&UnknownReason::RangeCapacity),
        "a refusal with no failed calls must not mint a zero count"
    );
    let mut r = InstanceRouter::new(
        domain(),
        RouterLimits {
            instances: 1,
            ..RouterLimits::default()
        },
    );
    r.observe_legacy(observation(2, 0, 0, load(BASE_A)));
    r.observe_legacy(observation(3, 0, 0, load(BASE_A)));
    assert!(
        !r.unknown_counts()
            .contains_key(&UnknownReason::InstanceCapacity),
        "a failed mint must not mint a zero count before the call routes"
    );
}

#[test]
fn router_debug_redacts_cookies_and_epochs() {
    const COOKIE_BIG: u64 = 0x1234;
    const FAULT_BIG: u64 = 0xbeef;
    let mut r = router();
    assert!(r.audit(FAULT_BIG, 0, 0).is_empty());
    let mut reading = reading(2, 0, FAULT_BIG);
    reading.cookie = COOKIE_BIG;
    assert_eq!(
        r.observe_legacy(StableObservation {
            file_slot: FILE,
            reading,
            ranges: load(BASE_A),
            fence: r.fence(),
        })
        .0,
        ObserveOutcome::New
    );
    assert_eq!(
        r.ranges_retained(),
        3,
        "redaction must cover retained state"
    );
    r.route(call_for(1, COOKIE_BIG, stamp(3, 0, 0), ip_in(BASE_A)));
    r.retire_process(COOKIE_BIG + 1);
    let rendered = format!("{r:?}");
    assert!(rendered.contains("observed_keys"), "{rendered}");
    for needle in ["0x1234", "4660", "beef", "48879", "0x1235", "4661"] {
        assert!(!rendered.contains(needle), "{rendered} leaks {needle}");
    }
}

#[test]
fn ip_must_lie_in_one_executable_partition_at_the_attached_offset() {
    let mut r = router();
    // An orphan executable range before the first load base.
    let mut ranges = vec![MapRange::new(0x1000, 0x3000, 0x1000, true)];
    ranges.extend(load(BASE_A));
    r.observe_legacy(observation(2, 0, 0, ranges));
    let s = stamp(2, 0, 0);
    assert_eq!(
        r.route(call(1, s, 0x2000)),
        Route::Unknown(UnknownReason::Unpartitionable)
    );
    assert_eq!(
        r.route(call(2, s, BASE_A + 0x9000)),
        Route::Unknown(UnknownReason::IpOutside)
    );
    let mut data = call(3, s, BASE_A + 0x3800);
    data.attached_offset = None;
    assert_eq!(r.route(data), Route::Unknown(UnknownReason::NotExecutable));
    let mut wrong = call(4, s, ip_in(BASE_A));
    wrong.attached_offset = Some(TEXT + 0x10);
    assert_eq!(
        r.route(wrong),
        Route::Unknown(UnknownReason::OffsetMismatch)
    );
    // An unknown attached offset cannot be matched: it never joins.
    let mut unknown_offset = call(6, s, ip_in(BASE_A));
    unknown_offset.attached_offset = None;
    assert_eq!(
        r.route(unknown_offset),
        Route::Unknown(UnknownReason::OffsetMismatch)
    );
    joined(r.route(call(5, s, ip_in(BASE_A))));
}

#[test]
fn a_range_appearing_at_unchanged_epochs_is_a_sticky_coverage_fault() {
    let mut r = router();
    r.observe_legacy(observation(2, 0, 0, load(BASE_A)));
    let mut grown = load(BASE_A);
    grown.extend(load(BASE_B));
    assert_eq!(
        r.observe_legacy(observation(2, 0, 0, grown)).0,
        ObserveOutcome::CoverageFault
    );
    assert_eq!(
        r.route(call(1, stamp(2, 0, 0), ip_in(BASE_A))),
        Route::Unknown(UnknownReason::CoverageFault)
    );
    // Sticky: even a later, moved epoch does not re-enable this (P, F).
    assert_eq!(
        r.observe_legacy(observation(5, 0, 0, load(BASE_A))).0,
        ObserveOutcome::CoverageFault
    );
    assert_eq!(
        r.route(call(2, stamp(5, 0, 0), ip_in(BASE_A))),
        Route::Unknown(UnknownReason::CoverageFault)
    );
}

#[test]
fn a_range_disappearing_at_unchanged_epochs_keeps_its_instance_for_late_calls() {
    let mut r = router();
    r.observe_legacy(observation(2, 0, 0, load(BASE_A)));
    let id = joined(r.route(call(1, stamp(2, 0, 0), ip_in(BASE_A))));
    // Teardown (exec/exit) removes ranges without a bump.
    assert_eq!(
        r.observe_legacy(observation(2, 0, 0, Vec::new())).0,
        ObserveOutcome::Continued
    );
    assert_eq!(joined(r.route(call(2, stamp(2, 0, 0), ip_in(BASE_A)))), id);
}

#[test]
fn pending_calls_resolve_on_observation_or_become_unobserved() {
    let mut r = router();
    assert_eq!(
        r.route(call(1, stamp(2, 0, 0), ip_in(BASE_A))),
        Route::Pending
    );
    assert_eq!(
        r.route(call(2, stamp(3, 0, 0), ip_in(BASE_A))),
        Route::Pending
    );
    let (_, resolved) = r.observe_legacy(observation(3, 0, 0, load(BASE_A)));
    // Epoch 3 joins; epoch 2 can never be observed any more.
    assert_eq!(resolved.len(), 2);
    let by_token: BTreeMap<_, _> = resolved.into_iter().collect();
    assert_eq!(by_token[&1], Route::Unknown(UnknownReason::Unobserved));
    assert!(matches!(by_token[&2], Route::Joined(_)));
    assert_eq!(r.pending_len(), 0);
    // A stamp newer than every observation waits for the next scan.
    assert_eq!(
        r.route(call(3, stamp(4, 0, 0), ip_in(BASE_A))),
        Route::Pending
    );
    assert_eq!(
        r.expire_pending(COOKIE),
        vec![(3, Route::Unknown(UnknownReason::Unobserved))]
    );
}

#[test]
fn pending_ceiling_refuses_at_n_plus_one() {
    let mut r = InstanceRouter::new(
        domain(),
        RouterLimits {
            pending: 3,
            ..RouterLimits::default()
        },
    );
    for token in 0..3 {
        assert_eq!(
            r.route(call(token, stamp(2, 0, 0), ip_in(BASE_A))),
            Route::Pending
        );
    }
    assert_eq!(
        r.route(call(3, stamp(2, 0, 0), ip_in(BASE_A))),
        Route::Unknown(UnknownReason::PendingCapacity)
    );
    assert_eq!(r.pending_len(), 3);
}

#[test]
fn instance_ceiling_refuses_at_n_plus_one_and_never_reuses_ids() {
    let mut r = InstanceRouter::new(
        domain(),
        RouterLimits {
            instances: 2,
            ..RouterLimits::default()
        },
    );
    r.observe_legacy(observation(2, 0, 0, load(BASE_A)));
    let first = joined(r.route(call(1, stamp(2, 0, 0), ip_in(BASE_A))));
    r.observe_legacy(observation(3, 0, 0, load(BASE_A)));
    let second = joined(r.route(call(2, stamp(3, 0, 0), ip_in(BASE_A))));
    assert_eq!(r.instances_minted(), 2);
    r.observe_legacy(observation(4, 0, 0, load(BASE_A)));
    assert_eq!(
        r.route(call(3, stamp(4, 0, 0), ip_in(BASE_A))),
        Route::Unknown(UnknownReason::InstanceCapacity)
    );
    assert_eq!(r.instances_minted(), 2);
    assert!(first < second);
}

#[test]
fn range_ceiling_refuses_at_n_plus_one() {
    let mut r = InstanceRouter::new(
        domain(),
        RouterLimits {
            ranges: 6,
            ..RouterLimits::default()
        },
    );
    let mut both = load(BASE_A);
    both.extend(load(BASE_B));
    assert_eq!(
        r.observe_legacy(observation(2, 0, 0, both)).0,
        ObserveOutcome::New
    );
    assert_eq!(r.ranges_retained(), 6);
    assert_eq!(
        r.observe_legacy(observation(3, 0, 0, load(BASE_A))).0,
        ObserveOutcome::RangeCapacity
    );
    assert_eq!(r.ranges_retained(), 6);
    assert_eq!(
        r.route(call(1, stamp(3, 0, 0), ip_in(BASE_A))),
        Route::Pending,
        "an unstored epoch is never joined"
    );
}

#[test]
fn retained_keys_are_bounded_and_evicted_calls_are_unknown() {
    let mut r = router();
    for local in 1..=(KEYS_PER_PROCESS_FILE as u64 + 1) {
        r.observe_legacy(observation(local, 0, 0, load(BASE_A)));
    }
    assert_eq!(r.ranges_retained(), KEYS_PER_PROCESS_FILE * 3);
    assert_eq!(
        r.route(call(1, stamp(1, 0, 0), ip_in(BASE_A))),
        Route::Unknown(UnknownReason::Evicted)
    );
    joined(r.route(call(2, stamp(2, 0, 0), ip_in(BASE_A))));
}

#[test]
fn observed_registry_eviction_degrades_late_calls_to_unobserved() {
    const A: u64 = 0xA1;
    const B: u64 = 0xA2;
    const C: u64 = 0xA3;
    let mut r = InstanceRouter::new(
        domain(),
        RouterLimits {
            observed_keys: 2,
            ..RouterLimits::default()
        },
    );
    assert_eq!(
        r.observe_legacy(observation_for(A, 2, load(BASE_A))).0,
        ObserveOutcome::New
    );
    assert_eq!(
        r.observe_legacy(observation_for(B, 2, load(BASE_A))).0,
        ObserveOutcome::New
    );
    // The third key evicts the smallest (stalest) one, freeing its ranges.
    assert_eq!(
        r.observe_legacy(observation_for(C, 2, load(BASE_A))).0,
        ObserveOutcome::New
    );
    assert_eq!(r.counters().observed_evictions, 1);
    assert_eq!(r.ranges_retained(), 6);
    // The evicted key's late calls wait, then expire: they never join.
    assert_eq!(
        r.route(call_for(1, A, stamp(2, 0, 0), ip_in(BASE_A))),
        Route::Pending
    );
    assert_eq!(
        r.expire_pending(A),
        vec![(1, Route::Unknown(UnknownReason::Unobserved))]
    );
    joined(r.route(call_for(2, C, stamp(2, 0, 0), ip_in(BASE_A))));
}

#[test]
fn faulted_registry_overflow_latches_coverage_refusal() {
    // P2-1: the evicted tombstone is indistinguishable from a new key, so
    // the overflow latches CoverageFault for every unknown key — while
    // keys with a retained observation keep continuity.
    const A: u64 = 0xA1;
    const B: u64 = 0xA2;
    const C: u64 = 0xA3;
    const D: u64 = 0xA4;
    let mut r = InstanceRouter::new(
        domain(),
        RouterLimits {
            faulted_keys: 1,
            ..RouterLimits::default()
        },
    );
    let fault = |r: &mut InstanceRouter, cookie: u64| {
        r.observe_legacy(observation_for(cookie, 2, load(BASE_A)));
        let mut grown = load(BASE_A);
        grown.extend(load(BASE_B));
        assert_eq!(
            r.observe_legacy(observation_for(cookie, 2, grown)).0,
            ObserveOutcome::CoverageFault
        );
    };
    assert_eq!(
        r.observe_legacy(observation_for(D, 2, load(BASE_A))).0,
        ObserveOutcome::New
    );
    fault(&mut r, A);
    assert_eq!(
        r.route(call_for(1, A, stamp(2, 0, 0), ip_in(BASE_A))),
        Route::Unknown(UnknownReason::CoverageFault)
    );
    fault(&mut r, B);
    assert_eq!(r.counters().faulted_evictions, 1);
    // The evicted key and any genuinely new key are refused, never joined.
    assert_eq!(
        r.route(call_for(2, A, stamp(2, 0, 0), ip_in(BASE_A))),
        Route::Unknown(UnknownReason::CoverageFault)
    );
    assert_eq!(
        r.observe_legacy(observation_for(C, 2, load(BASE_A))).0,
        ObserveOutcome::CoverageFault
    );
    assert_eq!(
        r.route(call_for(3, B, stamp(2, 0, 0), ip_in(BASE_A))),
        Route::Unknown(UnknownReason::CoverageFault)
    );
    // The retained key keeps continuity and still joins.
    assert_eq!(
        r.observe_legacy(observation_for(D, 2, load(BASE_A))).0,
        ObserveOutcome::Continued
    );
    joined(r.route(call_for(4, D, stamp(2, 0, 0), ip_in(BASE_A))));
}

#[test]
fn latched_overflow_plus_era_change_refuses_everything_until_recreation() {
    // Availability cost, on record: once the P2-1 latch is set, a
    // fault-era change clears the retained observations that kept
    // continuity, after which every key is unknown and refused — fresh
    // observations included — until the router is recreated.
    const A: u64 = 0xA1;
    const B: u64 = 0xA2;
    const D: u64 = 0xA4;
    let limits = RouterLimits {
        faulted_keys: 1,
        ..RouterLimits::default()
    };
    let mut r = InstanceRouter::new(domain(), limits);
    assert_eq!(
        r.observe_legacy(observation_for(D, 2, load(BASE_A))).0,
        ObserveOutcome::New
    );
    let fault = |r: &mut InstanceRouter, cookie: u64| {
        r.observe_legacy(observation_for(cookie, 2, load(BASE_A)));
        let mut grown = load(BASE_A);
        grown.extend(load(BASE_B));
        assert_eq!(
            r.observe_legacy(observation_for(cookie, 2, grown)).0,
            ObserveOutcome::CoverageFault
        );
    };
    fault(&mut r, A);
    fault(&mut r, B);
    assert_eq!(
        r.observe_legacy(observation_for(D, 2, load(BASE_A))).0,
        ObserveOutcome::Continued
    );
    assert!(r.audit(1, 0, 0).is_empty());
    let mut fresh = observation_for(D, 2, load(BASE_A));
    fresh.reading.fault = 1;
    fresh.fence = r.fence();
    assert_eq!(r.observe_legacy(fresh).0, ObserveOutcome::CoverageFault);
    assert_eq!(
        r.route(call_for(1, D, stamp(2, 0, 1), ip_in(BASE_A))),
        Route::Unknown(UnknownReason::CoverageFault)
    );
    // A recreated router accepts the same evidence again.
    let mut recreated = InstanceRouter::new(domain(), limits);
    assert!(recreated.audit(1, 0, 0).is_empty());
    let mut fresh = observation_for(D, 2, load(BASE_A));
    fresh.reading.fault = 1;
    fresh.fence = recreated.fence();
    assert_eq!(recreated.observe_legacy(fresh).0, ObserveOutcome::New);
    joined(recreated.route(call_for(1, D, stamp(2, 0, 1), ip_in(BASE_A))));
}

#[test]
fn fault_evict_reobserve_same_epoch_still_refuses_route() {
    // P2-1 (astra retro): evicting a coverage-fault tombstone must not let
    // the same discredited epoch re-join on re-observation.
    const A: u64 = 0xA1;
    const B: u64 = 0xA2;
    let mut r = InstanceRouter::new(
        domain(),
        RouterLimits {
            faulted_keys: 1,
            ..RouterLimits::default()
        },
    );
    let fault = |r: &mut InstanceRouter, cookie: u64| {
        r.observe_legacy(observation_for(cookie, 2, load(BASE_A)));
        let mut grown = load(BASE_A);
        grown.extend(load(BASE_B));
        assert_eq!(
            r.observe_legacy(observation_for(cookie, 2, grown)).0,
            ObserveOutcome::CoverageFault
        );
    };
    fault(&mut r, A);
    fault(&mut r, B);
    assert_eq!(r.counters().faulted_evictions, 1);
    // Re-observing A's discredited epoch must still refuse: never New.
    assert_eq!(
        r.observe_legacy(observation_for(A, 2, load(BASE_A))).0,
        ObserveOutcome::CoverageFault
    );
    // And no call at that epoch may join, directly or via pending.
    assert_eq!(
        r.route(call_for(1, A, stamp(2, 0, 0), ip_in(BASE_A))),
        Route::Unknown(UnknownReason::CoverageFault)
    );
}

#[test]
fn retired_cookie_eviction_still_refuses_delayed_observations() {
    // Astra follow-up: a saved StableObservation submitted after its
    // retirement was evicted must not be accepted as New.
    const A: u64 = 0xA1;
    const B: u64 = 0xA2;
    const C: u64 = 0xA3;
    let mut r = InstanceRouter::new(
        domain(),
        RouterLimits {
            retired_cookies: 1,
            ..RouterLimits::default()
        },
    );
    let saved = observation_for(A, 2, load(BASE_A));
    assert_eq!(r.observe_legacy(saved.clone()).0, ObserveOutcome::New);
    assert!(r.retire_process(A).is_empty());
    assert!(r.retire_process(B).is_empty());
    assert_eq!(r.counters().retired_evictions, 1);
    // The delayed observation is refused, never New; its calls never join.
    assert_eq!(r.observe_legacy(saved).0, ObserveOutcome::Retired);
    assert_eq!(
        r.route(call_for(9, A, stamp(2, 0, 0), ip_in(BASE_A))),
        Route::Unknown(UnknownReason::Retired)
    );
    // A genuinely new cookie still joins: the ledger is per cookie.
    assert_eq!(
        r.observe_legacy(observation_for(C, 2, load(BASE_A))).0,
        ObserveOutcome::New
    );
    joined(r.route(call_for(10, C, stamp(2, 0, 0), ip_in(BASE_A))));
}

#[test]
fn delayed_new_era_observation_across_retirement_eviction_and_reset_is_refused() {
    // The kernel fault advances while the router still knows0. A cached
    // seal predates the audit, while A's exact tombstone is evicted at N+1.
    // Neither the cached scan nor a late call can revive the terminal task:
    // the original fence refuses the scan and permanent death refuses calls.
    const A: u64 = 0xA1;
    const B: u64 = 0xA2;
    let mut r = InstanceRouter::new(
        domain(),
        RouterLimits {
            retired_cookies: 1,
            ..RouterLimits::default()
        },
    );
    let mut cached = observation_for(A, 2, load(BASE_A));
    cached.reading.fault = 1;
    // Acquired before the router learns of the new era (fence 0).
    cached.fence = r.fence();
    assert!(r.retire_process(A).is_empty());
    assert!(r.retire_process(B).is_empty());
    assert_eq!(r.counters().retired_evictions, 1);
    assert!(r.audit(1, 0, 0).is_empty());
    assert_eq!(r.observe_legacy(cached).0, ObserveOutcome::StaleEra);
    assert_eq!(
        r.route(call_for(9, A, stamp(2, 0, 1), ip_in(BASE_A))),
        Route::Unknown(UnknownReason::Retired)
    );
    assert!(r.expire_pending(A).is_empty());
}

#[test]
fn retired_registry_eviction_preserves_retirement_refusal() {
    const A: u64 = 0xA1;
    const B: u64 = 0xA2;
    let mut r = InstanceRouter::new(
        domain(),
        RouterLimits {
            retired_cookies: 1,
            ..RouterLimits::default()
        },
    );
    assert!(r.retire_process(A).is_empty());
    assert_eq!(
        r.route(call_for(1, A, stamp(2, 0, 0), ip_in(BASE_A))),
        Route::Unknown(UnknownReason::Retired)
    );
    assert!(r.retire_process(B).is_empty());
    assert_eq!(r.counters().retired_evictions, 1);
    // Permanent per-cookie death survives exact-cache eviction.
    assert_eq!(
        r.route(call_for(2, A, stamp(2, 0, 0), ip_in(BASE_A))),
        Route::Unknown(UnknownReason::Retired)
    );
    assert_eq!(
        r.route(call_for(3, B, stamp(2, 0, 0), ip_in(BASE_A))),
        Route::Unknown(UnknownReason::Retired)
    );
}

#[test]
fn retirement_ledger_leaves_unrelated_live_keys_available_across_eras() {
    const LIVE: u64 = 0xA0;
    const A: u64 = 0xA1;
    const B: u64 = 0xA2;
    let mut r = InstanceRouter::new(
        domain(),
        RouterLimits {
            retired_cookies: 1,
            ..RouterLimits::default()
        },
    );
    // Other cookies' death cannot suppress this live cookie, even with a
    // smaller ticket and after an ordinary fault era clears observations.
    assert_eq!(
        r.observe_legacy(observation_for(LIVE, 2, load(BASE_A))).0,
        ObserveOutcome::New
    );
    assert!(r.retire_process(A).is_empty());
    assert!(r.retire_process(B).is_empty());
    assert_eq!(r.counters().retired_evictions, 1);
    assert_eq!(
        r.observe_legacy(observation_for(LIVE, 2, load(BASE_A))).0,
        ObserveOutcome::Continued
    );
    joined(r.route(call_for(1, LIVE, stamp(2, 0, 0), ip_in(BASE_A))));
    // Ordinary era changes retain negative metadata, while this unrelated
    // live cookie may acquire a fresh full observation.
    assert!(r.audit(1, 0, 0).is_empty());
    let mut old_era = observation_for(LIVE, 2, load(BASE_A));
    old_era.reading.fault = 0;
    assert_eq!(r.observe_legacy(old_era).0, ObserveOutcome::StaleEra);
    let mut rescanned = observation_for(LIVE, 2, load(BASE_A));
    rescanned.reading.fault = 1;
    assert_eq!(
        r.observe_legacy(fresh(&r, rescanned)).0,
        ObserveOutcome::New
    );
    joined(r.route(call_for(2, LIVE, stamp(2, 0, 1), ip_in(BASE_A))));
}

#[test]
fn a_fault_era_change_ends_every_observation_and_pending_call() {
    let mut r = router();
    r.observe_legacy(observation(2, 0, 0, load(BASE_A)));
    let old = joined(r.route(call(1, stamp(2, 0, 0), ip_in(BASE_A))));
    assert_eq!(
        r.route(call(2, stamp(3, 0, 0), ip_in(BASE_A))),
        Route::Pending
    );
    let resolved = r.audit(1, 0, 0);
    assert_eq!(resolved, vec![(2, Route::Unknown(UnknownReason::FaultEra))]);
    assert_eq!(r.ranges_retained(), 0);
    // Calls stamped before the fault never join, even at identical epochs.
    assert_eq!(
        r.route(call(3, stamp(2, 0, 0), ip_in(BASE_A))),
        Route::Unknown(UnknownReason::FaultEra)
    );
    // An observation from the old era is refused; the new era mints anew.
    assert_eq!(
        r.observe_legacy(observation(2, 0, 0, load(BASE_A))).0,
        ObserveOutcome::StaleEra
    );
    r.observe_legacy(fresh(&r, observation(2, 0, 1, load(BASE_A))));
    let new = joined(r.route(call(4, stamp(2, 0, 1), ip_in(BASE_A))));
    assert_ne!(old, new);
}

#[test]
fn a_recursion_miss_increase_without_a_raise_latches_the_era() {
    let mut r = router();
    r.observe_legacy(observation(2, 0, 0, load(BASE_A)));
    let old = joined(r.route(call(1, stamp(2, 0, 0), ip_in(BASE_A))));
    assert_eq!(
        r.route(call(2, stamp(3, 0, 0), ip_in(BASE_A))),
        Route::Pending
    );
    // The loop passed new misses without raising the fault: the pending
    // call fails, retained observations are dropped, and the era latches.
    assert_eq!(
        r.audit(0, 0, 1),
        vec![(2, Route::Unknown(UnknownReason::FaultEra))]
    );
    assert_eq!(r.ranges_retained(), 0);
    assert_eq!(r.counters().miss_eras, 1);
    // A call stamped before the miss never joins afterwards — not even at
    // identical epochs — and a fresh scan at the old fault is refused: a
    // skipped relevant bump would leave stale epochs under changed ranges.
    assert_eq!(
        r.route(call(3, stamp(2, 0, 0), ip_in(BASE_A))),
        Route::Unknown(UnknownReason::FaultEra)
    );
    assert_eq!(
        r.observe_legacy(observation(2, 0, 0, load(BASE_A))).0,
        ObserveOutcome::StaleEra
    );
    // A late raise re-coheres the era: the new fault is observable again.
    assert!(r.audit(1, 0, 1).is_empty());
    r.observe_legacy(fresh(&r, observation(2, 0, 1, load(BASE_A))));
    let new = joined(r.route(call(4, stamp(2, 0, 1), ip_in(BASE_A))));
    assert_ne!(old, new);
    assert_eq!(r.counters().miss_eras, 1);
    // Any miss change latches, including a decrease (reloaded hooks restart
    // their counters): fail closed on the unknown skip window.
    assert_eq!(
        r.route(call(5, stamp(3, 0, 1), ip_in(BASE_A))),
        Route::Pending
    );
    assert_eq!(
        r.audit(1, 0, 0),
        vec![(5, Route::Unknown(UnknownReason::FaultEra))]
    );
    assert_eq!(
        r.route(call(6, stamp(2, 0, 1), ip_in(BASE_A))),
        Route::Unknown(UnknownReason::FaultEra)
    );
}

#[test]
fn a_raise_covering_the_miss_advances_a_single_era() {
    let mut r = router();
    r.observe_legacy(observation(2, 0, 0, load(BASE_A)));
    // The normal capture-loop order (raise, then audit with both changed)
    // advances once and needs no latch: the kernel fault covers the misses.
    assert!(r.audit(1, 0, 1).is_empty());
    assert_eq!(r.counters().eras, 1);
    assert_eq!(r.counters().miss_eras, 0);
    assert_eq!(
        r.observe_legacy(fresh(&r, observation(2, 0, 1, load(BASE_A))))
            .0,
        ObserveOutcome::New
    );
    joined(r.route(call(1, stamp(2, 0, 1), ip_in(BASE_A))));
}

#[test]
fn sticky_refusal_disables_routing_for_the_capture() {
    let mut r = router();
    r.observe_legacy(observation(2, 0, 0, load(BASE_A)));
    assert_eq!(
        r.route(call(1, stamp(3, 0, 0), ip_in(BASE_A))),
        Route::Pending
    );
    assert_eq!(
        r.audit(0, instance::STICKY_FORK_UNMARKED, 0),
        vec![(1, Route::Unknown(UnknownReason::Sticky))]
    );
    assert_eq!(
        r.route(call(2, stamp(2, 0, 0), ip_in(BASE_A))),
        Route::Unknown(UnknownReason::Sticky)
    );
}

#[test]
fn retired_processes_free_state_and_refuse_late_calls() {
    let mut r = router();
    r.observe_legacy(observation(2, 0, 0, load(BASE_A)));
    assert_eq!(
        r.route(call(1, stamp(3, 0, 0), ip_in(BASE_A))),
        Route::Pending
    );
    assert_eq!(
        r.retire_process(COOKIE),
        vec![(1, Route::Unknown(UnknownReason::Retired))]
    );
    assert_eq!(r.ranges_retained(), 0);
    assert_eq!(
        r.route(call(2, stamp(2, 0, 0), ip_in(BASE_A))),
        Route::Unknown(UnknownReason::Retired)
    );
    assert_eq!(
        r.observe_legacy(observation(2, 0, 0, load(BASE_A))).0,
        ObserveOutcome::Retired
    );
}

#[test]
fn other_processes_and_files_never_share_instances() {
    let mut r = router();
    r.observe_legacy(observation(2, 0, 0, load(BASE_A)));
    let mut other = call(1, stamp(2, 0, 0), ip_in(BASE_A));
    other.image.task_cookie = COOKIE + 1;
    assert_eq!(
        r.route(other),
        Route::Pending,
        "another process is unobserved"
    );
    let mut other_file = call(2, stamp(2, 0, 0), ip_in(BASE_A));
    other_file.entry.file_slot_plus1 += 1;
    other_file.ret = other_file.entry;
    assert_eq!(
        r.route(other_file),
        Route::Pending,
        "another file is unobserved"
    );
}

struct Scripted {
    epochs: VecDeque<EpochReading>,
    ranges: Vec<MapRange>,
    maps_reads: usize,
}

impl ScanReader for Scripted {
    fn epochs(&mut self) -> Result<EpochReading, String> {
        self.epochs
            .pop_front()
            .ok_or_else(|| "exhausted".to_string())
    }
    fn ranges(&mut self) -> Result<Vec<MapRange>, String> {
        self.maps_reads += 1;
        Ok(self.ranges.clone())
    }
}

#[test]
fn stable_scan_requires_equal_brackets_and_bounds_retries() {
    let mut moving = Scripted {
        epochs: [
            reading(1, 0, 0),
            reading(2, 0, 0),
            reading(2, 0, 0),
            reading(2, 0, 0),
        ]
        .into(),
        ranges: load(BASE_A),
        maps_reads: 0,
    };
    let observed = stable_scan(&mut moving, FILE, 3, 7).expect("second attempt is stable");
    assert_eq!(observed.reading, reading(2, 0, 0));
    assert_eq!(observed.fence, 7);
    assert_eq!(moving.maps_reads, 2);

    let mut never = Scripted {
        epochs: [
            reading(1, 0, 0),
            reading(2, 0, 0),
            reading(3, 0, 0),
            reading(4, 0, 0),
        ]
        .into(),
        ranges: load(BASE_A),
        maps_reads: 0,
    };
    assert_eq!(
        stable_scan(&mut never, FILE, 2, 0),
        Err(ScanRefusal::Unstable)
    );

    let mut global_moved = Scripted {
        epochs: [reading(1, 0, 0), reading(1, 1, 0)].into(),
        ranges: load(BASE_A),
        maps_reads: 0,
    };
    assert_eq!(
        stable_scan(&mut global_moved, FILE, 1, 0),
        Err(ScanRefusal::Unstable)
    );

    let mut no_cookie = Scripted {
        epochs: [EpochReading::default()].into(),
        ranges: Vec::new(),
        maps_reads: 0,
    };
    assert_eq!(
        stable_scan(&mut no_cookie, FILE, 1, 0),
        Err(ScanRefusal::NoCookie)
    );
}

#[test]
fn private_addresses_are_redacted_from_debug() {
    let ip = EntryIp::new(0x7f12_3456_789a);
    let range = MapRange::new(0x7f12_3456_0000, 0x7f12_3457_0000, 0x1000, true);
    let facts = call(9, stamp(2, 0, 0), 0x7f12_3456_789a);
    for rendered in [
        format!("{ip:?}"),
        format!("{range:?}"),
        format!("{facts:?}"),
    ] {
        for needle in ["7f123456789a", "7f1234560000", "139716164622490", "0x7f"] {
            assert!(!rendered.contains(needle), "{rendered} leaks {needle}");
        }
    }
}

#[test]
fn ranges_for_selects_exactly_the_maps_visible_file_key() {
    let maps = b"7f0000000000-7f0000001000 r--p 00000000 00:23 100 /lib/a.so\n\
7f0000001000-7f0000003000 r-xp 00001000 00:23 100 /lib/a.so\n\
7f0000004000-7f0000005000 r-xp 00001000 00:24 100 /other-dev\n\
7f0000006000-7f0000007000 r-xp 00001000 00:23 101 /other-ino\n\
7f0000008000-7f0000009000 rw-p 00000000 00:00 0\n";
    let entries = p11scope_manifest::maps::parse_maps(maps).expect("valid maps");
    let ranges = ranges_for(&entries, 0, 0x23, 100);
    assert_eq!(
        ranges,
        vec![
            MapRange::new(0x7f00_0000_0000, 0x7f00_0000_1000, 0, false),
            MapRange::new(0x7f00_0000_1000, 0x7f00_0000_3000, 0x1000, true),
        ]
    );
    assert!(
        ranges_for(&entries, 0, 0, 0).is_empty(),
        "anonymous never matches"
    );
}

/// The btrfs trap: two different files in different subvolumes show the same
/// maps `00:23 45598` (`i_sb->s_dev`, `i_ino`), while their map_files `stat()`
/// identities differ (0:37 vs 0:47 on the observed host). The maps key alone
/// would join the colliding file's load to the watched file's instance.
#[test]
fn colliding_maps_keys_are_confirmed_by_map_files_identity() {
    const WATCHED: MappedFileIdentity = MappedFileIdentity {
        dev: 37,
        ino: 45598,
    };
    const OTHER: MappedFileIdentity = MappedFileIdentity {
        dev: 47,
        ino: 45598,
    };
    let maps = b"7f0000000000-7f0000001000 r--p 00000000 00:23 45598 /usr/lib/provider.so\n\
7f0000001000-7f0000003000 r-xp 00001000 00:23 45598 /usr/lib/provider.so\n\
7f1000000000-7f1000001000 r--p 00000000 00:23 45598 /home/user/other.so\n\
7f1000001000-7f1000003000 r-xp 00001000 00:23 45598 /home/user/other.so\n";
    let entries = p11scope_manifest::maps::parse_maps(maps).expect("valid maps");
    let candidates = ranges_for(&entries, 0, 0x23, 45598);
    assert_eq!(
        candidates.len(),
        4,
        "the maps key cannot tell the files apart"
    );
    let stat = |start: u64, _end: u64| {
        Ok(if start >= 0x7f10_0000_0000 {
            OTHER
        } else {
            WATCHED
        })
    };

    let confirmed = confirm_identity(candidates.clone(), WATCHED, stat).expect("all stat");
    assert_eq!(
        confirmed,
        vec![
            MapRange::new(0x7f00_0000_0000, 0x7f00_0000_1000, 0, false),
            MapRange::new(0x7f00_0000_1000, 0x7f00_0000_3000, 0x1000, true),
        ]
    );

    // A call executing in the colliding file's text: with only the maps key
    // it joins a minted instance (the trap); confirmed ranges keep it out.
    let other_ip = 0x7f10_0000_0000 + TEXT;
    let mut keyed_only = router();
    keyed_only.observe_legacy(observation(1, 0, 0, candidates.clone()));
    joined(keyed_only.route(call(1, stamp(1, 0, 0), other_ip)));
    let mut exact = router();
    exact.observe_legacy(observation(1, 0, 0, confirmed));
    assert_eq!(
        exact.route(call(1, stamp(1, 0, 0), other_ip)),
        Route::Unknown(UnknownReason::IpOutside)
    );
    joined(exact.route(call(2, stamp(1, 0, 0), ip_in(0x7f00_0000_0000))));
    assert_eq!(exact.instances_minted(), 1);

    // An unreadable identity refuses the whole scan; nothing is kept.
    let mut seen = 0;
    let refused = confirm_identity(candidates, WATCHED, |start, end| {
        seen += 1;
        if seen == 3 {
            Err(format!("identity of mapped range {start:x}-{end:x}: gone"))
        } else {
            Ok(WATCHED)
        }
    });
    assert!(refused.is_err());
}
