//! SPDX-License-Identifier: GPL-3.0-or-later
//! Task 7 (finish plan): adaptive capacity, sustained identity, bounded history.
//!
//! RED suite: every test names one Task 7 box. The `capacity` items under
//! test do not exist yet, so this file fails to compile until the GREEN
//! implementation lands (same RED discipline as `capacity_contract.rs`).

use p11scope::capacity::{
    AdmissionError, AllocState, Allocation, BudgetError, CounterCell, DiskBudget, DurableAck,
    DurableSink, EvidenceRotation, ExportError, ExportKind, ExportRecord, ExportSession,
    FaultScript, FinalSnapshot, HistoryBudget, InjectedFault, InnerMapKind, LiveAdmission,
    OverlapError, OverlapPair, RamBudget, SegmentDirectory, SegmentError, SegmentSpec, SinkError,
    SlotIdentity, StagedExport, StoreError, TICKET_CAS_TRIES, TicketAllocator, TicketError,
    TicketPolicy, WriterSet, export_checksum,
};
use p11scope_ebpf_common::IMAGE_IDENTITY_TICKET_LIMIT;

// Box 1: ticket policy pins C1; wider limits need an explicit reviewed version.
#[test]
fn ticket_policy_v1_pins_c1_limit_and_versions_fail_closed() {
    let v1 = TicketPolicy::v1_c1();
    assert_eq!(v1.limit(), IMAGE_IDENTITY_TICKET_LIMIT);
    assert_eq!(v1.limit(), 16_384);
    assert_eq!(v1.version(), 1);
    assert!(TicketPolicy::reviewed(16_384, 1).is_ok());
    assert!(TicketPolicy::reviewed(16_385, 1).is_err());
    assert!(TicketPolicy::reviewed(16_384, 0).is_err());
    assert!(TicketPolicy::reviewed(0, 2).is_err());
    let wide = TicketPolicy::reviewed(u64::MAX, 2).expect("reviewed wide policy");
    assert_eq!(wide.limit(), u64::MAX);
    // The loader seam publishes exactly the C1 control image by default.
    let image = v1.control_image();
    assert_eq!(
        (
            image.limit,
            image.next_ticket,
            image.unavailable,
            image.create_failures,
            image.retry_exhausted
        ),
        (16_384, 0, 0, 0, 0)
    );
    assert!(TicketPolicy::validate_control(&image, v1).is_ok());
    let mut tampered = image;
    tampered.limit = 16_385;
    assert!(TicketPolicy::validate_control(&tampered, v1).is_err());
    let mut dirty = image;
    dirty.next_ticket = 1;
    assert!(TicketPolicy::validate_control(&dirty, v1).is_err());
    assert!(TicketPolicy::validate_control(&wide.control_image(), wide).is_ok());
}

// Box 1: u64 monotonic tickets mirror native cookie_for (zero reserved, no reuse).
#[test]
fn ticket_allocator_is_monotonic_zero_reserved_and_never_reuses() {
    let mut allocator = TicketAllocator::new(TicketPolicy::v1_c1());
    assert_eq!(allocator.allocate(), Ok(1));
    assert_eq!(allocator.allocate(), Ok(2));
    assert_eq!(allocator.allocate(), Ok(3));
    allocator.retire(2);
    assert_eq!(allocator.allocate(), Ok(4));
    assert_eq!(allocator.resolve(0), SlotIdentity::Unknown);
    assert_eq!(allocator.resolve(1), SlotIdentity::Active);
    assert_eq!(allocator.resolve(2), SlotIdentity::Retired);
    assert_eq!(allocator.resolve(99), SlotIdentity::Unknown);
    allocator.retire(2);
    allocator.retire(99);
    assert_eq!(allocator.resolve(2), SlotIdentity::Retired);
    assert_eq!(allocator.resolve(99), SlotIdentity::Unknown);
    let accounting = allocator.accounting();
    assert_eq!((accounting.attempted, accounting.admitted), (4, 4));
    assert_eq!(accounting.quota_refusals, 0);
}

// Box 1: quota names the resource and counts attempts separately from admissions.
#[test]
fn ticket_quota_names_resource_and_counts_attempts() {
    let policy = TicketPolicy::reviewed(2, 2).expect("tiny reviewed policy");
    let mut allocator = TicketAllocator::new(policy);
    assert_eq!(allocator.allocate(), Ok(1));
    assert_eq!(allocator.allocate(), Ok(2));
    let err = allocator.allocate().unwrap_err();
    assert_eq!(
        err,
        TicketError::Quota {
            wanted_cookie: 3,
            limit: 2
        }
    );
    assert!(
        err.to_string().contains("identity tickets"),
        "quota names the resource: {err}"
    );
    let accounting = allocator.accounting();
    assert_eq!(accounting.attempted, 3);
    assert_eq!(accounting.admitted, 2);
    assert_eq!(accounting.quota_refusals, 1);
}

// Box 4 RED: near-u64 allocator exhaustion issues the last cookie once, then quota.
#[test]
fn ticket_allocator_near_u64_boundary_issues_max_once_then_quota() {
    let policy = TicketPolicy::reviewed(u64::MAX, 2).expect("full-namespace policy");
    let mut allocator =
        TicketAllocator::restore(policy, u64::MAX - 1, &[]).expect("boundary state");
    assert_eq!(allocator.allocate(), Ok(u64::MAX));
    assert_eq!(allocator.resolve(u64::MAX), SlotIdentity::Active);
    let err = allocator.allocate().unwrap_err();
    assert!(
        matches!(err, TicketError::Quota { .. }),
        "exhausted namespace refuses, never wraps: {err:?}"
    );
    assert!(
        !err.to_string().contains("cookie 0"),
        "wanted cookie saturates, never the reserved zero: {err}"
    );
    let consumed =
        TicketAllocator::restore(policy, u64::MAX, &[]).expect("fully consumed state restores");
    assert_eq!(consumed.accounting().next_ticket, u64::MAX);
    assert!(TicketAllocator::restore(policy, 4, &[0]).is_err());
    assert!(TicketAllocator::restore(policy, 4, &[5]).is_err());
    assert!(TicketAllocator::restore(TicketPolicy::v1_c1(), 16_385, &[]).is_err());
    let restored =
        TicketAllocator::restore(TicketPolicy::v1_c1(), 4, &[2]).expect("restart replay state");
    assert_eq!(restored.resolve(2), SlotIdentity::Retired);
    assert_eq!(restored.resolve(3), SlotIdentity::Active);
}

// Box 4 RED: CAS contention and create failures consume exactly like native.
#[test]
fn ticket_cas_and_create_failures_consume_exactly_like_native() {
    assert_eq!(TICKET_CAS_TRIES, 8, "mirrors COOKIE_CAS_TRIES");
    let mut allocator = TicketAllocator::new(TicketPolicy::v1_c1());
    let mut flaky = FaultScript::new(vec![InjectedFault::CasContention; 7]);
    assert_eq!(allocator.allocate_with_faults(&mut flaky), Ok(1));
    let mut exhausted = FaultScript::new(vec![InjectedFault::CasContention; 8]);
    assert_eq!(
        allocator.allocate_with_faults(&mut exhausted),
        Err(TicketError::RetryExhausted)
    );
    // A failed creation consumes its ticket, exactly like native: the ticket
    // is gone but no live identity exists for it.
    let mut create_fail = FaultScript::new(vec![InjectedFault::CreateFailed]);
    let err = allocator
        .allocate_with_faults(&mut create_fail)
        .unwrap_err();
    assert_eq!(err, TicketError::CreateFailed { consumed_cookie: 2 });
    assert_eq!(allocator.resolve(2), SlotIdentity::Active);
    assert_eq!(allocator.allocate(), Ok(3));
    let accounting = allocator.accounting();
    assert_eq!(accounting.create_failures, 1);
    assert_eq!(accounting.retries_exhausted, 1);
    assert_eq!(accounting.attempted, accounting.admitted + 2);
}

// Box 1: live admission is reserved, admitted, rolled back and released.
#[test]
fn live_admission_reserve_admit_release_with_rollback() {
    assert!(LiveAdmission::new(0).is_err());
    let mut admission = LiveAdmission::new(2).expect("live cap");
    let a = admission.reserve(1).expect("reserve 1");
    let b = admission.reserve(2).expect("reserve 2");
    let err = admission.reserve(3).unwrap_err();
    assert_eq!(
        err,
        AdmissionError::LiveBudgetExhausted { cookie: 3, cap: 2 }
    );
    assert!(
        err.to_string().contains("live admissions"),
        "refusal names the resource: {err}"
    );
    admission.rollback(b);
    let c = admission
        .reserve(3)
        .expect("rollback frees the reservation");
    let token = admission.admit(a);
    assert_eq!(admission.live_count(), 1);
    admission.release(token);
    assert_eq!(admission.live_count(), 0);
    let _ = admission.admit(c);
    assert_eq!(admission.live_count(), 1);
    let accounting = admission.accounting();
    assert_eq!(accounting.peak_live, 1);
    assert_eq!(accounting.admitted_total, 2);
    assert_eq!(accounting.refused_total, 1);
    assert_eq!(accounting.rollbacks, 1);
    assert_eq!(accounting.releases, 1);
}

// Box 4 RED: delayed reclamation keeps the budget full until the token releases.
#[test]
fn live_admission_delayed_reclamation_blocks_until_token_release() {
    let mut admission = LiveAdmission::new(1).expect("live cap");
    let reservation = admission.reserve(7).expect("reserve");
    let token = admission.admit(reservation);
    assert!(matches!(
        admission.reserve(8),
        Err(AdmissionError::LiveBudgetExhausted { .. })
    ));
    admission.release(token);
    assert!(admission.reserve(8).is_ok());
}

// Box 1: candidate B doubles transient cost and needs cross-domain aliases.
#[test]
fn candidate_b_overlap_doubles_links_and_aliases_cross_domain() {
    let mut pair = OverlapPair::single(TicketPolicy::v1_c1());
    assert_eq!(pair.link_factor(), 1);
    pair.begin_overlap(TicketPolicy::v1_c1())
        .expect("first overlap");
    assert_eq!(pair.link_factor(), 2);
    assert_eq!(
        pair.begin_overlap(TicketPolicy::v1_c1()),
        Err(OverlapError::OverlapInProgress)
    );
    pair.alias_same_task(3, 1);
    pair.alias_same_task(5, 2);
    assert_eq!(pair.alias_count(), 2);
    assert_eq!(
        pair.close_old_domain(),
        Err(OverlapError::OldDomainStillProducing)
    );
    pair.seal_old_domain();
    assert_eq!(
        pair.close_old_domain(),
        Err(OverlapError::TerminalEvidenceUnacked)
    );
    pair.ack_old_terminal(DurableAck {
        through_id: 9,
        checksum: 0,
    });
    let closed = pair.close_old_domain().expect("sealed and acked");
    assert_eq!(closed.aliases_preserved, 2);
    assert_eq!(pair.link_factor(), 1);
}

// Box 1: candidate C needs a writer proof plus a covering ack before release.
#[test]
fn candidate_c_rotation_requires_writer_proof_and_ack() {
    let mut rotation = EvidenceRotation::new();
    rotation.append(100);
    rotation.rotate(3).expect("first rotation");
    assert_eq!(rotation.rotate(0), Err(StoreError::RotationInProgress));
    assert_eq!(
        rotation.redirect_writers(2),
        Err(StoreError::WriterCountMismatch {
            at_seal: 3,
            redirected: 2
        })
    );
    rotation.redirect_writers(3).expect("exact writer proof");
    let short = DurableAck {
        through_id: 50,
        checksum: 0,
    };
    assert!(matches!(
        rotation.release_retired(&short),
        Err(StoreError::UnackedRelease { .. })
    ));
    let covering = DurableAck {
        through_id: 99,
        checksum: 0,
    };
    let sealed = rotation.release_retired(&covering).expect("covered ack");
    assert_eq!((sealed.epoch, sealed.records), (0, 100));
    rotation.append(10);
    rotation.rotate(0).expect("rotation reopens after release");
}

// Box 1: the same churn workload against all three candidates. This is the
// ordinary half of the A/B/C comparison; the decision record cites these
// rows and lists the live proofs each candidate still owes.
struct CandidateEvidence {
    admitted: u64,
    refused: u64,
    peak_live: usize,
    aliases: usize,
    rotations: u64,
    max_link_factor: u64,
    retired_tombstones: u64,
}

const COMPARISON_LIFETIMES: u64 = 16_384 + 16;
const COMPARISON_LIVE_CAP: usize = 68;

fn run_candidate_a(policy: TicketPolicy) -> CandidateEvidence {
    let mut tickets = TicketAllocator::new(policy);
    let mut live = LiveAdmission::new(COMPARISON_LIVE_CAP).expect("live cap");
    let mut admitted = 0;
    let mut refused = 0;
    for _ in 0..COMPARISON_LIFETIMES {
        let cookie = match tickets.allocate() {
            Ok(cookie) => cookie,
            Err(_) => {
                refused += 1;
                continue;
            }
        };
        let reservation = live.reserve(cookie).expect("low occupancy fits");
        let token = live.admit(reservation);
        live.release(token);
        tickets.retire(cookie);
        admitted += 1;
    }
    let live_accounting = live.accounting();
    CandidateEvidence {
        admitted,
        refused,
        peak_live: live_accounting.peak_live,
        aliases: 0,
        rotations: 0,
        max_link_factor: 1,
        retired_tombstones: admitted,
    }
}

fn run_candidate_b() -> CandidateEvidence {
    let mut pair = OverlapPair::single(TicketPolicy::v1_c1());
    let mut live = LiveAdmission::new(COMPARISON_LIVE_CAP).expect("live cap");
    let mut admitted = 0;
    let mut max_link_factor = 1;
    for _ in 0..COMPARISON_LIFETIMES {
        let (side, cookie) = pair.allocate();
        let cookie = cookie.expect("current domain has room");
        let reservation = live.reserve(cookie).expect("low occupancy fits");
        let token = live.admit(reservation);
        live.release(token);
        pair.retire(side, cookie);
        admitted += 1;
        if admitted == 16_384 {
            pair.begin_overlap(TicketPolicy::v1_c1())
                .expect("rollover at the old limit");
            max_link_factor = pair.link_factor();
            pair.alias_same_task(cookie, 1);
        }
    }
    let live_accounting = live.accounting();
    CandidateEvidence {
        admitted,
        refused: 0,
        peak_live: live_accounting.peak_live,
        aliases: pair.alias_count(),
        rotations: 1,
        max_link_factor,
        retired_tombstones: admitted,
    }
}

fn run_candidate_c(policy: TicketPolicy) -> CandidateEvidence {
    let mut tickets = TicketAllocator::new(policy);
    let mut live = LiveAdmission::new(COMPARISON_LIVE_CAP).expect("live cap");
    let mut rotation = EvidenceRotation::new();
    let mut rotations = 0;
    for _ in 0..COMPARISON_LIFETIMES {
        let cookie = tickets.allocate().expect("wide namespace admits");
        let reservation = live.reserve(cookie).expect("low occupancy fits");
        let token = live.admit(reservation);
        live.release(token);
        tickets.retire(cookie);
        rotation.append(1);
    }
    rotation.rotate(0).expect("seal evidence");
    rotation.redirect_writers(0).expect("no live writers");
    let ack = DurableAck {
        through_id: COMPARISON_LIFETIMES - 1,
        checksum: 0,
    };
    rotation.release_retired(&ack).expect("covered ack");
    rotations += 1;
    let live_accounting = live.accounting();
    CandidateEvidence {
        admitted: COMPARISON_LIFETIMES,
        refused: 0,
        peak_live: live_accounting.peak_live,
        aliases: 0,
        rotations,
        max_link_factor: 1,
        retired_tombstones: COMPARISON_LIFETIMES,
    }
}

#[test]
fn comparison_same_workload_reports_admission_refusal_aliasing_and_cost() {
    let a_v1 = run_candidate_a(TicketPolicy::v1_c1());
    assert_eq!(a_v1.admitted, 16_384);
    assert_eq!(a_v1.refused, 16);
    assert_eq!(a_v1.peak_live, 1);
    assert_eq!(a_v1.aliases, 0);
    let wide = TicketPolicy::reviewed(1 << 40, 2).expect("reviewed wide policy");
    let a_wide = run_candidate_a(wide);
    assert_eq!(a_wide.admitted, COMPARISON_LIFETIMES);
    assert_eq!(a_wide.refused, 0);
    assert_eq!(a_wide.retired_tombstones, COMPARISON_LIFETIMES);
    let b = run_candidate_b();
    assert_eq!(b.admitted, COMPARISON_LIFETIMES);
    assert_eq!(b.max_link_factor, 2);
    assert!(b.aliases >= 1, "rollover creates cross-domain aliases");
    let c = run_candidate_c(wide);
    assert_eq!(c.admitted, COMPARISON_LIFETIMES);
    assert_eq!(c.rotations, 1);
    assert_eq!(c.aliases, 0);
}

// Box 4 RED (E10): >16,384 serial lifetimes at low occupancy; old limit
// refuses exactly, wide policy continues, tombstones never recycle.
#[test]
fn serial_lifetimes_past_16384_at_low_occupancy_refuse_then_continue() {
    let mut tickets = TicketAllocator::new(TicketPolicy::v1_c1());
    let mut live = LiveAdmission::new(COMPARISON_LIVE_CAP).expect("live cap");
    for _ in 0..16_384 {
        let cookie = tickets.allocate().expect("in-budget lifetime");
        let reservation = live.reserve(cookie).expect("low occupancy");
        let token = live.admit(reservation);
        live.release(token);
        tickets.retire(cookie);
    }
    assert_eq!(live.accounting().peak_live, 1);
    assert!(matches!(tickets.allocate(), Err(TicketError::Quota { .. })));
    for cookie in 1..=16_384 {
        assert_eq!(tickets.resolve(cookie), SlotIdentity::Retired);
    }
    let mut wide_tickets = TicketAllocator::restore(
        TicketPolicy::reviewed(1 << 40, 2).expect("wide"),
        16_384,
        &[],
    )
    .expect("policy migration restores the counter");
    for expected in 16_385..=16_400 {
        assert_eq!(wide_tickets.allocate(), Ok(expected));
    }
}

// Box 4 RED: new caller/RV keys on an already-hot endpoint hit the pair
// budget explicitly; relookup of a known key is not a new admission.
#[test]
fn hot_endpoint_new_caller_rv_keys_hit_pair_budget_explicitly() {
    use p11scope::capacity::FirstTouchLedger;
    let ledger = FirstTouchLedger::new(3);
    assert!(ledger.first_touch_or_relookup(101).expect("caller key"));
    assert!(!ledger.first_touch_or_relookup(101).expect("relookup"));
    assert!(ledger.first_touch_or_relookup(202).expect("rv key"));
    assert!(ledger.first_touch_or_relookup(303).expect("rv key"));
    let err = ledger.first_touch_or_relookup(404).unwrap_err();
    assert!(
        err.to_string().contains("cap 3"),
        "exhaustion names the budget: {err}"
    );
    let snapshot = ledger.snapshot();
    assert_eq!(snapshot.initializations, 3);
    assert_eq!(snapshot.relookups, 1);
    assert_eq!(snapshot.insert_failures, 1);
}

// Box 2: appended segments route endpoints; incompatible inners are refused.
#[test]
fn segments_append_routing_and_compat() {
    let spec = SegmentSpec {
        kind: InnerMapKind::PerCpuArray,
        key_bytes: 4,
        value_bytes: 296,
        max_entries: 2112,
    };
    let mut directory = SegmentDirectory::new(4).expect("directory");
    assert_eq!(directory.append(spec, 512), Ok(0));
    assert_eq!(directory.append(spec, 2112), Ok(1));
    assert_eq!(directory.resolve(0), Some((0, 0)));
    assert_eq!(directory.resolve(511), Some((0, 511)));
    assert_eq!(directory.resolve(512), Some((1, 0)));
    assert_eq!(directory.resolve(512 + 2111), Some((1, 2111)));
    assert_eq!(directory.resolve(512 + 2112), None);
    assert_eq!(directory.total_endpoints(), 512 + 2112);
    let wider_value = SegmentSpec {
        value_bytes: 512,
        ..spec
    };
    assert_eq!(
        directory.append(wider_value, 8),
        Err(SegmentError::IncompatibleSpec)
    );
    let hashed = SegmentSpec {
        kind: InnerMapKind::Hash,
        ..spec
    };
    assert_eq!(
        directory.append(hashed, 8),
        Err(SegmentError::IncompatibleSpec)
    );
    // Same kind and key/value shape with a different per-segment bound stays
    // compatible: the kernel checks shape, not max_entries.
    let roomier = SegmentSpec {
        max_entries: 4096,
        ..spec
    };
    assert!(spec.compatible_with(roomier));
    assert_eq!(directory.append(roomier, 64), Ok(2));
}

// Box 4 RED: map-directory exhaustion names the directory, never a prefix.
#[test]
fn segments_directory_exhaustion_is_explicit() {
    let spec = SegmentSpec {
        kind: InnerMapKind::PerCpuArray,
        key_bytes: 4,
        value_bytes: 296,
        max_entries: 512,
    };
    assert!(SegmentDirectory::new(0).is_err());
    let mut directory = SegmentDirectory::new(2).expect("directory");
    assert_eq!(directory.append(spec, 512), Ok(0));
    assert_eq!(directory.append(spec, 512), Ok(1));
    let err = directory.append(spec, 512).unwrap_err();
    assert_eq!(err, SegmentError::DirectoryFull { cap: 2 });
    assert!(
        err.to_string().contains("segment directory"),
        "exhaustion names the resource: {err}"
    );
    assert_eq!(directory.segment_count(), 2);
}

// Box 4 RED: cross-segment operations name every touched segment.
#[test]
fn segments_cross_segment_identity_lists_every_touched_segment() {
    let spec = SegmentSpec {
        kind: InnerMapKind::PerCpuArray,
        key_bytes: 4,
        value_bytes: 296,
        max_entries: 512,
    };
    let mut directory = SegmentDirectory::new(4).expect("directory");
    directory.append(spec, 512).expect("segment 0");
    directory.append(spec, 512).expect("segment 1");
    assert_eq!(directory.check_cross_segment(&[10, 600]), Ok(vec![0, 1]));
    assert_eq!(directory.check_cross_segment(&[7]), Ok(vec![0]));
    assert_eq!(
        directory.check_cross_segment(&[7, 9_999]),
        Err(SegmentError::UnknownEndpoint { endpoint: 9_999 })
    );
}

// Box 2: the segment cost model counts lookups, FDs, per-CPU bytes and links.
#[test]
fn segments_cost_model_counts_lookups_fds_and_percpu() {
    let spec = SegmentSpec {
        kind: InnerMapKind::PerCpuArray,
        key_bytes: 4,
        value_bytes: 296,
        max_entries: 2112,
    };
    let mut directory = SegmentDirectory::new(4).expect("directory");
    directory.append(spec, 2112).expect("segment 0");
    directory.append(spec, 2112).expect("segment 1");
    let cost = directory.cost(12);
    assert_eq!(
        (cost.outer_lookups_per_op, cost.inner_lookups_per_op),
        (1, 1)
    );
    assert_eq!(cost.fds, 3, "one outer plus one FD per inner map");
    assert_eq!(
        (cost.inner_creations, cost.outer_publications),
        (2, 2),
        "one inner creation plus one outer publication per segment"
    );
    assert_eq!(cost.per_cpu_payload_bytes, 2 * 2112 * 296 * 12);
    assert_eq!(cost.link_pairs, 2 * 2112);
}

// Box 2 RED: a live counter map is never swapped under active writers.
#[test]
fn segments_never_replace_live_counter_without_writer_transition() {
    let cell = CounterCell::new();
    let writers = WriterSet::new();
    cell.increment();
    cell.increment();
    {
        let _guard = writers.hold();
        let err = cell.try_replace_quiesced(0, &writers).unwrap_err();
        assert_eq!(err.in_flight(), 1, "refusal counts live writers");
        assert_eq!(cell.get(), 2, "refused replace touches nothing");
    }
    assert!(writers.quiesced());
    assert_eq!(cell.try_replace_quiesced(0, &writers), Ok(2));
    assert_eq!(cell.get(), 0);
}

// Box 2 RED: no replacement loses a concurrent increment. Every increment
// lands either inside a returned old value or in the final cell.
#[test]
fn counter_cell_concurrent_increments_survive_refused_replace() {
    use std::sync::{Arc, Mutex};
    let cell = Arc::new(CounterCell::new());
    let writers = Arc::new(WriterSet::new());
    let observed = Arc::new(Mutex::new(Vec::new()));
    std::thread::scope(|scope| {
        for _ in 0..4 {
            let (cell, writers) = (Arc::clone(&cell), Arc::clone(&writers));
            scope.spawn(move || {
                for _ in 0..1_000 {
                    let _guard = writers.hold();
                    cell.increment();
                }
            });
        }
        let (cell, writers, observed) = (
            Arc::clone(&cell),
            Arc::clone(&writers),
            Arc::clone(&observed),
        );
        scope.spawn(move || {
            for _ in 0..400 {
                if let Ok(old) = cell.try_replace_quiesced(0, &writers) {
                    observed.lock().expect("observed ledger").push(old);
                }
            }
        });
    });
    let drained: u64 = observed.lock().expect("observed ledger").iter().sum();
    assert_eq!(
        drained + cell.get(),
        4_000,
        "every increment is in a returned old value or the final cell"
    );
    assert!(writers.quiesced());
}

// Box 3: allocation walks reserved -> settlement with no skips.
#[test]
fn allocation_states_follow_reserved_to_settlement() {
    let mut allocation = Allocation::reserve(11, 4096);
    assert_eq!(allocation.state(), AllocState::Reserved);
    for next in [
        AllocState::Initialized,
        AllocState::Published,
        AllocState::ProducersEnabled,
        AllocState::Retired,
        AllocState::SettlementAcked,
    ] {
        allocation.transition(next).expect("legal edge");
        assert_eq!(allocation.state(), next);
    }
    assert_eq!(allocation.payload_bytes(), 4096);
}

// Box 3 RED: illegal transitions fail and preserve prior state and data.
#[test]
fn allocation_illegal_transition_preserves_state_and_payload() {
    let mut allocation = Allocation::reserve(12, 512);
    assert!(allocation.transition(AllocState::Published).is_err());
    assert_eq!(allocation.state(), AllocState::Reserved);
    assert_eq!(allocation.payload_bytes(), 512);
    allocation
        .transition(AllocState::Initialized)
        .expect("edge");
    allocation.transition(AllocState::Published).expect("edge");
    allocation
        .transition(AllocState::ProducersEnabled)
        .expect("edge");
    assert!(allocation.transition(AllocState::Initialized).is_err());
    assert_eq!(allocation.state(), AllocState::ProducersEnabled);
    assert_eq!(allocation.payload_bytes(), 512);
}

// Box 3/4 RED: partial attach/readback failure quarantines, then settles.
#[test]
fn allocation_quarantine_paths_for_partial_failure() {
    let mut readback = Allocation::reserve(13, 64);
    readback.transition(AllocState::Initialized).expect("edge");
    readback
        .transition(AllocState::Quarantined)
        .expect("readback failure quarantines");
    readback
        .transition(AllocState::SettlementAcked)
        .expect("quarantine settles");
    let mut attach = Allocation::reserve(14, 64);
    attach.transition(AllocState::Initialized).expect("edge");
    attach.transition(AllocState::Published).expect("edge");
    attach
        .transition(AllocState::Quarantined)
        .expect("partial attach quarantines");
    assert!(attach.transition(AllocState::ProducersEnabled).is_err());
    attach
        .transition(AllocState::SettlementAcked)
        .expect("quarantine settles");
}

// Box 5: RAM, history and disk budgets are independent and name their resource.
#[test]
fn ram_history_disk_budgets_are_independent() {
    let mut ram = RamBudget::new(1024).expect("ram budget");
    let mut history = HistoryBudget::new(4).expect("history budget");
    let mut disk = DiskBudget::new(512).expect("disk budget");
    assert!(RamBudget::new(0).is_err());
    ram.acquire(1024).expect("fill ram");
    let err = ram.acquire(1).unwrap_err();
    assert_eq!(
        err,
        BudgetError::RamExhausted {
            wanted: 1,
            available: 0
        }
    );
    assert!(err.to_string().contains("RAM"), "refusal names RAM: {err}");
    history
        .acquire_records(4)
        .expect("history unaffected by RAM");
    let err = history.acquire_records(1).unwrap_err();
    assert_eq!(err, BudgetError::HistoryExhausted { wanted: 1, cap: 4 });
    assert!(err.to_string().contains("history"), "{err}");
    disk.acquire(512).expect("disk unaffected");
    let err = disk.acquire(1).unwrap_err();
    assert_eq!(
        err,
        BudgetError::DiskExhausted {
            wanted: 1,
            available: 0
        }
    );
    assert!(err.to_string().contains("disk"), "{err}");
    ram.release(1024);
    history.release_records(4);
    disk.release(512);
    assert_eq!(ram.peak(), 1024);
    assert_eq!(history.peak(), 4);
    assert_eq!(disk.peak(), 512);
}

// Box 5 RED: export needs producer cutoff, exact final snapshot and full ack.
#[test]
fn export_requires_cutoff_snapshot_and_full_ack() {
    let mut session = ExportSession::new();
    session.append(ExportKind::PositiveEvidence, 32);
    session.append(ExportKind::CounterSnapshot, 64);
    assert_eq!(session.pending_count(), 2);
    assert!(matches!(
        session.stage_batch(),
        Err(ExportError::ProducersStillOpen { .. })
    ));
    assert_eq!(
        session.cutoff_producers(2),
        Err(ExportError::ProducersStillOpen { open: 2 })
    );
    session.cutoff_producers(0).expect("cutoff");
    assert_eq!(
        session.stage_batch(),
        Err(ExportError::FinalSnapshotMissing)
    );
    let wrong = FinalSnapshot {
        records: 3,
        checksum: 0,
    };
    assert!(matches!(
        session.include_final_snapshot(&wrong),
        Err(ExportError::FinalSnapshotMismatch { .. })
    ));
    let batch_preview = session.pending_batch();
    session
        .include_final_snapshot(&FinalSnapshot::compute(&batch_preview))
        .expect("exact snapshot");
    let batch = session.stage_batch().expect("staged");
    assert_eq!(batch.len(), 2);
    let short = DurableAck {
        through_id: 0,
        checksum: export_checksum(&batch),
    };
    assert!(matches!(
        session.commit_ack(&short),
        Err(ExportError::AckThroughMismatch { .. })
    ));
    let bad_checksum = DurableAck {
        through_id: 1,
        checksum: export_checksum(&batch).wrapping_add(1),
    };
    assert!(matches!(
        session.commit_ack(&bad_checksum),
        Err(ExportError::AckChecksumMismatch { .. })
    ));
    let ack = DurableAck {
        through_id: 1,
        checksum: export_checksum(&batch),
    };
    assert_eq!(session.commit_ack(&ack), Ok(2));
    assert_eq!(session.acked_through(), Some(1));
    assert_eq!(session.pending_count(), 0);
}

// Box 5 RED (A-F5): publication cannot strand omission history behind positives.
#[test]
fn export_preserves_omission_history_a_f5() {
    let mut session = ExportSession::new();
    session.append(ExportKind::PositiveEvidence, 32);
    session.append(ExportKind::OmissionHistory, 16);
    session.cutoff_producers(0).expect("cutoff");
    let preview = session.pending_batch();
    session
        .include_final_snapshot(&FinalSnapshot::compute(&preview))
        .expect("snapshot");
    let batch = session.stage_batch().expect("staged");
    assert_eq!(batch.len(), 2, "no subset staging strands omission history");
    assert!(
        batch
            .iter()
            .any(|record| record.kind == ExportKind::OmissionHistory)
    );
    // A partial ack that would strand the omission record is refused.
    let partial = DurableAck {
        through_id: batch[0].id,
        checksum: export_checksum(&batch[..1]),
    };
    assert!(session.commit_ack(&partial).is_err());
    let full = DurableAck {
        through_id: batch[1].id,
        checksum: export_checksum(&batch),
    };
    assert_eq!(session.commit_ack(&full), Ok(2));
}

/// Scripted durable sink: fail, truncate or strand writes on demand.
struct ScriptedSink {
    script: std::collections::VecDeque<ScriptedAction>,
    disk: DiskBudget,
    staged_bytes: u64,
}

#[derive(Clone, Copy)]
enum ScriptedAction {
    FailWrite,
    PartialWrite(u64),
    FillDisk,
    Ok,
}

impl ScriptedSink {
    fn new(script: Vec<ScriptedAction>, disk_bytes: u64) -> Self {
        Self {
            script: script.into(),
            disk: DiskBudget::new(disk_bytes).expect("sink disk"),
            staged_bytes: 0,
        }
    }
}

impl DurableSink for ScriptedSink {
    fn stage(&mut self, records: &[ExportRecord]) -> Result<StagedExport, SinkError> {
        let total: u64 = records.iter().map(|record| record.bytes).sum();
        match self.script.pop_front().unwrap_or(ScriptedAction::Ok) {
            ScriptedAction::FailWrite => {
                return Err(SinkError::WriteFailed {
                    written_bytes: 0,
                    total_bytes: total,
                });
            }
            ScriptedAction::PartialWrite(written) => {
                let written = written.min(total);
                return Err(SinkError::WriteFailed {
                    written_bytes: written,
                    total_bytes: total,
                });
            }
            ScriptedAction::FillDisk => {
                let _ = self.disk.acquire(self.disk.available());
            }
            ScriptedAction::Ok => {}
        }
        if total > self.disk.available() {
            return Err(SinkError::SinkFull {
                needed_bytes: total,
                available_bytes: self.disk.available(),
            });
        }
        self.staged_bytes = total;
        Ok(StagedExport {
            through_id: records.last().map(|record| record.id).unwrap_or(0),
            checksum: export_checksum(records),
            bytes: total,
        })
    }

    fn commit(
        &mut self,
        staged: StagedExport,
        readback_checksum: u64,
    ) -> Result<DurableAck, SinkError> {
        if readback_checksum != staged.checksum {
            return Err(SinkError::ReadbackMismatch {
                expected: staged.checksum,
                actual: readback_checksum,
            });
        }
        self.disk
            .acquire(staged.bytes)
            .map_err(|_| SinkError::SinkFull {
                needed_bytes: staged.bytes,
                available_bytes: self.disk.available(),
            })?;
        Ok(DurableAck {
            through_id: staged.through_id,
            checksum: staged.checksum,
        })
    }
}

fn ready_session() -> (ExportSession, Vec<ExportRecord>) {
    let mut session = ExportSession::new();
    session.append(ExportKind::PositiveEvidence, 100);
    session.append(ExportKind::CounterSnapshot, 200);
    session.cutoff_producers(0).expect("cutoff");
    let preview = session.pending_batch();
    session
        .include_final_snapshot(&FinalSnapshot::compute(&preview))
        .expect("snapshot");
    let batch = session.stage_batch().expect("staged");
    (session, batch)
}

// Box 5 RED: sink failure, partial write and full sink keep pending stable.
#[test]
fn export_survives_sink_failure_partial_write_and_full_sink() {
    let (mut session, batch) = ready_session();
    let mut failing = ScriptedSink::new(vec![ScriptedAction::FailWrite], 1 << 20);
    let err = failing.stage(&batch).unwrap_err();
    assert_eq!(
        err,
        SinkError::WriteFailed {
            written_bytes: 0,
            total_bytes: 300
        }
    );
    let mut partial = ScriptedSink::new(vec![ScriptedAction::PartialWrite(100)], 1 << 20);
    let err = partial.stage(&batch).unwrap_err();
    assert_eq!(
        err,
        SinkError::WriteFailed {
            written_bytes: 100,
            total_bytes: 300
        }
    );
    let mut full = ScriptedSink::new(vec![ScriptedAction::FillDisk], 300);
    let err = full.stage(&batch).unwrap_err();
    assert!(matches!(err, SinkError::SinkFull { .. }), "{err:?}");
    assert_eq!(session.pending_count(), 2, "failed stages strand nothing");
    assert_eq!(session.stage_batch().expect("re-stage").len(), 2);
    let mut healthy = ScriptedSink::new(vec![ScriptedAction::Ok], 1 << 20);
    let staged = healthy.stage(&batch).expect("staged");
    let ack = healthy
        .commit(staged, export_checksum(&batch))
        .expect("committed");
    assert_eq!(session.commit_ack(&ack), Ok(2));
}

// Box 5 RED: crash between stage and commit replays the same stable IDs.
#[test]
fn export_crash_between_stage_and_commit_replays_without_duplication() {
    let (mut session, batch) = ready_session();
    let mut sink = ScriptedSink::new(vec![ScriptedAction::Ok], 1 << 20);
    let staged = sink.stage(&batch).expect("staged");
    let _ = staged;
    assert_eq!(session.pending_count(), 2, "crash strands no record");
    assert_eq!(session.acked_through(), None);
    let replayed = session.stage_batch().expect("re-stage after crash");
    assert_eq!(replayed, batch, "stable IDs survive the crash");
    let staged = sink.stage(&replayed).expect("staged again");
    let ack = sink
        .commit(staged, export_checksum(&replayed))
        .expect("committed");
    session.commit_ack(&ack).expect("acked");
    let report = session.replay_report(&[(0, 0), (1, 0), (1, 0), (7, 0)]);
    assert_eq!(report.duplicates, 3);
    assert_eq!(report.unaccounted, 1);
}

// Box 6: ordinary preflight math for the controller-owned live cells. Link,
// FD, payload and segment budgets are pure arithmetic the controller
// compares against the live host envelope before running privileged cells.
#[test]
fn capacity_preflight_budgets_for_t7_live_cells() {
    use p11scope::capacity::{AttachCost, InventoryBudget};
    for (n, links, payload) in [
        (576u64, 578u64, 4608u64),
        (1024, 1026, 8192),
        (4097, 4099, 32776),
        (6530, 6532, 52240),
        (8192, 8194, 65536),
    ] {
        let cost = AttachCost::for_endpoints(n);
        assert_eq!(cost.links, n);
        assert_eq!(cost.program_loads, 2);
        assert_eq!(cost.teardown_steps, 2 * n);
        assert!(!cost.map_value_sharing_removes_link_cost);
        assert_eq!(cost.links + 2, links, "N entry plus 2 lifecycle links");
        assert_eq!(2 * cost.links, 2 * n, "paired Detailed probes");
        let budget = InventoryBudget::new(n, 8 * n).expect("8N inventory payload");
        assert_eq!(budget.payload_bytes(), payload);
    }
    // Segmented growth to the 6530 union: three full 2112 segments plus a
    // 194 tail under one outer directory.
    let spec = SegmentSpec {
        kind: InnerMapKind::PerCpuArray,
        key_bytes: 4,
        value_bytes: 296,
        max_entries: 2112,
    };
    let mut directory = SegmentDirectory::new(4).expect("directory");
    for len in [2112, 2112, 2112, 194] {
        directory.append(spec, len).expect("segment");
    }
    assert_eq!(directory.total_endpoints(), 6530);
    let at_64 = directory.cost(64);
    assert_eq!(at_64.fds, 5, "one outer plus one FD per inner map");
    assert_eq!(
        (at_64.inner_creations, at_64.outer_publications),
        (4, 4),
        "four inners created and published for the 6530 union"
    );
    assert_eq!(at_64.per_cpu_payload_bytes, 6530 * 296 * 64);
    assert_eq!(at_64.link_pairs, 6530);
    assert_eq!(directory.cost(12).per_cpu_payload_bytes, 6530 * 296 * 12);
}

// Box 7: peak, current and retained are measured as separate dimensions.
#[test]
fn envelope_report_measures_peak_current_retained_separately() {
    use p11scope::capacity::EnvelopeReport;
    let mut ram = RamBudget::new(1 << 20).expect("ram");
    let mut history = HistoryBudget::new(1 << 20).expect("history");
    let mut disk = DiskBudget::new(1 << 20).expect("disk");
    ram.acquire(900).expect("ram");
    ram.release(800);
    history.acquire_records(500).expect("history");
    history.release_records(400);
    disk.acquire(300).expect("disk");
    let report = EnvelopeReport::capture(&ram, &history, &disk, 100, 50, 300);
    let rendered = report.render();
    for line in [
        "ram current=100 peak=900 retained=100",
        "history current=100 peak=500 retained=50",
        "disk current=300 peak=300 retained=300",
    ] {
        assert!(
            rendered.contains(line),
            "report renders {line}:\n{rendered}"
        );
    }
}
