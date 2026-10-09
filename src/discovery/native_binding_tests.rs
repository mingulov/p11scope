//! SPDX-License-Identifier: GPL-3.0-or-later
//! Scripted binder tests: rows, pins, cookie answers and exec records are
//! programmed, never read from the host.

use super::*;
use crate::attach::capture::{CaptureHealth, CapturePhase, ScopeCustody};
use crate::discovery::inventory_attach_set::{AttachObjectId, EndpointId};
use p11scope_ebpf_common::DiscoveryRecord;
use std::collections::HashMap;

/// A scripted pin: (pid, generation). Two generations of one pid are two
/// processes.
type Pin = (u32, u64);

#[derive(Default)]
struct World {
    live: HashMap<u32, (CallerId, u64, Pin)>,
    /// What a cookie query through a pin answers, per domain.
    answers: HashMap<(Pin, NativeDomainId), CookieQuery>,
    queries: usize,
}

impl World {
    fn admit(&mut self, pid: u32, generation: u64, caller: u32, first_seen_ns: u64) -> CallerId {
        let id = CallerId(caller);
        self.live
            .insert(pid, (id, first_seen_ns, (pid, generation)));
        id
    }

    fn retire(&mut self, pid: u32) {
        self.live.remove(&pid);
    }

    fn answer(&mut self, pid: u32, generation: u64, domain: NativeDomainId, query: CookieQuery) {
        self.answers.insert(((pid, generation), domain), query);
    }
}

fn cookie(domain: NativeDomainId, value: u64) -> CookieQuery {
    CookieQuery::Cookie(DomainCookie::scripted(domain, value))
}

fn row(domain: NativeDomainId, ticket: u64, exec: u64, tgid: u32, t0: u64) -> WitnessRow {
    row_on(domain, ticket, exec, tgid, t0, 0)
}

fn row_on(
    domain: NativeDomainId,
    ticket: u64,
    exec: u64,
    tgid: u32,
    t0: u64,
    object: u32,
) -> WitnessRow {
    WitnessRow::scripted(
        domain,
        ticket,
        exec,
        AttachObjectId::scripted(object),
        EndpointId(object),
        tgid,
        t0,
    )
}

/// One witness read whose health (read first, at `at_ns`) shows `ring_loss`
/// lost lifecycle records so far; `None` makes the health unreadable.
fn read_at(
    domain: NativeDomainId,
    rows: Vec<WitnessRow>,
    at_ns: u64,
    ring_loss: Option<u64>,
) -> WitnessBatch {
    WitnessBatch {
        domain,
        phase: CapturePhase::Active,
        rows,
        integrity: Vec::new(),
        integrity_total: 0,
        visited: 0,
        sweep_completed: true,
        sweeps_completed: 1,
        row_bound_reached: false,
        deadline_reached: false,
        read_failures: Vec::new(),
        unrecorded_rows: 0,
        sweep_gaps: false,
        counts: Vec::new(),
        refresh_sweep_completed: true,
        refresh_sweep_gaps: false,
        refresh_deadline_reached: false,
        refresh_sweeps_completed: 1,
        seen_rows: 0,
        pair_limit: 65_536,
        health: CaptureHealth {
            discovery_counters: ring_loss.map(|loss| [loss, 0, 0, 0, 0]),
            ..CaptureHealth::default()
        },
        health_regression: None,
        health_unproven: None,
        health_baseline_ns: 0,
        health_read_ns: at_ns,
        rows_anchor_ns: at_ns + 1,
        rows_read_ns: at_ns + 1,
        counts_read_ns: at_ns + 1,
        changed_objects: Vec::new(),
        custody: ScopeCustody::System,
        custody_proven_ns: None,
        lifecycle_proven_ns: u64::MAX,
        lifecycle_loss: None,
        unsettled: false,
    }
}

fn exec_record(tgid: u32, ts: u64) -> DiscoveryRecord {
    // SAFETY: `DiscoveryRecord` is a plain `repr(C)` integer record; all
    // zeroes is a valid value (the same construction engine tests use).
    let mut record: DiscoveryRecord = unsafe { std::mem::zeroed() };
    record.kind = DISCOVERY_KIND_EXEC;
    record.pid_tgid = (u64::from(tgid) << 32) | u64::from(tgid);
    record.hook_ts_ns = ts;
    record
}

/// A complete drain of `domain` that started at `at_ns`.
fn drained(domain: NativeDomainId, execs: &[(u32, u64)], at_ns: u64) -> DiscoveryBatch {
    DiscoveryBatch::scripted(
        domain,
        execs
            .iter()
            .map(|(tgid, ts)| exec_record(*tgid, *ts))
            .collect(),
        at_ns,
    )
}

struct Run {
    binder: NativeBinder,
    world: World,
    domain: NativeDomainId,
    clock: u64,
}

impl Run {
    /// A domain whose exec coverage began at 0, before every admission
    /// these tests script (the coverage tests set their own).
    fn new() -> Self {
        Self::with_limits(BinderLimits::default())
    }

    fn with_limits(limits: BinderLimits) -> Self {
        let domain = NativeDomainId::mint();
        let mut binder = NativeBinder::new(limits);
        binder.note_exec_coverage(ExecCoverage::scripted(domain, 0));
        Self {
            binder,
            world: World::default(),
            domain,
            clock: 1_000,
        }
    }

    /// A domain whose exec coverage began at `start_ns`.
    fn covered_from(start_ns: u64) -> Self {
        let domain = NativeDomainId::mint();
        let mut binder = NativeBinder::new(BinderLimits::default());
        binder.note_exec_coverage(ExecCoverage::scripted(domain, start_ns));
        Self {
            binder,
            world: World::default(),
            domain,
            clock: 1_000,
        }
    }

    fn tick(&mut self) -> u64 {
        self.clock += 10;
        self.clock
    }

    fn read(&mut self, rows: Vec<WitnessRow>) {
        self.read_with_loss(rows, 0);
    }

    fn read_with_loss(&mut self, rows: Vec<WitnessRow>, ring_loss: u64) {
        let domain = self.domain;
        self.read_domain(domain, rows, Some(ring_loss));
    }

    fn read_domain(&mut self, domain: NativeDomainId, rows: Vec<WitnessRow>, loss: Option<u64>) {
        let at = self.tick();
        let batch = read_at(domain, rows, at, loss);
        let World {
            live,
            answers,
            queries,
        } = &mut self.world;
        let lookup = Lookup(live);
        let mut identity = AnswerTable { answers, queries };
        self.binder.absorb_witnesses(&batch, &lookup, &mut identity);
    }

    fn drain(&mut self, execs: &[(u32, u64)]) {
        let domain = self.domain;
        let at = self.tick();
        self.binder.absorb_lifecycle(&drained(domain, execs, at));
    }

    /// Both horizons after everything read so far: a complete drain, then
    /// a readable health read with no rows.
    fn settle(&mut self) {
        self.drain(&[]);
        self.read(Vec::new());
    }

    fn verdicts(&mut self) -> Vec<Binding> {
        self.binder
            .take_decisions()
            .into_iter()
            .map(|decision| decision.binding)
            .collect()
    }
}

struct Lookup<'a>(&'a HashMap<u32, (CallerId, u64, Pin)>);

impl CallerLookup<Pin> for Lookup<'_> {
    fn live_caller(&self, pid: u32) -> Option<LiveCaller<'_, Pin>> {
        self.0.get(&pid).map(|(id, first_seen_ns, pin)| LiveCaller {
            id: *id,
            first_seen_ns: *first_seen_ns,
            pin,
        })
    }
}

struct AnswerTable<'a> {
    answers: &'a HashMap<(Pin, NativeDomainId), CookieQuery>,
    queries: &'a mut usize,
}

impl NativeIdentity<Pin> for AnswerTable<'_> {
    fn owner_image(&mut self, _: u32) -> Option<ImageIdentity> {
        None
    }

    fn query_cookie(&mut self, domain: NativeDomainId, pin: &Pin) -> CookieQuery {
        *self.queries += 1;
        self.answers
            .get(&(*pin, domain))
            .cloned()
            .unwrap_or(CookieQuery::NoCookie)
    }
}

const T: u32 = 4242;

fn bound(caller: CallerId) -> Binding {
    Binding::Bound(caller)
}

fn unbound(reason: UnboundReason) -> Binding {
    Binding::Unbound(reason)
}

#[test]
fn a_row_binds_exactly_once_both_horizons_cover_its_read() {
    let mut run = Run::new();
    let d = run.domain;
    let x = run.world.admit(T, 1, 0, 1_000);
    run.world.answer(T, 1, d, cookie(d, 7));
    run.read(vec![row(d, 7, 1, T, 1_500)]);
    assert!(run.verdicts().is_empty(), "no lifecycle horizon yet");
    run.drain(&[]);
    assert!(
        run.verdicts().is_empty(),
        "no health read after the row yet"
    );
    run.read(Vec::new());
    assert_eq!(run.verdicts(), vec![bound(x)]);
    assert_eq!(run.binder.census().bound, 1);
    assert_eq!(run.binder.census().pending, 0);
}

#[test]
fn an_incomplete_drain_never_covers_a_read() {
    let mut run = Run::new();
    let d = run.domain;
    run.world.admit(T, 1, 0, 1_000);
    run.world.answer(T, 1, d, cookie(d, 7));
    run.read(vec![row(d, 7, 1, T, 1_500)]);
    let mut partial = drained(d, &[], run.tick());
    partial.record_bound_reached = true;
    run.binder.absorb_lifecycle(&partial);
    run.read(Vec::new());
    assert!(
        run.verdicts().is_empty(),
        "a drain that stopped at its record bound proves nothing about later records"
    );
    let mut late = drained(d, &[], run.tick());
    late.deadline_reached = true;
    run.binder.absorb_lifecycle(&late);
    assert!(run.verdicts().is_empty(), "nor one that hit its deadline");
}

/// The race the horizon closes: an exec before the row's insertion whose
/// record is still in the ring when the row is read.
#[test]
fn an_exec_record_drained_after_the_read_still_blocks_the_row() {
    let mut run = Run::new();
    let d = run.domain;
    run.world.admit(T, 1, 0, 1_000);
    run.world.answer(T, 1, d, cookie(d, 7));
    run.read(vec![row(d, 7, 2, T, 1_600)]);
    run.drain(&[(T, 1_550)]);
    run.read(Vec::new());
    assert_eq!(
        run.verdicts(),
        vec![unbound(UnboundReason::ExecAfterAdmission)]
    );
}

#[test]
fn same_binary_re_exec_splits_by_exec_id() {
    let mut run = Run::new();
    let d = run.domain;
    let x = run.world.admit(T, 1, 0, 1_000);
    run.world.answer(T, 1, d, cookie(d, 7));
    run.read(vec![row_on(d, 7, 1, T, 1_500, 0)]);
    run.settle();
    assert_eq!(run.verdicts(), vec![bound(x)]);

    // A leader exec of the same binary: same ticket, exec sequence 2. The
    // scan lane cannot see it (same exe identity), so X stays live.
    run.drain(&[(T, 2_000)]);
    run.read(vec![row_on(d, 7, 2, T, 2_100, 1)]);
    run.settle();
    assert_eq!(run.verdicts(), vec![unbound(UnboundReason::ExecTransition)]);
    let transitions = run.binder.take_transitions();
    assert_eq!(transitions.len(), 1);
    assert_eq!(transitions[0].caller(), x);
    assert_eq!(transitions[0].pid(), T);
    assert_eq!(transitions[0].old().1, 1);
    assert_eq!(transitions[0].new_image().1, 2);

    // The old image's rows still bind to X, at once (cached exact image).
    run.read(vec![row_on(d, 7, 1, T, 2_200, 2)]);
    assert_eq!(run.verdicts(), vec![bound(x)]);

    // The coordinator retired X and minted its successor.
    let successor = run.world.admit(T, 1, 1, 2_500);
    run.read(vec![row_on(d, 7, 2, T, 2_600, 3)]);
    run.settle();
    assert_eq!(run.verdicts(), vec![bound(successor)]);
    assert!(run.binder.take_transitions().is_empty());
    // Both images keep their incarnations.
    run.read(vec![
        row_on(d, 7, 1, T, 2_700, 4),
        row_on(d, 7, 2, T, 2_700, 5),
    ]);
    assert_eq!(run.verdicts(), vec![bound(x), bound(successor)]);
}

#[test]
fn different_binary_exec_binds_each_image_to_its_own_incarnation() {
    let mut run = Run::new();
    let d = run.domain;
    let x = run.world.admit(T, 1, 0, 1_000);
    run.world.answer(T, 1, d, cookie(d, 7));
    run.read(vec![row_on(d, 7, 1, T, 1_500, 0)]);
    run.settle();
    assert_eq!(run.verdicts(), vec![bound(x)]);
    // The exe changed: the scan lane retired X and admitted X' at 2_400
    // (same pin: same process, same ticket after a leader exec).
    run.world.retire(T);
    let successor = run.world.admit(T, 1, 1, 2_400);
    run.drain(&[(T, 2_000)]);
    run.read(vec![
        row_on(d, 7, 2, T, 2_100, 1), // the new image, before X' was admitted
        row_on(d, 7, 2, T, 2_500, 2), // after
    ]);
    run.settle();
    assert_eq!(
        run.verdicts(),
        vec![unbound(UnboundReason::BeforeAdmission), bound(successor)]
    );
    assert!(
        run.binder.take_transitions().is_empty(),
        "the scan lane already split; the binder proves nothing new"
    );
}

#[test]
fn nonleader_exec_makes_the_cookie_mismatch_and_the_row_unbound() {
    let mut run = Run::new();
    let d = run.domain;
    run.world.admit(T, 1, 0, 1_000);
    // A nonleader exec replaced the leader task: the pidfd now answers no
    // ticket (the new leader never entered an endpoint) ...
    run.world.answer(T, 1, d, CookieQuery::NoCookie);
    run.read(vec![row(d, 7, 1, T, 1_500)]);
    run.settle();
    assert_eq!(run.verdicts(), vec![unbound(UnboundReason::CookieMismatch)]);
    // ... or a new one, which the old leader's rows never equal.
    run.world.answer(T, 1, d, cookie(d, 8));
    run.read(vec![row_on(d, 7, 1, T, 1_600, 1)]);
    run.settle();
    assert_eq!(run.verdicts(), vec![unbound(UnboundReason::CookieMismatch)]);
}

#[test]
fn a_changed_leader_under_a_bound_incarnation_is_a_transition() {
    let mut run = Run::new();
    let d = run.domain;
    let x = run.world.admit(T, 1, 0, 1_000);
    run.world.answer(T, 1, d, cookie(d, 7));
    run.read(vec![row(d, 7, 1, T, 1_500)]);
    run.settle();
    assert_eq!(run.verdicts(), vec![bound(x)]);
    // Nonleader exec: the held pidfd now answers ticket 8, and the new
    // leader's row carries it. The record of that exec was lost, so only
    // the ticket change proves it.
    run.world.answer(T, 1, d, cookie(d, 8));
    run.read(vec![row_on(d, 8, 1, T, 2_100, 1)]);
    run.settle();
    assert_eq!(run.verdicts(), vec![unbound(UnboundReason::ExecTransition)]);
    let transitions = run.binder.take_transitions();
    assert_eq!(transitions.len(), 1);
    assert_eq!(transitions[0].caller(), x);
}

#[test]
fn pid_reuse_produces_a_different_cookie_and_an_unbound_row() {
    let mut run = Run::new();
    let d = run.domain;
    // The original process (ticket 7) exited; its pid now names another
    // process, admitted at 1_000, holding ticket 9.
    run.world.admit(T, 2, 3, 1_000);
    run.world.answer(T, 2, d, cookie(d, 9));
    run.read(vec![row(d, 7, 1, T, 1_500)]);
    run.settle();
    assert_eq!(run.verdicts(), vec![unbound(UnboundReason::CookieMismatch)]);
}

#[test]
fn exit_before_the_poll_leaves_the_row_unbound() {
    let mut run = Run::new();
    let d = run.domain;
    run.read(vec![row(d, 7, 1, T, 1_500)]);
    run.settle();
    assert_eq!(run.verdicts(), vec![unbound(UnboundReason::NoLiveCaller)]);
    // Exit during the query.
    run.world.admit(T + 1, 1, 1, 1_000);
    run.world.answer(T + 1, 1, d, CookieQuery::Exited);
    run.read(vec![row(d, 9, 1, T + 1, 1_500)]);
    run.settle();
    assert_eq!(run.verdicts(), vec![unbound(UnboundReason::CallerExited)]);
}

#[test]
fn a_cached_image_binds_rows_read_after_its_caller_exited() {
    let mut run = Run::new();
    let d = run.domain;
    let x = run.world.admit(T, 1, 0, 1_000);
    run.world.answer(T, 1, d, cookie(d, 7));
    run.read(vec![row_on(d, 7, 1, T, 1_500, 0)]);
    run.settle();
    assert_eq!(run.verdicts(), vec![bound(x)]);
    run.world.retire(T);
    let queries = run.world.queries;
    run.read(vec![row_on(d, 7, 1, T, 1_900, 1)]);
    assert_eq!(run.verdicts(), vec![bound(x)], "decided at once, exactly");
    assert_eq!(run.world.queries, queries, "a cached image costs no query");
}

#[test]
fn discovery_loss_makes_binding_ambiguous() {
    // Ring loss detected after the admission.
    let mut run = Run::new();
    let d = run.domain;
    run.world.admit(T, 1, 0, 1_000);
    run.world.answer(T, 1, d, cookie(d, 7));
    run.read(vec![row(d, 7, 1, T, 1_500)]);
    run.drain(&[]);
    run.read_with_loss(Vec::new(), 3);
    assert_eq!(run.verdicts(), vec![unbound(UnboundReason::LifecycleLoss)]);

    // A malformed lifecycle record in the drain.
    let mut run = Run::new();
    let d = run.domain;
    run.world.admit(T, 1, 0, 1_000);
    run.world.answer(T, 1, d, cookie(d, 7));
    run.read(vec![row(d, 7, 1, T, 1_500)]);
    let mut failed = drained(d, &[], run.tick());
    failed.failure = Some("malformed record".into());
    run.binder.absorb_lifecycle(&failed);
    run.settle();
    assert_eq!(run.verdicts(), vec![unbound(UnboundReason::LifecycleLoss)]);

    // A loss detected before the admission cannot hide this image's exec.
    let mut run = Run::new();
    let d = run.domain;
    run.read_with_loss(Vec::new(), 3);
    let x = run.world.admit(T, 1, 0, 5_000);
    run.world.answer(T, 1, d, cookie(d, 7));
    run.read_with_loss(vec![row(d, 7, 1, T, 5_500)], 3);
    run.drain(&[]);
    run.read_with_loss(Vec::new(), 3);
    assert_eq!(run.verdicts(), vec![bound(x)]);
}

#[test]
fn unreadable_health_holds_rows_until_finish_then_they_stay_unbound() {
    let mut run = Run::new();
    let d = run.domain;
    run.world.admit(T, 1, 0, 1_000);
    run.world.answer(T, 1, d, cookie(d, 7));
    run.read(vec![row(d, 7, 1, T, 1_500)]);
    run.drain(&[]);
    run.read_domain(d, Vec::new(), None);
    assert!(run.verdicts().is_empty());
    assert_eq!(run.binder.census().pending, 1);
    run.binder.finish(d);
    assert_eq!(
        run.verdicts(),
        vec![unbound(UnboundReason::EvidenceIncomplete)]
    );
    assert_eq!(run.binder.census().pending, 0);
}

#[test]
fn equal_cookie_values_from_two_domains_never_join() {
    let mut run = Run::new();
    let inventory = run.domain;
    let detailed = NativeDomainId::mint();
    let x = run.world.admit(T, 1, 0, 1_000);
    run.world.answer(T, 1, inventory, cookie(inventory, 7));
    run.read(vec![row(inventory, 7, 1, T, 1_500)]);
    run.settle();
    assert_eq!(run.verdicts(), vec![bound(x)]);

    // The same ticket value in another domain: its query answers in that
    // domain only. Without a Detailed answer for this pin, no join.
    run.read_domain(detailed, vec![row(detailed, 7, 1, T, 1_600)], Some(0));
    run.binder.absorb_lifecycle(&drained(detailed, &[], 2_000));
    run.read_domain(detailed, Vec::new(), Some(0));
    assert_eq!(run.verdicts(), vec![unbound(UnboundReason::CookieMismatch)]);

    // A (defective) source that answers the Inventory ticket for a Detailed
    // query still never joins: the ticket carries its domain.
    run.world.answer(T, 1, detailed, cookie(inventory, 7));
    run.read_domain(detailed, vec![row_on(detailed, 7, 1, T, 1_700, 1)], Some(0));
    run.binder.absorb_lifecycle(&drained(detailed, &[], 2_100));
    run.read_domain(detailed, Vec::new(), Some(0));
    assert_eq!(run.verdicts(), vec![unbound(UnboundReason::CookieMismatch)]);
    assert_ne!(
        DomainCookie::scripted(inventory, 7),
        DomainCookie::scripted(detailed, 7)
    );
}

#[test]
fn a_row_recorded_before_the_admission_never_binds() {
    let mut run = Run::new();
    let d = run.domain;
    run.world.admit(T, 1, 0, 2_000);
    run.world.answer(T, 1, d, cookie(d, 7));
    run.read(vec![row(d, 7, 1, T, 1_999)]);
    run.settle();
    assert_eq!(
        run.verdicts(),
        vec![unbound(UnboundReason::BeforeAdmission)]
    );
}

#[test]
fn a_later_exec_sequence_of_the_ticket_makes_its_rows_ambiguous() {
    let mut run = Run::new();
    let d = run.domain;
    run.world.admit(T, 1, 0, 1_000);
    run.world.answer(T, 1, d, cookie(d, 7));
    // Contradictory evidence (two images after the admission and no exec
    // record): neither binds.
    run.read(vec![
        row_on(d, 7, 1, T, 1_500, 0),
        row_on(d, 7, 2, T, 1_600, 1),
    ]);
    run.settle();
    assert_eq!(
        run.verdicts(),
        vec![
            unbound(UnboundReason::ExecAmbiguous),
            unbound(UnboundReason::ExecAmbiguous)
        ]
    );
}

#[test]
fn an_earlier_image_seen_only_before_the_admission_does_not_compete() {
    let mut run = Run::new();
    let d = run.domain;
    let x = run.world.admit(T, 1, 0, 2_000);
    run.world.answer(T, 1, d, cookie(d, 7));
    run.drain(&[(T, 1_800)]);
    run.read(vec![
        row_on(d, 7, 1, T, 1_500, 0),
        row_on(d, 7, 2, T, 2_100, 1),
    ]);
    run.settle();
    assert_eq!(
        run.verdicts(),
        vec![unbound(UnboundReason::BeforeAdmission), bound(x)]
    );
}

#[test]
fn an_incarnation_binds_to_one_image_only() {
    let mut run = Run::new();
    let d = run.domain;
    let x = run.world.admit(T, 1, 0, 1_000);
    run.world.answer(T, 1, d, cookie(d, 7));
    run.read(vec![row(d, 7, 2, T, 1_500)]);
    run.settle();
    assert_eq!(run.verdicts(), vec![bound(x)]);
    // An older sequence of the same ticket read later is never X's image.
    run.read(vec![row_on(d, 7, 1, T, 1_600, 1)]);
    run.settle();
    assert_eq!(run.verdicts(), vec![unbound(UnboundReason::ExecAmbiguous)]);
    assert!(run.binder.take_transitions().is_empty());
}

#[test]
fn bounds_are_counted_never_silent() {
    let mut run = Run::with_limits(BinderLimits {
        pending: 1,
        cookies: 1,
        exec_tgids: 1,
    });
    let d = run.domain;
    run.world.admit(T, 1, 0, 1_000);
    run.world.answer(T, 1, d, cookie(d, 7));
    run.read(vec![
        row_on(d, 7, 1, T, 1_500, 0),
        row_on(d, 8, 1, T, 1_500, 1),
    ]);
    assert_eq!(
        run.verdicts(),
        vec![unbound(UnboundReason::Capacity)],
        "a second waiting row past the pending bound"
    );
    run.settle();
    assert_eq!(run.verdicts().len(), 1);
    run.read(vec![row_on(d, 9, 1, T, 1_500, 2)]);
    assert_eq!(
        run.verdicts(),
        vec![unbound(UnboundReason::Capacity)],
        "a second ticket past the cookie bound"
    );
    // The pending bound on its own.
    let mut waiting = Run::with_limits(BinderLimits {
        pending: 1,
        cookies: 10,
        exec_tgids: 10,
    });
    let w = waiting.domain;
    waiting.read(vec![
        row_on(w, 7, 1, T, 1_500, 0),
        row_on(w, 8, 1, T, 1_500, 1),
    ]);
    assert_eq!(waiting.verdicts(), vec![unbound(UnboundReason::Capacity)]);
    assert_eq!(waiting.binder.census().pending, 1);
    // An exec the full table cannot remember counts as a loss.
    let x = run.world.admit(T + 1, 1, 1, 3_000);
    run.world.answer(T + 1, 1, d, cookie(d, 7));
    run.drain(&[(T + 2, 1_000), (T + 3, 3_100)]);
    run.read(vec![row(d, 7, 3, T + 1, 3_500)]);
    run.settle();
    assert_eq!(run.verdicts(), vec![unbound(UnboundReason::LifecycleLoss)]);
    let _ = x;
}

#[test]
fn the_census_counts_every_row_once() {
    let mut run = Run::new();
    let d = run.domain;
    let x = run.world.admit(T, 1, 0, 1_000);
    run.world.answer(T, 1, d, cookie(d, 7));
    let mut batch = read_at(
        d,
        vec![
            row_on(d, 7, 1, T, 1_500, 0),
            row_on(d, 5, 1, T + 9, 1_500, 1),
        ],
        900,
        Some(0),
    );
    batch
        .integrity
        .push(crate::attach::capture::WitnessIntegrity {
            key: p11scope_ebpf_common::inventory_callers::CallerObjectKey {
                image: ImageIdentity {
                    task_cookie: 1,
                    exec_id: 1,
                },
                object_id: 0,
                reserved: 0,
            },
            value: None,
            reason: "scripted".into(),
        });
    let World {
        live,
        answers,
        queries,
    } = &mut run.world;
    run.binder
        .absorb_witnesses(&batch, &Lookup(live), &mut AnswerTable { answers, queries });
    assert_eq!(run.binder.census().pending, 2);
    run.settle();
    assert_eq!(
        run.verdicts(),
        vec![bound(x), unbound(UnboundReason::NoLiveCaller)]
    );
    let census = run.binder.census();
    assert_eq!(census.rows, 2);
    assert_eq!(census.bound, 1);
    assert_eq!(census.unbound_total(), 1);
    assert_eq!(census.unbound[&UnboundReason::NoLiveCaller], 1);
    assert_eq!(census.integrity, 1);
    assert_eq!(census.pending, 0);
}

impl Run {
    /// One scan pass that started at `start_ns` and found `callers`
    /// unchanged since their admission.
    fn revalidate(&mut self, start_ns: u64, callers: &[CallerId]) {
        let domain = self.domain;
        self.binder
            .note_revalidation(domain, start_ns, callers.iter().copied().collect());
    }
}

/// C1 (C4 review): the exact interleaving. X is admitted at 100 (foo maps
/// M); T execs bar at 150, before the exec tracepoint is attached, so no
/// record exists; activation at 200; bar calls M at 210 under the same
/// ticket. The cookie query answers C: without the coverage gate the row
/// joined X and cached `(C, E+1) -> X`.
#[test]
fn a_pre_activation_exec_to_another_binary_never_joins() {
    let mut run = Run::covered_from(200);
    let d = run.domain;
    let x = run.world.admit(T, 1, 0, 100);
    run.world.answer(T, 1, d, cookie(d, 7));
    run.read(vec![row_on(d, 7, 2, T, 210, 0)]);
    run.settle();
    assert!(
        run.verdicts().is_empty(),
        "X predates exec coverage: its rows wait for the revalidation pass"
    );
    assert_eq!(run.binder.census().pending, 1);
    assert!(run.binder.revalidation_due(150).is_empty());
    assert_eq!(run.binder.revalidation_due(250), vec![(d, 200)]);
    // Coverage never restarts within a domain: the first report holds.
    run.binder
        .note_exec_coverage(ExecCoverage::scripted(d, 900));
    assert_eq!(run.binder.revalidation_due(250), vec![(d, 200)]);

    // A pass that started before the coverage start proves nothing.
    run.revalidate(150, &[x]);
    run.settle();
    assert!(run.verdicts().is_empty());

    // The qualifying pass saw bar's exe: X failed revalidation (the scan
    // lane retired it as exec'd and admitted bar's incarnation Y).
    run.revalidate(250, &[]);
    assert_eq!(
        run.verdicts(),
        vec![unbound(UnboundReason::ExecCoverageGap)]
    );
    assert!(
        run.binder.revalidation_due(300).is_empty(),
        "first pass only"
    );
    // A later pass never overrides the first one's verdict.
    run.revalidate(260, &[x]);
    run.read(vec![row_on(d, 7, 2, T, 255, 2)]);
    run.settle();
    assert_eq!(
        run.verdicts(),
        vec![unbound(UnboundReason::ExecCoverageGap)]
    );
    run.world.retire(T);
    let y = run.world.admit(T, 1, 1, 250);

    // Nothing was cached for X: the image's next row binds to Y, the
    // incarnation admitted after coverage began.
    run.read(vec![row_on(d, 7, 2, T, 260, 1)]);
    run.settle();
    assert_eq!(run.verdicts(), vec![bound(y)]);
}

/// C1 named boundary: a re-exec of the same binary before activation keeps
/// the pin, start time and exe identity the pass compares, so the image is
/// treated as the same incarnation (as the scan lane already treats it).
/// An exec after the coverage start still splits by exec ID.
#[test]
fn a_same_binary_re_exec_before_activation_is_the_named_boundary() {
    let mut run = Run::covered_from(200);
    let d = run.domain;
    let x = run.world.admit(T, 1, 0, 100);
    run.world.answer(T, 1, d, cookie(d, 7));
    // Exec sequence 2: the unrecorded same-binary re-exec at 150.
    run.read(vec![row_on(d, 7, 2, T, 210, 0)]);
    run.settle();
    run.revalidate(250, &[x]);
    assert_eq!(run.verdicts(), vec![bound(x)]);

    // A recorded re-exec after the coverage start splits.
    run.drain(&[(T, 300)]);
    run.read(vec![row_on(d, 7, 3, T, 310, 1)]);
    run.settle();
    assert_eq!(run.verdicts(), vec![unbound(UnboundReason::ExecTransition)]);
    assert_eq!(run.binder.take_transitions().len(), 1);
}

#[test]
fn an_incarnation_admitted_at_or_after_the_coverage_start_never_waits() {
    let mut run = Run::covered_from(200);
    let d = run.domain;
    let x = run.world.admit(T, 1, 0, 200);
    run.world.answer(T, 1, d, cookie(d, 7));
    run.read(vec![row(d, 7, 1, T, 210)]);
    run.settle();
    assert_eq!(run.verdicts(), vec![bound(x)], "no pass needed");
}

#[test]
fn rows_awaiting_revalidation_or_without_known_coverage_are_coverage_gaps() {
    // The capture ended before any qualifying pass.
    let mut run = Run::covered_from(200);
    let d = run.domain;
    run.world.admit(T, 1, 0, 100);
    run.world.answer(T, 1, d, cookie(d, 7));
    run.read(vec![row(d, 7, 1, T, 210)]);
    run.settle();
    run.binder.finish(d);
    assert_eq!(
        run.verdicts(),
        vec![unbound(UnboundReason::ExecCoverageGap)]
    );

    // A domain whose coverage start was never reported: nothing predating
    // a revalidation is eligible, and no pass can qualify.
    let mut run = Run::new();
    let unknown = NativeDomainId::mint();
    run.world.admit(T, 1, 0, 100);
    run.world.answer(T, 1, unknown, cookie(unknown, 7));
    run.read_domain(unknown, vec![row(unknown, 7, 1, T, 210)], Some(0));
    let at = run.tick();
    run.binder.absorb_lifecycle(&drained(unknown, &[], at));
    run.read_domain(unknown, Vec::new(), Some(0));
    assert_eq!(
        run.verdicts(),
        vec![unbound(UnboundReason::ExecCoverageGap)]
    );
    assert!(
        run.binder
            .revalidation_due(u64::MAX - 1)
            .iter()
            .all(|(domain, _)| *domain != unknown),
        "no pass can qualify without a coverage start"
    );
}

/// M2 (C4 review): `finish` names its domain; another domain's rows keep
/// waiting for their own evidence.
#[test]
fn finish_settles_only_its_own_domain() {
    let mut run = Run::new();
    let d = run.domain;
    let other = NativeDomainId::mint();
    run.binder
        .note_exec_coverage(ExecCoverage::scripted(other, 0));
    let x = run.world.admit(T, 1, 0, 100);
    run.world.answer(T, 1, d, cookie(d, 7));
    run.world.answer(T, 1, other, cookie(other, 7));
    run.read(vec![row(d, 7, 1, T, 210)]);
    run.read_domain(other, vec![row(other, 7, 1, T, 210)], Some(0));
    run.binder.finish(other);
    assert_eq!(
        run.verdicts(),
        vec![unbound(UnboundReason::EvidenceIncomplete)]
    );
    assert_eq!(run.binder.census().pending, 1);
    run.settle();
    assert_eq!(run.verdicts(), vec![bound(x)]);
}

/// M2 (C4 review): evidence is ordered by the facade's stamps, never by
/// call order. A drain or health read that started before the row's read
/// finished covers nothing, whenever it is staged; a quantum tagged with
/// another domain covers nothing here; an unstamped one proves nothing.
#[test]
fn horizons_follow_the_facade_stamps_and_domain_tags() {
    let mut run = Run::new();
    let d = run.domain;
    let x = run.world.admit(T, 1, 0, 100);
    run.world.answer(T, 1, d, cookie(d, 7));
    let before = run.tick();
    run.read(vec![row(d, 7, 1, T, 210)]);
    // Staged after the read, but drained before the read finished.
    run.binder.absorb_lifecycle(&drained(d, &[], before));
    let at = run.tick();
    run.binder
        .absorb_lifecycle(&drained(NativeDomainId::mint(), &[], at));
    run.binder.absorb_lifecycle(&drained(d, &[], u64::MAX));
    run.read(Vec::new());
    assert!(
        run.verdicts().is_empty(),
        "no drain of this domain followed"
    );
    run.drain(&[]);
    assert_eq!(run.verdicts(), vec![bound(x)]);

    // A health read staged late but taken before the row's read finished.
    let mut run = Run::new();
    let d = run.domain;
    let x = run.world.admit(T, 1, 0, 100);
    run.world.answer(T, 1, d, cookie(d, 7));
    let before = run.tick();
    run.read(vec![row(d, 7, 1, T, 210)]);
    run.drain(&[]);
    let stale = read_at(d, Vec::new(), before, Some(0));
    let World {
        live,
        answers,
        queries,
    } = &mut run.world;
    run.binder
        .absorb_witnesses(&stale, &Lookup(live), &mut AnswerTable { answers, queries });
    assert!(
        run.verdicts().is_empty(),
        "the stale health read covers nothing"
    );
    run.read(Vec::new());
    assert_eq!(run.verdicts(), vec![bound(x)]);
}

/// M1 (C4 review): a drain that ended at a busy ring head covers nothing.
#[test]
fn a_drain_that_ended_at_a_busy_head_never_covers_a_read() {
    let mut run = Run::new();
    let d = run.domain;
    let x = run.world.admit(T, 1, 0, 100);
    run.world.answer(T, 1, d, cookie(d, 7));
    run.read(vec![row(d, 7, 1, T, 210)]);
    let mut busy = drained(d, &[], run.tick());
    busy.head_pending = true;
    run.binder.absorb_lifecycle(&busy);
    run.read(Vec::new());
    assert!(run.verdicts().is_empty());
    run.settle();
    assert_eq!(run.verdicts(), vec![bound(x)]);
}
