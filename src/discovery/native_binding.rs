//! SPDX-License-Identifier: GPL-3.0-or-later
//! Native caller binding (Task 6 C4, plan §3.3): conservative, exact or
//! nothing.
//!
//! A `CALLER_USE` witness row names a domain-tagged task cookie `C`, the
//! image's exec sequence `E`, the host tgid `T`, the attach object, and the
//! first association instant `t0`. The row binds to the caller adapter's
//! incarnation `X` only when every rule below holds; otherwise it stays an
//! [`UnboundReason`]-tagged unbound witness (module-level positive use with a
//! named gap), never merged by pid.
//!
//! 1. `X` was the live incarnation for `T` when the row was read, and a
//!    cookie query through `X`'s retained pidfd (live before and after the
//!    lookup) answered.
//! 2. That query answered `C` in the row's own domain. Cookies are lifetime
//!    tickets of one leader task inside one loaded object, never reused
//!    there; [`DomainCookie`] equality includes the domain, so equal ticket
//!    values from two domains never compare equal.
//! 3. `X.first_seen_ns <= t0`.
//! 4. No exec record for `T` was seen at or after `X`'s admission, and no
//!    lifecycle evidence was lost at or after it. The decision waits until
//!    both a complete lifecycle drain and a readable health read started
//!    after the row was read: an exec that preceded the row's insertion was
//!    submitted (or counted lost) before the row existed, so both horizons
//!    cover it. "After" is decided on the facade's CLOCK_MONOTONIC stamps
//!    (`WitnessBatch::rows_read_ns`, `DiscoveryBatch::started_ns`,
//!    `WitnessBatch::health_read_ns`), strictly, never on call order: a
//!    batch staged late or out of order covers only reads it followed. A
//!    drain that ended at a busy ring head (`head_pending`) covers nothing.
//!
//!    Exec records exist only from the domain's exec coverage start
//!    ([`ExecCoverage`], stamped after its roots attached). An incarnation
//!    admitted before that instant could have exec'd unrecorded in between,
//!    so it is eligible only after a scan pass that started at or after the
//!    coverage start revalidated it (same pin, start time and exe identity;
//!    [`NativeBinder::note_revalidation`]). Its rows wait for that pass and
//!    are [`UnboundReason::ExecCoverageGap`] when it fails, retired the
//!    incarnation, or never came. Named boundary: a re-exec of the same
//!    binary before the coverage start keeps every identity the pass
//!    compares, so it stays the same incarnation (as the scan lane already
//!    treats it); execs after the coverage start still split by exec ID.
//! 5. No later exec sequence than `E` was seen for `C`, and `X` is bound to
//!    no other image. (Earlier sequences under `C` are earlier images of the
//!    same task; they cannot be `X`'s image once rules 3 and 4 hold.)
//!
//! Every domain is settled on its own: lifecycle quanta carry the domain
//! the facade drained them from, and `finish` names one domain.
//!
//! A binding is exact for the image `(D, C, E)` and is cached: later rows of
//! that image bind to the same incarnation even after it retired (a row read
//! after exit is still use).
//!
//! A row whose cookie query through `X`'s pidfd answers `C` while `X` is
//! bound to `(C, E')` with `E > E'`, or to another cookie of the same domain,
//! proves `X`'s image ended (a leader exec advances `E` under one ticket; a
//! nonleader exec replaces the leader task under the held pidfd). That is an
//! [`ExecTransition`]: the coordinator retires `X` and mints its successor.
//! The proving row itself stays unbound: the successor is admitted after it.
//!
//! What this does not claim: the `ImageGuard` `Exact` contract (the current
//! exec sequence is never read from userspace), so the mapping lane stays
//! scan-pinned.

use crate::attach::capture::{
    CookieQuery, DiscoveryBatch, DomainCookie, ExecCoverage, InventoryCapture, NativeDomainId,
    RetiredCapture, RetiringCapture, WitnessBatch, WitnessRow,
};
use crate::discovery::caller_registry::{CallerAdapter, CallerId, ProcessSource};
use crate::process::PidPin;
use p11scope_ebpf_common::{DISCOVERY_KIND_EXEC, ImageIdentity};
use std::collections::{BTreeMap, HashMap, HashSet, VecDeque};

/// Where native identity comes from: the owner lane's exact image (the
/// `ImageGuard` contract; `None` everywhere in production) and the cookie
/// queries the binder makes through a caller's retained pin.
pub(crate) trait NativeIdentity<Pin> {
    /// Exact image identity for the native owner lane, or `None` (the
    /// scan lane).
    fn owner_image(&mut self, pid: u32) -> Option<ImageIdentity>;
    /// The `domain` object's ticket for the process `pin` holds. A source
    /// without that domain answers `Unavailable`.
    fn query_cookie(&mut self, domain: NativeDomainId, pin: &Pin) -> CookieQuery;
}

/// The scan lane: no native identity of any kind.
pub(crate) struct ScanOnlyIdentity;

impl<Pin> NativeIdentity<Pin> for ScanOnlyIdentity {
    fn owner_image(&mut self, _: u32) -> Option<ImageIdentity> {
        None
    }

    fn query_cookie(&mut self, _: NativeDomainId, _: &Pin) -> CookieQuery {
        CookieQuery::Unavailable("no native capture runs".into())
    }
}

/// Test seam: the owner lane's scripted exact images, no cookie queries.
#[cfg(test)]
pub(crate) struct OwnerImages(pub fn(u32) -> Option<ImageIdentity>);

#[cfg(test)]
impl<Pin> NativeIdentity<Pin> for OwnerImages {
    fn owner_image(&mut self, pid: u32) -> Option<ImageIdentity> {
        (self.0)(pid)
    }

    fn query_cookie(&mut self, _: NativeDomainId, _: &Pin) -> CookieQuery {
        CookieQuery::Unavailable("scripted owner images only".into())
    }
}

// The capture-facade impls below are C5's; newer compilers see them unused.
#[cfg_attr(not(test), allow(dead_code))]
fn foreign_domain() -> CookieQuery {
    CookieQuery::Unavailable("the cookie query names another native domain".into())
}

impl NativeIdentity<PidPin> for InventoryCapture {
    fn owner_image(&mut self, _: u32) -> Option<ImageIdentity> {
        None
    }

    fn query_cookie(&mut self, domain: NativeDomainId, pin: &PidPin) -> CookieQuery {
        if domain == self.domain() {
            InventoryCapture::query_cookie(self, pin)
        } else {
            foreign_domain()
        }
    }
}

impl NativeIdentity<PidPin> for RetiringCapture {
    fn owner_image(&mut self, _: u32) -> Option<ImageIdentity> {
        None
    }

    fn query_cookie(&mut self, domain: NativeDomainId, pin: &PidPin) -> CookieQuery {
        if domain == self.domain() {
            RetiringCapture::query_cookie(self, pin)
        } else {
            foreign_domain()
        }
    }
}

impl NativeIdentity<PidPin> for RetiredCapture {
    fn owner_image(&mut self, _: u32) -> Option<ImageIdentity> {
        None
    }

    fn query_cookie(&mut self, domain: NativeDomainId, pin: &PidPin) -> CookieQuery {
        if domain == self.domain() {
            RetiredCapture::query_cookie(self, pin)
        } else {
            foreign_domain()
        }
    }
}

/// The adapter's live incarnation for one pid, as the binder sees it.
pub(crate) struct LiveCaller<'a, Pin> {
    pub id: CallerId,
    pub first_seen_ns: u64,
    pub pin: &'a Pin,
}

/// The live-incarnation lookup the binder reads (the caller adapter).
pub(crate) trait CallerLookup<Pin> {
    fn live_caller(&self, pid: u32) -> Option<LiveCaller<'_, Pin>>;
}

impl<Source: ProcessSource> CallerLookup<Source::Pin> for CallerAdapter<Source> {
    fn live_caller(&self, pid: u32) -> Option<LiveCaller<'_, Source::Pin>> {
        let (record, pin) = self.live_pin(pid)?;
        Some(LiveCaller {
            id: record.id,
            first_seen_ns: record.first_seen_ns,
            pin,
        })
    }
}

/// A current-image query for an already historically bound image.
#[derive(Clone, Copy)]
pub(crate) struct CurrentBindingRequest {
    pub caller: CallerId,
    pub pid: u32,
    pub image: DomainCookie,
    pub exec_id: u64,
}

#[derive(Clone, Copy)]
pub(crate) struct CurrentBindingSighting {
    request: CurrentBindingRequest,
    first_seen_ns: u64,
    sighted_ns: u64,
}

impl CurrentBindingSighting {
    pub(crate) fn sighted_ns(&self) -> u64 {
        self.sighted_ns
    }
}

#[derive(Clone, Copy)]
pub(crate) enum CurrentBindingCheck {
    Pending,
    Proven,
    Rejected(UnboundReason),
}

/// Why one witness row stays unbound. The order is the census order.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub(crate) enum UnboundReason {
    /// No live incarnation held the row's tgid when it was read (the
    /// process exited before the poll, or was never admitted).
    NoLiveCaller,
    /// The pinned process exited before or during the cookie query.
    CallerExited,
    /// The cookie query could not be made (no such domain, a lookup error).
    CookieUnavailable,
    /// The pinned process holds another ticket or none: a reused pid, a
    /// nonleader exec, or another process under that pid number.
    CookieMismatch,
    /// The row was recorded before the incarnation was admitted.
    BeforeAdmission,
    /// An exec of the tgid was seen at or after the incarnation's admission.
    ExecAfterAdmission,
    /// Lifecycle evidence (an exec record) may have been lost at or after
    /// the incarnation's admission.
    LifecycleLoss,
    /// Several images of one ticket compete for the incarnation.
    ExecAmbiguous,
    /// The row proved its incarnation's image ended; the successor was
    /// admitted after the row.
    ExecTransition,
    /// The incarnation was admitted before the domain's exec coverage began
    /// and no scan pass after it revalidated the incarnation (it exec'd,
    /// retired, or the pass never came).
    ExecCoverageGap,
    /// The row's lifecycle or health horizon never arrived (capture ended).
    EvidenceIncomplete,
    /// A binder table bound was reached.
    Capacity,
}

impl UnboundReason {
    /// Stable machine code (JSON census and module `unbound_use`).
    pub(crate) const fn code(self) -> &'static str {
        match self {
            Self::NoLiveCaller => "no_live_caller",
            Self::CallerExited => "caller_exited",
            Self::CookieUnavailable => "cookie_unavailable",
            Self::CookieMismatch => "cookie_mismatch",
            Self::BeforeAdmission => "before_admission",
            Self::ExecAfterAdmission => "exec_after_admission",
            Self::LifecycleLoss => "lifecycle_loss",
            Self::ExecAmbiguous => "exec_ambiguous",
            Self::ExecTransition => "exec_transition",
            Self::ExecCoverageGap => "exec_coverage_gap",
            Self::EvidenceIncomplete => "evidence_incomplete",
            Self::Capacity => "capacity",
        }
    }

    /// Human wording for gaps.
    pub(crate) const fn text(self) -> &'static str {
        match self {
            Self::NoLiveCaller => "no live caller incarnation held the tgid when the row was read",
            Self::CallerExited => "the pinned caller exited before its cookie could be queried",
            Self::CookieUnavailable => "the native cookie query was unavailable",
            Self::CookieMismatch => {
                "the pinned caller holds another task cookie (pid reuse or nonleader exec)"
            }
            Self::BeforeAdmission => "the row predates the caller incarnation's admission",
            Self::ExecAfterAdmission => "an exec of the tgid was seen after the admission",
            Self::LifecycleLoss => "lifecycle evidence was lost after the admission",
            Self::ExecAmbiguous => "several images of one task cookie compete",
            Self::ExecTransition => "the row proved an exec; its successor was admitted later",
            Self::ExecCoverageGap => {
                "the caller predates exec coverage and no later scan revalidated it"
            }
            Self::EvidenceIncomplete => "the lifecycle or health horizon after the read never came",
            Self::Capacity => "a native binder table bound was reached",
        }
    }
}

/// One row's verdict.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Binding {
    Bound(CallerId),
    Unbound(UnboundReason),
}

/// One decided witness row.
#[derive(Debug, Clone)]
pub(crate) struct Decision {
    pub row: WitnessRow,
    pub binding: Binding,
}

/// Proof that one incarnation's image ended, seen natively: under the
/// incarnation's held pidfd its bound ticket answered a later exec sequence,
/// or the leader task changed. Only the binder constructs it (private
/// fields), so `ExecProof` built from it can only come from here.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct ExecTransition {
    caller: CallerId,
    pid: u32,
    old: (DomainCookie, u64),
    new: (DomainCookie, u64),
}

impl ExecTransition {
    /// The incarnation whose image ended.
    pub(crate) fn caller(&self) -> CallerId {
        self.caller
    }

    pub(crate) fn pid(&self) -> u32 {
        self.pid
    }

    /// The ended image (ticket, exec sequence).
    #[cfg_attr(not(test), allow(dead_code))] // ExecProof carries it.
    pub(crate) fn old(&self) -> (DomainCookie, u64) {
        self.old
    }

    /// The image that replaced it.
    #[cfg_attr(not(test), allow(dead_code))] // ExecProof carries it.
    pub(crate) fn new_image(&self) -> (DomainCookie, u64) {
        self.new
    }
}

/// The unbound-witness measurement (DR-05): every witness row the binder
/// saw, how it was decided, and what still waits.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub(crate) struct BindingCensus {
    pub rows: u64,
    pub bound: u64,
    pub unbound: BTreeMap<UnboundReason, u64>,
    pub pending: u64,
    /// Rows that failed facade validation (never offered to the binder).
    pub integrity: u64,
}

impl BindingCensus {
    pub(crate) fn unbound_total(&self) -> u64 {
        self.unbound.values().sum()
    }
}

/// Table bounds. Every bound reached is a counted `Capacity` verdict (or a
/// lifecycle loss for the exec table), never silent.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct BinderLimits {
    /// Rows waiting for their horizons, per domain.
    pub pending: usize,
    /// Distinct tickets, per domain.
    pub cookies: usize,
    /// Distinct tgids with a remembered exec instant, per domain.
    pub exec_tgids: usize,
}

/// The default bound: the caller-pair default `P` (a domain never holds
/// more distinct rows than its `CALLER_USE` capacity).
pub(crate) const DEFAULT_BINDER_LIMIT: usize = 65_536;

impl Default for BinderLimits {
    fn default() -> Self {
        Self {
            pending: DEFAULT_BINDER_LIMIT,
            cookies: DEFAULT_BINDER_LIMIT,
            exec_tgids: DEFAULT_BINDER_LIMIT,
        }
    }
}

/// What the cookie query said when the row was read, through the live
/// incarnation's pin.
#[derive(Debug, Clone)]
struct Sighting {
    caller: CallerId,
    first_seen_ns: u64,
    query: CookieQuery,
}

#[derive(Debug)]
struct Pending {
    row: WitnessRow,
    /// When the row's read finished (`None`: unstamped, never covered).
    read_ns: Option<u64>,
    sighting: Option<Sighting>,
}

/// A facade stamp, or `None` when the clock read failed (`u64::MAX`): an
/// unstamped batch never proves an ordering.
fn stamp(ns: u64) -> Option<u64> {
    (ns != u64::MAX).then_some(ns)
}

/// One native domain's binding state.
struct DomainState {
    domain: NativeDomainId,
    finished: bool,
    /// Start of the latest complete lifecycle drain.
    lifecycle_ns: Option<u64>,
    /// Start of the latest readable health read.
    health_ns: Option<u64>,
    /// Where exec coverage began (`None`: not reported, nothing predating
    /// a revalidation is eligible).
    coverage_ns: Option<u64>,
    /// The incarnations the first scan pass started at or after
    /// `coverage_ns` revalidated (`None`: no such pass yet).
    revalidated: Option<HashSet<CallerId>>,
    ring_loss: u64,
    malformed: u64,
    /// Latest instant at which lifecycle evidence may have been lost.
    loss_ns: Option<u64>,
    /// Latest exec record instant per tgid.
    exec_ns: HashMap<u32, u64>,
    pending: VecDeque<Pending>,
    /// Exec sequences seen per ticket.
    cookies: HashMap<DomainCookie, BTreeMap<u64, ExecSeen>>,
    /// The image each incarnation is bound to in this domain.
    callers: HashMap<CallerId, (DomainCookie, u64)>,
    /// Incarnations whose image already ended (a transition was emitted).
    ended: HashSet<CallerId>,
}

/// One exec sequence of one ticket: who holds it, and its latest row.
#[derive(Debug, Clone, Copy, Default)]
struct ExecSeen {
    bound: Option<CallerId>,
    last_t0_ns: u64,
}

impl DomainState {
    fn new(domain: NativeDomainId) -> Self {
        Self {
            domain,
            finished: false,
            lifecycle_ns: None,
            health_ns: None,
            coverage_ns: None,
            revalidated: None,
            ring_loss: 0,
            malformed: 0,
            loss_ns: None,
            exec_ns: HashMap::new(),
            pending: VecDeque::new(),
            cookies: HashMap::new(),
            callers: HashMap::new(),
            ended: HashSet::new(),
        }
    }

    fn note_loss(&mut self, at_ns: u64) {
        self.loss_ns = Some(self.loss_ns.map_or(at_ns, |was| was.max(at_ns)));
    }

    /// Both horizons started strictly after the row's read finished.
    fn horizons_cover(&self, pending: &Pending) -> bool {
        pending.read_ns.is_some_and(|read_ns| {
            self.lifecycle_ns.is_some_and(|ns| ns > read_ns)
                && self.health_ns.is_some_and(|ns| ns > read_ns)
        })
    }

    /// The sighted incarnation predates exec coverage: it is eligible only
    /// through a revalidation (unknown coverage: never).
    fn predates_coverage(&self, first_seen_ns: u64) -> bool {
        self.coverage_ns.is_none_or(|start| first_seen_ns < start)
    }

    /// The row waits for the revalidation pass: its incarnation predates a
    /// known coverage start and no qualifying pass has run.
    fn awaits_revalidation(&self, pending: &Pending) -> bool {
        self.coverage_ns.is_some()
            && self.revalidated.is_none()
            && pending
                .sighting
                .as_ref()
                .is_some_and(|sighting| self.predates_coverage(sighting.first_seen_ns))
    }
}

/// The binder: per-domain state, decisions and transitions for the
/// coordinator to stage, and the census.
pub(crate) struct NativeBinder {
    limits: BinderLimits,
    domains: Vec<DomainState>,
    domain_indices: HashMap<NativeDomainId, usize>,
    decided: Vec<Decision>,
    transitions: Vec<ExecTransition>,
    census: BindingCensus,
    #[cfg(test)]
    current_binding_clock: Option<fn() -> Option<u64>>,
}

impl NativeBinder {
    pub(crate) fn new(limits: BinderLimits) -> Self {
        Self {
            limits,
            domains: Vec::new(),
            domain_indices: HashMap::new(),
            decided: Vec::new(),
            transitions: Vec::new(),
            census: BindingCensus::default(),
            #[cfg(test)]
            current_binding_clock: None,
        }
    }

    pub(crate) fn census(&self) -> &BindingCensus {
        &self.census
    }

    /// Every row still waiting for its decision, across domains (read
    /// order within a domain). The presentation overlay matches these
    /// against watched edges; a row's ambiguity is its presence here, not
    /// its sighting, so only the row is exposed.
    pub(crate) fn pending_rows(&self) -> impl Iterator<Item = &WitnessRow> + '_ {
        self.domains
            .iter()
            .flat_map(|state| state.pending.iter().map(|pending| &pending.row))
    }

    /// A stamped row still waits: its read finished with a usable clock,
    /// so its horizons may still arrive and it may still decide. An
    /// unstamped row (`rows_read_ns` failed) never decides before the
    /// finish flush, so it never stalls the proven-clean instant.
    pub(crate) fn has_stamped_pending(&self) -> bool {
        self.domains.iter().any(|state| {
            state
                .pending
                .iter()
                .any(|pending| pending.read_ns.is_some())
        })
    }

    /// Decisions made since the last take, in decision order.
    pub(crate) fn take_decisions(&mut self) -> Vec<Decision> {
        std::mem::take(&mut self.decided)
    }

    /// Image transitions proven since the last take.
    pub(crate) fn take_transitions(&mut self) -> Vec<ExecTransition> {
        std::mem::take(&mut self.transitions)
    }

    fn domain_index(&mut self, domain: NativeDomainId) -> usize {
        match self.domain_indices.get(&domain).copied() {
            Some(index) => index,
            None => {
                let index = self.domains.len();
                self.domains.push(DomainState::new(domain));
                self.domain_indices.insert(domain, index);
                index
            }
        }
    }

    /// Where `coverage`'s domain began recording execs (the facade's
    /// activation stamp). The first report wins: coverage never restarts
    /// later within one domain.
    pub(crate) fn note_exec_coverage(&mut self, coverage: ExecCoverage) {
        let index = self.domain_index(coverage.domain());
        let state = &mut self.domains[index];
        if state.coverage_ns.is_none() {
            state.coverage_ns = Some(coverage.start_ns());
        }
        self.decide_ready(index);
    }

    /// Domains whose revalidation pass is due for a scan pass that started
    /// at `pass_start_ns`: coverage known, started no later than the pass,
    /// and not yet revalidated. Each with its coverage start (the admission
    /// cutoff the pass revalidates below).
    pub(crate) fn revalidation_due(&self, pass_start_ns: u64) -> Vec<(NativeDomainId, u64)> {
        self.domains
            .iter()
            .filter(|state| state.revalidated.is_none())
            .filter_map(|state| {
                let start = state.coverage_ns?;
                (start <= pass_start_ns).then_some((state.domain, start))
            })
            .collect()
    }

    /// The revalidation pass of `domain`: `revalidated` are the
    /// incarnations admitted before its coverage start that a scan pass
    /// started at `pass_start_ns` found unchanged (same pin, start time and
    /// exe identity). Ignored unless that pass started at or after the
    /// coverage start; only the first qualifying pass counts.
    pub(crate) fn note_revalidation(
        &mut self,
        domain: NativeDomainId,
        pass_start_ns: u64,
        revalidated: HashSet<CallerId>,
    ) {
        let Some(index) = self.domains.iter().position(|state| state.domain == domain) else {
            return;
        };
        let state = &mut self.domains[index];
        if state.revalidated.is_some()
            || state.coverage_ns.is_none_or(|start| pass_start_ns < start)
        {
            return;
        }
        state.revalidated = Some(revalidated);
        self.decide_ready(index);
    }

    /// One lifecycle quantum, in the domain the facade drained it from. A
    /// drain that emptied the ring (no bound, deadline, failure, or busy
    /// head) covers every read that finished before it started; a failed
    /// record is dated at the quantum's end.
    pub(crate) fn absorb_lifecycle(&mut self, batch: &DiscoveryBatch) {
        let index = self.domain_index(batch.domain);
        let limit = self.limits.exec_tgids;
        let state = &mut self.domains[index];
        for record in &batch.records {
            if record.kind != DISCOVERY_KIND_EXEC {
                continue;
            }
            let tgid = (record.pid_tgid >> 32) as u32;
            let ts = record.hook_ts_ns;
            if !state.exec_ns.contains_key(&tgid) && state.exec_ns.len() >= limit {
                // An exec the table cannot remember is a lost record.
                state.note_loss(ts);
                continue;
            }
            let latest = state.exec_ns.entry(tgid).or_insert(ts);
            *latest = (*latest).max(ts);
        }
        if batch.failure.is_some() {
            state.note_loss(batch.finished_ns);
        }
        if batch.drained()
            && let Some(started) = stamp(batch.started_ns)
        {
            state.lifecycle_ns = Some(state.lifecycle_ns.map_or(started, |was| was.max(started)));
        }
        self.decide_ready(index);
    }

    /// One witness read: its health (read before its rows) covers earlier
    /// reads; each row is decided at once from a cached exact image, or
    /// sighted (live incarnation plus cookie query, now) and decided once
    /// both horizons cover its read.
    pub(crate) fn absorb_witnesses<Pin>(
        &mut self,
        batch: &WitnessBatch,
        lookup: &dyn CallerLookup<Pin>,
        identity: &mut dyn NativeIdentity<Pin>,
    ) {
        let index = self.domain_index(batch.domain);
        let limits = self.limits;
        let state = &mut self.domains[index];
        if let Some(counters) = batch.health.discovery_counters {
            if crate::attach::capture::ring_loss_rose(state.ring_loss, Some(counters)).is_some()
                || batch.health.malformed_discovery > state.malformed
            {
                state.note_loss(batch.health_read_ns);
            }
            state.ring_loss = state.ring_loss.max(counters[0]);
            state.malformed = state.malformed.max(batch.health.malformed_discovery);
            if let Some(read) = stamp(batch.health_read_ns) {
                state.health_ns = Some(state.health_ns.map_or(read, |was| was.max(read)));
            }
        }
        let read_ns = stamp(batch.rows_read_ns);
        self.census.integrity += batch.integrity.len() as u64;
        for row in &batch.rows {
            self.census.rows += 1;
            let state = &mut self.domains[index];
            let cookie = row.cookie();
            if let Some(caller) = state
                .cookies
                .get(&cookie)
                .and_then(|execs| execs.get(&row.exec_id()))
                .and_then(|seen| seen.bound)
            {
                self.record(row.clone(), Binding::Bound(caller));
                continue;
            }
            if !state.cookies.contains_key(&cookie) && state.cookies.len() >= limits.cookies
                || state.pending.len() >= limits.pending
            {
                self.record(row.clone(), Binding::Unbound(UnboundReason::Capacity));
                continue;
            }
            let seen = state
                .cookies
                .entry(cookie)
                .or_default()
                .entry(row.exec_id())
                .or_default();
            seen.last_t0_ns = seen.last_t0_ns.max(row.recorded_at_ns);
            let sighting = lookup.live_caller(row.host_tgid).map(|caller| Sighting {
                caller: caller.id,
                first_seen_ns: caller.first_seen_ns,
                query: identity.query_cookie(row.domain, caller.pin),
            });
            state.pending.push_back(Pending {
                row: row.clone(),
                read_ns,
                sighting,
            });
            self.census.pending += 1;
        }
        self.decide_ready(index);
    }

    #[cfg(test)]
    pub(crate) fn set_current_binding_clock(&mut self, clock: fn() -> Option<u64>) {
        self.current_binding_clock = Some(clock);
    }

    pub(crate) fn domain_active(&self, domain: NativeDomainId) -> bool {
        self.domain_indices
            .get(&domain)
            .is_some_and(|index| !self.domains[*index].finished)
    }

    pub(crate) fn sight_current_binding<Pin>(
        &self,
        request: CurrentBindingRequest,
        lookup: &dyn CallerLookup<Pin>,
        identity: &mut dyn NativeIdentity<Pin>,
    ) -> Result<CurrentBindingSighting, UnboundReason> {
        #[cfg(test)]
        let clock = self
            .current_binding_clock
            .unwrap_or(crate::attach::monotonic_ns);
        #[cfg(not(test))]
        let clock = crate::attach::monotonic_ns;
        self.sight_current_binding_at(request, lookup, identity, || clock().and_then(stamp))
    }

    fn sight_current_binding_at<Pin>(
        &self,
        request: CurrentBindingRequest,
        lookup: &dyn CallerLookup<Pin>,
        identity: &mut dyn NativeIdentity<Pin>,
        clock: impl FnOnce() -> Option<u64>,
    ) -> Result<CurrentBindingSighting, UnboundReason> {
        let state = self
            .domain_indices
            .get(&request.image.domain())
            .map(|index| &self.domains[*index])
            .ok_or(UnboundReason::EvidenceIncomplete)?;
        if state.finished {
            return Err(UnboundReason::EvidenceIncomplete);
        }
        if state.ended.contains(&request.caller) {
            return Err(UnboundReason::ExecTransition);
        }
        if state.callers.get(&request.caller) != Some(&(request.image, request.exec_id)) {
            return Err(UnboundReason::ExecAmbiguous);
        }
        let caller = lookup
            .live_caller(request.pid)
            .filter(|caller| caller.id == request.caller)
            .ok_or(UnboundReason::NoLiveCaller)?;
        let query = identity.query_cookie(request.image.domain(), caller.pin);
        // Query completion, never the caller's pass-start or an old witness stamp.
        let sighted_ns = clock()
            .filter(|ns| *ns > 0)
            .ok_or(UnboundReason::EvidenceIncomplete)?;
        match query {
            CookieQuery::Cookie(answered) if answered == request.image => {}
            CookieQuery::Cookie(_) | CookieQuery::NoCookie => {
                return Err(UnboundReason::CookieMismatch);
            }
            CookieQuery::Exited => return Err(UnboundReason::CallerExited),
            CookieQuery::Unavailable(_) => return Err(UnboundReason::CookieUnavailable),
        }
        if sighted_ns < caller.first_seen_ns {
            return Err(UnboundReason::BeforeAdmission);
        }
        let sighting = CurrentBindingSighting {
            request,
            first_seen_ns: caller.first_seen_ns,
            sighted_ns,
        };
        if let CurrentBindingCheck::Rejected(reason) = self.check_current_binding(&sighting) {
            return Err(reason);
        }
        Ok(sighting)
    }

    pub(crate) fn check_current_binding(
        &self,
        sighting: &CurrentBindingSighting,
    ) -> CurrentBindingCheck {
        let request = sighting.request;
        let Some(state) = self
            .domain_indices
            .get(&request.image.domain())
            .map(|index| &self.domains[*index])
        else {
            return CurrentBindingCheck::Rejected(UnboundReason::EvidenceIncomplete);
        };
        let rejected = if state.finished {
            Some(UnboundReason::EvidenceIncomplete)
        } else if state.ended.contains(&request.caller) {
            Some(UnboundReason::ExecTransition)
        } else if state.callers.get(&request.caller) != Some(&(request.image, request.exec_id)) {
            Some(UnboundReason::ExecAmbiguous)
        } else if state
            .exec_ns
            .get(&request.pid)
            .is_some_and(|ns| *ns >= sighting.first_seen_ns)
        {
            Some(UnboundReason::ExecAfterAdmission)
        } else if state.loss_ns.is_some_and(|ns| ns >= sighting.first_seen_ns) {
            Some(UnboundReason::LifecycleLoss)
        } else if state.predates_coverage(sighting.first_seen_ns)
            && state
                .revalidated
                .as_ref()
                .is_none_or(|ids| !ids.contains(&request.caller))
        {
            Some(UnboundReason::ExecCoverageGap)
        } else if state.cookies.get(&request.image).is_none_or(|execs| {
            execs
                .keys()
                .next_back()
                .is_none_or(|exec| *exec != request.exec_id)
        }) {
            Some(UnboundReason::ExecAmbiguous)
        } else {
            None
        };
        if let Some(reason) = rejected {
            return CurrentBindingCheck::Rejected(reason);
        }
        if state
            .lifecycle_ns
            .is_some_and(|ns| ns > sighting.sighted_ns)
            && state.health_ns.is_some_and(|ns| ns > sighting.sighted_ns)
        {
            CurrentBindingCheck::Proven
        } else {
            CurrentBindingCheck::Pending
        }
    }

    /// No later evidence will arrive for `domain` (its capture retired):
    /// every row of that domain still waiting is unbound. Other domains
    /// are untouched.
    pub(crate) fn finish(&mut self, domain: NativeDomainId) {
        let index = self.domain_index(domain);
        self.domains[index].finished = true;
        while let Some(pending) = self.domains[index].pending.pop_front() {
            self.census.pending -= 1;
            let reason = if self.domains[index].awaits_revalidation(&pending) {
                UnboundReason::ExecCoverageGap
            } else {
                UnboundReason::EvidenceIncomplete
            };
            self.record(pending.row, Binding::Unbound(reason));
        }
    }

    fn record(&mut self, row: WitnessRow, binding: Binding) {
        match binding {
            Binding::Bound(_) => self.census.bound += 1,
            Binding::Unbound(reason) => *self.census.unbound.entry(reason).or_default() += 1,
        }
        self.decided.push(Decision { row, binding });
    }

    fn decide_ready(&mut self, index: usize) {
        loop {
            let state = &mut self.domains[index];
            if state.pending.front().is_none_or(|pending| {
                !state.horizons_cover(pending) || state.awaits_revalidation(pending)
            }) {
                return;
            }
            let pending = state.pending.pop_front().expect("checked front");
            self.census.pending -= 1;
            let binding = decide(state, &pending, &mut self.transitions);
            self.record(pending.row, binding);
        }
    }
}

/// The §3.3 rules for one sighted row whose horizons arrived (module doc).
fn decide(
    state: &mut DomainState,
    pending: &Pending,
    transitions: &mut Vec<ExecTransition>,
) -> Binding {
    let row = &pending.row;
    let cookie = row.cookie();
    let exec = row.exec_id();
    // An image bound while this row waited is exact for it too.
    if let Some(caller) = state
        .cookies
        .get(&cookie)
        .and_then(|execs| execs.get(&exec))
        .and_then(|seen| seen.bound)
    {
        return Binding::Bound(caller);
    }
    // Rule 1: a live incarnation answered through its held pidfd.
    let Some(sighting) = &pending.sighting else {
        return Binding::Unbound(UnboundReason::NoLiveCaller);
    };
    let answered = match &sighting.query {
        CookieQuery::Cookie(answered) => *answered,
        CookieQuery::NoCookie => return Binding::Unbound(UnboundReason::CookieMismatch),
        CookieQuery::Exited => return Binding::Unbound(UnboundReason::CallerExited),
        CookieQuery::Unavailable(_) => return Binding::Unbound(UnboundReason::CookieUnavailable),
    };
    // Rule 2: the same ticket of the same domain (equality includes the
    // domain: equal values from two domains are different tickets).
    if answered != cookie {
        return Binding::Unbound(UnboundReason::CookieMismatch);
    }
    let caller = sighting.caller;
    // The incarnation already holds an image here: this row is not it. Under
    // the held pidfd a later sequence of the same ticket, or another ticket,
    // proves that image ended.
    if let Some(&(held, held_exec)) = state.callers.get(&caller) {
        let ended = held != cookie || exec > held_exec;
        if ended && state.ended.insert(caller) {
            transitions.push(ExecTransition {
                caller,
                pid: row.host_tgid,
                old: (held, held_exec),
                new: (cookie, exec),
            });
        }
        return Binding::Unbound(if ended {
            UnboundReason::ExecTransition
        } else {
            UnboundReason::ExecAmbiguous
        });
    }
    // Rule 3: never a row recorded before the admission.
    if row.recorded_at_ns < sighting.first_seen_ns {
        return Binding::Unbound(UnboundReason::BeforeAdmission);
    }
    // Rule 4, coverage: an incarnation admitted before exec coverage began
    // may have exec'd unrecorded; only the revalidation pass makes it
    // eligible (the row waited for that pass in `decide_ready`).
    if state.predates_coverage(sighting.first_seen_ns)
        && !state
            .revalidated
            .as_ref()
            .is_some_and(|revalidated| revalidated.contains(&caller))
    {
        return Binding::Unbound(UnboundReason::ExecCoverageGap);
    }
    // Rule 4: no exec of the tgid, and no lost lifecycle evidence, at or
    // after the admission (both horizons cover the row's insertion).
    if state
        .exec_ns
        .get(&row.host_tgid)
        .is_some_and(|&exec_ns| exec_ns >= sighting.first_seen_ns)
    {
        return Binding::Unbound(UnboundReason::ExecAfterAdmission);
    }
    if state
        .loss_ns
        .is_some_and(|loss_ns| loss_ns >= sighting.first_seen_ns)
    {
        return Binding::Unbound(UnboundReason::LifecycleLoss);
    }
    // Rule 5: no competing image of the ticket. A later sequence always
    // competes; an earlier one competes unless another incarnation holds it
    // (this one holds none: the branch above returned) or all its rows
    // predate this admission.
    let competing = state.cookies.get(&cookie).is_some_and(|execs| {
        execs.iter().any(|(&other, seen)| {
            other != exec
                && (other > exec
                    || seen.bound.is_none() && seen.last_t0_ns >= sighting.first_seen_ns)
        })
    });
    if competing {
        return Binding::Unbound(UnboundReason::ExecAmbiguous);
    }
    state
        .cookies
        .entry(cookie)
        .or_default()
        .entry(exec)
        .or_default()
        .bound = Some(caller);
    state.callers.insert(caller, (cookie, exec));
    Binding::Bound(caller)
}

#[cfg(test)]
#[path = "native_binding_tests.rs"]
mod tests;
