//! SPDX-License-Identifier: GPL-3.0-or-later
//! Per-edge semantic reducer (S1): mechanism/operation context.
//!
//! One [`EdgeSemantics`] per inventory edge turns that edge's completed
//! API calls — from the EXISTING trusted-slot mechanism path, no new
//! capture — into mechanism labels, operation categories, last
//! activity, and evidence provenance. Raw session handles live only in
//! the in-memory maps below; the published projection
//! ([`EdgeProjection`]) carries per-edge aggregates only, never a
//! handle.
//!
//! No divergent computation: descriptors resolve through
//! [`kinds::descriptor`](crate::kinds::descriptor) (the same function
//! the plan path uses), operation categories through
//! [`semantics::operation_name`](crate::semantics::operation_name) /
//! [`semantics::direct_name`](crate::semantics::direct_name), cancel
//! flags through
//! [`semantics::cancel_operation_mask`](crate::semantics::cancel_operation_mask),
//! and every transition/lifecycle rule below mirrors the capture-wide
//! reducer (`semantics::State`) — including its conservative corners
//! (cancel-on-`OPERATION_CANCEL_FAILED`, login clearing the slot's
//! operations, pending surviving close). Where S1 deliberately differs
//! (per-edge bounds refuse instead of capture-wide admit, async ids
//! need no cross-process tombstone inside one edge), the code says so.
//!
//! Keying: state is per edge — (caller incarnation, module instance)
//! — and, inside the edge, per raw session handle plus operation bit.
//! An `Init` on session A plus an `Update` on session B never joins;
//! identical numeric handles on different edges, or on successive
//! incarnations of one pid, live in different maps and cannot merge.
//! Fork-inherited sessions read as unknown-origin on the child's edge
//! (no cross-edge copying — that is S2 scope), never as invented
//! operations.
//!
//! Deliberate differences from the capture-wide reducer (fix round
//! 1): (F2) async records bind to their ORIGINATING operation
//! lifetime — the capture-wide `complete_pending` replays against
//! current bindings, so a completion can finish an unrelated
//! replacement operation; here a completion whose affected bits no
//! longer hold the queue-time machine generation orphans instead of
//! joining. (F5) a trusted OK `*Init` with an unreadable mechanism
//! still starts its operation (mechanism unknown) under A1, where the
//! capture-wide reducer drops the binding.

use crate::semantics::{cancel_operation_mask, direct_cancel_flag};
use p11scope_ebpf_common::{
    FUNCTION_NONE, SESSION_NONE, SlotSemantics, USER_TYPE_NONE, capture, direct, lifecycle,
    semantic_flags, transition,
};
use pkcs11_types::CkRv;
use std::collections::{BTreeMap, BTreeSet};

/// Per-edge bounds. New keys past a bound are REFUSED (counted in
/// [`EdgeProjection::dropped`] and the registry's `semantic_refused`),
/// never evicting retained facts — the inventory rule that refusal
/// never erases retained evidence. Pending/detached async records are
/// the one exception: like the capture-wide reducer they evict oldest
/// past the bound, counted in `async_evictions`.
pub(crate) const MAX_EDGE_SESSIONS: usize = 1024;
pub(crate) const MAX_EDGE_MECHANISMS: usize = 256;
pub(crate) const MAX_EDGE_ACTIVE_OPS: usize = 2048;
pub(crate) const MAX_EDGE_PENDING: usize = 256;
pub(crate) const MAX_EDGE_PROVENANCE_FUNCTIONS: usize = 64;
pub(crate) const MAX_EDGE_PROVENANCE_RETURNS: usize = 32;

/// One completed API call's semantic facts, as the feed boundary
/// observed them. Every field below already exists in the trusted
/// capture path (`Event` + the producing slot's effective semantics);
/// the boundary copies, never invents.
#[derive(Clone)]
pub(crate) struct SemanticCall {
    /// Verbatim function name — provenance and the
    /// [`kinds::descriptor`](crate::kinds::descriptor) lookup key.
    pub function: String,
    /// Verbatim return code.
    pub rv: u64,
    /// Raw session handle (`SESSION_NONE` when the call names none).
    /// Internal only: never serialized.
    pub session: u64,
    /// Verbatim mechanism id (meaningful per `capture` bits).
    pub mechanism: u64,
    /// Mechanism + output capture bits (`capture::*` vocabulary).
    pub capture: u32,
    /// PKCS#11 slot id (async-id namespace dimension).
    pub slot_id: u64,
    /// Async target function id (`FUNCTION_NONE` when none).
    pub target_function: u32,
    /// Async id value (for `C_AsyncGetID` / `C_AsyncJoin`).
    pub async_value: u64,
    /// `C_SessionCancel` flags (0 otherwise).
    pub flags: u64,
    /// Login user type (`USER_TYPE_NONE` when none): a context-specific
    /// `C_Login` must not clear the slot's operations.
    pub user_type: u32,
    /// The producing module is semantically authoritative.
    pub authorized: bool,
    /// The producing descriptor is unambiguous (not aliased/ambiguous).
    pub unambiguous: bool,
    /// The effective slot semantics were forced `COUNT_ONLY`.
    pub count_only: bool,
    /// The call attributes to exactly one module instance. The
    /// registry clears this on same-file double-loaded edges (F7b),
    /// where two instances share every file identity and no call can
    /// name its instance.
    pub attributable: bool,
    /// Observation time (the edge's clock, nanoseconds).
    pub ts_ns: u64,
}

impl std::fmt::Debug for SemanticCall {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("SemanticCall(<private facts>)")
    }
}

impl Default for SemanticCall {
    fn default() -> Self {
        Self {
            function: String::new(),
            rv: CkRv::OK.0,
            session: SESSION_NONE,
            mechanism: 0,
            capture: capture::MECHANISM_NONE | capture::OUTPUT_NONE,
            slot_id: 0,
            target_function: FUNCTION_NONE,
            async_value: 0,
            flags: 0,
            user_type: USER_TYPE_NONE,
            authorized: true,
            unambiguous: true,
            count_only: false,
            attributable: true,
            ts_ns: 0,
        }
    }
}

impl SemanticCall {
    /// The mechanism capture on this call (`capture::MECHANISM_*`).
    fn mechanism_capture(&self) -> u32 {
        self.capture & capture::MECHANISM_MASK
    }
}

/// One tracked operation's live state: initialized by an `*Init` OK,
/// in progress once an `*Update`/`*Final`/multipart call advanced it.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub(crate) enum OpState {
    Initialized,
    InProgress,
}

impl OpState {
    pub(crate) const fn label(self) -> &'static str {
        match self {
            Self::Initialized => "initialized",
            Self::InProgress => "in_progress",
        }
    }
}

#[derive(Debug, Clone)]
struct OpMachine {
    /// The bound mechanism id, or `None` when a trusted OK `*Init`
    /// carried no usable mechanism (F5): the operation is tracked —
    /// category and initialized state are established by the OK
    /// return — but no mechanism is ever attributed or named.
    mechanism: Option<u64>,
    state: OpState,
    /// Edge-wide unique lifetime id from [`EdgeSemantics::machine_seq`]:
    /// no two machines — live or dead — share one, so an async
    /// record's captured generation identifies its originating
    /// machine exactly, across sessions (F2).
    generation: u64,
}

/// An async record's bind to its originating operation lifetime (F2):
/// one (operation bit, queue-time machine generation) pair per
/// affected bit. A `None` generation means no machine was live at
/// queue time — so a machine found at completion is a REPLACEMENT
/// (mismatch), never a match. Empty for calls with no operation bits
/// (direct, lifecycle-only): nothing to bind, completions apply.
#[derive(Debug, Clone, Default)]
struct CallOrigin {
    bits: Vec<(u16, Option<u64>)>,
}

/// A `CKR_PENDING` call awaiting its `C_AsyncComplete`: the pending
/// call's facts, its originating operation lifetime (F2), plus a
/// sequence for oldest-first eviction.
#[derive(Debug, Clone)]
struct PendingCall {
    call: SemanticCall,
    origin: CallOrigin,
    sequence: u64,
}

/// An issued async id: which session holds it (`None` floats —
/// joinable, a live state, not a dead one) plus the detached call
/// itself and its queue-time operation lifetime (F2, carried over
/// from the pending record — never re-snapshotted, so a completion
/// cannot adopt a machine created after the call was queued).
#[derive(Debug, Clone)]
struct AsyncId {
    owner: Option<u64>,
    call: SemanticCall,
    origin: CallOrigin,
    sequence: u64,
}

/// One mechanism id's per-edge aggregates. The id stays verbatim
/// (`u64` — vendor ids survive unchanged); the name resolves at
/// render from the registered table.
#[derive(Debug, Clone, Default)]
pub(crate) struct EdgeMechStat {
    /// API calls attributed to this mechanism (`Init` + operational
    /// calls observed against an active binding).
    pub calls: u64,
    /// Attributed calls with `rv != OK` (`PENDING` excluded: its
    /// outcome is still unknown).
    pub errors: u64,
    /// Operation categories this id was seen initializing, from the
    /// `*Init` function names via the shared category tables.
    pub ops: BTreeSet<&'static str>,
    /// Last attributed call's timestamp.
    pub last_seen_ns: u64,
    /// Functions that established claims on this mechanism.
    pub functions: BTreeSet<String>,
    /// Return codes observed on attributed calls.
    pub returns: BTreeSet<u64>,
    /// True when a provenance set hit its bound and stopped growing.
    pub truncated: bool,
}

/// Small ambiguity evidence, mirroring the capture-wide
/// `SemanticEvidence` names where the semantics match.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub(crate) struct EdgeEvidence {
    pub state_reconciliations: u64,
    pub session_cancel_ambiguities: u64,
    pub session_cancel_unknown_flags: u64,
    pub operation_state_imports: u64,
    pub auth_state_ambiguities: u64,
    pub semantic_capture_failures: u64,
    pub async_duplicates: u64,
    pub async_evictions: u64,
    pub unmatched_closes: u64,
}

/// The per-edge semantic reducer. Not `Clone`: edges own theirs.
#[derive(Default)]
pub(crate) struct EdgeSemantics {
    /// Open sessions: raw handle → PKCS#11 slot id. Raw handles are
    /// internal keys only (S2 owns session identity).
    open: BTreeMap<u64, u64>,
    /// Live operation machines: (raw session handle, operation bit).
    active: BTreeMap<(u64, u16), OpMachine>,
    mechs: BTreeMap<u64, EdgeMechStat>,
    /// `(session, function id)` of the pending call → the call.
    pending: BTreeMap<(u64, u32), PendingCall>,
    /// `(slot, function id, async value)` → the issued id. No
    /// cross-process tombstone: the edge holds one caller incarnation
    /// and one module instance, so a second independent claimant
    /// cannot exist inside this map (successive incarnations live on
    /// different edges).
    detached: BTreeMap<(u64, u32, u64), AsyncId>,
    sequence: u64,
    /// Next operation-machine generation (F2): every machine takes a
    /// fresh value, so generations identify lifetimes edge-wide.
    machine_seq: u64,
    /// Authorized calls with effective semantic content (every `*Init`,
    /// operational, direct, lifecycle, cancel, and async call that
    /// passed the downgrade gates — NOT a synonym for operations).
    calls: u64,
    /// Operations started (`*Init` OK bindings plus completed-direct
    /// calls, which start and finish in one call).
    started: u64,
    completed: u64,
    cancelled: u64,
    failed: u64,
    /// Ended-unknown: loss-invalidated, retired, or reconciled-away.
    unknown: u64,
    /// Calls/completions the reducer could not attribute to a tracked
    /// operation (unknown-origin evidence — never invented joins).
    orphans: u64,
    /// New keys refused past the per-edge bounds.
    dropped: u64,
    last_seen_ns: u64,
    evidence: EdgeEvidence,
    /// Downgrade memory for the unknown-reason derivation: counts of
    /// calls that carried no usable semantic content, by cause.
    unauthorized_calls: u64,
    ambiguous_calls: u64,
    count_only_calls: u64,
    unattributable_calls: u64,
    /// Same-file double-load detection latch (F7c): set when scan
    /// evidence proves this edge's object loaded twice, cleared when
    /// a later mapping note shows one load again. While set, the
    /// label reads unknown even though the historical counters
    /// stand — no retained claim can name its instance. Unlike the
    /// downgrade memory above (which never clears), this mirrors
    /// the CURRENT detection verdict.
    double_load_detected: bool,
    /// Any fully-authorized call with effective semantic content.
    seen_claim_capable: bool,
}

impl std::fmt::Debug for EdgeSemantics {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("EdgeSemantics")
            .field("open_bindings", &self.open.len())
            .field("active_machines", &self.active.len())
            .field("pending_calls", &self.pending.len())
            .field("detached_calls", &self.detached.len())
            .field("mechanisms", &self.mechs.len())
            .field("calls", &self.calls)
            .field("started", &self.started)
            .field("completed", &self.completed)
            .field("unknown", &self.unknown)
            .finish_non_exhaustive()
    }
}

/// Published per-edge semantic labels. `observed` iff the edge holds
/// at least one mechanism or operation claim AND no double-load
/// detection stands; otherwise the reason no claim exists — or the
/// reason retained claims cannot name their instance (B3/F7c:
/// unsupported, ambiguous, or unattributable semantics render
/// `unknown`, never invented).
pub(crate) const SEMANTIC_OBSERVED: &str = "observed";
pub(crate) const SEMANTIC_UNKNOWN_UNAUTHORIZED: &str = "unknown (unauthoritative module)";
pub(crate) const SEMANTIC_UNKNOWN_AMBIGUOUS: &str = "unknown (ambiguous descriptor)";
pub(crate) const SEMANTIC_UNKNOWN_COUNT_ONLY: &str = "unknown (count-only slot)";
pub(crate) const SEMANTIC_UNKNOWN_NO_EVIDENCE: &str = "unknown (no operation evidence)";
pub(crate) const SEMANTIC_UNKNOWN_DOUBLE_LOAD: &str = "unknown (same-file double-load)";

/// How one tracked operation ended. Completed ⟺ ended by an `OK`
/// return; cancelled ⟺ ended by cancel/replacement/scope end;
/// failed ⟺ ended by an error return; unknown ⟺ invalidated by loss,
/// retirement, or a contradicted model — never silently completed,
/// never silently dropped.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum EndState {
    Completed,
    Cancelled,
    Failed,
    Unknown,
}

impl EdgeSemantics {
    /// Feed one completed call. Returns the number of per-edge keys
    /// refused past bounds by THIS call (the registry folds it into
    /// its `semantic_refused` total).
    pub(crate) fn observe(&mut self, call: &SemanticCall) -> u64 {
        let dropped_before = self.dropped;
        let Some(descriptor) = self.gate(call) else {
            return 0;
        };
        self.calls = self.calls.saturating_add(1);
        self.last_seen_ns = self.last_seen_ns.max(call.ts_ns);
        if matches!(
            descriptor.lifecycle,
            lifecycle::ASYNC_COMPLETE | lifecycle::ASYNC_GET_ID | lifecycle::ASYNC_JOIN
        ) {
            self.observe_async(call);
        } else if call.rv == CkRv::PENDING.0 {
            self.queue_pending(call);
        } else {
            self.apply_completed(call, &descriptor);
        }
        self.dropped.saturating_sub(dropped_before)
    }

    /// The downgrade gates (B3): only fully-authorized calls with
    /// effective semantic content reach the machines. Everything else
    /// is counted by cause (the unknown-reason memory) and ignored —
    /// a downgraded call establishes no claim.
    fn gate(&mut self, call: &SemanticCall) -> Option<SlotSemantics> {
        // Instance unattributability dominates the call-level causes:
        // on a double-loaded edge no call can name its instance,
        // whatever its own authority.
        if !call.attributable {
            self.unattributable_calls = self.unattributable_calls.saturating_add(1);
            return None;
        }
        if !call.authorized {
            self.unauthorized_calls = self.unauthorized_calls.saturating_add(1);
            return None;
        }
        if !call.unambiguous {
            self.ambiguous_calls = self.ambiguous_calls.saturating_add(1);
            return None;
        }
        if call.count_only {
            self.count_only_calls = self.count_only_calls.saturating_add(1);
            return None;
        }
        let descriptor =
            crate::kinds::descriptor(&call.function).unwrap_or(SlotSemantics::COUNT_ONLY);
        if descriptor == SlotSemantics::COUNT_ONLY {
            // Unknown function names land here too: `kinds` treats
            // them as OTHER, and so does this reducer.
            self.count_only_calls = self.count_only_calls.saturating_add(1);
            return None;
        }
        self.seen_claim_capable = true;
        Some(descriptor)
    }

    /// The completed-call pipeline, in the capture-wide reducer's
    /// order: mechanism record → reconciliation → lifecycle →
    /// init/operations/direct. (`calls`/`last_seen` are already
    /// counted by the caller — [`Self::observe`] or the async
    /// completion path — so completions never double-count.)
    fn apply_completed(&mut self, call: &SemanticCall, descriptor: &SlotSemantics) {
        if descriptor.transition == transition::INITIALIZE || descriptor.direct != direct::NONE {
            self.record_init_mechanism(call, descriptor);
        }
        if self.reconcile_conclusive(call, descriptor) {
            return;
        }
        self.apply_lifecycle(call, descriptor);
        if descriptor.transition == transition::INITIALIZE {
            self.apply_init(call, descriptor);
        } else if descriptor.direct == direct::NONE && descriptor.operations != 0 {
            self.apply_operations(call, descriptor);
        } else if descriptor.direct != direct::NONE {
            self.apply_direct(call);
        }
    }

    /// Mechanism claim for an `*Init`/direct call: `OK` + a captured
    /// value only (the capture-wide allowlisted rule — S1 has no
    /// unsafe policy). A failed `Init` records no mechanism, like it
    /// creates no operation.
    fn record_init_mechanism(&mut self, call: &SemanticCall, descriptor: &SlotSemantics) {
        if call.rv != CkRv::OK.0 || call.mechanism_capture() != capture::MECHANISM_VALUE {
            return;
        }
        if !self.mechs.contains_key(&call.mechanism) && self.mechs.len() >= MAX_EDGE_MECHANISMS {
            self.dropped = self.dropped.saturating_add(1);
            return;
        }
        let stat = self.mechs.entry(call.mechanism).or_default();
        stat.calls = stat.calls.saturating_add(1);
        for (_, name) in crate::semantics::operation_bits(descriptor.operations) {
            stat.ops.insert(name);
        }
        if let Some(name) = crate::semantics::direct_name(descriptor.direct) {
            stat.ops.insert(name);
        }
        stat.last_seen_ns = stat.last_seen_ns.max(call.ts_ns);
        Self::record_provenance(stat, call);
    }

    /// Attribute one operational call to its bound mechanism. Called
    /// exactly once per attributed call — at observation for completed
    /// calls, at completion for `PENDING` ones — so outcomes are never
    /// double-counted.
    fn attribute_op_call(&mut self, call: &SemanticCall, mechanism: u64) {
        if !self.mechs.contains_key(&mechanism) && self.mechs.len() >= MAX_EDGE_MECHANISMS {
            self.dropped = self.dropped.saturating_add(1);
            return;
        }
        let stat = self.mechs.entry(mechanism).or_default();
        stat.calls = stat.calls.saturating_add(1);
        if call.rv != CkRv::OK.0 {
            stat.errors = stat.errors.saturating_add(1);
        }
        stat.last_seen_ns = stat.last_seen_ns.max(call.ts_ns);
        Self::record_provenance(stat, call);
    }

    /// Provenance: which functions/returns established claims on this
    /// mechanism. Bounded sets that saturate with an explicit
    /// `truncated` flag, never silent loss.
    fn record_provenance(stat: &mut EdgeMechStat, call: &SemanticCall) {
        if !stat.functions.contains(&call.function) {
            if stat.functions.len() >= MAX_EDGE_PROVENANCE_FUNCTIONS {
                stat.truncated = true;
            } else {
                stat.functions.insert(call.function.clone());
            }
        }
        if !stat.returns.contains(&call.rv) {
            if stat.returns.len() >= MAX_EDGE_PROVENANCE_RETURNS {
                stat.truncated = true;
            } else {
                stat.returns.insert(call.rv);
            }
        }
    }

    /// Conclusive module evidence that contradicts tracked state,
    /// mirroring `reconcile_conclusive` (including its early return:
    /// a reconciling call drives no lifecycle/init/operation effects
    /// of its own). Scope ends (dead session, dead Cryptoki) cancel
    /// like an observed close/finalize; a contradicted single
    /// operation ends unknown — its true end is unprovable.
    fn reconcile_conclusive(&mut self, call: &SemanticCall, descriptor: &SlotSemantics) -> bool {
        if call.rv == CkRv::OPERATION_NOT_INITIALIZED.0 {
            let mut changed = false;
            for (bit, _) in crate::semantics::operation_bits(descriptor.operations) {
                changed |= self.end_machine(call.session, bit, EndState::Unknown);
            }
            if changed {
                self.evidence.state_reconciliations =
                    self.evidence.state_reconciliations.saturating_add(1);
            }
            return true;
        }
        if call.rv == CkRv::SESSION_CLOSED.0 || call.rv == CkRv::SESSION_HANDLE_INVALID.0 {
            let changed = self.retire_session(call.session, EndState::Cancelled);
            if changed {
                self.evidence.state_reconciliations =
                    self.evidence.state_reconciliations.saturating_add(1);
            }
            return true;
        }
        if call.rv == CkRv::CRYPTOKI_NOT_INITIALIZED.0 {
            let changed = self.retire_all(EndState::Cancelled);
            if changed {
                self.evidence.state_reconciliations =
                    self.evidence.state_reconciliations.saturating_add(1);
            }
            return true;
        }
        false
    }

    /// Session/module lifecycle, mirroring `apply_lifecycle`
    /// (S2/S3-owned state — find/search, templates, logins — excluded).
    fn apply_lifecycle(&mut self, call: &SemanticCall, descriptor: &SlotSemantics) {
        match descriptor.lifecycle {
            lifecycle::OPEN_SESSION if call.rv == CkRv::OK.0 && call.session != SESSION_NONE => {
                // Prior state under a reopened handle is a stale model
                // (handle reuse without an observed close): its true
                // end is unprovable.
                if self.retire_session(call.session, EndState::Unknown) {
                    self.evidence.state_reconciliations =
                        self.evidence.state_reconciliations.saturating_add(1);
                }
                if !self.open.contains_key(&call.session) && self.open.len() >= MAX_EDGE_SESSIONS {
                    self.dropped = self.dropped.saturating_add(1);
                } else {
                    self.open.insert(call.session, call.slot_id);
                }
            }
            lifecycle::CLOSE_SESSION if call.rv == CkRv::OK.0 => {
                let existed = self.open.remove(&call.session).is_some();
                self.end_session_machines(call.session, EndState::Cancelled);
                self.pending.retain(|(owner, _), _| *owner != call.session);
                self.float_session_async(call.session);
                if !existed {
                    // A close with no observed open: mid-life-attach
                    // evidence, counted — while still ending whatever
                    // the edge had tracked on the handle.
                    self.evidence.unmatched_closes =
                        self.evidence.unmatched_closes.saturating_add(1);
                }
            }
            lifecycle::CLOSE_ALL_SESSIONS if call.rv == CkRv::OK.0 => {
                // Tracked sessions with NO observed open have no proven
                // slot (computed BEFORE the proven path mutates `open`):
                // the close-all may or may not have ended them, so
                // their slot uncertainty ends them unknown below —
                // never continued definite activity, never a proven
                // cancel. Sessions proven on other slots stay live.
                let unproven: BTreeSet<u64> = self
                    .active
                    .keys()
                    .map(|(session, _)| *session)
                    .chain(self.pending.keys().map(|(session, _)| *session))
                    .chain(self.detached.values().filter_map(|id| id.owner))
                    .filter(|session| !self.open.contains_key(session))
                    .collect();
                // This edge's sessions on that PKCS#11 slot id end by
                // observed close — a proven scope end, hence cancelled.
                let owned: Vec<u64> = self
                    .open
                    .iter()
                    .filter(|(_, slot)| **slot == call.slot_id)
                    .map(|(session, _)| *session)
                    .collect();
                for session in owned {
                    self.open.remove(&session);
                    self.end_session_machines(session, EndState::Cancelled);
                    self.pending.retain(|(owner, _), _| *owner != session);
                    self.float_session_async(session);
                }
                for session in unproven {
                    self.retire_session(session, EndState::Unknown);
                }
            }
            lifecycle::FINALIZE if call.rv == CkRv::OK.0 => {
                self.retire_all(EndState::Cancelled);
            }
            lifecycle::LOGIN | lifecycle::LOGOUT => self.apply_auth(call),
            lifecycle::SESSION_CANCEL => self.apply_session_cancel(call),
            lifecycle::SET_OPERATION_STATE if call.rv == CkRv::OK.0 => {
                // Imported state replaces tracked state: the old
                // machines ended by replacement.
                self.end_session_machines(call.session, EndState::Cancelled);
                self.evidence.operation_state_imports =
                    self.evidence.operation_state_imports.saturating_add(1);
            }
            _ => {}
        }
    }

    /// Login/logout clears the slot's operations, mirroring
    /// `apply_auth` exactly: context-specific `C_Login` is exempt, and
    /// `OK`/`PIN_LOCKED` both proceed (both prove the token answered
    /// with changed auth state).
    fn apply_auth(&mut self, call: &SemanticCall) {
        if call.function == "C_Login" && call.user_type == 2 && call.rv == CkRv::OK.0 {
            return;
        }
        if call.rv != CkRv::OK.0 && call.rv != CkRv::PIN_LOCKED.0 {
            return;
        }
        let Some(slot) = self.open.get(&call.session).copied() else {
            return;
        };
        let owned: Vec<u64> = self
            .open
            .iter()
            .filter(|(_, candidate)| **candidate == slot)
            .map(|(session, _)| *session)
            .collect();
        let mut changed = false;
        for session in owned {
            changed |= self.end_session_machines(session, EndState::Cancelled);
            let pending_before = self.pending.len();
            self.pending.retain(|(owner, _), _| *owner != session);
            changed |= self.pending.len() != pending_before;
            changed |= self.float_session_async(session);
        }
        if changed {
            self.evidence.auth_state_ambiguities =
                self.evidence.auth_state_ambiguities.saturating_add(1);
        }
    }

    /// `C_SessionCancel`, mirroring `apply_session_cancel`: `OK`
    /// clears; `OPERATION_CANCEL_FAILED` with more than one selected
    /// flag clears too but counts the ambiguity (the attempt is
    /// evidence even though it reports failure); anything else clears
    /// nothing.
    fn apply_session_cancel(&mut self, call: &SemanticCall) {
        if call.flags & !crate::semantics::KNOWN_CANCEL_FLAGS != 0 {
            self.evidence.session_cancel_unknown_flags =
                self.evidence.session_cancel_unknown_flags.saturating_add(1);
        }
        let selected = (call.flags & crate::semantics::KNOWN_CANCEL_FLAGS).count_ones();
        if call.rv == CkRv::OPERATION_CANCEL_FAILED.0 && selected > 1 {
            self.clear_selected(call.session, call.flags);
            self.evidence.session_cancel_ambiguities =
                self.evidence.session_cancel_ambiguities.saturating_add(1);
        } else if call.rv == CkRv::OK.0 {
            self.clear_selected(call.session, call.flags);
        }
    }

    /// Clear what a cancel selected: masked machines, matching
    /// pendings, and owned async ids — mirroring `clear_selected`
    /// (minus find state, which is S2, and minus tombstones, which
    /// cannot exist inside one edge).
    fn clear_selected(&mut self, session: u64, flags: u64) {
        let mask = cancel_operation_mask(flags);
        let doomed: Vec<(u64, u16)> = self
            .active
            .keys()
            .filter(|(owner, bit)| *owner == session && mask & *bit != 0)
            .copied()
            .collect();
        for key in doomed {
            self.active.remove(&key);
            self.cancelled = self.cancelled.saturating_add(1);
        }
        self.pending.retain(|(owner, _), pending| {
            if *owner != session {
                return true;
            }
            let descriptor = crate::kinds::descriptor(&pending.call.function)
                .unwrap_or(SlotSemantics::COUNT_ONLY);
            descriptor.operations & mask == 0 && direct_cancel_flag(descriptor.direct) & flags == 0
        });
        self.detached.retain(|_, id| {
            if id.owner != Some(session) {
                return true;
            }
            let descriptor =
                crate::kinds::descriptor(&id.call.function).unwrap_or(SlotSemantics::COUNT_ONLY);
            descriptor.operations & mask == 0 && direct_cancel_flag(descriptor.direct) & flags == 0
        });
    }

    /// `*Init` OK: bind each operation bit, mirroring `apply_init`
    /// EXCEPT (F5) a trusted OK `Init` with an unreadable mechanism
    /// still starts its operation with the mechanism unknown — the OK
    /// return establishes category and initialized state under A1 —
    /// where the capture-wide reducer drops the binding. A failed
    /// `Init` never reaches here (no operation); a competing `*Init`
    /// cancels the machine it replaces; `NULL` with the descriptor's
    /// null-cancel flag stays a genuine cancel (no machine), while
    /// `NULL` without the flag tracks unknown and counts the capture
    /// failure.
    fn apply_init(&mut self, call: &SemanticCall, descriptor: &SlotSemantics) {
        if call.rv != CkRv::OK.0 || call.session == SESSION_NONE {
            return;
        }
        for (bit, _) in crate::semantics::operation_bits(descriptor.operations) {
            match call.mechanism_capture() {
                capture::MECHANISM_VALUE => {
                    self.start_machine(call.session, bit, Some(call.mechanism));
                }
                capture::MECHANISM_NULL
                    if descriptor.semantic_flags & semantic_flags::NULL_MECHANISM_CANCEL != 0 =>
                {
                    self.end_machine(call.session, bit, EndState::Cancelled);
                }
                capture::MECHANISM_NULL => {
                    self.evidence.semantic_capture_failures =
                        self.evidence.semantic_capture_failures.saturating_add(1);
                    self.start_machine(call.session, bit, None);
                }
                _ => {
                    self.start_machine(call.session, bit, None);
                }
            }
        }
    }

    /// Start (or replace) one operation machine: bound-checked,
    /// generation-stamped (F2); the replaced machine ends cancelled
    /// by replacement — never completed.
    fn start_machine(&mut self, session: u64, bit: u16, mechanism: Option<u64>) {
        let key = (session, bit);
        if !self.active.contains_key(&key) && self.active.len() >= MAX_EDGE_ACTIVE_OPS {
            self.dropped = self.dropped.saturating_add(1);
            return;
        }
        self.machine_seq = self.machine_seq.wrapping_add(1);
        let generation = self.machine_seq;
        if self
            .active
            .insert(
                key,
                OpMachine {
                    mechanism,
                    state: OpState::Initialized,
                    generation,
                },
            )
            .is_some()
        {
            // Competing `Init`: the old machine ended by
            // replacement, never completed.
            self.cancelled = self.cancelled.saturating_add(1);
        }
        self.started = self.started.saturating_add(1);
    }

    /// Operational call: attribute to each bound mechanism (or count
    /// the orphan when no machine is active — unknown-origin evidence,
    /// never an invented operation), then run the transition, mirroring
    /// `apply_operations` including its exact retain rules. Retained
    /// machines advance to in-progress; ended machines complete iff
    /// the ending call returned `OK`. Machines with an unknown
    /// mechanism (F5) advance and end normally but attribute to
    /// nothing — no invented mechanism id.
    fn apply_operations(&mut self, call: &SemanticCall, descriptor: &SlotSemantics) {
        let mut mechanisms = BTreeSet::new();
        for (bit, _) in crate::semantics::operation_bits(descriptor.operations) {
            match self.active.get(&(call.session, bit)) {
                Some(machine) => {
                    if let Some(mechanism) = machine.mechanism {
                        mechanisms.insert(mechanism);
                    }
                }
                None => self.orphans = self.orphans.saturating_add(1),
            }
        }
        for mechanism in mechanisms {
            self.attribute_op_call(call, mechanism);
        }
        let retain = match descriptor.transition {
            transition::CONTINUE => call.rv == CkRv::OK.0,
            transition::UPDATE_WITH_OUTPUT => {
                call.rv == CkRv::OK.0 || call.rv == CkRv::BUFFER_TOO_SMALL.0
            }
            transition::FINISH_WITH_OUTPUT => {
                call.rv == CkRv::BUFFER_TOO_SMALL.0
                    || (call.rv == CkRv::OK.0
                        && call.capture & capture::OUTPUT_MASK == capture::OUTPUT_NULL)
            }
            transition::FINISH_ALWAYS => false,
            transition::RETAIN_ALWAYS => true,
            transition::FINISH_ON_SUCCESS => call.rv != CkRv::OK.0,
            _ => true,
        };
        if !retain {
            let end = if call.rv == CkRv::OK.0 {
                EndState::Completed
            } else {
                EndState::Failed
            };
            for (bit, _) in crate::semantics::operation_bits(descriptor.operations) {
                self.end_machine(call.session, bit, end);
            }
        } else {
            for (bit, _) in crate::semantics::operation_bits(descriptor.operations) {
                if let Some(machine) = self.active.get_mut(&(call.session, bit)) {
                    machine.state = OpState::InProgress;
                }
            }
        }
    }

    /// Direct call (`C_GenerateKey`, `C_WrapKey`, ...): no machine — a
    /// successful call starts and finishes its operation in this one
    /// call. (The mechanism claim, if any, was already recorded.)
    fn apply_direct(&mut self, call: &SemanticCall) {
        if call.rv != CkRv::OK.0 {
            return;
        }
        self.started = self.started.saturating_add(1);
        self.completed = self.completed.saturating_add(1);
    }

    /// End one machine with an explicit end state. Returns whether a
    /// machine was actually ended.
    fn end_machine(&mut self, session: u64, bit: u16, end: EndState) -> bool {
        if self.active.remove(&(session, bit)).is_some() {
            match end {
                EndState::Completed => self.completed = self.completed.saturating_add(1),
                EndState::Cancelled => self.cancelled = self.cancelled.saturating_add(1),
                EndState::Failed => self.failed = self.failed.saturating_add(1),
                EndState::Unknown => self.unknown = self.unknown.saturating_add(1),
            }
            true
        } else {
            false
        }
    }

    /// End every machine on one session. Returns whether any ended.
    fn end_session_machines(&mut self, session: u64, end: EndState) -> bool {
        let doomed: Vec<(u64, u16)> = self
            .active
            .keys()
            .filter(|(owner, _)| *owner == session)
            .copied()
            .collect();
        let changed = !doomed.is_empty();
        for key in doomed {
            self.active.remove(&key);
            match end {
                EndState::Completed => self.completed = self.completed.saturating_add(1),
                EndState::Cancelled => self.cancelled = self.cancelled.saturating_add(1),
                EndState::Failed => self.failed = self.failed.saturating_add(1),
                EndState::Unknown => self.unknown = self.unknown.saturating_add(1),
            }
        }
        changed
    }

    /// Retire one session: forget the open, end its machines, drop its
    /// pendings, float its async ids (still joinable — a live state).
    /// Returns whether the scope held any state.
    fn retire_session(&mut self, session: u64, end: EndState) -> bool {
        let mut changed = self.open.remove(&session).is_some();
        changed |= self.end_session_machines(session, end);
        let pending_before = self.pending.len();
        self.pending.retain(|(owner, _), _| *owner != session);
        changed |= self.pending.len() != pending_before;
        changed |= self.float_session_async(session);
        changed
    }

    /// Retire the whole edge scope (finalize / dead Cryptoki): every
    /// open, machine, and pending goes, and issued async ids die with
    /// the Cryptoki (a later `C_Initialize` could re-mint an identical
    /// key — a join must never adopt a dead operation). Returns whether
    /// the scope held any state.
    fn retire_all(&mut self, end: EndState) -> bool {
        let mut changed = !self.open.is_empty();
        self.open.clear();
        changed |= self.end_session_machines_all(end);
        changed |= !self.pending.is_empty();
        self.pending.clear();
        changed |= !self.detached.is_empty();
        self.detached.clear();
        changed
    }

    fn end_session_machines_all(&mut self, end: EndState) -> bool {
        let changed = !self.active.is_empty();
        let count = self.active.len() as u64;
        self.active.clear();
        match end {
            EndState::Completed => self.completed = self.completed.saturating_add(count),
            EndState::Cancelled => self.cancelled = self.cancelled.saturating_add(count),
            EndState::Failed => self.failed = self.failed.saturating_add(count),
            EndState::Unknown => self.unknown = self.unknown.saturating_add(count),
        }
        changed
    }

    /// Float one session's async ids (owner `None`: detached and
    /// joinable). Returns whether any floated.
    fn float_session_async(&mut self, session: u64) -> bool {
        let mut changed = false;
        for id in self.detached.values_mut() {
            if id.owner == Some(session) {
                id.owner = None;
                changed = true;
            }
        }
        changed
    }

    /// Capture-loss boundary / retirement / eviction (C2): every live
    /// machine ends unknown with explicit accounting — never silently
    /// completed, never silently dropped — and outstanding custody
    /// dies with the boundary (F3): pending calls, detached async ids,
    /// and session-slot bindings. A pending Init must not recreate
    /// definite state after loss, a detached completion must not
    /// replay, and bindings lose their proof (a missed close would
    /// leave them stale) — post-loss lifecycle re-proves via observed
    /// opens, exactly like mid-life attach. Historical claims
    /// (mechanism rows, counters) stand: loss invalidates "right
    /// now", not the observed past.
    pub(crate) fn invalidate(&mut self) {
        self.end_session_machines_all(EndState::Unknown);
        self.pending.clear();
        self.detached.clear();
        self.open.clear();
    }

    /// Same-file double-load detection (F7b/F7c): live operations end
    /// unknown (shared with loss — "right now" is unattributable),
    /// and the detection latch forces the label unknown from this
    /// moment on. Historical claims (mechanism rows, counters) stand
    /// — detection voids attribution, not the observed past — and
    /// the registry voids every later call at the gate.
    pub(crate) fn mark_double_load(&mut self) {
        self.invalidate();
        self.double_load_detected = true;
    }

    /// A later mapping note shows one load again: the latch clears
    /// and labeling returns to claims-or-memory. Downgrade memories
    /// (including past unattributable calls) stand as history.
    pub(crate) fn clear_double_load(&mut self) {
        self.double_load_detected = false;
    }

    /// Async lifecycle, mirroring `observe_async` minus the
    /// cross-process machinery (one caller incarnation per edge: no
    /// second claimant, no tombstone). Unroutable async evidence
    /// counts as orphans — never invented joins.
    fn observe_async(&mut self, call: &SemanticCall) {
        if call.target_function == FUNCTION_NONE {
            self.orphans = self.orphans.saturating_add(1);
            return;
        }
        if call.capture & capture::ASYNC_VALUE_UNREADABLE != 0 {
            self.orphans = self.orphans.saturating_add(1);
            return;
        }
        let descriptor =
            crate::kinds::descriptor(&call.function).unwrap_or(SlotSemantics::COUNT_ONLY);
        match descriptor.lifecycle {
            lifecycle::ASYNC_COMPLETE => {
                if call.rv == CkRv::PENDING.0 {
                    return;
                }
                if let Some(pending) = self.pending.remove(&(call.session, call.target_function)) {
                    self.complete_pending(call, pending.call, &pending.origin);
                    return;
                }
                let detached_key = self.detached.iter().find_map(|(key, id)| {
                    (id.owner == Some(call.session) && key.1 == call.target_function)
                        .then_some(*key)
                });
                let Some(detached_key) = detached_key else {
                    self.orphans = self.orphans.saturating_add(1);
                    return;
                };
                let Some(id) = self.detached.remove(&detached_key) else {
                    self.orphans = self.orphans.saturating_add(1);
                    return;
                };
                self.complete_pending(call, id.call, &id.origin);
            }
            lifecycle::ASYNC_GET_ID if call.rv == CkRv::OK.0 => {
                let Some(slot) = self.open.get(&call.session).copied() else {
                    self.orphans = self.orphans.saturating_add(1);
                    return;
                };
                let Some(pending) = self.pending.remove(&(call.session, call.target_function))
                else {
                    self.orphans = self.orphans.saturating_add(1);
                    return;
                };
                self.sequence = self.sequence.wrapping_add(1);
                let sequence = self.sequence;
                if self
                    .detached
                    .insert(
                        (slot, call.target_function, call.async_value),
                        AsyncId {
                            owner: Some(call.session),
                            call: pending.call,
                            origin: pending.origin,
                            sequence,
                        },
                    )
                    .is_some()
                {
                    // Same-scope re-mint (the only possible claimant
                    // inside one edge): overwrite and count, exactly
                    // like the capture-wide same-owner rule.
                    self.evidence.async_duplicates =
                        self.evidence.async_duplicates.saturating_add(1);
                }
                self.evict_async_if_needed();
            }
            lifecycle::ASYNC_JOIN if call.rv == CkRv::OK.0 => {
                let Some(slot) = self.open.get(&call.session).copied() else {
                    self.orphans = self.orphans.saturating_add(1);
                    return;
                };
                match self
                    .detached
                    .get_mut(&(slot, call.target_function, call.async_value))
                {
                    Some(id) => {
                        // A successful join assigns custody whole to
                        // the joining session.
                        id.owner = Some(call.session);
                    }
                    None => self.orphans = self.orphans.saturating_add(1),
                }
            }
            _ => {}
        }
    }

    /// Queue a `PENDING` call for its completion, mirroring
    /// `queue_pending`. Unroutable pendings (unknown function, or an
    /// `OPEN_SESSION` that never named its session) count as orphans.
    fn queue_pending(&mut self, call: &SemanticCall) {
        let descriptor =
            crate::kinds::descriptor(&call.function).unwrap_or(SlotSemantics::COUNT_ONLY);
        let Some(function_id) = crate::kinds::function_id(&call.function) else {
            self.orphans = self.orphans.saturating_add(1);
            return;
        };
        if descriptor.lifecycle == lifecycle::OPEN_SESSION && call.session == SESSION_NONE {
            self.orphans = self.orphans.saturating_add(1);
            return;
        }
        self.sequence = self.sequence.wrapping_add(1);
        let sequence = self.sequence;
        let origin = self.capture_origin(call.session, &descriptor);
        if self
            .pending
            .insert(
                (call.session, function_id),
                PendingCall {
                    call: call.clone(),
                    origin,
                    sequence,
                },
            )
            .is_some()
        {
            self.evidence.async_duplicates = self.evidence.async_duplicates.saturating_add(1);
        }
        self.evict_async_if_needed();
    }

    /// Snapshot the live-machine generations a pending call binds to
    /// (F2): one entry per affected operation bit, `None` where no
    /// machine is live.
    fn capture_origin(&self, session: u64, descriptor: &SlotSemantics) -> CallOrigin {
        let bits = crate::semantics::operation_bits(descriptor.operations)
            .map(|(bit, _)| {
                (
                    bit,
                    self.active
                        .get(&(session, bit))
                        .map(|machine| machine.generation),
                )
            })
            .collect();
        CallOrigin { bits }
    }

    /// Whether the completing session still holds every originating
    /// machine lifetime (F2): each bound bit's live generation must
    /// equal the queue-time generation — including `None == None` (no
    /// machine then, none now). Any replacement, end, or new machine
    /// since queue time is a mismatch: the completion is stale.
    fn origin_matches(&self, session: u64, origin: &CallOrigin) -> bool {
        origin.bits.iter().all(|(bit, generation)| {
            self.active
                .get(&(session, *bit))
                .map(|machine| machine.generation)
                == *generation
        })
    }

    /// Apply a completion to the record it named: the pending call's
    /// facts with the completion's return, session, and time — but
    /// ONLY when the completing session still holds the originating
    /// operation lifetime on every affected bit (F2). A stale
    /// completion (replaced, ended, or never-related machine — notably
    /// a joined completion landing on the receiver's own operation)
    /// orphans per affected bit instead of joining, like any other
    /// unattributable evidence. This deliberately differs from the
    /// capture-wide `complete_pending`, which replays against current
    /// bindings.
    fn complete_pending(
        &mut self,
        completion: &SemanticCall,
        pending: SemanticCall,
        origin: &CallOrigin,
    ) {
        if !self.origin_matches(completion.session, origin) {
            let unattributed = origin.bits.len().max(1) as u64;
            self.orphans = self.orphans.saturating_add(unattributed);
            return;
        }
        let mut completed = pending;
        completed.rv = completion.rv;
        completed.session = completion.session;
        completed.ts_ns = completion.ts_ns;
        let descriptor =
            crate::kinds::descriptor(&completed.function).unwrap_or(SlotSemantics::COUNT_ONLY);
        self.apply_completed(&completed, &descriptor);
    }

    /// Oldest-first async eviction past the bound, mirroring
    /// `evict_pending_if_needed` (the one place retained async facts
    /// drop, and every drop is counted) — plus the affected
    /// operation's end (F3/C2): when the evicted record's originating
    /// machine is still live (same generation), it ends unknown with
    /// explicit accounting, since its outstanding call history is now
    /// lost. A newer machine on the same key is a different lifetime
    /// and is left alone.
    fn evict_async_if_needed(&mut self) {
        if self.pending.len() + self.detached.len() <= MAX_EDGE_PENDING {
            return;
        }
        let pending = self
            .pending
            .iter()
            .min_by_key(|(_, value)| value.sequence)
            .map(|(key, _)| *key);
        let detached = self
            .detached
            .iter()
            .min_by_key(|(_, value)| value.sequence)
            .map(|(key, value)| (*key, value.sequence));
        let evicted: Option<(u64, CallOrigin)> = match (pending, detached) {
            (Some(key), Some((detached_key, detached_sequence))) => {
                if self.pending[&key].sequence <= detached_sequence {
                    self.pending
                        .remove(&key)
                        .map(|record| (key.0, record.origin))
                } else {
                    self.detached
                        .remove(&detached_key)
                        .map(|id| (id.call.session, id.origin))
                }
            }
            (Some(key), None) => self
                .pending
                .remove(&key)
                .map(|record| (key.0, record.origin)),
            (None, Some((key, _))) => self
                .detached
                .remove(&key)
                .map(|id| (id.call.session, id.origin)),
            (None, None) => return,
        };
        let Some((session, origin)) = evicted else {
            return;
        };
        for (bit, generation) in &origin.bits {
            let live_matches = generation.is_some()
                && self
                    .active
                    .get(&(session, *bit))
                    .map(|machine| machine.generation)
                    == *generation;
            if live_matches {
                self.end_machine(session, *bit, EndState::Unknown);
            }
        }
        self.evidence.async_evictions = self.evidence.async_evictions.saturating_add(1);
    }
}

/// Published projection: aggregates only. No accessor returns a raw
/// session handle, a pending call, or an async id value.
impl EdgeSemantics {
    /// Whether the edge holds any mechanism or operation claim.
    pub(crate) fn has_claims(&self) -> bool {
        !self.mechs.is_empty() || self.started > 0
    }

    /// The edge's semantic label: `observed`, or the reason no claim
    /// exists — or the reason retained claims are unattributable.
    /// Total: a materialized edge either holds claims, has seen an
    /// authorized content call, or has counted a downgrade. The
    /// double-load latch dominates history (F7c): from detection
    /// on, the label reads unknown even though the historical
    /// counters stand — no retained claim can name its instance.
    pub(crate) fn label(&self) -> &'static str {
        if self.double_load_detected {
            return SEMANTIC_UNKNOWN_DOUBLE_LOAD;
        }
        if self.has_claims() {
            return SEMANTIC_OBSERVED;
        }
        // The edge-level attribution failure names the label before
        // any call-level cause (mirrors the gate order above).
        if self.unattributable_calls > 0 {
            return SEMANTIC_UNKNOWN_DOUBLE_LOAD;
        }
        if self.seen_claim_capable {
            return SEMANTIC_UNKNOWN_NO_EVIDENCE;
        }
        if self.unauthorized_calls > 0 {
            return SEMANTIC_UNKNOWN_UNAUTHORIZED;
        }
        if self.ambiguous_calls > 0 {
            return SEMANTIC_UNKNOWN_AMBIGUOUS;
        }
        SEMANTIC_UNKNOWN_COUNT_ONLY
    }

    /// Any operation machine live right now (initialized or
    /// in-progress): the dashboard's genuine operation state (B4) and
    /// one leg of the "right now" trichotomy (B3).
    pub(crate) fn has_live_operations(&self) -> bool {
        !self.active.is_empty()
    }

    pub(crate) fn mechanisms(&self) -> &BTreeMap<u64, EdgeMechStat> {
        &self.mechs
    }

    /// Live machines aggregated by (category, state) with counts,
    /// sorted. Raw sessions never leave the map.
    pub(crate) fn active_summary(&self) -> Vec<(String, OpState, u64)> {
        let mut summary: BTreeMap<(String, OpState), u64> = BTreeMap::new();
        for ((_, bit), machine) in &self.active {
            let category = crate::semantics::operation_name(*bit)
                .map(str::to_string)
                .unwrap_or_else(|| format!("operation#{bit}"));
            *summary.entry((category, machine.state)).or_default() += 1;
        }
        summary
            .into_iter()
            .map(|((category, state), count)| (category, state, count))
            .collect()
    }

    pub(crate) fn calls(&self) -> u64 {
        self.calls
    }
    pub(crate) fn started(&self) -> u64 {
        self.started
    }
    pub(crate) fn completed(&self) -> u64 {
        self.completed
    }
    pub(crate) fn cancelled(&self) -> u64 {
        self.cancelled
    }
    pub(crate) fn failed(&self) -> u64 {
        self.failed
    }
    pub(crate) fn unknown(&self) -> u64 {
        self.unknown
    }
    pub(crate) fn orphans(&self) -> u64 {
        self.orphans
    }
    pub(crate) fn dropped(&self) -> u64 {
        self.dropped
    }
    pub(crate) fn last_seen_ns(&self) -> u64 {
        self.last_seen_ns
    }
    pub(crate) fn evidence(&self) -> EdgeEvidence {
        self.evidence
    }
}

/// `CKR_*` name for a return code, via the `pkcs11-types` display
/// vocabulary (`"CKR_OK (0x00000000)"` → `"CKR_OK"`). `None` for
/// unregistered codes — verbatim only, never guessed.
pub(crate) fn rv_name(rv: u64) -> Option<String> {
    let rendered = format!("{}", CkRv(rv));
    let name = rendered.split(" (").next().unwrap_or("CKR_UNKNOWN");
    (name != "CKR_UNKNOWN").then(|| name.to_string())
}

#[cfg(test)]
mod tests {
    use super::*;

    const AES_GCM: u64 = 0x1087;
    const RSA_PSS: u64 = 0x000d;

    fn call(function: &str, session: u64, rv: u64, ts_ns: u64) -> SemanticCall {
        SemanticCall {
            function: function.into(),
            rv,
            session,
            ts_ns,
            ..SemanticCall::default()
        }
    }

    fn init(function: &str, session: u64, mechanism: u64, ts_ns: u64) -> SemanticCall {
        SemanticCall {
            function: function.into(),
            session,
            mechanism,
            capture: capture::MECHANISM_VALUE | capture::OUTPUT_NON_NULL,
            ts_ns,
            ..SemanticCall::default()
        }
    }

    fn op(function: &str, session: u64, ts_ns: u64) -> SemanticCall {
        SemanticCall {
            function: function.into(),
            session,
            capture: capture::MECHANISM_NONE | capture::OUTPUT_NON_NULL,
            ts_ns,
            ..SemanticCall::default()
        }
    }

    #[test]
    fn init_success_starts_an_initialized_operation() {
        let mut edge = EdgeSemantics::default();
        assert_eq!(edge.observe(&init("C_SignInit", 7, RSA_PSS, 100)), 0);
        assert_eq!(edge.label(), SEMANTIC_OBSERVED);
        assert!(edge.has_live_operations());
        assert_eq!(
            edge.active_summary(),
            vec![("sign".to_string(), OpState::Initialized, 1)]
        );
        assert_eq!(edge.calls(), 1);
        assert_eq!(edge.started(), 1);
        let stat = &edge.mechanisms()[&RSA_PSS];
        assert_eq!(stat.calls, 1);
        assert_eq!(stat.errors, 0);
        assert!(stat.ops.contains("sign"));
        assert_eq!(stat.last_seen_ns, 100);
        assert!(stat.functions.contains("C_SignInit"));
        assert!(stat.returns.contains(&CkRv::OK.0));
        assert!(!stat.truncated);
    }

    #[test]
    fn failed_init_creates_no_operation_and_no_mechanism() {
        let mut edge = EdgeSemantics::default();
        let failed = SemanticCall {
            rv: CkRv::OPERATION_ACTIVE.0,
            ..init("C_SignInit", 7, RSA_PSS, 100)
        };
        edge.observe(&failed);
        assert_eq!(edge.calls(), 1);
        assert_eq!(edge.started(), 0);
        assert!(edge.mechanisms().is_empty());
        assert!(!edge.has_live_operations());
        assert_eq!(edge.label(), SEMANTIC_UNKNOWN_NO_EVIDENCE);
    }

    #[test]
    fn retry_loop_is_n_calls_one_operation() {
        let mut edge = EdgeSemantics::default();
        edge.observe(&init("C_EncryptInit", 7, AES_GCM, 100));
        let mut retry = op("C_EncryptUpdate", 7, 110);
        retry.rv = CkRv::BUFFER_TOO_SMALL.0;
        edge.observe(&retry);
        edge.observe(&op("C_EncryptUpdate", 7, 120));
        edge.observe(&op("C_EncryptFinal", 7, 130));
        assert_eq!(edge.calls(), 4);
        assert_eq!(edge.started(), 1);
        assert_eq!(edge.completed(), 1);
        assert_eq!(edge.cancelled(), 0);
        assert_eq!(edge.failed(), 0);
        assert!(!edge.has_live_operations());
        assert_eq!(edge.mechanisms()[&AES_GCM].calls, 4);
        assert_eq!(edge.mechanisms()[&AES_GCM].errors, 1);
        assert_eq!(edge.mechanisms()[&AES_GCM].last_seen_ns, 130);
    }

    #[test]
    fn size_query_retains_then_retry_completes() {
        let mut edge = EdgeSemantics::default();
        edge.observe(&init("C_SignInit", 7, RSA_PSS, 100));
        let mut query = op("C_Sign", 7, 110);
        query.rv = CkRv::BUFFER_TOO_SMALL.0;
        edge.observe(&query);
        assert!(edge.has_live_operations());
        assert_eq!(
            edge.active_summary(),
            vec![("sign".to_string(), OpState::InProgress, 1)]
        );
        edge.observe(&op("C_Sign", 7, 120));
        assert_eq!((edge.calls(), edge.started(), edge.completed()), (3, 1, 1));
        assert!(!edge.has_live_operations());
    }

    #[test]
    fn init_with_unreadable_mechanism_tracks_an_unknown_mechanism_operation() {
        // F5: a trusted OK Init with an unreadable mechanism still
        // establishes one operation (category + initialized state);
        // its Update/completion advance it with no invented mechanism.
        let mut edge = EdgeSemantics::default();
        let mut unreadable = init("C_SignInit", 7, 0, 100);
        unreadable.capture = capture::MECHANISM_UNREADABLE | capture::OUTPUT_NON_NULL;
        edge.observe(&unreadable);
        assert_eq!(edge.started(), 1);
        assert!(edge.has_live_operations());
        assert!(edge.mechanisms().is_empty(), "no invented mechanism ID");
        assert_eq!(edge.label(), SEMANTIC_OBSERVED);
        edge.observe(&op("C_SignUpdate", 7, 110));
        assert_eq!(
            edge.active_summary(),
            vec![("sign".to_string(), OpState::InProgress, 1)]
        );
        edge.observe(&op("C_SignFinal", 7, 120));
        assert_eq!((edge.started(), edge.completed()), (1, 1));
        assert!(edge.mechanisms().is_empty());
        assert_eq!(edge.orphans(), 0);
    }

    #[test]
    fn null_mechanism_init_cancels_only_for_null_cancel_descriptors() {
        // `C_SignInit` declares null-cancel: NULL stays a genuine
        // cancel (no machine), exactly as before.
        let mut edge = EdgeSemantics::default();
        edge.observe(&init("C_SignInit", 7, RSA_PSS, 100));
        let mut null = init("C_SignInit", 7, 0, 110);
        null.capture = capture::MECHANISM_NULL | capture::OUTPUT_NON_NULL;
        edge.observe(&null);
        assert_eq!(edge.started(), 1);
        assert_eq!(edge.cancelled(), 1);
        assert!(!edge.has_live_operations());
        // `C_MessageSignInit` does not: NULL tracks unknown and counts
        // the capture failure.
        let mut edge = EdgeSemantics::default();
        let mut null = init("C_MessageSignInit", 7, 0, 100);
        null.capture = capture::MECHANISM_NULL | capture::OUTPUT_NON_NULL;
        edge.observe(&null);
        assert_eq!(edge.started(), 1);
        assert!(edge.has_live_operations());
        assert!(edge.mechanisms().is_empty());
        assert_eq!(edge.evidence().semantic_capture_failures, 1);
    }

    #[test]
    fn cross_session_update_never_joins() {
        let mut edge = EdgeSemantics::default();
        edge.observe(&init("C_SignInit", 7, RSA_PSS, 100));
        edge.observe(&op("C_SignUpdate", 8, 110));
        assert_eq!(edge.orphans(), 1);
        assert_eq!(edge.started(), 1);
        assert_eq!(
            edge.active_summary(),
            vec![("sign".to_string(), OpState::Initialized, 1)]
        );
    }

    #[test]
    fn update_without_init_invents_nothing() {
        let mut edge = EdgeSemantics::default();
        edge.observe(&op("C_SignUpdate", 7, 100));
        assert_eq!(edge.orphans(), 1);
        assert_eq!(edge.started(), 0);
        assert!(edge.mechanisms().is_empty());
        assert_eq!(edge.label(), SEMANTIC_UNKNOWN_NO_EVIDENCE);
    }

    #[test]
    fn competing_init_cancels_the_replaced_operation() {
        let mut edge = EdgeSemantics::default();
        edge.observe(&init("C_SignInit", 7, RSA_PSS, 100));
        edge.observe(&init("C_SignInit", 7, AES_GCM, 110));
        assert_eq!(edge.started(), 2);
        assert_eq!(edge.cancelled(), 1);
        assert_eq!(edge.completed(), 0);
        assert!(edge.has_live_operations());
        assert!(edge.mechanisms().contains_key(&RSA_PSS));
        assert!(edge.mechanisms().contains_key(&AES_GCM));
    }

    #[test]
    fn cancel_close_and_finalize_end_as_cancelled_never_completed() {
        let mut edge = EdgeSemantics::default();
        edge.observe(&init("C_SignInit", 7, RSA_PSS, 100));
        edge.observe(&init("C_EncryptInit", 8, AES_GCM, 110));
        let mut cancel = call("C_SessionCancel", 7, CkRv::OK.0, 120);
        cancel.flags = 0x0000_0800; // CKF_SIGN
        edge.observe(&cancel);
        assert_eq!(edge.cancelled(), 1);
        assert!(edge.has_live_operations());
        edge.observe(&call("C_CloseSession", 8, CkRv::OK.0, 130));
        assert_eq!(edge.cancelled(), 2);
        assert_eq!(edge.evidence().unmatched_closes, 1);
        assert!(!edge.has_live_operations());
        edge.observe(&init("C_DigestInit", 9, 0x250, 140));
        edge.observe(&call("C_Finalize", SESSION_NONE, CkRv::OK.0, 150));
        assert_eq!(edge.cancelled(), 3);
        assert_eq!(edge.completed(), 0);
    }

    #[test]
    fn close_all_without_observed_open_ends_machines_unknown() {
        // F4: an Init observed after mid-life attach creates a machine
        // with no proven slot; a successful CloseAllSessions then ends
        // it unknown (slot uncertainty) — never left definitely live,
        // never a proven cancel.
        let mut edge = EdgeSemantics::default();
        edge.observe(&init("C_SignInit", 7, RSA_PSS, 100));
        assert!(edge.has_live_operations());
        edge.observe(&call("C_CloseAllSessions", SESSION_NONE, CkRv::OK.0, 110));
        assert!(!edge.has_live_operations());
        assert_eq!(edge.unknown(), 1);
        assert_eq!(edge.cancelled(), 0);
        assert_eq!(edge.completed(), 0);
        // A session proven on ANOTHER slot is proven unaffected and
        // stays live through this slot's close-all.
        let mut edge = EdgeSemantics::default();
        let mut open = call("C_OpenSession", 8, CkRv::OK.0, 90);
        open.slot_id = 1;
        edge.observe(&open);
        edge.observe(&init("C_SignInit", 8, RSA_PSS, 100));
        edge.observe(&call("C_CloseAllSessions", SESSION_NONE, CkRv::OK.0, 110));
        assert!(edge.has_live_operations());
        assert_eq!(edge.unknown(), 0);
    }

    #[test]
    fn failed_cancel_with_two_flags_clears_and_counts_ambiguity() {
        let mut edge = EdgeSemantics::default();
        edge.observe(&init("C_SignInit", 7, RSA_PSS, 100));
        let mut cancel = call("C_SessionCancel", 7, CkRv::OPERATION_CANCEL_FAILED.0, 110);
        cancel.flags = 0x0000_0800 | 0x0000_0400; // CKF_SIGN | CKF_DIGEST
        edge.observe(&cancel);
        assert_eq!(edge.cancelled(), 1);
        assert_eq!(edge.evidence().session_cancel_ambiguities, 1);
        let mut unknown = call("C_SessionCancel", 7, CkRv::OK.0, 120);
        unknown.flags = 0x8000_0000_0000_0000;
        edge.observe(&unknown);
        assert_eq!(edge.evidence().session_cancel_unknown_flags, 1);
    }

    #[test]
    fn loss_invalidation_ends_unknown_and_keeps_history() {
        let mut edge = EdgeSemantics::default();
        edge.observe(&init("C_SignInit", 7, RSA_PSS, 100));
        edge.observe(&op("C_SignUpdate", 7, 110));
        edge.invalidate();
        assert_eq!(edge.unknown(), 1);
        assert_eq!(edge.completed(), 0);
        assert!(!edge.has_live_operations());
        // Historical claims stand; only "right now" was invalidated.
        assert_eq!(edge.label(), SEMANTIC_OBSERVED);
        assert_eq!(edge.mechanisms()[&RSA_PSS].calls, 2);
    }

    #[test]
    fn pending_init_across_loss_cannot_recreate_definite_state() {
        // F3: a pending Init queued before a loss boundary must not
        // establish an operation when its completion lands after it.
        let mut edge = EdgeSemantics::default();
        let mut pending = init("C_SignInit", 7, RSA_PSS, 100);
        pending.rv = CkRv::PENDING.0;
        edge.observe(&pending);
        edge.invalidate();
        let mut complete = call("C_AsyncComplete", 7, CkRv::OK.0, 110);
        complete.target_function = crate::kinds::function_id("C_SignInit").unwrap();
        edge.observe(&complete);
        assert_eq!(edge.started(), 0, "no operation from pre-loss custody");
        assert_eq!(edge.orphans(), 1);
        assert!(!edge.has_live_operations());
        assert!(edge.mechanisms().is_empty());
    }

    #[test]
    fn detached_completion_across_loss_orphans() {
        // F3: a detached pending Init (GetID issued, completion still
        // outstanding) is custody too: loss kills it, the late
        // completion orphans instead of establishing an operation.
        let mut edge = EdgeSemantics::default();
        edge.observe(&call("C_OpenSession", 7, CkRv::OK.0, 90));
        let mut pending = init("C_SignInit", 7, RSA_PSS, 100);
        pending.rv = CkRv::PENDING.0;
        edge.observe(&pending);
        let init_id = crate::kinds::function_id("C_SignInit").unwrap();
        let mut get_id = call("C_AsyncGetID", 7, CkRv::OK.0, 110);
        get_id.target_function = init_id;
        get_id.async_value = 7;
        edge.observe(&get_id);
        edge.invalidate();
        let mut complete = call("C_AsyncComplete", 7, CkRv::OK.0, 120);
        complete.target_function = init_id;
        edge.observe(&complete);
        assert_eq!(edge.started(), 0, "no operation from pre-loss custody");
        assert_eq!(edge.orphans(), 1);
        assert!(!edge.has_live_operations());
    }

    #[test]
    fn pending_eviction_ends_the_live_owning_machine_unknown() {
        // F3/C2: evicting a pending call whose owning machine is still
        // live ends that machine unknown (its outstanding history is
        // lost) — `async_evictions` alone is not the accounting.
        let mut edge = EdgeSemantics::default();
        edge.observe(&init("C_SignInit", 1, RSA_PSS, 100));
        let mut first = op("C_Sign", 1, 110);
        first.rv = CkRv::PENDING.0;
        edge.observe(&first);
        for session in 2..=(MAX_EDGE_PENDING as u64 + 1) {
            let mut extra = op("C_Sign", session, 110);
            extra.rv = CkRv::PENDING.0;
            edge.observe(&extra);
        }
        assert_eq!(edge.evidence().async_evictions, 1);
        assert_eq!(edge.unknown(), 1, "the owning machine ends unknown");
        assert_eq!(edge.completed(), 0);
        assert!(!edge.has_live_operations());
        // The evicted call's late completion is unattributable now.
        let mut complete = call("C_AsyncComplete", 1, CkRv::OK.0, 200);
        complete.target_function = crate::kinds::function_id("C_Sign").unwrap();
        edge.observe(&complete);
        assert_eq!(edge.orphans(), 1);
        assert_eq!(edge.completed(), 0);
    }

    #[test]
    fn downgrades_render_unknown_with_cause_precedence() {
        let mut edge = EdgeSemantics::default();
        let mut unauthorized = init("C_SignInit", 7, RSA_PSS, 100);
        unauthorized.authorized = false;
        edge.observe(&unauthorized);
        assert_eq!(edge.calls(), 0);
        assert_eq!(edge.label(), SEMANTIC_UNKNOWN_UNAUTHORIZED);

        let mut edge = EdgeSemantics::default();
        let mut ambiguous = init("C_SignInit", 7, RSA_PSS, 100);
        ambiguous.unambiguous = false;
        edge.observe(&ambiguous);
        assert_eq!(edge.label(), SEMANTIC_UNKNOWN_AMBIGUOUS);

        let mut edge = EdgeSemantics::default();
        let mut count_only = init("C_SignInit", 7, RSA_PSS, 100);
        count_only.count_only = true;
        edge.observe(&count_only);
        assert_eq!(edge.label(), SEMANTIC_UNKNOWN_COUNT_ONLY);

        // Unknown function names are count-only, like `kinds` says.
        let mut edge = EdgeSemantics::default();
        edge.observe(&call("C_NotAStandardFunction", 7, CkRv::OK.0, 100));
        assert_eq!(edge.label(), SEMANTIC_UNKNOWN_COUNT_ONLY);

        // Precedence: unauthorized wins over the other downgrades.
        let mut edge = EdgeSemantics::default();
        edge.observe(&count_only);
        edge.observe(&unauthorized);
        assert_eq!(edge.label(), SEMANTIC_UNKNOWN_UNAUTHORIZED);
    }

    #[test]
    fn unattributable_calls_establish_no_claim_and_name_the_double_load() {
        // F7b: calls the edge cannot attribute to one instance (the
        // registry clears `attributable` on double-loaded edges)
        // establish no claim and render the double-load label.
        let mut edge = EdgeSemantics::default();
        let mut first = init("C_SignInit", 7, RSA_PSS, 100);
        first.attributable = false;
        edge.observe(&first);
        let mut second = init("C_EncryptInit", 7, AES_GCM, 120);
        second.attributable = false;
        edge.observe(&second);
        assert_eq!(edge.calls(), 0);
        assert!(!edge.has_claims());
        assert_eq!(edge.label(), SEMANTIC_UNKNOWN_DOUBLE_LOAD);
        // Precedence: the edge-level attribution failure wins over
        // every call-level cause, in both orders.
        let mut unauthorized = init("C_SignInit", 7, RSA_PSS, 100);
        unauthorized.authorized = false;
        let mut edge = EdgeSemantics::default();
        edge.observe(&unauthorized);
        edge.observe(&first);
        assert_eq!(edge.label(), SEMANTIC_UNKNOWN_DOUBLE_LOAD);
        let mut edge = EdgeSemantics::default();
        edge.observe(&first);
        edge.observe(&unauthorized);
        assert_eq!(edge.label(), SEMANTIC_UNKNOWN_DOUBLE_LOAD);
        // Detection dominates history (F7c): claims established
        // before detection keep their COUNTERS, but the label reads
        // unknown from detection on — no retained claim can name its
        // instance. A later single-load note clears the latch and
        // the claims read observed again.
        let mut edge = EdgeSemantics::default();
        edge.observe(&init("C_SignInit", 7, RSA_PSS, 100));
        edge.observe(&op("C_Sign", 7, 110));
        assert_eq!(edge.label(), SEMANTIC_OBSERVED);
        edge.mark_double_load();
        assert_eq!(edge.label(), SEMANTIC_UNKNOWN_DOUBLE_LOAD);
        assert_eq!((edge.started(), edge.completed()), (1, 1));
        edge.observe(&second);
        assert_eq!(edge.label(), SEMANTIC_UNKNOWN_DOUBLE_LOAD);
        assert_eq!((edge.started(), edge.completed()), (1, 1));
        edge.clear_double_load();
        assert_eq!(edge.label(), SEMANTIC_OBSERVED);
    }

    #[test]
    fn direct_call_starts_and_finishes_in_one_call() {
        let mut edge = EdgeSemantics::default();
        edge.observe(&init("C_GenerateKey", 7, AES_GCM, 100));
        assert_eq!((edge.calls(), edge.started(), edge.completed()), (1, 1, 1));
        assert!(!edge.has_live_operations());
        assert!(edge.mechanisms()[&AES_GCM].ops.contains("generate_key"));
        let failed = SemanticCall {
            rv: CkRv::GENERAL_ERROR.0,
            ..init("C_GenerateKey", 7, AES_GCM, 110)
        };
        edge.observe(&failed);
        assert_eq!((edge.calls(), edge.started(), edge.completed()), (2, 1, 1));
    }

    #[test]
    fn pending_call_completes_through_async_complete() {
        let mut edge = EdgeSemantics::default();
        edge.observe(&init("C_SignInit", 7, RSA_PSS, 100));
        let mut pending = op("C_Sign", 7, 110);
        pending.rv = CkRv::PENDING.0;
        edge.observe(&pending);
        assert!(edge.has_live_operations());
        // The pending outcome is unknown: no attribution yet.
        assert_eq!(edge.mechanisms()[&RSA_PSS].calls, 1);
        let mut complete = call("C_AsyncComplete", 7, CkRv::OK.0, 120);
        complete.target_function = crate::kinds::function_id("C_Sign").unwrap();
        edge.observe(&complete);
        assert_eq!((edge.calls(), edge.started(), edge.completed()), (3, 1, 1));
        assert_eq!(edge.mechanisms()[&RSA_PSS].calls, 2);
        assert!(!edge.has_live_operations());
    }

    #[test]
    fn pending_init_creates_its_operation_at_completion() {
        let mut edge = EdgeSemantics::default();
        let mut pending = init("C_SignInit", 7, RSA_PSS, 100);
        pending.rv = CkRv::PENDING.0;
        edge.observe(&pending);
        // A pending Init is not an operation yet: no machine, no
        // mechanism claim — the outcome is still unknown.
        assert_eq!(edge.started(), 0);
        assert!(edge.mechanisms().is_empty());
        assert!(!edge.has_live_operations());
        let mut complete = call("C_AsyncComplete", 7, CkRv::OK.0, 110);
        complete.target_function = crate::kinds::function_id("C_SignInit").unwrap();
        edge.observe(&complete);
        assert_eq!((edge.calls(), edge.started()), (2, 1));
        assert!(edge.has_live_operations());
        assert_eq!(edge.mechanisms()[&RSA_PSS].calls, 1);
        // An error completion is a failed Init: still no operation.
        let mut edge = EdgeSemantics::default();
        edge.observe(&pending);
        let mut failed = call("C_AsyncComplete", 7, CkRv::GENERAL_ERROR.0, 110);
        failed.target_function = crate::kinds::function_id("C_SignInit").unwrap();
        edge.observe(&failed);
        assert_eq!((edge.calls(), edge.started()), (2, 0));
        assert!(edge.mechanisms().is_empty());
    }

    #[test]
    fn pending_direct_completes_at_completion() {
        let mut edge = EdgeSemantics::default();
        let mut pending = init("C_GenerateKey", 7, AES_GCM, 100);
        pending.rv = CkRv::PENDING.0;
        edge.observe(&pending);
        assert_eq!((edge.started(), edge.completed()), (0, 0));
        let mut complete = call("C_AsyncComplete", 7, CkRv::OK.0, 110);
        complete.target_function = crate::kinds::function_id("C_GenerateKey").unwrap();
        edge.observe(&complete);
        assert_eq!((edge.calls(), edge.started(), edge.completed()), (2, 1, 1));
        assert!(edge.mechanisms()[&AES_GCM].ops.contains("generate_key"));
    }

    #[test]
    fn async_join_moves_custody_across_sessions() {
        let mut edge = EdgeSemantics::default();
        edge.observe(&call("C_OpenSession", 7, CkRv::OK.0, 90));
        edge.observe(&call("C_OpenSession", 8, CkRv::OK.0, 95));
        edge.observe(&init("C_SignInit", 7, RSA_PSS, 100));
        let mut pending = op("C_Sign", 7, 110);
        pending.rv = CkRv::PENDING.0;
        edge.observe(&pending);
        let sign_id = crate::kinds::function_id("C_Sign").unwrap();
        let mut get_id = call("C_AsyncGetID", 7, CkRv::OK.0, 120);
        get_id.target_function = sign_id;
        get_id.async_value = 42;
        edge.observe(&get_id);
        // Completion on the originating session replays the detached
        // call against its machine.
        let mut complete = call("C_AsyncComplete", 7, CkRv::OK.0, 130);
        complete.target_function = sign_id;
        edge.observe(&complete);
        assert_eq!(edge.completed(), 1);
        assert_eq!(edge.orphans(), 0);

        // A second operation detaches, then session 8 joins it.
        edge.observe(&init("C_SignInit", 7, RSA_PSS, 140));
        let mut pending = op("C_Sign", 7, 150);
        pending.rv = CkRv::PENDING.0;
        edge.observe(&pending);
        let mut get_id = call("C_AsyncGetID", 7, CkRv::OK.0, 160);
        get_id.target_function = sign_id;
        get_id.async_value = 43;
        edge.observe(&get_id);
        let mut join = call("C_AsyncJoin", 8, CkRv::OK.0, 170);
        join.target_function = sign_id;
        join.async_value = 43;
        edge.observe(&join);
        // Completion on the JOINING session cannot reach the machine
        // on session 7: completions apply on the completing session
        // only (mirroring `complete_pending`), so this orphans rather
        // than joining across sessions — and the machine stays live
        // until session 7 ends it.
        let mut complete = call("C_AsyncComplete", 8, CkRv::OK.0, 180);
        complete.target_function = sign_id;
        edge.observe(&complete);
        assert_eq!(edge.completed(), 1);
        assert_eq!(edge.orphans(), 1);
        assert!(edge.has_live_operations());
        edge.observe(&call("C_CloseSession", 7, CkRv::OK.0, 190));
        assert_eq!(edge.cancelled(), 1);
        // Joining an unissued id invents nothing.
        let mut bogus = call("C_AsyncJoin", 8, CkRv::OK.0, 200);
        bogus.target_function = sign_id;
        bogus.async_value = 44;
        edge.observe(&bogus);
        assert_eq!(edge.orphans(), 2);
    }

    #[test]
    fn completion_after_replacement_init_orphans_rather_than_joining() {
        // F2: Init(M1) → Sign(PENDING) → competing Init(M2) →
        // AsyncComplete(Sign, OK). The stale completion must not
        // finish or attribute to M2's replacement operation.
        let mut edge = EdgeSemantics::default();
        edge.observe(&init("C_SignInit", 7, RSA_PSS, 100));
        let mut pending = op("C_Sign", 7, 110);
        pending.rv = CkRv::PENDING.0;
        edge.observe(&pending);
        edge.observe(&init("C_SignInit", 7, AES_GCM, 120));
        assert_eq!(edge.cancelled(), 1, "replacement cancels M1");
        let mut complete = call("C_AsyncComplete", 7, CkRv::OK.0, 130);
        complete.target_function = crate::kinds::function_id("C_Sign").unwrap();
        edge.observe(&complete);
        assert_eq!(edge.completed(), 0, "stale completion finishes nothing");
        assert_eq!(edge.orphans(), 1, "stale completion is counted");
        assert!(edge.has_live_operations(), "M2's machine stays live");
        // M2's machine completes only via its own call — and the stale
        // call was never attributed to either mechanism.
        edge.observe(&op("C_Sign", 7, 140));
        assert_eq!(edge.completed(), 1);
        assert_eq!(edge.mechanisms()[&AES_GCM].calls, 2);
        assert_eq!(edge.mechanisms()[&RSA_PSS].calls, 1);
    }

    #[test]
    fn joined_completion_into_busy_receiver_orphans() {
        // F2: session 7 detaches a pending Sign; session 8 holds its OWN
        // initialized Sign; session 8 joins, then completes. The joined
        // completion must not consume 8's unrelated machine.
        let mut edge = EdgeSemantics::default();
        edge.observe(&call("C_OpenSession", 7, CkRv::OK.0, 90));
        edge.observe(&call("C_OpenSession", 8, CkRv::OK.0, 95));
        edge.observe(&init("C_SignInit", 7, RSA_PSS, 100));
        let mut pending = op("C_Sign", 7, 110);
        pending.rv = CkRv::PENDING.0;
        edge.observe(&pending);
        let sign_id = crate::kinds::function_id("C_Sign").unwrap();
        let mut get_id = call("C_AsyncGetID", 7, CkRv::OK.0, 120);
        get_id.target_function = sign_id;
        get_id.async_value = 42;
        edge.observe(&get_id);
        edge.observe(&init("C_SignInit", 8, AES_GCM, 130));
        let mut join = call("C_AsyncJoin", 8, CkRv::OK.0, 140);
        join.target_function = sign_id;
        join.async_value = 42;
        edge.observe(&join);
        let mut complete = call("C_AsyncComplete", 8, CkRv::OK.0, 150);
        complete.target_function = sign_id;
        edge.observe(&complete);
        assert_eq!(edge.completed(), 0, "joined completion consumes nothing");
        assert_eq!(edge.orphans(), 1);
        assert_eq!(
            edge.active_summary(),
            vec![("sign".to_string(), OpState::Initialized, 2)],
            "both sessions' machines stay live"
        );
        // Each session ends its own operation normally afterwards.
        edge.observe(&op("C_Sign", 7, 160));
        edge.observe(&op("C_Sign", 8, 170));
        assert_eq!(edge.completed(), 2);
    }

    #[test]
    fn message_based_flow_tracks_its_own_categories() {
        let mut edge = EdgeSemantics::default();
        edge.observe(&init("C_MessageSignInit", 7, RSA_PSS, 100));
        assert_eq!(
            edge.active_summary(),
            vec![("message_sign".to_string(), OpState::Initialized, 1)]
        );
        edge.observe(&op("C_SignMessage", 7, 110));
        assert!(edge.has_live_operations());
        edge.observe(&op("C_MessageSignFinal", 7, 120));
        assert_eq!((edge.calls(), edge.started(), edge.completed()), (3, 1, 1));
        assert!(edge.mechanisms()[&RSA_PSS].ops.contains("message_sign"));
    }

    #[test]
    fn error_termination_ends_failed_and_reconciles() {
        let mut edge = EdgeSemantics::default();
        edge.observe(&init("C_VerifyInit", 7, RSA_PSS, 100));
        edge.observe(&call("C_Verify", 7, CkRv::SIGNATURE_INVALID.0, 110));
        assert_eq!(edge.failed(), 1);
        assert_eq!(edge.completed(), 0);
        edge.observe(&init("C_SignInit", 7, RSA_PSS, 120));
        edge.observe(&call("C_Sign", 7, CkRv::OPERATION_NOT_INITIALIZED.0, 130));
        assert_eq!(edge.unknown(), 1);
        assert_eq!(edge.evidence().state_reconciliations, 1);
        assert!(!edge.has_live_operations());
    }

    #[test]
    fn bounds_refuse_new_keys_with_accounting() {
        let mut edge = EdgeSemantics::default();
        let mut refused = 0;
        for index in 0..(MAX_EDGE_MECHANISMS + 5) {
            refused += edge.observe(&init("C_SignInit", 7, 0x1000 + index as u64, 100));
        }
        assert_eq!(edge.mechanisms().len(), MAX_EDGE_MECHANISMS);
        assert_eq!(edge.dropped(), 5);
        assert_eq!(refused, 5, "observe reports this call's refusals");
    }

    #[test]
    fn rv_names_come_from_the_registered_table() {
        assert_eq!(rv_name(CkRv::OK.0), Some("CKR_OK".to_string()));
        assert_eq!(
            rv_name(CkRv::BUFFER_TOO_SMALL.0),
            Some("CKR_BUFFER_TOO_SMALL".to_string())
        );
        assert_eq!(rv_name(0xdead_beef), None);
    }
}
