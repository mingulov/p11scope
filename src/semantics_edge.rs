//! SPDX-License-Identifier: GPL-3.0-or-later
//! SPDX-FileCopyrightText: 2026 Denis Mingulov <denis@mingulov.com>
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

use crate::keymeta::{CompletionEvidence, LengthOutcome};
use crate::semantics::{cancel_operation_mask, direct_cancel_flag};
use crate::semantics_objects::journal::LeafBudget;
use p11scope_ebpf_common::{
    FUNCTION_NONE, SESSION_NONE, SlotSemantics, USER_TYPE_NONE, capture, direct, lifecycle,
    semantic_flags, transition,
};
use pkcs11_types::CkRv;
use std::collections::{BTreeMap, BTreeSet};

#[path = "semantics_edge/resources.rs"]
pub(crate) mod resources;
use resources::{ResourceLease, ScratchLease, SemanticResourcePool, SemanticResourceRefusal};

struct PreparedResourceTransition {
    reservation: ResourceLease,
    _scratch: ScratchLease,
}

/// Per-edge bounds. New keys past a bound are REFUSED (counted in
/// [`EdgeProjection::dropped`] and the registry's `semantic_refused`),
/// never evicting retained facts — the inventory rule that refusal
/// never erases retained evidence. Pending/detached async records are
/// the one exception: like the capture-wide reducer they evict oldest
/// past the bound, counted in `async_evictions`.
pub(crate) const MAX_EDGE_SESSIONS: usize = 1024;
pub(crate) const MAX_EDGE_MECHANISMS: usize = 256;
// One active op machine per occupant plus headroom: the room's
// 4,096 begins plus held associations exceed 4,096 occupants
// (raised 2,048 to 8,192 with MAX_UNSETTLED_STAGED, keeping the
// 2x ratio).
pub(crate) const MAX_EDGE_ACTIVE_OPS: usize = 8192;
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
    /// machine exactly, across sessions (F2). Checked allocation:
    /// exhaustion refuses the new identity (counted in
    /// [`EdgeSemantics::id_exhaustions`]) instead of wrapping.
    generation: u64,
    /// At most one fixed key receipt for the `Init` that started
    /// this machine (H9): bound positionally at replay, fixed for
    /// the machine's life, `None` for S1Only or unassociated starts.
    key: Option<KeyReceipt>,
    /// Per-operation corroboration slot (keymeta §5.4): the latest
    /// retained `BUFFER_TOO_SMALL` length on this machine. Query
    /// values never land here (dropped on arrival); failures and
    /// cancellation clear it with the machine.
    corroboration: Option<u64>,
}

/// Reducer-local checked operation identity: the reducer is per exact
/// instance/era, so this ordinal identifies the operation within that
/// incarnation. Minted only by checked allocation at the start/direct
/// mutation sites; never wraps, never recycles, never a raw handle or
/// an output key identity (H9).
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub(crate) struct OperationId(u64);

impl OperationId {
    #[cfg(test)]
    pub(crate) fn ordinal_for_test(self) -> u64 {
        self.0
    }

    #[cfg(test)]
    pub(crate) fn from_ordinal_for_test(value: u64) -> Self {
        Self(value)
    }
}

/// How one tracked operation ended, as reported on
/// [`OperationEffect::Ended`]: the public projection of the private
/// end states below.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum OperationOutcome {
    Completed,
    Cancelled,
    Failed,
    Unknown,
}

/// Identity of the source call one [`OperationEffect`] belongs to. The
/// registry supplies the consumed call's origin to
/// [`EdgeSemantics::observe_with_effects`]; async completions carry
/// their ORIGINAL call's identity (never the receiver's). Presence of
/// an origin is not object authority — only a positional key receipt
/// can bind a key (H9). Redacted `Debug`: raw session handles never
/// render.
#[derive(Clone, PartialEq, Eq)]
pub(crate) struct EffectOrigin {
    pub function: String,
    pub session: u64,
    pub ts_ns: u64,
}

impl std::fmt::Debug for EffectOrigin {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("EffectOrigin(<private facts>)")
    }
}

/// The role one positional key receipt plays in its call (H9): the
/// input's meaning, never an inferred label. Assigned by
/// (descriptor action, function, input ordinal); anything outside
/// the classified vocabulary is [`KeyRole::Other`] with explicit
/// evidence, never a guessed role.
// Guarded (N1): values flow through the Joint receipt pipeline once
// installed receipts + an H8 driver exist; unreachable while feeds
// stay S1Only.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum KeyRole {
    /// A single-input operation key (`*Init`, `C_DigestKey`).
    OperationKey,
    /// `C_WrapKey` input 0: the key that wraps.
    WrappingKey,
    /// `C_WrapKey` input 1: the key being wrapped.
    WrappedKey,
    /// `C_DeriveKey` input 0: the base key.
    BaseKey,
    /// `C_UnwrapKey` input 0: the unwrapping key.
    UnwrappingKey,
    /// `C_EncapsulateKey` input 0: the encapsulation key.
    EncapsulationKey,
    /// `C_DecapsulateKey` input 0: the decapsulation key.
    DecapsulationKey,
    /// Outside the classified vocabulary: counted, never guessed.
    Other,
}

/// One positional key receipt (H9): the model's qualified exact
/// observation for one call input, bound positionally at replay —
/// never callback position, never an inferred label. The key is the
/// opaque exact observation (never a raw handle); metadata is a
/// presence snapshot (never values).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct KeyReceipt {
    /// The qualified exact key observation.
    pub key: crate::semantics_objects::ObjectId,
    /// Catalog id of the referencing call.
    pub function: u32,
    /// Input ordinal within the call (minted at the qualified join).
    pub input: u8,
    /// The input's role.
    pub role: KeyRole,
    /// H0 ordinal of the referencing call.
    pub position: u64,
    /// Metadata presence known by (not after) the transition.
    pub metadata: crate::semantics_objects::KeyMetadataFlags,
    /// Established-only combined label snapshot (sizes/curve, never
    /// key material): `None` when unestablished at use.
    pub label: Option<crate::semantics_objects::KeyLabel>,
    /// Established key-type code snapshot (keymeta §4.5 left side):
    /// `Some` when the key type is established non-conflicting at
    /// use, even without a combined label.
    pub key_type: Option<u16>,
    /// Whether the viewed attribution was valid at use (H9 §72: a
    /// label needs valid attribution plus non-conflicting fields).
    pub attribution_valid: bool,
    /// The viewed object's origin is first-observed (its creation
    /// or lookup predates the observed window; late attach).
    pub first_observed: bool,
    /// Set when retirement ends this association before the S1
    /// terminal (H9 §66 `key_join_lost`); never backfilled.
    pub lost: bool,
}

impl From<&SemanticCall> for EffectOrigin {
    fn from(call: &SemanticCall) -> Self {
        Self {
            function: call.function.clone(),
            session: call.session,
            ts_ns: call.ts_ns,
        }
    }
}

impl EffectOrigin {
    /// Allocation-free placeholder (`String::new` never allocates):
    /// consumed only where `S::WANTS_EFFECTS` is false — never read
    /// there, since every emit site is gated — so plain observation
    /// builds no origins.
    fn placeholder() -> Self {
        Self {
            function: String::new(),
            session: SESSION_NONE,
            ts_ns: 0,
        }
    }
}

/// One typed operation transition, emitted at the exact reducer
/// mutation site that changed the counters — never reconstructed from
/// aggregates (H9). `Started` fires at machine start (replacement
/// emits the old `Ended` first); `Ended` at every end site including
/// replacement, retirement, eviction and loss; `DirectCompleted` is
/// the one atomic effect of a successful direct call (start and
/// completion together — a failed direct call emits nothing).
/// `Started` carries the machine's fixed key receipt (`None` for
/// S1Only or unassociated starts); `DirectCompleted` carries the
/// call's positional receipts (at most two); `Ended` joins by id.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum OperationEffect {
    Started {
        id: OperationId,
        category: &'static str,
        mechanism: Option<u64>,
        key_receipt: Option<KeyReceipt>,
        origin: EffectOrigin,
    },
    Ended {
        id: OperationId,
        category: &'static str,
        outcome: OperationOutcome,
        origin: EffectOrigin,
        /// Terminal length evidence for this completion (keymeta §9):
        /// `Some` only on `Completed` terminals of evidence calls.
        length: Option<crate::keymeta::LengthOutcome>,
        /// Retained corroboration from an earlier `BUFFER_TOO_SMALL`
        /// on this operation (§5.4): the reducer compares it against
        /// the terminal and counts mismatches, never conflicts.
        corroboration: Option<u64>,
    },
    DirectCompleted {
        id: OperationId,
        category: &'static str,
        mechanism: Option<u64>,
        key_receipts: Vec<KeyReceipt>,
        origin: EffectOrigin,
        /// Terminal length evidence for this direct call (keymeta
        /// §9): `Some` on evidence calls (directs emit only on OK).
        length: Option<crate::keymeta::LengthOutcome>,
        /// Exact-one fresh result view for result-creating directs
        /// (the unwrap U1 park, §5.4); `None` unless the seal proved
        /// exactly one created view for this call.
        fresh_view: Option<u64>,
    },
}

/// Receiver for [`OperationEffect`]s. [`EdgeSemantics::observe`]
/// reduces with [`NoSink`] (zero-cost: every emit site is gated on
/// [`OperationSink::WANTS_EFFECTS` and monomorphized away — plain
/// observation allocates nothing for effects);
/// [`EdgeSemantics::observe_with_effects`] drives a live sink with the
/// same single pass — never a second reducer run.
pub(crate) trait OperationSink {
    /// Whether effects are consumed. `false` eliminates every emit
    /// site at compile time, including its origin construction.
    const WANTS_EFFECTS: bool = true;
    fn emit(&mut self, effect: OperationEffect);
}

/// The effect-free sink: plain observation.
pub(crate) struct NoSink;

impl OperationSink for NoSink {
    const WANTS_EFFECTS: bool = false;
    fn emit(&mut self, _effect: OperationEffect) {}
}

impl OperationSink for Vec<OperationEffect> {
    fn emit(&mut self, effect: OperationEffect) {
        self.push(effect);
    }
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
#[derive(Debug)]
struct PendingCall {
    call: SemanticCall,
    origin: CallOrigin,
    /// Originating H0 admission position for Joint-replayed
    /// originals; `None` for S1Only or unassociated starts. The
    /// Activation compares this to the redeemed origin's position:
    /// same origin means equal positions.
    /// First production reader lands with the Activation's receipt gate.
    #[cfg_attr(not(test), allow(dead_code))]
    origin_pos: Option<u64>,
    sequence: u64,
    // Payload fields precede the move-only owner: refund after destruction.
    resource: Option<ResourceLease>,
}

/// An issued async id: which session holds it (`None` floats —
/// joinable, a live state, not a dead one) plus the detached call
/// itself and its queue-time operation lifetime (F2, carried over
/// from the pending record — never re-snapshotted, so a completion
/// cannot adopt a machine created after the call was queued).
#[derive(Debug)]
struct AsyncId {
    owner: Option<u64>,
    call: SemanticCall,
    origin: CallOrigin,
    /// The pending record's H0 position, carried over at the GetID
    /// mint — never re-snapshotted, like `origin`.
    /// First production reader lands with the Activation's receipt gate.
    #[cfg_attr(not(test), allow(dead_code))]
    origin_pos: Option<u64>,
    sequence: u64,
    resource: Option<ResourceLease>,
}

/// Same-origin check for an S1 async record against a redeemed
/// origin (CP-3a groundwork): both sides must carry the origin's H0
/// position and they must be equal. An unknown (S1Only) side never
/// confirms.
#[cfg_attr(not(test), allow(dead_code))] // First production caller: the Activation's receipt gate.
fn same_origin_position(stored: Option<u64>, redeemed: Option<u64>) -> bool {
    matches!((stored, redeemed), (Some(a), Some(b)) if a == b)
}

/// First-wins PENDING routing (§3.5): preflight reserves exactly the
/// `Fresh` insertion charge; execution orphans the rest.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum PendingRoute {
    /// Unknown function or a session-less OPEN_SESSION: orphans,
    /// grows nothing.
    Unroutable,
    /// A live (session, target) already holds custody: first wins
    /// with counted ambiguity, grows nothing.
    Duplicate,
    /// A new fact will queue.
    Fresh {
        function: u32,
        descriptor: SlotSemantics,
        charge: usize,
    },
}

/// Exactly-one completion eligibility (§3.3): preflight reserves the
/// unique record's replay growth only; execution consumes it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum CompleteEligible {
    /// No record: orphans, grows nothing.
    Zero,
    /// Two or more records: ambiguous, orphans with evidence and
    /// consumes none, grows nothing.
    Many,
    /// The unique pending (session, target) record.
    Pending((u64, u32)),
    /// The unique detached (slot, target, value) record.
    Detached((u64, u32, crate::semantics_objects::AsyncValue)),
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
    detached: BTreeMap<(u64, u32, crate::semantics_objects::AsyncValue), AsyncId>,
    sequence: u64,
    /// Next operation-machine generation (F2/H9): every machine and
    /// every direct operation takes a fresh value via checked
    /// allocation, so generations identify lifetimes edge-wide and
    /// never wrap or recycle.
    machine_seq: u64,
    /// New identities refused past `u64::MAX`: the affected Init
    /// counts started-then-unknown (no machine, no effect); an
    /// exhausted direct call keeps its definite in-call completion
    /// but emits no effect. Conservation reads effects against
    /// counters minus this term.
    id_exhaustions: u64,
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
    resource_transition: Option<PreparedResourceTransition>,
    // Drop order is declaration order. Keep the base/history owner after
    // every container, so a different reducer cannot spend an early refund.
    resource_owner: Option<ResourceLease>,
    /// Test-only unified budgeted-read counter: every edge-map lookup
    /// on a budgeted path (retire scan visits, decision lookups, peek
    /// classifications, pending admission/eviction visits). Incremented
    /// at the actual read site so per-poll `reads <= spent` assertions
    /// observe real reads, never the debit. Unbudgeted (live S1) paths
    /// bump it too; tests reset around the measured region.
    #[cfg(test)]
    test_edge_reads: std::cell::Cell<usize>,
}

impl Drop for EdgeSemantics {
    fn drop(&mut self) {
        // Pop owned async facts only after BTreeMap has finished removal and
        // rebalancing. BTreeMap::clear drops values while destroying nodes;
        // a value-local lease must not refund against that unfinished drop.
        self.invalidate();
        self.mechs.clear();
    }
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

/// Counts of owned S1 state. B-tree nodes have no public capacity accessor;
/// their actual allocation costs are measured by the isolated host probe.
/// These counts contain no handles, function names, or return-code values.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub(crate) struct S1Occupancy {
    pub open_bindings: usize,
    pub active_machines: usize,
    pub pending_calls: usize,
    pub detached_calls: usize,
    pub mechanisms: usize,
    pub operation_categories: usize,
    pub provenance_functions: usize,
    pub provenance_function_bytes: usize,
    pub provenance_function_capacity_bytes: usize,
    pub provenance_returns: usize,
    pub async_function_bytes: usize,
    pub async_function_capacity_bytes: usize,
    pub origin_vectors: usize,
    pub origin_elements: usize,
    pub origin_capacity_elements: usize,
}

impl EdgeSemantics {
    /// A0 lens (R3): this edge's session/operation/mechanism maps.
    /// Read-only; O(structures).
    pub(crate) fn memory_lens(&self) -> crate::memory_counters::EdgeLens {
        use crate::memory_counters::{HEAP_MAP_ENTRY, HEAP_MECH_ROW, counter_row};
        use std::mem::size_of;
        crate::memory_counters::EdgeLens {
            open: counter_row(self.open.len(), size_of::<(u64, u64)>(), HEAP_MAP_ENTRY),
            active: counter_row(
                self.active.len(),
                size_of::<((u64, u16), OpMachine)>(),
                HEAP_MAP_ENTRY,
            ),
            mechs: counter_row(
                self.mechs.len(),
                size_of::<(u64, EdgeMechStat)>(),
                HEAP_MECH_ROW,
            ),
            pending: counter_row(
                self.pending.len(),
                size_of::<((u64, u32), PendingCall)>(),
                HEAP_MAP_ENTRY,
            ),
            detached: counter_row(
                self.detached.len(),
                size_of::<((u64, u32, crate::semantics_objects::AsyncValue), AsyncId)>(),
                HEAP_MAP_ENTRY,
            ),
        }
    }

    pub(crate) fn with_resources(
        pool: &SemanticResourcePool,
    ) -> Result<Self, SemanticResourceRefusal> {
        let owner = pool.reserve(resources::REDUCER_BASE_CHARGE)?;
        let mut reducer = Self::default();
        reducer.resource_owner = Some(owner);
        Ok(reducer)
    }

    pub(crate) fn observe_with_resources(
        &mut self,
        call: &SemanticCall,
    ) -> Result<u64, SemanticResourceRefusal> {
        let prepared = match self.prepare_resource_transition(call) {
            Ok(prepared) => prepared,
            Err(refusal) => {
                self.invalidate();
                return Err(refusal);
            }
        };
        assert!(self.resource_transition.is_none());
        self.resource_transition = Some(prepared);
        let refused = self.observe(call);
        drop(self.resource_transition.take());
        Ok(refused)
    }

    /// The same resourced observation, plus typed transition
    /// notifications into `sink`: the guarded Joint arm's
    /// S1Only-direct reduction (sibling facts under Joint, or Joint
    /// staging fallback). Unreached while no Joint feed exists.
    pub(crate) fn observe_with_resources_and_effects<S: OperationSink>(
        &mut self,
        call: &SemanticCall,
        origin: &EffectOrigin,
        sink: &mut S,
    ) -> Result<u64, SemanticResourceRefusal> {
        let prepared = match self.prepare_resource_transition(call) {
            Ok(prepared) => prepared,
            Err(refusal) => {
                self.invalidate();
                return Err(refusal);
            }
        };
        assert!(self.resource_transition.is_none());
        self.resource_transition = Some(prepared);
        let refused = self.observe_with_effects(call, origin, sink);
        drop(self.resource_transition.take());
        Ok(refused)
    }

    fn prepare_resource_transition(
        &self,
        call: &SemanticCall,
    ) -> Result<PreparedResourceTransition, SemanticResourceRefusal> {
        let owner = self
            .resource_owner
            .as_ref()
            .expect("budgeted ingress requires an admitted reducer");
        Ok(PreparedResourceTransition {
            _scratch: owner.scratch()?,
            reservation: owner.reserve(self.preflight_growth(call))?,
        })
    }

    fn take_resource_charge(&mut self, bytes: usize) -> Option<ResourceLease> {
        self.resource_transition
            .as_mut()
            .map(|prepared| prepared.reservation.split(bytes))
    }

    fn retain_resource_charge(&mut self, bytes: usize) {
        if let Some(lease) = self.take_resource_charge(bytes) {
            self.resource_owner
                .as_mut()
                .expect("admitted owner")
                .absorb(lease);
        }
    }

    fn release_resource_charge(&mut self, bytes: usize) {
        if let Some(owner) = self.resource_owner.as_mut() {
            owner.release(bytes);
        }
    }

    /// First-wins PENDING routing shared by preflight and execution
    /// (§3.5): at most one live fact per (session, target).
    fn route_pending(&self, call: &SemanticCall) -> PendingRoute {
        let descriptor =
            crate::kinds::descriptor(&call.function).unwrap_or(SlotSemantics::COUNT_ONLY);
        let Some(function) = crate::kinds::function_id(&call.function) else {
            return PendingRoute::Unroutable;
        };
        if descriptor.lifecycle == lifecycle::OPEN_SESSION && call.session == SESSION_NONE {
            return PendingRoute::Unroutable;
        }
        // No test bump here: the budgeted admission cursor charges and
        // counts this lookup at its own read site; the synchronous
        // path stays unbumped.
        if self.pending.contains_key(&(call.session, function)) {
            return PendingRoute::Duplicate;
        }
        let charge = Self::async_charge(call, &descriptor);
        PendingRoute::Fresh {
            function,
            descriptor,
            charge,
        }
    }

    /// Exactly-one completion eligibility shared by preflight and
    /// execution (§3.3): the pending (session, target) plus detached
    /// ids owned by the completer for that target.
    fn complete_eligible(&self, session: u64, target: u32) -> CompleteEligible {
        let pending_key = (session, target);
        let has_pending = self.pending.contains_key(&pending_key);
        let mut detached_match = None;
        let mut detached_count = 0usize;
        for (key, id) in &self.detached {
            if id.owner == Some(session) && key.1 == target {
                detached_count += 1;
                detached_match = Some(*key);
            }
        }
        let eligible = usize::from(has_pending) + detached_count;
        if eligible != 1 {
            return if eligible >= 2 {
                CompleteEligible::Many
            } else {
                CompleteEligible::Zero
            };
        }
        if has_pending {
            CompleteEligible::Pending(pending_key)
        } else {
            CompleteEligible::Detached(detached_match.expect("sole eligible record"))
        }
    }

    // Inspect the incoming descriptor and touched keys only. No allocation,
    // accumulated provenance scan, deletion credit or cloned reducer.
    fn preflight_growth(&self, call: &SemanticCall) -> usize {
        if !call.attributable || !call.authorized || !call.unambiguous || call.count_only {
            return 0;
        }
        let descriptor =
            crate::kinds::descriptor(&call.function).unwrap_or(SlotSemantics::COUNT_ONLY);
        if descriptor == SlotSemantics::COUNT_ONLY {
            return 0;
        }
        if descriptor.lifecycle == lifecycle::ASYNC_COMPLETE {
            if call.rv == CkRv::PENDING.0
                || call.target_function == FUNCTION_NONE
                || call.capture & capture::ASYNC_VALUE_UNREADABLE != 0
            {
                return 0;
            }
            // Shared exactly-one eligibility with execution (§3.3):
            // zero or ambiguous completions grow nothing.
            let original = match self.complete_eligible(call.session, call.target_function) {
                CompleteEligible::Pending(key) => {
                    let record = &self.pending[&key];
                    (&record.call, &record.origin)
                }
                CompleteEligible::Detached(key) => {
                    let record = &self.detached[&key];
                    (&record.call, &record.origin)
                }
                CompleteEligible::Zero | CompleteEligible::Many => return 0,
            };
            if !self.origin_matches(call.session, original.1) {
                return 0;
            }
            return self.completed_growth(original.0, call.session, call.rv);
        }
        if matches!(
            descriptor.lifecycle,
            lifecycle::ASYNC_GET_ID | lifecycle::ASYNC_JOIN
        ) {
            return 0;
        }
        if call.rv == CkRv::PENDING.0 {
            // Shared first-wins routing with execution (§3.5):
            // unroutable and duplicate PENDINGs grow nothing.
            match self.route_pending(call) {
                PendingRoute::Fresh { charge, .. } => return charge,
                PendingRoute::Unroutable | PendingRoute::Duplicate => return 0,
            }
        }
        self.completed_growth(call, call.session, call.rv)
    }

    fn async_charge(call: &SemanticCall, descriptor: &SlotSemantics) -> usize {
        let count = descriptor.operations.count_ones() as usize;
        let origin = if count == 0 {
            0
        } else {
            count.next_power_of_two().max(4) * std::mem::size_of::<(u16, Option<u64>)>()
                + resources::OWNED_ALLOCATION_PADDING
        };
        resources::ASYNC_FACT_CHARGE
            + call.function.len()
            + resources::OWNED_ALLOCATION_PADDING
            + origin
    }

    fn provenance_growth(&self, mechanism: u64, call: &SemanticCall, rv: u64) -> usize {
        let stat = self.mechs.get(&mechanism);
        if stat.is_none() && self.mechs.len() >= MAX_EDGE_MECHANISMS {
            return 0;
        }
        let mut bytes = if stat.is_none() {
            resources::MECHANISM_CHARGE
        } else {
            0
        };
        if stat.is_none_or(|s| {
            !s.functions.contains(&call.function)
                && s.functions.len() < MAX_EDGE_PROVENANCE_FUNCTIONS
        }) {
            bytes += resources::FUNCTION_CHARGE
                + call.function.len()
                + resources::OWNED_ALLOCATION_PADDING;
        }
        if stat.is_none_or(|s| {
            !s.returns.contains(&rv) && s.returns.len() < MAX_EDGE_PROVENANCE_RETURNS
        }) {
            bytes += resources::RETURN_CHARGE;
        }
        bytes
    }

    fn completed_growth(&self, call: &SemanticCall, session: u64, rv: u64) -> usize {
        let descriptor =
            crate::kinds::descriptor(&call.function).unwrap_or(SlotSemantics::COUNT_ONLY);
        let init = descriptor.transition == transition::INITIALIZE;
        let mut bytes = 0;
        // Claims precede reconciliation in the real transition pipeline.
        if (init || descriptor.direct != direct::NONE)
            && rv == CkRv::OK.0
            && call.mechanism_capture() == capture::MECHANISM_VALUE
            && (self.mechs.contains_key(&call.mechanism) || self.mechs.len() < MAX_EDGE_MECHANISMS)
        {
            bytes += self.provenance_growth(call.mechanism, call, rv);
            let stat = self.mechs.get(&call.mechanism);
            for (_, name) in crate::semantics::operation_bits(descriptor.operations) {
                if stat.is_none_or(|s| !s.ops.contains(name)) {
                    bytes += resources::CATEGORY_CHARGE;
                }
            }
            if let Some(name) = crate::semantics::direct_name(descriptor.direct)
                && stat.is_none_or(|s| !s.ops.contains(name))
            {
                bytes += resources::CATEGORY_CHARGE;
            }
        }
        if matches!(rv, x if x == CkRv::OPERATION_NOT_INITIALIZED.0 || x == CkRv::SESSION_CLOSED.0
            || x == CkRv::SESSION_HANDLE_INVALID.0 || x == CkRv::CRYPTOKI_NOT_INITIALIZED.0)
        {
            return bytes;
        }
        if descriptor.lifecycle == lifecycle::OPEN_SESSION
            && rv == CkRv::OK.0
            && session != SESSION_NONE
            && (self.open.contains_key(&session) || self.open.len() < MAX_EDGE_SESSIONS)
        {
            bytes += resources::OPEN_BINDING_CHARGE;
        }
        if init
            && rv == CkRv::OK.0
            && session != SESSION_NONE
            && !(call.mechanism_capture() == capture::MECHANISM_NULL
                && descriptor.semantic_flags & semantic_flags::NULL_MECHANISM_CANCEL != 0)
        {
            let mut additions = 0;
            for (bit, _) in crate::semantics::operation_bits(descriptor.operations) {
                if !self.active.contains_key(&(session, bit))
                    && self.active.len() + additions < MAX_EDGE_ACTIVE_OPS
                {
                    bytes += resources::ACTIVE_MACHINE_CHARGE;
                    additions += 1;
                }
            }
        } else if !init && descriptor.direct == direct::NONE && descriptor.operations != 0 {
            // A descriptor can touch multiple machines carrying one mechanism.
            // Fixed scalar storage deduplicates only this call's bounded bits.
            let mut seen = [None; 16];
            let mut count = 0;
            for (bit, _) in crate::semantics::operation_bits(descriptor.operations) {
                if let Some(mechanism) = self.active.get(&(session, bit)).and_then(|m| m.mechanism)
                    && !seen[..count].contains(&Some(mechanism))
                {
                    seen[count] = Some(mechanism);
                    count += 1;
                    bytes += self.provenance_growth(mechanism, call, rv);
                }
            }
        }
        bytes
    }

    pub(crate) fn resource_usage(&self) -> S1Occupancy {
        let mut usage = S1Occupancy {
            open_bindings: self.open.len(),
            active_machines: self.active.len(),
            pending_calls: self.pending.len(),
            detached_calls: self.detached.len(),
            mechanisms: self.mechs.len(),
            ..S1Occupancy::default()
        };
        for stat in self.mechs.values() {
            usage.operation_categories += stat.ops.len();
            usage.provenance_functions += stat.functions.len();
            usage.provenance_returns += stat.returns.len();
            for function in &stat.functions {
                usage.provenance_function_bytes += function.len();
                usage.provenance_function_capacity_bytes += function.capacity();
            }
        }
        for (call, origin) in self
            .pending
            .values()
            .map(|p| (&p.call, &p.origin))
            .chain(self.detached.values().map(|id| (&id.call, &id.origin)))
        {
            usage.async_function_bytes += call.function.len();
            usage.async_function_capacity_bytes += call.function.capacity();
            usage.origin_vectors += 1;
            usage.origin_elements += origin.bits.len();
            usage.origin_capacity_elements += origin.bits.capacity();
        }
        usage
    }
}

#[cfg(all(test, target_os = "linux", target_env = "gnu"))]
#[path = "semantics_edge/resource_tests.rs"]
pub(crate) mod resource_tests;

#[cfg(all(test, target_os = "linux", target_env = "gnu"))]
#[path = "semantics_edge/budget_tests.rs"]
mod budget_tests;

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

impl EndState {
    fn outcome(self) -> OperationOutcome {
        match self {
            Self::Completed => OperationOutcome::Completed,
            Self::Cancelled => OperationOutcome::Cancelled,
            Self::Failed => OperationOutcome::Failed,
            Self::Unknown => OperationOutcome::Unknown,
        }
    }
}

/// Resumable budgeted invalidation cursor: drains active machines
/// one per leaf, then pending/detached payloads and open bindings.
/// Held by the disposal across credits; the edge maps themselves
/// retain the remaining entries (pop reduces, no snapshot).
pub(crate) struct EdgeInvalidationCursor {
    phase: EdgeInvalidationPhase,
    origin: EffectOrigin,
    end: EndState,
    count_reconciliations: bool,
    changed: bool,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum EdgeInvalidationPhase {
    Active,
    Pending,
    Detached,
    Open,
    Done,
}

/// Budgeted retire scope for one staged lifecycle call during
/// disposal (All retires use [`EdgeInvalidationCursor`] with
/// `end_unknown=false`; these cover the subset scopes). Mirrors the
/// synchronous `retire_session` / `end_session_machines` /
/// `clear_selected` / CLOSE_ALL / LOGIN conditions; the peek
/// [`EdgeSemantics::would_retire_scope`] shares the pure condition
/// helpers so the two cannot drift.
/// Post-retire action for one session scope (mirrors the
/// synchronous arms' evidence counts and open inserts; counts are
/// O(1) integer increments, free; the OPEN insert charges 1 leaf).
#[derive(Debug, Clone, Copy)]
pub(crate) enum SessionPost {
    /// CLOSE_SESSION OK: count unmatched_closes when no open existed.
    Close,
    /// SESSION_CLOSED/HANDLE_INVALID reconcile: count
    /// state_reconciliations when anything retired.
    Reconcile,
    /// OPEN_SESSION OK reuse: insert the new open (session→slot) with
    /// headroom counting (dropped when full).
    Open { slot: u64 },
}

#[derive(Debug, Clone)]
pub(crate) enum EdgeRetireScope {
    /// One session: forget its open, end its machines as `end_unknown`
    /// (false=Cancelled), drop its pendings, float its async ids,
    /// then apply `post`. Covers CLOSE_SESSION OK (`Close`),
    /// SESSION_CLOSED/HANDLE_INVALID (`Reconcile`), OPEN_SESSION
    /// handle reuse (`Open`, Unknown).
    Session {
        session: u64,
        end_unknown: bool,
        post: SessionPost,
    },
    /// One session's machines only (no open/pending/async): covers
    /// SET_OPERATION_STATE OK (counts operation_state_imports after).
    SessionMachines { session: u64, end_unknown: bool },
    /// Sessions on one slot: end owned machines as Cancelled, drop
    /// owned pendings, float owned async, forget owned opens. When
    /// `close_all` also ends unproven sessions (active/pending with
    /// no open) as Unknown (CLOSE_ALL_SESSIONS OK); otherwise owned
    /// only (LOGIN/LOGOUT OK/PIN_LOCKED).
    Slot { slot: u64, close_all: bool },
    /// Selected machines/pendings/async on one session by cancel
    /// flags (SESSION_CANCEL OK / OPERATION_CANCEL_FAILED ambiguity
    /// when `ambiguous`).
    Selected {
        session: u64,
        flags: u64,
        ambiguous: bool,
    },
}

/// Resumable budgeted retire cursor for one staged head's subset
/// scope: scans active/pending/detached/open incrementally with
/// `done_upto` positions (no snapshot allocation), one leaf per
/// visited entry (plus one per emitted terminal for matching
/// machines, via `try_charge_n(2)` atomically so visit+terminal never
/// split across credits). Association releases for emitted terminals
/// queue in the caller's assoc queue (same shared budget). Preserves
/// terminal reasons (Cancelled for owned/selected, Unknown for
/// unproven) and effect order (map order per phase).
pub(crate) struct EdgeRetireCursor {
    scope: EdgeRetireScope,
    origin: EffectOrigin,
    phase: EdgeRetirePhase,
    active_done_upto: Option<(u64, u16)>,
    pending_done_upto: Option<(u64, u32)>,
    detached_done_upto: Option<(u64, u32, crate::semantics_objects::AsyncValue)>,
    open_done_upto: Option<u64>,
    /// Slot CLOSE_ALL second Active pass (unproven Unknown after owned
    /// Cancelled, matching synchronous grouped order): false during
    /// the owned pass, true during the unproven pass.
    slot_unproven_pass: bool,
    /// Whether any state retired (open/machine/pending/async): drives
    /// reconcile/auth post counts. Set as phases drain.
    changed: bool,
    /// Whether the session's open existed before the forget (Session
    /// Close/Reconcile posts): set during the Open forget.
    session_had_open: Option<bool>,
    /// Pending OPEN insert (session, slot) after the forget (Session
    /// Open post): set after forget completes, cleared after insert.
    open_insert_pending: Option<(u64, u64)>,
    /// Whether Selected unknown-flags counting ran (first poll).
    selected_counted: bool,
    /// Retained active visit (charged next lookup + decision): held
    /// across yields so a refused terminal charge never re-reads.
    pending_active: Option<ActiveVisit>,
    /// Retained pending visit: key + decision (`None` while the
    /// decision read is still owed).
    pending_pending: Option<((u64, u32), Option<bool>)>,
    /// Retained detached visit (charged next lookup + staged value /
    /// open decision).
    pending_detached: Option<DetachedVisit>,
    /// Retained slot-open visit (session + owner): held across
    /// yields so a refused removal charge never re-reads or skips
    /// the unbind.
    pending_open: Option<(u64, u64)>,
}

/// One scanned active machine with its end/skip decision (`None`
/// while a Slot decision read is still owed).
#[derive(Debug, Clone, Copy)]
struct ActiveVisit {
    next: (u64, u16),
    decision: Option<RetireActiveDecision>,
}

/// One scanned detached id with its staged decision.
#[derive(Debug, Clone, Copy)]
struct DetachedVisit {
    next: (u64, u32, crate::semantics_objects::AsyncValue),
    stage: DetachedVisitStage,
}

#[derive(Debug, Clone, Copy)]
enum DetachedVisitStage {
    /// Value unread: charge, read, resolve or retain the owner.
    NeedValue,
    /// Owned id under a Slot scope: charge, read the owner's open.
    NeedOpen { owner: u64 },
    /// Resolved: float, drop, or keep.
    Ready { action: RetireDetachedAction },
}

/// Preliminary detached decision from a retained value read.
enum DetachedPreliminaryAction {
    Done(RetireDetachedAction),
    NeedOpen { owner: u64 },
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum EdgeRetirePhase {
    Active,
    Pending,
    Detached,
    Open,
    Done,
}

/// Resumable budgeted pending admission for one staged PENDING head:
/// routes, captures the origin, inserts, then evicts oldest-first past
/// [`MAX_EDGE_PENDING`] — every map lookup charged before it reads
/// through the shared gate, one leaf per visit, with the charged
/// visit and the eviction best retained across yields. Matches
/// synchronous queueing + oldest eviction exactly (same inserts, same
/// evicted record, same Unknown terminals, same counts and evidence).
pub(crate) struct PendingAdmissionCursor {
    /// Retained head facts (the head stays staged until the admission
    /// commits, so the cursor clones what it needs up front).
    /// Eviction terminals name the evicted call (like sync), never
    /// this head, so no head origin is retained.
    call: SemanticCall,
    phase: PendingAdmissionPhase,
    /// Retained routing (charged lookup).
    route: Option<PendingRoute>,
    /// Operation bits to capture, in `operation_bits` order.
    bits: Vec<u16>,
    /// Retained origin bits captured so far.
    capture: Vec<(u16, Option<u64>)>,
    /// Pending-scan position (BTree key order) and remaining count
    /// (snapshotted at insert: nothing mutates the maps mid-scan, so
    /// no terminal lookup is needed).
    scan_pending_upto: Option<(u64, u32)>,
    scan_pending_left: usize,
    /// Detached-scan position and remaining count.
    scan_detached_upto: Option<(u64, u32, crate::semantics_objects::AsyncValue)>,
    scan_detached_left: usize,
    /// Best (oldest) record so far. Pending wins ties (matches the
    /// synchronous comparison).
    best: Option<PendingAdmissionBest>,
    /// Retained evicted record for the Unknown-end walk.
    evicted: Option<EvictedRecord>,
    /// Evicted-origin bits ended so far.
    evict_done: usize,
    /// Retained liveness decision (session, bit) whose visit +
    /// terminal still needs its atomic 2-unit credit: set when the
    /// liveness read succeeds but the terminal charge refuses, so the
    /// resume never re-reads the charged visit.
    evict_end_pending: Option<(u64, u16)>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum PendingAdmissionPhase {
    Route,
    Capture,
    Insert,
    EvictScan,
    EvictEnd,
    Done,
}

#[derive(Debug, Clone, Copy)]
enum PendingAdmissionBest {
    Pending {
        key: (u64, u32),
        sequence: u64,
    },
    Detached {
        key: (u64, u32, crate::semantics_objects::AsyncValue),
        sequence: u64,
    },
}

impl PendingAdmissionBest {
    fn sequence(self) -> u64 {
        match self {
            Self::Pending { sequence, .. } | Self::Detached { sequence, .. } => sequence,
        }
    }
}

struct EvictedRecord {
    session: u64,
    origin: CallOrigin,
    effect_origin: EffectOrigin,
    resource: Option<ResourceLease>,
}

/// Pure peek result for one staged head (see
/// [`EdgeSemantics::would_retire_scope`]).
#[derive(Debug, Clone)]
pub(crate) enum RetirePeek {
    /// Zero-leaf observe (downgrade-gate failure, unsealed/COUNT_ONLY):
    /// caller pops for 1 unit and runs observe synchronously with no
    /// pre-charge (0 reads). Lifecycle guard misses are Bounded
    /// (their synchronous observe may read); PENDING queues are
    /// Pending (their admission + eviction scan is budgeted).
    NoOp,
    /// Budgeted pending admission + oldest-first eviction (caller uses
    /// [`Self::start_pending_admission`] and pops without a second
    /// observe once the cursor completes).
    Pending,
    /// Bounded observe (Init/Update/Direct/Async, 2-machine
    /// OPERATION_NOT_INITIALIZED, lifecycle guard miss):
    /// caller reserve-checks HEAD_WORST and runs atomically.
    Bounded,
    /// Whole-scope retire (caller uses budgeted invalidation):
    /// `count_reconciliations` mirrors sync (true for
    /// CRYPTOKI_NOT_INITIALIZED reconcile, false for FINALIZE and
    /// loss finalization).
    All { count_reconciliations: bool },
    /// Subset retire (caller uses budgeted retire cursor).
    Subset(EdgeRetireScope),
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum RetireActiveDecision {
    Skip,
    End(EndState),
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum RetireDetachedAction {
    Keep,
    Float,
    Drop,
}

impl EdgeSemantics {
    /// Feed one completed call. Returns the number of per-edge keys
    /// refused past bounds by THIS call (the registry folds it into
    /// its `semantic_refused` total). Effect-free: the same
    /// implementation as [`Self::observe_with_effects`] with a no-op
    /// sink, never a second pass.
    pub(crate) fn observe(&mut self, call: &SemanticCall) -> u64 {
        let origin = EffectOrigin::placeholder();
        self.observe_with_effects(call, &origin, &mut NoSink)
    }

    /// Feed one completed call with typed transition notifications:
    /// the same observe implementation, not a second reducer pass.
    /// `origin` is the registry-supplied identity of the uniquely
    /// consumed H3/H8 call; effects caused by this call carry it,
    /// while async completions carry their original call's identity.
    pub(crate) fn observe_with_effects<S: OperationSink>(
        &mut self,
        call: &SemanticCall,
        origin: &EffectOrigin,
        sink: &mut S,
    ) -> u64 {
        self.observe_inner(call, origin, &[], &CompletionEvidence::NONE, sink)
    }

    /// Joint replay (H9): the same single pass, plus this call's
    /// positional key receipts (at most two) for the machines and
    /// direct operations it starts. S1Only reduction passes none —
    /// receipts exist only under sealed object proof.
    // Guarded (N1): reachable only through Joint seal/failure
    // delivery, which needs installed receipts + an H8 driver.
    // Production replay reserves first (N14); this stays for
    // unit-test reducers without a pool.
    #[cfg_attr(not(test), allow(dead_code))]
    pub(crate) fn observe_joint<S: OperationSink>(
        &mut self,
        call: &SemanticCall,
        origin: &EffectOrigin,
        keys: &[KeyReceipt],
        sink: &mut S,
    ) -> u64 {
        self.observe_inner(call, origin, keys, &CompletionEvidence::NONE, sink)
    }

    /// Joint replay with H3 resource reservation (N14): prepares the
    /// growth reservation BEFORE the single replay pass (fallback
    /// passes no receipts). On refusal returns Err WITHOUT
    /// invalidating, so the caller can invalidate with effects teed
    /// (open key rows close as Unknown) and dispose the
    /// un-replayable payload as history. Reducers without a pool
    /// (unit-test defaults; production registry reducers always
    /// carry one) replay unresourced.
    pub(crate) fn observe_joint_with_resources<S: OperationSink>(
        &mut self,
        call: &SemanticCall,
        origin: &EffectOrigin,
        keys: &[KeyReceipt],
        completion: &CompletionEvidence,
        sink: &mut S,
    ) -> Result<u64, SemanticResourceRefusal> {
        if self.resource_owner.is_none() {
            return Ok(self.observe_inner(call, origin, keys, completion, sink));
        }
        let prepared = self.prepare_resource_transition(call)?;
        assert!(self.resource_transition.is_none());
        self.resource_transition = Some(prepared);
        let refused = self.observe_inner(call, origin, keys, completion, sink);
        drop(self.resource_transition.take());
        Ok(refused)
    }

    fn observe_inner<S: OperationSink>(
        &mut self,
        call: &SemanticCall,
        origin: &EffectOrigin,
        keys: &[KeyReceipt],
        completion: &CompletionEvidence,
        sink: &mut S,
    ) -> u64 {
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
            // Async paths derive effect origins from the stored
            // ORIGINAL calls, never from the completing call.
            self.observe_async(call, sink);
        } else if call.rv == CkRv::PENDING.0 {
            self.queue_pending(call, sink);
        } else {
            self.apply_completed(call, &descriptor, origin, keys, completion, sink);
        }
        self.dropped.saturating_sub(dropped_before)
    }

    /// Checked identity allocation (H9): the next ordinal, or `None`
    /// past `u64::MAX` — never wraps, never recycles.
    fn alloc_generation(&mut self) -> Option<u64> {
        let next = self.machine_seq.checked_add(1)?;
        self.machine_seq = next;
        Some(next)
    }

    /// Test-only exhaustion control: positions the checked allocator.
    #[cfg(test)]
    pub(crate) fn seed_machine_seq_for_test(&mut self, value: u64) {
        self.machine_seq = value;
    }

    /// Test-only bump of the unified edge-read counter: one per
    /// edge-map lookup, at the actual read site.
    #[cfg(test)]
    fn bump_edge_read_for_test(&self) {
        self.test_edge_reads.set(self.test_edge_reads.get() + 1);
    }

    /// Test-only read of the unified edge-read counter.
    #[cfg(test)]
    pub(crate) fn test_edge_reads_for_test(&self) -> usize {
        self.test_edge_reads.get()
    }

    /// Test-only reset of the unified edge-read counter.
    #[cfg(test)]
    pub(crate) fn reset_test_edge_reads_for_test(&self) {
        self.test_edge_reads.set(0);
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
    /// `origin` is the source-call identity effects from this call
    /// carry (the consumed call, or the original for async replay).
    /// `keys` are this call's positional key receipts for the
    /// machines and direct operations it starts (Joint only).
    fn apply_completed<S: OperationSink>(
        &mut self,
        call: &SemanticCall,
        descriptor: &SlotSemantics,
        origin: &EffectOrigin,
        keys: &[KeyReceipt],
        completion: &CompletionEvidence,
        sink: &mut S,
    ) {
        if descriptor.transition == transition::INITIALIZE || descriptor.direct != direct::NONE {
            self.record_init_mechanism(call, descriptor);
        }
        if self.reconcile_conclusive(call, descriptor, origin, sink) {
            return;
        }
        self.apply_lifecycle(call, descriptor, origin, sink);
        if descriptor.transition == transition::INITIALIZE {
            self.apply_init(call, descriptor, origin, keys, sink);
        } else if descriptor.direct == direct::NONE && descriptor.operations != 0 {
            self.apply_operations(call, descriptor, origin, completion, sink);
        } else if descriptor.direct != direct::NONE {
            self.apply_direct(call, descriptor, origin, keys, completion, sink);
        }
    }

    /// Category name for a live machine's bit. Keys enter `active`
    /// only from [`crate::semantics::operation_bits`], so every live
    /// bit is known; the fallback is unreachable defense, never a
    /// guessed category on a real machine.
    fn category_name(bit: u16) -> &'static str {
        crate::semantics::operation_name(bit).unwrap_or("operation")
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
        let mut charge = self.provenance_growth(call.mechanism, call, call.rv);
        let prior = self.mechs.get(&call.mechanism);
        for (_, name) in crate::semantics::operation_bits(descriptor.operations) {
            if prior.is_none_or(|stat| !stat.ops.contains(name)) {
                charge += resources::CATEGORY_CHARGE;
            }
        }
        if let Some(name) = crate::semantics::direct_name(descriptor.direct)
            && prior.is_none_or(|stat| !stat.ops.contains(name))
        {
            charge += resources::CATEGORY_CHARGE;
        }
        self.retain_resource_charge(charge);
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
        self.retain_resource_charge(self.provenance_growth(mechanism, call, call.rv));
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
    fn reconcile_conclusive<S: OperationSink>(
        &mut self,
        call: &SemanticCall,
        descriptor: &SlotSemantics,
        origin: &EffectOrigin,
        sink: &mut S,
    ) -> bool {
        if call.rv == CkRv::OPERATION_NOT_INITIALIZED.0 {
            let mut changed = false;
            for (bit, name) in crate::semantics::operation_bits(descriptor.operations) {
                changed |= self.end_machine(
                    call.session,
                    bit,
                    name,
                    EndState::Unknown,
                    origin,
                    &CompletionEvidence::NONE,
                    sink,
                );
            }
            if changed {
                self.evidence.state_reconciliations =
                    self.evidence.state_reconciliations.saturating_add(1);
            }
            return true;
        }
        if call.rv == CkRv::SESSION_CLOSED.0 || call.rv == CkRv::SESSION_HANDLE_INVALID.0 {
            let changed = self.retire_session(call.session, EndState::Cancelled, origin, sink);
            if changed {
                self.evidence.state_reconciliations =
                    self.evidence.state_reconciliations.saturating_add(1);
            }
            return true;
        }
        if call.rv == CkRv::CRYPTOKI_NOT_INITIALIZED.0 {
            let changed = self.retire_all(EndState::Cancelled, origin, sink);
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
    fn apply_lifecycle<S: OperationSink>(
        &mut self,
        call: &SemanticCall,
        descriptor: &SlotSemantics,
        origin: &EffectOrigin,
        sink: &mut S,
    ) {
        match descriptor.lifecycle {
            lifecycle::OPEN_SESSION if call.rv == CkRv::OK.0 && call.session != SESSION_NONE => {
                // Prior state under a reopened handle is a stale model
                // (handle reuse without an observed close): its true
                // end is unprovable.
                if self.retire_session(call.session, EndState::Unknown, origin, sink) {
                    self.evidence.state_reconciliations =
                        self.evidence.state_reconciliations.saturating_add(1);
                }
                if !self.open.contains_key(&call.session) && self.open.len() >= MAX_EDGE_SESSIONS {
                    self.dropped = self.dropped.saturating_add(1);
                } else {
                    self.retain_resource_charge(resources::OPEN_BINDING_CHARGE);
                    self.open.insert(call.session, call.slot_id);
                }
            }
            lifecycle::CLOSE_SESSION if call.rv == CkRv::OK.0 => {
                let existed = self.open.remove(&call.session).is_some();
                if existed {
                    self.release_resource_charge(resources::OPEN_BINDING_CHARGE);
                }
                self.end_session_machines(call.session, EndState::Cancelled, origin, sink);
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
                    if self.open.remove(&session).is_some() {
                        self.release_resource_charge(resources::OPEN_BINDING_CHARGE);
                    }
                    self.end_session_machines(session, EndState::Cancelled, origin, sink);
                    self.pending.retain(|(owner, _), _| *owner != session);
                    self.float_session_async(session);
                }
                for session in unproven {
                    self.retire_session(session, EndState::Unknown, origin, sink);
                }
            }
            lifecycle::FINALIZE if call.rv == CkRv::OK.0 => {
                self.retire_all(EndState::Cancelled, origin, sink);
            }
            lifecycle::LOGIN | lifecycle::LOGOUT => self.apply_auth(call, origin, sink),
            lifecycle::SESSION_CANCEL => self.apply_session_cancel(call, origin, sink),
            lifecycle::SET_OPERATION_STATE if call.rv == CkRv::OK.0 => {
                // Imported state replaces tracked state: the old
                // machines ended by replacement.
                self.end_session_machines(call.session, EndState::Cancelled, origin, sink);
                self.evidence.operation_state_imports =
                    self.evidence.operation_state_imports.saturating_add(1);
            }
            _ => {}
        }
    }

    /// Whether one login/logout call retires its slot's operations,
    /// shared by the synchronous reducer ([`Self::apply_auth`]), the
    /// feed peek ([`Self::would_retire_scope`]) and the feed's
    /// charge-then-classify helper so the three cannot drift:
    /// context-specific `C_Login` with `OK` is exempt, and only
    /// `OK`/`PIN_LOCKED` proceed (both prove the token answered with
    /// changed auth state).
    pub(crate) fn auth_retires_slot(call: &SemanticCall) -> bool {
        if call.function == "C_Login" && call.user_type == 2 && call.rv == CkRv::OK.0 {
            return false;
        }
        call.rv == CkRv::OK.0 || call.rv == CkRv::PIN_LOCKED.0
    }

    /// Login/logout clears the slot's operations: the scope predicate
    /// above decides, then every session proven on the call's slot
    /// ends cancelled (machines, pendings, floated async).
    fn apply_auth<S: OperationSink>(
        &mut self,
        call: &SemanticCall,
        origin: &EffectOrigin,
        sink: &mut S,
    ) {
        if !Self::auth_retires_slot(call) {
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
            changed |= self.end_session_machines(session, EndState::Cancelled, origin, sink);
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
    fn apply_session_cancel<S: OperationSink>(
        &mut self,
        call: &SemanticCall,
        origin: &EffectOrigin,
        sink: &mut S,
    ) {
        if call.flags & !crate::semantics::KNOWN_CANCEL_FLAGS != 0 {
            self.evidence.session_cancel_unknown_flags =
                self.evidence.session_cancel_unknown_flags.saturating_add(1);
        }
        let selected = (call.flags & crate::semantics::KNOWN_CANCEL_FLAGS).count_ones();
        if call.rv == CkRv::OPERATION_CANCEL_FAILED.0 && selected > 1 {
            self.clear_selected(call.session, call.flags, origin, sink);
            self.evidence.session_cancel_ambiguities =
                self.evidence.session_cancel_ambiguities.saturating_add(1);
        } else if call.rv == CkRv::OK.0 {
            self.clear_selected(call.session, call.flags, origin, sink);
        }
    }

    /// Clear what a cancel selected: masked machines, matching
    /// pendings, and owned async ids — mirroring `clear_selected`
    /// (minus find state, which is S2, and minus tombstones, which
    /// cannot exist inside one edge). Ended machines emit through the
    /// same end site as every other cancel.
    fn clear_selected<S: OperationSink>(
        &mut self,
        session: u64,
        flags: u64,
        origin: &EffectOrigin,
        sink: &mut S,
    ) {
        let mask = cancel_operation_mask(flags);
        let doomed: Vec<(u64, u16)> = self
            .active
            .keys()
            .filter(|(owner, bit)| *owner == session && mask & *bit != 0)
            .copied()
            .collect();
        for (owner, bit) in doomed {
            self.end_machine(
                owner,
                bit,
                Self::category_name(bit),
                EndState::Cancelled,
                origin,
                &CompletionEvidence::NONE,
                sink,
            );
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
    fn apply_init<S: OperationSink>(
        &mut self,
        call: &SemanticCall,
        descriptor: &SlotSemantics,
        origin: &EffectOrigin,
        keys: &[KeyReceipt],
        sink: &mut S,
    ) {
        if call.rv != CkRv::OK.0 || call.session == SESSION_NONE {
            return;
        }
        // An Init names at most one key: the first positional receipt
        // fixes every machine this Init starts. (Descriptors admit a
        // single key input for `*Init`; anything beyond the first
        // would be a second input the model never emits for one.)
        let key = keys.first().copied();
        for (bit, name) in crate::semantics::operation_bits(descriptor.operations) {
            match call.mechanism_capture() {
                capture::MECHANISM_VALUE => {
                    self.start_machine(
                        call.session,
                        bit,
                        name,
                        Some(call.mechanism),
                        key,
                        origin,
                        sink,
                    );
                }
                capture::MECHANISM_NULL
                    if descriptor.semantic_flags & semantic_flags::NULL_MECHANISM_CANCEL != 0 =>
                {
                    self.end_machine(
                        call.session,
                        bit,
                        name,
                        EndState::Cancelled,
                        origin,
                        &CompletionEvidence::NONE,
                        sink,
                    );
                }
                capture::MECHANISM_NULL => {
                    self.evidence.semantic_capture_failures =
                        self.evidence.semantic_capture_failures.saturating_add(1);
                    self.start_machine(call.session, bit, name, None, key, origin, sink);
                }
                _ => {
                    self.start_machine(call.session, bit, name, None, key, origin, sink);
                }
            }
        }
    }

    /// Start (or replace) one operation machine: bound-checked,
    /// generation-stamped (F2); the replaced machine ends cancelled
    /// by replacement — never completed. The replacement terminal
    /// emits BEFORE the new start. Identity allocation is checked
    /// (H9): on exhaustion no machine is retained — the competing
    /// old machine still ends cancelled, the new operation counts
    /// started-then-unknown, and the refusal is counted instead of
    /// wrapping or recycling an identity. `key_receipt` fixes the
    /// machine's receipt for its life (`None` for S1Only/unassociated
    /// starts).
    #[allow(clippy::too_many_arguments)] // Exact machine identity: session/bit/category/mechanism/receipt plus origin/sink.
    fn start_machine<S: OperationSink>(
        &mut self,
        session: u64,
        bit: u16,
        category: &'static str,
        mechanism: Option<u64>,
        key_receipt: Option<KeyReceipt>,
        origin: &EffectOrigin,
        sink: &mut S,
    ) {
        let key = (session, bit);
        if !self.active.contains_key(&key) && self.active.len() >= MAX_EDGE_ACTIVE_OPS {
            self.dropped = self.dropped.saturating_add(1);
            return;
        }
        let Some(generation) = self.alloc_generation() else {
            // A competing `Init` still cancels what it replaces; the
            // untrackable new operation ends unknown, never completed.
            self.end_machine(
                session,
                bit,
                category,
                EndState::Cancelled,
                origin,
                &CompletionEvidence::NONE,
                sink,
            );
            self.started = self.started.saturating_add(1);
            self.unknown = self.unknown.saturating_add(1);
            self.id_exhaustions = self.id_exhaustions.saturating_add(1);
            return;
        };
        if !self.active.contains_key(&key) {
            self.retain_resource_charge(resources::ACTIVE_MACHINE_CHARGE);
        }
        let replaced = self.active.insert(
            key,
            OpMachine {
                mechanism,
                state: OpState::Initialized,
                generation,
                key: key_receipt,
                corroboration: None,
            },
        );
        if let Some(old) = replaced {
            // Competing `Init`: the old machine ended by
            // replacement, never completed. Its terminal emits
            // BEFORE the new start and names the OLD identity.
            self.cancelled = self.cancelled.saturating_add(1);
            if S::WANTS_EFFECTS {
                sink.emit(OperationEffect::Ended {
                    id: OperationId(old.generation),
                    category,
                    outcome: OperationOutcome::Cancelled,
                    origin: origin.clone(),
                    // A replacement names no completion: cancelled
                    // terminals carry no length evidence.
                    length: None,
                    corroboration: None,
                });
            }
        }
        self.started = self.started.saturating_add(1);
        if S::WANTS_EFFECTS {
            // The emit reads the stored binding: the machine is the
            // single source of truth for its fixed receipt.
            let stored = self.active.get(&key).and_then(|machine| machine.key);
            debug_assert_eq!(stored, key_receipt);
            sink.emit(OperationEffect::Started {
                id: OperationId(generation),
                category,
                mechanism,
                key_receipt: stored,
                origin: origin.clone(),
            });
        }
    }

    /// Operational call: attribute to each bound mechanism (or count
    /// the orphan when no machine is active — unknown-origin evidence,
    /// never an invented operation), then run the transition, mirroring
    /// `apply_operations` including its exact retain rules. Retained
    /// machines advance to in-progress; ended machines complete iff
    /// the ending call returned `OK`. Machines with an unknown
    /// mechanism (F5) advance and end normally but attribute to
    /// nothing — no invented mechanism id.
    fn apply_operations<S: OperationSink>(
        &mut self,
        call: &SemanticCall,
        descriptor: &SlotSemantics,
        origin: &EffectOrigin,
        completion: &CompletionEvidence,
        sink: &mut S,
    ) {
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
            for (bit, name) in crate::semantics::operation_bits(descriptor.operations) {
                self.end_machine(call.session, bit, name, end, origin, completion, sink);
            }
        } else {
            for (bit, _) in crate::semantics::operation_bits(descriptor.operations) {
                if let Some(machine) = self.active.get_mut(&(call.session, bit)) {
                    machine.state = OpState::InProgress;
                    // Keymeta §5.4: a retained BUFFER_TOO_SMALL length
                    // corroborates (exact per PKCS#11 v2.40 §5.2);
                    // every other retained value — queries
                    // included — drops on arrival, never stored.
                    if call.rv == CkRv::BUFFER_TOO_SMALL.0
                        && let Some(LengthOutcome::Value(value)) = completion.length
                    {
                        machine.corroboration = Some(value);
                    }
                }
            }
        }
    }

    /// Direct call (`C_GenerateKey`, `C_WrapKey`, ...): no machine — a
    /// successful call starts and finishes its operation in this one
    /// call. (The mechanism claim, if any, was already recorded.) One
    /// atomic [`OperationEffect::DirectCompleted`]; a failed direct
    /// call emits nothing. The identity draws from the same checked
    /// source as machines: on exhaustion the definite in-call
    /// completion still counts, but no effect is emitted.
    fn apply_direct<S: OperationSink>(
        &mut self,
        call: &SemanticCall,
        descriptor: &SlotSemantics,
        origin: &EffectOrigin,
        keys: &[KeyReceipt],
        completion: &CompletionEvidence,
        sink: &mut S,
    ) {
        if call.rv != CkRv::OK.0 {
            return;
        }
        self.started = self.started.saturating_add(1);
        self.completed = self.completed.saturating_add(1);
        let Some(generation) = self.alloc_generation() else {
            self.id_exhaustions = self.id_exhaustions.saturating_add(1);
            return;
        };
        if S::WANTS_EFFECTS {
            debug_assert!(
                keys.len() <= 2,
                "descriptors admit at most two key inputs per direct call"
            );
            let mechanism =
                (call.mechanism_capture() == capture::MECHANISM_VALUE).then_some(call.mechanism);
            // Keymeta §5.4: a NULL-output OK direct is a length
            // query (wrap/encapsulate shapes): the call completes
            // but the over-estimate value drops on arrival — never
            // stored, classified or counted. Only output-bearing
            // directs ever read OUTPUT_NULL; V-directs always read
            // OUTPUT_NONE.
            let length = if call.capture & capture::OUTPUT_MASK == capture::OUTPUT_NULL {
                None
            } else {
                completion.length
            };
            sink.emit(OperationEffect::DirectCompleted {
                id: OperationId(generation),
                category: crate::semantics::direct_name(descriptor.direct).unwrap_or("direct"),
                mechanism,
                key_receipts: keys.to_vec(),
                origin: origin.clone(),
                // Directs emit only on OK: a terminal length (queries
                // drop above) and the seal's exact-one fresh view
                // ride through.
                length,
                fresh_view: completion.fresh_view,
            });
        }
    }

    /// End one machine with an explicit end state, emitting its
    /// terminal. Returns whether a machine was actually ended.
    #[allow(clippy::too_many_arguments)]
    fn end_machine<S: OperationSink>(
        &mut self,
        session: u64,
        bit: u16,
        category: &'static str,
        end: EndState,
        origin: &EffectOrigin,
        completion: &CompletionEvidence,
        sink: &mut S,
    ) -> bool {
        if let Some(machine) = self.active.remove(&(session, bit)) {
            self.release_resource_charge(resources::ACTIVE_MACHINE_CHARGE);
            match end {
                EndState::Completed => self.completed = self.completed.saturating_add(1),
                EndState::Cancelled => self.cancelled = self.cancelled.saturating_add(1),
                EndState::Failed => self.failed = self.failed.saturating_add(1),
                EndState::Unknown => self.unknown = self.unknown.saturating_add(1),
            }
            if S::WANTS_EFFECTS {
                // Keymeta §9: only a terminal Completed completion
                // classifies (failures prove nothing, cancellations
                // end by replacement, retirements are not
                // completions); the retained corroboration rides the
                // terminal for the reducer's mismatch check.
                let completed = matches!(end, EndState::Completed);
                sink.emit(OperationEffect::Ended {
                    id: OperationId(machine.generation),
                    category,
                    outcome: end.outcome(),
                    origin: origin.clone(),
                    length: if completed { completion.length } else { None },
                    corroboration: if completed {
                        machine.corroboration
                    } else {
                        None
                    },
                });
            }
            true
        } else {
            false
        }
    }

    /// End every machine on one session through the one end site.
    /// Returns whether any ended.
    fn end_session_machines<S: OperationSink>(
        &mut self,
        session: u64,
        end: EndState,
        origin: &EffectOrigin,
        sink: &mut S,
    ) -> bool {
        let doomed: Vec<(u64, u16)> = self
            .active
            .keys()
            .filter(|(owner, _)| *owner == session)
            .copied()
            .collect();
        let changed = !doomed.is_empty();
        for (owner, bit) in doomed {
            self.end_machine(
                owner,
                bit,
                Self::category_name(bit),
                end,
                origin,
                &CompletionEvidence::NONE,
                sink,
            );
        }
        changed
    }

    /// Retire one session: forget the open, end its machines, drop its
    /// pendings, float its async ids (still joinable — a live state).
    /// Returns whether the scope held any state.
    fn retire_session<S: OperationSink>(
        &mut self,
        session: u64,
        end: EndState,
        origin: &EffectOrigin,
        sink: &mut S,
    ) -> bool {
        let mut changed = self.open.remove(&session).is_some();
        if changed {
            self.release_resource_charge(resources::OPEN_BINDING_CHARGE);
        }
        changed |= self.end_session_machines(session, end, origin, sink);
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
    fn retire_all<S: OperationSink>(
        &mut self,
        session_end: EndState,
        origin: &EffectOrigin,
        sink: &mut S,
    ) -> bool {
        let mut changed = !self.open.is_empty();
        let open_charge = self.open.len() * resources::OPEN_BINDING_CHARGE;
        self.open.clear();
        self.release_resource_charge(open_charge);
        changed |= self.end_session_machines_all(session_end, origin, sink);
        changed |= !self.pending.is_empty() || !self.detached.is_empty();
        self.clear_async_payloads();
        changed
    }

    fn end_session_machines_all<S: OperationSink>(
        &mut self,
        end: EndState,
        origin: &EffectOrigin,
        sink: &mut S,
    ) -> bool {
        // Per-machine ends (not a bulk clear): every terminal emits
        // with its own identity, like every other end path. Popped
        // (never collected): invalidation allocates nothing.
        let changed = !self.active.is_empty();
        while let Some(((_, bit), machine)) = self.active.pop_first() {
            // Reinsert for the one end site would reallocate; end
            // inline instead with the popped machine's identity.
            self.release_resource_charge(resources::ACTIVE_MACHINE_CHARGE);
            match end {
                EndState::Completed => self.completed = self.completed.saturating_add(1),
                EndState::Cancelled => self.cancelled = self.cancelled.saturating_add(1),
                EndState::Failed => self.failed = self.failed.saturating_add(1),
                EndState::Unknown => self.unknown = self.unknown.saturating_add(1),
            }
            if S::WANTS_EFFECTS {
                sink.emit(OperationEffect::Ended {
                    id: OperationId(machine.generation),
                    category: Self::category_name(bit),
                    outcome: end.outcome(),
                    origin: origin.clone(),
                    // Bulk-pop ends (invalidation sweeps) name no
                    // completion: no length evidence by construction.
                    length: None,
                    corroboration: None,
                });
            }
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

    fn clear_async_payloads(&mut self) {
        while let Some((_, fact)) = self.pending.pop_first() {
            drop(fact);
        }
        while let Some((_, fact)) = self.detached.pop_first() {
            drop(fact);
        }
        // Empty roots are covered by the retained base charge, and their
        // actual destruction completes before the whole reducer refunds it.
        self.pending.clear();
        self.detached.clear();
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
        self.invalidate_with_effects(&mut NoSink);
    }

    /// [`Self::invalidate`] with typed terminals for every live
    /// machine. Loss carries no source call, so terminals name the
    /// loss origin explicitly.
    pub(crate) fn invalidate_with_effects<S: OperationSink>(&mut self, sink: &mut S) {
        let origin = if S::WANTS_EFFECTS {
            EffectOrigin {
                function: "loss".into(),
                session: SESSION_NONE,
                ts_ns: self.last_seen_ns,
            }
        } else {
            EffectOrigin::placeholder()
        };
        self.end_session_machines_all(EndState::Unknown, &origin, sink);
        self.clear_async_payloads();
        let open_charge = self.open.len() * resources::OPEN_BINDING_CHARGE;
        self.open.clear();
        self.release_resource_charge(open_charge);
    }

    /// Start a resumable budgeted invalidation (disposal finalization
    /// and staged All-scope retiring calls): drains active machines
    /// two leaves per machine (visit + terminal), then
    /// pending/detached drops and open unbinds, with the same terminal
    /// reasons, effect order (active-map order), counters and resource
    /// releases as the synchronous arms. `end_unknown` names the
    /// terminal (true=Unknown for loss/invalidate, false=Cancelled for
    /// finalize/retire); `origin` names the terminals (`None` for the
    /// loss origin of finalization, `Some` for a retiring head's call
    /// origin like sync `retire_all`); `count_reconciliations` mirrors
    /// sync (true only for CRYPTOKI_NOT_INITIALIZED reconcile). The
    /// caller drives [`Self::poll_invalidation_step`] with the shared
    /// [`LeafBudget`] until it completes.
    pub(crate) fn start_budgeted_invalidation(
        &self,
        end_unknown: bool,
        origin: Option<&EffectOrigin>,
        count_reconciliations: bool,
    ) -> EdgeInvalidationCursor {
        let end = if end_unknown {
            EndState::Unknown
        } else {
            EndState::Cancelled
        };
        EdgeInvalidationCursor {
            phase: EdgeInvalidationPhase::Active,
            origin: match origin {
                Some(origin) => origin.clone(),
                None => EffectOrigin {
                    function: "loss".into(),
                    session: SESSION_NONE,
                    ts_ns: self.last_seen_ns,
                },
            },
            end,
            count_reconciliations,
            changed: false,
        }
    }

    /// Drive one budgeted invalidation step through the shared
    /// pre-debit gate: two leaves per active machine (visit +
    /// terminal, atomically via `try_charge_n(2)` so the pair never
    /// splits), one per pending/detached drop or open unbind. Returns
    /// whether the invalidation completed. On exhaustion yields
    /// WITHOUT popping (no read past the credit). Emitted terminals
    /// feed `sink` (the disposal tees them into its preserved
    /// key-use, queuing association releases for the same budget).
    /// Preserves terminal reasons and effect order.
    pub(crate) fn poll_invalidation_step<S: OperationSink>(
        &mut self,
        cursor: &mut EdgeInvalidationCursor,
        sink: &mut S,
        budget: &mut LeafBudget,
    ) -> bool {
        loop {
            match cursor.phase {
                EdgeInvalidationPhase::Active => {
                    if self.active.is_empty() {
                        cursor.phase = EdgeInvalidationPhase::Pending;
                        continue;
                    }
                    if !budget.try_charge_n(2) {
                        return false;
                    }
                    let Some(((_, bit), machine)) = self.active.pop_first() else {
                        cursor.phase = EdgeInvalidationPhase::Pending;
                        continue;
                    };
                    #[cfg(test)]
                    {
                        self.bump_edge_read_for_test();
                        self.bump_edge_read_for_test();
                    }
                    cursor.changed = true;
                    self.release_resource_charge(resources::ACTIVE_MACHINE_CHARGE);
                    match cursor.end {
                        EndState::Completed => {
                            self.completed = self.completed.saturating_add(1);
                        }
                        EndState::Cancelled => {
                            self.cancelled = self.cancelled.saturating_add(1);
                        }
                        EndState::Failed => self.failed = self.failed.saturating_add(1),
                        EndState::Unknown => {
                            self.unknown = self.unknown.saturating_add(1);
                        }
                    }
                    if S::WANTS_EFFECTS {
                        sink.emit(OperationEffect::Ended {
                            id: OperationId(machine.generation),
                            category: Self::category_name(bit),
                            outcome: cursor.end.outcome(),
                            origin: cursor.origin.clone(),
                            length: None,
                            corroboration: None,
                        });
                    }
                    if budget.remaining() == 0 {
                        return false;
                    }
                }
                EdgeInvalidationPhase::Pending => {
                    if self.pending.is_empty() {
                        cursor.phase = EdgeInvalidationPhase::Detached;
                        continue;
                    }
                    if !budget.try_charge() {
                        return false;
                    }
                    let _ = self.pending.pop_first();
                    #[cfg(test)]
                    self.bump_edge_read_for_test();
                    cursor.changed = true;
                    if budget.remaining() == 0 {
                        return false;
                    }
                }
                EdgeInvalidationPhase::Detached => {
                    if self.detached.is_empty() {
                        cursor.phase = EdgeInvalidationPhase::Open;
                        continue;
                    }
                    if !budget.try_charge() {
                        return false;
                    }
                    let _ = self.detached.pop_first();
                    #[cfg(test)]
                    self.bump_edge_read_for_test();
                    cursor.changed = true;
                    if budget.remaining() == 0 {
                        return false;
                    }
                }
                EdgeInvalidationPhase::Open => {
                    if self.open.is_empty() {
                        if cursor.count_reconciliations && cursor.changed {
                            self.evidence.state_reconciliations =
                                self.evidence.state_reconciliations.saturating_add(1);
                        }
                        cursor.phase = EdgeInvalidationPhase::Done;
                        continue;
                    }
                    if !budget.try_charge() {
                        return false;
                    }
                    let _ = self.open.pop_first();
                    #[cfg(test)]
                    self.bump_edge_read_for_test();
                    cursor.changed = true;
                    self.release_resource_charge(resources::OPEN_BINDING_CHARGE);
                    if budget.remaining() == 0 {
                        return false;
                    }
                }
                EdgeInvalidationPhase::Done => {
                    return true;
                }
            }
        }
    }

    /// Pure retire-scope peek for one staged head during disposal:
    /// returns how the head would retire WITHOUT mutating (no counter
    /// increments, no map changes). `NoOp` means zero-leaf observe
    /// (caller pops for 1, no pre-charge); `Pending` means budgeted
    /// admission + eviction (caller uses
    /// [`Self::start_pending_admission`]); `Bounded` means bounded
    /// observe (caller reserve-checks HEAD_WORST and runs atomically);
    /// `All` means whole-scope retire (caller uses
    /// [`Self::start_budgeted_invalidation`] with Cancelled);
    /// `Subset(scope)` means subset retire (caller uses
    /// [`Self::start_budgeted_retire`]). Shares the pure
    /// gate/descriptor/lifecycle condition helpers with
    /// [`Self::observe_inner`] so the two cannot drift (only the
    /// downgrade-cause counting differs, which the peek correctly
    /// omits). LOGIN/LOGOUT share the synchronous auth scope predicate
    /// ([`Self::auth_retires_slot`]) and resolve their slot from the
    /// live open map (like sync); the caller pre-charges that one
    /// lookup before calling (see the feed's charge-then-classify
    /// helper). Exempt and slot-less logins observe Bounded.
    pub(crate) fn would_retire_scope(&self, call: &SemanticCall) -> RetirePeek {
        if !call.attributable || !call.authorized || !call.unambiguous || call.count_only {
            return RetirePeek::NoOp;
        }
        let descriptor =
            crate::kinds::descriptor(&call.function).unwrap_or(SlotSemantics::COUNT_ONLY);
        if descriptor == SlotSemantics::COUNT_ONLY {
            return RetirePeek::NoOp;
        }
        if call.rv == CkRv::OPERATION_NOT_INITIALIZED.0 {
            return RetirePeek::Bounded;
        }
        if call.rv == CkRv::SESSION_CLOSED.0 || call.rv == CkRv::SESSION_HANDLE_INVALID.0 {
            return RetirePeek::Subset(EdgeRetireScope::Session {
                session: call.session,
                end_unknown: false,
                post: SessionPost::Reconcile,
            });
        }
        if call.rv == CkRv::CRYPTOKI_NOT_INITIALIZED.0 {
            return RetirePeek::All {
                count_reconciliations: true,
            };
        }
        if matches!(
            descriptor.lifecycle,
            x if x == lifecycle::ASYNC_COMPLETE
                || x == lifecycle::ASYNC_GET_ID
                || x == lifecycle::ASYNC_JOIN
        ) {
            return RetirePeek::Bounded;
        }
        if call.rv == CkRv::PENDING.0 {
            return RetirePeek::Pending;
        }
        match descriptor.lifecycle {
            x if x == lifecycle::OPEN_SESSION => {
                if call.rv == CkRv::OK.0 && call.session != SESSION_NONE {
                    RetirePeek::Subset(EdgeRetireScope::Session {
                        session: call.session,
                        end_unknown: true,
                        post: SessionPost::Open { slot: call.slot_id },
                    })
                } else {
                    RetirePeek::Bounded
                }
            }
            x if x == lifecycle::CLOSE_SESSION => {
                if call.rv == CkRv::OK.0 {
                    RetirePeek::Subset(EdgeRetireScope::Session {
                        session: call.session,
                        end_unknown: false,
                        post: SessionPost::Close,
                    })
                } else {
                    RetirePeek::Bounded
                }
            }
            x if x == lifecycle::CLOSE_ALL_SESSIONS => {
                if call.rv == CkRv::OK.0 {
                    RetirePeek::Subset(EdgeRetireScope::Slot {
                        slot: call.slot_id,
                        close_all: true,
                    })
                } else {
                    RetirePeek::Bounded
                }
            }
            x if x == lifecycle::FINALIZE => {
                if call.rv == CkRv::OK.0 {
                    RetirePeek::All {
                        count_reconciliations: false,
                    }
                } else {
                    RetirePeek::Bounded
                }
            }
            x if x == lifecycle::LOGIN || x == lifecycle::LOGOUT => {
                if !Self::auth_retires_slot(call) {
                    return RetirePeek::Bounded;
                }
                #[cfg(test)]
                self.bump_edge_read_for_test();
                match self.open.get(&call.session).copied() {
                    Some(slot) => RetirePeek::Subset(EdgeRetireScope::Slot {
                        slot,
                        close_all: false,
                    }),
                    None => RetirePeek::Bounded,
                }
            }
            x if x == lifecycle::SESSION_CANCEL => {
                let selected = (call.flags & crate::semantics::KNOWN_CANCEL_FLAGS).count_ones();
                if call.rv == CkRv::OK.0
                    || (call.rv == CkRv::OPERATION_CANCEL_FAILED.0 && selected > 1)
                {
                    RetirePeek::Subset(EdgeRetireScope::Selected {
                        session: call.session,
                        flags: call.flags,
                        ambiguous: call.rv == CkRv::OPERATION_CANCEL_FAILED.0 && selected > 1,
                    })
                } else {
                    RetirePeek::Bounded
                }
            }
            x if x == lifecycle::SET_OPERATION_STATE => {
                if call.rv == CkRv::OK.0 {
                    RetirePeek::Subset(EdgeRetireScope::SessionMachines {
                        session: call.session,
                        end_unknown: false,
                    })
                } else {
                    RetirePeek::Bounded
                }
            }
            _ => RetirePeek::Bounded,
        }
    }

    /// Start a resumable budgeted subset retire for one staged head's
    /// scope (see [`Self::would_retire_scope`]). The caller drives
    /// [`Self::poll_retire_step`] with the shared [`LeafBudget`]
    /// until it completes, then finishes the head (pop/count, no
    /// second retire: the synchronous observe's retire arms must NOT
    /// run for this head since the cursor already applied them; the
    /// caller skips observe for retiring heads and only preserves via
    /// the cursor's emitted terminals).
    pub(crate) fn start_budgeted_retire(
        &self,
        scope: EdgeRetireScope,
        origin: &EffectOrigin,
    ) -> EdgeRetireCursor {
        let _ = self.last_seen_ns;
        EdgeRetireCursor {
            scope,
            origin: origin.clone(),
            phase: EdgeRetirePhase::Active,
            active_done_upto: None,
            pending_done_upto: None,
            detached_done_upto: None,
            open_done_upto: None,
            slot_unproven_pass: false,
            changed: false,
            session_had_open: None,
            open_insert_pending: None,
            selected_counted: false,
            pending_active: None,
            pending_pending: None,
            pending_detached: None,
            pending_open: None,
        }
    }

    /// Drive one budgeted subset-retire step through the shared
    /// pre-debit gate. Returns whether the retire completed. On
    /// exhaustion yields WITHOUT advancing past the refused leaf (no
    /// read past the credit). Matching machines emit `Ended` through
    /// `sink` (the disposal tees them into its preserved key-use,
    /// queuing association releases for the same budget). Preserves
    /// terminal reasons and effect order (map order per phase).
    pub(crate) fn poll_retire_step<S: OperationSink>(
        &mut self,
        cursor: &mut EdgeRetireCursor,
        sink: &mut S,
        budget: &mut LeafBudget,
    ) -> bool {
        if let EdgeRetireScope::Selected { flags, .. } = &cursor.scope
            && !cursor.selected_counted
        {
            cursor.selected_counted = true;
            if flags & !crate::semantics::KNOWN_CANCEL_FLAGS != 0 {
                self.evidence.session_cancel_unknown_flags =
                    self.evidence.session_cancel_unknown_flags.saturating_add(1);
            }
        }
        loop {
            match cursor.phase {
                EdgeRetirePhase::Active => {
                    if cursor.pending_active.is_none() {
                        if !budget.try_charge() {
                            return false;
                        }
                        let Some(next) = self.retire_next_active(cursor) else {
                            if matches!(cursor.scope, EdgeRetireScope::SessionMachines { .. }) {
                                self.evidence.operation_state_imports =
                                    self.evidence.operation_state_imports.saturating_add(1);
                                cursor.phase = EdgeRetirePhase::Done;
                                continue;
                            }
                            if matches!(
                                cursor.scope,
                                EdgeRetireScope::Slot {
                                    close_all: true,
                                    ..
                                }
                            ) && !cursor.slot_unproven_pass
                            {
                                cursor.slot_unproven_pass = true;
                                cursor.active_done_upto = None;
                                continue;
                            }
                            cursor.phase = EdgeRetirePhase::Pending;
                            continue;
                        };
                        cursor.pending_active = Some(ActiveVisit {
                            next,
                            decision: None,
                        });
                    }
                    let next = cursor.pending_active.expect("visit retained").next;
                    let decision = match cursor.pending_active.expect("visit retained").decision {
                        Some(decision) => decision,
                        None => {
                            // Slot decisions read the open map
                            // (charged); all others are pure.
                            if matches!(cursor.scope, EdgeRetireScope::Slot { .. })
                                && !budget.try_charge()
                            {
                                return false;
                            }
                            let (session, bit) = next;
                            let decision = self.retire_active_decision(cursor, session, bit);
                            cursor
                                .pending_active
                                .as_mut()
                                .expect("visit retained")
                                .decision = Some(decision);
                            decision
                        }
                    };
                    let (session, bit) = next;
                    match decision {
                        RetireActiveDecision::Skip => {
                            cursor.active_done_upto = Some(next);
                            cursor.pending_active = None;
                            if budget.remaining() == 0 {
                                return false;
                            }
                        }
                        RetireActiveDecision::End(end) => {
                            if !budget.try_charge_n(2) {
                                return false;
                            }
                            cursor.active_done_upto = Some(next);
                            cursor.pending_active = None;
                            cursor.changed = true;
                            #[cfg(test)]
                            {
                                self.bump_edge_read_for_test();
                                self.bump_edge_read_for_test();
                            }
                            let machine = self
                                .active
                                .remove(&next)
                                .expect("retire scan retained its machine");
                            self.release_resource_charge(resources::ACTIVE_MACHINE_CHARGE);
                            match end {
                                EndState::Completed => {
                                    self.completed = self.completed.saturating_add(1);
                                }
                                EndState::Cancelled => {
                                    self.cancelled = self.cancelled.saturating_add(1);
                                }
                                EndState::Failed => {
                                    self.failed = self.failed.saturating_add(1);
                                }
                                EndState::Unknown => {
                                    self.unknown = self.unknown.saturating_add(1);
                                }
                            }
                            if S::WANTS_EFFECTS {
                                sink.emit(OperationEffect::Ended {
                                    id: OperationId(machine.generation),
                                    category: Self::category_name(bit),
                                    outcome: end.outcome(),
                                    origin: cursor.origin.clone(),
                                    length: None,
                                    corroboration: None,
                                });
                            }
                            let _ = session;
                            if budget.remaining() == 0 {
                                return false;
                            }
                        }
                    }
                }
                EdgeRetirePhase::Pending => {
                    if cursor.pending_pending.is_none() {
                        if matches!(cursor.scope, EdgeRetireScope::SessionMachines { .. }) {
                            cursor.phase = EdgeRetirePhase::Detached;
                            continue;
                        }
                        if !budget.try_charge() {
                            return false;
                        }
                        let Some(next) = self.retire_next_pending(cursor) else {
                            cursor.phase = EdgeRetirePhase::Detached;
                            continue;
                        };
                        // Session decisions are pure (always doomed);
                        // Slot/Selected decisions read below.
                        let doomed = if matches!(cursor.scope, EdgeRetireScope::Session { .. }) {
                            Some(true)
                        } else {
                            None
                        };
                        cursor.pending_pending = Some((next, doomed));
                    }
                    let (next, doomed) = cursor.pending_pending.expect("visit retained");
                    let doomed = match doomed {
                        Some(doomed) => doomed,
                        None => {
                            if !budget.try_charge() {
                                return false;
                            }
                            let doomed = self.retire_pending_doomed(cursor, &next);
                            cursor.pending_pending = Some((next, Some(doomed)));
                            doomed
                        }
                    };
                    if doomed {
                        if !budget.try_charge() {
                            return false;
                        }
                        #[cfg(test)]
                        self.bump_edge_read_for_test();
                        self.pending.remove(&next);
                        cursor.changed = true;
                    }
                    cursor.pending_done_upto = Some(next);
                    cursor.pending_pending = None;
                    if budget.remaining() == 0 {
                        return false;
                    }
                }
                EdgeRetirePhase::Detached => {
                    if self.detached.is_empty()
                        || matches!(cursor.scope, EdgeRetireScope::SessionMachines { .. })
                    {
                        if matches!(
                            cursor.scope,
                            EdgeRetireScope::Slot {
                                close_all: false,
                                ..
                            }
                        ) {
                            if cursor.changed {
                                self.evidence.auth_state_ambiguities =
                                    self.evidence.auth_state_ambiguities.saturating_add(1);
                            }
                            cursor.phase = EdgeRetirePhase::Done;
                        } else {
                            cursor.phase = EdgeRetirePhase::Open;
                        }
                        continue;
                    }
                    if cursor.pending_detached.is_none() {
                        if !budget.try_charge() {
                            return false;
                        }
                        let Some(next) = self.retire_next_detached(cursor) else {
                            if matches!(
                                cursor.scope,
                                EdgeRetireScope::Slot {
                                    close_all: false,
                                    ..
                                }
                            ) {
                                if cursor.changed {
                                    self.evidence.auth_state_ambiguities =
                                        self.evidence.auth_state_ambiguities.saturating_add(1);
                                }
                                cursor.phase = EdgeRetirePhase::Done;
                            } else {
                                cursor.phase = EdgeRetirePhase::Open;
                            }
                            continue;
                        };
                        cursor.pending_detached = Some(DetachedVisit {
                            next,
                            stage: DetachedVisitStage::NeedValue,
                        });
                    }
                    let visit = cursor.pending_detached.expect("visit retained");
                    match visit.stage {
                        DetachedVisitStage::NeedValue => {
                            if !budget.try_charge() {
                                return false;
                            }
                            #[cfg(test)]
                            self.bump_edge_read_for_test();
                            let id = self
                                .detached
                                .get(&visit.next)
                                .expect("retire scan retained");
                            let owner = id.owner;
                            let function = id.call.function.clone();
                            match Self::detached_preliminary_action(&cursor.scope, owner, &function)
                            {
                                DetachedPreliminaryAction::Done(action) => {
                                    cursor.pending_detached = Some(DetachedVisit {
                                        next: visit.next,
                                        stage: DetachedVisitStage::Ready { action },
                                    });
                                }
                                DetachedPreliminaryAction::NeedOpen { owner } => {
                                    cursor.pending_detached = Some(DetachedVisit {
                                        next: visit.next,
                                        stage: DetachedVisitStage::NeedOpen { owner },
                                    });
                                }
                            }
                        }
                        DetachedVisitStage::NeedOpen { owner } => {
                            if !budget.try_charge() {
                                return false;
                            }
                            #[cfg(test)]
                            self.bump_edge_read_for_test();
                            let open = self.open.get(&owner).copied();
                            let action = Self::detached_slot_action(&cursor.scope, open);
                            cursor.pending_detached = Some(DetachedVisit {
                                next: visit.next,
                                stage: DetachedVisitStage::Ready { action },
                            });
                        }
                        DetachedVisitStage::Ready { action } => {
                            match action {
                                RetireDetachedAction::Float => {
                                    if !budget.try_charge() {
                                        return false;
                                    }
                                    #[cfg(test)]
                                    self.bump_edge_read_for_test();
                                    if let Some(id) = self.detached.get_mut(&visit.next) {
                                        id.owner = None;
                                        cursor.changed = true;
                                    }
                                }
                                RetireDetachedAction::Drop => {
                                    if !budget.try_charge() {
                                        return false;
                                    }
                                    #[cfg(test)]
                                    self.bump_edge_read_for_test();
                                    self.detached.remove(&visit.next);
                                    cursor.changed = true;
                                }
                                RetireDetachedAction::Keep => {}
                            }
                            cursor.detached_done_upto = Some(visit.next);
                            cursor.pending_detached = None;
                            if budget.remaining() == 0 {
                                return false;
                            }
                        }
                    }
                }
                EdgeRetirePhase::Open => match cursor.scope.clone() {
                    EdgeRetireScope::Session { session, post, .. } => {
                        if cursor.open_insert_pending.is_none() && cursor.session_had_open.is_none()
                        {
                            if !budget.try_charge() {
                                return false;
                            }
                            #[cfg(test)]
                            self.bump_edge_read_for_test();
                            let had = self.open.remove(&session).is_some();
                            if had {
                                self.release_resource_charge(resources::OPEN_BINDING_CHARGE);
                                cursor.changed = true;
                            }
                            cursor.session_had_open = Some(had);
                            if let SessionPost::Open { slot } = post {
                                cursor.open_insert_pending = Some((session, slot));
                            }
                        }
                        if let Some((ins_session, ins_slot)) = cursor.open_insert_pending {
                            if !budget.try_charge() {
                                return false;
                            }
                            #[cfg(test)]
                            self.bump_edge_read_for_test();
                            // One entry lookup (charged above) covers
                            // the occupancy check and the insert; the
                            // length pre-read is free metadata. Each arm
                            // retains exactly like
                            // `retain_resource_charge` (split + absorb
                            // through disjoint field borrows, since the
                            // entry holds the map).
                            let full = self.open.len() >= MAX_EDGE_SESSIONS;
                            use std::collections::btree_map::Entry;
                            match self.open.entry(ins_session) {
                                Entry::Occupied(mut slot) => {
                                    if let Some(prepared) = self.resource_transition.as_mut() {
                                        let lease = prepared
                                            .reservation
                                            .split(resources::OPEN_BINDING_CHARGE);
                                        self.resource_owner
                                            .as_mut()
                                            .expect("admitted owner")
                                            .absorb(lease);
                                    }
                                    slot.insert(ins_slot);
                                }
                                Entry::Vacant(slot) => {
                                    if full {
                                        self.dropped = self.dropped.saturating_add(1);
                                    } else {
                                        if let Some(prepared) = self.resource_transition.as_mut() {
                                            let lease = prepared
                                                .reservation
                                                .split(resources::OPEN_BINDING_CHARGE);
                                            self.resource_owner
                                                .as_mut()
                                                .expect("admitted owner")
                                                .absorb(lease);
                                        }
                                        slot.insert(ins_slot);
                                    }
                                }
                            }
                            cursor.open_insert_pending = None;
                        }
                        match post {
                            SessionPost::Close => {
                                if cursor.session_had_open == Some(false) {
                                    self.evidence.unmatched_closes =
                                        self.evidence.unmatched_closes.saturating_add(1);
                                }
                            }
                            SessionPost::Reconcile => {
                                if cursor.changed {
                                    self.evidence.state_reconciliations =
                                        self.evidence.state_reconciliations.saturating_add(1);
                                }
                            }
                            SessionPost::Open { .. } => {
                                if cursor.changed {
                                    self.evidence.state_reconciliations =
                                        self.evidence.state_reconciliations.saturating_add(1);
                                }
                            }
                        }
                        cursor.phase = EdgeRetirePhase::Done;
                    }
                    EdgeRetireScope::SessionMachines { .. } => {
                        cursor.phase = EdgeRetirePhase::Done;
                    }
                    EdgeRetireScope::Selected { ambiguous, .. } => {
                        if ambiguous {
                            self.evidence.session_cancel_ambiguities =
                                self.evidence.session_cancel_ambiguities.saturating_add(1);
                        }
                        cursor.phase = EdgeRetirePhase::Done;
                    }
                    EdgeRetireScope::Slot { slot, close_all } => {
                        if !close_all {
                            cursor.phase = EdgeRetirePhase::Done;
                            continue;
                        }
                        if cursor.pending_open.is_none() {
                            if !budget.try_charge() {
                                return false;
                            }
                            let Some(next) = self.retire_next_open(cursor) else {
                                cursor.phase = EdgeRetirePhase::Done;
                                continue;
                            };
                            cursor.pending_open = Some(next);
                        }
                        let (session, owner) = cursor.pending_open.expect("visit retained");
                        if owner == slot {
                            if !budget.try_charge() {
                                return false;
                            }
                            #[cfg(test)]
                            self.bump_edge_read_for_test();
                            self.open.remove(&session);
                            self.release_resource_charge(resources::OPEN_BINDING_CHARGE);
                            cursor.changed = true;
                        }
                        cursor.open_done_upto = Some(session);
                        cursor.pending_open = None;
                        if budget.remaining() == 0 {
                            return false;
                        }
                    }
                },
                EdgeRetirePhase::Done => {
                    return true;
                }
            }
        }
    }

    /// Next active key for the retire scan: session ranges seek
    /// directly (only the session's keys are visited); slot scopes
    /// scan all with a per-session predicate.
    fn retire_next_active(&self, cursor: &EdgeRetireCursor) -> Option<(u64, u16)> {
        #[cfg(test)]
        self.bump_edge_read_for_test();
        use std::ops::Bound::{Excluded, Included, Unbounded};
        match &cursor.scope {
            EdgeRetireScope::Session { session, .. }
            | EdgeRetireScope::SessionMachines { session, .. } => match cursor.active_done_upto {
                None => self
                    .active
                    .range((*session, 0)..=(*session, u16::MAX))
                    .next()
                    .map(|(key, _)| *key),
                Some(done) => self
                    .active
                    .range((Excluded(done), Included((*session, u16::MAX))))
                    .next()
                    .map(|(key, _)| *key),
            },
            EdgeRetireScope::Selected { session, .. } => match cursor.active_done_upto {
                None => self
                    .active
                    .range((*session, 0)..=(*session, u16::MAX))
                    .next()
                    .map(|(key, _)| *key),
                Some(done) => self
                    .active
                    .range((Excluded(done), Included((*session, u16::MAX))))
                    .next()
                    .map(|(key, _)| *key),
            },
            EdgeRetireScope::Slot { .. } => match cursor.active_done_upto {
                None => self.active.keys().next().copied(),
                Some(done) => self
                    .active
                    .range((Excluded(done), Unbounded))
                    .next()
                    .map(|(key, _)| *key),
            },
        }
    }

    /// Whether the scanned active machine ends (and how) or is
    /// skipped (still visited, 1 leaf).
    fn retire_active_decision(
        &self,
        cursor: &EdgeRetireCursor,
        session: u64,
        bit: u16,
    ) -> RetireActiveDecision {
        match &cursor.scope {
            EdgeRetireScope::Session { end_unknown, .. }
            | EdgeRetireScope::SessionMachines { end_unknown, .. } => {
                RetireActiveDecision::End(if *end_unknown {
                    EndState::Unknown
                } else {
                    EndState::Cancelled
                })
            }
            EdgeRetireScope::Slot { slot, close_all } => {
                #[cfg(test)]
                self.bump_edge_read_for_test();
                if *close_all && cursor.slot_unproven_pass {
                    match self.open.get(&session) {
                        None => RetireActiveDecision::End(EndState::Unknown),
                        Some(_) => RetireActiveDecision::Skip,
                    }
                } else {
                    match self.open.get(&session) {
                        Some(owner) if owner == slot => {
                            RetireActiveDecision::End(EndState::Cancelled)
                        }
                        _ => RetireActiveDecision::Skip,
                    }
                }
            }
            EdgeRetireScope::Selected { flags, .. } => {
                let mask = cancel_operation_mask(*flags);
                if mask & bit != 0 {
                    RetireActiveDecision::End(EndState::Cancelled)
                } else {
                    RetireActiveDecision::Skip
                }
            }
        }
    }

    /// Next pending key for the retire scan.
    fn retire_next_pending(&self, cursor: &EdgeRetireCursor) -> Option<(u64, u32)> {
        #[cfg(test)]
        self.bump_edge_read_for_test();
        use std::ops::Bound::{Excluded, Included, Unbounded};
        match &cursor.scope {
            EdgeRetireScope::Session { session, .. }
            | EdgeRetireScope::Selected { session, .. } => match cursor.pending_done_upto {
                None => self
                    .pending
                    .range((*session, 0)..=(*session, u32::MAX))
                    .next()
                    .map(|(key, _)| *key),
                Some(done) => self
                    .pending
                    .range((Excluded(done), Included((*session, u32::MAX))))
                    .next()
                    .map(|(key, _)| *key),
            },
            EdgeRetireScope::SessionMachines { .. } => None,
            EdgeRetireScope::Slot { .. } => match cursor.pending_done_upto {
                None => self.pending.keys().next().copied(),
                Some(done) => self
                    .pending
                    .range((Excluded(done), Unbounded))
                    .next()
                    .map(|(key, _)| *key),
            },
        }
    }

    /// Whether the scanned pending call drops.
    fn retire_pending_doomed(&self, cursor: &EdgeRetireCursor, next: &(u64, u32)) -> bool {
        match &cursor.scope {
            EdgeRetireScope::Session { .. } => true,
            EdgeRetireScope::SessionMachines { .. } => false,
            EdgeRetireScope::Slot { slot, close_all } => {
                #[cfg(test)]
                self.bump_edge_read_for_test();
                match self.open.get(&next.0) {
                    Some(owner) => owner == slot,
                    None => *close_all,
                }
            }
            EdgeRetireScope::Selected {
                session: _, flags, ..
            } => {
                #[cfg(test)]
                self.bump_edge_read_for_test();
                let pending = self.pending.get(next).expect("retire scan retained");
                let descriptor = crate::kinds::descriptor(&pending.call.function)
                    .unwrap_or(SlotSemantics::COUNT_ONLY);
                let mask = cancel_operation_mask(*flags);
                !(descriptor.operations & mask == 0
                    && direct_cancel_flag(descriptor.direct) & flags == 0)
            }
        }
    }

    /// Next detached key for the retire scan (detached keys are not
    /// owner-ordered, so session scopes scan all).
    fn retire_next_detached(
        &self,
        cursor: &EdgeRetireCursor,
    ) -> Option<(u64, u32, crate::semantics_objects::AsyncValue)> {
        #[cfg(test)]
        self.bump_edge_read_for_test();
        use std::ops::Bound::{Excluded, Unbounded};
        match &cursor.scope {
            EdgeRetireScope::SessionMachines { .. } => None,
            _ => match &cursor.detached_done_upto {
                None => self.detached.keys().next().copied(),
                Some(done) => self
                    .detached
                    .range((Excluded(*done), Unbounded))
                    .next()
                    .map(|(key, _)| *key),
            },
        }
    }

    /// Preliminary detached action from a retained value read (no
    /// map access): `Done` resolves immediately; `NeedOpen` needs the
    /// owner's open row (Slot scope with an owned id only). Mirrors
    /// the synchronous float/drop/keep exactly.
    fn detached_preliminary_action(
        scope: &EdgeRetireScope,
        owner: Option<u64>,
        function: &str,
    ) -> DetachedPreliminaryAction {
        match scope {
            EdgeRetireScope::Session { session, .. } => {
                if owner == Some(*session) {
                    DetachedPreliminaryAction::Done(RetireDetachedAction::Float)
                } else {
                    DetachedPreliminaryAction::Done(RetireDetachedAction::Keep)
                }
            }
            EdgeRetireScope::SessionMachines { .. } => {
                DetachedPreliminaryAction::Done(RetireDetachedAction::Keep)
            }
            EdgeRetireScope::Slot { .. } => match owner {
                Some(owner) => DetachedPreliminaryAction::NeedOpen { owner },
                None => DetachedPreliminaryAction::Done(RetireDetachedAction::Keep),
            },
            EdgeRetireScope::Selected { session, flags, .. } => {
                if owner != Some(*session) {
                    return DetachedPreliminaryAction::Done(RetireDetachedAction::Keep);
                }
                let descriptor =
                    crate::kinds::descriptor(function).unwrap_or(SlotSemantics::COUNT_ONLY);
                let mask = cancel_operation_mask(*flags);
                if descriptor.operations & mask == 0
                    && direct_cancel_flag(descriptor.direct) & flags == 0
                {
                    DetachedPreliminaryAction::Done(RetireDetachedAction::Keep)
                } else {
                    DetachedPreliminaryAction::Done(RetireDetachedAction::Drop)
                }
            }
        }
    }

    /// Slot detached action from a retained open read (Slot scope
    /// only): float owned (or close-all orphaned) ids, keep the rest.
    /// Mirrors the synchronous arm exactly.
    fn detached_slot_action(scope: &EdgeRetireScope, open: Option<u64>) -> RetireDetachedAction {
        let EdgeRetireScope::Slot { slot, close_all } = scope else {
            debug_assert!(false, "only Slot scopes read the owner's open");
            return RetireDetachedAction::Keep;
        };
        match open {
            Some(candidate) if candidate == *slot => RetireDetachedAction::Float,
            Some(_) => RetireDetachedAction::Keep,
            None if *close_all => RetireDetachedAction::Float,
            None => RetireDetachedAction::Keep,
        }
    }

    /// Next open key for slot-scope scans.
    /// Next open entry for the retire scan: session + slot in one
    /// charged lookup (the caller compares the retained slot, never
    /// re-reading).
    fn retire_next_open(&self, cursor: &EdgeRetireCursor) -> Option<(u64, u64)> {
        #[cfg(test)]
        self.bump_edge_read_for_test();
        use std::ops::Bound::{Excluded, Unbounded};
        match cursor.open_done_upto {
            None => self.open.iter().next().map(|(key, slot)| (*key, *slot)),
            Some(done) => self
                .open
                .range((Excluded(done), Unbounded))
                .next()
                .map(|(key, slot)| (*key, *slot)),
        }
    }

    /// Start the resumable budgeted admission for one staged PENDING
    /// head's facts. The caller drives
    /// [`Self::poll_pending_admission_step`] with the shared
    /// [`LeafBudget`] until it completes, then pops the head WITHOUT a
    /// second observe (the cursor already queued it; a second observe
    /// would double-queue).
    pub(crate) fn start_pending_admission(&self, call: SemanticCall) -> PendingAdmissionCursor {
        let _ = self.last_seen_ns;
        PendingAdmissionCursor {
            call,
            phase: PendingAdmissionPhase::Route,
            route: None,
            bits: Vec::new(),
            capture: Vec::new(),
            scan_pending_upto: None,
            scan_pending_left: 0,
            scan_detached_upto: None,
            scan_detached_left: 0,
            best: None,
            evicted: None,
            evict_done: 0,
            evict_end_pending: None,
        }
    }

    /// Drive one budgeted pending-admission step through the shared
    /// pre-debit gate. Returns whether the admission completed. On
    /// exhaustion yields WITHOUT advancing past the refused leaf (no
    /// read past the credit). Eviction terminals emit through `sink`
    /// (the disposal tees them into its preserved key-use, queuing
    /// association releases for the same budget). Matches synchronous
    /// queueing + oldest eviction exactly.
    pub(crate) fn poll_pending_admission_step<S: OperationSink>(
        &mut self,
        cursor: &mut PendingAdmissionCursor,
        sink: &mut S,
        budget: &mut LeafBudget,
    ) -> bool {
        loop {
            match cursor.phase {
                PendingAdmissionPhase::Route => {
                    if cursor.route.is_none() {
                        if !budget.try_charge() {
                            return false;
                        }
                        #[cfg(test)]
                        self.bump_edge_read_for_test();
                        cursor.route = Some(self.route_pending(&cursor.call));
                    }
                    match cursor.route.expect("route retained") {
                        PendingRoute::Unroutable => {
                            self.orphans = self.orphans.saturating_add(1);
                            cursor.phase = PendingAdmissionPhase::Done;
                        }
                        PendingRoute::Duplicate => {
                            self.evidence.async_duplicates =
                                self.evidence.async_duplicates.saturating_add(1);
                            self.orphans = self.orphans.saturating_add(1);
                            cursor.phase = PendingAdmissionPhase::Done;
                        }
                        PendingRoute::Fresh { descriptor, .. } => {
                            cursor.bits = crate::semantics::operation_bits(descriptor.operations)
                                .map(|(bit, _)| bit)
                                .collect();
                            cursor.phase = PendingAdmissionPhase::Capture;
                        }
                    }
                    continue;
                }
                PendingAdmissionPhase::Capture => {
                    if cursor.capture.len() >= cursor.bits.len() {
                        cursor.phase = PendingAdmissionPhase::Insert;
                        continue;
                    }
                    if !budget.try_charge() {
                        return false;
                    }
                    #[cfg(test)]
                    self.bump_edge_read_for_test();
                    let bit = cursor.bits[cursor.capture.len()];
                    let session = cursor.call.session;
                    let generation = self
                        .active
                        .get(&(session, bit))
                        .map(|machine| machine.generation);
                    cursor.capture.push((bit, generation));
                    if budget.remaining() == 0 {
                        return false;
                    }
                }
                PendingAdmissionPhase::Insert => {
                    let PendingRoute::Fresh {
                        function, charge, ..
                    } = cursor.route.expect("fresh admission inserts")
                    else {
                        debug_assert!(false, "only fresh admissions insert");
                        return false;
                    };
                    self.sequence = self.sequence.wrapping_add(1);
                    let sequence = self.sequence;
                    let resource = self.take_resource_charge(charge);
                    let origin = CallOrigin {
                        bits: std::mem::take(&mut cursor.capture),
                    };
                    self.pending.insert(
                        (cursor.call.session, function),
                        PendingCall {
                            call: cursor.call.clone(),
                            origin,
                            origin_pos: None,
                            sequence,
                            resource,
                        },
                    );
                    cursor.scan_pending_left = self.pending.len();
                    cursor.scan_detached_left = self.detached.len();
                    cursor.phase = PendingAdmissionPhase::EvictScan;
                    continue;
                }
                PendingAdmissionPhase::EvictScan => {
                    if self.pending.len() + self.detached.len() <= MAX_EDGE_PENDING {
                        cursor.phase = PendingAdmissionPhase::Done;
                        continue;
                    }
                    if cursor.scan_pending_left > 0 {
                        if !budget.try_charge() {
                            return false;
                        }
                        #[cfg(test)]
                        self.bump_edge_read_for_test();
                        let (key, sequence) = self
                            .scan_next_pending(cursor.scan_pending_upto)
                            .expect("admission scan retained its record");
                        cursor.scan_pending_upto = Some(key);
                        cursor.scan_pending_left -= 1;
                        let better = cursor.best.is_none_or(|best| sequence < best.sequence());
                        if better {
                            cursor.best = Some(PendingAdmissionBest::Pending { key, sequence });
                        }
                        if budget.remaining() == 0 {
                            return false;
                        }
                        continue;
                    }
                    if cursor.scan_detached_left > 0 {
                        if !budget.try_charge() {
                            return false;
                        }
                        #[cfg(test)]
                        self.bump_edge_read_for_test();
                        let (key, sequence) = self
                            .scan_next_detached(cursor.scan_detached_upto)
                            .expect("admission scan retained its record");
                        cursor.scan_detached_upto = Some(key);
                        cursor.scan_detached_left -= 1;
                        // Strictly less keeps pending-wins-ties (matches
                        // the synchronous comparison).
                        let better = cursor.best.is_none_or(|best| sequence < best.sequence());
                        if better {
                            cursor.best = Some(PendingAdmissionBest::Detached { key, sequence });
                        }
                        if budget.remaining() == 0 {
                            return false;
                        }
                        continue;
                    }
                    let best = cursor.best.expect("an over-bound scan finds a record");
                    let (session, call, origin, resource) = match best {
                        PendingAdmissionBest::Pending { key, .. } => {
                            let record =
                                self.pending.remove(&key).expect("scan retained its record");
                            (key.0, record.call, record.origin, record.resource)
                        }
                        PendingAdmissionBest::Detached { key, .. } => {
                            let id = self
                                .detached
                                .remove(&key)
                                .expect("scan retained its record");
                            (id.call.session, id.call, id.origin, id.resource)
                        }
                    };
                    let effect_origin = if S::WANTS_EFFECTS {
                        EffectOrigin::from(&call)
                    } else {
                        EffectOrigin::placeholder()
                    };
                    drop(call);
                    cursor.evicted = Some(EvictedRecord {
                        session,
                        origin,
                        effect_origin,
                        resource,
                    });
                    cursor.evict_done = 0;
                    cursor.phase = PendingAdmissionPhase::EvictEnd;
                    continue;
                }
                PendingAdmissionPhase::EvictEnd => {
                    let total = cursor
                        .evicted
                        .as_ref()
                        .map_or(0, |evicted| evicted.origin.bits.len());
                    if cursor.evict_done >= total {
                        if let Some(evicted) = cursor.evicted.take() {
                            self.evidence.async_evictions =
                                self.evidence.async_evictions.saturating_add(1);
                            drop(evicted.origin);
                            drop(evicted.resource);
                        }
                        cursor.evict_end_pending = None;
                        cursor.phase = PendingAdmissionPhase::Done;
                        continue;
                    }
                    if let Some((session, bit)) = cursor.evict_end_pending {
                        if !budget.try_charge_n(2) {
                            return false;
                        }
                        #[cfg(test)]
                        {
                            self.bump_edge_read_for_test();
                            self.bump_edge_read_for_test();
                        }
                        let evicted = cursor.evicted.as_ref().expect("evicted retained");
                        let end_origin = evicted.effect_origin.clone();
                        self.end_machine(
                            session,
                            bit,
                            Self::category_name(bit),
                            EndState::Unknown,
                            &end_origin,
                            &CompletionEvidence::NONE,
                            sink,
                        );
                        cursor.evict_end_pending = None;
                        cursor.evict_done += 1;
                        if budget.remaining() == 0 {
                            return false;
                        }
                        continue;
                    }
                    if !budget.try_charge() {
                        return false;
                    }
                    #[cfg(test)]
                    self.bump_edge_read_for_test();
                    let evicted = cursor.evicted.as_ref().expect("evicted retained");
                    let (session, bound) =
                        (evicted.session, evicted.origin.bits[cursor.evict_done]);
                    let (bit, generation) = bound;
                    let live_matches = generation.is_some()
                        && self
                            .active
                            .get(&(session, bit))
                            .map(|machine| machine.generation)
                            == generation;
                    if !live_matches {
                        cursor.evict_done += 1;
                        if budget.remaining() == 0 {
                            return false;
                        }
                        continue;
                    }
                    cursor.evict_end_pending = Some((session, bit));
                    if !budget.try_charge_n(2) {
                        return false;
                    }
                    #[cfg(test)]
                    {
                        self.bump_edge_read_for_test();
                        self.bump_edge_read_for_test();
                    }
                    let evicted = cursor.evicted.as_ref().expect("evicted retained");
                    let end_origin = evicted.effect_origin.clone();
                    self.end_machine(
                        session,
                        bit,
                        Self::category_name(bit),
                        EndState::Unknown,
                        &end_origin,
                        &CompletionEvidence::NONE,
                        sink,
                    );
                    cursor.evict_end_pending = None;
                    cursor.evict_done += 1;
                    if budget.remaining() == 0 {
                        return false;
                    }
                }
                PendingAdmissionPhase::Done => {
                    return true;
                }
            }
        }
    }

    /// Next pending record for the oldest scan: key + sequence in
    /// BTree key order (one charged read at the call site).
    fn scan_next_pending(&self, upto: Option<(u64, u32)>) -> Option<((u64, u32), u64)> {
        use std::ops::Bound::{Excluded, Unbounded};
        match upto {
            None => self
                .pending
                .iter()
                .next()
                .map(|(key, record)| (*key, record.sequence)),
            Some(done) => self
                .pending
                .range((Excluded(done), Unbounded))
                .next()
                .map(|(key, record)| (*key, record.sequence)),
        }
    }

    /// Next detached record for the oldest scan: key + sequence in
    /// BTree key order (one charged read at the call site).
    fn scan_next_detached(
        &self,
        upto: Option<(u64, u32, crate::semantics_objects::AsyncValue)>,
    ) -> Option<((u64, u32, crate::semantics_objects::AsyncValue), u64)> {
        use std::ops::Bound::{Excluded, Unbounded};
        match upto {
            None => self
                .detached
                .iter()
                .next()
                .map(|(key, id)| (*key, id.sequence)),
            Some(done) => self
                .detached
                .range((Excluded(done), Unbounded))
                .next()
                .map(|(key, id)| (*key, id.sequence)),
        }
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
    fn observe_async<S: OperationSink>(&mut self, call: &SemanticCall, sink: &mut S) {
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
                // 6.07b Complete-once (§3.3): eligible at the
                // completion's own invocation cut are the pending
                // (session, target) plus detached ids owned by the
                // completer for that target. Exactly one eligible
                // record consumes once; zero or ≥2 orphan with
                // evidence and consume none. Pending-first and
                // BTree-first selection are withdrawn as proof.
                // Eligibility is shared with preflight, which reserves
                // only the unique record's replay growth.
                match self.complete_eligible(call.session, call.target_function) {
                    CompleteEligible::Zero => {
                        self.orphans = self.orphans.saturating_add(1);
                    }
                    CompleteEligible::Many => {
                        self.orphans = self.orphans.saturating_add(1);
                        self.evidence.async_duplicates =
                            self.evidence.async_duplicates.saturating_add(1);
                    }
                    CompleteEligible::Pending(pending_key) => {
                        let pending = self
                            .pending
                            .remove(&pending_key)
                            .expect("eligible pending record");
                        let PendingCall {
                            call: original,
                            origin,
                            resource,
                            ..
                        } = pending;
                        self.complete_pending(call, original, &origin, sink);
                        drop(origin);
                        drop(resource);
                    }
                    CompleteEligible::Detached(detached_key) => {
                        let id = self
                            .detached
                            .remove(&detached_key)
                            .expect("eligible detached record");
                        let AsyncId {
                            call: original,
                            origin,
                            resource,
                            ..
                        } = id;
                        self.complete_pending(call, original, &origin, sink);
                        drop(origin);
                        drop(resource);
                    }
                }
            }
            lifecycle::ASYNC_GET_ID if call.rv == CkRv::OK.0 => {
                let Some(slot) = self.open.get(&call.session).copied() else {
                    self.orphans = self.orphans.saturating_add(1);
                    return;
                };
                // 6.07b GetID mint (§3.1): vacancy is checked BEFORE
                // custody moves. A same-key remint over a live origin
                // refuses/orphans the second mint and counts
                // ambiguity — it never overwrites the first origin,
                // and the refused mint's pending stays intact.
                let detached_key = (
                    slot,
                    call.target_function,
                    crate::semantics_objects::AsyncValue::from(call.async_value),
                );
                if self.detached.contains_key(&detached_key) {
                    self.orphans = self.orphans.saturating_add(1);
                    self.evidence.async_duplicates =
                        self.evidence.async_duplicates.saturating_add(1);
                    return;
                }
                let Some(pending) = self.pending.remove(&(call.session, call.target_function))
                else {
                    self.orphans = self.orphans.saturating_add(1);
                    return;
                };
                self.sequence = self.sequence.wrapping_add(1);
                let sequence = self.sequence;
                self.detached.insert(
                    detached_key,
                    AsyncId {
                        owner: Some(call.session),
                        call: pending.call,
                        origin: pending.origin,
                        origin_pos: pending.origin_pos,
                        sequence,
                        resource: pending.resource,
                    },
                );
                self.evict_async_if_needed(sink);
            }
            lifecycle::ASYNC_JOIN if call.rv == CkRv::OK.0 => {
                let Some(slot) = self.open.get(&call.session).copied() else {
                    self.orphans = self.orphans.saturating_add(1);
                    return;
                };
                match self.detached.get_mut(&(
                    slot,
                    call.target_function,
                    crate::semantics_objects::AsyncValue::from(call.async_value),
                )) {
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
    fn queue_pending<S: OperationSink>(&mut self, call: &SemanticCall, sink: &mut S) {
        // 6.07b duplicate queue (§3.5): a live (session, target)
        // refuses the second PENDING — first wins, counted ambiguity,
        // never an overwrite. No charge is taken for a refused queue.
        // Routing is shared with preflight, which reserves only Fresh.
        let route = self.route_pending(call);
        let PendingRoute::Fresh {
            function,
            descriptor,
            charge,
        } = route
        else {
            if route == PendingRoute::Duplicate {
                self.evidence.async_duplicates = self.evidence.async_duplicates.saturating_add(1);
            }
            self.orphans = self.orphans.saturating_add(1);
            return;
        };
        self.sequence = self.sequence.wrapping_add(1);
        let sequence = self.sequence;
        let resource = self.take_resource_charge(charge);
        let origin = self.capture_origin(call.session, &descriptor);
        self.pending.insert(
            (call.session, function),
            PendingCall {
                call: call.clone(),
                origin,
                // No H0 channel yet: S1Only queueing stores no
                // origin position. Joint replay will supply it.
                origin_pos: None,
                sequence,
                resource,
            },
        );
        self.evict_async_if_needed(sink);
    }

    /// Snapshot the live-machine generations a pending call binds to
    /// (F2): one entry per affected operation bit, `None` where no
    /// machine is live.
    fn capture_origin(&self, session: u64, descriptor: &SlotSemantics) -> CallOrigin {
        // No test bump here: the budgeted admission cursor charges and
        // counts each capture lookup at its own read site; the
        // synchronous path stays unbumped.
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

    /// Apply a completion to the record it named: the execution
    /// replays the pending call's facts with the completion's return,
    /// session, and time (receiver custody + terminal time) — but
    /// ONLY when the completing session still holds the originating
    /// operation lifetime on every affected bit (F2). The replayed
    /// effects keep the ORIGINAL consumed call's identity, separate
    /// from that custody. A stale completion (replaced, ended, or
    /// never-related machine — notably a joined completion landing
    /// on the receiver's own operation) orphans per affected bit
    /// instead of joining, like any other unattributable evidence.
    /// This deliberately differs from the capture-wide
    /// `complete_pending`, which replays against current bindings.
    fn complete_pending<S: OperationSink>(
        &mut self,
        completion: &SemanticCall,
        pending: SemanticCall,
        origin: &CallOrigin,
        sink: &mut S,
    ) {
        if !self.origin_matches(completion.session, origin) {
            let unattributed = origin.bits.len().max(1) as u64;
            self.orphans = self.orphans.saturating_add(unattributed);
            return;
        }
        // The replayed effects carry the ORIGINAL call's identity —
        // never the completion's, never a receiver's later key (H9).
        // Built only when consumed: plain observation stays free.
        // The execution facts below still take the completion's
        // return, session and time.
        let owned;
        let effect_origin: &EffectOrigin = if S::WANTS_EFFECTS {
            owned = EffectOrigin::from(&pending);
            &owned
        } else {
            owned = EffectOrigin::placeholder();
            &owned
        };
        let mut completed = pending;
        completed.rv = completion.rv;
        completed.session = completion.session;
        completed.ts_ns = completion.ts_ns;
        let descriptor =
            crate::kinds::descriptor(&completed.function).unwrap_or(SlotSemantics::COUNT_ONLY);
        // Async replay carries no receipts: H8's frozen endpoint
        // table leaves async completions negative-only, so the
        // original call never completes in the model, its inputs
        // never join, and no receipt can exist for the machine
        // starting here. Such rows are unknown-key with explicit
        // evidence (carry: modeling async completions in H8 is an
        // owner decision).
        self.apply_completed(
            &completed,
            &descriptor,
            effect_origin,
            &[],
            &CompletionEvidence::NONE,
            sink,
        );
    }

    /// Oldest-first async eviction past the bound, mirroring
    /// `evict_pending_if_needed` (the one place retained async facts
    /// drop, and every drop is counted) — plus the affected
    /// operation's end (F3/C2): when the evicted record's originating
    /// machine is still live (same generation), it ends unknown with
    /// explicit accounting, since its outstanding call history is now
    /// lost. A newer machine on the same key is a different lifetime
    /// and is left alone.
    fn evict_async_if_needed<S: OperationSink>(&mut self, sink: &mut S) {
        if self.pending.len() + self.detached.len() <= MAX_EDGE_PENDING {
            return;
        }
        let pending = self
            .pending
            .iter()
            .min_by_key(|(_, value)| {
                #[cfg(test)]
                self.bump_edge_read_for_test();
                value.sequence
            })
            .map(|(key, _)| *key);
        let detached = self
            .detached
            .iter()
            .min_by_key(|(_, value)| {
                #[cfg(test)]
                self.bump_edge_read_for_test();
                value.sequence
            })
            .map(|(key, value)| (*key, value.sequence));
        let evicted: Option<(u64, SemanticCall, CallOrigin, Option<ResourceLease>)> =
            match (pending, detached) {
                (Some(key), Some((detached_key, detached_sequence))) => {
                    #[cfg(test)]
                    self.bump_edge_read_for_test();
                    if self.pending[&key].sequence <= detached_sequence {
                        self.pending
                            .remove(&key)
                            .map(|record| (key.0, record.call, record.origin, record.resource))
                    } else {
                        self.detached
                            .remove(&detached_key)
                            .map(|id| (id.call.session, id.call, id.origin, id.resource))
                    }
                }
                (Some(key), None) => self
                    .pending
                    .remove(&key)
                    .map(|record| (key.0, record.call, record.origin, record.resource)),
                (None, Some((key, _))) => self
                    .detached
                    .remove(&key)
                    .map(|id| (id.call.session, id.call, id.origin, id.resource)),
                (None, None) => return,
            };
        let Some((session, call, origin, resource)) = evicted else {
            return;
        };
        // The evicted machine ends unknown through the one end site;
        // its terminal names the evicted call whose history was lost.
        // Built only when consumed: plain observation stays free.
        let owned;
        let effect_origin: &EffectOrigin = if S::WANTS_EFFECTS {
            owned = EffectOrigin::from(&call);
            &owned
        } else {
            owned = EffectOrigin::placeholder();
            &owned
        };
        drop(call);
        for (bit, generation) in &origin.bits {
            #[cfg(test)]
            self.bump_edge_read_for_test();
            let live_matches = generation.is_some()
                && self
                    .active
                    .get(&(session, *bit))
                    .map(|machine| machine.generation)
                    == *generation;
            if live_matches {
                self.end_machine(
                    session,
                    *bit,
                    Self::category_name(*bit),
                    EndState::Unknown,
                    effect_origin,
                    &CompletionEvidence::NONE,
                    sink,
                );
            }
        }
        self.evidence.async_evictions = self.evidence.async_evictions.saturating_add(1);
        drop(origin);
        drop(resource);
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
    // Live-loop carry (T4): read only by staged tests until the
    // projection carries exhaustion as a coverage fact. Kept ungated
    // (not cfg(test)) so the counter field stays read in all builds.
    #[allow(dead_code)]
    pub(crate) fn id_exhaustions(&self) -> u64 {
        self.id_exhaustions
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
    fn edge_memory_lens_moves_with_observed_sessions() {
        let mut edge = EdgeSemantics::default();
        let zero = edge.memory_lens();
        assert_eq!(zero.open.len, 0);
        assert_eq!(zero.active.len, 0);
        assert_eq!(zero.mechs.len, 0);
        assert_eq!(zero.pending.len, 0);
        assert_eq!(zero.detached.len, 0);
        edge.observe(&call("C_OpenSession", 7, 0, 100));
        edge.observe(&init("C_SignInit", 7, RSA_PSS, 200));
        // One PENDING op minted through GetID lands in detached.
        let sign_id = crate::kinds::function_id("C_Sign").unwrap();
        let mut pending = op("C_Sign", 7, 210);
        pending.rv = CkRv::PENDING.0;
        edge.observe(&pending);
        let mut get_id = call("C_AsyncGetID", 7, CkRv::OK.0, 220);
        get_id.target_function = sign_id;
        get_id.async_value = 42;
        edge.observe(&get_id);
        let lens = edge.memory_lens();
        assert_eq!(lens.open.len, 1);
        assert_eq!(lens.active.len, 1);
        assert_eq!(lens.mechs.len, 1);
        assert_eq!(lens.detached.len, 1);
        assert!(lens.open.bytes > 0);
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
    fn init_with_flagged_unregistered_mechanism_tracks_row_under_raw_id() {
        // Round 2: the Detailed return path publishes unregistered ids
        // with `capture::MECHANISM_UNREGISTERED` set alongside
        // `MECHANISM_VALUE`. The mask-gated reducer admits them exactly
        // like registered ids (row keyed by the raw id plus the started
        // machine); naming stays a render-layer lookup.
        let mut edge = EdgeSemantics::default();
        let mut flagged = init("C_SignInit", 7, 0xCE53_43A9, 100);
        flagged.capture |= capture::MECHANISM_UNREGISTERED;
        assert_eq!(edge.observe(&flagged), 0);
        assert_eq!(edge.label(), SEMANTIC_OBSERVED);
        assert_eq!((edge.calls(), edge.started()), (1, 1));
        let stat = &edge.mechanisms()[&0xCE53_43A9];
        assert_eq!((stat.calls, stat.errors), (1, 0));
        assert_eq!(stat.last_seen_ns, 100);
        assert!(stat.functions.contains("C_SignInit"));
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
    fn same_origin_position_truth_table() {
        // Same origin means equal carried positions; an unknown
        // (S1Only) side never confirms.
        assert!(same_origin_position(Some(900), Some(900)));
        assert!(!same_origin_position(Some(900), Some(901)));
        assert!(!same_origin_position(Some(900), None));
        assert!(!same_origin_position(None, Some(900)));
        assert!(!same_origin_position(None, None));
    }

    #[test]
    fn queued_pending_carries_no_origin_position() {
        // S1Only queueing stores no origin position; Joint replay
        // will supply it (Activation wires the channel).
        let mut edge = EdgeSemantics::default();
        let sign_id = crate::kinds::function_id("C_Sign").unwrap();
        let mut pending = op("C_Sign", 7, 110);
        pending.rv = CkRv::PENDING.0;
        edge.observe(&pending);
        assert_eq!(edge.pending[&(7, sign_id)].origin_pos, None);
    }

    #[test]
    fn get_id_carries_origin_position_to_detached() {
        // A Joint-replayed original's H0 position rides with its
        // record across the GetID mint, never re-snapshotted.
        let mut edge = EdgeSemantics::default();
        edge.observe(&call("C_OpenSession", 7, CkRv::OK.0, 90));
        let sign_id = crate::kinds::function_id("C_Sign").unwrap();
        let mut pending = op("C_Sign", 7, 110);
        pending.rv = CkRv::PENDING.0;
        edge.observe(&pending);
        edge.pending
            .get_mut(&(7, sign_id))
            .expect("queued")
            .origin_pos = Some(900);
        let mut get_id = call("C_AsyncGetID", 7, CkRv::OK.0, 120);
        get_id.target_function = sign_id;
        get_id.async_value = 42;
        edge.observe(&get_id);
        assert_eq!(edge.detached.len(), 1);
        let id = edge.detached.values().next().expect("detached");
        assert_eq!(id.owner, Some(7));
        assert_eq!(id.origin_pos, Some(900));
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

    fn seed_edge(edge: &mut EdgeSemantics, seed: u64) {
        let mut state = seed.wrapping_add(0x1234_5678_9abc_def1);
        let mut next = || {
            state ^= state >> 12;
            state ^= state << 25;
            state ^= state >> 27;
            state = state.wrapping_mul(0x2545_f491_4f6c_dd1d);
            state
        };
        for index in 0..(20 + (next() % 40)) {
            let session = 1 + (next() % 8);
            let function = match next() % 6 {
                0 => "C_OpenSession",
                1 => "C_SignInit",
                2 => "C_EncryptInit",
                3 => "C_Sign",
                4 => "C_CloseSession",
                _ => "C_Login",
            };
            let ts = 100 + index * 10;
            if function.ends_with("Init") {
                edge.observe(&init(function, session, RSA_PSS, ts));
            } else {
                edge.observe(&call(function, session, CkRv::OK.0, ts));
            }
        }
    }

    fn retiring_calls() -> Vec<SemanticCall> {
        vec![
            call("C_Finalize", SESSION_NONE, CkRv::OK.0, 10_000),
            call("C_Sign", 3, CkRv::CRYPTOKI_NOT_INITIALIZED.0, 10_010),
            call("C_CloseSession", 2, CkRv::OK.0, 10_020),
            call("C_CloseAllSessions", 1, CkRv::OK.0, 10_030),
            call("C_Login", 4, CkRv::OK.0, 10_040),
            call("C_Logout", 4, CkRv::OK.0, 10_050),
            SemanticCall {
                flags: crate::semantics::KNOWN_CANCEL_FLAGS & 0x3,
                ..call("C_SessionCancel", 2, CkRv::OK.0, 10_060)
            },
            call("C_SetOperationState", 5, CkRv::OK.0, 10_070),
            call("C_Sign", 6, CkRv::SESSION_CLOSED.0, 10_080),
            call("C_OpenSession", 7, CkRv::OK.0, 10_090),
            call("C_SignUpdate", 3, CkRv::PENDING.0, 10_100),
        ]
    }

    /// Budgeted retire cursors match synchronous observe exactly:
    /// same end maps, counters, evidence and effect order, one leaf
    /// per visit/terminal/drop/unbind, over random seeds and every
    /// retiring call shape (All, Session, Slot, Selected, Pending).
    #[test]
    fn budgeted_retire_matches_synchronous_observe() {
        use crate::semantics_objects::journal::LeafBudget;
        for seed in 0..30u64 {
            for retiring in retiring_calls() {
                let origin = EffectOrigin {
                    function: retiring.function.clone(),
                    session: retiring.session,
                    ts_ns: retiring.ts_ns,
                };
                let mut sync_edge = EdgeSemantics::default();
                seed_edge(&mut sync_edge, seed);
                let mut sync_effects = Vec::new();
                sync_edge.observe_with_effects(&retiring, &origin, &mut sync_effects);
                let mut budgeted_edge = EdgeSemantics::default();
                seed_edge(&mut budgeted_edge, seed);
                let mut budgeted_effects = Vec::new();
                match budgeted_edge.would_retire_scope(&retiring) {
                    RetirePeek::NoOp | RetirePeek::Bounded => {
                        budgeted_edge.observe_with_effects(
                            &retiring,
                            &origin,
                            &mut budgeted_effects,
                        );
                    }
                    RetirePeek::Pending => {
                        let mut cursor = budgeted_edge.start_pending_admission(retiring.clone());
                        let mut polls = 0;
                        loop {
                            let mut gate = LeafBudget::new(3);
                            if budgeted_edge.poll_pending_admission_step(
                                &mut cursor,
                                &mut budgeted_effects,
                                &mut gate,
                            ) {
                                break;
                            }
                            assert!(
                                gate.spent() <= 3,
                                "seed {seed}: poll spent {} above 3",
                                gate.spent()
                            );
                            polls += 1;
                            assert!(polls < 100_000, "seed {seed}: admission must complete");
                        }
                    }
                    RetirePeek::All {
                        count_reconciliations,
                    } => {
                        let mut cursor = budgeted_edge.start_budgeted_invalidation(
                            false,
                            Some(&origin),
                            count_reconciliations,
                        );
                        let mut polls = 0;
                        loop {
                            let mut gate = LeafBudget::new(2);
                            if budgeted_edge.poll_invalidation_step(
                                &mut cursor,
                                &mut budgeted_effects,
                                &mut gate,
                            ) {
                                break;
                            }
                            assert!(
                                gate.spent() <= 2,
                                "seed {seed}: poll spent {} above 2",
                                gate.spent()
                            );
                            polls += 1;
                            assert!(polls < 100_000, "seed {seed}: retire must complete");
                        }
                    }
                    RetirePeek::Subset(scope) => {
                        let mut cursor = budgeted_edge.start_budgeted_retire(scope, &origin);
                        let mut polls = 0;
                        loop {
                            let mut gate = LeafBudget::new(7);
                            if budgeted_edge.poll_retire_step(
                                &mut cursor,
                                &mut budgeted_effects,
                                &mut gate,
                            ) {
                                break;
                            }
                            assert!(
                                gate.spent() <= 7,
                                "seed {seed}: poll spent {} above 7",
                                gate.spent()
                            );
                            polls += 1;
                            assert!(polls < 100_000, "seed {seed}: retire must complete");
                        }
                    }
                }
                assert_eq!(
                    budgeted_effects, sync_effects,
                    "seed {seed} {}: effects match",
                    retiring.function
                );
                assert_eq!(
                    (
                        budgeted_edge.active.len(),
                        budgeted_edge.pending.len(),
                        budgeted_edge.detached.len(),
                        budgeted_edge.open.len()
                    ),
                    (
                        sync_edge.active.len(),
                        sync_edge.pending.len(),
                        sync_edge.detached.len(),
                        sync_edge.open.len()
                    ),
                    "seed {seed} {}: end maps match",
                    retiring.function
                );
                assert_eq!(
                    (
                        budgeted_edge.completed,
                        budgeted_edge.cancelled,
                        budgeted_edge.failed,
                        budgeted_edge.unknown
                    ),
                    (
                        sync_edge.completed,
                        sync_edge.cancelled,
                        sync_edge.failed,
                        sync_edge.unknown
                    ),
                    "seed {seed} {}: counters match",
                    retiring.function
                );
                assert_eq!(
                    budgeted_edge.evidence, sync_edge.evidence,
                    "seed {seed} {}: evidence matches",
                    retiring.function
                );
            }
        }
    }

    /// Budgeted pending admission matches synchronous queueing
    /// exactly at the 256/257 boundary and on duplicate/unroutable
    /// inputs: same maps, counters, evidence and effect order, one
    /// leaf per visit, with the Unknown end's visit + terminal kept
    /// atomic across yields.
    #[test]
    fn budgeted_pending_admission_matches_synchronous_queue() {
        use crate::semantics_objects::journal::LeafBudget;
        fn pending(session: u64, ts: u64) -> SemanticCall {
            SemanticCall {
                function: "C_SignUpdate".into(),
                rv: CkRv::PENDING.0,
                session,
                ts_ns: ts,
                ..SemanticCall::default()
            }
        }
        fn snapshot(edge: &EdgeSemantics) -> (usize, usize, usize, usize, u64, u64, u64, u64, u64) {
            (
                edge.active.len(),
                edge.pending.len(),
                edge.detached.len(),
                edge.open.len(),
                edge.completed,
                edge.cancelled,
                edge.unknown,
                edge.orphans,
                edge.evidence.async_evictions,
            )
        }
        for shape in ["evict", "duplicate", "unroutable"] {
            let mut sync_edge = EdgeSemantics::default();
            sync_edge.observe(&init("C_SignInit", 1, RSA_PSS, 100));
            for session in 1..=256u64 {
                sync_edge.observe(&pending(session, 100 + session));
            }
            let head = match shape {
                "evict" => pending(257, 400),
                "duplicate" => pending(1, 400),
                // Session-less OPEN_SESSION PENDING: gate-passed with a
                // known descriptor (so the peek routes Pending), but
                // unroutable at queue time.
                _ => call("C_OpenSession", SESSION_NONE, CkRv::PENDING.0, 400),
            };
            let origin = EffectOrigin {
                function: head.function.clone(),
                session: head.session,
                ts_ns: head.ts_ns,
            };
            let mut sync_effects = Vec::new();
            sync_edge.observe_with_effects(&head, &origin, &mut sync_effects);
            let mut cursor_edge = EdgeSemantics::default();
            cursor_edge.observe(&init("C_SignInit", 1, RSA_PSS, 100));
            for session in 1..=256u64 {
                cursor_edge.observe(&pending(session, 100 + session));
            }
            let mut cursor = cursor_edge.start_pending_admission(head);
            let mut cursor_effects = Vec::new();
            cursor_edge.reset_test_edge_reads_for_test();
            let (mut total_spent, mut total_reads, mut stalls, mut polls) = (0, 0, 0, 0);
            let mut units = 1usize;
            loop {
                cursor_edge.reset_test_edge_reads_for_test();
                let mut gate = LeafBudget::new(units);
                let done = cursor_edge.poll_pending_admission_step(
                    &mut cursor,
                    &mut cursor_effects,
                    &mut gate,
                );
                assert_eq!(
                    gate.spent(),
                    cursor_edge.test_edge_reads_for_test(),
                    "{shape} poll {polls}: every read debited"
                );
                total_spent += gate.spent();
                total_reads += cursor_edge.test_edge_reads_for_test();
                if done {
                    break;
                }
                if gate.spent() == 0 {
                    stalls += 1;
                    units = 2;
                } else {
                    units = 1;
                }
                polls += 1;
                assert!(polls < 100_000, "{shape}: the admission must complete");
            }
            if shape == "evict" {
                assert_eq!(
                    stalls, 1,
                    "the atomic Unknown end stalls a 1-unit gate once"
                );
                assert_eq!(
                    (total_spent, total_reads),
                    (262, 262),
                    "route + capture + 257-visit scan + liveness + visit + terminal"
                );
            } else {
                assert_eq!(
                    (total_spent, total_reads),
                    (1, 1),
                    "{shape}: one routed lookup"
                );
                assert_eq!(stalls, 0, "{shape}: no atomic end stalls");
            }
            assert_eq!(cursor_effects, sync_effects, "{shape}: terminals match");
            assert_eq!(
                snapshot(&cursor_edge),
                snapshot(&sync_edge),
                "{shape}: maps match"
            );
            assert_eq!(
                cursor_edge.evidence, sync_edge.evidence,
                "{shape}: evidence matches"
            );
        }
    }

    /// A one-unit retire reads only after its grant and retains the
    /// charged visit across yields: the first unit takes the entry,
    /// the terminal waits for later credit, and the resume ends the
    /// machine with its exact terminal and custody.
    #[test]
    fn budgeted_retire_one_unit_retains_charged_visit_across_yield() {
        use crate::semantics_objects::journal::LeafBudget;
        let mut edge = EdgeSemantics::default();
        edge.observe(&call("C_OpenSession", 7, CkRv::OK.0, 100));
        edge.observe(&init("C_SignInit", 7, RSA_PSS, 110));
        assert_eq!(edge.active.len(), 1);
        let origin = EffectOrigin {
            function: "C_CloseSession".into(),
            session: 7,
            ts_ns: 120,
        };
        let mut cursor = edge.start_budgeted_retire(
            EdgeRetireScope::Session {
                session: 7,
                end_unknown: false,
                post: SessionPost::Close,
            },
            &origin,
        );
        let mut effects = Vec::new();
        edge.reset_test_edge_reads_for_test();
        let mut gate = LeafBudget::new(1);
        assert!(
            !edge.poll_retire_step(&mut cursor, &mut effects, &mut gate),
            "one unit cannot finish visit + terminal"
        );
        assert_eq!(gate.spent(), 1, "the visit charges first");
        assert_eq!(
            edge.test_edge_reads_for_test(),
            1,
            "exactly the charged visit reads"
        );
        assert_eq!(edge.active.len(), 1, "the machine survives the yield");
        assert!(effects.is_empty(), "no terminal before its credit");
        edge.reset_test_edge_reads_for_test();
        let mut gate = LeafBudget::new(64);
        assert!(
            edge.poll_retire_step(&mut cursor, &mut effects, &mut gate),
            "the resume completes without re-reading the visit"
        );
        assert_eq!(
            edge.test_edge_reads_for_test(),
            gate.spent(),
            "every later read is debited"
        );
        assert_eq!(edge.active.len(), 0);
        assert_eq!(edge.open.len(), 0);
        assert_eq!(effects.len(), 1, "exactly one terminal");
        match &effects[0] {
            OperationEffect::Ended { outcome, .. } => {
                assert_eq!(*outcome, OperationOutcome::Cancelled)
            }
            _ => panic!("the retired machine ends Cancelled"),
        }
        assert_eq!(edge.cancelled, 1);
        assert_eq!(edge.evidence.unmatched_closes, 0);
    }

    /// An empty scan still consumes its lookups: each phase's
    /// next-entry read charges before it happens, so a retire over
    /// an empty edge debits exactly its lookups and completes.
    #[test]
    fn budgeted_retire_empty_scan_consumes_its_lookups() {
        use crate::semantics_objects::journal::LeafBudget;
        let mut edge = EdgeSemantics::default();
        let origin = EffectOrigin {
            function: "C_CloseSession".into(),
            session: 9,
            ts_ns: 120,
        };
        let mut cursor = edge.start_budgeted_retire(
            EdgeRetireScope::Session {
                session: 9,
                end_unknown: false,
                post: SessionPost::Close,
            },
            &origin,
        );
        let mut effects = Vec::new();
        edge.reset_test_edge_reads_for_test();
        let mut gate = LeafBudget::new(64);
        assert!(
            edge.poll_retire_step(&mut cursor, &mut effects, &mut gate),
            "an empty retire completes"
        );
        assert_eq!(
            gate.spent(),
            3,
            "active + pending lookups and the open forget"
        );
        assert_eq!(
            edge.test_edge_reads_for_test(),
            3,
            "each lookup reads exactly once"
        );
        assert!(effects.is_empty());
        assert_eq!(edge.evidence.unmatched_closes, 1);
    }

    /// Retire mutations debit their keyed lookup: a Slot CLOSE_ALL
    /// retire over one doomed pending, one floated detached id and
    /// one removed open debits exactly two empty active scans plus
    /// visit + decision + removal + terminal per mutated phase
    /// (14 units, 14 reads).
    #[test]
    fn budgeted_retire_mutations_debit_their_lookup() {
        use crate::semantics_objects::journal::LeafBudget;
        let mut edge = EdgeSemantics::default();
        edge.observe(&call("C_OpenSession", 7, CkRv::OK.0, 90));
        let slot = edge.open.get(&7).copied().expect("session 7 open");
        let sign_id = crate::kinds::function_id("C_Sign").unwrap();
        let mut pending = op("C_Sign", 7, 100);
        pending.rv = CkRv::PENDING.0;
        edge.observe(&pending);
        let mut get_id = call("C_AsyncGetID", 7, CkRv::OK.0, 110);
        get_id.target_function = sign_id;
        get_id.async_value = 42;
        edge.observe(&get_id);
        let mut pending_unowned = op("C_Sign", 8, 120);
        pending_unowned.rv = CkRv::PENDING.0;
        edge.observe(&pending_unowned);
        assert_eq!(edge.active.len(), 0);
        assert_eq!(edge.pending.len(), 1);
        assert_eq!(edge.detached.len(), 1);
        assert_eq!(edge.open.len(), 1);
        let origin = EffectOrigin {
            function: "C_CloseAllSessions".into(),
            session: 7,
            ts_ns: 130,
        };
        let mut cursor = edge.start_budgeted_retire(
            EdgeRetireScope::Slot {
                slot,
                close_all: true,
            },
            &origin,
        );
        let mut effects = Vec::new();
        edge.reset_test_edge_reads_for_test();
        let mut gate = LeafBudget::new(64);
        assert!(
            edge.poll_retire_step(&mut cursor, &mut effects, &mut gate),
            "the small retire completes in one credit"
        );
        assert_eq!(
            gate.spent(),
            14,
            "two empty active scans + visit/decision/removal/terminal per mutated phase"
        );
        assert_eq!(
            edge.test_edge_reads_for_test(),
            14,
            "every charged lookup reads exactly once"
        );
        assert!(effects.is_empty(), "no machine terminals here");
        assert_eq!(edge.pending.len(), 0, "the doomed pending drops");
        assert_eq!(edge.detached.len(), 1, "the owned id floats");
        assert!(
            edge.detached.values().all(|id| id.owner.is_none()),
            "floating clears the owner"
        );
        assert_eq!(edge.open.len(), 0, "the owned open unbinds");
    }

    /// A Selected retire drops (not floats) its matching detached
    /// id, and the drop debits its keyed lookup: one empty active
    /// scan plus one empty pending scan plus visit + value + drop.
    #[test]
    fn budgeted_retire_detached_drop_debits_its_lookup() {
        use crate::semantics_objects::journal::LeafBudget;
        // Session-cancel flag selecting the SIGN operation (mirrors
        // the private CKF_SIGN in `semantics`).
        const CKF_SIGN: u64 = 0x0000_0800;
        let mut edge = EdgeSemantics::default();
        edge.observe(&call("C_OpenSession", 2, CkRv::OK.0, 90));
        let sign_id = crate::kinds::function_id("C_Sign").unwrap();
        let mut pending = op("C_Sign", 2, 100);
        pending.rv = CkRv::PENDING.0;
        edge.observe(&pending);
        let mut get_id = call("C_AsyncGetID", 2, CkRv::OK.0, 110);
        get_id.target_function = sign_id;
        get_id.async_value = 42;
        edge.observe(&get_id);
        assert_eq!(edge.active.len(), 0);
        assert_eq!(edge.pending.len(), 0);
        assert_eq!(edge.detached.len(), 1);
        let origin = EffectOrigin {
            function: "C_SessionCancel".into(),
            session: 2,
            ts_ns: 120,
        };
        let mut cursor = edge.start_budgeted_retire(
            EdgeRetireScope::Selected {
                session: 2,
                flags: CKF_SIGN,
                ambiguous: false,
            },
            &origin,
        );
        let mut effects = Vec::new();
        edge.reset_test_edge_reads_for_test();
        let mut gate = LeafBudget::new(64);
        assert!(
            edge.poll_retire_step(&mut cursor, &mut effects, &mut gate),
            "the small retire completes in one credit"
        );
        assert_eq!(
            gate.spent(),
            5,
            "empty active + empty pending scans plus visit/value/drop"
        );
        assert_eq!(
            edge.test_edge_reads_for_test(),
            5,
            "every charged lookup reads exactly once"
        );
        assert!(effects.is_empty(), "detached drops are silent");
        assert_eq!(edge.detached.len(), 0, "the matching id drops");
    }
}
