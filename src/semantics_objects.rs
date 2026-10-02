//! SPDX-License-Identifier: GPL-3.0-or-later
//! Pure S2/S3 reference model: instance/session/object observation lifetimes.
//!
//! One capture-owned [`ObjectSemantics`] owns capture-local IDs, budgets,
//! semantic domains, session incarnations, per-session object views and the
//! bounded pending-call table. Inputs are typed reference facts:
//!
//! - [`ObjectSemantics::begin`] admits one logical call at its reference
//!   entry cut ([`OriginFact`]); returned handles are unknown at begin.
//! - [`ObjectSemantics::complete`] stages that call's matched outcome
//!   ([`CompletedFact`]) privately; nothing is published.
//! - [`ObjectSemantics::settle`] accepts an opaque complete-input prefix
//!   ([`CompleteInputPrefix`]) and applies the covered history in reference
//!   cut order, once, predecessors before dependents.
//! - [`ObjectSemantics::invalidate`] applies an explicit reference boundary
//!   (loss, exec, fork, unload, token reset...) to an [`AffectedScope`].
//!
//! The model never derives authority from PIDs, paths, equal handles,
//! metadata, completion arrival order or timestamps. Domains, cuts, call keys,
//! prefixes and bootstrap statements are reference evidence: their
//! constructors are test-only (`#[cfg(test)]`) until a later reviewed task
//! supplies independently proven production evidence. No production feed is
//! wired yet (Tasks 3/4/6), so non-test builds carry this module unused.
//!
//! Privacy: raw session/object handles, domain words, slot/epoch words, cuts
//! and call keys live in private newtypes whose `Debug` is redacted. Effects,
//! errors and the projection carry capture-local public IDs and finite facts.
#![cfg_attr(not(test), allow(dead_code))]

mod state;

use p11scope_ebpf_common::LinuxLayout;
use p11scope_ebpf_common::object_policy::{
    SafeAttributeKind, SafeCurve, classify_attribute_scalar, classify_ec_params,
    safe_attribute_kind, valid_safe_attribute_length,
};
use std::fmt;

/// The v3 ceiling of accessing-session relations per object. Current
/// accepted authority proves at most one (the view's own session); no
/// cross-session identity input exists, so storage does not reserve 32.
pub(crate) const MAX_ACCESS_RELATIONS: usize = 32;

/// Accepted inputs per call (descriptor input/result/find/template bounds).
pub(crate) const MAX_INPUT_HANDLES: usize = 2;
pub(crate) const MAX_RESULT_HANDLES: usize = 2;
pub(crate) const MAX_FIND_HANDLES: usize = 8;
pub(crate) const MAX_TEMPLATE_ATTRIBUTES: usize = 8;
/// Six classified metadata fields per source (requested / established).
pub(crate) const METADATA_FIELDS: usize = 6;

// ---------------------------------------------------------------------------
// Private words
// ---------------------------------------------------------------------------

macro_rules! redacted_debug {
    ($name:ident) => {
        impl fmt::Debug for $name {
            fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
                f.write_str(concat!(stringify!($name), "(..)"))
            }
        }
    };
}

/// A nonzero PKCS#11 object handle word. Private; never formatted.
#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub(crate) struct ObjectHandle(u64);
redacted_debug!(ObjectHandle);

impl ObjectHandle {
    /// `CK_INVALID_HANDLE` (zero) is never an object handle.
    pub(crate) fn new(raw: u64) -> Option<Self> {
        (raw != 0).then_some(Self(raw))
    }
}

/// A nonzero PKCS#11 session handle word. Private; never formatted.
#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub(crate) struct SessionHandle(u64);
redacted_debug!(SessionHandle);

impl SessionHandle {
    pub(crate) fn new(raw: u64) -> Option<Self> {
        (raw != 0).then_some(Self(raw))
    }
}

/// Exact outer semantic domain: caller incarnation, process image, native
/// source (image-domain tag), proven load instance and initialization era.
///
/// Producer contract (Tasks 3/6), on which ended-domain pruning relies:
/// - every identity includes a capture-local, never-reused
///   instance/incarnation component;
/// - a producer never registers or bootstraps an identity that has ended.
///
/// The model fails closed regardless: a fact naming a domain it does not
/// hold (never registered, or pruned) is refused and counted as a gap. It
/// never creates a domain implicitly, accepts a bootstrap for it, or joins.
#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub(crate) struct ObjectDomain {
    caller: u64,
    image: u64,
    native_source: u64,
    instance: u64,
    init_era: u64,
}
redacted_debug!(ObjectDomain);

impl ObjectDomain {
    /// Reference-evidence boundary: tests construct explicit domains. A
    /// production constructor requires Task 3's reviewed instance proof.
    #[cfg(test)]
    pub(crate) fn reference(
        caller: u64,
        image: u64,
        native_source: u64,
        instance: u64,
        init_era: u64,
    ) -> Self {
        Self {
            caller,
            image,
            native_source,
            instance,
            init_era,
        }
    }

    /// The per-instance budget key (all fields but the initialization era).
    fn instance_key(&self) -> (u64, u64, u64, u64) {
        (self.caller, self.image, self.native_source, self.instance)
    }
}

/// An ordinal cut in one domain's admitted reference history. Distinct from
/// observation timestamps and from delivery order.
#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub(crate) struct RefCut(u64);
redacted_debug!(RefCut);

impl RefCut {
    #[cfg(test)]
    pub(crate) fn reference(cut: u64) -> Self {
        Self(cut)
    }
}

/// A stable logical-call key within one domain's reference history.
#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub(crate) struct CallKey(u64);
redacted_debug!(CallKey);

impl CallKey {
    #[cfg(test)]
    pub(crate) fn reference(key: u64) -> Self {
        Self(key)
    }
}

/// Known slot/token scope evidence, or explicitly unknown. Unknown is
/// neither slot zero nor proof of separation.
#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub(crate) enum SlotScope {
    Unknown,
    Known(KnownScope),
}

impl fmt::Debug for SlotScope {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Unknown => f.write_str("Unknown"),
            Self::Known(_) => f.write_str("Known(..)"),
        }
    }
}

/// A proven slot and observed local token epoch (never a token serial).
#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub(crate) struct KnownScope {
    slot: u64,
    token_epoch: u64,
}

impl SlotScope {
    #[cfg(test)]
    pub(crate) fn reference_known(slot: u64, token_epoch: u64) -> Self {
        Self::Known(KnownScope { slot, token_epoch })
    }

    /// Equal known scope, or either side unknown.
    fn compatible(self, other: Self) -> bool {
        match (self, other) {
            (Self::Known(a), Self::Known(b)) => a == b,
            _ => true,
        }
    }
}

// ---------------------------------------------------------------------------
// Public capture-local IDs
// ---------------------------------------------------------------------------

/// A checked, never-recycled call ticket. Not an object generation.
#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub(crate) struct CallToken(u64);

impl fmt::Debug for CallToken {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "call#{}", self.0)
    }
}

/// A capture-local object observation incarnation (`object#N`).
#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub(crate) struct ObjectId(u64);

impl fmt::Debug for ObjectId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "object#{}", self.0)
    }
}

/// A capture-local session incarnation (`sess#N`).
#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub(crate) struct SessionIncarnation(u64);

impl fmt::Debug for SessionIncarnation {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "sess#{}", self.0)
    }
}

// ---------------------------------------------------------------------------
// Finite reasons
// ---------------------------------------------------------------------------

/// Every finite refusal, uncertainty and boundary reason. Carries no data.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub(crate) enum ObjectGap {
    // Settlement / proof.
    BootstrapUnproven,
    BootstrapRefused,
    PrefixContradiction,
    StalePrefix,
    ClosedFrontier,
    DuplicateCall,
    DuplicateCompletion,
    StaleToken,
    FencedCompletion,
    MalformedFact,
    UnsupportedFunction,
    DomainEnded,
    // Result protocols.
    ResultProtocolUnavailable,
    PendingResultUnavailable,
    OutputUnreadable,
    PairDuplicate,
    NullMechanismCancel,
    // Joins.
    SameSessionOverlap,
    OverlapUncertain,
    OutputCollision,
    StaleOrigin,
    DependencyBroken,
    UnprovenInput,
    UnprovenSession,
    MetadataUncertain,
    // Lifecycle / boundaries.
    DestroyAlias,
    CloseUncertain,
    CloseAllUncertain,
    LogoutUncertain,
    SessionClosed,
    InvalidHandle,
    AmbiguousOutcome,
    SessionContradiction,
    HandleReuse,
    Finalize,
    TokenReset,
    Exec,
    Fork,
    Unload,
    Loss,
    // Bounds.
    PendingCapacity,
    SessionCapacity,
    ObjectCapacity,
    InstanceCapacity,
    IdExhausted,
    // Removal, unseen finalize and lost-outcome evidence.
    DeviceLoss,
    UnseenFinalize,
    InconsistentMechanism,
    OutcomeLost,
    // Domain registration.
    UnknownDomain,
    DomainPruned,
}

// ---------------------------------------------------------------------------
// Inputs
// ---------------------------------------------------------------------------

/// A captured handle argument: absent, a validated nonzero word, or
/// unreadable. Never an overloaded `None`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum HandleInput<T> {
    Absent,
    Value(T),
    Unreadable,
}

/// Captured mechanism evidence (`capture::MECHANISM_*` vocabulary).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum MechanismEvidence {
    NotCaptured,
    Null,
    Unreadable,
    Value(u64),
}

/// One returned-handle slot of a completed call.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum ResultSlot {
    NotCaptured,
    Handle(ObjectHandle),
    Unreadable,
}

/// The bounded `C_FindObjects` output (at most eight handles).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum FindResult {
    NotCaptured,
    Unreadable,
    Handles {
        handles: [Option<ObjectHandle>; MAX_FIND_HANDLES],
        truncated: bool,
    },
}

impl FindResult {
    /// Keeps at most eight handles; more marks the result truncated.
    pub(crate) fn handles(found: &[ObjectHandle]) -> Self {
        let mut handles = [None; MAX_FIND_HANDLES];
        for (slot, handle) in handles.iter_mut().zip(found) {
            *slot = Some(*handle);
        }
        Self::Handles {
            handles,
            truncated: found.len() > MAX_FIND_HANDLES,
        }
    }
}

/// A finite classified attribute value.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum FieldValue {
    Scalar(u16),
    Curve(SafeCurve),
}

/// One query outcome per field (latest status, distinct from validity).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum QueryStatus {
    NotQueried,
    Established,
    Unavailable,
    SizeOnly,
    Unsupported,
    Malformed,
    /// The selector is outside the allowlist: no value is retained.
    Excluded,
}

/// One attribute observation, classified at construction through the
/// Task 1 policy classifiers. Raw words are never retained.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct AttrObservation {
    kind: Option<SafeAttributeKind>,
    status: QueryStatus,
    value: Option<FieldValue>,
}

impl AttrObservation {
    /// A scalar (or one-byte token) result, validated by exact selector,
    /// target-width length and full-width value membership.
    pub(crate) fn scalar(selector: u64, len: u64, value: u64, layout: LinuxLayout) -> Self {
        let Some(kind) = safe_attribute_kind(selector) else {
            return Self::excluded();
        };
        if kind == SafeAttributeKind::EcParams || !valid_safe_attribute_length(kind, len, layout) {
            return Self::with_status(kind, QueryStatus::Malformed);
        }
        match classify_attribute_scalar(kind, value) {
            Some(exact) => Self {
                kind: Some(kind),
                status: QueryStatus::Established,
                value: Some(FieldValue::Scalar(exact)),
            },
            None => Self::with_status(kind, QueryStatus::Unsupported),
        }
    }

    /// A complete EC parameter encoding, by exact byte equality only.
    pub(crate) fn curve(selector: u64, bytes: &[u8], layout: LinuxLayout) -> Self {
        let Some(kind) = safe_attribute_kind(selector) else {
            return Self::excluded();
        };
        if kind != SafeAttributeKind::EcParams
            || !valid_safe_attribute_length(kind, bytes.len() as u64, layout)
        {
            return Self::with_status(kind, QueryStatus::Malformed);
        }
        match classify_ec_params(bytes) {
            Some(curve) => Self {
                kind: Some(kind),
                status: QueryStatus::Established,
                value: Some(FieldValue::Curve(curve)),
            },
            None => Self::with_status(kind, QueryStatus::Unsupported),
        }
    }

    /// `CK_UNAVAILABLE_INFORMATION` or otherwise unreadable value.
    pub(crate) fn unavailable(selector: u64) -> Self {
        match safe_attribute_kind(selector) {
            Some(kind) => Self::with_status(kind, QueryStatus::Unavailable),
            None => Self::excluded(),
        }
    }

    /// A null value pointer: size only, never a value.
    pub(crate) fn size_only(selector: u64) -> Self {
        match safe_attribute_kind(selector) {
            Some(kind) => Self::with_status(kind, QueryStatus::SizeOnly),
            None => Self::excluded(),
        }
    }

    pub(crate) fn status(&self) -> QueryStatus {
        self.status
    }

    fn excluded() -> Self {
        Self {
            kind: None,
            status: QueryStatus::Excluded,
            value: None,
        }
    }

    fn with_status(kind: SafeAttributeKind, status: QueryStatus) -> Self {
        Self {
            kind: Some(kind),
            status,
            value: None,
        }
    }
}

/// At most eight observations from one template.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct AttributeList {
    items: [Option<AttrObservation>; MAX_TEMPLATE_ATTRIBUTES],
    truncated: bool,
}

impl AttributeList {
    pub(crate) fn new(observations: &[AttrObservation]) -> Self {
        let mut items = [None; MAX_TEMPLATE_ATTRIBUTES];
        for (slot, observation) in items.iter_mut().zip(observations) {
            *slot = Some(*observation);
        }
        Self {
            items,
            truncated: observations.len() > MAX_TEMPLATE_ATTRIBUTES,
        }
    }

    fn observations(&self) -> impl Iterator<Item = &AttrObservation> {
        self.items.iter().flatten()
    }
}

/// One call's reference entry evidence.
#[derive(Debug, Clone)]
pub(crate) struct OriginFact {
    pub(crate) domain: ObjectDomain,
    pub(crate) cut: RefCut,
    pub(crate) key: CallKey,
    /// Checked entry observation time (nanoseconds).
    pub(crate) entry_ns: u64,
    /// Frozen standard function catalog ID.
    pub(crate) function: u32,
    pub(crate) session: HandleInput<SessionHandle>,
    /// Positional per descriptor `input_args`.
    pub(crate) inputs: [HandleInput<ObjectHandle>; MAX_INPUT_HANDLES],
    /// Positional per descriptor `template_args` (requested facts only).
    pub(crate) requested: [Option<AttributeList>; 2],
    /// Entry-time mechanism evidence (Derive result-protocol guard).
    pub(crate) entry_mechanism: MechanismEvidence,
    /// Slot/token scope evidence (OpenSession, CloseAllSessions).
    pub(crate) scope: SlotScope,
}

/// One call's matched reference completion evidence.
#[derive(Debug, Clone)]
pub(crate) struct CompletedFact {
    pub(crate) cut: RefCut,
    pub(crate) end_ns: u64,
    pub(crate) rv: u64,
    /// Existing guarded return-time mechanism capture.
    pub(crate) return_mechanism: MechanismEvidence,
    pub(crate) results: [ResultSlot; MAX_RESULT_HANDLES],
    pub(crate) session_out: HandleInput<SessionHandle>,
    pub(crate) found: FindResult,
    pub(crate) attributes: Option<AttributeList>,
}

/// An opaque scoped monotonic reference frontier. Its producer states that
/// every affecting begin, due outcome, boundary and loss through `frontier`
/// is represented, with still-open calls listed explicitly. An optional
/// bootstrap cut states that every call in progress at that cut which could
/// affect the scope is represented.
#[derive(Clone)]
pub(crate) struct CompleteInputPrefix {
    domain: ObjectDomain,
    frontier: RefCut,
    open: Vec<CallKey>,
    bootstrap: Option<RefCut>,
}

impl fmt::Debug for CompleteInputPrefix {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("CompleteInputPrefix")
            .field("open_calls", &self.open.len())
            .field("bootstrap", &self.bootstrap.is_some())
            .finish_non_exhaustive()
    }
}

impl CompleteInputPrefix {
    /// Reference-evidence boundary: explicit test histories only. The open
    /// list is bounded by the pending-call budget at use.
    #[cfg(test)]
    pub(crate) fn reference(
        domain: ObjectDomain,
        frontier: RefCut,
        open: &[CallKey],
        bootstrap: Option<RefCut>,
    ) -> Self {
        Self {
            domain,
            frontier,
            open: open.to_vec(),
            bootstrap,
        }
    }
}

/// The scope an explicit reference boundary affects.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum AffectedScope {
    /// Unlocalizable: every domain.
    Capture,
    Domain(ObjectDomain),
    Session(ObjectDomain, SessionHandle),
    Slot(ObjectDomain, SlotScope),
}

// ---------------------------------------------------------------------------
// Effects and projection
// ---------------------------------------------------------------------------

/// The six creation families with accepted result protocols.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum CreationFamily {
    Create,
    Copy,
    Generate,
    GeneratePair,
    Derive,
    Unwrap,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum SessionEnd {
    Closed,
    Uncertain(ObjectGap),
}

/// One finite transition result. Public IDs and reasons only.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum ObjectEffect {
    SessionOpened {
        call: CallToken,
        session: SessionIncarnation,
    },
    SessionFirstObserved {
        call: CallToken,
        session: SessionIncarnation,
    },
    SessionEnded {
        session: SessionIncarnation,
        end: SessionEnd,
    },
    Created {
        call: CallToken,
        slot: u8,
        object: ObjectId,
        session: SessionIncarnation,
    },
    FirstObserved {
        call: CallToken,
        object: ObjectId,
        session: SessionIncarnation,
    },
    Referenced {
        call: CallToken,
        object: ObjectId,
        key_use: bool,
    },
    Destroyed {
        call: CallToken,
        object: ObjectId,
    },
    AccessEnded {
        object: ObjectId,
        reason: ObjectGap,
    },
    Retired {
        object: ObjectId,
        reason: ObjectGap,
    },
    MetadataEstablished {
        call: CallToken,
        object: ObjectId,
    },
    MetadataConflict {
        call: CallToken,
        object: ObjectId,
        field: SafeAttributeKind,
    },
    MetadataInvalidated {
        object: ObjectId,
        reason: ObjectGap,
    },
    Downgraded {
        object: ObjectId,
        reason: ObjectGap,
    },
    /// The call's object/session join stays unknown.
    Unresolved {
        call: CallToken,
        reason: ObjectGap,
    },
    Gap {
        reason: ObjectGap,
    },
}

/// Effects of one transition.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub(crate) struct ObjectEffects {
    pub(crate) effects: Vec<ObjectEffect>,
}

impl ObjectEffects {
    fn push(&mut self, effect: ObjectEffect) {
        self.effects.push(effect);
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum SessionOrigin {
    Opened,
    FirstObserved,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum SessionState {
    Live,
    Closed,
    Ended(ObjectGap),
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct SessionView {
    pub(crate) id: SessionIncarnation,
    pub(crate) origin: SessionOrigin,
    pub(crate) scope_known: bool,
    pub(crate) state: SessionState,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum ViewOrigin {
    Created(CreationFamily),
    FirstObserved,
}

/// Creation is observed within its call interval; never physical age.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Birth {
    Observed { start_ns: u64, end_ns: u64 },
    Unknown,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Lifetime {
    Live,
    /// Proven destruction of this exact observation.
    Destroyed,
    /// This view's access proven ended (no physical-lifetime claim).
    AccessEnded(ObjectGap),
    /// Continuity unknown; observation retained.
    Retired(ObjectGap),
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Attribution {
    Valid,
    Downgraded(ObjectGap),
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum FieldState {
    Unknown,
    Value(FieldValue),
    /// Two claims disagreed; the earlier value is retained as history.
    Conflict(Option<FieldValue>),
    /// Current claim invalidated; the previous value is history only.
    Invalidated(Option<FieldValue>),
}

/// Six fixed metadata slots indexed by [`SafeAttributeKind`] order.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct MetadataView {
    fields: [FieldState; METADATA_FIELDS],
}

impl MetadataView {
    pub(crate) fn field(&self, kind: SafeAttributeKind) -> FieldState {
        self.fields[field_index(kind)]
    }
}

fn field_index(kind: SafeAttributeKind) -> usize {
    match kind {
        SafeAttributeKind::Class => 0,
        SafeAttributeKind::KeyType => 1,
        SafeAttributeKind::Token => 2,
        SafeAttributeKind::ValueLen => 3,
        SafeAttributeKind::ModulusBits => 4,
        SafeAttributeKind::EcParams => 5,
    }
}

/// A combined label from established facts of the same view only.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum KeyLabel {
    Aes { value_len: u16 },
    Rsa { modulus_bits: u16 },
    Ec { curve: SafeCurve },
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct ObjectView {
    pub(crate) id: ObjectId,
    /// The one proven accessing session (current authority).
    pub(crate) session: SessionIncarnation,
    pub(crate) origin: ViewOrigin,
    pub(crate) creator: Option<SessionIncarnation>,
    pub(crate) birth: Birth,
    pub(crate) lifetime: Lifetime,
    pub(crate) attribution: Attribution,
    pub(crate) references: u64,
    pub(crate) key_uses: u64,
    pub(crate) requested: MetadataView,
    pub(crate) established: MetadataView,
    pub(crate) queries: [QueryStatus; METADATA_FIELDS],
    pub(crate) label: Option<KeyLabel>,
    pub(crate) accessing_sessions: usize,
}

/// Cardinalities of retained state.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub(crate) struct StateUsage {
    pub(crate) domains: usize,
    pub(crate) instances: usize,
    pub(crate) live_sessions: usize,
    pub(crate) session_records: usize,
    pub(crate) object_records: usize,
    pub(crate) live_bindings: usize,
    pub(crate) tombstones: usize,
    pub(crate) pending_calls: usize,
    /// Lifetime counts (IDs minted) versus occupancy above: records are
    /// pruned and refunded only once no fence can still need them.
    pub(crate) lifetime_objects: u64,
    pub(crate) lifetime_sessions: u64,
    pub(crate) pruned_objects: u64,
    pub(crate) pruned_sessions: u64,
    pub(crate) refunded_tombstones: u64,
    pub(crate) pruned_domains: u64,
}

/// ESTIMATE: entries times `size_of` per structure. Not heap evidence.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub(crate) struct StateEstimate {
    pub(crate) occupied_bytes: usize,
    pub(crate) object_records: usize,
    pub(crate) session_records: usize,
    pub(crate) live_bindings: usize,
    pub(crate) pending_calls: usize,
}

/// The sanitized, pointer-free projection.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct ObjectProjection {
    pub(crate) sessions: Vec<SessionView>,
    pub(crate) objects: Vec<ObjectView>,
    pub(crate) gaps: Vec<(ObjectGap, u64)>,
    pub(crate) usage: StateUsage,
}

impl ObjectProjection {
    pub(crate) fn object(&self, id: ObjectId) -> Option<&ObjectView> {
        self.objects.iter().find(|view| view.id == id)
    }

    pub(crate) fn session(&self, id: SessionIncarnation) -> Option<&SessionView> {
        self.sessions.iter().find(|view| view.id == id)
    }

    pub(crate) fn gap(&self, reason: ObjectGap) -> u64 {
        self.gaps
            .iter()
            .find(|(gap, _)| *gap == reason)
            .map_or(0, |(_, count)| *count)
    }
}

// ---------------------------------------------------------------------------
// Limits and the model
// ---------------------------------------------------------------------------

/// Injectable bounds; [`ObjectLimits::policy`] is the v3 contract.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct ObjectLimits {
    pub(crate) live_sessions_per_instance: usize,
    pub(crate) views_per_instance: usize,
    pub(crate) instances: usize,
    pub(crate) session_records: usize,
    pub(crate) object_records: usize,
    pub(crate) pending_calls: usize,
    pub(crate) max_object_id: u64,
    pub(crate) max_session_id: u64,
    pub(crate) max_call_token: u64,
}

impl ObjectLimits {
    pub(crate) const fn policy() -> Self {
        Self {
            live_sessions_per_instance: 1_024,
            views_per_instance: 4_096,
            instances: 4_096,
            session_records: 16_384,
            object_records: 65_536,
            pending_calls: 1_024,
            max_object_id: u64::MAX,
            max_session_id: u64::MAX,
            max_call_token: u64::MAX,
        }
    }
}

/// The capture-owned object model.
#[derive(Debug)]
pub(crate) struct ObjectSemantics {
    state: state::ModelState,
}

/// A terminal outcome the producer can prove it lost, with an upper-bound
/// reference cut after which the call can no longer take effect.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum LostOutcome {
    /// An admitted call whose completion will never arrive.
    Ticket(CallToken, RefCut),
    /// Begins refused for capacity in this domain are all over by the cut.
    Refused(ObjectDomain, RefCut),
}

impl ObjectSemantics {
    /// Production construction always uses the policy limits.
    pub(crate) fn new() -> Self {
        Self {
            state: state::ModelState::new(ObjectLimits::policy()),
        }
    }

    /// Test-only limit injection for capacity regressions.
    #[cfg(test)]
    pub(crate) fn with_limits(limits: ObjectLimits) -> Self {
        Self {
            state: state::ModelState::new(limits),
        }
    }

    /// Test-only: put a domain's proof generation at its maximum.
    #[cfg(test)]
    pub(crate) fn exhaust_generation(&mut self, domain: ObjectDomain) {
        self.state.exhaust_generation(domain);
    }

    /// Reference fact: a call's terminal outcome was lost; the cut is an
    /// upper bound on where it could have taken effect.
    pub(crate) fn outcome_lost(&mut self, lost: LostOutcome) -> ObjectEffects {
        self.state.outcome_lost(lost)
    }

    /// Register a domain identity before any fact names it. Idempotent
    /// while held. At the instance cap, ended domains with no ticket, live
    /// view or live session are pruned first (lazily). A recently pruned
    /// identity is refused (`DomainPruned`). See the producer contract on
    /// [`ObjectDomain`]: identities are never reused, and an ended identity
    /// is never registered or bootstrapped again.
    pub(crate) fn register_domain(&mut self, domain: ObjectDomain) -> Result<(), ObjectGap> {
        self.state.register_domain(domain)
    }

    /// Admit one logical call at its reference entry cut.
    ///
    /// Producer obligation: never re-deliver a begin the model may have
    /// retired. Only an exact re-delivery of a still-admitted key is a no-op
    /// (`DuplicateCall`); a new key at or below the covered frontier
    /// (`ClosedFrontier`) or at an occupied cut (`MalformedFact`) is
    /// unrepresentable history and contradicts the domain's proof.
    pub(crate) fn begin(&mut self, origin: OriginFact) -> Result<CallToken, ObjectGap> {
        self.state.begin(origin)
    }

    /// Stage one matched completion privately; publishes no object claim.
    pub(crate) fn complete(&mut self, token: CallToken, result: CompletedFact) -> ObjectEffects {
        self.state.complete(token, result)
    }

    /// Apply the history covered by a complete reference prefix.
    pub(crate) fn settle(&mut self, prefix: CompleteInputPrefix) -> ObjectEffects {
        self.state.settle(prefix)
    }

    /// Apply an explicit reference boundary to the affected scope.
    pub(crate) fn invalidate(&mut self, scope: AffectedScope, reason: ObjectGap) -> ObjectEffects {
        self.state.invalidate(scope, reason)
    }

    pub(crate) fn project(&self) -> ObjectProjection {
        self.state.project()
    }

    pub(crate) fn state_estimate(&self) -> StateEstimate {
        self.state.estimate()
    }
}
