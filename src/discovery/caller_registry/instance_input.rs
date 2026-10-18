//! SPDX-License-Identifier: GPL-3.0-or-later
//! Sealed H2 consumer inputs. H3 must consume runtime proofs here; these
//! reference builders never exist in a production build.
#![cfg_attr(not(test), allow(dead_code))]

use super::{
    BudgetRefusal, CallerId, CallerRegistry, MappingState, ModuleId, ModuleKey, Mutation,
    RegistryGap,
};
use crate::attach::capture::NativeDomainId;
use crate::discovery::engine::inventory_coordinator::semantics::SemanticCallerBinding;
use crate::discovery::instances::{InstanceId, Route};
use crate::inventory_semantics::{AttestedSubset, LaneCoverage, LaneNegative};
use crate::semantic_capture::{Endpoint, InvalidationScope, RoutedCall};
use crate::semantics_edge::{EdgeSemantics, EffectOrigin, NoSink, SemanticCall};
use crate::semantics_key_use::{FeedMode, JointStaging, KeyUseTee, StagingRefusal};
use p11scope_ebpf_common::object_wire::ValidatedObjectCall;
use p11scope_ebpf_common::{Event, ImageIdentity, SlotSemantics};
use std::collections::{BTreeMap, BTreeSet, HashMap};
use std::fmt;
use std::hash::{Hash, Hasher};

pub(crate) const MAX_REGISTRY_INSTANCES: usize = 4096;
pub(crate) const MAX_INSTANCE_NEGATIVE_SCOPES: usize = 4096;

#[derive(Clone, PartialEq, Eq)]
pub(crate) struct InstanceKey {
    domain: NativeDomainId,
    image: ImageIdentity,
    router: InstanceId,
    module: ModuleKey,
}

impl Hash for InstanceKey {
    fn hash<H: Hasher>(&self, state: &mut H) {
        self.domain.hash(state);
        self.image.task_cookie.hash(state);
        self.image.exec_id.hash(state);
        self.router.hash(state);
        self.module.hash(state);
    }
}

#[cfg(test)]
impl InstanceKey {
    /// Tests-only reference key (N1): production keys come only
    /// from admission.
    pub(crate) fn scripted(
        domain: NativeDomainId,
        image: ImageIdentity,
        router: InstanceId,
        module: ModuleKey,
    ) -> Self {
        Self {
            domain,
            image,
            router,
            module,
        }
    }
}

#[cfg(test)]
impl AdmittedInstance {
    /// Tests-only reference registration (N1): a current,
    /// boundary-free registration for feed-selection tests.
    pub(crate) fn scripted(key: InstanceKey, caller: CallerId) -> Self {
        Self {
            key,
            caller,
            observed_ns: 0,
            boundary: None,
        }
    }
}

#[cfg(test)]
impl AdmittedInstanceCall {
    /// Tests-only reference call (N1): a current-continuity call at
    /// `ordinal` carrying `facts`, for guarded-path tests.
    pub(crate) fn scripted(
        key: InstanceKey,
        caller: CallerId,
        ordinal: u64,
        facts: SemanticCall,
    ) -> Self {
        let position = SemanticPosition {
            domain: key.domain,
            ordinal,
        };
        Self {
            key,
            caller,
            position,
            facts,
            permission: ReductionPermission::CurrentContinuity,
            journal_invocation: None,
            object: None,
        }
    }
}

impl fmt::Debug for InstanceKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("InstanceKey(<private>)")
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub(crate) struct RegistryInstanceId(u32);

impl RegistryInstanceId {
    /// The raw registry instance number (H9 key-row attribution).
    pub(crate) const fn from_raw(raw: u32) -> Self {
        Self(raw)
    }

    pub(crate) fn label(self) -> String {
        format!("i{}", self.0)
    }
}

#[derive(Clone, Copy)]
pub(crate) struct SemanticPosition {
    domain: NativeDomainId,
    ordinal: u64,
}

impl fmt::Debug for SemanticPosition {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("SemanticPosition(<private>)")
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub(crate) enum InstanceReason {
    NoCalls,
    InstanceUnproven,
    ProviderInstanceUnproven,
    CallerUnbound,
    Unauthorized,
    AmbiguousDescriptor,
    CountOnly,
    SemanticLoss,
    BeforeSemanticBoundary,
    OutOfOrderReturn,
    InstanceRetired,
    ImageRetired,
    TaskRetired,
    CaptureStopped,
    InstanceCapacity,
    SemanticStateCapacity,
    AuthorityExhausted,
    NegativeStateCapacity,
    SemanticResourceCapacity,
}

impl InstanceReason {
    pub(crate) const fn label(self) -> &'static str {
        match self {
            Self::NoCalls => "no_calls",
            Self::InstanceUnproven => "instance_unproven",
            Self::ProviderInstanceUnproven => "provider_instance_unproven",
            Self::CallerUnbound => "caller_unbound",
            Self::Unauthorized => "unauthorized",
            Self::AmbiguousDescriptor => "ambiguous_descriptor",
            Self::CountOnly => "count_only",
            Self::SemanticLoss => "semantic_loss",
            Self::BeforeSemanticBoundary => "before_semantic_boundary",
            Self::OutOfOrderReturn => "out_of_order_return",
            Self::InstanceRetired => "instance_retired",
            Self::ImageRetired => "image_retired",
            Self::TaskRetired => "task_retired",
            Self::CaptureStopped => "capture_stopped",
            Self::InstanceCapacity => "instance_capacity",
            Self::SemanticStateCapacity => "semantic_state_capacity",
            Self::AuthorityExhausted => "authority_exhausted",
            Self::NegativeStateCapacity => "negative_state_capacity",
            Self::SemanticResourceCapacity => "semantic_resource_capacity",
        }
    }
}

#[derive(Debug)]
pub(crate) struct AdmittedInstance {
    key: InstanceKey,
    caller: CallerId,
    observed_ns: u64,
    boundary: Option<SemanticPosition>,
}

#[derive(Debug)]
enum ReductionPermission {
    CurrentContinuity,
    HistoricalOnly(InstanceReason),
}

/// Original physical API invocation, retained privately before S1 drops
/// the raw thread and duration. It carries no continuity authority.
#[derive(Clone, Copy)]
struct JournalInvocationIdentity {
    pid_tgid: u64,
    entry_ns: u64,
    return_ns: u64,
    slot: u32,
}

impl JournalInvocationIdentity {
    fn from_event(event: &p11scope_ebpf_common::Event) -> Option<Self> {
        // The producer saturates its duration subtraction. Zero duration
        // cannot distinguish an actual zero interval from saturation.
        if event.duration_ns == 0 || event.pid_tgid as u32 == 0 || event.pid_tgid >> 32 == 0 {
            return None;
        }
        Some(Self {
            pid_tgid: event.pid_tgid,
            entry_ns: event.ts_ns.checked_sub(event.duration_ns)?,
            return_ns: event.ts_ns,
            slot: event.slot,
        })
    }
}

pub(crate) struct AdmittedInstanceCall {
    key: InstanceKey,
    caller: CallerId,
    position: SemanticPosition,
    facts: SemanticCall,
    permission: ReductionPermission,
    journal_invocation: Option<JournalInvocationIdentity>,
    /// Slice D: the private validated object tail, bound to the attested
    /// slot descriptor at admission and dropped on mismatch. H9 consumes
    /// it; no public object projection exists here.
    object: Option<ValidatedObjectCall>,
}

impl fmt::Debug for AdmittedInstanceCall {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        // Presence only: raw tail words never render.
        f.debug_struct("AdmittedInstanceCall")
            .field("key", &self.key)
            .field("caller", &self.caller)
            .field("position", &self.position)
            .field("facts", &self.facts)
            .field("permission", &self.permission)
            .field("object", &self.object.is_some())
            .finish()
    }
}

impl AdmittedInstanceCall {
    /// Journal domain binding (H8): the admitted call's exact native
    /// domain, image, router and caller for sealed incarnation minting.
    /// Only the journal child reads this; the values feed private model
    /// keys and never render.
    pub(crate) fn journal_binding(
        &self,
    ) -> (
        crate::attach::capture::NativeDomainId,
        p11scope_ebpf_common::ImageIdentity,
        crate::discovery::instances::InstanceId,
        crate::discovery::caller_registry::CallerId,
    ) {
        (
            self.key.domain,
            self.key.image,
            self.key.router,
            self.caller,
        )
    }

    /// H9 joint staging: the S1 payload this admission proved, for
    /// ordered replay after the seal settles its call. Only the H9
    /// feed child reads this; the payload is never modified.
    pub(crate) fn s1_facts(&self) -> &SemanticCall {
        &self.facts
    }

    /// H9 joint staging: the H0 ordinal positioning this admission,
    /// for replay-order and fallback-coverage checks. Only the H9
    /// feed child reads this.
    pub(crate) fn h0_ordinal(&self) -> u64 {
        self.position.ordinal
    }

    /// Journal per-call authority (H8): this admitted call's
    /// attribution shape for staged-BEGIN matching. `None` when the
    /// call cannot name its instance (unattributable) or names no
    /// catalog function: such admissions bind the key but authorize no
    /// staged call. Only the journal child reads this.
    pub(crate) fn journal_call_fingerprint(
        &self,
    ) -> Option<crate::semantics_objects::journal::CallFingerprint> {
        use crate::semantics_objects::journal::CallFingerprint;
        if !self.facts.attributable {
            return None;
        }
        let function = crate::kinds::function_id(&self.facts.function)?;
        let invocation = self.journal_invocation?;
        Some(CallFingerprint {
            image: (self.key.image.task_cookie, self.key.image.exec_id),
            function,
            pid_tgid: invocation.pid_tgid,
            entry_ns: invocation.entry_ns,
            slot: invocation.slot,
            session: self.facts.session,
            mechanism: self.facts.mechanism,
            capture: self.facts.capture,
            slot_id: self.facts.slot_id,
            flags: self.facts.flags,
            user_type: self.facts.user_type,
        })
    }
    pub(crate) fn journal_return_ns(&self) -> Option<u64> {
        self.journal_invocation
            .map(|invocation| invocation.return_ns)
    }
}

enum InstanceScope {
    Domain(NativeDomainId),
    Image(NativeDomainId, ImageIdentity),
    Module(NativeDomainId, ImageIdentity, ModuleKey),
    Exact(InstanceKey),
}

impl fmt::Debug for InstanceScope {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("InstanceScope(<private>)")
    }
}
impl InstanceScope {
    fn domain(&self) -> NativeDomainId {
        match self {
            Self::Domain(d) | Self::Image(d, _) | Self::Module(d, _, _) => *d,
            Self::Exact(k) => k.domain,
        }
    }
}

#[derive(Debug)]
pub(crate) struct InstanceSemanticLoss {
    scope: InstanceScope,
    position: Option<SemanticPosition>,
    reason: InstanceReason,
}

enum RetirementScope {
    Domain(NativeDomainId),
    Image(NativeDomainId, ImageIdentity),
    Exact(InstanceKey),
    Task(NativeDomainId, u64),
}

impl fmt::Debug for RetirementScope {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("RetirementScope(<private>)")
    }
}
impl RetirementScope {
    fn domain(&self) -> NativeDomainId {
        match self {
            Self::Domain(d) | Self::Image(d, _) | Self::Task(d, _) => *d,
            Self::Exact(k) => k.domain,
        }
    }
}

#[derive(Debug)]
pub(crate) struct InstanceRetirement {
    scope: RetirementScope,
    position: SemanticPosition,
    reason: InstanceReason,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum InstanceLifecycle {
    Observed,
    Uncertain,
    Retired,
}

impl InstanceLifecycle {
    pub(crate) const fn label(self) -> &'static str {
        match self {
            Self::Observed => "observed",
            Self::Uncertain => "uncertain",
            Self::Retired => "retired",
        }
    }
}

#[derive(Debug)]
pub(crate) struct InstanceRecord {
    pub(crate) id: RegistryInstanceId,
    key: InstanceKey,
    pub(crate) caller: CallerId,
    pub(crate) module: ModuleId,
    pub(crate) state: InstanceLifecycle,
    pub(crate) reason: Option<InstanceReason>,
    pub(crate) first_seen_ns: u64,
    pub(crate) last_seen_ns: u64,
}

#[derive(Debug)]
pub(crate) struct InstanceSemanticRecord {
    pub(crate) id: RegistryInstanceId,
    pub(crate) caller: CallerId,
    pub(crate) module: ModuleId,
    pub(crate) api_returns: Option<u64>,
    pub(crate) saturated: bool,
    pub(crate) historical_only_returns: u64,
    boundary: Option<u64>,
    last_reduced: Option<u64>,
    pub(crate) reasons: BTreeSet<InstanceReason>,
    pub(crate) lossy: bool,
    pub(crate) semantics: Option<EdgeSemantics>,
    authority_exhausted: bool,
    /// The instance's H9 feed, selected once at registration from an
    /// installed Joint receipt (S1Only without one — the production
    /// default, since no live grants exist).
    pub(crate) feed: JointStaging,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
enum NegativeKind {
    Domain,
    Task,
    Image,
    Module,
    Exact,
}

#[derive(Clone, Copy)]
struct NegativeRecord {
    domain: NativeDomainId,
    cookie: u64,
    exec: u64,
    router: u64,
    module: ModuleId,
    barrier: u64,
    reasons: u32,
    kind: NegativeKind,
    retirement: Option<InstanceReason>,
    authority_exhausted: bool,
}

impl fmt::Debug for NegativeRecord {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("NegativeRecord")
            .field("scope", &"<private>")
            .field("reason_count", &self.reasons.count_ones())
            .field(
                "permanent",
                &(self.retirement.is_some() || self.authority_exhausted),
            )
            .finish_non_exhaustive()
    }
}
impl NegativeRecord {
    fn domain(domain: NativeDomainId) -> Self {
        Self {
            domain,
            cookie: 0,
            exec: 0,
            router: 0,
            module: ModuleId(0),
            barrier: 0,
            reasons: 0,
            kind: NegativeKind::Domain,
            retirement: None,
            authority_exhausted: false,
        }
    }
    fn same_scope(&self, other: &Self) -> bool {
        self.domain == other.domain
            && self.kind == other.kind
            && self.cookie == other.cookie
            && self.exec == other.exec
            && self.router == other.router
            && self.module == other.module
    }
    fn matches(&self, key: &InstanceKey, module: ModuleId) -> bool {
        self.domain == key.domain
            && match self.kind {
                NegativeKind::Domain => true,
                NegativeKind::Task => self.cookie == key.image.task_cookie,
                NegativeKind::Image => {
                    self.cookie == key.image.task_cookie && self.exec == key.image.exec_id
                }
                NegativeKind::Module => {
                    self.cookie == key.image.task_cookie
                        && self.exec == key.image.exec_id
                        && self.module == module
                }
                NegativeKind::Exact => {
                    self.cookie == key.image.task_cookie
                        && self.exec == key.image.exec_id
                        && self.module == module
                        && self.router == key.router.get()
                }
            }
    }
}

impl InstanceReason {
    const ALL: &'static [Self] = &[
        Self::NoCalls,
        Self::InstanceUnproven,
        Self::ProviderInstanceUnproven,
        Self::CallerUnbound,
        Self::Unauthorized,
        Self::AmbiguousDescriptor,
        Self::CountOnly,
        Self::SemanticLoss,
        Self::BeforeSemanticBoundary,
        Self::OutOfOrderReturn,
        Self::InstanceRetired,
        Self::ImageRetired,
        Self::TaskRetired,
        Self::CaptureStopped,
        Self::InstanceCapacity,
        Self::SemanticStateCapacity,
        Self::AuthorityExhausted,
        Self::NegativeStateCapacity,
        Self::SemanticResourceCapacity,
    ];
    fn bit(self) -> u32 {
        1u32 << (self as u32)
    }
}
const _: () = assert!((InstanceReason::SemanticResourceCapacity as u32) < 32);

const _: () = assert!(std::mem::size_of::<NegativeRecord>() <= 64);
const _: () = assert!(!std::mem::needs_drop::<NegativeRecord>());

pub(super) struct InstanceState {
    records: BTreeMap<RegistryInstanceId, InstanceRecord>,
    semantics: BTreeMap<RegistryInstanceId, InstanceSemanticRecord>,
    by_key: HashMap<InstanceKey, RegistryInstanceId>,
    next_id: u32,
    limit: usize,
    occupied: usize,
    refused: u64,
    semantic_refused: u64,
    negatives: Vec<NegativeRecord>,
    negative_limit: usize,
    negative_refused: u64,
    negative_exhausted: bool,
    identity_exhausted: bool,
}

impl Default for InstanceState {
    fn default() -> Self {
        Self {
            records: BTreeMap::new(),
            semantics: BTreeMap::new(),
            by_key: HashMap::new(),
            next_id: 0,
            limit: MAX_REGISTRY_INSTANCES,
            occupied: 0,
            refused: 0,
            semantic_refused: 0,
            negatives: Vec::new(),
            negative_limit: MAX_INSTANCE_NEGATIVE_SCOPES,
            negative_refused: 0,
            negative_exhausted: false,
            identity_exhausted: false,
        }
    }
}

impl CallerRegistry {
    /// Census at immutable publication, never on the semantic ingress path.
    /// The byte pool and these counts cover both legacy and instance reducers.
    pub(crate) fn semantic_resource_occupancy(&self) -> crate::semantics_edge::S1Occupancy {
        let mut total = crate::semantics_edge::S1Occupancy::default();
        for reducer in self
            .edges
            .values()
            .filter_map(|edge| edge.semantics.as_ref())
            .chain(
                self.instance_state
                    .semantics
                    .values()
                    .filter_map(|edge| edge.semantics.as_ref()),
            )
        {
            let usage = reducer.resource_usage();
            total.open_bindings += usage.open_bindings;
            total.active_machines += usage.active_machines;
            total.pending_calls += usage.pending_calls;
            total.detached_calls += usage.detached_calls;
            total.mechanisms += usage.mechanisms;
            total.operation_categories += usage.operation_categories;
            total.provenance_functions += usage.provenance_functions;
            total.provenance_function_bytes += usage.provenance_function_bytes;
            total.provenance_function_capacity_bytes += usage.provenance_function_capacity_bytes;
            total.provenance_returns += usage.provenance_returns;
            total.async_function_bytes += usage.async_function_bytes;
            total.async_function_capacity_bytes += usage.async_function_capacity_bytes;
            total.origin_vectors += usage.origin_vectors;
            total.origin_elements += usage.origin_elements;
            total.origin_capacity_elements += usage.origin_capacity_elements;
        }
        total
    }

    pub(crate) fn instances(&self) -> impl Iterator<Item = &InstanceRecord> {
        self.instance_state.records.values()
    }
    pub(crate) fn instance_semantic_edges(&self) -> impl Iterator<Item = &InstanceSemanticRecord> {
        self.instance_state.semantics.values()
    }
    pub(crate) fn instance_limit(&self) -> usize {
        self.instance_state.limit
    }
    pub(crate) fn instance_refused(&self) -> u64 {
        self.instance_state.refused
    }
    pub(crate) fn instance_semantic_occupied(&self) -> usize {
        self.instance_state.occupied
    }
    pub(crate) fn instance_semantic_refused(&self) -> u64 {
        self.instance_state.semantic_refused
    }
    pub(crate) fn instance_negative_limit(&self) -> usize {
        self.instance_state.negative_limit
    }
    pub(crate) fn instance_negative_occupied(&self) -> usize {
        self.instance_state.negatives.len()
    }
    pub(crate) fn instance_negative_refused(&self) -> u64 {
        self.instance_state.negative_refused
    }
    pub(crate) fn instance_negative_exhausted(&self) -> bool {
        self.instance_state.negative_exhausted
    }
    pub(crate) fn instance_semantic_unknown_edges(&self) -> usize {
        self.instance_state
            .semantics
            .values()
            .filter(|s| {
                s.semantics
                    .as_ref()
                    .is_none_or(|r| r.label() != crate::semantics_edge::SEMANTIC_OBSERVED)
            })
            .count()
    }

    pub(crate) fn note_instance(&mut self, input: AdmittedInstance) {
        self.staged.push(Mutation::NoteInstance(input));
    }

    /// Install one instance's Joint feed receipt (guarded H9 path):
    /// the next registration of `key` selects Joint, consuming the
    /// receipt. Bounded by the instance limit (excess installs
    /// refuse). Live-loop carry: only the staged driver and
    /// tests install (production has no grants until the joint seal
    /// tick lands).
    #[cfg_attr(not(test), allow(dead_code))]
    pub(crate) fn install_joint_receipt(
        &mut self,
        key: InstanceKey,
        receipt: crate::semantics_objects::journal::BootstrapReceipt,
    ) -> bool {
        if self.joint_grants.len() >= self.instance_state.limit {
            return false;
        }
        self.joint_grants.insert(key, receipt);
        true
    }

    /// Joint-mode feeds (the effects-tee guard reads this).
    #[cfg_attr(not(test), allow(dead_code))]
    pub(crate) fn joint_feeds(&self) -> usize {
        self.joint_feeds
    }

    /// Tests-only feed-mode read (N1): the feed an instance's
    /// registration selected.
    #[cfg(test)]
    pub(crate) fn feed_mode_for_test(
        &self,
        id: RegistryInstanceId,
    ) -> Option<crate::semantics_key_use::FeedMode> {
        self.instance_state
            .semantics
            .get(&id)
            .map(|record| record.feed.mode())
    }

    /// Inspect accounting without granting publication authority.
    #[cfg(test)]
    pub(crate) fn keyuse_for_test(&self) -> &crate::semantics_key_use::KeyUseReducer {
        &self.joint_keyuse
    }

    /// Joint calls reduced S1Only-direct for lack of H8 staging.
    #[cfg_attr(not(test), allow(dead_code))]
    pub(crate) fn joint_direct_fallback(&self) -> u64 {
        self.joint_direct_fallback
    }

    /// Deliver one H8 seal to an instance's Joint feed (guarded H9
    /// path): exact-correlated replay through the shared reducer,
    /// then the H8 projection is retained for capture. Unknown
    /// instances and missing reducers hold without effect.
    /// Live-loop carry: only the staged driver and tests deliver
    /// (production runs no H8 seals until the joint seal tick lands).
    #[cfg_attr(not(test), allow(dead_code))]
    pub(crate) fn deliver_joint_seal(
        &mut self,
        id: RegistryInstanceId,
        seal: &crate::semantics_objects::journal::SealSuccess,
        model: &crate::semantics_objects::ObjectSemantics,
        ledger: &mut crate::semantics_objects::journal::StagingLedger,
    ) -> crate::semantics_key_use::SealApplyOutcome {
        use crate::semantics_key_use::SealApplyOutcome;
        let Some(record) = self.instance_state.semantics.get_mut(&id) else {
            return SealApplyOutcome::Held;
        };
        if !record.feed.accepts_seal(seal) {
            return SealApplyOutcome::Held;
        }
        let was_joint = record.feed.mode() == FeedMode::Joint;
        let Some(reducer) = record.semantics.as_mut() else {
            return SealApplyOutcome::Held;
        };
        let mut outer = NoSink;
        let (outcome, refused) = record.feed.apply_seal(
            seal,
            model,
            ledger,
            reducer,
            &mut self.joint_keyuse,
            id,
            &mut outer,
            Some(&mut self.assoc_fallback),
        );
        self.instance_state.semantic_refused =
            self.instance_state.semantic_refused.saturating_add(refused);
        self.after_joint_delivery(id, was_joint, model);
        outcome
    }

    /// Deliver one H8 seal failure (guarded H9 path): loss disposal
    /// or proof-only fallback through the shared reducer, then the
    /// H8 projection is retained for capture. Same holds as seals.
    #[cfg_attr(not(test), allow(dead_code))]
    pub(crate) fn deliver_joint_failure(
        &mut self,
        id: RegistryInstanceId,
        failure: &crate::semantics_objects::journal::SealFailure,
        finalizer: &mut impl crate::semantics_objects::journal::H3EvidenceSource,
        model: &crate::semantics_objects::ObjectSemantics,
        ledger: &mut crate::semantics_objects::journal::StagingLedger,
    ) -> crate::semantics_key_use::FailureApplyOutcome {
        use crate::semantics_key_use::FailureApplyOutcome;
        let Some(record) = self.instance_state.semantics.get_mut(&id) else {
            return FailureApplyOutcome::Ignored;
        };
        if !record.feed.accepts_failure(failure) {
            return FailureApplyOutcome::Ignored;
        }
        let was_joint = record.feed.mode() == FeedMode::Joint;
        let Some(reducer) = record.semantics.as_mut() else {
            return FailureApplyOutcome::Ignored;
        };
        let mut outer = NoSink;
        let (outcome, refused) = record.feed.apply_failure(
            failure,
            finalizer,
            model,
            ledger,
            reducer,
            &mut self.joint_keyuse,
            id,
            &mut outer,
            Some(&mut self.assoc_fallback),
        );
        self.instance_state.semantic_refused =
            self.instance_state.semantic_refused.saturating_add(refused);
        self.after_joint_delivery(id, was_joint, model);
        outcome
    }

    /// Post-delivery bookkeeping: decrement the current Joint count
    /// for feeds leaving that mode, and retain delivered Joint evidence
    /// as the H8 projection for capture.
    #[cfg_attr(not(test), allow(dead_code))]
    fn after_joint_delivery(
        &mut self,
        id: RegistryInstanceId,
        was_joint: bool,
        model: &crate::semantics_objects::ObjectSemantics,
    ) {
        let now_joint = self
            .instance_state
            .semantics
            .get(&id)
            .expect("delivered record retained")
            .feed
            .mode()
            == FeedMode::Joint;
        if was_joint && !now_joint {
            self.joint_feeds = self.joint_feeds.saturating_sub(1);
        }
        if was_joint {
            self.key_projection = Some(model.project());
        }
    }

    /// Capture the guarded H9 section: commit from retained Joint
    /// evidence, or unavailable exactly as before without it.
    pub(crate) fn joint_observations(
        &self,
        revision: u64,
    ) -> crate::key_operation_projection::ObjectObservations {
        let Some(projection) = self.key_projection.as_ref() else {
            return crate::key_operation_projection::ObjectObservations::unavailable(
                revision,
                "bootstrap_unavailable",
            );
        };
        let stagings: Vec<&JointStaging> = self
            .instance_state
            .semantics
            .values()
            .map(|record| &record.feed)
            .collect();
        crate::key_operation_projection::producer::commit(
            revision,
            &stagings,
            projection,
            &self.joint_keyuse,
        )
    }
    pub(crate) fn observe_instance_semantic(&mut self, input: AdmittedInstanceCall) {
        self.staged.push(Mutation::ObserveInstanceSemantic(input));
    }
    pub(crate) fn note_instance_semantic_loss(&mut self, input: InstanceSemanticLoss) {
        self.staged.push(Mutation::InstanceSemanticLoss(input));
    }
    pub(crate) fn retire_instance(&mut self, input: InstanceRetirement) {
        self.staged.push(Mutation::RetireInstance(input));
    }

    fn instance_gap(
        &mut self,
        caller: Option<CallerId>,
        module: Option<ModuleId>,
        reason: InstanceReason,
        budget: Option<BudgetRefusal>,
    ) {
        self.push_gap(RegistryGap {
            caller,
            module,
            pid: None,
            subject: "instance semantics refused".into(),
            reason: reason.label().into(),
            budget,
        });
    }

    pub(super) fn apply_instance(
        &mut self,
        input: AdmittedInstance,
        mut shared: Option<&mut crate::semantics_objects::journal::StagingLedger>,
    ) {
        let module = self.modules_by_key.get(&input.key.module).copied();
        let refuse = if matches!(input.key.module, ModuleKey::Unidentified { .. })
            || input.key.image.task_cookie == 0
        {
            Some(InstanceReason::ProviderInstanceUnproven)
        } else if self.retired.contains_key(&input.caller)
            || module.is_none_or(|m| !self.edges.contains_key(&(input.caller, m)))
        {
            Some(InstanceReason::CallerUnbound)
        } else if input.boundary.is_some_and(|p| p.domain != input.key.domain) {
            Some(InstanceReason::InstanceUnproven)
        } else {
            None
        };
        if let Some(reason) = refuse {
            self.instance_gap(Some(input.caller), module, reason, None);
            return;
        }
        let module = module.expect("physical mapping checked");
        if self.instance_state.negative_exhausted || self.instance_state.identity_exhausted {
            self.instance_gap(
                Some(input.caller),
                Some(module),
                if self.instance_state.negative_exhausted {
                    InstanceReason::NegativeStateCapacity
                } else {
                    InstanceReason::AuthorityExhausted
                },
                None,
            );
            return;
        }
        let mut boundary = input.boundary.map(|p| p.ordinal);
        let mut reasons = 0u32;
        let mut permanent = None;
        for negative in &self.instance_state.negatives {
            if negative.matches(&input.key, module) {
                if negative.barrier != 0 {
                    boundary =
                        Some(boundary.map_or(negative.barrier, |old| old.max(negative.barrier)));
                }
                reasons |= negative.reasons;
                if negative.authority_exhausted {
                    permanent = Some(InstanceReason::AuthorityExhausted);
                } else if let Some(reason) = negative.retirement {
                    permanent = Some(reason);
                }
            }
        }
        if let Some(reason) = permanent {
            self.instance_gap(Some(input.caller), Some(module), reason, None);
            return;
        }

        if let Some(id) = self.instance_state.by_key.get(&input.key).copied() {
            let record = &self.instance_state.records[&id];
            let refusal = if record.caller != input.caller {
                Some(InstanceReason::CallerUnbound)
            } else if record.state == InstanceLifecycle::Retired {
                Some(record.reason.unwrap_or(InstanceReason::InstanceRetired))
            } else {
                None
            };
            if let Some(reason) = refusal {
                self.instance_gap(Some(input.caller), Some(module), reason, None);
                return;
            }
            let last_seen_ns = record.last_seen_ns.max(input.observed_ns);
            self.instance_state
                .records
                .get_mut(&id)
                .expect("retained instance")
                .last_seen_ns = last_seen_ns;
            if boundary.is_some_and(|b| {
                self.instance_state.semantics[&id]
                    .boundary
                    .is_none_or(|old| b > old)
            }) {
                self.invalidate_instance(
                    id,
                    boundary,
                    InstanceReason::SemanticLoss,
                    false,
                    shared.as_deref_mut(),
                );
            }
            self.inherit_instance_reasons(id, reasons);
            return;
        }
        if self.instance_state.records.len() >= self.instance_state.limit {
            self.instance_state.refused = self.instance_state.refused.saturating_add(1);
            self.instance_gap(
                Some(input.caller),
                Some(module),
                InstanceReason::InstanceCapacity,
                Some(BudgetRefusal {
                    resource: "instances",
                    limit: self.instance_state.limit,
                    requested: self.instance_state.records.len() + 1,
                }),
            );
            return;
        }
        let Some(next) = self.instance_state.next_id.checked_add(1) else {
            self.instance_state.identity_exhausted = true;
            let ids: Vec<_> = self.instance_state.records.keys().copied().collect();
            for id in ids {
                self.invalidate_instance(
                    id,
                    None,
                    InstanceReason::AuthorityExhausted,
                    false,
                    shared.as_deref_mut(),
                );
                self.instance_state
                    .semantics
                    .get_mut(&id)
                    .expect("retained edge")
                    .authority_exhausted = true;
            }
            self.instance_gap(
                Some(input.caller),
                Some(module),
                InstanceReason::AuthorityExhausted,
                None,
            );
            return;
        };
        let id = RegistryInstanceId(self.instance_state.next_id);
        self.instance_state.next_id = next;
        self.instance_state.by_key.insert(input.key.clone(), id);
        // Feed selection, once at registration: an installed Joint
        // receipt selects Joint (consumed — one receipt, one feed);
        // without one the feed stays S1Only, exactly as before.
        let installed = self.joint_grants.remove(&input.key);
        let feed = JointStaging::select_joint(installed.as_ref());
        if feed.mode() == FeedMode::Joint {
            self.joint_feeds = self.joint_feeds.saturating_add(1);
            self.joint_accounting = true;
        }
        self.instance_state.records.insert(
            id,
            InstanceRecord {
                id,
                key: input.key,
                caller: input.caller,
                module,
                state: InstanceLifecycle::Observed,
                reason: None,
                first_seen_ns: input.observed_ns,
                last_seen_ns: input.observed_ns,
            },
        );
        self.instance_state.semantics.insert(
            id,
            InstanceSemanticRecord {
                id,
                caller: input.caller,
                module,
                api_returns: None,
                saturated: false,
                historical_only_returns: 0,
                boundary: None,
                last_reduced: None,
                reasons: BTreeSet::from([InstanceReason::NoCalls]),
                lossy: false,
                semantics: None,
                authority_exhausted: false,
                feed,
            },
        );
        if boundary.is_some() {
            self.invalidate_instance(id, boundary, InstanceReason::SemanticLoss, false, shared);
        }
        self.inherit_instance_reasons(id, reasons);
    }

    fn inherit_instance_reasons(&mut self, id: RegistryInstanceId, reasons: u32) {
        let state = self
            .instance_state
            .semantics
            .get_mut(&id)
            .expect("retained semantic edge");
        for reason in InstanceReason::ALL {
            if reasons & reason.bit() != 0 {
                state.reasons.insert(*reason);
                state.lossy = true;
            }
        }
    }

    pub(super) fn apply_instance_call(
        &mut self,
        input: AdmittedInstanceCall,
        mut ledger: Option<&mut crate::semantics_objects::journal::StagingLedger>,
    ) {
        let Some(id) = self.instance_state.by_key.get(&input.key).copied() else {
            self.instance_gap(
                Some(input.caller),
                self.modules_by_key.get(&input.key.module).copied(),
                InstanceReason::InstanceUnproven,
                None,
            );
            return;
        };
        let record = &self.instance_state.records[&id];
        let module = record.module;
        if record.caller != input.caller || input.position.domain != input.key.domain {
            self.instance_gap(
                Some(input.caller),
                Some(module),
                InstanceReason::CallerUnbound,
                None,
            );
            return;
        }
        let state = &self.instance_state.semantics[&id];
        let historical = if self.instance_state.negative_exhausted {
            Some(InstanceReason::NegativeStateCapacity)
        } else if state.authority_exhausted || self.instance_state.identity_exhausted {
            Some(InstanceReason::AuthorityExhausted)
        } else if record.state == InstanceLifecycle::Retired {
            Some(record.reason.unwrap_or(InstanceReason::InstanceRetired))
        } else if let ReductionPermission::HistoricalOnly(reason) = input.permission {
            Some(reason)
        } else if state.boundary.is_some_and(|b| input.position.ordinal <= b) {
            Some(InstanceReason::BeforeSemanticBoundary)
        } else if state
            .last_reduced
            .is_some_and(|p| input.position.ordinal <= p)
        {
            Some(InstanceReason::OutOfOrderReturn)
        } else if self.edges[&(record.caller, module)].mapping != MappingState::Mapped {
            Some(InstanceReason::SemanticLoss)
        } else {
            None
        };
        let state = self
            .instance_state
            .semantics
            .get_mut(&id)
            .expect("retained semantic edge");
        let previous = state.api_returns.unwrap_or(0);
        state.api_returns = Some(previous.saturating_add(1));
        state.saturated |= previous == u64::MAX;
        state.reasons.remove(&InstanceReason::NoCalls);
        if let Some(reason) = historical {
            state.historical_only_returns = state.historical_only_returns.saturating_add(1);
            state.reasons.insert(reason);
            state.lossy = true;
            return;
        }
        let downgrade = if !input.facts.authorized {
            Some(InstanceReason::Unauthorized)
        } else if !input.facts.unambiguous {
            Some(InstanceReason::AmbiguousDescriptor)
        } else if input.facts.count_only {
            Some(InstanceReason::CountOnly)
        } else if !input.facts.attributable {
            Some(InstanceReason::InstanceUnproven)
        } else {
            None
        };
        if let Some(reason) = downgrade {
            self.invalidate_instance(
                id,
                Some(input.position.ordinal),
                reason,
                false,
                ledger.as_deref_mut(),
            );
            return;
        }
        let materialize = state.semantics.is_none();
        if materialize
            && self.semantic_occupied + self.instance_state.occupied
                >= self.limits.max_semantic_states
        {
            self.instance_state.semantic_refused =
                self.instance_state.semantic_refused.saturating_add(1);
            self.invalidate_instance(
                id,
                Some(input.position.ordinal),
                InstanceReason::SemanticStateCapacity,
                false,
                ledger.as_deref_mut(),
            );
            self.instance_gap(
                Some(input.caller),
                Some(module),
                InstanceReason::SemanticStateCapacity,
                Some(BudgetRefusal {
                    resource: "instance_semantic_state",
                    limit: self.limits.max_semantic_states,
                    requested: self.semantic_occupied + self.instance_state.occupied + 1,
                }),
            );
            return;
        }
        if materialize {
            let reducer = match EdgeSemantics::with_resources(&self.semantic_resources) {
                Ok(reducer) => reducer,
                Err(refusal) => {
                    self.refuse_instance_resource(
                        id,
                        &input,
                        module,
                        refusal,
                        ledger.as_deref_mut(),
                    );
                    return;
                }
            };
            self.instance_state
                .semantics
                .get_mut(&id)
                .expect("retained edge")
                .semantics = Some(reducer);
            self.instance_state.occupied += 1;
        }
        // Once a Joint feed activates capture-wide accounting, every
        // S1 reduction keeps teeing its effects, including after an
        // ordered fallback before the first seal/failure delivery.
        // The latch carries no object or publication authority.
        let joint_path = self.joint_accounting;
        let refused = if joint_path {
            self.reduce_with_joint_path(id, &input, ledger.as_deref_mut())
        } else {
            let state = self
                .instance_state
                .semantics
                .get_mut(&id)
                .expect("retained edge");
            state
                .semantics
                .as_mut()
                .expect("materialized above")
                .observe_with_resources(&input.facts)
        };
        let refused = match refused {
            Ok(refused) => refused,
            Err(refusal) => {
                self.refuse_instance_resource(id, &input, module, refusal, ledger);
                return;
            }
        };
        let state = self
            .instance_state
            .semantics
            .get_mut(&id)
            .expect("retained edge");
        state.last_reduced = Some(input.position.ordinal);
        self.instance_state.semantic_refused =
            self.instance_state.semantic_refused.saturating_add(refused);
        let record = self
            .instance_state
            .records
            .get_mut(&id)
            .expect("retained instance");
        record.state = InstanceLifecycle::Observed;
        record.reason = None;
        record.last_seen_ns = record.last_seen_ns.max(input.facts.ts_ns);
    }

    /// Reduce one call on the guarded Joint path (N1): Joint feeds
    /// stage against the shared H8 ledger for seal replay; S1Only
    /// siblings (and Joint staging fallbacks) reduce direct, teeing
    /// effects into the shared key-use reducer. When staging cannot
    /// hold the order (Full, missing ledger, unsealable with queued
    /// calls), queued calls fall back in order first (C4) — reducing
    /// a later fact direct would overtake them. Unreached before the
    /// first Joint registration activates capture-wide accounting.
    fn reduce_with_joint_path(
        &mut self,
        id: RegistryInstanceId,
        input: &AdmittedInstanceCall,
        mut ledger: Option<&mut crate::semantics_objects::journal::StagingLedger>,
    ) -> Result<u64, crate::semantics_edge::resources::SemanticResourceRefusal> {
        let joint = self
            .instance_state
            .semantics
            .get(&id)
            .expect("retained edge")
            .feed
            .mode()
            == FeedMode::Joint;
        let mut fallback_refused = 0u64;
        if joint {
            if let Some(ledger) = ledger.as_deref_mut() {
                let origin = EffectOrigin::from(&input.facts);
                // The stage attempt borrows the feed; the fallback
                // below reborrows the registry, so decide first.
                enum StageAction {
                    Staged,
                    CarveOut,
                    FallbackUncounted,
                    FallbackCounted,
                    Drop,
                }
                let action = {
                    let state = self
                        .instance_state
                        .semantics
                        .get_mut(&id)
                        .expect("retained edge");
                    match state.feed.stage(
                        input.facts.clone(),
                        origin,
                        input.position.ordinal,
                        &mut *ledger,
                    ) {
                        Ok(()) => StageAction::Staged,
                        // By-design carve-out, but ordered (C4): with
                        // queued calls the completion must not
                        // overtake its original — fall back in order
                        // first, then reduce direct below.
                        Err(StagingRefusal::Unsealable) => {
                            if state.feed.staged_len() > 0 {
                                StageAction::FallbackUncounted
                            } else {
                                StageAction::CarveOut
                            }
                        }
                        Err(StagingRefusal::Full) => StageAction::FallbackCounted,
                        // NotJoint contradicts the mode branch;
                        // ReplayRefused contradicts the
                        // OutOfOrderReturn guard above (frontier can
                        // only trail staged ordinals): drop, never
                        // double-reduce — counted, never silent.
                        // (Dropped, not reduced: no overtake.)
                        Err(_) => StageAction::Drop,
                    }
                };
                match action {
                    StageAction::Staged => return Ok(0),
                    StageAction::CarveOut => {}
                    StageAction::FallbackUncounted => {
                        fallback_refused = self.fallback_joint_for_order(id, Some(ledger));
                    }
                    StageAction::FallbackCounted => {
                        self.joint_direct_fallback = self.joint_direct_fallback.saturating_add(1);
                        fallback_refused = self.fallback_joint_for_order(id, Some(ledger));
                    }
                    StageAction::Drop => {
                        self.joint_direct_fallback = self.joint_direct_fallback.saturating_add(1);
                        return Ok(0);
                    }
                }
            } else {
                // No H8 owner, no staging: S1 preserved direct,
                // Joint evidence absent for this call. With queued
                // calls, fall back in order first (C4, releases
                // pend until the next ledger contact).
                self.joint_direct_fallback = self.joint_direct_fallback.saturating_add(1);
                let queued = self
                    .instance_state
                    .semantics
                    .get(&id)
                    .expect("retained edge")
                    .feed
                    .staged_len()
                    > 0;
                if queued {
                    fallback_refused = self.fallback_joint_for_order(id, None);
                }
            }
        }
        // S1Only-direct reduction with effects into the shared
        // reducer (no outer consumer: the committed projection
        // carries S1 facts downstream).
        let origin = EffectOrigin::from(&input.facts);
        let state = self
            .instance_state
            .semantics
            .get_mut(&id)
            .expect("retained edge");
        let reducer = state.semantics.as_mut().expect("materialized above");
        let mut outer = NoSink;
        let mut tee = KeyUseTee::new(
            &mut outer,
            &mut self.joint_keyuse,
            id,
            ledger,
            Some(&mut self.assoc_fallback),
        );
        let refused =
            reducer.observe_with_resources_and_effects(&input.facts, &origin, &mut tee)?;
        Ok(fallback_refused.saturating_add(refused))
    }

    /// Ordered fallback for one Joint feed (C4): replay queued calls
    /// S1-direct in original order, degrade to S1Only, decrement the
    /// Joint count. Capture-wide accounting stays active for terminals.
    /// Returns fallback per-edge bound refusals.
    fn fallback_joint_for_order(
        &mut self,
        id: RegistryInstanceId,
        ledger: Option<&mut crate::semantics_objects::journal::StagingLedger>,
    ) -> u64 {
        let mut outer = NoSink;
        let record = self
            .instance_state
            .semantics
            .get_mut(&id)
            .expect("retained edge");
        debug_assert_eq!(record.feed.mode(), FeedMode::Joint);
        let (feed, reducer_slot) = (&mut record.feed, &mut record.semantics);
        let reducer = reducer_slot.as_mut().expect("materialized above");
        let (_, refused) = feed.ordered_fallback(
            reducer,
            &mut self.joint_keyuse,
            id,
            &mut outer,
            ledger,
            Some(&mut self.assoc_fallback),
        );
        debug_assert_eq!(feed.mode(), FeedMode::S1Only);
        self.joint_feeds = self.joint_feeds.saturating_sub(1);
        refused
    }

    fn refuse_instance_resource(
        &mut self,
        id: RegistryInstanceId,
        input: &AdmittedInstanceCall,
        module: ModuleId,
        refusal: crate::semantics_edge::resources::SemanticResourceRefusal,
        shared: Option<&mut crate::semantics_objects::journal::StagingLedger>,
    ) {
        self.instance_state.semantic_refused =
            self.instance_state.semantic_refused.saturating_add(1);
        self.invalidate_instance(
            id,
            Some(input.position.ordinal),
            InstanceReason::SemanticResourceCapacity,
            false,
            shared,
        );
        self.instance_gap(
            Some(input.caller),
            Some(module),
            InstanceReason::SemanticResourceCapacity,
            Some(BudgetRefusal {
                resource: "semantic_resource",
                limit: refusal.limit_bytes,
                requested: refusal.requested_bytes,
            }),
        );
    }

    fn invalidate_instance(
        &mut self,
        id: RegistryInstanceId,
        boundary: Option<u64>,
        reason: InstanceReason,
        retire: bool,
        shared: Option<&mut crate::semantics_objects::journal::StagingLedger>,
    ) {
        // Joint accounting is active for this feed's S1 (same latch
        // as the reduce path): its starts teed, so its loss
        // terminals must tee too — else opens stick active (C5).
        let joint_accounting = self.joint_accounting;
        let state = self
            .instance_state
            .semantics
            .get_mut(&id)
            .expect("retained edge");
        if let Some(boundary) = boundary {
            state.boundary = Some(state.boundary.map_or(boundary, |old| old.max(boundary)));
        }
        state.lossy = true;
        state.reasons.insert(reason);
        // C5: dispose/notify the owned feed in order, before
        // publication, once per payload/terminal. Staged payloads at
        // or below the barrier dispose as history (releases pend: no
        // ledger on this path — the ledger-bearing publish flushes);
        // above-barrier staging stays queued for its seals. Live S1
        // invalidates with terminals teed into shared key-use while
        // Joint accounting is active, else plainly as before.
        // Completed history stands; siblings untouched; repeats
        // no-op (empty staging, no live machines).
        let (feed, reducer_slot) = (&mut state.feed, &mut state.semantics);
        if feed.mode() == FeedMode::Joint {
            feed.dispose_below_barrier(boundary, None);
        }
        if let Some(reducer) = reducer_slot.as_mut() {
            if joint_accounting {
                let mut outer = NoSink;
                let mut tee = KeyUseTee::new(
                    &mut outer,
                    &mut self.joint_keyuse,
                    id,
                    shared,
                    Some(&mut self.assoc_fallback),
                );
                reducer.invalidate_with_effects(&mut tee);
            } else {
                reducer.invalidate();
            }
        }
        let record = self
            .instance_state
            .records
            .get_mut(&id)
            .expect("retained instance");
        if record.state != InstanceLifecycle::Retired {
            record.state = if retire {
                InstanceLifecycle::Retired
            } else {
                InstanceLifecycle::Uncertain
            };
            record.reason = Some(reason);
        }
    }

    fn compact_negative(&self, scope: &InstanceScope) -> NegativeRecord {
        let mut record = NegativeRecord::domain(scope.domain());
        let (image, module, router) = match scope {
            InstanceScope::Domain(_) => return record,
            InstanceScope::Image(_, i) => (*i, None, None),
            InstanceScope::Module(_, i, m) => (*i, self.modules_by_key.get(m).copied(), None),
            InstanceScope::Exact(k) => (
                k.image,
                self.modules_by_key.get(&k.module).copied(),
                Some(k.router),
            ),
        };
        if image.task_cookie == 0 {
            return record;
        }
        record.kind = NegativeKind::Image;
        record.cookie = image.task_cookie;
        record.exec = image.exec_id;
        if let Some(module) = module {
            record.module = module;
            record.kind = NegativeKind::Module;
            if let Some(router) = router {
                record.router = router.get();
                record.kind = NegativeKind::Exact;
            }
        }
        record
    }

    fn retain_negative(
        &mut self,
        input: NegativeRecord,
        mut shared: Option<&mut crate::semantics_objects::journal::StagingLedger>,
    ) -> Option<NegativeRecord> {
        if let Some(old) = self
            .instance_state
            .negatives
            .iter_mut()
            .find(|old| old.same_scope(&input))
        {
            old.barrier = old.barrier.max(input.barrier);
            old.reasons |= input.reasons;
            old.retirement = old.retirement.or(input.retirement);
            old.authority_exhausted |= input.authority_exhausted;
            return Some(*old);
        }
        if self.instance_state.negatives.len() < self.instance_state.negative_limit
            && !self.instance_state.negative_exhausted
        {
            self.instance_state.negatives.push(input);
            return Some(input);
        }
        self.instance_state.negative_refused =
            self.instance_state.negative_refused.saturating_add(1);
        if !self.instance_state.negative_exhausted {
            self.instance_state.negative_exhausted = true;
            let ids: Vec<_> = self.instance_state.records.keys().copied().collect();
            for id in ids {
                self.invalidate_instance(
                    id,
                    None,
                    InstanceReason::NegativeStateCapacity,
                    false,
                    shared.as_deref_mut(),
                );
            }
        }
        self.instance_gap(
            None,
            None,
            InstanceReason::NegativeStateCapacity,
            Some(BudgetRefusal {
                resource: "instance_negative_state",
                limit: self.instance_state.negative_limit,
                requested: self.instance_state.negative_limit + 1,
            }),
        );
        None
    }

    fn apply_negative(
        &mut self,
        negative: NegativeRecord,
        mut shared: Option<&mut crate::semantics_objects::journal::StagingLedger>,
    ) {
        let Some(negative) = self.retain_negative(negative, shared.as_deref_mut()) else {
            return;
        };
        let ids: Vec<_> = self
            .instance_state
            .records
            .values()
            .filter(|r| negative.matches(&r.key, r.module))
            .map(|r| r.id)
            .collect();
        for id in ids {
            let reason = if negative.authority_exhausted {
                InstanceReason::AuthorityExhausted
            } else {
                negative.retirement.unwrap_or(InstanceReason::SemanticLoss)
            };
            let state = &self.instance_state.semantics[&id];
            let advanced =
                negative.barrier != 0 && state.boundary.is_none_or(|old| negative.barrier > old);
            let newly_permanent = (negative.authority_exhausted && !state.authority_exhausted)
                || (negative.retirement.is_some()
                    && self.instance_state.records[&id].state != InstanceLifecycle::Retired);
            // Replaying an already applied fence must not end an operation
            // that began after it. Historical loss disclosure remains sticky.
            if advanced || newly_permanent {
                self.invalidate_instance(
                    id,
                    (negative.barrier != 0).then_some(negative.barrier),
                    reason,
                    negative.retirement.is_some(),
                    shared.as_deref_mut(),
                );
            }
            self.inherit_instance_reasons(id, negative.reasons);
            self.instance_state
                .semantics
                .get_mut(&id)
                .expect("retained edge")
                .authority_exhausted |= negative.authority_exhausted;
        }
    }

    pub(super) fn apply_instance_loss(
        &mut self,
        input: InstanceSemanticLoss,
        shared: Option<&mut crate::semantics_objects::journal::StagingLedger>,
    ) {
        if input
            .position
            .is_some_and(|p| p.domain != input.scope.domain())
        {
            self.instance_gap(None, None, InstanceReason::InstanceUnproven, None);
            return;
        }
        let mut negative = if input.position.is_none() {
            NegativeRecord::domain(input.scope.domain())
        } else {
            self.compact_negative(&input.scope)
        };
        negative.barrier = input.position.map_or(0, |p| p.ordinal);
        negative.reasons = input.reason.bit();
        negative.authority_exhausted =
            input.reason == InstanceReason::AuthorityExhausted || input.position.is_none();
        self.apply_negative(negative, shared);
    }
    pub(super) fn apply_instance_retirement(
        &mut self,
        input: InstanceRetirement,
        shared: Option<&mut crate::semantics_objects::journal::StagingLedger>,
    ) {
        if input.position.domain != input.scope.domain() {
            self.instance_gap(None, None, InstanceReason::InstanceUnproven, None);
            return;
        }
        let mut negative = match &input.scope {
            RetirementScope::Domain(d) => NegativeRecord::domain(*d),
            RetirementScope::Image(d, i) => self.compact_negative(&InstanceScope::Image(*d, *i)),
            RetirementScope::Exact(k) => self.compact_negative(&InstanceScope::Exact(k.clone())),
            RetirementScope::Task(d, c) => {
                let mut r = NegativeRecord::domain(*d);
                r.kind = NegativeKind::Task;
                r.cookie = *c;
                r
            }
        };
        negative.barrier = input.position.ordinal;
        negative.reasons = input.reason.bit();
        negative.retirement = Some(input.reason);
        self.apply_negative(negative, shared);
    }
    pub(super) fn invalidate_physical_instances(
        &mut self,
        caller: CallerId,
        module: Option<ModuleId>,
        retire: bool,
        mut shared: Option<&mut crate::semantics_objects::journal::StagingLedger>,
    ) {
        let ids: Vec<_> = self
            .instance_state
            .records
            .values()
            .filter(|r| r.caller == caller && module.is_none_or(|m| r.module == m))
            .map(|r| r.id)
            .collect();
        for id in ids {
            self.invalidate_instance(
                id,
                None,
                if retire {
                    InstanceReason::InstanceRetired
                } else {
                    InstanceReason::SemanticLoss
                },
                retire,
                shared.as_deref_mut(),
            );
        }
    }

    /// Flush eligible payload and association releases at each shared
    /// ledger contact, before new admissions and before publication.
    pub(super) fn flush_joint_releases(
        &mut self,
        ledger: &mut crate::semantics_objects::journal::StagingLedger,
    ) {
        for record in self.instance_state.semantics.values_mut() {
            record.feed.flush_pending_releases(ledger);
        }
        self.joint_keyuse.flush_pending_shared_releases(ledger);
    }

    #[cfg(test)]
    pub(crate) fn reference_negative_limit(&mut self, limit: usize) {
        self.instance_state.negative_limit = limit.min(MAX_INSTANCE_NEGATIVE_SCOPES);
    }
    #[cfg(test)]
    pub(crate) fn reference_negative_occupied(&self) -> usize {
        self.instance_state.negatives.len()
    }

    #[cfg(test)]
    pub(crate) fn reference_instance_limit(&mut self, limit: usize) {
        self.instance_state.limit = limit.min(MAX_REGISTRY_INSTANCES);
    }
}

// ---- H3 Task 3 production conversion (evidence adapter) ----
//
// The sole positive factory consumes one unique opaque `RoutedCall` into
// one move-only envelope, without cloning it or re-minting from a
// borrowed record. The thin by-value move lands in `CallEvidence`; every
// authority decision below combines the coordinator's caller binding, the
// attested subset's descriptor proof and the lane's validated coverage.
// Ordinals are H0-timeline evidence, never caller-selected authority.

/// Owned decomposed call evidence: the thin by-value move out of a unique
/// `RoutedCall`. Production builds it only by consuming the call
/// (exactly-once); tests script equivalent evidence directly.
pub(crate) struct CallEvidence {
    domain: NativeDomainId,
    image: ImageIdentity,
    token: u64,
    router: InstanceId,
    endpoint: Option<Endpoint>,
    event: Event,
    /// Slice D: the private validated object tail moved out of the owned
    /// routed call. No raw-value Debug: the redacted `Debug` below stays.
    object: Option<ValidatedObjectCall>,
}

impl std::fmt::Debug for CallEvidence {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("CallEvidence(<private>)")
    }
}

impl CallEvidence {
    /// Consume the unique call. `None` unless the call joined an instance
    /// with a timeline token; pending and unknown routes convert nothing.
    pub(crate) fn from_routed(call: RoutedCall) -> Option<Self> {
        let Route::Joined(router) = call.route() else {
            return None;
        };
        let token = call.token()?;
        let domain = call.domain();
        let image = call.image();
        let endpoint = call.endpoint();
        let event = call.record().event;
        let object = call.into_object_tail();
        Some(Self {
            domain,
            image,
            token,
            router,
            endpoint,
            event,
            object,
        })
    }

    /// Tests-only observation of the moved tail: production reads it only
    /// through the consuming admission in this module.
    #[cfg(test)]
    pub(crate) fn object_tail(&self) -> Option<&ValidatedObjectCall> {
        self.object.as_ref()
    }

    #[cfg(test)]
    pub(crate) fn scripted(
        domain: NativeDomainId,
        image: ImageIdentity,
        token: u64,
        router: InstanceId,
        endpoint: Option<Endpoint>,
        event: Event,
    ) -> Self {
        Self {
            domain,
            image,
            token,
            router,
            endpoint,
            event,
            object: None,
        }
    }

    /// Binding lookup and position ordering read these; conversion still
    /// consumes the whole owned evidence.
    pub(crate) fn domain(&self) -> NativeDomainId {
        self.domain
    }

    pub(crate) fn image(&self) -> ImageIdentity {
        self.image
    }

    pub(crate) fn token(&self) -> u64 {
        self.token
    }

    pub(crate) fn router(&self) -> InstanceId {
        self.router
    }
}

/// Reduction standing for one call: a validated current-partition proof
/// or a finite historical-only reason.
pub(crate) enum CallStanding<'a> {
    Current(&'a LaneCoverage),
    Historical(InstanceReason),
}

/// Finite conversion refusal: the finalizer records it through the
/// audited path and stages no envelope for the input.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum ConversionRefusal {
    Domain,
    Custody,
    Slot,
    Coverage,
    Position,
    Module,
}

impl ConversionRefusal {
    pub(crate) const fn code(self) -> &'static str {
        match self {
            Self::Domain => "domain",
            Self::Custody => "custody",
            Self::Slot => "slot",
            Self::Coverage => "coverage",
            Self::Position => "position",
            Self::Module => "module",
        }
    }
}

/// Slice D: bind one validated tail to its attested slot name. Only a
/// tail whose descriptor is the slot function's ordinal + 1 survives;
/// anything else (including unknown names) drops the tail while the
/// base call is unaffected.
fn bound_object_tail(
    slot_name: &str,
    tail: Option<ValidatedObjectCall>,
) -> Option<ValidatedObjectCall> {
    match tail {
        Some(tail) => {
            let bound = crate::kinds::function_id(slot_name)
                .is_some_and(|id| tail.descriptor_index() == id + 1);
            bound.then_some(tail)
        }
        None => None,
    }
}

/// Convert one owned call: assemble the full key from proofs, decode the
/// verbatim record facts, and decide current versus historical-only
/// reduction. `barrier` is the narrowest staged loss ordinal covering
/// this scope in the same publication, if any: a call at or before it is
/// historical even with a validated current proof. No legacy physical
/// reduction happens here; the legacy reducer is never touched.
pub(crate) fn admit_call_from_evidence(
    evidence: CallEvidence,
    binding: &SemanticCallerBinding,
    subset: &AttestedSubset,
    standing: CallStanding<'_>,
    barrier: Option<u64>,
) -> Result<AdmittedInstanceCall, ConversionRefusal> {
    if evidence.domain != binding.domain() {
        return Err(ConversionRefusal::Domain);
    }
    if evidence.image != binding.image() {
        return Err(ConversionRefusal::Custody);
    }
    if evidence.token == 0 {
        return Err(ConversionRefusal::Position);
    }
    let module = binding.module();
    if matches!(module, ModuleKey::Unidentified { .. }) {
        return Err(ConversionRefusal::Module);
    }
    let endpoint = evidence.endpoint.ok_or(ConversionRefusal::Slot)?;
    let plan = subset.plan();
    let slot = plan
        .slots
        .iter()
        .find(|slot| slot.index == evidence.event.slot)
        .ok_or(ConversionRefusal::Slot)?;
    if slot.object != endpoint.object || slot.file_offset != endpoint.offset {
        return Err(ConversionRefusal::Slot);
    }
    if !subset.proves_provider_module(endpoint.object, module) || !binding.proves_endpoint(endpoint)
    {
        return Err(ConversionRefusal::Module);
    }
    // Descriptor authority comes only from the attested plan: one
    // canonical operator-attested name, unambiguous, never count-only.
    // The flags below are derived from these checks, never selected.
    if !slot.semantic_authorized
        || slot.aliased
        || slot.semantic_ambiguous
        || slot.names.len() != 1
        || plan.effective_semantics(slot) == SlotSemantics::COUNT_ONLY
    {
        return Err(ConversionRefusal::Slot);
    }
    // Slice D: the tail's descriptor must be the attested slot's
    // descriptor (function ordinal + 1). A validated tail bound to the
    // wrong descriptor is dropped: the base call is unaffected, and no
    // misattributed object fact enters the admission result.
    let object = bound_object_tail(&slot.names[0], evidence.object);
    let permission = match standing {
        CallStanding::Historical(reason) => ReductionPermission::HistoricalOnly(reason),
        CallStanding::Current(coverage) => {
            // Partition granularity: the coverage proves the watched file
            // (slot and object) and the instance set current; functions
            // on other endpoints of the same file share it, while their
            // own descriptor authority comes from the slot proof above.
            let covered = coverage.endpoint();
            if !binding.scope_current()
                || coverage.domain() != evidence.domain
                || coverage.image() != evidence.image
                || covered.file_slot != endpoint.file_slot
                || covered.object != endpoint.object
                || !coverage.instances().contains(&evidence.router)
            {
                return Err(ConversionRefusal::Coverage);
            }
            if barrier.is_some_and(|at| evidence.token <= at) {
                ReductionPermission::HistoricalOnly(InstanceReason::BeforeSemanticBoundary)
            } else {
                ReductionPermission::CurrentContinuity
            }
        }
    };
    Ok(AdmittedInstanceCall {
        key: InstanceKey {
            domain: evidence.domain,
            image: evidence.image,
            router: evidence.router,
            module: module.clone(),
        },
        caller: binding.caller(),
        position: SemanticPosition {
            domain: evidence.domain,
            ordinal: evidence.token,
        },
        facts: SemanticCall {
            function: slot.names[0].clone(),
            rv: evidence.event.rv,
            session: evidence.event.session,
            mechanism: evidence.event.mechanism,
            capture: evidence.event.capture,
            slot_id: evidence.event.slot_id,
            target_function: evidence.event.target_function,
            async_value: evidence.event.async_value,
            flags: evidence.event.flags,
            user_type: evidence.event.user_type,
            authorized: true,
            unambiguous: true,
            count_only: false,
            attributable: true,
            ts_ns: evidence.event.ts_ns,
        },
        permission,
        journal_invocation: JournalInvocationIdentity::from_event(&evidence.event),
        object,
    })
}

/// Register one exact instance from validated coverage: `router` names one
/// id carried by the coverage itself (re-checked here, never free-chosen).
/// `boundary` inherits the staged barrier ordinal for this scope, if any;
/// `observed_ns` is the batch stamp, non-authority metadata.
pub(crate) fn admit_registration_from_coverage(
    coverage: &LaneCoverage,
    binding: &SemanticCallerBinding,
    subset: &AttestedSubset,
    router: InstanceId,
    observed_ns: u64,
    boundary: Option<u64>,
) -> Result<AdmittedInstance, ConversionRefusal> {
    if coverage.domain() != binding.domain() {
        return Err(ConversionRefusal::Domain);
    }
    if coverage.image() != binding.image() {
        return Err(ConversionRefusal::Custody);
    }
    if !coverage.instances().contains(&router) {
        return Err(ConversionRefusal::Coverage);
    }
    let module = binding.module();
    if !binding.scope_current()
        || !subset.proves_provider_module(coverage.endpoint().object, module)
        || !binding.proves_endpoint(coverage.endpoint())
    {
        return Err(ConversionRefusal::Module);
    }
    let boundary = match boundary {
        None => None,
        Some(0) => return Err(ConversionRefusal::Position),
        Some(ordinal) => Some(SemanticPosition {
            domain: coverage.domain(),
            ordinal,
        }),
    };
    Ok(AdmittedInstance {
        key: InstanceKey {
            domain: coverage.domain(),
            image: coverage.image(),
            router,
            module: module.clone(),
        },
        caller: binding.caller(),
        observed_ns,
        boundary,
    })
}

/// Convert one lane negative into the domain loss it proves, if it proves
/// one: a cut barrier becomes the domain loss at its ordinal, while a
/// refused collection is `None` (the finalizer records it through the
/// audited path instead of staging H2 loss).
pub(crate) fn tail_loss_from_negative(
    domain: NativeDomainId,
    negative: &LaneNegative,
) -> Option<Result<InstanceSemanticLoss, ConversionRefusal>> {
    match *negative {
        LaneNegative::CollectionRefused { .. } => None,
        LaneNegative::CutBarrier { ordinal } => {
            if ordinal == 0 {
                return Some(Err(ConversionRefusal::Position));
            }
            Some(Ok(InstanceSemanticLoss {
                scope: InstanceScope::Domain(domain),
                position: Some(SemanticPosition { domain, ordinal }),
                reason: InstanceReason::SemanticLoss,
            }))
        }
    }
}

/// Convert one H0 invalidation into staged losses and exact retirements.
/// Scopes stay as narrow as the proofs allow and widen only within the
/// domain. A superseded partition retires its exact prior ids only when a
/// validated same-batch coverage proves the fresh disjoint partition;
/// otherwise the invalidation is loss, never a silent revival. A missing
/// position (exhaustion) dominates every scope: the domain loss carries no
/// ordinal and persists permanent domain authority refusal.
pub(crate) fn finalize_invalidation(
    scope: &InvalidationScope,
    position: Option<u64>,
    domain: NativeDomainId,
    binding: Option<&SemanticCallerBinding>,
    fresh: &[LaneCoverage],
) -> Result<(Vec<InstanceSemanticLoss>, Vec<InstanceRetirement>), ConversionRefusal> {
    let Some(ordinal) = position else {
        return Ok((
            vec![InstanceSemanticLoss {
                scope: InstanceScope::Domain(domain),
                position: None,
                reason: InstanceReason::AuthorityExhausted,
            }],
            Vec::new(),
        ));
    };
    if ordinal == 0 {
        return Err(ConversionRefusal::Position);
    }
    let at = SemanticPosition { domain, ordinal };
    let loss = |scope: InstanceScope, reason: InstanceReason| InstanceSemanticLoss {
        scope,
        position: Some(at),
        reason,
    };
    let bound_image = binding
        .filter(|proof| proof.domain() == domain)
        .map(|proof| (proof.image(), proof.module().clone()));
    match scope {
        InvalidationScope::CoverageFailed => Ok((
            vec![loss(
                InstanceScope::Domain(domain),
                InstanceReason::SemanticLoss,
            )],
            Vec::new(),
        )),
        InvalidationScope::AuthorityExhausted => Ok((
            vec![loss(
                InstanceScope::Domain(domain),
                InstanceReason::AuthorityExhausted,
            )],
            Vec::new(),
        )),
        InvalidationScope::FaultEra => Ok((
            vec![loss(
                InstanceScope::Domain(domain),
                InstanceReason::SemanticLoss,
            )],
            Vec::new(),
        )),
        InvalidationScope::Stopped => Ok((
            vec![loss(
                InstanceScope::Domain(domain),
                InstanceReason::CaptureStopped,
            )],
            Vec::new(),
        )),
        InvalidationScope::TaskRetired(cookie) => Ok((
            Vec::new(),
            vec![InstanceRetirement {
                scope: RetirementScope::Task(domain, *cookie),
                position: at,
                reason: InstanceReason::TaskRetired,
            }],
        )),
        InvalidationScope::ImageRetired(image) => Ok((
            vec![loss(
                InstanceScope::Image(domain, *image),
                InstanceReason::ImageRetired,
            )],
            Vec::new(),
        )),
        InvalidationScope::File { image, .. } => {
            let scope = match &bound_image {
                Some((bound, module)) if *bound == *image => {
                    InstanceScope::Module(domain, *image, module.clone())
                }
                _ => InstanceScope::Image(domain, *image),
            };
            Ok((vec![loss(scope, InstanceReason::SemanticLoss)], Vec::new()))
        }
        InvalidationScope::InstancesRetired {
            image,
            file_slot,
            ids,
        } => {
            let fresh_partition = fresh.iter().any(|coverage| {
                coverage.domain() == domain
                    && coverage.image() == *image
                    && coverage.endpoint().file_slot == *file_slot
                    && !coverage.instances().is_empty()
                    && coverage.instances().iter().all(|id| !ids.contains(id))
            });
            match (&bound_image, fresh_partition) {
                (Some((bound, module)), true) if *bound == *image => {
                    let retirements = ids
                        .iter()
                        .map(|id| InstanceRetirement {
                            scope: RetirementScope::Exact(InstanceKey {
                                domain,
                                image: *image,
                                router: *id,
                                module: module.clone(),
                            }),
                            position: at,
                            reason: InstanceReason::InstanceRetired,
                        })
                        .collect();
                    Ok((Vec::new(), retirements))
                }
                (Some((bound, module)), _) if *bound == *image => {
                    let losses = ids
                        .iter()
                        .map(|id| {
                            loss(
                                InstanceScope::Exact(InstanceKey {
                                    domain,
                                    image: *image,
                                    router: *id,
                                    module: module.clone(),
                                }),
                                InstanceReason::SemanticLoss,
                            )
                        })
                        .collect();
                    Ok((losses, Vec::new()))
                }
                _ => Ok((
                    vec![loss(
                        InstanceScope::Image(domain, *image),
                        InstanceReason::SemanticLoss,
                    )],
                    Vec::new(),
                )),
            }
        }
    }
}

#[cfg(test)]
pub(crate) use reference::*;

#[cfg(test)]
mod reference {
    use super::*;
    pub(crate) fn key(
        domain: NativeDomainId,
        image: ImageIdentity,
        router: InstanceId,
        module: ModuleKey,
    ) -> InstanceKey {
        InstanceKey {
            domain,
            image,
            router,
            module,
        }
    }
    pub(crate) fn position(domain: NativeDomainId, ordinal: u64) -> SemanticPosition {
        assert!(ordinal > 0);
        SemanticPosition { domain, ordinal }
    }
    pub(crate) fn registration(
        key: InstanceKey,
        caller: CallerId,
        observed_ns: u64,
        boundary: Option<SemanticPosition>,
    ) -> AdmittedInstance {
        AdmittedInstance {
            key,
            caller,
            observed_ns,
            boundary,
        }
    }
    pub(crate) fn call(
        key: InstanceKey,
        caller: CallerId,
        position: SemanticPosition,
        facts: SemanticCall,
        historical: Option<InstanceReason>,
    ) -> AdmittedInstanceCall {
        AdmittedInstanceCall {
            key,
            caller,
            position,
            facts,
            permission: historical.map_or(
                ReductionPermission::CurrentContinuity,
                ReductionPermission::HistoricalOnly,
            ),
            journal_invocation: None,
            object: None,
        }
    }
    pub(crate) enum Scope {
        Domain(NativeDomainId),
        Image(NativeDomainId, ImageIdentity),
        Module(NativeDomainId, ImageIdentity, ModuleKey),
        Exact(InstanceKey),
    }
    fn scope(value: Scope) -> InstanceScope {
        match value {
            Scope::Domain(d) => InstanceScope::Domain(d),
            Scope::Image(d, i) => InstanceScope::Image(d, i),
            Scope::Module(d, i, m) => InstanceScope::Module(d, i, m),
            Scope::Exact(k) => InstanceScope::Exact(k),
        }
    }
    pub(crate) fn loss(
        value: Scope,
        position: SemanticPosition,
        reason: InstanceReason,
    ) -> InstanceSemanticLoss {
        InstanceSemanticLoss {
            scope: scope(value),
            position: Some(position),
            reason,
        }
    }
    pub(crate) enum Retirement {
        Domain(NativeDomainId),
        Image(NativeDomainId, ImageIdentity),
        Exact(InstanceKey),
        Task(NativeDomainId, u64),
    }
    pub(crate) fn exhausted_domain(domain: NativeDomainId) -> InstanceSemanticLoss {
        InstanceSemanticLoss {
            scope: InstanceScope::Domain(domain),
            position: None,
            reason: InstanceReason::AuthorityExhausted,
        }
    }
    pub(crate) fn negative_payload_debug(
        domain: NativeDomainId,
        image: ImageIdentity,
    ) -> (usize, bool, String) {
        let record = NegativeRecord {
            domain,
            cookie: image.task_cookie,
            exec: image.exec_id,
            router: 0,
            module: ModuleId(0),
            barrier: 0,
            reasons: 0,
            kind: NegativeKind::Image,
            retirement: None,
            authority_exhausted: false,
        };
        (
            std::mem::size_of::<NegativeRecord>(),
            std::mem::needs_drop::<NegativeRecord>(),
            format!("{record:?}"),
        )
    }
    pub(crate) fn retirement(
        value: Retirement,
        position: SemanticPosition,
        reason: InstanceReason,
    ) -> InstanceRetirement {
        InstanceRetirement {
            scope: match value {
                Retirement::Domain(d) => RetirementScope::Domain(d),
                Retirement::Image(d, i) => RetirementScope::Image(d, i),
                Retirement::Exact(k) => RetirementScope::Exact(k),
                Retirement::Task(d, c) => RetirementScope::Task(d, c),
            },
            position,
            reason,
        }
    }
}

#[cfg(test)]
mod object_tail_binding_tests {
    use super::*;
    use p11scope_ebpf_common::object_wire::{
        OBJECT_ACTION_CREATE, OBJECT_CALL_BYTES, OBJECT_CALL_VERSION, OBJECT_LAYOUT_LP64,
        OBJECT_TAIL_BYTES, publish_object_descriptors,
    };

    fn create_tail() -> ValidatedObjectCall {
        let table = publish_object_descriptors();
        let mut tail = [0u8; OBJECT_TAIL_BYTES];
        tail[0..2].copy_from_slice(&OBJECT_CALL_VERSION.to_le_bytes());
        tail[2..4].copy_from_slice(&OBJECT_CALL_BYTES.to_le_bytes());
        tail[4..8].copy_from_slice(&21u32.to_le_bytes());
        tail[12] = OBJECT_LAYOUT_LP64;
        tail[13] = OBJECT_ACTION_CREATE;
        tail[32..40].copy_from_slice(&0x1234u64.to_le_bytes());
        tail[114] = 1;
        ValidatedObjectCall::validate(&tail, &table[21]).expect("scripted tail validates")
    }

    #[test]
    fn object_producer_admission_binds_tail_to_attested_descriptor() {
        let tail = create_tail();
        assert_eq!(tail.descriptor_index(), 21);
        // The attested Create slot keeps its exact tail bytes.
        let kept = bound_object_tail("C_CreateObject", Some(tail)).expect("matching tail survives");
        assert_eq!(kept.tail_bytes(), tail.tail_bytes());
        // Any other slot (or none) drops the tail; the base call still
        // admits through the unchanged path.
        assert!(bound_object_tail("C_DestroyObject", Some(tail)).is_none());
        assert!(bound_object_tail("C_NoSuchFunction", Some(tail)).is_none());
        assert!(bound_object_tail("C_CreateObject", None).is_none());
    }
}
