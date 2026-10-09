//! SPDX-License-Identifier: GPL-3.0-or-later
//! Sealed H2 consumer inputs. H3 must consume runtime proofs here; these
//! reference builders never exist in a production build.
#![cfg_attr(not(test), allow(dead_code))]

use super::{
    BudgetRefusal, CallerId, CallerRegistry, MappingState, ModuleId, ModuleKey, Mutation,
    RegistryGap,
};
use crate::attach::capture::NativeDomainId;
use crate::discovery::instances::InstanceId;
use crate::semantics_edge::{EdgeSemantics, SemanticCall};
use p11scope_ebpf_common::ImageIdentity;
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

impl fmt::Debug for InstanceKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("InstanceKey(<private>)")
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub(crate) struct RegistryInstanceId(u32);

impl RegistryInstanceId {
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

#[derive(Debug)]
pub(crate) struct AdmittedInstanceCall {
    key: InstanceKey,
    caller: CallerId,
    position: SemanticPosition,
    facts: SemanticCall,
    permission: ReductionPermission,
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

    pub(super) fn apply_instance(&mut self, input: AdmittedInstance) {
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
                self.invalidate_instance(id, boundary, InstanceReason::SemanticLoss, false);
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
                self.invalidate_instance(id, None, InstanceReason::AuthorityExhausted, false);
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
            },
        );
        if boundary.is_some() {
            self.invalidate_instance(id, boundary, InstanceReason::SemanticLoss, false);
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

    pub(super) fn apply_instance_call(&mut self, input: AdmittedInstanceCall) {
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
            self.invalidate_instance(id, Some(input.position.ordinal), reason, false);
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
                    self.refuse_instance_resource(id, &input, module, refusal);
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
        let state = self
            .instance_state
            .semantics
            .get_mut(&id)
            .expect("retained edge");
        let refused = state
            .semantics
            .as_mut()
            .expect("materialized above")
            .observe_with_resources(&input.facts);
        let refused = match refused {
            Ok(refused) => refused,
            Err(refusal) => {
                self.refuse_instance_resource(id, &input, module, refusal);
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

    fn refuse_instance_resource(
        &mut self,
        id: RegistryInstanceId,
        input: &AdmittedInstanceCall,
        module: ModuleId,
        refusal: crate::semantics_edge::resources::SemanticResourceRefusal,
    ) {
        self.instance_state.semantic_refused =
            self.instance_state.semantic_refused.saturating_add(1);
        self.invalidate_instance(
            id,
            Some(input.position.ordinal),
            InstanceReason::SemanticResourceCapacity,
            false,
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
    ) {
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
        if let Some(reducer) = state.semantics.as_mut() {
            reducer.invalidate();
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

    fn retain_negative(&mut self, input: NegativeRecord) -> Option<NegativeRecord> {
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
                self.invalidate_instance(id, None, InstanceReason::NegativeStateCapacity, false);
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

    fn apply_negative(&mut self, negative: NegativeRecord) {
        let Some(negative) = self.retain_negative(negative) else {
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

    pub(super) fn apply_instance_loss(&mut self, input: InstanceSemanticLoss) {
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
        self.apply_negative(negative);
    }
    pub(super) fn apply_instance_retirement(&mut self, input: InstanceRetirement) {
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
        self.apply_negative(negative);
    }
    pub(super) fn invalidate_physical_instances(
        &mut self,
        caller: CallerId,
        module: Option<ModuleId>,
        retire: bool,
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
            );
        }
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
