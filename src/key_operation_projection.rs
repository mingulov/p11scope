//! SPDX-License-Identifier: GPL-3.0-or-later
//! H9 operation/key delivery and presentation: the ONE immutable
//! projection and its three consumers' shared contract.
//!
//! [`ObjectObservations`] is the frozen `object_observations`
//! section (version 1) of `p11scope/inventory/v1`: status, sessions,
//! objects, proved-key aggregates, unknown-key summaries, gaps and
//! budgets. JSON, JSONL and the dashboard render from this type
//! only — never from live reducers, friendly labels or raw tails.
//! The frozen consumer contract is
//! `docs/schema/inventory-v1-object-observations.schema.json`; the
//! hand-reviewed populated example is
//! `tests/fixtures/key-operations/object-observations.json`.
//!
//! The producer mapping ([`producer::commit`]) is staged behind the
//! live-loop carry (test-gated): production owns no Joint evidence
//! yet, so production captures [`ObjectObservations::unavailable`]
//! with a finite reason. The publisher, the renderers and the frozen
//! key/enum tables ship ungated: they process unavailable sections
//! today and populated ones once the driver lands.

/// Frozen retained key-operation row bound (H9 §91): history is
/// never evicted; N+1 refuses with PARTIAL coverage. Lives here
/// (ungated) so production budgets name the same bound the staged
/// reducer enforces.
pub(crate) const KEY_OP_ROW_CAPACITY: usize = 65_536;

/// Frozen section version. Consumers reject unknown versions.
pub(crate) const OBSERVATIONS_VERSION: u8 = 1;

/// Frozen machine reasons. `none` only when populated.
pub(crate) const REASON_LABELS: [&str; 8] = [
    "none",
    "bootstrap_unavailable",
    "proof_refused_fallback",
    "authority_lost",
    "row_budget_exhausted",
    "publication_budget_exhausted",
    "serialization_refused",
    "sink_failed",
];

/// Frozen contract tables for the exact-key/enum tests: the Rust
/// mirror of the schema file. Test-gated (the schema file is the
/// production contract artifact); the contract test pins these
/// tables key-for-key against the schema and the golden.
#[cfg(test)]
pub(crate) mod contract {
    /// Frozen top-level section keys, in contract order.
    pub(crate) const SECTION_KEYS: [&str; 10] = [
        "version",
        "revision",
        "status",
        "reason",
        "sessions",
        "objects",
        "key_operations",
        "unknown_key_operations",
        "gaps",
        "budgets",
    ];

    /// Frozen publication statuses (H9 §76).
    pub(crate) const STATUS_LABELS: [&str; 4] = ["populated", "partial", "stale", "unavailable"];

    pub(crate) const SESSION_ROW_KEYS: [&str; 3] = ["session", "origin", "status"];
    pub(crate) const SESSION_ORIGINS: [&str; 2] = ["opened", "first_observed"];
    pub(crate) const SESSION_STATUSES: [&str; 3] = ["live", "closed", "lost"];

    pub(crate) const OBJECT_ROW_KEYS: [&str; 16] = [
        "object",
        "session",
        "origin",
        "creation",
        "birth",
        "lifetime",
        "lifetime_reason",
        "attribution",
        "attribution_reason",
        "requested",
        "established",
        "queries",
        "label",
        "successful_references",
        "successful_key_references",
        "accessing_sessions",
    ];
    pub(crate) const OBJECT_ORIGINS: [&str; 2] = ["created", "first_observed"];
    pub(crate) const CREATION_LABELS: [&str; 6] = [
        "create",
        "copy",
        "generate",
        "generate_pair",
        "derive",
        "unwrap",
    ];
    pub(crate) const BIRTH_KEYS: [&str; 2] = ["start_ns", "end_ns"];
    pub(crate) const LIFETIME_LABELS: [&str; 4] = ["live", "destroyed", "access_ended", "retired"];
    pub(crate) const ATTRIBUTION_LABELS: [&str; 2] = ["valid", "downgraded"];

    pub(crate) const METADATA_KEYS: [&str; 6] = [
        "class",
        "key_type",
        "token",
        "value_len",
        "modulus_bits",
        "ec_params",
    ];
    pub(crate) const FIELD_KEYS: [&str; 2] = ["status", "value"];
    pub(crate) const FIELD_STATUSES: [&str; 4] = ["unknown", "value", "conflict", "invalidated"];
    pub(crate) const QUERY_STATUSES: [&str; 7] = [
        "not_queried",
        "established",
        "unavailable",
        "size_only",
        "unsupported",
        "malformed",
        "excluded",
    ];
    pub(crate) const CURVE_LABELS: [&str; 3] = ["secp256r1", "secp384r1", "secp521r1"];

    /// Frozen metadata-at-use labels: established RSA modulus bits, AES
    /// value length in bits, EC finite curve. Requested-only sizes never
    /// label.
    pub(crate) const METADATA_LABELS: [&str; 12] = [
        "rsa_1024",
        "rsa_2048",
        "rsa_3072",
        "rsa_4096",
        "rsa_other",
        "aes_128",
        "aes_192",
        "aes_256",
        "aes_other",
        "ec_p256",
        "ec_p384",
        "ec_p521",
    ];

    /// Frozen operation categories: 11 machine operations, 9 direct
    /// operations, and the `operation` / `direct` / `unknown` fallbacks.
    pub(crate) const CATEGORY_LABELS: [&str; 23] = [
        "digest",
        "sign",
        "verify",
        "encrypt",
        "decrypt",
        "sign_recover",
        "verify_recover",
        "message_encrypt",
        "message_decrypt",
        "message_sign",
        "message_verify",
        "generate_key",
        "generate_key_pair",
        "wrap",
        "unwrap",
        "derive",
        "encapsulate",
        "decapsulate",
        "wrap_authenticated",
        "unwrap_authenticated",
        "operation",
        "direct",
        "unknown",
    ];

    /// Frozen key roles. `wrapped_object` is secondary (H9 §82).
    pub(crate) const ROLE_LABELS: [&str; 6] = [
        "key",
        "wrapping_key",
        "wrapped_object",
        "unwrapping_key",
        "base_key",
        "other",
    ];

    pub(crate) const UNIT_LABELS: [&str; 2] = ["operations", "message_contexts"];

    pub(crate) const KEY_ROW_KEYS: [&str; 13] = [
        "instance",
        "object",
        "category",
        "role",
        "metadata_at_use",
        "unit",
        "started",
        "completed",
        "failed",
        "cancelled",
        "unknown",
        "active",
        "key_join_lost",
    ];

    /// Frozen unknown-key reasons (H9 §82).
    pub(crate) const UNKNOWN_REASONS: [&str; 6] = [
        "unbound",
        "key_join_lost",
        "metadata_unknown",
        "metadata_conflicting",
        "role_unavailable",
        "not_applicable",
    ];

    pub(crate) const UNKNOWN_ROW_KEYS: [&str; 8] = [
        "category",
        "reason",
        "unit",
        "completed",
        "failed",
        "cancelled",
        "unknown",
        "active",
    ];

    pub(crate) const GAP_KEYS: [&str; 2] = ["rows", "suppressed"];
    pub(crate) const GAP_ROW_KEYS: [&str; 3] = ["subject", "reason", "repeats"];
    pub(crate) const GAP_SUBJECTS: [&str; 2] = ["model", "key_operation"];

    /// Frozen gap reasons: the 51 model-gap snakes plus the one key-side
    /// reason. The producer test enumerates every model variant into
    /// this set, so the map cannot drift from the list.
    pub(crate) const GAP_REASONS: [&str; 52] = [
        "bootstrap_unproven",
        "bootstrap_refused",
        "prefix_contradiction",
        "stale_prefix",
        "closed_frontier",
        "duplicate_call",
        "duplicate_completion",
        "stale_token",
        "fenced_completion",
        "malformed_fact",
        "unsupported_function",
        "domain_ended",
        "result_protocol_unavailable",
        "pending_result_unavailable",
        "output_unreadable",
        "pair_duplicate",
        "null_mechanism_cancel",
        "same_session_overlap",
        "overlap_uncertain",
        "output_collision",
        "stale_origin",
        "dependency_broken",
        "unproven_input",
        "unproven_session",
        "metadata_uncertain",
        "destroy_alias",
        "close_uncertain",
        "close_all_uncertain",
        "logout_uncertain",
        "session_closed",
        "invalid_handle",
        "ambiguous_outcome",
        "session_contradiction",
        "handle_reuse",
        "finalize",
        "token_reset",
        "exec",
        "fork",
        "unload",
        "loss",
        "pending_capacity",
        "session_capacity",
        "object_capacity",
        "instance_capacity",
        "id_exhausted",
        "device_loss",
        "unseen_finalize",
        "inconsistent_mechanism",
        "outcome_lost",
        "unknown_domain",
        "domain_pruned",
        "pruned_object_referenced",
    ];

    pub(crate) const BUDGET_KEYS: [&str; 6] = [
        "key_rows",
        "object_rows",
        "unknown_rows",
        "encoded_bytes",
        "allocation_refused",
        "refusal_reason",
    ];
    pub(crate) const ROW_BUDGET_KEYS: [&str; 3] = ["limit", "occupied", "refused"];
    pub(crate) const UNKNOWN_BUDGET_KEYS: [&str; 1] = ["occupied"];

    /// Gap rows carried per publication before `suppressed` counts.
    pub(crate) const GAPS_CAPACITY: usize = 256;
}

/// Publication status: object authority, never S1 health.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum ObsStatus {
    // Live-loop carry (T4): constructed only by the staged commit;
    // ungate (drop these allows) with its driver.
    #[allow(dead_code)]
    Populated,
    #[allow(dead_code)]
    Partial,
    Stale,
    Unavailable,
}

impl ObsStatus {
    pub(crate) const fn label(self) -> &'static str {
        match self {
            Self::Populated => "populated",
            Self::Partial => "partial",
            Self::Stale => "stale",
            Self::Unavailable => "unavailable",
        }
    }
}

/// One metadata field: frozen status plus the retained observation
/// (u16 scalar or finite curve name — never key material). Exactly
/// one of `scalar` / `curve` applies per field kind.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct MetadataField {
    pub status: &'static str,
    pub scalar: Option<u16>,
    pub curve: Option<&'static str>,
}

/// The six fixed metadata slots, requested or established.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct MetadataBlock {
    pub class: MetadataField,
    pub key_type: MetadataField,
    pub token: MetadataField,
    pub value_len: MetadataField,
    pub modulus_bits: MetadataField,
    pub ec_params: MetadataField,
}

/// One query outcome per field (latest status, not validity).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct QueriesBlock {
    pub class: &'static str,
    pub key_type: &'static str,
    pub token: &'static str,
    pub value_len: &'static str,
    pub modulus_bits: &'static str,
    pub ec_params: &'static str,
}

/// One session row: public id, origin, status. No instance: the
/// model is capture-wide; instance attribution lives on key rows.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct SessionRow {
    pub session: u64,
    pub origin: &'static str,
    pub status: &'static str,
}

/// One object row: origin, birth interval, lifetime, attribution,
/// requested/established metadata with statuses, and explicitly
/// named successful-reference counters — never distinct keys,
/// completed operations or physical token inventory.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct ObjectRow {
    pub object: u64,
    pub session: u64,
    pub origin: &'static str,
    pub creation: Option<&'static str>,
    pub birth: Option<(u64, u64)>,
    pub lifetime: &'static str,
    pub lifetime_reason: Option<&'static str>,
    pub attribution: &'static str,
    pub attribution_reason: Option<&'static str>,
    pub requested: MetadataBlock,
    pub established: MetadataBlock,
    pub queries: QueriesBlock,
    pub label: Option<&'static str>,
    pub successful_references: u64,
    pub successful_key_references: u64,
    pub accessing_sessions: u64,
}

/// One proved-key aggregate row: associations for one
/// (instance, object, category, role, metadata_at_use) key. Role
/// rows count associations; the equation
/// `started = completed + failed + cancelled + unknown + active +
/// key_join_lost` holds per row before counter saturation.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct KeyAggRow {
    pub instance: String,
    pub object: u64,
    pub category: &'static str,
    pub role: &'static str,
    pub metadata_at_use: &'static str,
    pub unit: &'static str,
    pub started: u64,
    pub completed: u64,
    pub failed: u64,
    pub cancelled: u64,
    pub unknown: u64,
    pub active: u64,
    pub key_join_lost: u64,
}

/// One capture-wide unknown-key summary row: terminals partitioned
/// here once per primary operation role. Starts are never
/// fabricated into the unknown bucket: there is no `started`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct UnknownAggRow {
    pub category: &'static str,
    pub reason: &'static str,
    pub unit: &'static str,
    pub completed: u64,
    pub failed: u64,
    pub cancelled: u64,
    pub unknown: u64,
    pub active: u64,
}

/// One gap row: model loss facts plus key-side scope facts.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct GapRow {
    pub subject: &'static str,
    pub reason: &'static str,
    pub repeats: u64,
}

/// Publication budgets: row/cardinality counters plus the measured
/// encoding size. Pool fields stay false/none until a reviewed pool
/// ships with a schema update.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct ObsBudgets {
    pub key_limit: usize,
    pub key_occupied: usize,
    pub key_refused: u64,
    pub object_limit: usize,
    pub object_occupied: usize,
    pub object_refused: u64,
    pub unknown_occupied: usize,
    pub encoded_bytes: usize,
}

/// The ONE immutable key-operation projection: owned, sorted,
/// revision-tagged. Built by [`producer::commit`] (staged) or
/// [`Self::unavailable`] (production today); every consumer reads
/// only this.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct ObjectObservations {
    pub revision: u64,
    pub status: ObsStatus,
    pub reason: &'static str,
    pub sessions: Vec<SessionRow>,
    pub objects: Vec<ObjectRow>,
    pub key_operations: Vec<KeyAggRow>,
    pub unknown_key_operations: Vec<UnknownAggRow>,
    pub gaps: Vec<GapRow>,
    pub gaps_suppressed: u64,
    pub budgets: ObsBudgets,
}

impl ObjectObservations {
    /// The honest no-evidence publication: no Joint facts exist, so
    /// sessions/objects/rows are empty and S1 is unaffected. The
    /// reason is finite (`bootstrap_unavailable` in production
    /// today), never an empty successful projection.
    pub(crate) fn unavailable(revision: u64, reason: &'static str) -> Self {
        debug_assert!(
            REASON_LABELS.contains(&reason),
            "unavailable reasons are frozen"
        );
        let mut observations = Self {
            revision,
            status: ObsStatus::Unavailable,
            reason,
            sessions: Vec::new(),
            objects: Vec::new(),
            key_operations: Vec::new(),
            unknown_key_operations: Vec::new(),
            gaps: Vec::new(),
            gaps_suppressed: 0,
            budgets: ObsBudgets {
                key_limit: KEY_OP_ROW_CAPACITY,
                key_occupied: 0,
                key_refused: 0,
                object_limit: crate::semantics_objects::ObjectLimits::policy().object_records,
                object_occupied: 0,
                object_refused: 0,
                unknown_occupied: 0,
                encoded_bytes: 0,
            },
        };
        observations.budgets.encoded_bytes = measure(&observations);
        observations
    }
}

/// Measured JSON encoding bytes of one section: a real measurement
/// for the byte check, never an RSS estimate. The count lives inside
/// the measured document, so digits feed back into the total;
/// iterating to the fixed point (digit flips settle immediately)
/// keeps the published count self-consistent.
fn measure(observations: &ObjectObservations) -> usize {
    let mut probe = observations.clone();
    probe.budgets.encoded_bytes = 0;
    for _ in 0..8 {
        let len =
            serde_json::to_vec(&object_observations_json(&probe)).map_or(0, |bytes| bytes.len());
        if len == probe.budgets.encoded_bytes {
            return len;
        }
        probe.budgets.encoded_bytes = len;
    }
    debug_assert!(false, "byte-count fixed point settles immediately");
    probe.budgets.encoded_bytes
}

/// Render one metadata field: frozen status plus the scalar or the
/// curve name (never key material).
pub(crate) fn metadata_field_json(field: &MetadataField, curve: bool) -> serde_json::Value {
    let value = if curve {
        field
            .curve
            .map(serde_json::Value::from)
            .unwrap_or(serde_json::Value::Null)
    } else {
        field
            .scalar
            .map(serde_json::Value::from)
            .unwrap_or(serde_json::Value::Null)
    };
    serde_json::json!({
        "status": field.status,
        "value": value,
    })
}

/// Render one six-slot metadata block (requested or established).
pub(crate) fn metadata_block_json(block: &MetadataBlock) -> serde_json::Value {
    serde_json::json!({
        "class": metadata_field_json(&block.class, false),
        "key_type": metadata_field_json(&block.key_type, false),
        "token": metadata_field_json(&block.token, false),
        "value_len": metadata_field_json(&block.value_len, false),
        "modulus_bits": metadata_field_json(&block.modulus_bits, false),
        "ec_params": metadata_field_json(&block.ec_params, true),
    })
}

/// Render one per-field query-outcome block.
pub(crate) fn queries_block_json(block: &QueriesBlock) -> serde_json::Value {
    serde_json::json!({
        "class": block.class,
        "key_type": block.key_type,
        "token": block.token,
        "value_len": block.value_len,
        "modulus_bits": block.modulus_bits,
        "ec_params": block.ec_params,
    })
}

/// Render one session row: the exact frozen keys.
pub(crate) fn session_row_json(row: &SessionRow) -> serde_json::Value {
    serde_json::json!({
        "session": row.session,
        "origin": row.origin,
        "status": row.status,
    })
}

/// Render one object row: the exact frozen keys.
pub(crate) fn object_row_json(row: &ObjectRow) -> serde_json::Value {
    serde_json::json!({
        "object": row.object,
        "session": row.session,
        "origin": row.origin,
        "creation": row.creation,
        "birth": row.birth.map(|(start_ns, end_ns)| serde_json::json!({
            "start_ns": start_ns,
            "end_ns": end_ns,
        })).unwrap_or(serde_json::Value::Null),
        "lifetime": row.lifetime,
        "lifetime_reason": row.lifetime_reason,
        "attribution": row.attribution,
        "attribution_reason": row.attribution_reason,
        "requested": metadata_block_json(&row.requested),
        "established": metadata_block_json(&row.established),
        "queries": queries_block_json(&row.queries),
        "label": row.label,
        "successful_references": row.successful_references,
        "successful_key_references": row.successful_key_references,
        "accessing_sessions": row.accessing_sessions,
    })
}

/// Render one proved-key aggregate row: the exact frozen keys.
pub(crate) fn key_row_json(row: &KeyAggRow) -> serde_json::Value {
    serde_json::json!({
        "instance": row.instance,
        "object": row.object,
        "category": row.category,
        "role": row.role,
        "metadata_at_use": row.metadata_at_use,
        "unit": row.unit,
        "started": row.started,
        "completed": row.completed,
        "failed": row.failed,
        "cancelled": row.cancelled,
        "unknown": row.unknown,
        "active": row.active,
        "key_join_lost": row.key_join_lost,
    })
}

/// Render one unknown-key summary row: the exact frozen keys (no
/// `started` — starts are never fabricated into the unknown bucket).
pub(crate) fn unknown_row_json(row: &UnknownAggRow) -> serde_json::Value {
    serde_json::json!({
        "category": row.category,
        "reason": row.reason,
        "unit": row.unit,
        "completed": row.completed,
        "failed": row.failed,
        "cancelled": row.cancelled,
        "unknown": row.unknown,
        "active": row.active,
    })
}

/// Render one gap row: the exact frozen keys.
pub(crate) fn gap_row_json(row: &GapRow) -> serde_json::Value {
    serde_json::json!({
        "subject": row.subject,
        "reason": row.reason,
        "repeats": row.repeats,
    })
}

/// Render the budgets block: row counters plus the measured encoding
/// size. Pool fields stay false/none until a reviewed pool ships.
pub(crate) fn budgets_json(budgets: &ObsBudgets) -> serde_json::Value {
    serde_json::json!({
        "key_rows": {
            "limit": budgets.key_limit,
            "occupied": budgets.key_occupied,
            "refused": budgets.key_refused,
        },
        "object_rows": {
            "limit": budgets.object_limit,
            "occupied": budgets.object_occupied,
            "refused": budgets.object_refused,
        },
        "unknown_rows": {
            "occupied": budgets.unknown_occupied,
        },
        "encoded_bytes": budgets.encoded_bytes,
        "allocation_refused": false,
        "refusal_reason": "none",
    })
}

/// Render the whole section: the exact frozen keys. The single
/// renderer behind JSON, JSONL row payloads and byte measurement —
/// every consumer reads these shapes.
pub(crate) fn object_observations_json(observations: &ObjectObservations) -> serde_json::Value {
    serde_json::json!({
        "version": OBSERVATIONS_VERSION,
        "revision": observations.revision,
        "status": observations.status.label(),
        "reason": observations.reason,
        "sessions": observations.sessions.iter().map(session_row_json).collect::<Vec<_>>(),
        "objects": observations.objects.iter().map(object_row_json).collect::<Vec<_>>(),
        "key_operations": observations.key_operations.iter().map(key_row_json).collect::<Vec<_>>(),
        "unknown_key_operations": observations.unknown_key_operations.iter().map(unknown_row_json).collect::<Vec<_>>(),
        "gaps": {
            "rows": observations.gaps.iter().map(gap_row_json).collect::<Vec<_>>(),
            "suppressed": observations.gaps_suppressed,
        },
        "budgets": budgets_json(&observations.budgets),
    })
}

/// The publication gate: admits one candidate revision per call,
/// retaining the last complete publication when a new revision
/// cannot publish. Admission is by measured encoding bytes against
/// an injected limit (`None` until a reviewed pool freezes one:
/// admit all). A refused candidate never replaces the retained
/// publication; the retained rows are relabeled `stale` in place
/// (no new snapshot allocation) with the staleness cause, while
/// their budgets keep the content's partiality visible.
#[derive(Debug, Default)]
pub(crate) struct ObservationPublisher {
    last: Option<ObjectObservations>,
    byte_limit: Option<usize>,
}

impl ObservationPublisher {
    pub(crate) fn new() -> Self {
        Self::default()
    }

    /// A publisher with an injected byte bound (N/N+1 twins): the
    /// production bound awaits the reviewed pool decision.
    #[cfg(test)]
    pub(crate) fn with_byte_limit(limit: usize) -> Self {
        Self {
            last: None,
            byte_limit: Some(limit),
        }
    }

    pub(crate) fn publication(&self) -> Option<&ObjectObservations> {
        self.last.as_ref()
    }

    /// Publish one candidate: admit it, or retain the last complete
    /// publication relabeled `stale`. With no retained publication
    /// and an over-budget first candidate, publish the pre-reserved
    /// negative (unavailable + cause, no rows, no big allocation).
    /// Returns the current publication.
    pub(crate) fn publish(&mut self, candidate: ObjectObservations) -> &ObjectObservations {
        let over_budget = self
            .byte_limit
            .is_some_and(|limit| candidate.budgets.encoded_bytes > limit);
        if !over_budget {
            self.last = Some(candidate);
            return self.last.as_ref().expect("just published");
        }
        if self.last.is_none() {
            self.last = Some(ObjectObservations::unavailable(
                candidate.revision,
                "publication_budget_exhausted",
            ));
        } else if let Some(retained) = self.last.as_mut() {
            retained.status = ObsStatus::Stale;
            retained.reason = "publication_budget_exhausted";
        }
        self.last.as_ref().expect("retained or just published")
    }

    /// Record a sink failure after a populated revision: the retained
    /// publication goes `stale` in place (no new snapshot), keeping
    /// its rows as history. Unavailable publications have no rows to
    /// stale and stay unchanged. Staged: production stream-error
    /// wiring needs stream-error review (carry).
    #[cfg(test)]
    pub(crate) fn note_sink_failed(&mut self) {
        let Some(retained) = self.last.as_mut() else {
            return;
        };
        if retained.status == ObsStatus::Unavailable {
            return;
        }
        retained.status = ObsStatus::Stale;
        retained.reason = "sink_failed";
    }
}

/// The staged producer mapping: typed reducers in, immutable
/// projection out. Test-gated with the feed driver and reducer
/// (live-loop carry); ungate with them. Every vocabulary map is
/// exhaustive over its source enum, so the compiler pins the frozen
/// sets; the contract tests pin keys, enums, equations and orders.
#[cfg(test)]
pub(crate) mod producer {
    use super::*;
    use crate::semantics_edge::{KeyReceipt, KeyRole, OperationOutcome};
    use crate::semantics_key_use::{FeedMode, JointStaging, KeyUseReducer, unbound_reason_for};
    use crate::semantics_objects::{
        Attribution, Birth, CreationFamily, FieldState, FieldValue, KeyLabel, Lifetime,
        MetadataView, ObjectGap, ObjectProjection, ObjectView, QueryStatus, SessionOrigin,
        SessionState, SessionView, ViewOrigin, field_index,
    };
    use p11scope_ebpf_common::object_policy::{SafeAttributeKind, SafeCurve};
    use std::collections::BTreeMap;

    /// Commit one immutable revision from the live reducers: the one
    /// typed producer-to-projection mapping. Status derives from the
    /// capture-wide feed census plus refusal evidence: any Joint
    /// feed carries object authority (S1Only siblings contribute
    /// unknown-key S1 facts, never a refusal); with no Joint feed
    /// the reason names the loss. Rows aggregate per-operation
    /// reducer state into frozen aggregate rows; budgets measure.
    pub(crate) fn commit(
        revision: u64,
        stagings: &[&JointStaging],
        model: &ObjectProjection,
        keyuse: &KeyUseReducer,
    ) -> ObjectObservations {
        let evidence = keyuse.evidence();
        let joint = stagings
            .iter()
            .any(|staging| staging.mode() == FeedMode::Joint);
        let lost = stagings.iter().any(|staging| staging.degraded_loss());
        let fallback = stagings.iter().any(|staging| staging.fell_back());
        let (status, reason) = if joint && evidence.partial {
            (ObsStatus::Partial, "row_budget_exhausted")
        } else if joint {
            (ObsStatus::Populated, "none")
        } else if lost {
            (ObsStatus::Unavailable, "authority_lost")
        } else if fallback {
            (ObsStatus::Unavailable, "proof_refused_fallback")
        } else {
            (ObsStatus::Unavailable, "bootstrap_unavailable")
        };
        let mut observations = ObjectObservations {
            revision,
            status,
            reason,
            sessions: model.sessions.iter().map(session_row).collect(),
            objects: model.objects.iter().map(object_row).collect(),
            key_operations: Vec::new(),
            unknown_key_operations: Vec::new(),
            gaps: Vec::new(),
            gaps_suppressed: 0,
            budgets: ObsBudgets {
                key_limit: keyuse.capacity(),
                key_occupied: keyuse.rows().len().saturating_add(keyuse.open().len()),
                key_refused: evidence.rows_refused,
                object_limit: crate::semantics_objects::ObjectLimits::policy().object_records,
                object_occupied: model.objects.len(),
                object_refused: model.gap(ObjectGap::ObjectCapacity),
                unknown_occupied: 0,
                encoded_bytes: 0,
            },
        };
        observations.sessions.sort_by_key(|row| row.session);
        observations.objects.sort_by_key(|row| row.object);
        aggregate_key_use(&mut observations, model, keyuse);
        collect_gaps(&mut observations, model);
        observations.budgets.unknown_occupied = observations.unknown_key_operations.len();
        observations.budgets.encoded_bytes = super::measure(&observations);
        observations
    }

    /// Aggregate per-operation reducer state into proved-key rows
    /// (one per association key) and capture-wide unknown summaries.
    /// Terminals partition once per primary operation role; starts
    /// are never fabricated into the unknown bucket.
    fn aggregate_key_use(
        observations: &mut ObjectObservations,
        model: &ObjectProjection,
        keyuse: &KeyUseReducer,
    ) {
        let live: std::collections::BTreeSet<u64> =
            model.objects.iter().map(|view| view.id.as_u64()).collect();
        let mut proved: BTreeMap<
            (String, u64, &'static str, &'static str, &'static str),
            KeyAggRow,
        > = BTreeMap::new();
        let mut unknown: BTreeMap<(&'static str, &'static str), UnknownAggRow> = BTreeMap::new();
        let mut dangling = 0u64;

        // Completed rows: starts and terminals per association.
        for row in keyuse.rows() {
            let instance = row.instance.label();
            if row.partial {
                add_unknown(&mut unknown, row.category, "unbound", row.outcome);
                continue;
            }
            let primary = primary_receipt(&row.keys);
            for receipt in &row.keys {
                if !live.contains(&receipt.key.as_u64()) {
                    dangling = dangling.saturating_add(1);
                }
                match association_bucket(receipt) {
                    AssociationBucket::Proved { label } => {
                        let slot = proved
                            .entry((
                                instance.clone(),
                                receipt.key.as_u64(),
                                row.category,
                                role_label(receipt.role),
                                label,
                            ))
                            .or_insert_with(|| KeyAggRow {
                                instance: instance.clone(),
                                object: receipt.key.as_u64(),
                                category: row.category,
                                role: role_label(receipt.role),
                                metadata_at_use: label,
                                unit: crate::semantics_key_use::unit_for(row.category),
                                started: 0,
                                completed: 0,
                                failed: 0,
                                cancelled: 0,
                                unknown: 0,
                                active: 0,
                                key_join_lost: 0,
                            });
                        slot.started = slot.started.saturating_add(1);
                        if receipt.lost {
                            slot.key_join_lost = slot.key_join_lost.saturating_add(1);
                        } else {
                            add_outcome(slot, row.outcome);
                        }
                    }
                    AssociationBucket::Unknown { .. } => {}
                }
            }
            // The terminal partitions once, by the primary role.
            match primary {
                Some(receipt) if !receipt.lost && association_bucket(receipt).label().is_some() => {
                }
                Some(receipt) if receipt.lost => {
                    add_unknown(&mut unknown, row.category, "key_join_lost", row.outcome);
                }
                Some(receipt) => {
                    let reason = metadata_reason(receipt);
                    add_unknown(&mut unknown, row.category, reason, row.outcome);
                }
                None => {
                    let reason = unbound_reason_for(row.category);
                    add_unknown(&mut unknown, row.category, reason, row.outcome);
                }
            }
        }
        // Open associations: started + active; lost joins stay active
        // until their terminal (counted once, at the end).
        for open in keyuse.open().values() {
            let instance = open.instance.label();
            if open.keys.is_empty() {
                let reason = unbound_reason_for(open.category);
                add_unknown_open(&mut unknown, open.category, reason);
                continue;
            }
            for receipt in &open.keys {
                if !live.contains(&receipt.key.as_u64()) {
                    dangling = dangling.saturating_add(1);
                }
                match association_bucket(receipt) {
                    AssociationBucket::Proved { label } => {
                        let slot = proved
                            .entry((
                                instance.clone(),
                                receipt.key.as_u64(),
                                open.category,
                                role_label(receipt.role),
                                label,
                            ))
                            .or_insert_with(|| KeyAggRow {
                                instance: instance.clone(),
                                object: receipt.key.as_u64(),
                                category: open.category,
                                role: role_label(receipt.role),
                                metadata_at_use: label,
                                unit: crate::semantics_key_use::unit_for(open.category),
                                started: 0,
                                completed: 0,
                                failed: 0,
                                cancelled: 0,
                                unknown: 0,
                                active: 0,
                                key_join_lost: 0,
                            });
                        slot.started = slot.started.saturating_add(1);
                        slot.active = slot.active.saturating_add(1);
                    }
                    AssociationBucket::Unknown { .. } => {
                        let reason = if receipt.lost {
                            "key_join_lost"
                        } else {
                            metadata_reason(receipt)
                        };
                        add_unknown_open(&mut unknown, open.category, reason);
                    }
                }
            }
        }
        // Refused opens are live S1 without associations.
        for refused in keyuse.refused_opens().values() {
            add_unknown_open(
                &mut unknown,
                refused.category,
                unbound_reason_for(refused.category),
            );
        }
        let mut key_rows: Vec<KeyAggRow> = proved.into_values().collect();
        key_rows.sort_by(|a, b| {
            (&a.instance, a.object, a.category, a.role, a.metadata_at_use).cmp(&(
                &b.instance,
                b.object,
                b.category,
                b.role,
                b.metadata_at_use,
            ))
        });
        let mut unknown_rows: Vec<UnknownAggRow> = unknown.into_values().collect();
        unknown_rows.sort_by(|a, b| (a.category, a.reason).cmp(&(b.category, b.reason)));
        observations.key_operations = key_rows;
        observations.unknown_key_operations = unknown_rows;
        observations.budgets.unknown_occupied = observations.unknown_key_operations.len();
        if dangling > 0 {
            observations.gaps.push(GapRow {
                subject: "key_operation",
                reason: "pruned_object_referenced",
                repeats: dangling,
            });
        }
    }

    /// The primary receipt decides the terminal's bucket: the first
    /// non-secondary receipt (`wrapped_object` is secondary, H9 §82),
    /// else none. A secondary-only row never promotes its secondary
    /// to primary: the proved secondary association is retained in
    /// its own row while the missing primary's terminal partitions
    /// to the unknown-key summary.
    fn primary_receipt(keys: &[KeyReceipt]) -> Option<&KeyReceipt> {
        keys.iter()
            .find(|receipt| receipt.role != KeyRole::WrappedKey)
    }

    /// Where one receipt's association counts: a proved row under its
    /// usable label, or the unknown bucket. Lost joins keep their
    /// proved row (the association existed) and close it with
    /// `key_join_lost` at the end.
    enum AssociationBucket {
        Proved { label: &'static str },
        Unknown { _private: () },
    }

    impl AssociationBucket {
        fn label(&self) -> Option<&'static str> {
            match self {
                Self::Proved { label } => Some(label),
                Self::Unknown { .. } => None,
            }
        }
    }

    fn association_bucket(receipt: &KeyReceipt) -> AssociationBucket {
        match usable_label(receipt) {
            Some(label) => AssociationBucket::Proved { label },
            None => AssociationBucket::Unknown { _private: () },
        }
    }

    /// The usable metadata-at-use label (H9 §72): established-only,
    /// valid attribution, non-conflicting required fields.
    fn usable_label(receipt: &KeyReceipt) -> Option<&'static str> {
        if !receipt.attribution_valid {
            return None;
        }
        let label = receipt.label?;
        let required = match label {
            KeyLabel::Aes { .. } => {
                (1 << field_index(SafeAttributeKind::Class))
                    | (1 << field_index(SafeAttributeKind::KeyType))
                    | (1 << field_index(SafeAttributeKind::ValueLen))
            }
            KeyLabel::Rsa { .. } => {
                (1 << field_index(SafeAttributeKind::Class))
                    | (1 << field_index(SafeAttributeKind::KeyType))
                    | (1 << field_index(SafeAttributeKind::ModulusBits))
            }
            KeyLabel::Ec { .. } => {
                (1 << field_index(SafeAttributeKind::Class))
                    | (1 << field_index(SafeAttributeKind::KeyType))
                    | (1 << field_index(SafeAttributeKind::EcParams))
            }
        };
        if receipt.metadata.conflicted & required != 0 {
            return None;
        }
        Some(metadata_label(label))
    }

    /// The unknown reason for an unusable label: any conflict at use
    /// reports conflicting, otherwise unknown.
    fn metadata_reason(receipt: &KeyReceipt) -> &'static str {
        if receipt.metadata.conflicted != 0 {
            "metadata_conflicting"
        } else {
            "metadata_unknown"
        }
    }

    fn add_outcome(slot: &mut KeyAggRow, outcome: OperationOutcome) {
        match outcome {
            OperationOutcome::Completed => slot.completed = slot.completed.saturating_add(1),
            OperationOutcome::Failed => slot.failed = slot.failed.saturating_add(1),
            OperationOutcome::Cancelled => slot.cancelled = slot.cancelled.saturating_add(1),
            OperationOutcome::Unknown => slot.unknown = slot.unknown.saturating_add(1),
        }
    }

    fn add_unknown(
        unknown: &mut BTreeMap<(&'static str, &'static str), UnknownAggRow>,
        category: &'static str,
        reason: &'static str,
        outcome: OperationOutcome,
    ) {
        let slot = unknown
            .entry((category, reason))
            .or_insert_with(|| UnknownAggRow {
                category,
                reason,
                unit: crate::semantics_key_use::unit_for(category),
                completed: 0,
                failed: 0,
                cancelled: 0,
                unknown: 0,
                active: 0,
            });
        match outcome {
            OperationOutcome::Completed => slot.completed = slot.completed.saturating_add(1),
            OperationOutcome::Failed => slot.failed = slot.failed.saturating_add(1),
            OperationOutcome::Cancelled => slot.cancelled = slot.cancelled.saturating_add(1),
            OperationOutcome::Unknown => slot.unknown = slot.unknown.saturating_add(1),
        }
    }

    fn add_unknown_open(
        unknown: &mut BTreeMap<(&'static str, &'static str), UnknownAggRow>,
        category: &'static str,
        reason: &'static str,
    ) {
        let slot = unknown
            .entry((category, reason))
            .or_insert_with(|| UnknownAggRow {
                category,
                reason,
                unit: crate::semantics_key_use::unit_for(category),
                completed: 0,
                failed: 0,
                cancelled: 0,
                unknown: 0,
                active: 0,
            });
        slot.active = slot.active.saturating_add(1);
    }

    /// Model gaps plus key-side scope facts, sorted, bounded (the
    /// key-side pruned-reference row is pushed during aggregation).
    fn collect_gaps(observations: &mut ObjectObservations, model: &ObjectProjection) {
        for (gap, count) in &model.gaps {
            observations.gaps.push(GapRow {
                subject: "model",
                reason: gap_label(*gap),
                repeats: *count,
            });
        }
        observations
            .gaps
            .sort_by(|a, b| (a.subject, a.reason).cmp(&(b.subject, b.reason)));
        if observations.gaps.len() > super::contract::GAPS_CAPACITY {
            let suppressed = observations.gaps.len() - super::contract::GAPS_CAPACITY;
            observations.gaps.truncate(super::contract::GAPS_CAPACITY);
            observations.gaps_suppressed = observations
                .gaps_suppressed
                .saturating_add(suppressed as u64);
        }
    }

    fn session_row(view: &SessionView) -> SessionRow {
        SessionRow {
            session: view.id.as_u64(),
            origin: match view.origin {
                SessionOrigin::Opened => "opened",
                SessionOrigin::FirstObserved => "first_observed",
            },
            status: match view.state {
                SessionState::Live => "live",
                SessionState::Closed => "closed",
                SessionState::Ended(_) => "lost",
            },
        }
    }

    fn object_row(view: &ObjectView) -> ObjectRow {
        ObjectRow {
            object: view.id.as_u64(),
            session: view.session.as_u64(),
            origin: match view.origin {
                ViewOrigin::Created(_) => "created",
                ViewOrigin::FirstObserved => "first_observed",
            },
            creation: match view.origin {
                ViewOrigin::Created(CreationFamily::Create) => Some("create"),
                ViewOrigin::Created(CreationFamily::Copy) => Some("copy"),
                ViewOrigin::Created(CreationFamily::Generate) => Some("generate"),
                ViewOrigin::Created(CreationFamily::GeneratePair) => Some("generate_pair"),
                ViewOrigin::Created(CreationFamily::Derive) => Some("derive"),
                ViewOrigin::Created(CreationFamily::Unwrap) => Some("unwrap"),
                ViewOrigin::FirstObserved => None,
            },
            birth: match view.birth {
                Birth::Observed { start_ns, end_ns } => Some((start_ns, end_ns)),
                Birth::Unknown => None,
            },
            lifetime: match view.lifetime {
                Lifetime::Live => "live",
                Lifetime::Destroyed => "destroyed",
                Lifetime::AccessEnded(_) => "access_ended",
                Lifetime::Retired(_) => "retired",
            },
            lifetime_reason: match view.lifetime {
                Lifetime::AccessEnded(reason) | Lifetime::Retired(reason) => {
                    Some(gap_label(reason))
                }
                Lifetime::Live | Lifetime::Destroyed => None,
            },
            attribution: match view.attribution {
                Attribution::Valid => "valid",
                Attribution::Downgraded(_) => "downgraded",
            },
            attribution_reason: match view.attribution {
                Attribution::Downgraded(reason) => Some(gap_label(reason)),
                Attribution::Valid => None,
            },
            requested: metadata_block(&view.requested),
            established: metadata_block(&view.established),
            queries: QueriesBlock {
                class: query_label(view.queries[field_index(SafeAttributeKind::Class)]),
                key_type: query_label(view.queries[field_index(SafeAttributeKind::KeyType)]),
                token: query_label(view.queries[field_index(SafeAttributeKind::Token)]),
                value_len: query_label(view.queries[field_index(SafeAttributeKind::ValueLen)]),
                modulus_bits: query_label(
                    view.queries[field_index(SafeAttributeKind::ModulusBits)],
                ),
                ec_params: query_label(view.queries[field_index(SafeAttributeKind::EcParams)]),
            },
            label: view.label.map(metadata_label),
            successful_references: view.references,
            successful_key_references: view.key_uses,
            accessing_sessions: view.accessing_sessions as u64,
        }
    }

    fn metadata_block(view: &MetadataView) -> MetadataBlock {
        MetadataBlock {
            class: metadata_field(view.field(SafeAttributeKind::Class)),
            key_type: metadata_field(view.field(SafeAttributeKind::KeyType)),
            token: metadata_field(view.field(SafeAttributeKind::Token)),
            value_len: metadata_field(view.field(SafeAttributeKind::ValueLen)),
            modulus_bits: metadata_field(view.field(SafeAttributeKind::ModulusBits)),
            ec_params: metadata_field(view.field(SafeAttributeKind::EcParams)),
        }
    }

    pub(crate) fn metadata_field(state: FieldState) -> MetadataField {
        let (status, scalar, curve) = match state {
            FieldState::Unknown => ("unknown", None, None),
            FieldState::Value(FieldValue::Scalar(value)) => ("value", Some(value), None),
            FieldState::Value(FieldValue::Curve(curve)) => {
                ("value", None, Some(curve_label(curve)))
            }
            FieldState::Conflict(value) => ("conflict", scalar_of(value), curve_of(value)),
            FieldState::Invalidated(value) => ("invalidated", scalar_of(value), curve_of(value)),
        };
        MetadataField {
            status,
            scalar,
            curve,
        }
    }

    fn scalar_of(value: Option<FieldValue>) -> Option<u16> {
        match value {
            Some(FieldValue::Scalar(scalar)) => Some(scalar),
            _ => None,
        }
    }

    fn curve_of(value: Option<FieldValue>) -> Option<&'static str> {
        match value {
            Some(FieldValue::Curve(curve)) => Some(curve_label(curve)),
            _ => None,
        }
    }

    fn curve_label(curve: SafeCurve) -> &'static str {
        match curve {
            SafeCurve::Secp256r1 => "secp256r1",
            SafeCurve::Secp384r1 => "secp384r1",
            SafeCurve::Secp521r1 => "secp521r1",
        }
    }

    pub(crate) fn query_label(status: QueryStatus) -> &'static str {
        match status {
            QueryStatus::NotQueried => "not_queried",
            QueryStatus::Established => "established",
            QueryStatus::Unavailable => "unavailable",
            QueryStatus::SizeOnly => "size_only",
            QueryStatus::Unsupported => "unsupported",
            QueryStatus::Malformed => "malformed",
            QueryStatus::Excluded => "excluded",
        }
    }

    pub(crate) fn role_label(role: KeyRole) -> &'static str {
        match role {
            KeyRole::OperationKey => "key",
            KeyRole::WrappingKey => "wrapping_key",
            KeyRole::WrappedKey => "wrapped_object",
            KeyRole::BaseKey => "base_key",
            KeyRole::UnwrappingKey => "unwrapping_key",
            KeyRole::Other => "other",
        }
    }

    pub(crate) fn metadata_label(label: KeyLabel) -> &'static str {
        match label {
            KeyLabel::Rsa { modulus_bits } => match modulus_bits {
                1024 => "rsa_1024",
                2048 => "rsa_2048",
                3072 => "rsa_3072",
                4096 => "rsa_4096",
                _ => "rsa_other",
            },
            KeyLabel::Aes { value_len } => match value_len {
                16 => "aes_128",
                24 => "aes_192",
                32 => "aes_256",
                _ => "aes_other",
            },
            KeyLabel::Ec { curve } => match curve {
                SafeCurve::Secp256r1 => "ec_p256",
                SafeCurve::Secp384r1 => "ec_p384",
                SafeCurve::Secp521r1 => "ec_p521",
            },
        }
    }

    pub(crate) fn gap_label(gap: ObjectGap) -> &'static str {
        match gap {
            ObjectGap::BootstrapUnproven => "bootstrap_unproven",
            ObjectGap::BootstrapRefused => "bootstrap_refused",
            ObjectGap::PrefixContradiction => "prefix_contradiction",
            ObjectGap::StalePrefix => "stale_prefix",
            ObjectGap::ClosedFrontier => "closed_frontier",
            ObjectGap::DuplicateCall => "duplicate_call",
            ObjectGap::DuplicateCompletion => "duplicate_completion",
            ObjectGap::StaleToken => "stale_token",
            ObjectGap::FencedCompletion => "fenced_completion",
            ObjectGap::MalformedFact => "malformed_fact",
            ObjectGap::UnsupportedFunction => "unsupported_function",
            ObjectGap::DomainEnded => "domain_ended",
            ObjectGap::ResultProtocolUnavailable => "result_protocol_unavailable",
            ObjectGap::PendingResultUnavailable => "pending_result_unavailable",
            ObjectGap::OutputUnreadable => "output_unreadable",
            ObjectGap::PairDuplicate => "pair_duplicate",
            ObjectGap::NullMechanismCancel => "null_mechanism_cancel",
            ObjectGap::SameSessionOverlap => "same_session_overlap",
            ObjectGap::OverlapUncertain => "overlap_uncertain",
            ObjectGap::OutputCollision => "output_collision",
            ObjectGap::StaleOrigin => "stale_origin",
            ObjectGap::DependencyBroken => "dependency_broken",
            ObjectGap::UnprovenInput => "unproven_input",
            ObjectGap::UnprovenSession => "unproven_session",
            ObjectGap::MetadataUncertain => "metadata_uncertain",
            ObjectGap::DestroyAlias => "destroy_alias",
            ObjectGap::CloseUncertain => "close_uncertain",
            ObjectGap::CloseAllUncertain => "close_all_uncertain",
            ObjectGap::LogoutUncertain => "logout_uncertain",
            ObjectGap::SessionClosed => "session_closed",
            ObjectGap::InvalidHandle => "invalid_handle",
            ObjectGap::AmbiguousOutcome => "ambiguous_outcome",
            ObjectGap::SessionContradiction => "session_contradiction",
            ObjectGap::HandleReuse => "handle_reuse",
            ObjectGap::Finalize => "finalize",
            ObjectGap::TokenReset => "token_reset",
            ObjectGap::Exec => "exec",
            ObjectGap::Fork => "fork",
            ObjectGap::Unload => "unload",
            ObjectGap::Loss => "loss",
            ObjectGap::PendingCapacity => "pending_capacity",
            ObjectGap::SessionCapacity => "session_capacity",
            ObjectGap::ObjectCapacity => "object_capacity",
            ObjectGap::InstanceCapacity => "instance_capacity",
            ObjectGap::IdExhausted => "id_exhausted",
            ObjectGap::DeviceLoss => "device_loss",
            ObjectGap::UnseenFinalize => "unseen_finalize",
            ObjectGap::InconsistentMechanism => "inconsistent_mechanism",
            ObjectGap::OutcomeLost => "outcome_lost",
            ObjectGap::UnknownDomain => "unknown_domain",
            ObjectGap::DomainPruned => "domain_pruned",
        }
    }
}
