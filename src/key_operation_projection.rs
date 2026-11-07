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
/// H9 section version 2: v1 plus the KEM role/creation labels. The
/// renderer emits v2 only when KEM content is present; v1 output is
/// byte-stable.
pub(crate) const OBSERVATIONS_VERSION_V2: u8 = 2;
/// Section version 3: v2 vocabulary plus the `unattributed`
/// counters. The renderer emits v3 only when at least one count is
/// nonzero; fully attributed output stays byte-stable v1/v2.
pub(crate) const OBSERVATIONS_VERSION_V3: u8 = 3;
/// Section version 4: v3 vocabulary plus the `unknown` metadata
/// label on per-key rows (DEMO-4 late attach: a first-observed key
/// whose type/size were never established in the observed window).
/// The renderer emits v4 only when such a row is present; the
/// `unattributed` key is then always present (possibly empty).
pub(crate) const OBSERVATIONS_VERSION_V4: u8 = 4;
/// The metadata label of a first-observed key at use: its identity
/// and counts are proved, its type/size are not (first seen before
/// attach). Frozen v4 vocabulary; never a guessed label.
pub(crate) const METADATA_UNKNOWN: &str = "unknown";

/// Finite not-attributed reasons, in publication order. Each counts
/// calls that carry no per-key row, with the reason no key could be
/// proved (`started_before_attach`: direct reductions on a feed
/// registered without a witnessed birth). Counts and reason names
/// only — never handles, labels, or payloads.
pub(crate) const UNATTRIBUTED_REASONS: [&str; 7] = [
    "started_before_attach",
    "record_lost",
    "foreign_or_unproven_caller",
    "session_state_lost",
    "watchdog_no_progress",
    "unmodelled_call_shape",
    "proof_refused_fallback",
];

/// Frozen machine reasons. `none` only when populated.
/// `journal_unavailable` (OD33/R-50) names the v0.5.0 world: no journal
/// producer is linked, so no key-operation feed exists;
/// `bootstrap_unavailable` keeps its 0.6.0 meaning (linked, no birth
/// yet).
pub(crate) const REASON_LABELS: [&str; 9] = [
    "none",
    "bootstrap_unavailable",
    "journal_unavailable",
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
    /// H9 section v2 creation vocabulary: v1 plus the two KEM
    /// families. v1 stays frozen; v2 sections carry these.
    pub(crate) const CREATION_LABELS_V2: [&str; 8] = [
        "create",
        "copy",
        "generate",
        "generate_pair",
        "derive",
        "unwrap",
        "encapsulate",
        "decapsulate",
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

    /// H9 section v4 metadata vocabulary: the 12 established labels
    /// plus `unknown` (a first-observed key whose type/size were
    /// never established in the observed window).
    pub(crate) const METADATA_LABELS_V4: [&str; 13] = [
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
        "unknown",
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
    /// H9 section v2 role vocabulary: v1 plus the two KEM roles. v1
    /// stays frozen; v2 sections carry these.
    pub(crate) const ROLE_LABELS_V2: [&str; 8] = [
        "key",
        "wrapping_key",
        "wrapped_object",
        "unwrapping_key",
        "base_key",
        "encapsulation_key",
        "decapsulation_key",
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

    /// Section keys for a v3 section: v1 keys plus `unattributed`
    /// beside the row buckets it counts beside.
    pub(crate) const SECTION_KEYS_V3: [&str; 11] = [
        "version",
        "revision",
        "status",
        "reason",
        "sessions",
        "objects",
        "key_operations",
        "unknown_key_operations",
        "unattributed",
        "gaps",
        "budgets",
    ];
    pub(crate) const UNATTRIBUTED_ROW_KEYS: [&str; 2] = ["reason", "count"];

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
}

/// Gap rows carried per publication before `suppressed` counts.
pub(crate) const GAPS_CAPACITY: usize = 256;

/// Publication status: object authority, never S1 health.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum ObsStatus {
    // Guarded (N1): constructed by the guarded commit once Joint
    // evidence exists; unreachable while feeds stay S1Only.
    Populated,
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

/// The one secondary association role (H9 §82): [`KeyAggRow`]s
/// carrying it stand beside the primary's row, never
/// double-counted in operation tallies. Must stay an element of
/// the frozen role vocabulary (asserted against `contract` in
/// tests).
pub(crate) const SECONDARY_ROLE: &str = "wrapped_object";

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

/// One not-attributed counter: how many calls (or first-observed
/// sessions) carry no per-key row, and the finite reason why no key
/// could be proved for them. Attributed rows are never guessed
/// into existence to avoid this counter.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct UnattributedRow {
    pub reason: &'static str,
    pub count: u64,
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
    pub unattributed: Vec<UnattributedRow>,
    pub gaps: Vec<GapRow>,
    pub gaps_suppressed: u64,
    pub budgets: ObsBudgets,
}

impl ObjectObservations {
    /// The honest no-evidence publication: no Joint facts exist, so
    /// sessions/objects/rows are empty and S1 is unaffected. The
    /// reason is finite (`journal_unavailable` in production v0.5.0,
    /// whose lanes link no journal producer), never an empty
    /// successful projection.
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
            unattributed: Vec::new(),
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

    /// Add `count` to one finite not-attributed reason, keeping the
    /// frozen publication order, and re-measure so the published
    /// byte count stays self-consistent. Zero adds nothing.
    pub(crate) fn add_unattributed(&mut self, reason: &'static str, count: u64) {
        debug_assert!(
            UNATTRIBUTED_REASONS.contains(&reason),
            "unattributed reasons are frozen"
        );
        if count == 0 {
            return;
        }
        if let Some(row) = self
            .unattributed
            .iter_mut()
            .find(|row| row.reason == reason)
        {
            row.count = row.count.saturating_add(count);
        } else {
            self.unattributed.push(UnattributedRow { reason, count });
        }
        self.unattributed.sort_by_key(|row| {
            UNATTRIBUTED_REASONS
                .iter()
                .position(|known| *known == row.reason)
                .unwrap_or(usize::MAX)
        });
        self.budgets.encoded_bytes = measure(self);
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

/// The H9 section version for these observations: v4 iff a key row
/// carries the `unknown` metadata label, else v3 iff a
/// not-attributed count is present, else v2 iff a KEM creation or
/// role label is present, otherwise v1. The single version
/// authority behind the JSON section, the JSONL row payloads and
/// the pass marker.
pub(crate) fn observations_version(observations: &ObjectObservations) -> u8 {
    if observations
        .key_operations
        .iter()
        .any(|row| row.metadata_at_use == METADATA_UNKNOWN)
    {
        return OBSERVATIONS_VERSION_V4;
    }
    if !observations.unattributed.is_empty() {
        return OBSERVATIONS_VERSION_V3;
    }
    let kem = observations
        .objects
        .iter()
        .any(|row| matches!(row.creation, Some("encapsulate" | "decapsulate")))
        || observations
            .key_operations
            .iter()
            .any(|row| matches!(row.role, "encapsulation_key" | "decapsulation_key"));
    if kem {
        OBSERVATIONS_VERSION_V2
    } else {
        OBSERVATIONS_VERSION
    }
}

/// Render one not-attributed counter row: reason name and count only.
pub(crate) fn unattributed_row_json(row: &UnattributedRow) -> serde_json::Value {
    serde_json::json!({
        "reason": row.reason,
        "count": row.count,
    })
}

/// Render the whole section: the exact frozen keys. The single
/// renderer behind JSON, JSONL row payloads and byte measurement —
/// every consumer reads these shapes. The version follows the
/// content (see [`observations_version`]): v2 iff a KEM creation
/// or role label is present, otherwise byte-stable v1.
pub(crate) fn object_observations_json(observations: &ObjectObservations) -> serde_json::Value {
    let version = observations_version(observations);
    let mut section = serde_json::json!({
        "version": version,
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
    });
    if version >= OBSERVATIONS_VERSION_V3
        && let Some(map) = section.as_object_mut()
    {
        map.insert(
            "unattributed".to_string(),
            serde_json::Value::Array(
                observations
                    .unattributed
                    .iter()
                    .map(unattributed_row_json)
                    .collect(),
            ),
        );
        // Keep the frozen key order: `unattributed` sits beside the
        // row buckets, before `gaps`/`budgets`.
        let mut ordered = serde_json::Map::new();
        for key in [
            "version",
            "revision",
            "status",
            "reason",
            "sessions",
            "objects",
            "key_operations",
            "unknown_key_operations",
            "unattributed",
            "gaps",
            "budgets",
        ] {
            if let Some(value) = map.remove(key) {
                ordered.insert(key.to_string(), value);
            }
        }
        *map = ordered;
    }
    section
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
/// Guarded (N1): capture commits only from retained Joint evidence;
/// without it the section stays unavailable, exactly as before.
pub(crate) mod producer {
    use super::*;
    use crate::semantics_key_use::{FeedMode, JointStaging, KeyUseReducer};
    use crate::semantics_objects::{
        Attribution, Birth, CreationFamily, FieldState, FieldValue, Lifetime, MetadataView,
        ObjectGap, ObjectProjection, ObjectView, QueryStatus, SessionOrigin, SessionState,
        SessionView, ViewOrigin, field_index,
    };
    use p11scope_ebpf_common::object_policy::{SafeAttributeKind, SafeCurve};

    /// Commit one immutable revision from the live reducers: the one
    /// typed producer-to-projection mapping. Status derives from the
    /// capture-wide feed census plus refusal evidence: any Joint
    /// feed carries object authority (S1Only siblings contribute
    /// unknown-key S1 facts, never a refusal); with no Joint feed
    /// the reason names the loss. Rows aggregate per-operation
    /// reducer state into frozen aggregate rows; budgets measure.
    /// The linked entry (the 0.6.0 world the committed suites model);
    /// lanes commit here when linked, else through
    /// `commit_with_journal_linked`.
    pub(crate) fn commit(
        revision: u64,
        stagings: &[&JointStaging],
        model: &ObjectProjection,
        keyuse: &KeyUseReducer,
    ) -> ObjectObservations {
        commit_with_journal_linked(revision, stagings, model, keyuse, true)
    }

    /// Commit with the lane's latched journal linkage: with no Joint
    /// feed and no linked producer the reason is `journal_unavailable`
    /// (OD33/R-50); every other census maps exactly as before.
    pub(crate) fn commit_with_journal_linked(
        revision: u64,
        stagings: &[&JointStaging],
        model: &ObjectProjection,
        keyuse: &KeyUseReducer,
        journal_linked: bool,
    ) -> ObjectObservations {
        let evidence = keyuse.evidence();
        let joint = stagings
            .iter()
            .any(|staging| staging.mode() == FeedMode::Joint);
        // A tripped no-progress watchdog held the lane for exit: its
        // feeds left Joint for good, so the census is partial under
        // lost authority, the exact rows kept beside the counts. A
        // semantic loss that disposed staged history while the feed
        // stays Joint is lost authority too: a counted `record_lost`
        // never sits under `populated`.
        let lost = stagings.iter().any(|staging| {
            staging.degraded_loss() || staging.watchdog_tripped() || staging.history_disposed() > 0
        });
        let fallback = stagings.iter().any(|staging| staging.fell_back());
        let unattributed = collect_unattributed(stagings);
        // Joint never stops as a whole: a feed that fell back or lost
        // authority keeps every already-attributed and S1-preserved
        // row under `partial`, with its unattributed calls counted
        // beside them. Only a census with no evidence at all (no
        // rows, no sessions, no counted loss) stays unavailable.
        let has_evidence = !unattributed.is_empty()
            || !keyuse.aggregates().is_empty()
            || keyuse
                .unknown_counters()
                .iter()
                .any(|counters| counters.is_live())
            || !model.sessions.is_empty()
            || !model.objects.is_empty();
        let (status, reason) = if joint && evidence.partial {
            (ObsStatus::Partial, "row_budget_exhausted")
        } else if joint && lost {
            (ObsStatus::Partial, "authority_lost")
        } else if joint && fallback {
            (ObsStatus::Partial, "proof_refused_fallback")
        } else if joint {
            (ObsStatus::Populated, "none")
        } else if lost && has_evidence {
            (ObsStatus::Partial, "authority_lost")
        } else if fallback && has_evidence {
            (ObsStatus::Partial, "proof_refused_fallback")
        } else if lost {
            (ObsStatus::Unavailable, "authority_lost")
        } else if fallback {
            (ObsStatus::Unavailable, "proof_refused_fallback")
        } else if journal_linked {
            (ObsStatus::Unavailable, "bootstrap_unavailable")
        } else {
            (ObsStatus::Unavailable, "journal_unavailable")
        };
        let mut observations = ObjectObservations {
            revision,
            status,
            reason,
            sessions: model.sessions.iter().map(session_row).collect(),
            objects: model.objects.iter().map(object_row).collect(),
            key_operations: Vec::new(),
            unknown_key_operations: Vec::new(),
            unattributed,
            gaps: Vec::new(),
            gaps_suppressed: 0,
            budgets: ObsBudgets {
                key_limit: keyuse.capacity(),
                key_occupied: keyuse.aggregates().len(),
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

    /// Count what no per-key row can claim, per finite reason, from
    /// the feeds' retained counters. Derived only from counts
    /// already retained — no new capture. Zero reasons are omitted.
    pub(crate) fn unattributed(stagings: &[&JointStaging]) -> Vec<UnattributedRow> {
        collect_unattributed(stagings)
    }

    fn collect_unattributed(stagings: &[&JointStaging]) -> Vec<UnattributedRow> {
        let sum = |pick: &dyn Fn(&JointStaging) -> u64| {
            stagings
                .iter()
                .fold(0u64, |total, staging| total.saturating_add(pick(staging)))
        };
        let counts: [(&str, u64); 5] = [
            (
                "started_before_attach",
                sum(&|staging| staging.pre_attach_direct()),
            ),
            (
                "record_lost",
                sum(&|staging| {
                    staging
                        .history_disposed()
                        .saturating_add(staging.degraded_loss_direct())
                }),
            ),
            (
                "watchdog_no_progress",
                sum(&|staging| staging.watchdog_unsealed()),
            ),
            (
                "unmodelled_call_shape",
                sum(&|staging| staging.unsealable_direct()),
            ),
            (
                "proof_refused_fallback",
                sum(&|staging| {
                    staging
                        .fallback_replayed()
                        .saturating_add(staging.degraded_fallback_direct())
                }),
            ),
        ];
        counts
            .into_iter()
            .filter(|(_, count)| *count > 0)
            .map(|(reason, count)| UnattributedRow { reason, count })
            .collect()
    }

    /// Render the reducer's retained aggregate buckets and fixed
    /// unknown summaries into proved-key rows and capture-wide
    /// unknown rows. The reducer partitions terminals once per
    /// primary operation role at close time; this mapping only
    /// renders (sorted, stable) — it never re-partitions.
    fn aggregate_key_use(
        observations: &mut ObjectObservations,
        model: &ObjectProjection,
        keyuse: &KeyUseReducer,
    ) {
        use crate::semantics_key_use::{UNKNOWN_CATEGORIES, UNKNOWN_REASONS};
        let live: std::collections::BTreeSet<u64> =
            model.objects.iter().map(|view| view.id.as_u64()).collect();
        let mut dangling = 0u64;
        let mut key_rows: Vec<KeyAggRow> = Vec::with_capacity(keyuse.aggregates().len());
        for (bucket, counters) in keyuse.aggregates() {
            if !live.contains(&bucket.object) {
                dangling = dangling.saturating_add(counters.started);
            }
            key_rows.push(KeyAggRow {
                instance: bucket.instance.label(),
                object: bucket.object,
                category: bucket.category,
                role: bucket.role,
                metadata_at_use: bucket.metadata,
                unit: crate::semantics_key_use::unit_for(bucket.category),
                started: counters.started,
                completed: counters.completed,
                failed: counters.failed,
                cancelled: counters.cancelled,
                unknown: counters.unknown,
                active: counters.active,
                key_join_lost: counters.key_join_lost,
            });
        }
        key_rows.sort_by(|a, b| {
            (&a.instance, a.object, a.category, a.role, a.metadata_at_use).cmp(&(
                &b.instance,
                b.object,
                b.category,
                b.role,
                b.metadata_at_use,
            ))
        });
        let mut unknown_rows = Vec::new();
        let ever_live = keyuse.unknown_ever_live();
        for (index, counters) in keyuse.unknown_counters().iter().enumerate() {
            // Live summaries emit; drained summaries emit their
            // zero-active replacement iff the cumulative consumer
            // already saw them live (N9) — never stale activity.
            if !counters.is_live() && !ever_live[index] {
                continue;
            }
            let category = UNKNOWN_CATEGORIES[index / UNKNOWN_REASONS.len()];
            let reason = UNKNOWN_REASONS[index % UNKNOWN_REASONS.len()];
            unknown_rows.push(UnknownAggRow {
                category,
                reason,
                unit: crate::semantics_key_use::unit_for(category),
                completed: counters.completed,
                failed: counters.failed,
                cancelled: counters.cancelled,
                unknown: counters.unknown,
                active: counters.active,
            });
        }
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
        if observations.gaps.len() > super::GAPS_CAPACITY {
            let suppressed = observations.gaps.len() - super::GAPS_CAPACITY;
            observations.gaps.truncate(super::GAPS_CAPACITY);
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
                ViewOrigin::Created(CreationFamily::Encapsulate) => Some("encapsulate"),
                ViewOrigin::Created(CreationFamily::Decapsulate) => Some("decapsulate"),
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
            label: view.label.map(crate::semantics_key_use::metadata_label),
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
