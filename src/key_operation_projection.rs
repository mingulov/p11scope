//! SPDX-License-Identifier: GPL-3.0-or-later
//! SPDX-FileCopyrightText: 2026 Denis Mingulov <denis@mingulov.com>
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
/// Section version 5 (F16, 7.05 PQC): v4 vocabulary plus the
/// eighteen PQC parameter-set labels and the `parameter_set` key in
/// the requested/established/query metadata blocks. The renderer
/// emits v5 exactly when PQC content is present; v1–v4 output stays
/// byte-stable.
pub(crate) const OBSERVATIONS_VERSION_V5: u8 = 5;
/// Section version 6 (R2 new-site): v5 vocabulary plus the HKDF and
/// generic-secret size labels, the Montgomery/Edwards curve labels,
/// the CKK_HKDF key-type code, the 12/48 value lengths and the new
/// curve names. The renderer emits v6 exactly when such content is
/// present; v1–v5 output stays byte-stable.
pub(crate) const OBSERVATIONS_VERSION_V6: u8 = 6;
/// Section version 7 (keymeta inferred keys): v6 vocabulary plus the
/// `inferred_family`/`inferred_size` row keys. The renderer emits v7
/// exactly when a row carries non-blank inferred content or a
/// v7-only gap does; v1–v6 output stays byte-stable.
pub(crate) const OBSERVATIONS_VERSION_V7: u8 = 7;
/// Section version 9 (unknown-row mechanism detail): v7 vocabulary
/// plus the `mechanisms` key on unknown-key rows (by-number
/// terminal counts per observed mechanism id) and the
/// `unknown_mechanism_rows_refused` gap. Version 8 is taken by the
/// separate Task 7 provider section (shared allocator, spec
/// §10.1). The renderer emits v9 exactly when an unknown row
/// carries mechanism detail or the v9-only gap does; v1–v7 output
/// stays byte-stable.
pub(crate) const OBSERVATIONS_VERSION_V9: u8 = 9;
/// The named reason an unseen metadata field carries at v6 when its
/// creation template carried more than the eight observed cells
/// (controller KEYMETA-T1 rulings 2026-11-16, ruling 2). The closed
/// reason vocabulary has four members (fix round 4 adds the
/// partly-read reason); every other field carries null.
pub(crate) const TRUNCATED_TEMPLATE_REASON: &str =
    "template truncated (first 8 attributes captured)";
/// The named reason a seen-but-unclassifiable metadata field carries
/// at v6: the kind appeared in the retained window with a value
/// outside the approved finite set (or an unavailable, malformed or
/// size-only cell). Never the truncation reason, which is reserved
/// for fields never seen.
pub(crate) const UNSUPPORTED_TEMPLATE_VALUE_REASON: &str =
    "template value outside approved finite set";
/// The named reason an Edwards/Montgomery curve field carries at v6
/// when its key type stays unlabeled: the established curve is
/// mismatched for the key type, or no curve was established on a
/// complete template (controller KEYMETA-T1 rulings 2026-11-16,
/// ruling 1). Only created objects whose own template was seen
/// carry it, never the private half of a keypair (fix round 4).
/// On truncated templates the truncation reason keeps precedence
/// for unseen curves.
pub(crate) const CURVE_UNUSABLE_REASON: &str = "curve unusable for key type";
/// The named reason an unseen metadata field carries at v6 when its
/// creation template was only partly read (fix round 4): the wire
/// HEADER_READ_FAILURE or INVALID_SPAN bit. Observed cells still
/// promote; unseen fields name this reason, which keeps precedence
/// over truncation.
pub(crate) const PARTLY_READ_TEMPLATE_REASON: &str = "template partly read";
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
/// yet); `live_joint_feed_absent` names retained folded-Joint
/// evidence with no live Joint feed (partial, never unavailable).
pub(crate) const REASON_LABELS: [&str; 10] = [
    "none",
    "bootstrap_unavailable",
    "journal_unavailable",
    "live_joint_feed_absent",
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
    /// H9 section v5 metadata block keys (F16, 7.05 PQC): the six
    /// frozen keys plus `parameter_set`. Pins both the
    /// requested/established blocks and the query block.
    pub(crate) const METADATA_KEYS_V5: [&str; 7] = [
        "class",
        "key_type",
        "token",
        "value_len",
        "modulus_bits",
        "ec_params",
        "parameter_set",
    ];
    pub(crate) const FIELD_KEYS: [&str; 2] = ["status", "value"];
    /// H9 section v6 metadata field keys (R2 new-site + keymeta
    /// §6/K5 + the truncation reason): status/value plus the
    /// per-field `source` and `reason`.
    pub(crate) const FIELD_KEYS_V6: [&str; 4] = ["status", "value", "source", "reason"];
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
    /// H9 section v6 curve vocabulary (R2 new-site): the three NIST
    /// names plus the Montgomery/Edwards names.
    pub(crate) const CURVE_LABELS_V6: [&str; 7] = [
        "secp256r1",
        "secp384r1",
        "secp521r1",
        "x25519",
        "x448",
        "ed25519",
        "ed448",
    ];

    /// Frozen metadata-at-use labels: established RSA modulus bits, AES
    /// value length in bits, EC finite curve. (R2 new-site: complete
    /// finite creation templates establish on success, so these labels
    /// now cover promoted facts too; incomplete requested triples
    /// still never label.)
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

    /// H9 section v5 metadata vocabulary (F16, 7.05 PQC): the v4
    /// labels plus the eighteen PQC parameter-set labels.
    pub(crate) const METADATA_LABELS_V5: [&str; 31] = [
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
        "ml_dsa_44",
        "ml_dsa_65",
        "ml_dsa_87",
        "ml_kem_512",
        "ml_kem_768",
        "ml_kem_1024",
        "slh_dsa_sha2_128s",
        "slh_dsa_shake_128s",
        "slh_dsa_sha2_128f",
        "slh_dsa_shake_128f",
        "slh_dsa_sha2_192s",
        "slh_dsa_shake_192s",
        "slh_dsa_sha2_192f",
        "slh_dsa_shake_192f",
        "slh_dsa_sha2_256s",
        "slh_dsa_shake_256s",
        "slh_dsa_sha2_256f",
        "slh_dsa_shake_256f",
    ];

    /// H9 section v6 metadata vocabulary (R2 new-site): the v5
    /// labels plus the four Montgomery/Edwards curve labels, the six
    /// HKDF size labels and the six generic-secret size labels.
    pub(crate) const METADATA_LABELS_V6: [&str; 47] = [
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
        "ml_dsa_44",
        "ml_dsa_65",
        "ml_dsa_87",
        "ml_kem_512",
        "ml_kem_768",
        "ml_kem_1024",
        "slh_dsa_sha2_128s",
        "slh_dsa_shake_128s",
        "slh_dsa_sha2_128f",
        "slh_dsa_shake_128f",
        "slh_dsa_sha2_192s",
        "slh_dsa_shake_192s",
        "slh_dsa_sha2_192f",
        "slh_dsa_shake_192f",
        "slh_dsa_sha2_256s",
        "slh_dsa_shake_256s",
        "slh_dsa_sha2_256f",
        "slh_dsa_shake_256f",
        "x25519",
        "x448",
        "ed25519",
        "ed448",
        "hkdf_96",
        "hkdf_128",
        "hkdf_192",
        "hkdf_256",
        "hkdf_384",
        "hkdf_other",
        "generic_96",
        "generic_128",
        "generic_192",
        "generic_256",
        "generic_384",
        "generic_other",
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
    /// H9 section v7 proved-key row keys: the frozen 13 plus the
    /// `inferred_family`/`inferred_size` keys. v1–v6 rows keep the
    /// frozen 13; v7 sections carry all 15 on every proved row.
    pub(crate) const KEY_ROW_KEYS_V7: [&str; 15] = [
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
        "inferred_family",
        "inferred_size",
    ];
    /// The closed `inferred_family` keys (§10.2): reasons ride `-v`
    /// text, never this shape.
    pub(crate) const INFERRED_FAMILY_KEYS: [&str; 6] = [
        "status",
        "value",
        "completions",
        "conflict_value",
        "conflict_completions",
        "further_conflicts",
    ];
    /// The closed `inferred_size` keys (§10.2): reasons ride `-v`
    /// text, never this shape (`conflict_completions` is absent by
    /// design — `conflict_detail` is the second-value carrier).
    pub(crate) const INFERRED_SIZE_KEYS: [&str; 5] = [
        "status",
        "detail",
        "completions",
        "conflict_detail",
        "further_conflicts",
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
    /// H9 section v9 unknown-key row keys: the frozen 8 plus the
    /// `mechanisms` by-number detail. v1–v7 rows keep the frozen 8;
    /// v9 sections carry all 9 on every unknown row.
    pub(crate) const UNKNOWN_ROW_KEYS_V9: [&str; 9] = [
        "category",
        "reason",
        "unit",
        "completed",
        "failed",
        "cancelled",
        "unknown",
        "active",
        "mechanisms",
    ];
    /// The closed unknown-row mechanism entry keys (v9): the numeric
    /// mechanism id plus its terminal count. No name key exists —
    /// names ride `-v` text only, never this shape.
    pub(crate) const UNKNOWN_MECH_ROW_KEYS: [&str; 2] = ["mechanism", "terminals"];

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
/// one of `scalar` / `curve` applies per field kind. `source` names
/// the proof behind an established value (`query` or
/// `creation_success`); it renders only at section version 6+ and is
/// `None` for every other state. `reason` names why a field stays
/// unknown — or, for a mismatched Edwards/Montgomery curve, why its
/// key type stays unlabeled (the closed three-member vocabulary); it
/// renders only at v6+ and is `None` for every other field.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct MetadataField {
    pub status: &'static str,
    pub scalar: Option<u16>,
    pub curve: Option<&'static str>,
    pub source: Option<&'static str>,
    pub reason: Option<&'static str>,
}

/// The seven fixed metadata slots, requested or established. The
/// `parameter_set` slot renders only at v5+ (see
/// [`observations_version`]); v1–v4 sections carry the six frozen keys.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct MetadataBlock {
    pub class: MetadataField,
    pub key_type: MetadataField,
    pub token: MetadataField,
    pub value_len: MetadataField,
    pub modulus_bits: MetadataField,
    pub ec_params: MetadataField,
    pub parameter_set: MetadataField,
}

/// One query outcome per field (latest status, not validity). The
/// `parameter_set` outcome renders only at v5+.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct QueriesBlock {
    pub class: &'static str,
    pub key_type: &'static str,
    pub token: &'static str,
    pub value_len: &'static str,
    pub modulus_bits: &'static str,
    pub ec_params: &'static str,
    pub parameter_set: &'static str,
}

/// Whether a `metadata_at_use`/object label is one of the eighteen
/// F16 PQC parameter-set labels. The single version trigger behind
/// v5 sections; the contract test pins agreement with
/// `contract::METADATA_LABELS_V5`.
pub(crate) fn is_pqc_metadata_label(label: &str) -> bool {
    matches!(
        label,
        "ml_dsa_44"
            | "ml_dsa_65"
            | "ml_dsa_87"
            | "ml_kem_512"
            | "ml_kem_768"
            | "ml_kem_1024"
            | "slh_dsa_sha2_128s"
            | "slh_dsa_shake_128s"
            | "slh_dsa_sha2_128f"
            | "slh_dsa_shake_128f"
            | "slh_dsa_sha2_192s"
            | "slh_dsa_shake_192s"
            | "slh_dsa_sha2_192f"
            | "slh_dsa_shake_192f"
            | "slh_dsa_sha2_256s"
            | "slh_dsa_shake_256s"
            | "slh_dsa_sha2_256f"
            | "slh_dsa_shake_256f"
    )
}

/// Whether a `metadata_at_use`/object label is one of the sixteen
/// R2 new-site labels. Part of the version trigger behind v6
/// sections; the contract test pins agreement with
/// `contract::METADATA_LABELS_V6`.
pub(crate) fn is_newsite_metadata_label(label: &str) -> bool {
    matches!(
        label,
        "x25519"
            | "x448"
            | "ed25519"
            | "ed448"
            | "hkdf_96"
            | "hkdf_128"
            | "hkdf_192"
            | "hkdf_256"
            | "hkdf_384"
            | "hkdf_other"
            | "generic_96"
            | "generic_128"
            | "generic_192"
            | "generic_256"
            | "generic_384"
            | "generic_other"
    )
}

/// Whether an `ec_params` block curve name is one of the four R2
/// new-site names. Part of the version trigger behind v6 sections.
pub(crate) fn is_newsite_curve_name(name: &str) -> bool {
    matches!(name, "x25519" | "x448" | "ed25519" | "ed448")
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
    /// The creation template carried more than the eight observed
    /// cells. Internal only (JSON carries the per-field reasons):
    /// feeds the `-v` truncation count and the v6 trigger.
    pub creation_truncated: bool,
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
    /// v7 inferred keys (§10.2): `Some` on every proved row of a v7
    /// section (blank states render unknown), `None` below v7, so
    /// v1–v6 rows keep the frozen 13 keys byte-stable.
    pub inferred: Option<crate::semantics_key_use::RowInference>,
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
    /// By-number mechanism detail (v9): terminals partitioned here
    /// per observed mechanism id, sorted by id. Mechanism-less
    /// terminals (orphan ends, unreadable ids) keep no entry: the
    /// row counters stay exact while this breakdown covers
    /// mechanism-bearing terminals only.
    pub mechanisms: Vec<UnknownMechCount>,
}

/// One unknown-row mechanism entry: the numeric mechanism id plus
/// the terminals partitioned into its row with that id.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct UnknownMechCount {
    pub mechanism: u64,
    pub terminals: u64,
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
/// curve name (never key material). The `source` and `reason` keys
/// render only at v6+: v1–v5 sections keep the two frozen keys
/// byte-stable.
pub(crate) fn metadata_field_json(
    field: &MetadataField,
    curve: bool,
    version: u8,
) -> serde_json::Value {
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
    let mut out = serde_json::json!({
        "status": field.status,
        "value": value,
    });
    if version >= OBSERVATIONS_VERSION_V6
        && let Some(map) = out.as_object_mut()
    {
        map.insert(
            "source".to_string(),
            field
                .source
                .map(serde_json::Value::from)
                .unwrap_or(serde_json::Value::Null),
        );
        map.insert(
            "reason".to_string(),
            field
                .reason
                .map(serde_json::Value::from)
                .unwrap_or(serde_json::Value::Null),
        );
    }
    out
}

/// Render one seven-slot metadata block (requested or established).
/// The `parameter_set` key renders only at v5+: v1–v4 sections keep
/// the six frozen keys byte-stable. Every field carries `source`
/// and `reason` only at v6+.
pub(crate) fn metadata_block_json(block: &MetadataBlock, version: u8) -> serde_json::Value {
    let mut out = serde_json::json!({
        "class": metadata_field_json(&block.class, false, version),
        "key_type": metadata_field_json(&block.key_type, false, version),
        "token": metadata_field_json(&block.token, false, version),
        "value_len": metadata_field_json(&block.value_len, false, version),
        "modulus_bits": metadata_field_json(&block.modulus_bits, false, version),
        "ec_params": metadata_field_json(&block.ec_params, true, version),
    });
    if version >= OBSERVATIONS_VERSION_V5
        && let Some(map) = out.as_object_mut()
    {
        map.insert(
            "parameter_set".to_string(),
            metadata_field_json(&block.parameter_set, false, version),
        );
    }
    out
}

/// Render one per-field query-outcome block. The `parameter_set`
/// outcome renders only at v5+.
pub(crate) fn queries_block_json(block: &QueriesBlock, version: u8) -> serde_json::Value {
    let mut out = serde_json::json!({
        "class": block.class,
        "key_type": block.key_type,
        "token": block.token,
        "value_len": block.value_len,
        "modulus_bits": block.modulus_bits,
        "ec_params": block.ec_params,
    });
    if version >= OBSERVATIONS_VERSION_V5
        && let Some(map) = out.as_object_mut()
    {
        map.insert(
            "parameter_set".to_string(),
            serde_json::Value::from(block.parameter_set),
        );
    }
    out
}

/// Render one session row: the exact frozen keys.
pub(crate) fn session_row_json(row: &SessionRow) -> serde_json::Value {
    serde_json::json!({
        "session": row.session,
        "origin": row.origin,
        "status": row.status,
    })
}

/// Render one object row: the exact frozen keys. Callers pass the
/// section version from [`observations_version`]; the metadata
/// blocks carry `parameter_set` only at v5+.
pub(crate) fn object_row_json(row: &ObjectRow, version: u8) -> serde_json::Value {
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
        "requested": metadata_block_json(&row.requested, version),
        "established": metadata_block_json(&row.established, version),
        "queries": queries_block_json(&row.queries, version),
        "label": row.label,
        "successful_references": row.successful_references,
        "successful_key_references": row.successful_key_references,
        "accessing_sessions": row.accessing_sessions,
    })
}

/// Render one proved-key aggregate row: the exact frozen keys,
/// plus the v7 inferred keys exactly when the row carries them.
pub(crate) fn key_row_json(row: &KeyAggRow) -> serde_json::Value {
    let mut rendered = serde_json::json!({
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
    });
    if let Some(inferred) = row.inferred.as_ref() {
        let object = rendered.as_object_mut().expect("row object");
        object.insert(
            "inferred_family".to_string(),
            inferred_family_json(&inferred.family),
        );
        object.insert(
            "inferred_size".to_string(),
            inferred_size_json(&inferred.size),
        );
    }
    rendered
}

/// Render one inferred family (§10.2 closed shape): status, the
/// first value or null, supporting completions, and the pinned
/// conflict pair plus further count when present.
pub(crate) fn inferred_family_json(
    family: &crate::semantics_key_use::FamilyState,
) -> serde_json::Value {
    use crate::semantics_key_use::InferredStatus;
    let mut rendered = serde_json::json!({
        "status": match family.status {
            InferredStatus::Inferred => "inferred",
            InferredStatus::Unknown => "unknown",
            InferredStatus::Conflicting => "conflicting",
            InferredStatus::Unsupported => "unsupported",
        },
        "value": family.value.map(crate::keymeta::family_value),
        "completions": family.completions,
    });
    let object = rendered.as_object_mut().expect("family object");
    if let Some(conflict) = family.conflict_value {
        object.insert(
            "conflict_value".to_string(),
            serde_json::Value::String(crate::keymeta::family_value(conflict).to_string()),
        );
        object.insert(
            "conflict_completions".to_string(),
            serde_json::json!(family.conflict_completions),
        );
    }
    if family.further > 0 {
        object.insert(
            "further_conflicts".to_string(),
            serde_json::json!(family.further),
        );
    }
    rendered
}

/// Render one inferred size (§10.2 closed shape).
pub(crate) fn inferred_size_json(size: &crate::semantics_key_use::SizeState) -> serde_json::Value {
    use crate::semantics_key_use::InferredStatus;
    let mut rendered = serde_json::json!({
        "status": match size.status {
            InferredStatus::Inferred => "inferred",
            InferredStatus::Unknown => "unknown",
            InferredStatus::Conflicting => "conflicting",
            InferredStatus::Unsupported => "unsupported",
        },
        "detail": size
            .detail
            .as_ref()
            .map(|(detail, tag)| size_detail_json(detail, *tag)),
        "completions": size.completions,
    });
    let object = rendered.as_object_mut().expect("size object");
    if let Some((detail, tag)) = size.conflict_detail.as_ref() {
        object.insert(
            "conflict_detail".to_string(),
            size_detail_json(detail, *tag),
        );
    }
    if size.further > 0 {
        object.insert(
            "further_conflicts".to_string(),
            serde_json::json!(size.further),
        );
    }
    rendered
}

/// Render one size detail (§10.2 `detail` shapes): the kind tag, the
/// size params, and the first evidence tag.
fn size_detail_json(
    detail: &crate::keymeta::SizeDetail,
    tag: crate::keymeta::EvidenceTag,
) -> serde_json::Value {
    use crate::keymeta::{SizeDetail, evidence_value};
    let evidence = evidence_value(tag);
    match detail {
        SizeDetail::Rsa {
            size_class,
            modulus_bytes,
        } => {
            if size_class.is_some() {
                serde_json::json!({
                    "kind": "rsa",
                    "size_class": size_class,
                    "modulus_bytes": modulus_bytes,
                    "evidence": evidence,
                })
            } else {
                serde_json::json!({
                    "kind": "rsa_nonstandard",
                    "modulus_bytes": modulus_bytes,
                    "evidence": evidence,
                })
            }
        }
        SizeDetail::Ec { curve, octets } => serde_json::json!({
            "kind": "ec",
            "curve": curve,
            "octets": octets,
            "evidence": evidence,
        }),
        SizeDetail::Eddsa { curve, octets } => serde_json::json!({
            "kind": "eddsa",
            "curve": curve,
            "octets": octets,
            "evidence": evidence,
        }),
        SizeDetail::DsaClass { label, octets } => serde_json::json!({
            "kind": "dsa_class",
            "label": label,
            "octets": octets,
            "evidence": evidence,
        }),
        SizeDetail::PqcSet {
            parameter_set,
            octets,
        } => serde_json::json!({
            "kind": "pqc_set",
            "parameter_set": parameter_set,
            "octets": octets,
            "evidence": evidence,
        }),
        SizeDetail::WrappedMaterial {
            material_octets,
            octets,
        } => serde_json::json!({
            "kind": "wrapped_material",
            "material_octets": material_octets,
            "octets": octets,
            "evidence": evidence,
            "about": "wrapped",
        }),
    }
}

/// Render one unknown-key summary row: the exact frozen keys (no
/// `started` — starts are never fabricated into the unknown bucket).
/// The `mechanisms` key renders only at v9+: v1–v7 rows keep the
/// frozen 8 keys byte-stable.
pub(crate) fn unknown_row_json(row: &UnknownAggRow, version: u8) -> serde_json::Value {
    let mut out = serde_json::json!({
        "category": row.category,
        "reason": row.reason,
        "unit": row.unit,
        "completed": row.completed,
        "failed": row.failed,
        "cancelled": row.cancelled,
        "unknown": row.unknown,
        "active": row.active,
    });
    if version >= OBSERVATIONS_VERSION_V9
        && let Some(map) = out.as_object_mut()
    {
        map.insert(
            "mechanisms".to_string(),
            row.mechanisms
                .iter()
                .map(|entry| {
                    serde_json::json!({
                        "mechanism": entry.mechanism,
                        "terminals": entry.terminals,
                    })
                })
                .collect(),
        );
    }
    out
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

/// The H9 section version for these observations: v6 iff R2
/// new-site content is present, else v5 iff PQC content is present
/// (a PQC label, a PQC key-type scalar, or a non-blank
/// parameter-set field/query), else v4 iff a key row carries the
/// `unknown` metadata label, else v3 iff a not-attributed count is
/// present, else v2 iff a KEM creation or role label is present,
/// otherwise v1. The single version authority behind the JSON
/// section, the JSONL row payloads and the pass marker.
fn has_pqc_content(observations: &ObjectObservations) -> bool {
    const PQC_KEY_TYPES: [u16; 3] = [0x49, 0x4a, 0x4b];
    if observations
        .key_operations
        .iter()
        .any(|row| is_pqc_metadata_label(row.metadata_at_use))
    {
        return true;
    }
    observations.objects.iter().any(|row| {
        row.label.is_some_and(is_pqc_metadata_label)
            || [row.requested, row.established].iter().any(|block| {
                block
                    .key_type
                    .scalar
                    .is_some_and(|scalar| PQC_KEY_TYPES.contains(&scalar))
                    || block.parameter_set.scalar.is_some()
                    || block.parameter_set.curve.is_some()
            })
            || row.queries.parameter_set != "not_queried"
    })
}

/// R2 new-site content: a new label, the HKDF key-type scalar, a
/// 12/48 value length, or a new curve name in any row or block —
/// or, keymeta §6/K5, any established field with a non-`query`
/// source (a view carrying `creation_success` emits v6, never v7) —
/// or, controller KEYMETA-T1 rulings 2026-11-16 ruling 2, any view
/// created from a truncated template (so its truncation reasons are
/// never silently dropped below v6) — or any unsupported-value,
/// unusable-curve (fix round 3) or partly-read (fix round 4) reason
/// (so those reasons are never silently dropped on complete or
/// partly-read templates).
fn has_newsite_content(observations: &ObjectObservations) -> bool {
    if observations
        .key_operations
        .iter()
        .any(|row| is_newsite_metadata_label(row.metadata_at_use))
    {
        return true;
    }
    observations.objects.iter().any(|row| {
        row.label.is_some_and(is_newsite_metadata_label)
            || row.creation_truncated
            || [row.requested, row.established].iter().any(|block| {
                block.key_type.scalar.is_some_and(|scalar| scalar == 0x42)
                    || block
                        .value_len
                        .scalar
                        .is_some_and(|scalar| scalar == 12 || scalar == 48)
                    || block.ec_params.curve.is_some_and(is_newsite_curve_name)
                    || block_has_named_reason(block)
            })
            || block_has_creation_source(&row.established)
    })
}

/// Whether any field of one block carries an unsupported-value,
/// unusable-curve or partly-read reason: v6 content on its own, so
/// the reason never silently drops below v6.
fn block_has_named_reason(block: &MetadataBlock) -> bool {
    [
        block.class,
        block.key_type,
        block.token,
        block.value_len,
        block.modulus_bits,
        block.ec_params,
        block.parameter_set,
    ]
    .iter()
    .any(|field| {
        field.reason.is_some_and(|reason| {
            reason == UNSUPPORTED_TEMPLATE_VALUE_REASON
                || reason == CURVE_UNUSABLE_REASON
                || reason == PARTLY_READ_TEMPLATE_REASON
        })
    })
}

/// Whether any field of one established block was proven by a
/// successful creation return rather than a query.
fn block_has_creation_source(block: &MetadataBlock) -> bool {
    const CREATION_SUCCESS: &str = "creation_success";
    [
        block.class,
        block.key_type,
        block.token,
        block.value_len,
        block.modulus_bits,
        block.ec_params,
        block.parameter_set,
    ]
    .iter()
    .any(|field| {
        field
            .source
            .is_some_and(|source| source == CREATION_SUCCESS)
    })
}

/// Keymeta v7 content: any proved row carrying non-blank inferred
/// keys (§10.1 — family alone emits v7; the off-mode size hint never
/// triggers a version on its own).
fn has_inferred_content(observations: &ObjectObservations) -> bool {
    observations.key_operations.iter().any(|row| {
        row.inferred
            .as_ref()
            .is_some_and(|keys| keys.is_v7_content())
    })
}

/// v7-only gap content: a refusal or residual that v1–v6 never carry.
/// A rowless park refusal still promotes its section to v7, so the
/// named gap never rides a version whose vocabulary forbids it.
fn has_v7_gap_content(observations: &ObjectObservations) -> bool {
    observations.gaps.iter().any(|gap| {
        gap.subject == "key_operation"
            && matches!(
                gap.reason,
                "corroboration_mismatch" | "wrapped_park_refused"
            )
    })
}

/// v9 content: an unknown row carrying mechanism detail, or the
/// v9-only refusal gap (a rowless refusal still promotes its section
/// to v9, so the named gap never rides a version whose vocabulary
/// forbids it).
fn has_v9_content(observations: &ObjectObservations) -> bool {
    if observations
        .unknown_key_operations
        .iter()
        .any(|row| !row.mechanisms.is_empty())
    {
        return true;
    }
    observations
        .gaps
        .iter()
        .any(|gap| gap.subject == "key_operation" && gap.reason == "unknown_mechanism_rows_refused")
}

pub(crate) fn observations_version(observations: &ObjectObservations) -> u8 {
    if has_v9_content(observations) {
        return OBSERVATIONS_VERSION_V9;
    }
    if has_inferred_content(observations) || has_v7_gap_content(observations) {
        return OBSERVATIONS_VERSION_V7;
    }
    if has_newsite_content(observations) {
        return OBSERVATIONS_VERSION_V6;
    }
    if has_pqc_content(observations) {
        return OBSERVATIONS_VERSION_V5;
    }
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
        "objects": observations.objects.iter().map(|row| object_row_json(row, version)).collect::<Vec<_>>(),
        "key_operations": observations.key_operations.iter().map(key_row_json).collect::<Vec<_>>(),
        "unknown_key_operations": observations.unknown_key_operations.iter().map(|row| unknown_row_json(row, version)).collect::<Vec<_>>(),
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
        Attribution, Birth, CreationFamily, FieldSource, FieldState, FieldValue, Lifetime,
        MetadataView, ObjectGap, ObjectProjection, ObjectView, QueryStatus, SessionOrigin,
        SessionState, SessionView, ViewOrigin, field_index,
    };
    use p11scope_ebpf_common::object_policy::{SafeAttributeKind, SafeCurve};

    /// The linked entry for suites that stage feeds without a
    /// registry (no folded evidence exists there): the 0.6.0 world
    /// the committed suites model. Production lanes commit through
    /// `commit_with_journal_linked` with the lane's folded evidence
    /// and latched linkage.
    #[cfg(test)]
    pub(crate) fn commit(
        revision: u64,
        stagings: &[&JointStaging],
        model: &ObjectProjection,
        keyuse: &KeyUseReducer,
    ) -> ObjectObservations {
        commit_with_journal_linked(
            revision,
            stagings,
            model,
            keyuse,
            &crate::discovery::caller_registry::instance_input::FoldedJointEvidence::default(),
            true,
        )
    }

    /// Commit one immutable revision from the live reducers: the one
    /// typed producer-to-projection mapping. Status derives from the
    /// capture-wide feed census plus refusal evidence: any Joint
    /// feed carries object authority (S1Only siblings contribute
    /// unknown-key S1 facts, never a refusal); with no Joint feed
    /// the reason names the loss. Rows aggregate per-operation
    /// reducer state into frozen aggregate rows; budgets measure.
    /// With no Joint feed, no loss, no fallback and no retained
    /// evidence the reason is `journal_unavailable` without a linked
    /// producer (OD33/R-50) and `bootstrap_unavailable` with one.
    /// Folded departed feeds lend their final authority and counters
    /// beside the live census, so a retirement never hides proved rows
    /// or erases named loss; only the live `joint` census drops the
    /// folded feed. A clean folded history with retained evidence
    /// stands as history under `populated`; retained evidence with
    /// no live Joint feed and no folded history is partial with
    /// `live_joint_feed_absent`, never unavailable. Every other
    /// census maps exactly as before.
    pub(crate) fn commit_with_journal_linked(
        revision: u64,
        stagings: &[&JointStaging],
        model: &ObjectProjection,
        keyuse: &KeyUseReducer,
        folded: &crate::discovery::caller_registry::instance_input::FoldedJointEvidence,
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
        // stays Joint is lost authority too: a current-segment
        // `record_lost` never sits under `populated`. A clean resume
        // clears the latches and baselines disposed history: the
        // closed segment stays counted beside a populated section.
        // A folded feed's ended segment lends the same authority.
        let lost = stagings.iter().any(|staging| {
            staging.degraded_loss()
                || staging.watchdog_tripped()
                || staging.history_disposed_since_resume() > 0
        }) || folded.lost();
        let fallback = stagings.iter().any(|staging| staging.fell_back()) || folded.fell_back();
        let mut unattributed = collect_unattributed(stagings);
        for (reason, count) in folded.rows() {
            if count == 0 {
                continue;
            }
            if let Some(row) = unattributed.iter_mut().find(|row| row.reason == reason) {
                row.count = row.count.saturating_add(count);
            } else {
                unattributed.push(UnattributedRow { reason, count });
            }
        }
        // Folded-only reasons join at the tail above; restore the
        // frozen publication order (same sort as `add_unattributed`).
        unattributed.sort_by_key(|row| {
            UNATTRIBUTED_REASONS
                .iter()
                .position(|known| *known == row.reason)
                .unwrap_or(usize::MAX)
        });
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
        // A proved folded Joint history carries the same row-budget
        // authority as a live Joint feed: the capture-wide reducer
        // still records refused rows after the last feed folds, so
        // the status must not clear to populated while refusals
        // stand. The live census stays separate, and a never-Joint
        // capture still bootstraps below.
        let joint_or_history = joint || folded.joint_history();
        let (status, reason) = if joint_or_history && evidence.partial {
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
        } else if has_evidence && folded.joint_history() {
            // The last Joint feed folded cleanly: no live feed, no
            // loss, but proved rows survive. They stand as history
            // under `populated`, never as a bootstrap that never
            // started.
            (ObsStatus::Populated, "none")
        } else if has_evidence {
            // Retained folded-Joint rows, objects, sessions or
            // counts with no live Joint feed and no folded
            // history: partial with the named reason, never
            // unavailable (only a census with no evidence at all
            // stays unavailable).
            (ObsStatus::Partial, "live_joint_feed_absent")
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
                inferred: Some(
                    keyuse
                        .inferred_map()
                        .get(bucket)
                        .cloned()
                        .unwrap_or_default(),
                ),
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
            // Commit-time only: inline detail arrives in first-seen
            // order, so the row sorts it by id here.
            let len = usize::from(counters.mech_len);
            let mut mechanisms: Vec<UnknownMechCount> = counters.mechs[..len]
                .iter()
                .map(|(id, terminals)| UnknownMechCount {
                    mechanism: *id,
                    terminals: *terminals,
                })
                .collect();
            mechanisms.sort_by_key(|entry| entry.mechanism);
            unknown_rows.push(UnknownAggRow {
                category,
                reason,
                unit: crate::semantics_key_use::unit_for(category),
                completed: counters.completed,
                failed: counters.failed,
                cancelled: counters.cancelled,
                unknown: counters.unknown,
                active: counters.active,
                mechanisms,
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
        // Corroboration mismatches are a counted residual, never a
        // conflict and never a coverage loss (no partial).
        let mismatches = keyuse.key_use_evidence().corroboration_mismatches;
        if mismatches > 0 {
            observations.gaps.push(GapRow {
                subject: "key_operation",
                reason: "corroboration_mismatch",
                repeats: mismatches,
            });
        }
        // Refused wrapped-material parks are inference-side, never
        // row loss (no partial): the count publishes as a named gap.
        let parks_refused = keyuse.key_use_evidence().parked_refused;
        if parks_refused > 0 {
            observations.gaps.push(GapRow {
                subject: "key_operation",
                reason: "wrapped_park_refused",
                repeats: parks_refused,
            });
        }
        // Refused unknown-mechanism detail is inference-side, never
        // row loss (no partial): the count publishes as a named gap.
        let mech_refused = keyuse.key_use_evidence().unknown_mechanism_refused;
        if mech_refused > 0 {
            observations.gaps.push(GapRow {
                subject: "key_operation",
                reason: "unknown_mechanism_rows_refused",
                repeats: mech_refused,
            });
        }
        // The row shape follows the same version decision as the
        // snapshot, marker and stream ([`observations_version`]):
        // v7 keeps the inferred keys on every proved row, whether a
        // row carries non-blank content or a v7-only gap does, so a
        // gap-driven v7 section still renders all 15 keys per row —
        // and v9 keeps them too (v9 is v7 vocabulary plus unknown
        // detail, so a mechanism-only v9 section still renders all
        // 15 keys per proved row). Below v7 every row drops its keys
        // (uniform fill above, frozen 13 below). Model gaps
        // (collected after this) never trigger v7 or v9, and the
        // key-side gaps sort before them under the 256-cap, so this
        // decision equals the final one.
        let v7 = observations.key_operations.iter().any(|row| {
            row.inferred
                .as_ref()
                .is_some_and(|keys| keys.is_v7_content())
        }) || has_v7_gap_content(observations)
            || has_v9_content(observations);
        if !v7 {
            for row in &mut observations.key_operations {
                row.inferred = None;
            }
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
        let mut requested = metadata_block(
            &view.requested,
            &view.requested,
            view.creation_truncated,
            view.creation_partly_read,
            &view.creation_seen,
        );
        let mut established = metadata_block(
            &view.established,
            &view.requested,
            view.creation_truncated,
            view.creation_partly_read,
            &view.creation_seen,
        );
        apply_curve_reason(view, &mut requested, &mut established);
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
            requested,
            established,
            queries: QueriesBlock {
                class: query_label(view.queries[field_index(SafeAttributeKind::Class)]),
                key_type: query_label(view.queries[field_index(SafeAttributeKind::KeyType)]),
                token: query_label(view.queries[field_index(SafeAttributeKind::Token)]),
                value_len: query_label(view.queries[field_index(SafeAttributeKind::ValueLen)]),
                modulus_bits: query_label(
                    view.queries[field_index(SafeAttributeKind::ModulusBits)],
                ),
                ec_params: query_label(view.queries[field_index(SafeAttributeKind::EcParams)]),
                parameter_set: query_label(
                    view.queries[field_index(SafeAttributeKind::ParameterSet)],
                ),
            },
            label: view.label.map(crate::semantics_key_use::metadata_label),
            successful_references: view.references,
            successful_key_references: view.key_uses,
            accessing_sessions: view.accessing_sessions as u64,
            creation_truncated: view.creation_truncated,
        }
    }

    fn metadata_block(
        view: &MetadataView,
        requested: &MetadataView,
        truncated: bool,
        partly_read: bool,
        seen: &[bool; crate::semantics_objects::METADATA_FIELDS],
    ) -> MetadataBlock {
        let field = |kind: SafeAttributeKind| {
            metadata_field(
                view.field(kind),
                view.source(kind),
                unknown_reason(
                    view.field(kind),
                    requested.field(kind),
                    truncated,
                    partly_read,
                    seen[field_index(kind)],
                ),
            )
        };
        MetadataBlock {
            class: field(SafeAttributeKind::Class),
            key_type: field(SafeAttributeKind::KeyType),
            token: field(SafeAttributeKind::Token),
            value_len: field(SafeAttributeKind::ValueLen),
            modulus_bits: field(SafeAttributeKind::ModulusBits),
            ec_params: field(SafeAttributeKind::EcParams),
            parameter_set: field(SafeAttributeKind::ParameterSet),
        }
    }

    /// The unknown reason for one field: a seen-but-valueless kind
    /// names the unsupported reason (fix round 3); a never-seen kind
    /// on a partly-read template names the partly-read reason (fix
    /// round 4), which keeps precedence over the truncation reason
    /// for never-seen kinds on truncated templates. A field with a
    /// state — valued, conflicting, invalidated, or
    /// requested-but-never-promoted like TOKEN — carries no reason:
    /// its state has its own rule.
    fn unknown_reason(
        state: FieldState,
        requested: FieldState,
        truncated: bool,
        partly_read: bool,
        seen: bool,
    ) -> Option<&'static str> {
        if !matches!(state, FieldState::Unknown) || !matches!(requested, FieldState::Unknown) {
            return None;
        }
        if seen {
            Some(UNSUPPORTED_TEMPLATE_VALUE_REASON)
        } else if partly_read {
            Some(PARTLY_READ_TEMPLATE_REASON)
        } else if truncated {
            Some(TRUNCATED_TEMPLATE_REASON)
        } else {
            None
        }
    }

    /// The Edwards/Montgomery curve reason (fix round 3, ruling 1):
    /// only a created object whose own template was seen carries
    /// it, never the private half of a keypair and never a
    /// query-only key (fix round 4). A mismatched established curve
    /// names the curve reason on the established curve field only
    /// (the requested curve is merely requested, never a label
    /// fact); an unestablished curve names it in both blocks only
    /// for a `C_CreateObject` or a public-half `C_GenerateKeyPair`
    /// with a complete template and no curve seen (fix round 5:
    /// unwrap, copy and pair-private templates never carry
    /// `CKA_EC_PARAMS`, so their absent curve says nothing).
    /// Truncation keeps precedence for unseen curves on truncated
    /// templates, and the unsupported reason keeps precedence for
    /// seen-but-valueless curves; matched curves on incompatible
    /// classes, conflicts and non-Edwards/Montgomery types carry
    /// none.
    fn apply_curve_reason(
        view: &ObjectView,
        requested: &mut MetadataBlock,
        established: &mut MetadataBlock,
    ) {
        if view.label.is_some() || !view.creation_template_seen || view.keypair_private {
            return;
        }
        let key_type = match view.established.field(SafeAttributeKind::KeyType) {
            FieldState::Value(FieldValue::Scalar(key_type))
                if key_type == 0x40 || key_type == 0x41 =>
            {
                key_type
            }
            _ => return,
        };
        match view.established.field(SafeAttributeKind::EcParams) {
            FieldState::Value(FieldValue::Curve(curve)) => {
                let matched = matches!(
                    (key_type, curve),
                    (0x40, SafeCurve::Ed25519 | SafeCurve::Ed448)
                        | (0x41, SafeCurve::X25519 | SafeCurve::X448)
                );
                if !matched {
                    established.ec_params.reason = Some(CURVE_UNUSABLE_REASON);
                }
            }
            FieldState::Unknown
                if view.creation_expects_curve_params
                    && !view.creation_truncated
                    && !view.creation_seen[field_index(SafeAttributeKind::EcParams)]
                    && matches!(
                        view.requested.field(SafeAttributeKind::EcParams),
                        FieldState::Unknown
                    ) =>
            {
                requested.ec_params.reason = Some(CURVE_UNUSABLE_REASON);
                established.ec_params.reason = Some(CURVE_UNUSABLE_REASON);
            }
            _ => {}
        }
    }

    pub(crate) fn metadata_field(
        state: FieldState,
        source: Option<FieldSource>,
        reason: Option<&'static str>,
    ) -> MetadataField {
        let (status, scalar, curve) = match state {
            FieldState::Unknown => ("unknown", None, None),
            FieldState::Value(FieldValue::Scalar(value)) => ("value", Some(value), None),
            FieldState::Value(FieldValue::Curve(curve)) => {
                ("value", None, Some(curve_label(curve)))
            }
            FieldState::Conflict(value) => ("conflict", scalar_of(value), curve_of(value)),
            FieldState::Invalidated(value) => ("invalidated", scalar_of(value), curve_of(value)),
        };
        // Keymeta §6/K5: the source rides `value` states only; every
        // other state carries null however the slot was proven.
        let source = if matches!(state, FieldState::Value(_)) {
            source.map(FieldSource::label)
        } else {
            None
        };
        MetadataField {
            status,
            scalar,
            curve,
            source,
            reason,
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
            // R2 new-site: Montgomery/Edwards curve names.
            SafeCurve::X25519 => "x25519",
            SafeCurve::X448 => "x448",
            SafeCurve::Ed25519 => "ed25519",
            SafeCurve::Ed448 => "ed448",
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
