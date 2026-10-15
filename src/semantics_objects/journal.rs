//! SPDX-License-Identifier: GPL-3.0-or-later
//! Sealed object-journal authority (H8): the private consumer that turns the
//! inactive journal wire into proven model inputs.
//!
//! This child owns the frozen effect-neutral S1 vocabulary, the finite
//! ABANDON reason-to-disposition matrix, the retained-cursor consumer
//! (frontier/audit), endpoint closure, birth witnesses and the sealed
//! prefix H9 consumes. It produces sealed authority, never public object
//! rows: conversion into the existing model lives here, projection stays
//! with H9.
//!
//! The native producer is inactive: no BPF root emits journal records, so
//! every ingest below consumes Session-decoded bytes plus Session-owned
//! audit evidence, never live ring state. Slices land in order: vocabulary
//! and disposition first, then ingest/terminal matching, then frontier and
//! capacity, then closure and bootstrap.
//!
//! Provenance: `docs/superpowers/plans/2026-10-09-object-journal-bootstrap.md`.
//! Privacy: raw handles, words, cuts and keys stay in the model's private
//! newtypes; this module adds no target-memory read, pointer output or
//! capture beyond allowlist v1/v2 and the six approved v3 attributes.

// ---------------------------------------------------------------------------
// Frozen effect-neutral S1 vocabulary
// ---------------------------------------------------------------------------

/// The exact finite effect-neutral S1 operation vocabulary, in plan order.
/// Neutral calls participate in BEGIN/END, overlap, loss and replay ordering
/// and carry existing S1 facts; they mint no object references, results or
/// new selector-read authority. Existing object descriptors retain precedence
/// for key-bearing Init, DigestKey and direct object calls; async controls,
/// token initialization, KEM and authenticated-wrap neighbors do not become
/// neutral by analogy. A later catalog addition requires an explicit
/// classification amendment here, never a prefix match.
pub(crate) const NEUTRAL_S1_FUNCTIONS: [&str; 41] = [
    "C_DigestInit",
    "C_Encrypt",
    "C_Decrypt",
    "C_Digest",
    "C_Sign",
    "C_SignRecover",
    "C_Verify",
    "C_VerifyRecover",
    "C_EncryptUpdate",
    "C_DecryptUpdate",
    "C_DigestUpdate",
    "C_SignUpdate",
    "C_VerifyUpdate",
    "C_EncryptFinal",
    "C_DecryptFinal",
    "C_DigestFinal",
    "C_SignFinal",
    "C_VerifyFinal",
    "C_DigestEncryptUpdate",
    "C_DecryptDigestUpdate",
    "C_SignEncryptUpdate",
    "C_DecryptVerifyUpdate",
    "C_EncryptMessage",
    "C_EncryptMessageBegin",
    "C_EncryptMessageNext",
    "C_DecryptMessage",
    "C_DecryptMessageBegin",
    "C_DecryptMessageNext",
    "C_SignMessage",
    "C_SignMessageBegin",
    "C_SignMessageNext",
    "C_VerifyMessage",
    "C_VerifyMessageBegin",
    "C_VerifyMessageNext",
    "C_MessageEncryptFinal",
    "C_MessageDecryptFinal",
    "C_MessageSignFinal",
    "C_MessageVerifyFinal",
    "C_VerifySignature",
    "C_VerifySignatureUpdate",
    "C_VerifySignatureFinal",
];

/// Whether a canonical function ordinal names an effect-neutral S1
/// operation: exact catalog-name membership, never a prefix or operation
/// bit. Unknown ordinals are not neutral.
pub(crate) fn is_neutral_function(function: u32) -> bool {
    let Some(name) = pkcs11_module::function_name(usize::try_from(function).unwrap_or(usize::MAX))
    else {
        return false;
    };
    NEUTRAL_S1_FUNCTIONS.contains(&name)
}

// ---------------------------------------------------------------------------
// Finite ABANDON reason-to-disposition matrix
// ---------------------------------------------------------------------------

/// What one ABANDON reason permits. A wire reason alone never certifies a
/// bounded terminal witness: even the candidate below still requires
/// independent evidence of an upper cut after which the invocation cannot
/// affect provider state.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum AbandonDisposition {
    /// Observer custody was lost with unknown continuing effects: the
    /// affected exact incarnation's object proof is irreversibly refused
    /// before bounded resources are disposed. Never a `LostOutcome`.
    UnboundedInvalidation,
    /// The only reason that may accompany a bounded terminal witness: an
    /// observed completed synchronous provider return whose result is
    /// unavailable. Still requires the independent return evidence; without
    /// it the call invalidates like every other reason.
    BoundedWitnessCandidate,
}

/// The frozen reason-to-disposition matrix over the nine finite wire codes.
/// Unknown codes have no disposition.
pub(crate) fn abandon_disposition(reason: u32) -> Option<AbandonDisposition> {
    use AbandonDisposition::{BoundedWitnessCandidate, UnboundedInvalidation};
    use p11scope_ebpf_common::object_journal::{
        JOURNAL_REASON_ABI_REFUSED, JOURNAL_REASON_ENTRY_COLLISION, JOURNAL_REASON_EXEC_EXIT,
        JOURNAL_REASON_IDENTITY_REFUSED, JOURNAL_REASON_INSERT_FAILED,
        JOURNAL_REASON_PARTIAL_TRANSACTION, JOURNAL_REASON_SCOPE_LOST, JOURNAL_REASON_STOP_CLEANUP,
        JOURNAL_REASON_SYNC_RETURN_RESULT_LOST,
    };
    match reason {
        JOURNAL_REASON_ENTRY_COLLISION
        | JOURNAL_REASON_INSERT_FAILED
        | JOURNAL_REASON_SCOPE_LOST
        | JOURNAL_REASON_ABI_REFUSED
        | JOURNAL_REASON_IDENTITY_REFUSED
        | JOURNAL_REASON_EXEC_EXIT
        | JOURNAL_REASON_STOP_CLEANUP
        | JOURNAL_REASON_PARTIAL_TRANSACTION => Some(UnboundedInvalidation),
        JOURNAL_REASON_SYNC_RETURN_RESULT_LOST => Some(BoundedWitnessCandidate),
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn object_journal_neutral_vocabulary_is_finite() {
        // Exactly the 41 frozen names, distinct and in plan order.
        assert_eq!(NEUTRAL_S1_FUNCTIONS.len(), 41);
        let mut sorted = NEUTRAL_S1_FUNCTIONS;
        sorted.sort_unstable();
        for pair in sorted.windows(2) {
            assert_ne!(pair[0], pair[1], "neutral names are distinct");
        }
        assert_eq!(NEUTRAL_S1_FUNCTIONS[0], "C_DigestInit");
        assert_eq!(NEUTRAL_S1_FUNCTIONS[40], "C_VerifySignatureFinal");

        for name in NEUTRAL_S1_FUNCTIONS {
            // Exact accepted catalog/descriptor agreement for every name.
            let id = crate::kinds::function_id(name)
                .unwrap_or_else(|| panic!("{name} resolves in the catalog"));
            assert!(
                crate::kinds::descriptor(name).is_some(),
                "{name} has an accepted capture descriptor"
            );
            // No object row: object descriptors retain precedence, so no
            // neutral name may collide with the object policy.
            assert!(
                crate::kinds::object_descriptor(name).is_none(),
                "{name} carries no object descriptor"
            );
            assert!(is_neutral_function(id), "{name} classifies neutral");
        }

        // Prefix-similar and neighboring functions are not neutral by
        // analogy: key-bearing Inits (object), DigestKey (object), Find
        // lifecycle, token init, wrap and message-Init neighbors.
        for name in [
            "C_SignInit",
            "C_SignRecoverInit",
            "C_VerifyInit",
            "C_VerifyRecoverInit",
            "C_EncryptInit",
            "C_DecryptInit",
            "C_MessageSignInit",
            "C_MessageVerifyInit",
            "C_VerifySignatureInit",
            "C_DigestKey",
            "C_FindObjectsInit",
            "C_FindObjects",
            "C_InitToken",
            "C_WrapKey",
            "C_UnwrapKey",
            "C_DeriveKey",
            "C_OpenSession",
            "C_CloseSession",
            "C_Login",
            "C_GetInfo",
            "C_GetFunctionList",
            "C_GenerateRandom",
            "C_SeedRandom",
        ] {
            let id = crate::kinds::function_id(name)
                .unwrap_or_else(|| panic!("{name} resolves in the catalog"));
            assert!(!is_neutral_function(id), "{name} is not neutral");
        }
        // Unknown ordinals are not neutral.
        assert!(!is_neutral_function(u32::MAX));
        assert!(!is_neutral_function(10_000));

        // Object precedence is structural: every object-policy function
        // classifies through the object arm first (checked again by the
        // model's classifier test), so neutral membership can never shadow
        // a key-bearing call.
        for name in [
            "C_CreateObject",
            "C_DestroyObject",
            "C_GetAttributeValue",
            "C_SetAttributeValue",
            "C_SignInit",
            "C_DigestKey",
        ] {
            let id = crate::kinds::function_id(name).expect("catalog");
            assert!(
                p11scope_ebpf_common::object_policy::object_descriptor(id).is_some(),
                "{name} keeps its object row"
            );
            assert!(!is_neutral_function(id));
        }
    }

    #[test]
    fn object_journal_abandon_reason_matrix_is_finite() {
        use p11scope_ebpf_common::object_journal::{
            JOURNAL_REASON_ABI_REFUSED, JOURNAL_REASON_ENTRY_COLLISION, JOURNAL_REASON_EXEC_EXIT,
            JOURNAL_REASON_IDENTITY_REFUSED, JOURNAL_REASON_INSERT_FAILED,
            JOURNAL_REASON_PARTIAL_TRANSACTION, JOURNAL_REASON_SCOPE_LOST,
            JOURNAL_REASON_STOP_CLEANUP, JOURNAL_REASON_SYNC_RETURN_RESULT_LOST,
        };
        // Eight unbounded reasons, one bounded-witness candidate, in frozen
        // code order; every code has a finite wire label.
        let unbounded = [
            (JOURNAL_REASON_ENTRY_COLLISION, 1u32),
            (JOURNAL_REASON_INSERT_FAILED, 2),
            (JOURNAL_REASON_SCOPE_LOST, 3),
            (JOURNAL_REASON_ABI_REFUSED, 4),
            (JOURNAL_REASON_IDENTITY_REFUSED, 5),
            (JOURNAL_REASON_EXEC_EXIT, 6),
            (JOURNAL_REASON_STOP_CLEANUP, 7),
            (JOURNAL_REASON_PARTIAL_TRANSACTION, 8),
        ];
        for (code, expected) in unbounded {
            assert_eq!(code, expected);
            assert_eq!(
                abandon_disposition(code),
                Some(AbandonDisposition::UnboundedInvalidation)
            );
            assert!(
                p11scope_ebpf_common::object_journal::reason_name(code).is_some(),
                "reason {code} has a finite label"
            );
        }
        assert_eq!(JOURNAL_REASON_SYNC_RETURN_RESULT_LOST, 9);
        assert_eq!(
            abandon_disposition(JOURNAL_REASON_SYNC_RETURN_RESULT_LOST),
            Some(AbandonDisposition::BoundedWitnessCandidate)
        );
        // Unknown codes have neither disposition nor label.
        for code in [0u32, 10, 99, u32::MAX] {
            assert_eq!(abandon_disposition(code), None);
            assert_eq!(
                p11scope_ebpf_common::object_journal::reason_name(code),
                None
            );
        }
    }
}
