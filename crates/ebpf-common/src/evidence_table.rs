//! SPDX-License-Identifier: GPL-2.0-or-later
//! SPDX-FileCopyrightText: 2026 Denis Mingulov <denis@mingulov.com>
//! Frozen evidence positions for key-metadata capture (v0.8.0 keymeta).
//!
//! Positions only: this table names where length evidence lives on each
//! call (S-protocol output-length cell vs V-protocol input-length scalar)
//! and which endpoints are Task 7 info endpoints. It authorizes no read,
//! retains nothing, and changes no descriptor: `object_descriptor()` is
//! untouched, `OBJECT_ACTION_MAX` stays 14, and the tail contract stays
//! true (evidence trailers ride outside the tail, §8.3).
//!
//! The 14 rows of spec §8.1: 11 length rows plus the 3 info rows (whose
//! kind + read ranges arrive with Task 7; here they carry no length
//! position). The S-protocol output-buffer bases live in the separate
//! `EVIDENCE_BUFFER_BASES` table (§5.1), never in the position rows.
//!
//! Provenance: `docs/superpowers/specs/2026-11-14-v080-keymeta-design.md`
//! §5.1, §8.1, §8.2.

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{ARG_NONE, MAX_DESCRIPTORS};

    fn function_ordinal(name: &str) -> u32 {
        (0..MAX_DESCRIPTORS)
            .find(|index| pkcs11_module::function_name(*index as usize) == Some(name))
            .expect("the frozen catalog contains the named evidence function")
    }

    /// The 14 frozen §8.1 rows in table order: 11 length rows (exactly
    /// one of the cell/scalar positions set) plus the 3 info rows (no
    /// length position). Any added, removed, reordered or reshaped row
    /// fails here; Task 7 fills the info kind + ranges, never the count.
    #[test]
    fn evidence_positions_pin_fourteen_frozen_rows() {
        assert_eq!(EVIDENCE_POSITIONS.len(), 14);
        let expected: [(&str, u8, u8, bool); 14] = [
            ("C_Sign", 4, ARG_NONE, false),
            ("C_SignRecover", 4, ARG_NONE, false),
            ("C_SignFinal", 2, ARG_NONE, false),
            ("C_Verify", ARG_NONE, 4, false),
            ("C_VerifyFinal", ARG_NONE, 2, false),
            ("C_Encrypt", 4, ARG_NONE, false),
            ("C_Decrypt", ARG_NONE, 2, false),
            ("C_WrapKey", 5, ARG_NONE, false),
            ("C_UnwrapKey", ARG_NONE, 4, false),
            ("C_EncapsulateKey", 6, ARG_NONE, false),
            ("C_DecapsulateKey", ARG_NONE, 6, false),
            ("C_GetInfo", ARG_NONE, ARG_NONE, true),
            ("C_GetTokenInfo", ARG_NONE, ARG_NONE, true),
            ("C_GetMechanismInfo", ARG_NONE, ARG_NONE, true),
        ];
        for (row, (name, cell, scalar, info)) in EVIDENCE_POSITIONS.iter().zip(expected) {
            assert_eq!(row.function, name, "row order");
            assert_eq!(row.length_cell_arg, cell, "{name}: S-cell position");
            assert_eq!(row.length_scalar_arg, scalar, "{name}: V-scalar position");
            assert_eq!(row.info, info, "{name}: info marker");
            // Shape exclusivity: exactly one of S-cell, V-scalar, info.
            let set = u32::from(cell != ARG_NONE)
                + u32::from(scalar != ARG_NONE)
                + u32::from(info);
            assert_eq!(set, 1, "{name}: exactly one evidence shape");
            // No new argument-7 exception: every position is arg ≤ 6.
            for arg in [cell, scalar] {
                assert!(arg == ARG_NONE || arg <= 6, "{name}: position {arg} within args");
            }
        }
        // The trailer vocabulary the rows feed is closed and unambiguous.
        assert_ne!(LENGTH_KIND_SCELL, LENGTH_KIND_VSCALAR);
        assert_ne!(LENGTH_STATUS_OK, LENGTH_STATUS_UNAVAILABLE);
        assert_eq!(LENGTH_TRAILER_VERSION, 1);
        assert_eq!(LENGTH_CAPACITY_MAX, 1 << 20);
    }

    /// Ordinal lookup mirrors `object_descriptor()`: the frozen catalog
    /// name resolves the row, unknown ordinals fail closed.
    #[test]
    fn evidence_positions_resolve_by_function_ordinal() {
        for row in EVIDENCE_POSITIONS {
            let ordinal = function_ordinal(row.function);
            assert_eq!(
                evidence_position(ordinal),
                Some(row),
                "{} resolves to its row",
                row.function
            );
        }
        for name in [
            "C_Initialize",
            "C_GetSlotInfo",
            "C_SignInit",
            "C_Digest",
            "C_GenerateKey",
        ] {
            assert_eq!(
                evidence_position(function_ordinal(name)),
                None,
                "{name} carries no evidence position"
            );
        }
        for ordinal in [MAX_DESCRIPTORS, MAX_DESCRIPTORS + 1, u32::MAX] {
            assert_eq!(evidence_position(ordinal), None, "ordinal {ordinal} fails closed");
        }
    }

    /// The §5.1 per-function output-buffer bases: every S-row has its
    /// disjointness base, while V-scalar, info and unknown endpoints
    /// have none (ARG_NONE). The cross-check below keeps the two tables
    /// in lockstep: an S-row without a base (or a base without an
    /// S-row) fails loudly instead of guarding the wrong span.
    #[test]
    fn evidence_buffer_bases_cover_s_rows_only() {
        let expected: [(&str, u8); 6] = [
            ("C_Sign", 3),
            ("C_SignRecover", 3),
            ("C_SignFinal", 1),
            ("C_Encrypt", 3),
            ("C_WrapKey", 4),
            ("C_EncapsulateKey", 5),
        ];
        assert_eq!(EVIDENCE_BUFFER_BASES.len(), expected.len());
        for (name, base) in expected {
            assert_eq!(
                length_buffer_base(function_ordinal(name)),
                base,
                "{name}: disjointness base"
            );
        }
        for name in [
            "C_Verify",
            "C_VerifyFinal",
            "C_Decrypt",
            "C_UnwrapKey",
            "C_DecapsulateKey",
            "C_GetInfo",
            "C_GetTokenInfo",
            "C_GetMechanismInfo",
            "C_Initialize",
            "C_SignInit",
        ] {
            assert_eq!(
                length_buffer_base(function_ordinal(name)),
                ARG_NONE,
                "{name} has no S-cell base"
            );
        }
        assert_eq!(length_buffer_base(MAX_DESCRIPTORS), ARG_NONE);
        // Lockstep: S-rows and bases agree on every catalog ordinal.
        for ordinal in 0..MAX_DESCRIPTORS {
            let is_cell_row = evidence_position(ordinal)
                .is_some_and(|row| row.length_cell_arg != ARG_NONE);
            assert_eq!(
                length_buffer_base(ordinal) != ARG_NONE,
                is_cell_row,
                "ordinal {ordinal}: base coverage matches S-cell rows"
            );
        }
    }

    /// Authority twin (§8.4): evidence adds no descriptors and changes
    /// no entry gating. The ten length/info endpoints without an object
    /// protocol keep none, and the four pre-existing rows (Wrap/Unwrap/
    /// KEM) keep their exact shapes — Task 2 moves neither.
    #[test]
    fn evidence_endpoints_add_no_entry_gating() {
        use crate::object_policy::{ObjectAction, object_descriptor};
        for row in EVIDENCE_POSITIONS {
            let ordinal = function_ordinal(row.function);
            let descriptor = object_descriptor(ordinal);
            match row.function {
                "C_WrapKey" => {
                    let kept = descriptor.expect("C_WrapKey keeps its Access row");
                    assert_eq!(kept.action, ObjectAction::Access);
                    assert_eq!(kept.input_args, [2, 3]);
                }
                "C_UnwrapKey" => {
                    let kept = descriptor.expect("C_UnwrapKey keeps its Unwrap row");
                    assert_eq!(kept.action, ObjectAction::Unwrap);
                    assert_eq!(kept.input_args, [2, ARG_NONE]);
                    assert_eq!(kept.result_pointer_args, [7, ARG_NONE]);
                    assert_eq!(kept.template_args, [(5, 6), (ARG_NONE, ARG_NONE)]);
                }
                "C_EncapsulateKey" => {
                    let kept = descriptor.expect("C_EncapsulateKey keeps its row");
                    assert_eq!(kept.action, ObjectAction::Encapsulate);
                    assert_eq!(kept.input_args, [2, ARG_NONE]);
                    assert_eq!(kept.result_pointer_args, [7, ARG_NONE]);
                }
                "C_DecapsulateKey" => {
                    let kept = descriptor.expect("C_DecapsulateKey keeps its row");
                    assert_eq!(kept.action, ObjectAction::Decapsulate);
                    assert_eq!(kept.input_args, [2, ARG_NONE]);
                    assert_eq!(kept.result_pointer_args, [7, ARG_NONE]);
                }
                _ => assert_eq!(
                    descriptor, None,
                    "{} gains no descriptor (a NULL entry still admits the provider)",
                    row.function
                ),
            }
        }
    }
}
