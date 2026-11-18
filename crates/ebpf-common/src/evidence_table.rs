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

use crate::ARG_NONE;

/// Length-trailer protocol version (spec §8.3).
pub const LENGTH_TRAILER_VERSION: u16 = 1;
/// S-protocol (output length cell) evidence kind.
pub const LENGTH_KIND_SCELL: u8 = 1;
/// V-protocol (input length scalar) evidence kind.
pub const LENGTH_KIND_VSCALAR: u8 = 2;
/// Trailer status: no length captured on this call.
pub const LENGTH_STATUS_UNAVAILABLE: u8 = 0;
/// Trailer status: `value` carries the length word.
pub const LENGTH_STATUS_OK: u8 = 1;
/// Entry-capacity admission bound (spec §5.1): larger cells are
/// bulk-encrypt outputs that classify to nothing. Inclusive.
pub const LENGTH_CAPACITY_MAX: u64 = 1 << 20;

/// One frozen evidence row: the length cell/scalar position for one
/// function, or the Task 7 info marker (no length position; the info
/// kind + read ranges arrive with Task 7). Exactly one of the three
/// shapes is set per row (pinned by the exact-count test).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct EvidencePosition {
    /// Frozen catalog name (spec §8.1 table order).
    pub function: &'static str,
    /// S-protocol output-length cell argument, or `ARG_NONE`.
    pub length_cell_arg: u8,
    /// V-protocol input-length scalar argument, or `ARG_NONE`.
    pub length_scalar_arg: u8,
    /// Task 7 info endpoint (never a length position).
    pub info: bool,
}

/// The 14 frozen §8.1 rows: 11 length rows plus the 3 info rows.
/// Test-only: production lookups below are `match` arms (the
/// `object_descriptor()` precedent — static tables would emit
/// relocated rodata into the BPF object), and the exact-count test
/// plus the ordinal cross-check pin the two spellings together, so
/// neither can drift silently.
#[cfg(test)]
pub const EVIDENCE_POSITIONS: [EvidencePosition; 14] = [
    EvidencePosition {
        function: "C_Sign",
        length_cell_arg: 4,
        length_scalar_arg: ARG_NONE,
        info: false,
    },
    EvidencePosition {
        function: "C_SignRecover",
        length_cell_arg: 4,
        length_scalar_arg: ARG_NONE,
        info: false,
    },
    EvidencePosition {
        function: "C_SignFinal",
        length_cell_arg: 2,
        length_scalar_arg: ARG_NONE,
        info: false,
    },
    EvidencePosition {
        function: "C_Verify",
        length_cell_arg: ARG_NONE,
        length_scalar_arg: 4,
        info: false,
    },
    EvidencePosition {
        function: "C_VerifyFinal",
        length_cell_arg: ARG_NONE,
        length_scalar_arg: 2,
        info: false,
    },
    EvidencePosition {
        function: "C_Encrypt",
        length_cell_arg: 4,
        length_scalar_arg: ARG_NONE,
        info: false,
    },
    EvidencePosition {
        function: "C_Decrypt",
        length_cell_arg: ARG_NONE,
        length_scalar_arg: 2,
        info: false,
    },
    EvidencePosition {
        function: "C_WrapKey",
        length_cell_arg: 5,
        length_scalar_arg: ARG_NONE,
        info: false,
    },
    EvidencePosition {
        function: "C_UnwrapKey",
        length_cell_arg: ARG_NONE,
        length_scalar_arg: 4,
        info: false,
    },
    EvidencePosition {
        function: "C_EncapsulateKey",
        length_cell_arg: 6,
        length_scalar_arg: ARG_NONE,
        info: false,
    },
    EvidencePosition {
        function: "C_DecapsulateKey",
        length_cell_arg: ARG_NONE,
        length_scalar_arg: 6,
        info: false,
    },
    EvidencePosition {
        function: "C_GetInfo",
        length_cell_arg: ARG_NONE,
        length_scalar_arg: ARG_NONE,
        info: true,
    },
    EvidencePosition {
        function: "C_GetTokenInfo",
        length_cell_arg: ARG_NONE,
        length_scalar_arg: ARG_NONE,
        info: true,
    },
    EvidencePosition {
        function: "C_GetMechanismInfo",
        length_cell_arg: ARG_NONE,
        length_scalar_arg: ARG_NONE,
        info: true,
    },
];

/// Resolve one function ordinal to its evidence row. A plain
/// ordinal match: BPF must never call `function_name()` (its 105-entry
/// static table would emit relocated rodata into the BPF object —
/// BPF objects carry no rodata today), so the ordinals below are
/// pinned against the frozen catalog by
/// `evidence_ordinals_pin_catalog_order` (a catalog reorder fails
/// loudly there, never silently here). Unknown ordinals fail closed.
#[inline(always)]
pub fn evidence_position(function: u32) -> Option<EvidencePosition> {
    let row = match function {
        43 => EvidencePosition {
            function: "C_Sign",
            length_cell_arg: 4,
            length_scalar_arg: ARG_NONE,
            info: false,
        },
        47 => EvidencePosition {
            function: "C_SignRecover",
            length_cell_arg: 4,
            length_scalar_arg: ARG_NONE,
            info: false,
        },
        45 => EvidencePosition {
            function: "C_SignFinal",
            length_cell_arg: 2,
            length_scalar_arg: ARG_NONE,
            info: false,
        },
        49 => EvidencePosition {
            function: "C_Verify",
            length_cell_arg: ARG_NONE,
            length_scalar_arg: 4,
            info: false,
        },
        51 => EvidencePosition {
            function: "C_VerifyFinal",
            length_cell_arg: ARG_NONE,
            length_scalar_arg: 2,
            info: false,
        },
        30 => EvidencePosition {
            function: "C_Encrypt",
            length_cell_arg: 4,
            length_scalar_arg: ARG_NONE,
            info: false,
        },
        34 => EvidencePosition {
            function: "C_Decrypt",
            length_cell_arg: ARG_NONE,
            length_scalar_arg: 2,
            info: false,
        },
        60 => EvidencePosition {
            function: "C_WrapKey",
            length_cell_arg: 5,
            length_scalar_arg: ARG_NONE,
            info: false,
        },
        61 => EvidencePosition {
            function: "C_UnwrapKey",
            length_cell_arg: ARG_NONE,
            length_scalar_arg: 4,
            info: false,
        },
        92 => EvidencePosition {
            function: "C_EncapsulateKey",
            length_cell_arg: 6,
            length_scalar_arg: ARG_NONE,
            info: false,
        },
        93 => EvidencePosition {
            function: "C_DecapsulateKey",
            length_cell_arg: ARG_NONE,
            length_scalar_arg: 6,
            info: false,
        },
        2 => EvidencePosition {
            function: "C_GetInfo",
            length_cell_arg: ARG_NONE,
            length_scalar_arg: ARG_NONE,
            info: true,
        },
        6 => EvidencePosition {
            function: "C_GetTokenInfo",
            length_cell_arg: ARG_NONE,
            length_scalar_arg: ARG_NONE,
            info: true,
        },
        8 => EvidencePosition {
            function: "C_GetMechanismInfo",
            length_cell_arg: ARG_NONE,
            length_scalar_arg: ARG_NONE,
            info: true,
        },
        _ => return None,
    };
    Some(row)
}

/// The §5.1 per-function output-buffer bases for the S-protocol
/// disjointness guard: the call's own output-buffer pointer argument.
/// The evidence table carries cell/scalar positions; this table
/// carries the base. V-scalar, info and unknown endpoints have none.
/// Test-only, like `EVIDENCE_POSITIONS`: production resolves
/// through the match below.
#[cfg(test)]
pub const EVIDENCE_BUFFER_BASES: [(&str, u8); 6] = [
    ("C_Sign", 3),
    ("C_SignRecover", 3),
    ("C_SignFinal", 1),
    ("C_Encrypt", 3),
    ("C_WrapKey", 4),
    ("C_EncapsulateKey", 5),
];

/// Resolve one canonical descriptor to its length kind
/// (`LENGTH_KIND_SCELL` / `LENGTH_KIND_VSCALAR`), or `None` when the
/// endpoint takes the base pair (count-only, out-of-range, unlisted,
/// corrupt or info descriptors). The length return root dispatches on
/// this: length endpoints take the length path (648), anything else
/// degrades to the base flow with a valid base END instead of losing
/// the completion.
#[inline(always)]
pub fn length_kind_for_descriptor(descriptor: u32) -> Option<u8> {
    if descriptor == 0 {
        return None;
    }
    let row = evidence_position(descriptor - 1)?;
    if row.info {
        return None;
    }
    if row.length_cell_arg != ARG_NONE && row.length_scalar_arg == ARG_NONE {
        Some(LENGTH_KIND_SCELL)
    } else if row.length_scalar_arg != ARG_NONE && row.length_cell_arg == ARG_NONE {
        Some(LENGTH_KIND_VSCALAR)
    } else {
        None
    }
}

/// Map one entry descriptor through the in-place-downgrade switch
/// (A′): a switched (narrowed) slot resolves descriptor 0, so the
/// length adapter refuses and the call still counts without length
/// evidence; an unswitched slot keeps its cookie descriptor. Range
/// checks stay the adapter's. The BPF length root maps through this
/// helper instead of branching inline.
#[inline(always)]
pub const fn length_entry_descriptor(descriptor: u32, switched: bool) -> u32 {
    if switched {
        0
    } else {
        descriptor
    }
}

/// Resolve one function ordinal to its S-cell disjointness base, or
/// `ARG_NONE` when the endpoint has no S-cell position. An ordinal
/// match like [`evidence_position`]: no `function_name()` call, no
/// static table, no rodata.
#[inline(always)]
pub fn length_buffer_base(function: u32) -> u8 {
    match function {
        43 => 3,
        47 => 3,
        45 => 1,
        30 => 3,
        60 => 4,
        92 => 5,
        _ => ARG_NONE,
    }
}

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
            let set = u32::from(cell != ARG_NONE) + u32::from(scalar != ARG_NONE) + u32::from(info);
            assert_eq!(set, 1, "{name}: exactly one evidence shape");
            // No new argument-7 exception: every position is arg ≤ 6.
            for arg in [cell, scalar] {
                assert!(
                    arg == ARG_NONE || arg <= 6,
                    "{name}: position {arg} within args"
                );
            }
        }
        // The trailer vocabulary the rows feed is closed and unambiguous.
        assert_ne!(LENGTH_KIND_SCELL, LENGTH_KIND_VSCALAR);
        assert_ne!(LENGTH_STATUS_OK, LENGTH_STATUS_UNAVAILABLE);
        assert_eq!(LENGTH_TRAILER_VERSION, 1);
        assert_eq!(LENGTH_CAPACITY_MAX, 1 << 20);
    }

    /// Ordinal pin: the production match arms name frozen catalog
    /// ordinals (BPF must never call `function_name()` — its static
    /// table would emit relocated rodata into the BPF object). A
    /// catalog reorder fails loudly here, so the BPF match can never
    /// silently miss its endpoints.
    #[test]
    fn evidence_ordinals_pin_catalog_order() {
        for (name, ordinal) in [
            ("C_Sign", 43),
            ("C_SignRecover", 47),
            ("C_SignFinal", 45),
            ("C_Verify", 49),
            ("C_VerifyFinal", 51),
            ("C_Encrypt", 30),
            ("C_Decrypt", 34),
            ("C_WrapKey", 60),
            ("C_UnwrapKey", 61),
            ("C_EncapsulateKey", 92),
            ("C_DecapsulateKey", 93),
            ("C_GetInfo", 2),
            ("C_GetTokenInfo", 6),
            ("C_GetMechanismInfo", 8),
        ] {
            assert_eq!(function_ordinal(name), ordinal, "{name} ordinal");
        }
    }

    /// Ordinal lookup cross-check: every frozen row resolves through
    /// the production ordinal match, and unlisted ordinals fail
    /// closed. Together with the ordinal pin above, neither the
    /// table, the match nor the catalog can drift silently.
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
            assert_eq!(
                evidence_position(ordinal),
                None,
                "ordinal {ordinal} fails closed"
            );
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
            let is_cell_row =
                evidence_position(ordinal).is_some_and(|row| row.length_cell_arg != ARG_NONE);
            assert_eq!(
                length_buffer_base(ordinal) != ARG_NONE,
                is_cell_row,
                "ordinal {ordinal}: base coverage matches S-cell rows"
            );
        }
    }

    /// Return-path dispatch: canonical descriptors resolve to their
    /// S/V kind, while count-only, unlisted, corrupt and info
    /// descriptors resolve to `None` (base pair). The length return
    /// root degrades `None` to the base flow with a valid base END.
    #[test]
    fn length_kind_for_descriptor_dispatches_endpoints() {
        for row in EVIDENCE_POSITIONS {
            let descriptor = function_ordinal(row.function) + 1;
            let kind = length_kind_for_descriptor(descriptor);
            if row.info {
                assert_eq!(kind, None, "{}: info takes the base pair", row.function);
            } else if row.length_cell_arg != ARG_NONE {
                assert_eq!(
                    kind,
                    Some(LENGTH_KIND_SCELL),
                    "{}: S endpoint",
                    row.function
                );
            } else {
                assert_eq!(
                    kind,
                    Some(LENGTH_KIND_VSCALAR),
                    "{}: V endpoint",
                    row.function
                );
            }
        }
        assert_eq!(length_kind_for_descriptor(0), None);
        assert_eq!(length_kind_for_descriptor(MAX_DESCRIPTORS), None);
        assert_eq!(
            length_kind_for_descriptor(function_ordinal("C_Initialize") + 1),
            None
        );
        assert_eq!(
            length_kind_for_descriptor(function_ordinal("C_SignInit") + 1),
            None
        );
    }

    /// Downgrade narrowing for the length entry: a switched (narrowed)
    /// slot resolves descriptor 0, so the adapter refuses and the call
    /// still counts without length evidence; an unswitched slot keeps
    /// its cookie descriptor. The BPF length root maps through this
    /// helper (shared, host-tested) instead of branching inline.
    #[test]
    fn length_entry_descriptor_narrows_switched_slots() {
        let sign = function_ordinal("C_Sign") + 1;
        assert_eq!(length_entry_descriptor(sign, false), sign);
        assert_eq!(length_entry_descriptor(sign, true), 0);
        assert_eq!(length_entry_descriptor(0, false), 0);
        assert_eq!(length_entry_descriptor(0, true), 0);
        assert_eq!(
            length_entry_descriptor(MAX_DESCRIPTORS + 1, false),
            MAX_DESCRIPTORS + 1,
            "range checks stay the adapter's (this maps narrowing only)"
        );
    }

    /// Authority twin (§8.4): evidence adds no descriptors and changes
    /// no entry gating. The ten length/info endpoints without an object
    /// protocol keep none, and the four pre-existing rows (Wrap/Unwrap/
    /// KEM) keep their exact shapes — Task 2 moves neither.
    #[test]
    fn evidence_endpoints_add_no_entry_gating() {
        use crate::object_policy::{object_descriptor, ObjectAction};
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
