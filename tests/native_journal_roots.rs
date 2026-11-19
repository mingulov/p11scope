//! SPDX-License-Identifier: GPL-3.0-or-later
//! SPDX-FileCopyrightText: 2026 Denis Mingulov <denis@mingulov.com>
//! Actual private journal roots and their emitted native call graph.

use std::{fs, path::Path, process::Command};

#[path = "../crates/ebpf/src/journal_roots.rs"]
mod root_writers;

#[test]
fn frozen_class_context_never_promotes_unknown_and_preserves_target_abi() {
    use p11scope_ebpf_common::{LinuxLayout, MAX_DESCRIPTORS};
    for (layout, code) in [(LinuxLayout::Lp64, 1), (LinuxLayout::Ilp32, 2)] {
        for (configured, normalized) in [(1, 0), (2, 1), (3, 2)] {
            let context = root_writers::entry_context(21, configured, layout).unwrap();
            assert_eq!(context.descriptor, 21);
            assert_eq!(context.class_bits, normalized);
            assert_eq!(context.layout, code);
            assert_eq!(context.reserved, 0);
        }
        for unknown in [0, 4, u32::MAX] {
            assert!(root_writers::entry_context(21, unknown, layout).is_none());
        }
        for descriptor in [0, MAX_DESCRIPTORS, u32::MAX] {
            assert!(root_writers::entry_context(descriptor, 2, layout).is_none());
        }
    }
}

#[test]
fn begin_decision_calls_every_valid_context_and_gaps_the_rest() {
    use p11scope_ebpf_common::{LinuxLayout, MAX_DESCRIPTORS};
    use root_writers::BeginDecision;
    for (layout, code) in [(LinuxLayout::Lp64, 1), (LinuxLayout::Ilp32, 2)] {
        for (configured, normalized) in [(1, 0), (2, 1), (3, 2)] {
            let BeginDecision::Call(context) = root_writers::begin_decision(21, configured, layout)
            else {
                panic!("configured {configured} must decide Call");
            };
            assert_eq!(context.descriptor, 21);
            assert_eq!(context.class_bits, normalized);
            assert_eq!(context.layout, code);
            assert_eq!(context.reserved, 0);
        }
        for unknown in [0, 4, u32::MAX] {
            assert!(matches!(
                root_writers::begin_decision(21, unknown, layout),
                BeginDecision::Gap
            ));
        }
        for descriptor in [0, MAX_DESCRIPTORS, u32::MAX] {
            assert!(matches!(
                root_writers::begin_decision(descriptor, 2, layout),
                BeginDecision::Gap
            ));
        }
    }
}

/// In-place downgrade (A′): only a switched slot's BEGIN decision
/// consults the narrowed arm — `begin()` takes the slot's switch bit
/// and decides through the shared pure `begin_action`, so a planned
/// descriptor-0 call (switch unset) keeps today's Gap path while a
/// downgraded call never re-enters the capture-failure arm. The
/// frozen `begin_decision` contract above stays untouched.
#[test]
fn switched_calls_decide_begin_through_the_narrowed_arm() {
    const SOURCE: &str = include_str!("../crates/ebpf/src/journal_roots.rs");
    fn begin_body(source: &str) -> Option<&str> {
        source
            .split_once("    pub(crate) fn begin(")
            .map(|(_, tail)| tail)
            .and_then(|tail| tail.split_once("\n    }\n").map(|(text, _)| text))
    }
    fn contract(source: &str) -> bool {
        let Some(text) = begin_body(source) else {
            return false;
        };
        text.contains("switched: bool")
            && text.contains("begin_action(switched,")
            && text.contains("BeginAction::Skip")
            && text.contains("BeginAction::Gap")
            && !text.contains("if descriptor == 0 {")
    }
    assert!(
        contract(SOURCE),
        "journal begin() must gate its narrowed arm on the switch bit"
    );
    let start = SOURCE.find("    pub(crate) fn begin(").unwrap();
    for marker in [
        "switched: bool",
        "begin_action(switched,",
        "BeginAction::Skip",
        "BeginAction::Gap",
    ] {
        let tail = SOURCE[start..].replacen(marker, "REMOVED", 1);
        assert!(
            !contract(&format!("{}{}", &SOURCE[..start], tail)),
            "removed {marker}"
        );
    }
}

/// In-place downgrade (A′): the shared BEGIN custody decision. A
/// switched slot skips silently only for a proved-irrelevant class;
/// an affecting (or unknown) class marks its history honestly
/// incomplete with a scope gap but no semantic-capture-failure
/// count. An unswitched call keeps today's decision, including the
/// Gap (with evidence) for a planned descriptor 0 — and a set bit
/// with descriptor 0 (a planned slot over a stale switch) keeps the
/// same Gap, since only a downgraded cookie descriptor narrows.
#[test]
fn begin_action_narrows_only_switched_slots() {
    use p11scope_ebpf_common::LinuxLayout;
    use root_writers::{BeginAction, BeginDecision};
    for layout in [LinuxLayout::Lp64, LinuxLayout::Ilp32] {
        assert_eq!(
            root_writers::begin_action(true, 21, 1, layout),
            BeginAction::Skip,
            "a switched proved-irrelevant call skips silently"
        );
        assert_eq!(
            root_writers::begin_action(true, 0, 1, layout),
            BeginAction::Gap { evidence: true },
            "a planned descriptor 0 keeps its Gap even with the bit set"
        );
        for configured in [0, 2, 3, 4, u32::MAX] {
            assert_eq!(
                root_writers::begin_action(true, 21, configured, layout),
                BeginAction::Gap { evidence: false },
                "a switched affecting call gaps without evidence (class {configured})"
            );
        }
        for (configured, normalized) in [(1, 0), (2, 1), (3, 2)] {
            let BeginAction::Call(context) =
                root_writers::begin_action(false, 21, configured, layout)
            else {
                panic!("unswitched configured {configured} must decide Call");
            };
            assert_eq!(context.descriptor, 21);
            assert_eq!(context.class_bits, normalized);
        }
        for (descriptor, configured) in [(0, 1), (0, 2), (21, 0), (21, 4), (u32::MAX, 2)] {
            assert_eq!(
                root_writers::begin_action(false, descriptor, configured, layout),
                BeginAction::Gap { evidence: true },
                "unswitched descriptor {descriptor} class {configured} keeps Gap with evidence"
            );
        }
        // The unswitched arm is exactly the frozen decision: Call maps
        // to Call, Gap maps to Gap with evidence.
        for descriptor in [0, 1, 21] {
            for configured in [0, 1, 2, 3, 4] {
                match root_writers::begin_decision(descriptor, configured, layout) {
                    BeginDecision::Call(expected) => assert_eq!(
                        root_writers::begin_action(false, descriptor, configured, layout),
                        BeginAction::Call(expected),
                    ),
                    BeginDecision::Gap => assert_eq!(
                        root_writers::begin_action(false, descriptor, configured, layout),
                        BeginAction::Gap { evidence: true },
                    ),
                }
            }
        }
    }
}

#[test]
fn completion_reason_names_result_lost_only_on_unjournaled() {
    use p11scope_ebpf_common::object_journal::{
        JOURNAL_END_TAIL_ABSENT, JOURNAL_END_UNJOURNALED, JOURNAL_REASON_SYNC_RETURN_RESULT_LOST,
    };
    for (flags, expected) in [
        (0, 0),
        (u32::from(JOURNAL_END_TAIL_ABSENT), 0),
        (
            u32::from(JOURNAL_END_UNJOURNALED),
            JOURNAL_REASON_SYNC_RETURN_RESULT_LOST,
        ),
        (
            u32::from(JOURNAL_END_TAIL_ABSENT | JOURNAL_END_UNJOURNALED),
            JOURNAL_REASON_SYNC_RETURN_RESULT_LOST,
        ),
    ] {
        let words = root_writers::ReturnWords {
            flags,
            ..root_writers::ReturnWords::default()
        };
        assert_eq!(root_writers::completion_reason(&words), expected);
    }
}

#[test]
fn end_header_and_absent_tail_initialize_every_byte_in_poisoned_storage() {
    use p11scope_ebpf_common::object_journal::{
        JOURNAL_END_FULL_BYTES, JOURNAL_END_TAIL_ABSENT, JOURNAL_END_UNJOURNALED, JOURNAL_KIND_END,
        JOURNAL_VERSION, JournalEndFull,
    };
    for absent in [false, true] {
        for tracked in [false, true] {
            let mut storage = std::mem::MaybeUninit::<JournalEndFull>::uninit();
            unsafe {
                storage
                    .as_mut_ptr()
                    .cast::<u8>()
                    .write_bytes(0xa5, JOURNAL_END_FULL_BYTES)
            };
            let words = root_writers::ReturnWords {
                thread: if tracked { 41 } else { 0 },
                sequence: if tracked { 7 } else { 0 },
                flags: if tracked {
                    0
                } else {
                    u32::from(JOURNAL_END_UNJOURNALED)
                },
                pad: 0,
            };
            unsafe { root_writers::initialize_end(storage.as_mut_ptr(), &words, absent) };
            let bytes = unsafe {
                std::slice::from_raw_parts(storage.as_ptr().cast::<u8>(), JOURNAL_END_FULL_BYTES)
            };
            let mut expected = [0u8; 24];
            expected[..2].copy_from_slice(&JOURNAL_VERSION.to_ne_bytes());
            expected[2..4].copy_from_slice(&(JOURNAL_END_FULL_BYTES as u16).to_ne_bytes());
            expected[4] = JOURNAL_KIND_END;
            expected[5] = words.flags as u8 | if absent { JOURNAL_END_TAIL_ABSENT } else { 0 };
            expected[8..16].copy_from_slice(&words.thread.to_ne_bytes());
            expected[16..24].copy_from_slice(&words.sequence.to_ne_bytes());
            assert_eq!(&bytes[..24], &expected);
            assert!(bytes[24..392].iter().all(|byte| *byte == 0xa5));
            assert!(
                bytes[392..]
                    .iter()
                    .all(|byte| *byte == if absent { 0 } else { 0xa5 })
            );
        }
    }
}

#[test]
fn end_length_header_trailer_and_absent_tail_initialize_in_poisoned_storage() {
    use p11scope_ebpf_common::evidence_table::{
        LENGTH_KIND_SCELL, LENGTH_STATUS_OK, LENGTH_TRAILER_VERSION,
    };
    use p11scope_ebpf_common::object_journal::{
        JOURNAL_END_FULL_BYTES, JOURNAL_END_LENGTH_BYTES, JOURNAL_END_TAIL_ABSENT,
        JOURNAL_END_UNJOURNALED, JOURNAL_KIND_END, JOURNAL_VERSION, JournalEndLength,
        LengthTrailer,
    };
    // v0.8.0 keymeta Task 2: the 648-byte writer shares the header and
    // absent-tail rules with the 632-byte writer, corrects the length
    // field, and stores the carried trailer verbatim.
    for absent in [false, true] {
        for tracked in [false, true] {
            let mut storage = std::mem::MaybeUninit::<JournalEndLength>::uninit();
            unsafe {
                storage
                    .as_mut_ptr()
                    .cast::<u8>()
                    .write_bytes(0xa5, JOURNAL_END_LENGTH_BYTES)
            };
            let words = root_writers::ReturnWords {
                thread: if tracked { 41 } else { 0 },
                sequence: if tracked { 7 } else { 0 },
                flags: if tracked {
                    0
                } else {
                    u32::from(JOURNAL_END_UNJOURNALED)
                },
                pad: 0,
            };
            let trailer = LengthTrailer {
                version: LENGTH_TRAILER_VERSION,
                kind: LENGTH_KIND_SCELL,
                status: LENGTH_STATUS_OK,
                reserved: [0; 4],
                value: 256,
            };
            let wrote = unsafe {
                root_writers::initialize_end_length(storage.as_mut_ptr(), &words, absent, &trailer)
            };
            assert!(wrote);
            let bytes = unsafe {
                std::slice::from_raw_parts(storage.as_ptr().cast::<u8>(), JOURNAL_END_LENGTH_BYTES)
            };
            let mut expected = [0u8; 24];
            expected[..2].copy_from_slice(&JOURNAL_VERSION.to_ne_bytes());
            expected[2..4].copy_from_slice(&(JOURNAL_END_LENGTH_BYTES as u16).to_ne_bytes());
            expected[4] = JOURNAL_KIND_END;
            expected[5] = words.flags as u8 | if absent { JOURNAL_END_TAIL_ABSENT } else { 0 };
            expected[8..16].copy_from_slice(&words.thread.to_ne_bytes());
            expected[16..24].copy_from_slice(&words.sequence.to_ne_bytes());
            assert_eq!(&bytes[..24], &expected);
            assert!(bytes[24..392].iter().all(|byte| *byte == 0xa5));
            assert!(
                bytes[392..JOURNAL_END_FULL_BYTES]
                    .iter()
                    .all(|byte| *byte == if absent { 0 } else { 0xa5 })
            );
            let mut expected_trailer = [0u8; 16];
            expected_trailer[..2].copy_from_slice(&LENGTH_TRAILER_VERSION.to_ne_bytes());
            expected_trailer[2] = LENGTH_KIND_SCELL;
            expected_trailer[3] = LENGTH_STATUS_OK;
            expected_trailer[8..16].copy_from_slice(&256u64.to_ne_bytes());
            assert_eq!(&bytes[JOURNAL_END_FULL_BYTES..], &expected_trailer);
        }
    }
    // A refused flag conversion writes no byte (the reservation stays
    // poisoned) and reports false.
    let mut storage = std::mem::MaybeUninit::<JournalEndLength>::uninit();
    unsafe {
        storage
            .as_mut_ptr()
            .cast::<u8>()
            .write_bytes(0xa5, JOURNAL_END_LENGTH_BYTES)
    };
    let words = root_writers::ReturnWords {
        thread: 41,
        sequence: 7,
        flags: 0x100,
        pad: 0,
    };
    let trailer = LengthTrailer {
        version: LENGTH_TRAILER_VERSION,
        kind: LENGTH_KIND_SCELL,
        status: LENGTH_STATUS_OK,
        reserved: [0; 4],
        value: 256,
    };
    let wrote = unsafe {
        root_writers::initialize_end_length(storage.as_mut_ptr(), &words, false, &trailer)
    };
    assert!(!wrote);
    let bytes = unsafe {
        std::slice::from_raw_parts(storage.as_ptr().cast::<u8>(), JOURNAL_END_LENGTH_BYTES)
    };
    assert!(bytes.iter().all(|byte| *byte == 0xa5));
}

/// Length stash (v0.8.0 keymeta Task 2): every entry acquisition
/// flows through the single shared `acquire_length_entry_args!`
/// invocation — the raw reader with the probe context, the layout
/// and the descriptor-derived mask variable, spelled exactly once
/// — whose exact fetch sequence the ebpf-common twin asserts with
/// a spy at the production boundary. The comment-free stash
/// signature and prologue are pinned contiguously (whitespace
/// normalized) through that call, so the mask resolves from the
/// stash's own descriptor parameter and a zero mask (count-only,
/// narrowed, unlisted, corrupt, info) runs the complete refusal
/// block — stale-row delete and return — before any acquisition.
/// No `arg_u64` use of any spelling may remain in the stash
/// body outside the pinned invocation: an extra read there — or a
/// widened mask in the invocation — would bypass the shared
/// guard-to-index binding the twin pins.
#[test]
fn length_stash_acquires_only_through_the_shared_masked_call() {
    const SOURCE: &str = include_str!("../crates/ebpf/src/journal_roots.rs");
    fn stash_body(source: &str) -> Option<&str> {
        source
            .split_once("    fn stash_length_entry(")
            .map(|(_, tail)| tail)
            .and_then(|tail| tail.split_once("\n    }\n").map(|(text, _)| text))
    }
    /// Code tokens of the stash body: line comments document the
    /// reader and the mask in prose, so only non-comment text is
    /// pinned. The body holds no string literal or `/` operator, so
    /// `//` always opens a comment; a future `//` inside a literal
    /// would truncate that line and fail the pin closed.
    fn code_tokens(text: &str) -> String {
        text.lines()
            .map(|line| line.split("//").next().unwrap_or(""))
            .collect::<Vec<_>>()
            .join("\n")
    }
    /// Whitespace-normalized form: every whitespace run becomes one
    /// space, so the prologue pin ignores indentation and line breaks
    /// but still fails on any inserted, removed or reworded token.
    fn normalize(text: &str) -> String {
        text.split_whitespace().collect::<Vec<_>>().join(" ")
    }
    fn contract(source: &str) -> bool {
        let Some(text) = stash_body(source) else {
            return false;
        };
        // Every check below runs on the normalized stash, so a line
        // break inside a whitespace run never fails the pin while
        // any inserted, removed or reworded token still does.
        let code = normalize(&code_tokens(text));
        // The sole acquisition: the shared macro exactly once, with
        // the raw reader, the probe context, the layout and the
        // descriptor-derived mask variable. A widened mask
        // expression (`mask | 64`) would hand descriptor 31 [3, 4, 6]
        // instead of the authorized [3, 4].
        const INVOCATION: &str =
            "acquire_length_entry_args!(arg_u64, ctx, layout, mask, words, present);";
        if code.matches("acquire_length_entry_args!").count() != 1 || !code.contains(INVOCATION) {
            return false;
        }
        // Contiguous signature-to-acquisition pin (comment-free above,
        // whitespace normalized): the stash parameter list, the
        // descriptor-derived mask, the complete zero-mask refusal
        // block and the acquisition preamble appear contiguously
        // through the sole macro call. A rebound `descriptor` before
        // the mask definition, or any weakening of the `if mask == 0`
        // condition or the refusal body, breaks the contiguity and
        // fails closed.
        const PROLOGUE: &str = "ctx: &ProbeContext, key: &StartKey, descriptor: u32, layout: LinuxLayout, ) { let mask = length_entry_fetch_mask(descriptor); if mask == 0 { let _ = EVIDENCE_START.remove(key); return; } let start_ts_ns = unsafe { p11_owner_start_get(key, 0).as_ref() }.map(|start| start.ts_ns); let mut row = EvidenceStart::default(); let mut words = [0u64; 7]; let mut present: u8 = 0; acquire_length_entry_args!(arg_u64, ctx, layout, mask, words, present);";
        if !code.starts_with(&normalize(PROLOGUE)) {
            return false;
        }
        // Descriptor-derived mask: the single definition resolves from
        // the stash parameter the prologue pins.
        const DEFINITION: &str = "let mask = length_entry_fetch_mask(descriptor);";
        if code.matches(DEFINITION).count() != 1 {
            return false;
        }
        // No other mask use: past the definition, `mask` names only
        // the refusal check and the pinned invocation argument.
        if code.replacen(DEFINITION, "", 1).matches("mask").count() != 2 {
            return false;
        }
        // No raw reader outside the pinned invocation: no `arg_u64`
        // use of any spelling survives beside the shared call.
        !code.replacen(INVOCATION, "", 1).contains("arg_u64")
    }
    assert!(
        contract(SOURCE),
        "stash_length_entry must refuse on a zero mask before acquiring, then acquire only through the single exact acquire_length_entry_args!(arg_u64, ctx, layout, mask, words, present) invocation with no other arg_u64 use"
    );
    let start = SOURCE.find("    fn stash_length_entry(").unwrap();
    // A wrapped spelling of the pinned invocation (a line break
    // inside a whitespace run) still satisfies the contract.
    let wrapped = SOURCE[start..].replacen(
        "acquire_length_entry_args!(arg_u64, ctx, layout, mask, words, present);",
        "acquire_length_entry_args!(arg_u64,\n            ctx, layout, mask, words, present);",
        1,
    );
    assert!(
        contract(&format!("{}{}", &SOURCE[..start], wrapped)),
        "a wrapped pinned invocation must satisfy the contract"
    );
    let tail = SOURCE[start..].replacen("acquire_length_entry_args!", "REMOVED!", 1);
    assert!(
        !contract(&format!("{}{}", &SOURCE[..start], tail)),
        "a stash that bypasses the shared call must fail the contract"
    );
    let tail = SOURCE[start..].replacen(
        "        let mut fetch = ",
        "        let _ = arg_u64(ctx, 6, layout);\n        let mut fetch = ",
        1,
    );
    assert!(
        !contract(&format!("{}{}", &SOURCE[..start], tail)),
        "an extra direct fetch beside the shared call must fail the contract"
    );
    let tail = SOURCE[start..].replacen("length_entry_fetch_mask(descriptor)", "REMOVED", 1);
    assert!(
        !contract(&format!("{}{}", &SOURCE[..start], tail)),
        "an unmasked stash must fail the contract"
    );
    // A widened mask in the invocation (descriptor 31/C_Encrypt:
    // authorized [3, 4] becomes [3, 4, 6]) must fail the contract.
    let tail = SOURCE[start..].replacen(
        "acquire_length_entry_args!(arg_u64, ctx, layout, mask, words, present);",
        "acquire_length_entry_args!(arg_u64, ctx, layout, mask | 64, words, present);",
        1,
    );
    assert!(
        !contract(&format!("{}{}", &SOURCE[..start], tail)),
        "a widened mask in the shared call must fail the contract"
    );
    // An equivalent parenthesized spelling of a direct fetch beside
    // the shared call must fail the contract.
    let tail = SOURCE[start..].replacen(
        "        let mut fetch = ",
        "        let _ = (arg_u64)(ctx, 6, layout);\n        let mut fetch = ",
        1,
    );
    assert!(
        !contract(&format!("{}{}", &SOURCE[..start], tail)),
        "an equivalent parenthesized direct fetch must fail the contract"
    );
    // A rebound descriptor before the mask definition (descriptor 94
    // selects the DecapsulateKey scalar [6] even on an Encrypt
    // descriptor 31 authorizing [3, 4], or a narrowed 0 authorizing
    // none) must fail the contract.
    let tail = SOURCE[start..].replacen(
        "        let mask = length_entry_fetch_mask(descriptor);",
        "        let descriptor = 94;\n        let mask = length_entry_fetch_mask(descriptor);",
        1,
    );
    assert!(
        !contract(&format!("{}{}", &SOURCE[..start], tail)),
        "a rebound descriptor before the mask definition must fail the contract"
    );
    // A weakened zero-mask refusal (descriptor 0 bypasses the required
    // early delete and return) must fail the contract.
    let tail = SOURCE[start..].replacen(
        "        if mask == 0 {",
        "        if mask == 0 && descriptor != 0 {",
        1,
    );
    assert!(
        !contract(&format!("{}{}", &SOURCE[..start], tail)),
        "a weakened zero-mask refusal must fail the contract"
    );
}

/// Shared length acquisition (v0.8.0 keymeta Task 2): the
/// production fetch macro binds each guard to its own literal
/// index — six `$fetch($ctx, N, $layout)` calls, each exactly
/// once, each under `$mask & (1 << N)`, nothing else. A dynamic
/// index becomes register-offset pt_regs arithmetic (`ctx += reg`),
/// which the kernel verifier rejects with "dereference of modified
/// ctx ptr" on every kernel (observed on 6.6/6.12/7.0); index 0 is
/// never an approved length position. The ebpf-common behavioral
/// twin asserts the same binding by executing the shared macro;
/// this pin locks the structure.
#[test]
fn length_acquisition_binds_each_guard_to_its_literal_index() {
    const SOURCE: &str = include_str!("../crates/ebpf-common/src/object_flow.rs");
    fn acquire_body(source: &str) -> Option<&str> {
        source
            .split_once("macro_rules! acquire_length_entry_args")
            .map(|(_, tail)| tail)
            .and_then(|tail| tail.split_once("\n}\n").map(|(text, _)| text))
    }
    fn guard_before(text: &str, position: usize) -> Option<u8> {
        let guard = text[..position].rfind("mask & 0x")?;
        let digits = text.get(guard + "mask & 0x".len()..guard + "mask & 0x".len() + 2)?;
        u8::from_str_radix(digits, 16).ok()
    }
    fn contract(source: &str) -> bool {
        let Some(text) = acquire_body(source) else {
            return false;
        };
        // Exactly six fetch calls exist, each literal exactly once,
        // and each sits under its own mask bit.
        text.matches("$fetch($ctx, ").count() == 6
            && (1..=6u8).all(|index| {
                let marker = format!("$fetch($ctx, {index}, $layout)");
                if text.matches(&marker).count() != 1 {
                    return false;
                }
                let position = text.find(&marker).expect("counted once");
                guard_before(text, position) == Some(1u8 << index)
            })
    }
    assert!(
        contract(SOURCE),
        "acquire_length_entry_args must fetch each literal index 1..=6 exactly once, each under its own mask bit"
    );
    let start = SOURCE
        .find("macro_rules! acquire_length_entry_args")
        .unwrap();
    // Swapped guard bits 1/2: the descriptor-35 shape (C_Decrypt,
    // authorized [2]) would acquire index 1 instead.
    let tail = SOURCE[start..]
        .replacen("if $mask & 0x02 != 0", "if $mask & 0xZZ != 0", 1)
        .replacen("if $mask & 0x04 != 0", "if $mask & 0x02 != 0", 1)
        .replacen("if $mask & 0xZZ != 0", "if $mask & 0x04 != 0", 1);
    assert!(
        !contract(&format!("{}{}", &SOURCE[..start], tail)),
        "swapped guard bits must fail the contract"
    );
    // An extra seventh-argument fetch: the descriptor-31 shape
    // (C_Encrypt, authorized [3, 4]) would acquire [3, 4, 6].
    let tail = SOURCE[start..].replacen(
        "$present |= 0x40;\n            }\n        }",
        "$present |= 0x40;\n            }\n        }\n        let _ = $fetch($ctx, 6, $layout);",
        1,
    );
    assert!(
        !contract(&format!("{}{}", &SOURCE[..start], tail)),
        "an extra fetch must fail the contract"
    );
    let tail = SOURCE[start..].replacen("$fetch($ctx, 3, $layout)", "REMOVED", 1);
    assert!(
        !contract(&format!("{}{}", &SOURCE[..start], tail)),
        "a removed fetch must fail the contract"
    );
    let tail = SOURCE[start..].replacen(
        "$fetch($ctx, 3, $layout)",
        "$fetch($ctx, index, $layout)",
        1,
    );
    assert!(
        !contract(&format!("{}{}", &SOURCE[..start], tail)),
        "a dynamic fetch index must fail the contract"
    );
    let tail = SOURCE[start..].replacen("$fetch($ctx, 3, $layout)", "$fetch($ctx, 0, $layout)", 1);
    assert!(
        !contract(&format!("{}{}", &SOURCE[..start], tail)),
        "an index-0 fetch must fail the contract"
    );
}

/// Length trailer (v0.8.0 keymeta Task 2): the START stamp lookup
/// null-checks its pointer through an explicit `is_null` branch
/// before any field load. Folding the lookup into an
/// `as_ref().map(ts)` Option chain lets LLVM merge the null check
/// with the adapter's downstream flag arithmetic into a bitwise OR
/// on the map pointer itself, which the verifier rejects ("bitwise
/// operator |= on pointer prohibited", observed on 7.0).
#[test]
fn length_trailer_null_checks_the_start_pointer_explicitly() {
    const SOURCE: &str = include_str!("../crates/ebpf/src/journal_roots.rs");
    fn trailer_body(source: &str) -> Option<&str> {
        source
            .split_once("    pub(crate) fn length_trailer_for_return(")
            .map(|(_, tail)| tail)
            .and_then(|tail| tail.split_once("\n    }\n").map(|(text, _)| text))
    }
    fn contract(source: &str) -> bool {
        let Some(text) = trailer_body(source) else {
            return false;
        };
        text.contains("start.is_null()") && !text.contains(".map(|start| start.ts_ns)")
    }
    assert!(
        contract(SOURCE),
        "length_trailer_for_return must null-check the START pointer explicitly"
    );
    let start = SOURCE
        .find("    pub(crate) fn length_trailer_for_return(")
        .unwrap();
    let tail = SOURCE[start..].replacen("start.is_null()", "REMOVED", 1);
    assert!(
        !contract(&format!("{}{}", &SOURCE[..start], tail)),
        "removed start.is_null()"
    );
    let tail = SOURCE[start..].replacen(
        "Some(unsafe { (*start).ts_ns })",
        "unsafe { p11_owner_start_get(key, 0).as_ref() }.map(|start| start.ts_ns)",
        1,
    );
    assert!(
        !contract(&format!("{}{}", &SOURCE[..start], tail)),
        "an as_ref().map chain must fail the contract"
    );
}

/// Length END (v0.8.0 keymeta Task 2): the 648 path stamps the
/// cookie-derived function ordinal into the payload's target
/// function. Sync START rows leave it `FUNCTION_NONE`, and the
/// trailer validator matches the kind against the
/// function-addressed evidence row — a 648 carrying -1 fails
/// closed, shedding every length call (observed: 172 arrivals, 0
/// decodes, all joins lost). The root's length dispatch
/// guarantees a valid length descriptor here.
#[test]
fn length_end_stamps_the_cookie_derived_function() {
    const SOURCE: &str = include_str!("../crates/ebpf/src/journal_roots.rs");
    fn return_body(source: &str) -> Option<&str> {
        source
            .split_once("    pub(crate) fn ordinary_return<Record: ReturnPayload>(")
            .map(|(_, tail)| tail)
            .and_then(|tail| tail.split_once("\n    }\n").map(|(text, _)| text))
    }
    fn contract(source: &str) -> bool {
        let Some(text) = return_body(source) else {
            return false;
        };
        text.contains("if Record::LENGTH {")
            && text.contains("cookie_descriptor(cookie_of(&ctx))")
            && text.contains("event.target_function).write(descriptor - 1)")
    }
    assert!(
        contract(SOURCE),
        "ordinary_return must stamp the cookie-derived function on the 648 path"
    );
    let start = SOURCE
        .find("    pub(crate) fn ordinary_return<Record: ReturnPayload>(")
        .unwrap();
    for marker in [
        "cookie_descriptor(cookie_of(&ctx))",
        "event.target_function).write(descriptor - 1)",
    ] {
        let tail = SOURCE[start..].replacen(marker, "REMOVED", 1);
        assert!(
            !contract(&format!("{}{}", &SOURCE[..start], tail)),
            "removed {marker}"
        );
    }
}

/// Length END on the modeled path (v0.8.0 keymeta Task 2): the
/// object-branch 648 path stamps the cookie-derived function
/// ordinal into the payload's target function, like the ordinary
/// path. Sync START rows leave it `FUNCTION_NONE`, and the trailer
/// validator refuses a `FUNCTION_NONE` 648 wholesale, losing the
/// completion. The root's length dispatch guarantees a valid length
/// descriptor here; `object_return` reuses its validated
/// `descriptor` local.
#[test]
fn length_end_stamps_the_cookie_derived_function_on_the_modeled_path() {
    const SOURCE: &str = include_str!("../crates/ebpf/src/main.rs");
    fn return_body(source: &str) -> Option<&str> {
        source
            .split_once("fn object_return<const JOURNAL: bool, Record: ReturnPayload>(")
            .map(|(_, tail)| tail)
            .and_then(|tail| tail.split_once("\n}\n").map(|(text, _)| text))
    }
    fn contract(source: &str) -> bool {
        let Some(text) = return_body(source) else {
            return false;
        };
        text.contains("if Record::LENGTH")
            && text.contains("base.event.target_function).write(descriptor - 1)")
    }
    assert!(
        contract(SOURCE),
        "object_return must stamp the cookie-derived function on the 648 path"
    );
    let start = SOURCE
        .find("fn object_return<const JOURNAL: bool, Record: ReturnPayload>(")
        .unwrap();
    let marker = "base.event.target_function).write(descriptor - 1)";
    let tail = SOURCE[start..].replacen(marker, "REMOVED", 1);
    assert!(
        !contract(&format!("{}{}", &SOURCE[..start], tail)),
        "removed {marker}"
    );
}

/// Length stash lifecycle (v0.8.0 keymeta Task 2): the entry wrapper
/// inserts on retention (overwrite), deletes on both refusals (the
/// zero-mask refusal before any fetch and the adapter refusal — a
/// stale row is never trusted) and counts full-map insert failures.
/// The return wrapper deletes unconditionally (every emission
/// deletes) and counts stamp/layout mismatches on its own cell.
#[test]
fn length_stash_lifecycle_pins_insert_delete_and_failure_counts() {
    const SOURCE: &str = include_str!("../crates/ebpf/src/journal_roots.rs");
    fn body<'a>(source: &'a str, marker: &str) -> Option<&'a str> {
        source
            .split_once(marker)
            .map(|(_, tail)| tail)
            .and_then(|tail| tail.split_once("\n    }\n").map(|(text, _)| text))
    }
    fn stash_contract(source: &str) -> bool {
        let Some(text) = body(source, "    fn stash_length_entry(") else {
            return false;
        };
        text.contains("EVIDENCE_START.insert(key, &row, 0)")
            && text.matches("EVIDENCE_START.remove(key)").count() >= 2
            && text.contains("bump_evidence(EVIDENCE_LENGTH_INSERT_FAILURES)")
    }
    fn trailer_contract(source: &str) -> bool {
        let Some(text) = body(source, "    pub(crate) fn length_trailer_for_return(") else {
            return false;
        };
        text.contains("let _ = EVIDENCE_START.remove(key);")
            && text
                .matches("bump_evidence(EVIDENCE_LENGTH_STASH_MISMATCHES)")
                .count()
                >= 2
    }
    assert!(
        stash_contract(SOURCE),
        "stash_length_entry must insert on retention, delete on refusal and bump insert failures"
    );
    assert!(
        trailer_contract(SOURCE),
        "length_trailer_for_return must delete unconditionally and bump mismatches"
    );
    let stash_start = SOURCE.find("    fn stash_length_entry(").unwrap();
    for marker in [
        "EVIDENCE_START.insert(key, &row, 0)",
        "EVIDENCE_START.remove(key)",
        "bump_evidence(EVIDENCE_LENGTH_INSERT_FAILURES)",
    ] {
        let tail = SOURCE[stash_start..].replacen(marker, "REMOVED", 1);
        assert!(
            !stash_contract(&format!("{}{}", &SOURCE[..stash_start], tail)),
            "removed {marker}"
        );
    }
    let trailer_start = SOURCE
        .find("    pub(crate) fn length_trailer_for_return(")
        .unwrap();
    for marker in [
        "let _ = EVIDENCE_START.remove(key);",
        "bump_evidence(EVIDENCE_LENGTH_STASH_MISMATCHES)",
    ] {
        let tail = SOURCE[trailer_start..].replacen(marker, "REMOVED", 1);
        assert!(
            !trailer_contract(&format!("{}{}", &SOURCE[..trailer_start], tail)),
            "removed {marker}"
        );
    }
}

/// Length stash on unemitted modeled returns (v0.8.0 keymeta Task 2):
/// an object-branch return that never emits never resolves its
/// trailer (which deletes), so it abandons the stash row; otherwise
/// the row lingers until key reuse or stop scrub.
#[test]
fn length_object_return_abandons_the_stash_when_unemitted() {
    const SOURCE: &str = include_str!("../crates/ebpf/src/main.rs");
    fn return_body(source: &str) -> Option<&str> {
        source
            .split_once("fn object_return<const JOURNAL: bool, Record: ReturnPayload>(")
            .map(|(_, tail)| tail)
            .and_then(|tail| tail.split_once("\n}\n").map(|(text, _)| text))
    }
    fn contract(source: &str) -> bool {
        let Some(text) = return_body(source) else {
            return false;
        };
        text.contains("if Record::LENGTH && !emitted")
            && text.contains("length_return_abandon(&key)")
    }
    assert!(
        contract(SOURCE),
        "object_return must abandon the stash when LENGTH and !emitted"
    );
    let start = SOURCE
        .find("fn object_return<const JOURNAL: bool, Record: ReturnPayload>(")
        .unwrap();
    let marker = "if Record::LENGTH && !emitted";
    let tail = SOURCE[start..].replacen(marker, "REMOVED", 1);
    assert!(
        !contract(&format!("{}{}", &SOURCE[..start], tail)),
        "removed {marker}"
    );
}

/// Length stash on identity-refused returns (v0.8.0 keymeta Task 2):
/// a length call that passes entry identity and meets a remap before
/// return retires START with the identity reason; the stash row must
/// go with it (abandoned under `Record::LENGTH`), or the stranded
/// row lingers until key reuse or stop scrub and the terminal-clear
/// contract fails. Both return halves — the ordinary journal half
/// and the modeled object half — abandon in that arm.
#[test]
fn length_identity_refusal_abandons_the_stash_on_both_halves() {
    const ROOTS: &str = include_str!("../crates/ebpf/src/journal_roots.rs");
    const MAIN: &str = include_str!("../crates/ebpf/src/main.rs");
    fn body<'a>(source: &'a str, marker: &str, end: &str) -> Option<&'a str> {
        source
            .split_once(marker)
            .map(|(_, tail)| tail)
            .and_then(|tail| tail.split_once(end).map(|(text, _)| text))
    }
    fn arm_abandons(text: &str) -> bool {
        let Some(identity) = text.find("!image_pair_matches") else {
            return false;
        };
        let Some(facts) = text[identity..].find("capture_return_facts") else {
            return false;
        };
        let arm = &text[identity..identity + facts];
        arm.contains("if Record::LENGTH") && arm.contains("length_return_abandon(&key)")
    }
    fn ordinary_contract(source: &str) -> bool {
        let Some(text) = body(
            source,
            "    pub(crate) fn ordinary_return<Record: ReturnPayload>(",
            "\n    }\n",
        ) else {
            return false;
        };
        arm_abandons(text)
    }
    fn modeled_contract(source: &str) -> bool {
        let Some(text) = body(
            source,
            "fn object_return<const JOURNAL: bool, Record: ReturnPayload>(",
            "\n}\n",
        ) else {
            return false;
        };
        arm_abandons(text)
    }
    assert!(
        ordinary_contract(ROOTS),
        "ordinary_return must abandon the stash in its identity-refusal arm"
    );
    assert!(
        modeled_contract(MAIN),
        "object_return must abandon the stash in its identity-refusal arm"
    );
    let start = ROOTS
        .find("    pub(crate) fn ordinary_return<Record: ReturnPayload>(")
        .unwrap();
    let marker = "length_return_abandon(&key)";
    let tail = ROOTS[start..].replacen(marker, "REMOVED", 1);
    assert!(
        !ordinary_contract(&format!("{}{}", &ROOTS[..start], tail)),
        "removed ordinary identity abandon"
    );
}

#[test]
fn routing_words_are_sampled_once_and_stored_before_the_next_sampler() {
    use p11scope_ebpf_common::Event;
    use root_writers::RoutingWord;
    let mut storage = std::mem::MaybeUninit::<Event>::uninit();
    let raw = storage.as_mut_ptr();
    unsafe {
        raw.cast::<u8>()
            .write_bytes(0xa5, std::mem::size_of::<Event>())
    };
    let mut order = Vec::new();
    unsafe {
        root_writers::fill_routing(raw, |word| {
            order.push(word);
            match word {
                RoutingWord::PidTgid => 11,
                RoutingWord::Cgroup => {
                    assert_eq!((*raw).pid_tgid, 11);
                    22
                }
                RoutingWord::RootAffiliation => {
                    assert_eq!((*raw).pid_tgid, 11);
                    assert_eq!((*raw).cgroup_id, 22);
                    1
                }
            }
        });
    }
    assert_eq!(
        order,
        [
            RoutingWord::PidTgid,
            RoutingWord::Cgroup,
            RoutingWord::RootAffiliation
        ]
    );
    let bytes =
        unsafe { std::slice::from_raw_parts(raw.cast::<u8>(), std::mem::size_of::<Event>()) };
    let mut expected = vec![0xa5; std::mem::size_of::<Event>()];
    for (offset, value) in [
        (std::mem::offset_of!(Event, pid_tgid), 11u64),
        (std::mem::offset_of!(Event, cgroup_id), 22),
        (std::mem::offset_of!(Event, root_affiliation), 1),
    ] {
        expected[offset..offset + 8].copy_from_slice(&value.to_ne_bytes());
    }
    assert_eq!(bytes, expected);
}

#[test]
fn native_prepare_initializes_retained_bytes_and_preserves_blocked_retry() {
    let temporary = tempfile::tempdir().unwrap();
    let source = fs::read_to_string("crates/ebpf/native/object_journal.c").unwrap();
    for (index, mutant) in [
        None,
        Some((
            "txn_copy(out->record + 56, (const unsigned char *)start, 8);",
            "txn_copy(out->record + 56, (const unsigned char *)start + 8, 8);",
        )),
        Some((
            "__builtin_memset(out, 0, sizeof(*out));",
            "__builtin_memset(out, 0, sizeof(*out) - 4);",
        )),
        Some((
            "out->state = JOURNAL_SETTLE_BLOCKED;",
            "out->state = JOURNAL_SETTLE_EMPTY;",
        )),
        Some((
            "if (!journal_header_valid(bytes, kind, flags, 0, thread, sequence))",
            "if (0)",
        )),
    ]
    .into_iter()
    .enumerate()
    {
        let directory = temporary.path().join(index.to_string());
        fs::create_dir(&directory).unwrap();
        for file in ["task_owner.c", "task_owner.h", "object_journal.h"] {
            fs::copy(
                Path::new("crates/ebpf/native").join(file),
                directory.join(file),
            )
            .unwrap();
        }
        let native = if let Some((before, after)) = mutant {
            assert_eq!(source.matches(before).count(), 1, "native mutation anchor");
            source.replace(before, after)
        } else {
            source.clone()
        };
        fs::write(directory.join("object_journal.c"), native).unwrap();
        let binary = directory.join("prepare");
        let output = Command::new("clang-18")
            .args([
                "-O2",
                "-g",
                "-Wall",
                "-Wextra",
                "-Werror",
                "-pthread",
                "-DP11SCOPE_OBJECT_JOURNAL",
                "-DP11_JOURNAL_ROOTS_PREPARE_TEST",
                "-I",
            ])
            .arg(&directory)
            .arg("tests/fixtures/object-journal/journal_roots_bridge.c")
            .arg("-o")
            .arg(&binary)
            .output()
            .unwrap();
        assert!(
            output.status.success(),
            "{}",
            String::from_utf8_lossy(&output.stderr)
        );
        let output = Command::new(binary)
            .current_dir(&directory)
            .output()
            .unwrap();
        assert_eq!(
            output.status.success(),
            mutant.is_none(),
            "native control {index}: {}",
            String::from_utf8_lossy(&output.stderr)
        );
        if mutant.is_none() {
            assert!(String::from_utf8_lossy(&output.stdout).contains("52 native prepare"));
        }
    }
}

#[test]
fn private_journal_roots_reach_the_real_producer_with_bounded_stack() {
    if option_env!("P11SCOPE_JOURNAL_PROOF_ENABLED") != Some("1") {
        assert_eq!(option_env!("P11SCOPE_JOURNAL_PROOF_ENABLED"), Some("0"));
        return;
    }
    let object = Path::new(env!("OUT_DIR")).join("journal-proof-v1/p11scope-ebpf-journal-proof-v1");
    let output = Command::new("python3")
        .current_dir(env!("CARGO_MANIFEST_DIR"))
        .args(["-I", "-c", ROOT_CHECKER])
        .arg(&object)
        .output()
        .expect("inspect actual private roots");
    assert!(
        output.status.success(),
        "{}{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    print!("{}", String::from_utf8_lossy(&output.stdout));

    let temporary = tempfile::tempdir().unwrap();
    let (reader, _) = ROOT_CHECKER
        .split_once("\nfor name, required in {")
        .unwrap();
    let output = Command::new("python3")
        .current_dir(env!("CARGO_MANIFEST_DIR"))
        .args(["-I", "-c", &format!("{reader}\n{ROOT_MUTATIONS}")])
        .arg(&object)
        .arg(temporary.path())
        .output()
        .unwrap();
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    for (name, diagnostic) in [
        ("no-begin", "missing native/shared path"),
        ("no-returning", "missing native/shared path"),
        ("excess-stack", "lacks >=5% headroom"),
    ] {
        let output = Command::new("python3")
            .current_dir(env!("CARGO_MANIFEST_DIR"))
            .args(["-I", "-c", ROOT_CHECKER])
            .arg(temporary.path().join(name))
            .output()
            .unwrap();
        assert!(!output.status.success(), "actual ELF mutant {name} passed");
        assert!(
            String::from_utf8_lossy(&output.stderr).contains(diagnostic),
            "wrong mutant refusal: {}",
            String::from_utf8_lossy(&output.stderr)
        );
    }
}

#[test]
fn private_roots_reach_no_void_global_callee() {
    if option_env!("P11SCOPE_JOURNAL_PROOF_ENABLED") != Some("1") {
        assert_eq!(option_env!("P11SCOPE_JOURNAL_PROOF_ENABLED"), Some("0"));
        return;
    }
    let object = Path::new(env!("OUT_DIR")).join("journal-proof-v1/p11scope-ebpf-journal-proof-v1");
    let output = Command::new("python3")
        .current_dir(env!("CARGO_MANIFEST_DIR"))
        .args(["-I", "-c", VOID_CALLEE_CHECKER])
        .arg(&object)
        .output()
        .expect("inspect actual private callees");
    assert!(
        output.status.success(),
        "{}{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    print!("{}", String::from_utf8_lossy(&output.stdout));
}

#[test]
fn checker_depth_metric_sees_deep_low_stack_branch() {
    let (_, rest) = ROOT_CHECKER
        .split_once("# == DEPTH-CONTROL-BEGIN ==\n")
        .expect("depth control begin marker");
    let (control, _) = rest
        .split_once("\n# == DEPTH-CONTROL-END ==")
        .expect("depth control end marker");
    let output = Command::new("python3")
        .current_dir(env!("CARGO_MANIFEST_DIR"))
        .args(["-I", "-c", control])
        .output()
        .expect("run synthetic depth control");
    assert!(
        output.status.success(),
        "{}{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    print!("{}", String::from_utf8_lossy(&output.stdout));
    assert!(
        String::from_utf8_lossy(&output.stdout).contains("synthetic depth control: depth=9"),
        "synthetic depth control did not run to completion"
    );
}

const ROOT_CHECKER: &str = r#"
from pathlib import Path
import struct
import sys
# == DEPTH-CONTROL-BEGIN ==
def chain(key, path=()):
    assert key not in path, 'recursive journal BPF graph'
    paths = [chain(child, path + (key,)) for child in children(key)]
    cost, subpath = max(paths, default=(0, ()))
    return frame(key) + cost, (names.get(key, bodies[key][0]),) + subpath

def depth(key, path=()):
    assert key not in path, 'recursive journal BPF graph'
    kids = children(key)
    if not kids:
        return 1
    return 1 + max(depth(child, path + (key,)) for child in kids)

# Synthetic control: a 9-frame low-stack branch beside a 3-frame high-stack
# branch. chain() selects by stack cost, so its path length cannot prove the
# frame bound; depth() must report the deep branch independently. The real
# bodies/names/children/frame definitions below replace these fabrications.
syn_bodies = {name: (name,) for name in (
    'syn_root', 'syn_high1', 'syn_high2',
    'syn_low1', 'syn_low2', 'syn_low3', 'syn_low4',
    'syn_low5', 'syn_low6', 'syn_low7', 'syn_low8')}
syn_calls = {
    'syn_root': ['syn_low1', 'syn_high1'],
    'syn_high1': ['syn_high2'], 'syn_high2': [],
    'syn_low1': ['syn_low2'], 'syn_low2': ['syn_low3'],
    'syn_low3': ['syn_low4'], 'syn_low4': ['syn_low5'],
    'syn_low5': ['syn_low6'], 'syn_low6': ['syn_low7'],
    'syn_low7': ['syn_low8'], 'syn_low8': [],
}
syn_frames = {name: 32 for name in syn_bodies}
syn_frames['syn_high1'] = 160
syn_frames['syn_high2'] = 160
bodies, names = syn_bodies, {}
def children(key):
    return syn_calls[key]
def frame(key):
    return syn_frames[key]
syn_cost, syn_path = chain('syn_root')
print(f'synthetic stack selection: path={syn_path}, cost={syn_cost}')
assert syn_path == ('syn_root', 'syn_high1', 'syn_high2'), syn_path
assert syn_cost == 352, syn_cost
assert len(syn_path) <= 8, syn_path
assert depth('syn_root') == 9, 'depth must see the 9-frame low-stack branch'
assert depth('syn_high1') == 2 and depth('syn_low8') == 1
syn_calls['syn_high2'] = ['syn_root']
for metric in (chain, depth):
    try:
        metric('syn_root')
    except AssertionError:
        pass
    else:
        raise AssertionError('recursive synthetic graph was not refused')
print('synthetic depth control: depth=9, max-stack path len=3, cost=352')
# == DEPTH-CONTROL-END ==
sys.path.insert(0, str(Path('scripts').resolve()))
from _loader import load_path
reader = load_path(Path('scripts/check-bpf-map-defs.py'), 'journal_root_elf')
elf = reader.Elf(Path(sys.argv[1]).read_bytes())
bodies = {(s[3], s[4]): s for s in elf.symbols if s[1] & 15 == 2 and s[3] and s[5]}
raws = {elf.indices[name]: raw for name, (_, raw) in elf.sections.items()}
relocations = {}
for row, raw in elf.sections.values():
    if row[1] == 9:
        for at in range(0, len(raw), 16):
            address, info = struct.unpack_from('<QQ', raw, at)
            relocations[row[7], address] = (info & 0xffffffff, elf.symbols[info >> 32])

# Associate Rust's mangled ELF symbols with their actual BTF FUNC names at
# the same section/offset. Substring presence is not call reachability.
btf = reader.Btf(elf.sections['.BTF'][1])
ext = elf.sections['.BTF.ext'][1]
magic, version, flags, hlen, off, length = struct.unpack_from('<HBBIII', ext)
assert (magic, version, flags, hlen) == (0xeb9f, 1, 0, 32)
raw = ext[hlen + off:hlen + off + length]
stride, = struct.unpack_from('<I', raw)
assert stride == 8
names, pos = {}, 4
while pos < len(raw):
    section_name, count = struct.unpack_from('<II', raw, pos)
    section = elf.indices[reader.string_at(btf.strings, section_name)]
    pos += 8
    for _ in range(count):
        offset, ident = struct.unpack_from('<II', raw, pos)
        pos += stride
        assert btf.types[ident][0] == 12 and (section, offset) in bodies
        names[section, offset] = btf.types[ident][1]

def only(name):
    matches = [key for key, symbol in bodies.items() if symbol[0] == name]
    assert len(matches) == 1, f'expected one actual {name}, saw {len(matches)}'
    return matches[0]

def instructions(key):
    symbol = bodies[key]
    raw = raws[key[0]][key[1]:key[1] + symbol[5]]
    return [struct.unpack_from('<BBhi', raw, at) for at in range(0, len(raw), 8)]

def calls(key):
    found = []
    for index, (op, reg, _, immediate) in enumerate(instructions(key)):
        if op != 0x85 or reg >> 4 != 1:
            continue
        relocation = relocations.get((key[0], key[1] + index * 8))
        if relocation:
            kind, target = relocation
            assert kind == 10, f'unknown call relocation in {bodies[key][0]}'
            child = (target[3], target[4] + (immediate + 1) * 8)
        else:
            child = (key[0], key[1] + index * 8 + (immediate + 1) * 8)
        assert child in bodies, f'unresolved call in {bodies[key][0]}'
        found.append((index, child))
    return found

def children(key):
    return [target for _, target in calls(key)]

def closure(root):
    seen, pending = set(), [root]
    while pending:
        key = pending.pop()
        if key not in seen:
            seen.add(key)
            pending.extend(children(key))
    return seen

def reachable(root):
    return {names.get(key, bodies[key][0]) for key in closure(root)}

def frame(key):
    depth = 0
    insns = instructions(key)
    for index, (op, reg, offset, immediate) in enumerate(insns):
        if ((op & 7 in (2, 3) and reg & 15 == 10)
                or (op & 7 == 1 and reg >> 4 == 10)) and offset < 0:
            depth = max(depth, -offset)
        if (index and op == 0x07 and immediate < 0
                and insns[index - 1][:2] == (0xbf, 0xa0 | (reg & 15))):
            depth = max(depth, -immediate)
    return ((max(depth, 1) + 31) // 32) * 32

for name, required in {
    'p11_entry_journal': {'p11_journal_begin', 'p11_owner_start_begin', 'p11_instance_entry'},
    'p11_return_journal': {'p11_journal_returning', 'p11_owner_start_remove_reason',
                           'p11_instance_return', 'object_fill_return',
                           'object_emit_find', 'object_emit_get_attributes'},
}.items():
    root = only(name)
    expected_section = 'uprobe' if name == 'p11_entry_journal' else 'uretprobe'
    assert root[0] == elf.indices[expected_section], f'{name} is not an actual probe root'
    assert required <= reachable(root), f'{name} missing native/shared path: {required - reachable(root)}'
    cost, path = chain(root)
    assert cost <= 480, f'{name} stack chain {cost} lacks >=5% headroom: {" > ".join(path)}'
    assert len(path) <= 8, f'{name} exceeds eight call frames: {path}'
    frames = depth(root)
    assert frames <= 8, f'{name} call depth {frames} exceeds eight frames'
    print(f'{name}: stack-chain={cost}/512, depth={frames}/8, path={" > ".join(path)}')
for name in ('p11_entry', 'p11_return'):
    assert not any(symbol[0] == name for symbol in bodies.values()), \
        f'private ELF retained the inapplicable duplicate ordinary root {name}'
programs = [key for key in bodies if key[0] != elf.indices['.text']]
assert len(programs) >= 20, 'missing ordinary discovery/lifecycle/identity program inventory'
for root in programs:
    cost, path = chain(root)
    assert cost <= 480, f'exported {bodies[root][0]} chain {cost} lacks >=5% headroom: {" > ".join(path)}'
    assert len(path) <= 8, f'exported {bodies[root][0]} exceeds eight call frames'
    frames = depth(root)
    assert frames <= 8, f'exported {bodies[root][0]} call depth {frames} exceeds eight frames'
    print(f'exported {bodies[root][0]}: stack-chain={cost}/512, depth={frames}/8, path={" > ".join(path)}')
print(f'all {len(programs)} exported private-ELF program chains <=480/512 and depth <=8 frames')
functions = [node for node in btf.types[1:] if node[0] == 12]
assert functions
for function in functions:
    proto = btf.types[function[2]]
    assert proto[0] == 13 and proto[3] <= 5, f'{function[1]} exceeds five-register BPF ABI'
assert not any(symbol[0] == 'journal_header_write' for symbol in bodies.values()), \
    'six-scalar source core must be fully inlined, never an emitted function'
print(f'all {len(functions)} emitted function ABIs <=5 arguments')
"#;

const ROOT_MUTATIONS: &str = r#"
data = Path(sys.argv[1]).read_bytes()
output = Path(sys.argv[2])
section_offsets = {elf.indices[name]: row[4] for name, (row, _) in elf.sections.items()}
for label, root_name, removed_name, replacement_name in (
    ('no-begin', 'p11_entry_journal', 'p11_journal_begin', 'p11_journal_returning'),
    ('no-returning', 'p11_return_journal', 'p11_journal_returning', 'p11_journal_begin'),
):
    removed, replacement = only(removed_name), only(replacement_name)
    found = [(caller, index) for caller in closure(only(root_name))
             for index, target in calls(caller) if target == removed]
    assert found, 'actual native call mutation has no site'
    changed = bytearray(data)
    for caller, index in found:
        address = caller[1] + index * 8
        relocation = relocations.get((caller[0], address))
        if relocation:
            assert relocation[0] == 10 and relocation[1][3] == replacement[0]
            immediate = (replacement[1] - relocation[1][4]) // 8 - 1
        else:
            assert caller[0] == replacement[0]
            immediate = (replacement[1] - address) // 8 - 1
        struct.pack_into('<i', changed, section_offsets[caller[0]] + address + 4, immediate)
    (output / label).write_bytes(changed)
root = only('p11_entry_journal')
sites = [index for index, (op, reg, offset, _) in enumerate(instructions(root))
         if offset < 0 and ((op & 7 in (2, 3) and reg & 15 == 10)
                            or (op & 7 == 1 and reg >> 4 == 10))]
assert sites, 'actual entry stack mutation has no site'
changed = bytearray(data)
struct.pack_into('<h', changed, section_offsets[root[0]] + root[1] + sites[0] * 8 + 2, -488)
(output / 'excess-stack').write_bytes(changed)
"#;

const VOID_CALLEE_CHECKER: &str = r#"
from pathlib import Path
import struct
import sys
sys.path.insert(0, str(Path('scripts').resolve()))
from _loader import load_path
reader = load_path(Path('scripts/check-bpf-map-defs.py'), 'journal_void_guard')
elf = reader.Elf(Path(sys.argv[1]).read_bytes())
bodies = {(s[3], s[4]): s for s in elf.symbols if s[1] & 15 == 2 and s[3] and s[5]}
raws = {elf.indices[name]: raw for name, (_, raw) in elf.sections.items()}
relocations = {}
for row, raw in elf.sections.values():
    if row[1] == 9:
        for at in range(0, len(raw), 16):
            address, info = struct.unpack_from('<QQ', raw, at)
            relocations[row[7], address] = (info & 0xffffffff, elf.symbols[info >> 32])

# Associate Rust's mangled ELF symbols with their actual BTF FUNC names at
# the same section/offset. Substring presence is not call reachability.
btf = reader.Btf(elf.sections['.BTF'][1])
ext = elf.sections['.BTF.ext'][1]
magic, version, flags, hlen, off, length = struct.unpack_from('<HBBIII', ext)
assert (magic, version, flags, hlen) == (0xeb9f, 1, 0, 32)
raw = ext[hlen + off:hlen + off + length]
stride, = struct.unpack_from('<I', raw)
assert stride == 8
names, pos = {}, 4
while pos < len(raw):
    section_name, count = struct.unpack_from('<II', raw, pos)
    section = elf.indices[reader.string_at(btf.strings, section_name)]
    pos += 8
    for _ in range(count):
        offset, ident = struct.unpack_from('<II', raw, pos)
        pos += stride
        assert btf.types[ident][0] == 12 and (section, offset) in bodies
        names[section, offset] = btf.types[ident][1]

def instructions(key):
    symbol = bodies[key]
    raw = raws[key[0]][key[1]:key[1] + symbol[5]]
    return [struct.unpack_from('<BBhi', raw, at) for at in range(0, len(raw), 8)]

def children(key):
    found = []
    for index, (op, reg, _, immediate) in enumerate(instructions(key)):
        if op != 0x85 or reg >> 4 != 1:
            continue
        relocation = relocations.get((key[0], key[1] + index * 8))
        if relocation:
            kind, target = relocation
            assert kind == 10, f'unknown call relocation in {bodies[key][0]}'
            child = (target[3], target[4] + (immediate + 1) * 8)
        else:
            child = (key[0], key[1] + index * 8 + (immediate + 1) * 8)
        assert child in bodies, f'unresolved call in {bodies[key][0]}'
        found.append(child)
    return found

def closure(root):
    seen, pending = set(), [root]
    while pending:
        key = pending.pop()
        if key not in seen:
            seen.add(key)
            pending.extend(children(key))
    return seen

def reachable(root):
    return {names.get(key, bodies[key][0]) for key in closure(root)}

# The kernel verifier requires every GLOBAL BPF callee to return a scalar;
# a void global reachable from a program is refused at BPF_PROG_LOAD. The
# three compiler builtins are empirically exempt (loaded programs reach
# memset); every other void global must be unreachable from every program.
void_globals = set()
for node in btf.types[1:]:
    if node[0] == 12 and node[3] == 1:
        proto = btf.types[node[2]]
        assert proto[0] == 13, 'global BTF function without a prototype'
        if proto[2] == 0:
            void_globals.add(node[1])
builtins = {'memcpy', 'memmove', 'memset'}
assert builtins <= void_globals, \
    f'builtin carve-out is not all void globals: {builtins - void_globals}'
for name in ('p11_journal_begin', 'p11_journal_returning',
             'p11_journal_settle_prepare', 'p11_journal_settle_finish'):
    functions = [node for node in btf.types[1:] if node[0] == 12 and node[1] == name]
    assert len(functions) == 1 and functions[0][3] == 1, name + ' must stay a global BTF function'
    proto = btf.types[functions[0][2]]
    assert proto[0] == 13 and proto[2] != 0, name + ' must return a scalar for the verifier'
programs = [key for key in bodies if key[0] != elf.indices['.text']]
assert len(programs) >= 20, 'missing ordinary discovery/lifecycle/identity program inventory'
for key in programs:
    bad = sorted((reachable(key) & void_globals) - builtins)
    assert not bad, f'{bodies[key][0]} reaches void GLOBAL FUNCs the verifier refuses: {bad}'
print(f'all {len(programs)} programs reach no void GLOBAL callee outside the 3 builtins')
"#;
