//! SPDX-License-Identifier: GPL-2.0-or-later
//! Bounded object read protocols: shared production core (H7 slice C).
//!
//! Pure `core`-only implementations of the entry/return protocols from the
//! object-producer brief ("Exact producer protocols") and proposed privacy
//! allowlist v3. Host unit tests execute these exact functions with injected
//! readers; BPF adapters (a follow-up step) supply probe reads against the
//! same signatures. There is intentionally no second model.
//!
//! Conventions:
//! - Every target-memory access goes through caller-supplied `FnMut`
//!   readers: `read_word(addr)` reads one target word (`W` bytes,
//!   zero-extended) and `read_bytes(addr, buf)` reads exactly `buf.len()`
//!   bytes. `Err(())` is a failed read, distinct from any value including
//!   zero. Value readers are invoked at most once per eligible slot; the streamed
//!   production path may reread bounded headers for alias checks. Nothing
//!   is read speculatively.
//! - Ownership, teardown, phase and S1 evidence arrive as data parameters
//!   (`ReturnAuthority`, retained pointers/state, RV, mechanism status).
//!   This core consults no maps and keeps no shared-mutable walker state
//!   across calls; per-call retained state is plain caller-owned data.
//! - Span arithmetic is checked before any access: full claimed spans with
//!   checked multiply/add, inclusive last bytes, LP64 no-wrap, ia32 `u32`
//!   range. Null, unreadable and out-of-range inputs yield finite statuses,
//!   never values.
//! - Raw target words (pointers, handles, lengths) travel as plain `u64`
//!   data or in explicitly `Debug`-free structs. Verdict types carry only
//!   finite codes and may derive `Debug` for host asserts.

use crate::capture;
use crate::object_policy::{
    classify_attribute_scalar, classify_ec_params, derive_result_protocol, object_descriptor,
    safe_attribute_kind, valid_safe_attribute_length, DeriveResultProtocol, ObjectAction,
    SafeAttributeKind, SafeCurve, ScalarDeriveMechanism,
};
use crate::object_wire::{
    ObjectAttributeListWire, ObjectAttributeWire, OBJECT_DERIVE_DH_PKCS, OBJECT_DERIVE_ECDH1,
    OBJECT_DERIVE_ECDH1_COFACTOR, OBJECT_DERIVE_SHA256, OBJECT_DERIVE_UNAVAILABLE,
};
use crate::{instance, target_word_end, InstanceStamp, LinuxLayout, ARG_NONE};

/// `CKR_OK`: the only RV that authorizes result-handle and Find reads.
/// From `cryptoki-sys` 0.5.0 (`CK_RV = 0`).
pub const CKR_OK: u64 = 0;
/// `CKR_ATTRIBUTE_SENSITIVE` (17): GetAttributeValue partial-result RV.
pub const CKR_ATTRIBUTE_SENSITIVE: u64 = 17;
/// `CKR_ATTRIBUTE_TYPE_INVALID` (18): GetAttributeValue partial-result RV.
pub const CKR_ATTRIBUTE_TYPE_INVALID: u64 = 18;
/// `CKR_BUFFER_TOO_SMALL` (336): GetAttributeValue partial-result RV.
pub const CKR_BUFFER_TOO_SMALL: u64 = 336;
/// `CKR_PENDING` (516): no result pointer is ever read on pending.
pub const CKR_PENDING: u64 = 516;

/// At most eight inspected slots per template; at most eight Find handles.
pub const MAX_ATTRIBUTE_SLOTS: u64 = 8;
pub const MAX_FIND_HANDLES: u64 = 8;

/// Finite attribute-cell statuses (brief wire codes 0..=10).
pub mod attr_status {
    pub const ABSENT: u8 = 0;
    pub const VALUE: u8 = 1;
    pub const UNSUPPORTED: u8 = 2;
    pub const UNREADABLE: u8 = 3;
    pub const SIZE_ONLY: u8 = 4;
    pub const UNAVAILABLE: u8 = 5;
    pub const INVALID_LENGTH: u8 = 6;
    pub const CHANGED: u8 = 7;
    pub const ALIAS: u8 = 8;
    pub const INVALID_SPAN: u8 = 9;
    pub const INSUFFICIENT_CAPACITY: u8 = 10;
}

/// Finite handle statuses (brief wire codes 0..=9). This core emits 0..=8;
/// `CHANGED` is reserved: no protocol here rereads a handle word.
pub mod handle_status {
    pub const ABSENT: u8 = 0;
    pub const VALUE: u8 = 1;
    pub const UNREADABLE: u8 = 2;
    pub const INVALID_ZERO: u8 = 3;
    pub const INVALID_SPAN: u8 = 4;
    pub const ALIAS: u8 = 5;
    pub const DUPLICATE: u8 = 6;
    pub const PROTOCOL_UNAVAILABLE: u8 = 7;
    pub const SUPPRESSED: u8 = 8;
    pub const CHANGED: u8 = 9;
}

/// Object-tail flag bits contributed by this core (brief bits 0..=7).
/// Bit 7 (`CAPTURE_UNAVAILABLE`) is adapter-only; this core never sets it.
pub mod object_flag {
    pub const ARG_READ_FAILURE: u32 = 1 << 0;
    pub const UNAVAILABLE_RESULT: u32 = 1 << 1;
    pub const ALIAS: u32 = 1 << 2;
    pub const DUPLICATE_RESULT: u32 = 1 << 3;
    pub const CHANGED_METADATA: u32 = 1 << 4;
    pub const PARTIAL_RESULT: u32 = 1 << 5;
    pub const NULL_MECHANISM_CANCEL: u32 = 1 << 6;
    pub const CAPTURE_UNAVAILABLE: u32 = 1 << 7;
}

/// Find-section flag bits (brief bits 0..=5).
pub mod find_flag {
    pub const TRUNCATED: u8 = 1 << 0;
    pub const CHANGED_COUNT: u8 = 1 << 1;
    pub const INVALID_COUNT: u8 = 1 << 2;
    pub const INVALID_SPAN: u8 = 1 << 3;
    pub const COUNT_ALIAS: u8 = 1 << 4;
    pub const UNREADABLE_ELEMENT: u8 = 1 << 5;
}

/// Attribute-list flag bits (brief bits 0..=3, plus the slice-D
/// uninspected marker bit 4 for lists whose inspection never ran).
pub mod attr_list_flag {
    pub const PRESENT: u8 = 1 << 0;
    pub const TRUNCATED: u8 = 1 << 1;
    pub const HEADER_READ_FAILURE: u8 = 1 << 2;
    pub const INVALID_SPAN: u8 = 1 << 3;
    pub const UNINSPECTED: u8 = 1 << 4;
}

/// Finite attribute kinds (brief codes 0..=6).
pub mod attr_kind {
    pub const ABSENT: u8 = 0;
    pub const CLASS: u8 = 1;
    pub const KEY_TYPE: u8 = 2;
    pub const TOKEN: u8 = 3;
    pub const VALUE_LEN: u8 = 4;
    pub const MODULUS_BITS: u8 = 5;
    pub const EC_PARAMS: u8 = 6;
}

/// One classified attribute cell: finite kind/status plus a classified value.
/// The value is either an approved scalar/curve code or zero; unknown
/// selectors leave an all-zero cell. Policy-only: safe for `Debug`.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct AttrCell {
    pub kind: u8,
    pub status: u8,
    pub value: u16,
}

impl AttrCell {
    /// Adapter convenience: exact wire encoding of this classified cell.
    pub fn to_wire(self) -> ObjectAttributeWire {
        ObjectAttributeWire {
            kind: self.kind,
            status: self.status,
            value: self.value,
        }
    }
}

/// One eight-cell attribute list: creation-request observations or
/// GetAttributeValue results. Requested and result lists never mix: creation
/// inspection yields request lists, Get return yields the result list. Both
/// mirror template slots: cell `i` describes template slot `i`.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct AttributeListOutcome {
    pub cells: [AttrCell; 8],
    pub inspected: u8,
    pub flags: u8,
    pub object_flags: u32,
}

impl AttributeListOutcome {
    /// Adapter convenience: exact wire encoding (reserved words zeroed).
    pub fn to_wire(self) -> ObjectAttributeListWire {
        let mut cells = [ObjectAttributeWire {
            kind: 0,
            status: 0,
            value: 0,
        }; 8];
        let mut i = 0;
        while i < 8 {
            cells[i] = self.cells[i].to_wire();
            i += 1;
        }
        ObjectAttributeListWire {
            cells,
            inspected: self.inspected,
            flags: self.flags,
            reserved: 0,
        }
    }
}

/// Entry-time Derive result-protocol evidence: the accepted finite mechanism
/// or unavailable. Only the enum is retained, never the raw mechanism word.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DeriveEntry {
    Accepted(ScalarDeriveMechanism),
    Unavailable,
}

impl DeriveEntry {
    /// Finite entry-derive wire code (0..=4).
    pub const fn code(self) -> u8 {
        match self {
            DeriveEntry::Accepted(ScalarDeriveMechanism::DhPkcs) => OBJECT_DERIVE_DH_PKCS,
            DeriveEntry::Accepted(ScalarDeriveMechanism::Sha256) => OBJECT_DERIVE_SHA256,
            DeriveEntry::Accepted(ScalarDeriveMechanism::Ecdh1) => OBJECT_DERIVE_ECDH1,
            DeriveEntry::Accepted(ScalarDeriveMechanism::Ecdh1Cofactor) => {
                OBJECT_DERIVE_ECDH1_COFACTOR
            }
            DeriveEntry::Unavailable => OBJECT_DERIVE_UNAVAILABLE,
        }
    }
}

/// Full-width mechanism value for one accepted scalar-result mechanism.
pub const fn derive_mechanism_code(mechanism: ScalarDeriveMechanism) -> u64 {
    match mechanism {
        ScalarDeriveMechanism::DhPkcs => 0x21,
        ScalarDeriveMechanism::Sha256 => 0x393,
        ScalarDeriveMechanism::Ecdh1 => 0x1050,
        ScalarDeriveMechanism::Ecdh1Cofactor => 0x1051,
    }
}

/// Ownership/phase/continuity authority for return processing, as data.
/// Adapters derive this from the live START owner, side binding, phase and
/// the existing instance-continuity join predicate; teardown passes a
/// denied authority and this core then performs no reads.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ReturnAuthority {
    pub owner_live: bool,
    pub phase_ready: bool,
    pub continuity_joined: bool,
}

impl ReturnAuthority {
    pub const AUTHORIZED: Self = Self {
        owner_live: true,
        phase_ready: true,
        continuity_joined: true,
    };
    pub const fn is_authorized(self) -> bool {
        self.owner_live && self.phase_ready && self.continuity_joined
    }
    /// Authority for one return: live owner, ready phase, and joinable
    /// entry/return continuity stamps. A found entry alone authorizes
    /// nothing; only the full join predicate does.
    pub const fn for_return(
        owner_live: bool,
        phase_ready: bool,
        entry: InstanceStamp,
        ret: InstanceStamp,
    ) -> Self {
        Self {
            owner_live,
            phase_ready,
            continuity_joined: instance::stamp_joinable(entry, ret),
        }
    }
}

/// Entry input-handle verdict: finite codes only. Raw handle words travel in
/// the companion `[u64; 2]` (nonzero only for value statuses).
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct EntryInputVerdict {
    pub supported: bool,
    pub statuses: [u8; 2],
    pub object_flags: u32,
}

/// Return result-handle verdict: finite codes plus flag contributions.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct ReturnHandlesVerdict {
    pub statuses: [u8; 2],
    pub object_flags: u32,
}

/// Find return verdict: per-element codes, bounded length, validity and the
/// Find flag bits. `result_cell` is the constant unavailable cell adapters
/// emit in the single-handle result position (Find carries no single handle;
/// facts live in the Find section, never a pointer word).
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct FindVerdict {
    pub statuses: [u8; 8],
    pub len: u8,
    pub valid: bool,
    pub flags: u8,
    pub result_cell: (u8, u64),
}

/// One retained GetAttributeValue entry-header slot. Holds raw target words:
/// deliberately no `Debug`. Only selected (known-selector) slots persist.
#[derive(Clone, Copy, Default, PartialEq, Eq)]
pub struct GetSlot {
    pub value_ptr: u64,
    pub entry_capacity: u64,
    pub kind: u8,
    pub slot_index: u8,
}

/// Retained GetAttributeValue entry state: template base, inspected-header
/// end and selected header facts. Holds raw target words: no `Debug`.
/// Creation-template pointers are never retained (see `ObjectStart` docs).
#[derive(Clone, Copy, Default)]
pub struct GetEntryState {
    pub template_base: u64,
    pub header_end: u64,
    pub slots: [GetSlot; 8],
    pub slot_count: u8,
    pub inspected: u8,
    pub entry_flags: u8,
}

/// Get entry verdict: finite copy of the retained counts/flags for asserts.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct GetEntryVerdict {
    pub inspected: u8,
    pub slot_count: u8,
    pub entry_flags: u8,
}

/// Checked `count * 3W` table bytes for `count` `CK_ATTRIBUTE` slots.
#[inline(always)]
pub fn attribute_table_span(count: u64, layout: LinuxLayout) -> Option<u64> {
    // Checked generic multiplication lowers to a wide-overflow intrinsic
    // (__multi3) unsupported by the BPF backend. Keep the full claimed count:
    // prove the exact constant-stride bound, then form 3W using shifts/add.
    match layout {
        LinuxLayout::Lp64 if count <= u64::MAX / 24 => Some((count << 4) + (count << 3)),
        LinuxLayout::Ilp32 if count <= u64::MAX / 12 => Some((count << 3) + (count << 2)),
        _ => None,
    }
}

/// Validate the complete `[base, base+len)` target span, inclusive last byte.
/// Empty spans are valid without touching memory; null bases with nonzero
/// length, LP64 wrap and ia32 range violations refuse. Returns the exclusive
/// end on success, clamped to `u64::MAX` for the single span shape that
/// reaches the top of the address space (its last byte is `u64::MAX`). The
/// end is for bound comparisons only; callers already hold the length.
pub fn validate_target_span(base: u64, len: u64, layout: LinuxLayout) -> Option<u64> {
    if len == 0 {
        return Some(base);
    }
    if base == 0 {
        return None;
    }
    match layout {
        LinuxLayout::Lp64 => {
            base.checked_add(len - 1)?;
            Some(base.saturating_add(len))
        }
        LinuxLayout::Ilp32 => {
            let end = base.checked_add(len)?;
            if base > u64::from(u32::MAX) || end > 0x1_0000_0000 {
                return None;
            }
            Some(end)
        }
    }
}

/// Inclusive-end overlap of two spans. Empty spans never overlap.
pub fn spans_overlap(a_base: u64, a_len: u64, b_base: u64, b_len: u64) -> bool {
    if a_len == 0 || b_len == 0 {
        return false;
    }
    // Saturated ends only over-approximate, which fails safe (alias).
    let a_end = a_base.saturating_add(a_len);
    let b_end = b_base.saturating_add(b_len);
    a_base < b_end && b_base < a_end
}

/// Checked addresses of one header's `{type, pValue, ulValueLen}` words.
pub fn attribute_header_addresses(
    base: u64,
    index: u64,
    layout: LinuxLayout,
) -> Option<(u64, u64, u64)> {
    let w = layout.word_bytes() as u64;
    let slot = base.checked_add(attribute_table_span(index, layout)?)?;
    validate_target_span(slot, 3 * w, layout)?;
    let ptr_addr = slot.checked_add(w)?;
    let len_addr = slot.checked_add(2 * w)?;
    Some((slot, ptr_addr, len_addr))
}

/// Width-correct all-ones unavailable length (`CK_UNAVAILABLE_INFORMATION`).
pub const fn unavailable_len(layout: LinuxLayout) -> u64 {
    match layout {
        LinuxLayout::Lp64 => u64::MAX,
        LinuxLayout::Ilp32 => u32::MAX as u64,
    }
}

/// Only these RVs accept per-attribute GetAttributeValue result processing.
pub const fn return_accepts_get_results(rv: u64) -> bool {
    matches!(
        rv,
        CKR_OK | CKR_ATTRIBUTE_SENSITIVE | CKR_ATTRIBUTE_TYPE_INVALID | CKR_BUFFER_TOO_SMALL
    )
}

#[inline(always)]
fn safe_kind_code(kind: SafeAttributeKind) -> u8 {
    match kind {
        SafeAttributeKind::Class => attr_kind::CLASS,
        SafeAttributeKind::KeyType => attr_kind::KEY_TYPE,
        SafeAttributeKind::Token => attr_kind::TOKEN,
        SafeAttributeKind::ValueLen => attr_kind::VALUE_LEN,
        SafeAttributeKind::ModulusBits => attr_kind::MODULUS_BITS,
        SafeAttributeKind::EcParams => attr_kind::EC_PARAMS,
    }
}

#[inline(always)]
fn kind_from_code(code: u8) -> Option<SafeAttributeKind> {
    match code {
        attr_kind::CLASS => Some(SafeAttributeKind::Class),
        attr_kind::KEY_TYPE => Some(SafeAttributeKind::KeyType),
        attr_kind::TOKEN => Some(SafeAttributeKind::Token),
        attr_kind::VALUE_LEN => Some(SafeAttributeKind::ValueLen),
        attr_kind::MODULUS_BITS => Some(SafeAttributeKind::ModulusBits),
        attr_kind::EC_PARAMS => Some(SafeAttributeKind::EcParams),
        _ => None,
    }
}

fn safe_curve_code(curve: SafeCurve) -> u16 {
    match curve {
        SafeCurve::Secp256r1 => 1,
        SafeCurve::Secp384r1 => 2,
        SafeCurve::Secp521r1 => 3,
    }
}

/// Smallest exact length that can carry a value: entry capacities below this
/// are insufficient regardless of the returned length.
#[inline(always)]
fn min_exact_len(kind: SafeAttributeKind, layout: LinuxLayout) -> u64 {
    match kind {
        SafeAttributeKind::Token => 1,
        SafeAttributeKind::EcParams => 7,
        _ => layout.word_bytes() as u64,
    }
}

/// Read and classify one established value span. `len` is the exact accepted
/// length (token 1, EC 7/10, scalar `W`). Returns the classified code or the
/// failure status; unreadable means the read failed, unsupported means the
/// bytes were read but classify to nothing.
#[inline(always)]
fn read_classified_value(
    kind: SafeAttributeKind,
    ptr: u64,
    len: u64,
    layout: LinuxLayout,
    read_word: &mut impl FnMut(u64) -> Result<u64, ()>,
    read_bytes: &mut impl FnMut(u64, &mut [u8]) -> Result<(), ()>,
) -> Result<u16, u8> {
    match kind {
        SafeAttributeKind::Token => {
            let mut byte = [0u8; 1];
            read_bytes(ptr, &mut byte).map_err(|()| attr_status::UNREADABLE)?;
            classify_attribute_scalar(kind, u64::from(byte[0])).ok_or(attr_status::UNSUPPORTED)
        }
        SafeAttributeKind::EcParams => {
            if len != 7 && len != 10 {
                return Err(attr_status::INVALID_LENGTH);
            }
            let mut buf = [0u8; 10];
            let buf = &mut buf[..len as usize];
            read_bytes(ptr, buf).map_err(|()| attr_status::UNREADABLE)?;
            let curve = classify_ec_params(buf).ok_or(attr_status::UNSUPPORTED)?;
            Ok(safe_curve_code(curve))
        }
        _ => {
            let word = read_word(ptr).map_err(|()| attr_status::UNREADABLE)?;
            // Width discipline: ia32 readers zero-extend; a high-bit word
            // where ia32 allows none is refused, never narrowed.
            if layout == LinuxLayout::Ilp32 && word > u64::from(u32::MAX) {
                return Err(attr_status::UNSUPPORTED);
            }
            classify_attribute_scalar(kind, word).ok_or(attr_status::UNSUPPORTED)
        }
    }
}

/// Capture scalar entry input handles as data (never pointer reads). Zero is
/// invalid except optional absent `C_SetOperationState` keys; unreadable
/// arguments (`None`) set the argument-read-failure flag. Unknown functions
/// are unsupported with no observations.
pub fn capture_entry_inputs(
    function: u32,
    input_args: [Option<u64>; 2],
    layout: LinuxLayout,
) -> (EntryInputVerdict, [u64; 2]) {
    let Some(descriptor) = object_descriptor(function) else {
        return (
            EntryInputVerdict {
                supported: false,
                statuses: [handle_status::ABSENT; 2],
                object_flags: 0,
            },
            [0, 0],
        );
    };
    let import = descriptor.action == ObjectAction::OperationImport;
    let mut statuses = [handle_status::ABSENT; 2];
    let mut words = [0u64; 2];
    let mut flags = 0u32;
    let mut i = 0;
    while i < 2 {
        if descriptor.input_args[i] == ARG_NONE {
            statuses[i] = handle_status::ABSENT;
        } else {
            match input_args[i] {
                None => {
                    statuses[i] = handle_status::UNREADABLE;
                    flags |= object_flag::ARG_READ_FAILURE;
                }
                Some(0) if import => {
                    statuses[i] = handle_status::ABSENT;
                }
                Some(0) => {
                    statuses[i] = handle_status::INVALID_ZERO;
                }
                Some(word) => {
                    if layout == LinuxLayout::Ilp32 && word > u64::from(u32::MAX) {
                        statuses[i] = handle_status::INVALID_SPAN;
                    } else {
                        statuses[i] = handle_status::VALUE;
                        words[i] = word;
                    }
                }
            }
        }
        i += 1;
    }
    (
        EntryInputVerdict {
            supported: true,
            statuses,
            object_flags: flags,
        },
        words,
    )
}

/// Apply a successful S1 `NULL_MECHANISM_CANCEL` transition (as data) to
/// entry inputs: an eligible observed cancellation suppresses value key
/// facts before that unrelated key is processed, and contributes the
/// cancellation flag. Ordinary accounting is untouched.
pub fn apply_null_mechanism_cancel(
    null_cancel_eligible: bool,
    cancel_observed: bool,
    verdict: EntryInputVerdict,
    words: [u64; 2],
) -> (EntryInputVerdict, [u64; 2]) {
    if !(null_cancel_eligible && cancel_observed) {
        return (verdict, words);
    }
    let mut out = verdict;
    let mut out_words = words;
    let mut i = 0;
    while i < 2 {
        if out.statuses[i] == handle_status::VALUE {
            out.statuses[i] = handle_status::SUPPRESSED;
            out_words[i] = 0;
        }
        i += 1;
    }
    out.object_flags |= object_flag::NULL_MECHANISM_CANCEL;
    (out, out_words)
}

/// Classify Derive membership from exactly one target word at the arg-1
/// mechanism pointer, WITHOUT touching any other argument. Adapters must
/// call this BEFORE acquiring the arg-5 result pointer, so refused
/// mechanisms never read arg 5. Neither `pParameter` nor `ulParameterLen`
/// is addressed.
pub fn classify_derive_mechanism(
    mechanism_ptr: u64,
    layout: LinuxLayout,
    mut read_word: impl FnMut(u64) -> Result<u64, ()>,
) -> DeriveEntry {
    if mechanism_ptr == 0 {
        return DeriveEntry::Unavailable;
    }
    if target_word_end(mechanism_ptr, layout).is_none() {
        return DeriveEntry::Unavailable;
    }
    let mechanism = match read_word(mechanism_ptr) {
        Ok(word) => word,
        Err(()) => return DeriveEntry::Unavailable,
    };
    match derive_result_protocol(mechanism) {
        DeriveResultProtocol::ScalarHandle(accepted) => DeriveEntry::Accepted(accepted),
        DeriveResultProtocol::Unavailable => DeriveEntry::Unavailable,
    }
}

/// Derive entry guard: classify the mechanism word and retain the
/// already-acquired arg-5 pointer only for the accepted mechanisms.
/// Null/invalid/unreadable/unlisted mechanisms retain nothing and
/// authorize no template access. Callers that have not acquired arg 5
/// yet must gate that acquisition on the returned membership (see
/// `classify_derive_mechanism`).
pub fn capture_derive_entry(
    mechanism_ptr: u64,
    out5_ptr: u64,
    layout: LinuxLayout,
    read_word: impl FnMut(u64) -> Result<u64, ()>,
) -> (DeriveEntry, Option<u64>) {
    let entry = classify_derive_mechanism(mechanism_ptr, layout, read_word);
    match entry {
        DeriveEntry::Accepted(_) => (entry, Some(out5_ptr)),
        DeriveEntry::Unavailable => (entry, None),
    }
}

/// Derive return authorization from data only: accepted entry evidence,
/// `CKR_OK`, an existing `MECHANISM_VALUE` return capture exactly equal to
/// the entry code. No reader is taken: no extra return mechanism read exists.
pub fn authorize_derive_return(
    entry: DeriveEntry,
    rv: u64,
    return_mechanism_status: u32,
    return_mechanism: u64,
) -> bool {
    let DeriveEntry::Accepted(accepted) = entry else {
        return false;
    };
    rv == CKR_OK
        && return_mechanism_status == capture::MECHANISM_VALUE
        && return_mechanism == derive_mechanism_code(accepted)
}

/// Which template pairs the entry may inspect. Creation families authorize
/// their descriptor pairs, Derive additionally requires accepted entry
/// evidence, Get authorizes pair zero for its header protocol, and every
/// other family (including Set and Find) plus unknown functions authorize
/// nothing. Scalars arrive as data; no reads happen here.
pub fn authorize_entry_templates(
    function: u32,
    template_scalars: [(u64, u64); 2],
    derive: DeriveEntry,
) -> [Option<(u64, u64)>; 2] {
    let Some(descriptor) = object_descriptor(function) else {
        return [None, None];
    };
    if descriptor.action == ObjectAction::Derive && !matches!(derive, DeriveEntry::Accepted(_)) {
        return [None, None];
    }
    let mut out = [None; 2];
    let mut i = 0;
    while i < 2 {
        let (ptr_arg, count_arg) = descriptor.template_args[i];
        if ptr_arg != ARG_NONE && count_arg != ARG_NONE {
            out[i] = Some(template_scalars[i]);
        }
        i += 1;
    }
    out
}

/// Read result handles at retained pointers: `CKR_OK` plus authority only.
/// Both known spans are validated and overlap-rejected before either read;
/// equal nonzero pair handles invalidate both; a single readable pair member
/// yields an explicitly partial result, never an invented sibling.
pub fn capture_return_handles(
    present: [bool; 2],
    authorized: [bool; 2],
    result_ptrs: [u64; 2],
    rv: u64,
    authority: ReturnAuthority,
    layout: LinuxLayout,
    mut read_word: impl FnMut(u64) -> Result<u64, ()>,
) -> (ReturnHandlesVerdict, [u64; 2]) {
    let mut statuses = [handle_status::ABSENT; 2];
    let mut words = [0u64; 2];
    let mut flags = 0u32;
    let mut gated = [false; 2];
    let mut i = 0;
    while i < 2 {
        if !present[i] {
            statuses[i] = handle_status::ABSENT;
        } else if !authorized[i] {
            statuses[i] = handle_status::PROTOCOL_UNAVAILABLE;
            flags |= object_flag::UNAVAILABLE_RESULT;
        } else {
            gated[i] = true;
        }
        i += 1;
    }
    if !(gated[0] || gated[1]) {
        return (
            ReturnHandlesVerdict {
                statuses,
                object_flags: flags,
            },
            words,
        );
    }
    if rv != CKR_OK || !authority.is_authorized() {
        let mut i = 0;
        while i < 2 {
            if gated[i] {
                statuses[i] = handle_status::PROTOCOL_UNAVAILABLE;
            }
            i += 1;
        }
        return (
            ReturnHandlesVerdict {
                statuses,
                object_flags: flags,
            },
            words,
        );
    }
    let mut readable = [false; 2];
    let mut i = 0;
    while i < 2 {
        if gated[i] {
            if result_ptrs[i] == 0 {
                statuses[i] = handle_status::UNREADABLE;
            } else if target_word_end(result_ptrs[i], layout).is_none() {
                statuses[i] = handle_status::INVALID_SPAN;
            } else {
                readable[i] = true;
            }
        }
        i += 1;
    }
    let w = layout.word_bytes() as u64;
    if readable[0] && readable[1] && spans_overlap(result_ptrs[0], w, result_ptrs[1], w) {
        statuses = [handle_status::ALIAS, handle_status::ALIAS];
        flags |= object_flag::ALIAS;
        return (
            ReturnHandlesVerdict {
                statuses,
                object_flags: flags,
            },
            words,
        );
    }
    let mut i = 0;
    while i < 2 {
        if readable[i] {
            match read_word(result_ptrs[i]) {
                Err(()) => statuses[i] = handle_status::UNREADABLE,
                Ok(0) => statuses[i] = handle_status::INVALID_ZERO,
                Ok(word) => {
                    if layout == LinuxLayout::Ilp32 && word > u64::from(u32::MAX) {
                        statuses[i] = handle_status::INVALID_SPAN;
                    } else {
                        statuses[i] = handle_status::VALUE;
                        words[i] = word;
                    }
                }
            }
        }
        i += 1;
    }
    if statuses[0] == handle_status::VALUE
        && statuses[1] == handle_status::VALUE
        && words[0] == words[1]
    {
        statuses = [handle_status::DUPLICATE, handle_status::DUPLICATE];
        words = [0, 0];
        flags |= object_flag::DUPLICATE_RESULT;
    }
    if gated[0] && gated[1] {
        let values = u32::from(statuses[0] == handle_status::VALUE)
            + u32::from(statuses[1] == handle_status::VALUE);
        if values == 1 {
            flags |= object_flag::PARTIAL_RESULT;
        }
    }
    (
        ReturnHandlesVerdict {
            statuses,
            object_flags: flags,
        },
        words,
    )
}

/// Bounded Find protocol: read count once, require `count <= capacity`,
/// validate the full claimed span plus a disjoint count-word span, read at
/// most eight words, then reread count. Changed counts discard the batch;
/// zero reads no array; nine truncates to eight with a flag.
pub fn capture_find_return(
    array_ptr: u64,
    capacity: u64,
    count_ptr: u64,
    rv: u64,
    authority: ReturnAuthority,
    layout: LinuxLayout,
    mut read_word: impl FnMut(u64) -> Result<u64, ()>,
) -> (FindVerdict, [u64; 8]) {
    let refused = |flags: u8| {
        (
            FindVerdict {
                statuses: [handle_status::ABSENT; 8],
                len: 0,
                valid: false,
                flags,
                result_cell: (handle_status::PROTOCOL_UNAVAILABLE, 0),
            },
            [0u64; 8],
        )
    };
    if rv != CKR_OK || !authority.is_authorized() {
        return refused(0);
    }
    if count_ptr == 0 || target_word_end(count_ptr, layout).is_none() {
        return refused(find_flag::INVALID_COUNT);
    }
    let count = match read_word(count_ptr) {
        Ok(count) => count,
        Err(()) => return refused(find_flag::INVALID_COUNT),
    };
    if layout == LinuxLayout::Ilp32 && count > u64::from(u32::MAX) {
        return refused(find_flag::INVALID_COUNT);
    }
    if count > capacity {
        return refused(find_flag::INVALID_COUNT);
    }
    let w = layout.word_bytes() as u64;
    let array_len = match count.checked_mul(w) {
        Some(len) => len,
        None => return refused(find_flag::INVALID_SPAN),
    };
    if validate_target_span(array_ptr, array_len, layout).is_none() {
        return refused(find_flag::INVALID_SPAN);
    }
    if spans_overlap(array_ptr, array_len, count_ptr, w) {
        return refused(find_flag::COUNT_ALIAS);
    }
    let take = core::cmp::min(count, MAX_FIND_HANDLES);
    let mut statuses = [handle_status::ABSENT; 8];
    let mut words = [0u64; 8];
    let mut flags = 0u8;
    if count > MAX_FIND_HANDLES {
        flags |= find_flag::TRUNCATED;
    }
    let mut i = 0u64;
    while i < take {
        let addr = match array_ptr.checked_add(i * w) {
            Some(addr) => addr,
            None => return refused(find_flag::INVALID_SPAN),
        };
        match read_word(addr) {
            Err(()) => {
                statuses[i as usize] = handle_status::UNREADABLE;
                flags |= find_flag::UNREADABLE_ELEMENT;
            }
            Ok(0) => statuses[i as usize] = handle_status::INVALID_ZERO,
            Ok(word) => {
                if layout == LinuxLayout::Ilp32 && word > u64::from(u32::MAX) {
                    statuses[i as usize] = handle_status::INVALID_SPAN;
                } else {
                    statuses[i as usize] = handle_status::VALUE;
                    words[i as usize] = word;
                }
            }
        }
        i += 1;
    }
    match read_word(count_ptr) {
        Ok(stable) if stable == count => (),
        _ => return refused(find_flag::CHANGED_COUNT),
    }
    (
        FindVerdict {
            statuses,
            len: take as u8,
            valid: true,
            flags,
            result_cell: (handle_status::PROTOCOL_UNAVAILABLE, 0),
        },
        words,
    )
}

/// Inspect one creation-request template at entry: selector-first headers
/// (unknown selectors authorize no pointer/length reads), full-span checks,
/// alias rejection against inspected headers and selected value spans
/// (including an optional pair peer whose headers are re-read here, never
/// retained), immediate classification and a post-read header recheck.
/// Pointers are transient scratch; nothing is retained.
pub fn inspect_request_template(
    template_ptr: u64,
    count: u64,
    peer: Option<(u64, u64)>,
    layout: LinuxLayout,
    mut read_word: impl FnMut(u64) -> Result<u64, ()>,
    mut read_bytes: impl FnMut(u64, &mut [u8]) -> Result<(), ()>,
) -> AttributeListOutcome {
    let mut outcome = AttributeListOutcome {
        cells: [AttrCell {
            kind: 0,
            status: 0,
            value: 0,
        }; 8],
        inspected: 0,
        flags: 0,
        object_flags: 0,
    };
    let table_len = match attribute_table_span(count, layout) {
        Some(len) => len,
        None => {
            outcome.flags |= attr_list_flag::INVALID_SPAN;
            return outcome;
        }
    };
    if validate_target_span(template_ptr, table_len, layout).is_none() {
        outcome.flags |= attr_list_flag::INVALID_SPAN;
        return outcome;
    }
    let n = core::cmp::min(count, MAX_ATTRIBUTE_SLOTS);
    outcome.inspected = n as u8;
    if n > 0 {
        outcome.flags |= attr_list_flag::PRESENT;
    }
    if count > MAX_ATTRIBUTE_SLOTS {
        outcome.flags |= attr_list_flag::TRUNCATED;
    }
    if n == 0 {
        return outcome;
    }
    let w = layout.word_bytes() as u64;
    let Some(header_end) = template_ptr.checked_add(n * 3 * w) else {
        return AttributeListOutcome {
            flags: attr_list_flag::INVALID_SPAN,
            ..AttributeListOutcome::default()
        };
    };
    // Phase A: selector-first own headers. Only known selectors proceed to
    // pointer/length reads; every stated known-selector span joins the
    // cross-check set below, even when its length later proves inexact.
    let mut kinds: [Option<SafeAttributeKind>; 8] = [None; 8];
    let mut selectors = [0u64; 8];
    let mut ptrs = [0u64; 8];
    let mut lens = [0u64; 8];
    let mut i = 0u64;
    while i < n {
        let slot = i as usize;
        let Some((sel_addr, ptr_addr, len_addr)) =
            attribute_header_addresses(template_ptr, i, layout)
        else {
            outcome.flags |= attr_list_flag::HEADER_READ_FAILURE;
            i += 1;
            continue;
        };
        let selector = match read_word(sel_addr) {
            Ok(selector) => selector,
            Err(()) => {
                outcome.flags |= attr_list_flag::HEADER_READ_FAILURE;
                i += 1;
                continue;
            }
        };
        let Some(kind) = safe_attribute_kind(selector) else {
            i += 1;
            continue;
        };
        let ptr = match read_word(ptr_addr) {
            Ok(ptr) => ptr,
            Err(()) => {
                outcome.cells[slot] = AttrCell {
                    kind: safe_kind_code(kind),
                    status: attr_status::UNREADABLE,
                    value: 0,
                };
                outcome.flags |= attr_list_flag::HEADER_READ_FAILURE;
                i += 1;
                continue;
            }
        };
        let len = match read_word(len_addr) {
            Ok(len) => len,
            Err(()) => {
                outcome.cells[slot] = AttrCell {
                    kind: safe_kind_code(kind),
                    status: attr_status::UNREADABLE,
                    value: 0,
                };
                outcome.flags |= attr_list_flag::HEADER_READ_FAILURE;
                i += 1;
                continue;
            }
        };
        kinds[slot] = Some(kind);
        selectors[slot] = selector;
        ptrs[slot] = ptr;
        lens[slot] = len;
        i += 1;
    }
    // Phase B: bounded peer header re-reads. The peer's inspected-header
    // span is arithmetic; peer value spans come only from re-read known
    // selectors. Peer values are never read.
    let mut peer_spans = [(0u64, 0u64); 8];
    let mut peer_spans_len = 0usize;
    let mut peer_header_len = 0u64;
    let mut peer_header_base = 0u64;
    if let Some((peer_ptr, peer_count)) = peer {
        if let Some(peer_table) = attribute_table_span(peer_count, layout) {
            if validate_target_span(peer_ptr, peer_table, layout).is_some() {
                let m = core::cmp::min(peer_count, MAX_ATTRIBUTE_SLOTS);
                peer_header_base = peer_ptr;
                peer_header_len = m * 3 * w;
                let mut j = 0u64;
                while j < m {
                    let Some((sel_addr, ptr_addr, len_addr)) =
                        attribute_header_addresses(peer_ptr, j, layout)
                    else {
                        outcome.flags |= attr_list_flag::HEADER_READ_FAILURE;
                        j += 1;
                        continue;
                    };
                    let selector = match read_word(sel_addr) {
                        Ok(selector) => selector,
                        Err(()) => {
                            outcome.flags |= attr_list_flag::HEADER_READ_FAILURE;
                            j += 1;
                            continue;
                        }
                    };
                    let Some(_) = safe_attribute_kind(selector) else {
                        j += 1;
                        continue;
                    };
                    let peer_value = match (read_word(ptr_addr), read_word(len_addr)) {
                        (Ok(ptr), Ok(len)) => (ptr, len),
                        _ => {
                            outcome.flags |= attr_list_flag::HEADER_READ_FAILURE;
                            j += 1;
                            continue;
                        }
                    };
                    if peer_value.0 != 0
                        && peer_value.1 != 0
                        && validate_target_span(peer_value.0, peer_value.1, layout).is_some()
                    {
                        peer_spans[peer_spans_len] = peer_value;
                        peer_spans_len += 1;
                    }
                    j += 1;
                }
            }
        }
    }
    // Phase C: length, span and alias validation without value reads.
    let mut viable = [false; 8];
    let mut i = 0u64;
    while i < n {
        let slot = i as usize;
        let Some(kind) = kinds[slot] else {
            i += 1;
            continue;
        };
        if ptrs[slot] == 0 {
            outcome.cells[slot] = AttrCell {
                kind: safe_kind_code(kind),
                status: attr_status::UNAVAILABLE,
                value: 0,
            };
        } else if !valid_safe_attribute_length(kind, lens[slot], layout) {
            outcome.cells[slot] = AttrCell {
                kind: safe_kind_code(kind),
                status: attr_status::INVALID_LENGTH,
                value: 0,
            };
        } else if validate_target_span(ptrs[slot], lens[slot], layout).is_none() {
            outcome.cells[slot] = AttrCell {
                kind: safe_kind_code(kind),
                status: attr_status::INVALID_SPAN,
                value: 0,
            };
        } else {
            viable[slot] = true;
        }
        i += 1;
    }
    // Alias pass over stated spans: own headers, own selected values (any
    // stated length, even inexact callers never read) and peer spans.
    let mut aliased = [false; 8];
    let mut i = 0u64;
    while i < n {
        let slot = i as usize;
        if !viable[slot] {
            i += 1;
            continue;
        }
        if spans_overlap(
            ptrs[slot],
            lens[slot],
            template_ptr,
            header_end - template_ptr,
        ) || spans_overlap(ptrs[slot], lens[slot], peer_header_base, peer_header_len)
        {
            aliased[slot] = true;
        }
        let mut k = 0usize;
        while k < peer_spans_len {
            if spans_overlap(ptrs[slot], lens[slot], peer_spans[k].0, peer_spans[k].1) {
                aliased[slot] = true;
            }
            k += 1;
        }
        let mut j = 0u64;
        while j < n {
            let other = j as usize;
            if other != slot
                && kinds[other].is_some()
                && ptrs[other] != 0
                && lens[other] != 0
                && validate_target_span(ptrs[other], lens[other], layout).is_some()
                && spans_overlap(ptrs[slot], lens[slot], ptrs[other], lens[other])
            {
                aliased[slot] = true;
            }
            j += 1;
        }
        i += 1;
    }
    let mut i = 0u64;
    while i < n {
        let slot = i as usize;
        if aliased[slot] {
            viable[slot] = false;
            // Unreachable without `Some`: only selected slots alias. A zero
            // cell is the fail-safe fallback.
            if let Some(kind) = kinds[slot] {
                outcome.cells[slot] = AttrCell {
                    kind: safe_kind_code(kind),
                    status: attr_status::ALIAS,
                    value: 0,
                };
                outcome.object_flags |= object_flag::ALIAS;
            }
        }
        i += 1;
    }
    // Phase D: per-slot value plus header recheck. Reads are unsupported
    // only after a stable recheck; races discard the value just read.
    let mut i = 0u64;
    while i < n {
        let slot = i as usize;
        if !viable[slot] {
            i += 1;
            continue;
        }
        let Some(kind) = kinds[slot] else {
            // Unreachable: only selected slots become viable.
            viable[slot] = false;
            i += 1;
            continue;
        };
        let Some((sel_addr, ptr_addr, len_addr)) =
            attribute_header_addresses(template_ptr, i, layout)
        else {
            // Unreachable: validated before any read. Fail safe, no reads.
            outcome.cells[slot] = AttrCell {
                kind: safe_kind_code(kind),
                status: attr_status::INVALID_SPAN,
                value: 0,
            };
            i += 1;
            continue;
        };
        let read = read_classified_value(
            kind,
            ptrs[slot],
            lens[slot],
            layout,
            &mut read_word,
            &mut read_bytes,
        );
        let classified = match read {
            Ok(value) => Some(value),
            Err(attr_status::UNREADABLE) => {
                outcome.cells[slot] = AttrCell {
                    kind: safe_kind_code(kind),
                    status: attr_status::UNREADABLE,
                    value: 0,
                };
                i += 1;
                continue;
            }
            Err(status) => {
                // Classified-but-unusable bytes still require a stable
                // header; anything else keeps its status without a recheck.
                if status != attr_status::UNSUPPORTED {
                    outcome.cells[slot] = AttrCell {
                        kind: safe_kind_code(kind),
                        status,
                        value: 0,
                    };
                    i += 1;
                    continue;
                }
                None
            }
        };
        match (
            read_word(sel_addr),
            read_word(ptr_addr),
            read_word(len_addr),
        ) {
            (Ok(sel), Ok(ptr), Ok(len))
                if sel == selectors[slot] && ptr == ptrs[slot] && len == lens[slot] =>
            {
                match classified {
                    Some(value) => {
                        outcome.cells[slot] = AttrCell {
                            kind: safe_kind_code(kind),
                            status: attr_status::VALUE,
                            value,
                        };
                    }
                    None => {
                        outcome.cells[slot] = AttrCell {
                            kind: safe_kind_code(kind),
                            status: attr_status::UNSUPPORTED,
                            value: 0,
                        };
                    }
                }
            }
            (Ok(_), Ok(_), Ok(_)) => {
                outcome.cells[slot] = AttrCell {
                    kind: safe_kind_code(kind),
                    status: attr_status::CHANGED,
                    value: 0,
                };
                outcome.object_flags |= object_flag::CHANGED_METADATA;
            }
            _ => {
                outcome.cells[slot] = AttrCell {
                    kind: safe_kind_code(kind),
                    status: attr_status::UNREADABLE,
                    value: 0,
                };
            }
        }
        i += 1;
    }
    outcome
}

/// GetAttributeValue entry: retain only selected header facts (selector
/// kind, slot index, pointer, capacity) plus the template base and
/// inspected-header end. Unknown selectors authorize no pointer/length
/// reads; null entry pointers persist as permanently size-only.
pub fn capture_get_entry(
    template_ptr: u64,
    count: u64,
    layout: LinuxLayout,
    state: &mut GetEntryState,
    mut read_word: impl FnMut(u64) -> Result<u64, ()>,
) -> GetEntryVerdict {
    *state = GetEntryState::default();
    let mut verdict = GetEntryVerdict {
        inspected: 0,
        slot_count: 0,
        entry_flags: 0,
    };
    let table_len = match attribute_table_span(count, layout) {
        Some(len) => len,
        None => {
            verdict.entry_flags |= attr_list_flag::INVALID_SPAN;
            state.entry_flags = verdict.entry_flags;
            return verdict;
        }
    };
    if validate_target_span(template_ptr, table_len, layout).is_none() {
        verdict.entry_flags |= attr_list_flag::INVALID_SPAN;
        state.entry_flags = verdict.entry_flags;
        return verdict;
    }
    let n = core::cmp::min(count, MAX_ATTRIBUTE_SLOTS);
    verdict.inspected = n as u8;
    if count > MAX_ATTRIBUTE_SLOTS {
        verdict.entry_flags |= attr_list_flag::TRUNCATED;
    }
    let w = layout.word_bytes() as u64;
    let Some(header_end) = template_ptr.checked_add(n * 3 * w) else {
        verdict.inspected = 0;
        verdict.entry_flags |= attr_list_flag::INVALID_SPAN;
        state.entry_flags = verdict.entry_flags;
        return verdict;
    };
    state.template_base = template_ptr;
    state.header_end = header_end;
    state.inspected = n as u8;
    let mut retained = 0u8;
    let mut i = 0u64;
    while i < n {
        let Some((sel_addr, ptr_addr, len_addr)) =
            attribute_header_addresses(template_ptr, i, layout)
        else {
            verdict.entry_flags |= attr_list_flag::HEADER_READ_FAILURE;
            i += 1;
            continue;
        };
        let selector = match read_word(sel_addr) {
            Ok(selector) => selector,
            Err(()) => {
                verdict.entry_flags |= attr_list_flag::HEADER_READ_FAILURE;
                i += 1;
                continue;
            }
        };
        let Some(kind) = safe_attribute_kind(selector) else {
            i += 1;
            continue;
        };
        let ptr = match read_word(ptr_addr) {
            Ok(ptr) => ptr,
            Err(()) => {
                verdict.entry_flags |= attr_list_flag::HEADER_READ_FAILURE;
                i += 1;
                continue;
            }
        };
        let len = match read_word(len_addr) {
            Ok(len) => len,
            Err(()) => {
                verdict.entry_flags |= attr_list_flag::HEADER_READ_FAILURE;
                i += 1;
                continue;
            }
        };
        state.slots[retained as usize] = GetSlot {
            value_ptr: ptr,
            entry_capacity: len,
            kind: safe_kind_code(kind),
            slot_index: i as u8,
        };
        retained += 1;
        i += 1;
    }
    verdict.slot_count = retained;
    state.slot_count = retained;
    state.entry_flags = verdict.entry_flags;
    verdict
}

/// GetAttributeValue return: accepted RVs plus authority only. The result
/// list mirrors template slots (unretained slots stay zero cells) so merged
/// entry flags keep their wire meaning. Per retained slot, require the
/// unchanged header, width-correct sentinel handling, an exact returned
/// length within entry capacity and valid disjoint spans established before
/// any value read; classify, then recheck the header. Duplicates are
/// preserved as separate cells; partial errors keep usable neighbors.
/// Unknown selector pointers are never read.
pub fn capture_get_return(
    entry: &GetEntryState,
    rv: u64,
    authority: ReturnAuthority,
    layout: LinuxLayout,
    mut read_word: impl FnMut(u64) -> Result<u64, ()>,
    mut read_bytes: impl FnMut(u64, &mut [u8]) -> Result<(), ()>,
) -> AttributeListOutcome {
    let mut outcome = AttributeListOutcome {
        cells: [AttrCell {
            kind: 0,
            status: 0,
            value: 0,
        }; 8],
        inspected: 0,
        flags: 0,
        object_flags: 0,
    };
    if !return_accepts_get_results(rv) || !authority.is_authorized() {
        return outcome;
    }
    let n = entry.inspected.min(8);
    let slot_count = entry.slot_count.min(8);
    outcome.inspected = n;
    outcome.flags = entry.entry_flags & 0x0F;
    if n > 0 {
        outcome.flags |= attr_list_flag::PRESENT;
    }
    // Retained slot per template slot, by slot index. Unretained slots
    // keep zero cells and are never addressed.
    let mut retained_for: [Option<u8>; 8] = [None; 8];
    let mut k = 0u8;
    while k < slot_count {
        let index = entry.slots[k as usize].slot_index;
        if index < n && retained_for[index as usize].is_none() {
            retained_for[index as usize] = Some(k);
        }
        k += 1;
    }
    // Phase 1: reread every retained header; establish lengths and spans.
    let mut kinds: [Option<SafeAttributeKind>; 8] = [None; 8];
    let mut returned = [0u64; 8];
    let mut viable = [false; 8];
    let mut i = 0u8;
    while i < n {
        let Some(k) = retained_for[i as usize] else {
            i += 1;
            continue;
        };
        let slot = &entry.slots[k as usize];
        let Some(kind) = kind_from_code(slot.kind) else {
            i += 1;
            continue;
        };
        let Some((sel_addr, ptr_addr, len_addr)) =
            attribute_header_addresses(entry.template_base, u64::from(i), layout)
        else {
            outcome.cells[i as usize] = AttrCell {
                kind: slot.kind,
                status: attr_status::INVALID_SPAN,
                value: 0,
            };
            i += 1;
            continue;
        };
        let header = (
            read_word(sel_addr),
            read_word(ptr_addr),
            read_word(len_addr),
        );
        let (Ok(sel), Ok(ptr), Ok(len)) = header else {
            outcome.cells[i as usize] = AttrCell {
                kind: slot.kind,
                status: attr_status::UNREADABLE,
                value: 0,
            };
            i += 1;
            continue;
        };
        // Full-width selector equality through the injective kind mapping.
        if safe_attribute_kind(sel) != Some(kind) {
            outcome.cells[i as usize] = AttrCell {
                kind: slot.kind,
                status: attr_status::CHANGED,
                value: 0,
            };
            outcome.object_flags |= object_flag::CHANGED_METADATA;
            i += 1;
            continue;
        }
        if slot.value_ptr == 0 {
            // Null entry pointers stay size-only even when the return
            // header changes the pointer.
            outcome.cells[i as usize] = AttrCell {
                kind: slot.kind,
                status: attr_status::SIZE_ONLY,
                value: 0,
            };
            i += 1;
            continue;
        }
        if ptr != slot.value_ptr {
            outcome.cells[i as usize] = AttrCell {
                kind: slot.kind,
                status: attr_status::CHANGED,
                value: 0,
            };
            outcome.object_flags |= object_flag::CHANGED_METADATA;
            i += 1;
            continue;
        }
        if len == unavailable_len(layout) {
            outcome.cells[i as usize] = AttrCell {
                kind: slot.kind,
                status: attr_status::UNAVAILABLE,
                value: 0,
            };
            i += 1;
            continue;
        }
        if slot.entry_capacity < min_exact_len(kind, layout) {
            outcome.cells[i as usize] = AttrCell {
                kind: slot.kind,
                status: attr_status::INSUFFICIENT_CAPACITY,
                value: 0,
            };
            i += 1;
            continue;
        }
        if len > slot.entry_capacity || !valid_safe_attribute_length(kind, len, layout) {
            outcome.cells[i as usize] = AttrCell {
                kind: slot.kind,
                status: attr_status::INVALID_LENGTH,
                value: 0,
            };
            i += 1;
            continue;
        }
        if validate_target_span(slot.value_ptr, len, layout).is_none() {
            outcome.cells[i as usize] = AttrCell {
                kind: slot.kind,
                status: attr_status::INVALID_SPAN,
                value: 0,
            };
            i += 1;
            continue;
        }
        kinds[i as usize] = Some(kind);
        returned[i as usize] = len;
        viable[i as usize] = true;
        i += 1;
    }
    // Alias pass: each value span against the inspected headers and every
    // other retained entry span (claimed buffers, which contain the values).
    let header_len = entry.header_end.saturating_sub(entry.template_base);
    let mut aliased = [false; 8];
    let mut i = 0u8;
    while i < n {
        if !viable[i as usize] {
            i += 1;
            continue;
        }
        let Some(k) = retained_for[i as usize] else {
            i += 1;
            continue;
        };
        let ptr = entry.slots[k as usize].value_ptr;
        let len = returned[i as usize];
        if spans_overlap(ptr, len, entry.template_base, header_len) {
            aliased[i as usize] = true;
        }
        let mut j = 0u8;
        while j < slot_count {
            let other = &entry.slots[j as usize];
            if j != k
                && other.value_ptr != 0
                && other.entry_capacity != 0
                && validate_target_span(other.value_ptr, other.entry_capacity, layout).is_some()
                && spans_overlap(ptr, len, other.value_ptr, other.entry_capacity)
            {
                aliased[i as usize] = true;
            }
            j += 1;
        }
        i += 1;
    }
    let mut i = 0u8;
    while i < n {
        if aliased[i as usize] {
            viable[i as usize] = false;
            // Unreachable without `Some`: only viable slots alias. A zero
            // cell is the fail-safe fallback.
            if let Some(kind) = kinds[i as usize] {
                outcome.cells[i as usize] = AttrCell {
                    kind: safe_kind_code(kind),
                    status: attr_status::ALIAS,
                    value: 0,
                };
                outcome.object_flags |= object_flag::ALIAS;
            }
        }
        i += 1;
    }
    // Phase 2: per-slot value plus header recheck against the phase-1
    // header (selector kind, unchanged pointer, returned length).
    let mut i = 0u8;
    while i < n {
        if !viable[i as usize] {
            i += 1;
            continue;
        }
        let Some(kind) = kinds[i as usize] else {
            // Unreachable: only established slots become viable.
            viable[i as usize] = false;
            i += 1;
            continue;
        };
        let Some(k) = retained_for[i as usize] else {
            viable[i as usize] = false;
            i += 1;
            continue;
        };
        let ptr = entry.slots[k as usize].value_ptr;
        let len = returned[i as usize];
        let Some((sel_addr, ptr_addr, len_addr)) =
            attribute_header_addresses(entry.template_base, u64::from(i), layout)
        else {
            // Unreachable: validated in phase 1. Fail safe, no reads.
            outcome.cells[i as usize] = AttrCell {
                kind: safe_kind_code(kind),
                status: attr_status::INVALID_SPAN,
                value: 0,
            };
            i += 1;
            continue;
        };
        let read = read_classified_value(kind, ptr, len, layout, &mut read_word, &mut read_bytes);
        let classified = match read {
            Ok(value) => Some(value),
            Err(attr_status::UNREADABLE) => {
                outcome.cells[i as usize] = AttrCell {
                    kind: safe_kind_code(kind),
                    status: attr_status::UNREADABLE,
                    value: 0,
                };
                i += 1;
                continue;
            }
            Err(status) => {
                if status != attr_status::UNSUPPORTED {
                    outcome.cells[i as usize] = AttrCell {
                        kind: safe_kind_code(kind),
                        status,
                        value: 0,
                    };
                    i += 1;
                    continue;
                }
                None
            }
        };
        match (
            read_word(sel_addr),
            read_word(ptr_addr),
            read_word(len_addr),
        ) {
            (Ok(sel), Ok(ptr2), Ok(len2))
                if safe_attribute_kind(sel) == Some(kind) && ptr2 == ptr && len2 == len =>
            {
                match classified {
                    Some(value) => {
                        outcome.cells[i as usize] = AttrCell {
                            kind: safe_kind_code(kind),
                            status: attr_status::VALUE,
                            value,
                        };
                    }
                    None => {
                        outcome.cells[i as usize] = AttrCell {
                            kind: safe_kind_code(kind),
                            status: attr_status::UNSUPPORTED,
                            value: 0,
                        };
                    }
                }
            }
            (Ok(_), Ok(_), Ok(_)) => {
                outcome.cells[i as usize] = AttrCell {
                    kind: safe_kind_code(kind),
                    status: attr_status::CHANGED,
                    value: 0,
                };
                outcome.object_flags |= object_flag::CHANGED_METADATA;
            }
            _ => {
                outcome.cells[i as usize] = AttrCell {
                    kind: safe_kind_code(kind),
                    status: attr_status::UNREADABLE,
                    value: 0,
                };
            }
        }
        i += 1;
    }
    outcome
}

/// Scan bounded selected header spans without reading values. A reread keeps
/// request inspection scalar: rejected-length neighbors still protect their
/// entire stated span. Unknown selectors never authorize pointer/length reads.
#[inline(always)]
#[allow(clippy::too_many_arguments)]
fn request_alias_scan(
    base: u64,
    count: u64,
    skip: u64,
    ptr: u64,
    len: u64,
    layout: LinuxLayout,
    read_word: &mut impl FnMut(u64) -> Result<u64, ()>,
) -> (bool, u8) {
    let Some(table) = attribute_table_span(count, layout) else {
        return (false, 0);
    };
    if validate_target_span(base, table, layout).is_none() {
        return (false, 0);
    }
    let n = count.min(MAX_ATTRIBUTE_SLOTS);
    let mut alias = spans_overlap(ptr, len, base, n * 3 * layout.word_bytes() as u64);
    let mut flags = 0;
    let mut j = 0;
    while j < n {
        if j != skip {
            if let Some((sel_addr, ptr_addr, len_addr)) =
                attribute_header_addresses(base, j, layout)
            {
                match read_word(sel_addr) {
                    Ok(sel) if safe_attribute_kind(sel).is_some() => {
                        match (read_word(ptr_addr), read_word(len_addr)) {
                            (Ok(other_ptr), Ok(other_len)) => {
                                if other_ptr != 0
                                    && other_len != 0
                                    && validate_target_span(other_ptr, other_len, layout).is_some()
                                    && spans_overlap(ptr, len, other_ptr, other_len)
                                {
                                    alias = true;
                                }
                            }
                            _ => flags |= attr_list_flag::HEADER_READ_FAILURE,
                        }
                    }
                    Err(()) => flags |= attr_list_flag::HEADER_READ_FAILURE,
                    _ => {}
                }
            } else {
                flags |= attr_list_flag::HEADER_READ_FAILURE;
            }
        }
        j += 1;
    }
    (alias, flags)
}

/// Read exactly one already-authorized value, then recheck its header before
/// publishing the finite classification. No target word is stored in output.
#[inline(always)]
#[allow(clippy::too_many_arguments)]
fn stable_attribute_cell(
    base: u64,
    index: u64,
    kind: SafeAttributeKind,
    ptr: u64,
    len: u64,
    layout: LinuxLayout,
    out: &mut ObjectAttributeWire,
    read_word: &mut impl FnMut(u64) -> Result<u64, ()>,
    read_bytes: &mut impl FnMut(u64, &mut [u8]) -> Result<(), ()>,
) -> u32 {
    let classified = read_classified_value(kind, ptr, len, layout, read_word, read_bytes);
    let value = match classified {
        Ok(value) => value,
        Err(attr_status::UNSUPPORTED) => 0,
        Err(status) => {
            out.status = status;
            return 0;
        }
    };
    let Some((sel_addr, ptr_addr, len_addr)) = attribute_header_addresses(base, index, layout)
    else {
        out.status = attr_status::INVALID_SPAN;
        return 0;
    };
    match (
        read_word(sel_addr),
        read_word(ptr_addr),
        read_word(len_addr),
    ) {
        (Ok(sel), Ok(ptr2), Ok(len2))
            if safe_attribute_kind(sel) == Some(kind) && ptr2 == ptr && len2 == len =>
        {
            out.status = if classified.is_ok() {
                attr_status::VALUE
            } else {
                attr_status::UNSUPPORTED
            };
            out.value = value;
        }
        (Ok(_), Ok(_), Ok(_)) => {
            out.status = attr_status::CHANGED;
            return object_flag::CHANGED_METADATA;
        }
        _ => out.status = attr_status::UNREADABLE,
    }
    0
}

// Volatile field stores keep list clearing leaf-flat on BPF. A synthesized
// memset would add a call level to the tightly bounded Get-return chain.
#[inline(always)]
fn clear_attribute_list(out: &mut ObjectAttributeListWire) {
    let mut i = 0;
    while i < 8 {
        // SAFETY: every pointer projects an initialized, exclusively borrowed
        // field. Field stores respect the list's two-byte alignment.
        unsafe {
            core::ptr::addr_of_mut!(out.cells[i].kind).write_volatile(0);
            core::ptr::addr_of_mut!(out.cells[i].status).write_volatile(0);
            core::ptr::addr_of_mut!(out.cells[i].value).write_volatile(0);
        }
        i += 1;
    }
    unsafe {
        core::ptr::addr_of_mut!(out.inspected).write_volatile(0);
        core::ptr::addr_of_mut!(out.flags).write_volatile(0);
        core::ptr::addr_of_mut!(out.reserved).write_volatile(0);
    }
}

/// Scalar in-place request protocol for the BPF path. Header rescans are
/// bounded by eight slots per pair; each eligible value is read once. The
/// array-based reference above remains independent for differential tests.
#[inline(always)]
#[allow(clippy::too_many_arguments)]
pub fn inspect_request_template_into(
    template_ptr: u64,
    count: u64,
    peer: Option<(u64, u64)>,
    layout: LinuxLayout,
    out: &mut ObjectAttributeListWire,
    mut read_word: impl FnMut(u64) -> Result<u64, ()>,
    mut read_bytes: impl FnMut(u64, &mut [u8]) -> Result<(), ()>,
) -> u32 {
    clear_attribute_list(out);
    let Some(table) = attribute_table_span(count, layout) else {
        out.flags = attr_list_flag::INVALID_SPAN;
        return 0;
    };
    if validate_target_span(template_ptr, table, layout).is_none() {
        out.flags = attr_list_flag::INVALID_SPAN;
        return 0;
    }
    let n = count.min(MAX_ATTRIBUTE_SLOTS);
    if template_ptr
        .checked_add(n * 3 * layout.word_bytes() as u64)
        .is_none()
    {
        out.flags = attr_list_flag::INVALID_SPAN;
        return 0;
    }
    out.inspected = n as u8;
    if n > 0 {
        out.flags |= attr_list_flag::PRESENT;
    }
    if count > MAX_ATTRIBUTE_SLOTS {
        out.flags |= attr_list_flag::TRUNCATED;
    }
    if n == 0 {
        return 0;
    }
    // Keep peer header failures visible even if no own value is viable.
    if let Some((base, count)) = peer {
        out.flags |= request_alias_scan(base, count, u64::MAX, 0, 0, layout, &mut read_word).1;
    }
    let mut contributed = 0;
    let mut i = 0;
    while i < n {
        let Some((sel_addr, ptr_addr, len_addr)) =
            attribute_header_addresses(template_ptr, i, layout)
        else {
            out.flags |= attr_list_flag::HEADER_READ_FAILURE;
            i += 1;
            continue;
        };
        let selector = match read_word(sel_addr) {
            Ok(sel) => sel,
            Err(()) => {
                out.flags |= attr_list_flag::HEADER_READ_FAILURE;
                i += 1;
                continue;
            }
        };
        let Some(kind) = safe_attribute_kind(selector) else {
            i += 1;
            continue;
        };
        let cell = &mut out.cells[i as usize];
        cell.kind = safe_kind_code(kind);
        let ptr = match read_word(ptr_addr) {
            Ok(ptr) => ptr,
            Err(()) => {
                cell.status = attr_status::UNREADABLE;
                out.flags |= attr_list_flag::HEADER_READ_FAILURE;
                i += 1;
                continue;
            }
        };
        let len = match read_word(len_addr) {
            Ok(len) => len,
            Err(()) => {
                cell.status = attr_status::UNREADABLE;
                out.flags |= attr_list_flag::HEADER_READ_FAILURE;
                i += 1;
                continue;
            }
        };
        if ptr == 0 {
            cell.status = attr_status::UNAVAILABLE;
        } else if !valid_safe_attribute_length(kind, len, layout) {
            cell.status = attr_status::INVALID_LENGTH;
        } else if validate_target_span(ptr, len, layout).is_none() {
            cell.status = attr_status::INVALID_SPAN;
        } else {
            let (mut alias, flags) =
                request_alias_scan(template_ptr, count, i, ptr, len, layout, &mut read_word);
            out.flags |= flags;
            if let Some((base, count)) = peer {
                let (a, f) =
                    request_alias_scan(base, count, u64::MAX, ptr, len, layout, &mut read_word);
                alias |= a;
                out.flags |= f;
            }
            if alias {
                cell.status = attr_status::ALIAS;
                contributed |= object_flag::ALIAS;
            } else {
                contributed |= stable_attribute_cell(
                    template_ptr,
                    i,
                    kind,
                    ptr,
                    len,
                    layout,
                    cell,
                    &mut read_word,
                    &mut read_bytes,
                );
            }
        }
        i += 1;
    }
    contributed
}

/// Retain selected Get headers directly in the owned side row. The four
/// entry-list flags use private bits, never the public object flag vocabulary.
#[inline(always)]
pub fn capture_get_entry_into(
    template_ptr: u64,
    count: u64,
    layout: LinuxLayout,
    side: &mut crate::object_wire::ObjectStart,
    mut read_word: impl FnMut(u64) -> Result<u64, ()>,
) -> GetEntryVerdict {
    use crate::object_wire::{ObjectAttributeSlot, GET_ENTRY_FLAGS_MASK, GET_ENTRY_FLAGS_SHIFT};
    side.get_template_base = 0;
    side.inspected_header_end = 0;
    side.get_inspected = 0;
    side.flags &= !GET_ENTRY_FLAGS_MASK;
    let mut i = 0;
    while i < 8 {
        side.slots[i] = ObjectAttributeSlot::default();
        i += 1;
    }
    let mut verdict = GetEntryVerdict::default();
    let valid = attribute_table_span(count, layout)
        .and_then(|len| validate_target_span(template_ptr, len, layout));
    if valid.is_none() {
        verdict.entry_flags = attr_list_flag::INVALID_SPAN;
    } else {
        let n = count.min(MAX_ATTRIBUTE_SLOTS);
        if let Some(end) = template_ptr.checked_add(n * 3 * layout.word_bytes() as u64) {
            side.get_template_base = template_ptr;
            side.inspected_header_end = end;
            side.get_inspected = n as u8;
            verdict.inspected = n as u8;
            if count > MAX_ATTRIBUTE_SLOTS {
                verdict.entry_flags |= attr_list_flag::TRUNCATED;
            }
            let mut i = 0;
            while i < n {
                let Some((sel_addr, ptr_addr, len_addr)) =
                    attribute_header_addresses(template_ptr, i, layout)
                else {
                    verdict.entry_flags |= attr_list_flag::HEADER_READ_FAILURE;
                    i += 1;
                    continue;
                };
                let selector = match read_word(sel_addr) {
                    Ok(sel) => sel,
                    Err(()) => {
                        verdict.entry_flags |= attr_list_flag::HEADER_READ_FAILURE;
                        i += 1;
                        continue;
                    }
                };
                let Some(kind) = safe_attribute_kind(selector) else {
                    i += 1;
                    continue;
                };
                let ptr = match read_word(ptr_addr) {
                    Ok(ptr) => ptr,
                    Err(()) => {
                        verdict.entry_flags |= attr_list_flag::HEADER_READ_FAILURE;
                        i += 1;
                        continue;
                    }
                };
                let len = match read_word(len_addr) {
                    Ok(len) => len,
                    Err(()) => {
                        verdict.entry_flags |= attr_list_flag::HEADER_READ_FAILURE;
                        i += 1;
                        continue;
                    }
                };
                let slot = &mut side.slots[verdict.slot_count as usize];
                slot.value_ptr = ptr;
                slot.entry_capacity = len;
                slot.kind = safe_kind_code(kind);
                slot.slot_index = i as u8;
                verdict.slot_count += 1;
                i += 1;
            }
        } else {
            verdict.entry_flags = attr_list_flag::INVALID_SPAN;
        }
    }
    side.flags |= u16::from(verdict.entry_flags) << GET_ENTRY_FLAGS_SHIFT;
    verdict
}

/// Read-only streamed Get return. Alias checks cover every retained entry
/// capacity, including neighbors whose returned length would be rejected.
/// No mutable reference or returned-length scratch is fabricated from `side`.
#[inline(always)]
#[allow(clippy::too_many_arguments)]
pub fn capture_get_return_into(
    side: &crate::object_wire::ObjectStart,
    rv: u64,
    authority: ReturnAuthority,
    layout: LinuxLayout,
    out: &mut ObjectAttributeListWire,
    mut read_word: impl FnMut(u64) -> Result<u64, ()>,
    mut read_bytes: impl FnMut(u64, &mut [u8]) -> Result<(), ()>,
) -> u32 {
    use crate::object_wire::{GET_ENTRY_FLAGS_MASK, GET_ENTRY_FLAGS_SHIFT};
    clear_attribute_list(out);
    if !return_accepts_get_results(rv) || !authority.is_authorized() {
        return 0;
    }
    if side.flags & crate::object_wire::GET_ENTRY_UNINSPECTED != 0 {
        out.flags = attr_list_flag::UNINSPECTED;
        return 0;
    }
    let n = side.get_inspected.min(8);
    out.inspected = n;
    out.flags = ((side.flags & GET_ENTRY_FLAGS_MASK) >> GET_ENTRY_FLAGS_SHIFT) as u8;
    if n > 0 {
        out.flags |= attr_list_flag::PRESENT;
    }
    let mut contributed = 0;
    let mut k = 0;
    while k < 8 {
        let slot = &side.slots[k];
        // Dense selected prefix is produced by entry; do not inspect or read
        // beyond the first unused slot even if stale trailing bytes exist.
        let Some(kind) = kind_from_code(slot.kind) else {
            break;
        };
        let i = u64::from(slot.slot_index);
        if i >= u64::from(n) {
            k += 1;
            continue;
        }
        let cell = &mut out.cells[i as usize];
        // Preserve the reference protocol's first retained slot per index.
        if cell.kind != 0 {
            k += 1;
            continue;
        }
        cell.kind = slot.kind;
        let Some((sel_addr, ptr_addr, len_addr)) =
            attribute_header_addresses(side.get_template_base, i, layout)
        else {
            cell.status = attr_status::INVALID_SPAN;
            k += 1;
            continue;
        };
        let header = (
            read_word(sel_addr),
            read_word(ptr_addr),
            read_word(len_addr),
        );
        let (Ok(sel), Ok(ptr), Ok(len)) = header else {
            cell.status = attr_status::UNREADABLE;
            k += 1;
            continue;
        };
        if safe_attribute_kind(sel) != Some(kind) {
            cell.status = attr_status::CHANGED;
            contributed |= object_flag::CHANGED_METADATA;
        } else if slot.value_ptr == 0 {
            cell.status = attr_status::SIZE_ONLY;
        } else if ptr != slot.value_ptr {
            cell.status = attr_status::CHANGED;
            contributed |= object_flag::CHANGED_METADATA;
        } else if len == unavailable_len(layout) {
            cell.status = attr_status::UNAVAILABLE;
        } else if slot.entry_capacity < min_exact_len(kind, layout) {
            cell.status = attr_status::INSUFFICIENT_CAPACITY;
        } else if len > slot.entry_capacity || !valid_safe_attribute_length(kind, len, layout) {
            cell.status = attr_status::INVALID_LENGTH;
        } else if validate_target_span(ptr, len, layout).is_none() {
            cell.status = attr_status::INVALID_SPAN;
        } else {
            let mut alias = spans_overlap(
                ptr,
                len,
                side.get_template_base,
                side.inspected_header_end
                    .saturating_sub(side.get_template_base),
            );
            let mut j = 0;
            while j < 8 {
                let other = &side.slots[j];
                if kind_from_code(other.kind).is_none() {
                    break;
                }
                if j != k
                    && other.value_ptr != 0
                    && other.entry_capacity != 0
                    && validate_target_span(other.value_ptr, other.entry_capacity, layout).is_some()
                    && spans_overlap(ptr, len, other.value_ptr, other.entry_capacity)
                {
                    alias = true;
                }
                j += 1;
            }
            if alias {
                cell.status = attr_status::ALIAS;
                contributed |= object_flag::ALIAS;
            } else {
                contributed |= stable_attribute_cell(
                    side.get_template_base,
                    i,
                    kind,
                    ptr,
                    len,
                    layout,
                    cell,
                    &mut read_word,
                    &mut read_bytes,
                );
            }
        }
        k += 1;
    }
    contributed
}

#[cfg(test)]
mod tests;
