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
//!   zero. Readers are invoked at most once per address per protocol step;
//!   nothing is read speculatively.
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
    DeriveResultProtocol, ObjectAction, ScalarDeriveMechanism, classify_attribute_scalar,
    classify_ec_params, derive_result_protocol, object_descriptor, safe_attribute_kind,
    valid_safe_attribute_length,
};
use crate::object_wire::{
    OBJECT_DERIVE_ECDH1, OBJECT_DERIVE_ECDH1_COFACTOR, OBJECT_DERIVE_DH_PKCS,
    OBJECT_DERIVE_SHA256, OBJECT_DERIVE_UNAVAILABLE, ObjectAttributeListWire, ObjectAttributeWire,
};
use crate::{ARG_NONE, LinuxLayout, target_word_end};

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

/// Attribute-list flag bits (brief bits 0..=3).
pub mod attr_list_flag {
    pub const PRESENT: u8 = 1 << 0;
    pub const TRUNCATED: u8 = 1 << 1;
    pub const HEADER_READ_FAILURE: u8 = 1 << 2;
    pub const INVALID_SPAN: u8 = 1 << 3;
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
        let _ = ();
        todo!()
    }
}

/// One eight-cell attribute list: creation-request observations or
/// GetAttributeValue results. Requested and result lists never mix: creation
/// inspection yields request lists, Get return yields the result list.
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
        let _ = ();
        todo!()
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
        todo!()
    }
}

/// Full-width mechanism value for one accepted scalar-result mechanism.
pub const fn derive_mechanism_code(mechanism: ScalarDeriveMechanism) -> u64 {
    todo!()
}

/// Ownership/phase authority for return processing, as data. Adapters derive
/// this from the live START owner, side binding and phase; teardown passes a
/// denied authority and this core then performs no reads.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ReturnAuthority {
    pub owner_live: bool,
    pub phase_ready: bool,
}

impl ReturnAuthority {
    pub const AUTHORIZED: Self = Self {
        owner_live: true,
        phase_ready: true,
    };
    pub const fn is_authorized(self) -> bool {
        todo!()
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
pub fn attribute_table_span(count: u64, layout: LinuxLayout) -> Option<u64> {
    let _ = (count, layout);
    todo!()
}

/// Validate the complete `[base, base+len)` target span, inclusive last byte.
/// Empty spans are valid without touching memory; null bases with nonzero
/// length, LP64 wrap and ia32 range violations refuse. Returns the exclusive
/// end on success.
pub fn validate_target_span(base: u64, len: u64, layout: LinuxLayout) -> Option<u64> {
    let _ = (base, len, layout);
    todo!()
}

/// Inclusive-end overlap of two spans. Empty spans never overlap.
pub fn spans_overlap(a_base: u64, a_len: u64, b_base: u64, b_len: u64) -> bool {
    let _ = (a_base, a_len, b_base, b_len);
    todo!()
}

/// Checked addresses of one header's `{type, pValue, ulValueLen}` words.
pub fn attribute_header_addresses(
    base: u64,
    index: u64,
    layout: LinuxLayout,
) -> Option<(u64, u64, u64)> {
    let _ = (base, index, layout);
    todo!()
}

/// Width-correct all-ones unavailable length (`CK_UNAVAILABLE_INFORMATION`).
pub const fn unavailable_len(layout: LinuxLayout) -> u64 {
    todo!()
}

/// Only these RVs accept per-attribute GetAttributeValue result processing.
pub const fn return_accepts_get_results(rv: u64) -> bool {
    todo!()
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
    let _ = (function, input_args, layout);
    todo!()
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
    let _ = (null_cancel_eligible, cancel_observed, verdict, words);
    todo!()
}

/// Derive entry guard: read exactly one target word at the arg-1 mechanism
/// pointer and require full-width membership in the four scalar-result
/// mechanisms before retaining arg 5. Null/invalid/unreadable/unlisted
/// mechanisms retain nothing and authorize no template access.
pub fn capture_derive_entry(
    mechanism_ptr: u64,
    out5_ptr: u64,
    layout: LinuxLayout,
    read_word: impl FnMut(u64) -> Result<u64, ()>,
) -> (DeriveEntry, Option<u64>) {
    let _ = (mechanism_ptr, out5_ptr, layout, read_word);
    todo!()
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
    let _ = (entry, rv, return_mechanism_status, return_mechanism);
    todo!()
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
    let _ = (function, template_scalars, derive);
    todo!()
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
    read_word: impl FnMut(u64) -> Result<u64, ()>,
) -> (ReturnHandlesVerdict, [u64; 2]) {
    let _ = (
        present,
        authorized,
        result_ptrs,
        rv,
        authority,
        layout,
        read_word,
    );
    todo!()
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
    read_word: impl FnMut(u64) -> Result<u64, ()>,
) -> (FindVerdict, [u64; 8]) {
    let _ = (
        array_ptr,
        capacity,
        count_ptr,
        rv,
        authority,
        layout,
        read_word,
    );
    todo!()
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
    read_word: impl FnMut(u64) -> Result<u64, ()>,
    read_bytes: impl FnMut(u64, &mut [u8]) -> Result<(), ()>,
) -> AttributeListOutcome {
    let _ = (template_ptr, count, peer, layout, read_word, read_bytes);
    todo!()
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
    read_word: impl FnMut(u64) -> Result<u64, ()>,
) -> GetEntryVerdict {
    let _ = (template_ptr, count, layout, state, read_word);
    todo!()
}

/// GetAttributeValue return: accepted RVs plus authority only. Per retained
/// slot, require the unchanged header, width-correct sentinel handling, an
/// exact returned length within entry capacity and valid disjoint spans
/// established before any value read; classify, then recheck the header.
/// Duplicates are preserved as separate cells; partial errors keep usable
/// neighbors. Unknown selector pointers are never read.
pub fn capture_get_return(
    entry: &GetEntryState,
    rv: u64,
    authority: ReturnAuthority,
    layout: LinuxLayout,
    read_word: impl FnMut(u64) -> Result<u64, ()>,
    read_bytes: impl FnMut(u64, &mut [u8]) -> Result<(), ()>,
) -> AttributeListOutcome {
    let _ = (entry, rv, authority, layout, read_word, read_bytes);
    todo!()
}

#[cfg(test)]
mod tests;
