//! SPDX-License-Identifier: GPL-2.0-or-later
//! Finite object-journal wire contracts (H8). Exact kernel/userspace layouts
//! for BEGIN/END/ABANDON journal records plus their pure validators.
//!
//! These types pin the frozen inactive wire; they activate no producer and
//! authorize no read by themselves. The native producer that would mint these
//! bytes stays unwired: no BPF root emits them, and the userspace consumer
//! (the journal child) treats every record as untrusted input until the
//! validators below plus the Session-owned audit accept it.
//!
//! Layouts are exact native little-endian `repr(C)` with zero padding. Like
//! the H7 wire, validated records hold raw target words (pointers, handles,
//! lengths) that must never be logged verbatim, so their `Debug` is redacted
//! to a bare type label (enough for `expect`, never the bytes).
//!
//! Provenance: `docs/superpowers/plans/2026-10-09-object-journal-bootstrap.md`
//! prototype wire table. The BEGIN descriptor word reuses the frozen
//! `function ordinal + 1` convention shared by START markers, H7 tails and
//! the static capture descriptors.

use crate::instance;
use crate::object_policy::object_descriptor;
use crate::object_wire::{
    valid_attribute_list, validate_object_tail, ObjectDescriptorWire, OBJECT_ACTION_MAX,
    OBJECT_GUARD_SCALAR_DERIVE, OBJECT_HANDLE_STATUS_MAX, OBJECT_LAYOUT_ILP32, OBJECT_LAYOUT_LP64,
    OBJECT_TAIL_BYTES,
};
use crate::{capture, event_type, ARG_NONE, MAX_DESCRIPTORS};

/// Journal record protocol version and exact byte lengths (wire bytes
/// without the ring's 8-byte header).
pub const JOURNAL_VERSION: u16 = 1;
pub const JOURNAL_COMMON_BYTES: usize = 24;
pub const JOURNAL_BEGIN_BYTES: usize = 224;
pub const JOURNAL_END_FULL_BYTES: usize = 632;
pub const JOURNAL_END_COMPACT_BYTES: usize = 472;
pub const JOURNAL_ABANDON_BYTES: usize = 64;

/// Ring occupancy per record form, including the 8-byte ring header.
pub const JOURNAL_BEGIN_RING_BYTES: usize = JOURNAL_BEGIN_BYTES + 8;
pub const JOURNAL_END_FULL_RING_BYTES: usize = JOURNAL_END_FULL_BYTES + 8;
pub const JOURNAL_END_COMPACT_RING_BYTES: usize = JOURNAL_END_COMPACT_BYTES + 8;
pub const JOURNAL_ABANDON_RING_BYTES: usize = JOURNAL_ABANDON_BYTES + 8;

/// Journal record kinds.
pub const JOURNAL_KIND_BEGIN: u8 = 1;
pub const JOURNAL_KIND_END: u8 = 2;
pub const JOURNAL_KIND_ABANDON: u8 = 3;

/// BEGIN header bit0: the producer commits that no END will ever follow for
/// this key. Any later END for a NO_END key is a contradiction, never a
/// completion.
pub const JOURNAL_BEGIN_NO_END: u8 = 0x01;
/// END header bit1: the 240-byte object tail is absent (all zero). Requires
/// the no-object-descriptor path; a present tail uses the exact H7 validator.
pub const JOURNAL_END_TAIL_ABSENT: u8 = 0x02;

/// Finite ABANDON reasons. Wire carries the code only, never a string; the
/// reason-to-disposition matrix lives with the journal consumer, and a wire
/// reason alone never certifies a bounded terminal witness.
pub const JOURNAL_REASON_ENTRY_COLLISION: u32 = 1;
pub const JOURNAL_REASON_INSERT_FAILED: u32 = 2;
pub const JOURNAL_REASON_SCOPE_LOST: u32 = 3;
pub const JOURNAL_REASON_ABI_REFUSED: u32 = 4;
pub const JOURNAL_REASON_IDENTITY_REFUSED: u32 = 5;
pub const JOURNAL_REASON_EXEC_EXIT: u32 = 6;
pub const JOURNAL_REASON_STOP_CLEANUP: u32 = 7;
pub const JOURNAL_REASON_PARTIAL_TRANSACTION: u32 = 8;
pub const JOURNAL_REASON_SYNC_RETURN_RESULT_LOST: u32 = 9;

/// Human label for one finite reason code; unknown codes have no label.
pub fn reason_name(reason: u32) -> Option<&'static str> {
    match reason {
        JOURNAL_REASON_ENTRY_COLLISION => Some("entry-collision"),
        JOURNAL_REASON_INSERT_FAILED => Some("insert-failed"),
        JOURNAL_REASON_SCOPE_LOST => Some("scope-lost"),
        JOURNAL_REASON_ABI_REFUSED => Some("abi-refused"),
        JOURNAL_REASON_IDENTITY_REFUSED => Some("identity-refused"),
        JOURNAL_REASON_EXEC_EXIT => Some("exec-exit"),
        JOURNAL_REASON_STOP_CLEANUP => Some("stop-cleanup"),
        JOURNAL_REASON_PARTIAL_TRANSACTION => Some("partial-transaction"),
        JOURNAL_REASON_SYNC_RETURN_RESULT_LOST => Some("sync-return-result-lost"),
        _ => None,
    }
}

/// The two legacy attribute arrays plus their eight count/bool words inside
/// a 608-byte completed payload (Event bytes 120..280, 160 bytes). The
/// compact END form omits exactly this span; eligibility requires every
/// omitted byte to be zero, so decode reconstructs exactly those zeros.
const COMPACT_OMIT_START: usize = 120;
const COMPACT_OMIT_END: usize = 280;

/// Only the frozen H7 capture bits may appear in a BEGIN's copied capture
/// word: mechanism (bits 0-1), output (bits 2-3), argument-read failure (4),
/// async session (5) and async value unreadable (6).
const CAPTURE_MASK: u32 = capture::MECHANISM_MASK
    | capture::OUTPUT_MASK
    | capture::ARG_READ_FAILURE
    | capture::ASYNC_SESSION
    | capture::ASYNC_VALUE_UNREADABLE;

/// Only the frozen stamp bits may appear in a BEGIN's copied entry stamp:
/// the VALID bit plus the five finite condition bits.
const STAMP_MASK: u16 = instance::STAMP_VALID
    | instance::STAMP_NO_FILE
    | instance::STAMP_NO_TASK
    | instance::STAMP_SHARED_MM
    | instance::STAMP_OVERFLOW
    | instance::STAMP_LOCAL_FAULT;

/// One validated 224-byte BEGIN record. Constructible only through
/// [`validate_begin`], so possession proves full structural validation.
/// Holds raw target words: deliberately redacted `Debug`.
#[derive(Clone, Copy)]
pub struct ValidatedJournalBegin {
    bytes: [u8; JOURNAL_BEGIN_BYTES],
}

impl ValidatedJournalBegin {
    /// Physical-task lifetime ticket (never zero, never recycled).
    pub fn thread(&self) -> u64 {
        journal_u64(&self.bytes, 8)
    }

    /// Per-thread affecting-entry sequence (never zero).
    pub fn sequence(&self) -> u64 {
        journal_u64(&self.bytes, 16)
    }

    /// Whether the producer committed NO_END for this key.
    pub fn no_end(&self) -> bool {
        self.bytes[5] & JOURNAL_BEGIN_NO_END != 0
    }

    /// Retained entry slot.
    pub fn slot(&self) -> u32 {
        journal_u32(&self.bytes, 104)
    }

    /// Canonical descriptor word (`function ordinal + 1`).
    pub fn descriptor(&self) -> u32 {
        journal_u32(&self.bytes, 108)
    }

    /// Retained entry pid_tgid evidence.
    pub fn pid_tgid(&self) -> u64 {
        journal_u64(&self.bytes, 24)
    }

    /// Retained entry timestamp evidence (nanoseconds).
    pub fn entry_ns(&self) -> u64 {
        journal_u64(&self.bytes, 48)
    }

    /// Retained entry image evidence (task cookie, exec id).
    pub fn image_cookie(&self) -> u64 {
        journal_u64(&self.bytes, 32)
    }

    /// Retained entry image evidence (task cookie, exec id).
    pub fn image_exec(&self) -> u64 {
        journal_u64(&self.bytes, 40)
    }

    /// Retained entry probe-address evidence.
    pub fn entry_ip(&self) -> u64 {
        journal_u64(&self.bytes, 56)
    }

    /// The exact copied 16-byte entry stamp.
    pub fn entry_stamp(&self) -> [u8; 16] {
        let mut stamp = [0u8; 16];
        stamp.copy_from_slice(&self.bytes[64..80]);
        stamp
    }

    /// Retained session word and its finite handle status.
    pub fn session_word(&self) -> u64 {
        journal_u64(&self.bytes, 80)
    }

    /// Retained session word and its finite handle status.
    pub fn session_status(&self) -> u8 {
        self.bytes[125]
    }

    /// Retained input word and status for position 0 or 1.
    pub fn input_word(&self, index: usize) -> u64 {
        journal_u64(&self.bytes, 88 + 8 * (index & 1))
    }

    /// Retained input word and status for position 0 or 1.
    pub fn input_status(&self, index: usize) -> u8 {
        self.bytes[126 + (index & 1)]
    }

    /// Copied entry mechanism evidence.
    pub fn entry_mechanism(&self) -> u64 {
        journal_u64(&self.bytes, 112)
    }

    /// Copied finite capture word.
    pub fn capture(&self) -> u32 {
        journal_u32(&self.bytes, 120)
    }

    /// Validated layout code.
    pub fn layout(&self) -> u8 {
        self.bytes[124]
    }

    /// One exact 36-byte requested attribute list (pair 0 or 1).
    pub fn requested_pair(&self, index: usize) -> [u8; 36] {
        let mut list = [0u8; 36];
        let base = 128 + 36 * (index & 1);
        list.copy_from_slice(&self.bytes[base..base + 36]);
        list
    }

    /// Retained slot identity evidence.
    pub fn slot_id(&self) -> u64 {
        journal_u64(&self.bytes, 200)
    }

    /// Copied call-flags evidence.
    pub fn call_flags(&self) -> u64 {
        journal_u64(&self.bytes, 208)
    }

    /// Copied user-type evidence.
    pub fn user_type(&self) -> u32 {
        journal_u32(&self.bytes, 216)
    }

    /// The exact validated BEGIN bytes.
    pub fn bytes(&self) -> &[u8; JOURNAL_BEGIN_BYTES] {
        &self.bytes
    }
}

impl core::fmt::Debug for ValidatedJournalBegin {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str("ValidatedJournalBegin(<private>)")
    }
}

/// One validated END record (full 632-byte or compact 472-byte form).
/// Constructible only through [`validate_end`]. Holds raw target words:
/// deliberately redacted `Debug`.
#[derive(Clone, Copy)]
pub struct ValidatedJournalEnd {
    raw: [u8; JOURNAL_END_FULL_BYTES],
    raw_len: usize,
}

impl ValidatedJournalEnd {
    /// Physical-task lifetime ticket.
    pub fn thread(&self) -> u64 {
        journal_u64(&self.raw, 8)
    }

    /// Per-thread affecting-entry sequence.
    pub fn sequence(&self) -> u64 {
        journal_u64(&self.raw, 16)
    }

    /// Whether this END arrived in the compact form.
    pub fn compact(&self) -> bool {
        self.raw_len == JOURNAL_END_COMPACT_BYTES
    }

    /// Whether the object tail is absent (all-zero tail, no object row).
    pub fn tail_absent(&self) -> bool {
        self.raw[5] & JOURNAL_END_TAIL_ABSENT != 0
    }

    /// The exact validated wire bytes of this END (either length).
    pub fn raw_bytes(&self) -> &[u8] {
        &self.raw[..self.raw_len]
    }

    /// The reconstructed base record (Event plus private continuity) of
    /// the validated 608-byte payload, identical for both END forms.
    pub fn payload_base(&self) -> crate::EventRecord {
        let payload = self.payload_bytes();
        let mut base = [0u8; 368];
        base.copy_from_slice(&payload[..368]);
        // SAFETY: exactly `EventRecord` bytes; the shared transport type
        // is `repr(C)` and plain-old-data.
        unsafe { core::ptr::read_unaligned(base.as_ptr().cast::<crate::EventRecord>()) }
    }

    /// The exact 240-byte object tail of the validated payload: the
    /// carried H7 tail, or all zeros for the absent-tail form.
    pub fn payload_tail(&self) -> [u8; OBJECT_TAIL_BYTES] {
        let payload = self.payload_bytes();
        let mut tail = [0u8; OBJECT_TAIL_BYTES];
        tail.copy_from_slice(&payload[368..]);
        tail
    }

    /// The reconstructed exact 608-byte H7 completed payload. For the full
    /// form this is the carried payload; for the compact form it is the
    /// carried prefix/suffix with the 160 omitted zero bytes restored, so
    /// both forms yield byte-identical payloads.
    pub fn payload_bytes(&self) -> [u8; OBJECT_TAIL_BYTES + 368] {
        let mut payload = [0u8; OBJECT_TAIL_BYTES + 368];
        if self.compact() {
            payload[..COMPACT_OMIT_START].copy_from_slice(
                &self.raw[JOURNAL_COMMON_BYTES..JOURNAL_COMMON_BYTES + COMPACT_OMIT_START],
            );
            payload[COMPACT_OMIT_END..].copy_from_slice(
                &self.raw[JOURNAL_COMMON_BYTES + COMPACT_OMIT_START..self.raw_len],
            );
        } else {
            payload.copy_from_slice(&self.raw[JOURNAL_COMMON_BYTES..self.raw_len]);
        }
        payload
    }
}

impl core::fmt::Debug for ValidatedJournalEnd {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str("ValidatedJournalEnd(<private>)")
    }
}

/// One validated 64-byte ABANDON record. Constructible only through
/// [`validate_abandon`]. Holds raw target words: redacted `Debug`.
#[derive(Clone, Copy)]
pub struct ValidatedJournalAbandon {
    bytes: [u8; JOURNAL_ABANDON_BYTES],
}

impl ValidatedJournalAbandon {
    /// Physical-task lifetime ticket of the abandoned key.
    pub fn thread(&self) -> u64 {
        journal_u64(&self.bytes, 8)
    }

    /// Per-thread sequence of the abandoned key.
    pub fn sequence(&self) -> u64 {
        journal_u64(&self.bytes, 16)
    }

    /// Retained slot evidence.
    pub fn slot(&self) -> u32 {
        journal_u32(&self.bytes, 48)
    }

    /// Finite abandonment reason code (1..=9).
    pub fn reason(&self) -> u32 {
        journal_u32(&self.bytes, 52)
    }

    /// Retained pid_tgid evidence.
    pub fn pid_tgid(&self) -> u64 {
        journal_u64(&self.bytes, 24)
    }

    /// Retained image evidence (task cookie, exec id).
    pub fn image_cookie(&self) -> u64 {
        journal_u64(&self.bytes, 32)
    }

    /// Retained image evidence (task cookie, exec id).
    pub fn image_exec(&self) -> u64 {
        journal_u64(&self.bytes, 40)
    }

    /// Retained entry timestamp evidence (nanoseconds).
    pub fn entry_ns(&self) -> u64 {
        journal_u64(&self.bytes, 56)
    }

    /// The exact validated ABANDON bytes.
    pub fn bytes(&self) -> &[u8; JOURNAL_ABANDON_BYTES] {
        &self.bytes
    }
}

impl core::fmt::Debug for ValidatedJournalAbandon {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str("ValidatedJournalAbandon(<private>)")
    }
}

/// Validate one complete 224-byte BEGIN record: exact version/length/kind,
/// finite header flags, nonzero identity, finite entry evidence and exact
/// descriptor agreement.
///
/// `descriptor` is `Some` frozen object row for object calls (requested
/// lists follow its template pairs) and `None` for lifecycle/neutral calls
/// without an object row (requested lists must be all zero). The `None` path
/// is structural only: it proves the descriptor names a known non-object
/// function, while the journal's frozen endpoint table (effect-neutral,
/// lifecycle, negative-only) is enforced by the consumer, not the wire.
pub fn validate_begin(
    bytes: &[u8],
    descriptor: Option<&ObjectDescriptorWire>,
) -> Option<ValidatedJournalBegin> {
    if bytes.len() != JOURNAL_BEGIN_BYTES {
        return None;
    }
    if !valid_common_header(bytes, JOURNAL_BEGIN_BYTES, JOURNAL_KIND_BEGIN) {
        return None;
    }
    if bytes[5] & !JOURNAL_BEGIN_NO_END != 0 {
        return None;
    }
    let layout = bytes[124];
    if layout != OBJECT_LAYOUT_LP64 && layout != OBJECT_LAYOUT_ILP32 {
        return None;
    }
    // Session and input words obey the H7 handle rule: VALUE requires a
    // nonzero word, every other finite status requires a zero word; ia32
    // words carry no high bits.
    if !valid_word(bytes[125], journal_u64(bytes, 80), layout) {
        return None;
    }
    if !valid_word(bytes[126], journal_u64(bytes, 88), layout) {
        return None;
    }
    if !valid_word(bytes[127], journal_u64(bytes, 96), layout) {
        return None;
    }
    // The copied entry stamp must be VALID with known bits only. Any
    // epoch/global/fault/slot values are finite evidence.
    let stamp_flags = journal_u16(bytes, 78);
    if stamp_flags & instance::STAMP_VALID == 0 || stamp_flags & !STAMP_MASK != 0 {
        return None;
    }
    // The copied capture word carries only frozen H7 capture bits.
    if journal_u32(bytes, 120) & !CAPTURE_MASK != 0 {
        return None;
    }
    let index = journal_u32(bytes, 108);
    if index == 0 || index >= MAX_DESCRIPTORS {
        return None;
    }
    let function = index - 1;
    pkcs11_module::function_name(usize::try_from(function).ok()?)?;
    match descriptor {
        Some(row) => {
            if row.function != function
                || row.action == 0
                || row.action > OBJECT_ACTION_MAX
                || row.guard == 0
                || row.guard > OBJECT_GUARD_SCALAR_DERIVE
            {
                return None;
            }
            for pair in 0..2 {
                let args = &row.template_args[2 * pair..2 * pair + 2];
                let present = args[0] != ARG_NONE && args[1] != ARG_NONE;
                if (args[0] != ARG_NONE) != (args[1] != ARG_NONE) {
                    return None;
                }
                let list = &bytes[128 + 36 * pair..128 + 36 * (pair + 1)];
                if !present {
                    if list.iter().any(|byte| *byte != 0) {
                        return None;
                    }
                } else if !valid_attribute_list(list) {
                    return None;
                }
            }
        }
        None => {
            if object_descriptor(function).is_some() {
                return None;
            }
            if bytes[128..200].iter().any(|byte| *byte != 0) {
                return None;
            }
        }
    }
    if journal_u32(bytes, 220) != 0 {
        return None;
    }
    let mut owned = [0u8; JOURNAL_BEGIN_BYTES];
    owned.copy_from_slice(bytes);
    Some(ValidatedJournalBegin { bytes: owned })
}

/// Validate one complete END record in either the full (632-byte) or the
/// compact (472-byte) form. Both forms must reconstruct the exact same
/// 608-byte H7 completed payload: event type CALL, affiliation at most 1,
/// and either a validated all-zero absent tail (only with `descriptor`
/// `None` and the absent bit set) or the exact H7 tail validator against
/// the frozen row.
pub fn validate_end(
    bytes: &[u8],
    descriptor: Option<&ObjectDescriptorWire>,
) -> Option<ValidatedJournalEnd> {
    if bytes.len() != JOURNAL_END_FULL_BYTES && bytes.len() != JOURNAL_END_COMPACT_BYTES {
        return None;
    }
    if !valid_common_header(bytes, bytes.len(), JOURNAL_KIND_END) {
        return None;
    }
    if bytes[5] & !JOURNAL_END_TAIL_ABSENT != 0 {
        return None;
    }
    let tail_absent = bytes[5] & JOURNAL_END_TAIL_ABSENT != 0;
    let mut owned = [0u8; JOURNAL_END_FULL_BYTES];
    owned[..bytes.len()].copy_from_slice(bytes);
    let end = ValidatedJournalEnd {
        raw: owned,
        raw_len: bytes.len(),
    };
    let payload = end.payload_bytes();
    if journal_u32(&payload, 284) != event_type::CALL {
        return None;
    }
    if journal_u64(&payload, 320) > 1 {
        return None;
    }
    let tail = &payload[368..];
    if tail_absent {
        if descriptor.is_some() || tail.iter().any(|byte| *byte != 0) {
            return None;
        }
    } else {
        let row = descriptor?;
        if !validate_object_tail(tail, row) {
            return None;
        }
    }
    Some(end)
}

/// Validate one complete 64-byte ABANDON record: exact version/length/kind,
/// zero flags, nonzero identity and a finite reason code.
pub fn validate_abandon(bytes: &[u8]) -> Option<ValidatedJournalAbandon> {
    if bytes.len() != JOURNAL_ABANDON_BYTES {
        return None;
    }
    if !valid_common_header(bytes, JOURNAL_ABANDON_BYTES, JOURNAL_KIND_ABANDON) {
        return None;
    }
    if bytes[5] != 0 {
        return None;
    }
    reason_name(journal_u32(bytes, 52))?;
    let mut owned = [0u8; JOURNAL_ABANDON_BYTES];
    owned.copy_from_slice(bytes);
    Some(ValidatedJournalAbandon { bytes: owned })
}

/// Whether a 608-byte completed payload is eligible for the compact END
/// form: exactly 608 bytes with every byte of the omitted span (120..280)
/// zero. Any nonzero legacy value forces the full form.
pub fn end_compact_eligible(payload: &[u8]) -> bool {
    payload.len() == OBJECT_TAIL_BYTES + 368
        && payload[COMPACT_OMIT_START..COMPACT_OMIT_END]
            .iter()
            .all(|byte| *byte == 0)
}

/// Pack one compact END record from an eligible 608-byte payload: the
/// header plus the payload with the 160-byte omitted span removed. Refuses
/// ineligible payloads, zero identity and non-END header flags.
pub fn pack_compact_end(
    thread: u64,
    sequence: u64,
    flags: u8,
    payload: &[u8],
) -> Option<[u8; JOURNAL_END_COMPACT_BYTES]> {
    if thread == 0 || sequence == 0 {
        return None;
    }
    if flags & !JOURNAL_END_TAIL_ABSENT != 0 {
        return None;
    }
    if !end_compact_eligible(payload) {
        return None;
    }
    let mut bytes = [0u8; JOURNAL_END_COMPACT_BYTES];
    bytes[0..2].copy_from_slice(&JOURNAL_VERSION.to_le_bytes());
    bytes[2..4].copy_from_slice(&(JOURNAL_END_COMPACT_BYTES as u16).to_le_bytes());
    bytes[4] = JOURNAL_KIND_END;
    bytes[5] = flags;
    bytes[8..16].copy_from_slice(&thread.to_le_bytes());
    bytes[16..24].copy_from_slice(&sequence.to_le_bytes());
    bytes[JOURNAL_COMMON_BYTES..JOURNAL_COMMON_BYTES + COMPACT_OMIT_START]
        .copy_from_slice(&payload[..COMPACT_OMIT_START]);
    bytes[JOURNAL_COMMON_BYTES + COMPACT_OMIT_START..]
        .copy_from_slice(&payload[COMPACT_OMIT_END..]);
    Some(bytes)
}

/// One decoded journal record in any of the four wire forms. The Session's
/// retained decoder extends to these lengths alongside the existing
/// 368/608-byte forms; every other length is malformed.
#[derive(Clone, Copy)]
#[allow(clippy::large_enum_variant)] // The frozen 632-byte END stays allocation-free in transfer.
pub enum JournalRecord {
    Begin(ValidatedJournalBegin),
    End(ValidatedJournalEnd),
    Abandon(ValidatedJournalAbandon),
}

impl core::fmt::Debug for JournalRecord {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str(match self {
            Self::Begin(_) => "JournalRecord::Begin(<private>)",
            Self::End(_) => "JournalRecord::End(<private>)",
            Self::Abandon(_) => "JournalRecord::Abandon(<private>)",
        })
    }
}

/// Decode one raw ring record into its validated journal form, or `None`
/// when its length is not a journal form or its bytes refuse. Descriptor
/// agreement mirrors the H7 decoder: the record's descriptor word selects
/// the frozen receipt-bound row, and only a live object row takes the
/// object path — anything else takes the structural no-row path, which
/// the validators re-check. The prefix alone never validates.
pub fn decode_journal_record(
    bytes: &[u8],
    descriptors: &[ObjectDescriptorWire; MAX_DESCRIPTORS as usize],
) -> Option<JournalRecord> {
    match bytes.len() {
        JOURNAL_BEGIN_BYTES => {
            let index = journal_u32(bytes, 108);
            validate_begin(bytes, live_row(index, descriptors)).map(JournalRecord::Begin)
        }
        JOURNAL_END_FULL_BYTES | JOURNAL_END_COMPACT_BYTES => {
            if bytes[5] & JOURNAL_END_TAIL_ABSENT != 0 {
                return validate_end(bytes, None).map(JournalRecord::End);
            }
            let index = if bytes.len() == JOURNAL_END_FULL_BYTES {
                journal_u32(bytes, JOURNAL_COMMON_BYTES + 372)
            } else {
                journal_u32(bytes, compact_tail_index_offset())
            };
            validate_end(bytes, live_row(index, descriptors)).map(JournalRecord::End)
        }
        JOURNAL_ABANDON_BYTES => validate_abandon(bytes).map(JournalRecord::Abandon),
        _ => None,
    }
}

/// The frozen row for one descriptor word, or `None` when the word names
/// no live object row (out of range, zero, or the NONE row). The caller
/// still validates on the taken path; this only selects it.
fn live_row(
    index: u32,
    descriptors: &[ObjectDescriptorWire; MAX_DESCRIPTORS as usize],
) -> Option<&ObjectDescriptorWire> {
    if index == 0 || index >= MAX_DESCRIPTORS {
        return None;
    }
    let row = &descriptors[index as usize];
    (row.action != 0).then_some(row)
}

/// Offset of the tail descriptor word inside a compact END record: header
/// plus the carried 120-byte prefix, 48-byte capture/identity span and
/// 40-byte continuity, then the tail's own 4-byte header.
const fn compact_tail_index_offset() -> usize {
    JOURNAL_COMMON_BYTES + COMPACT_OMIT_START + 48 + 40 + 4
}

/// Exact version/length/kind, zero reserved word and nonzero identity.
fn valid_common_header(bytes: &[u8], len: usize, kind: u8) -> bool {
    journal_u16(bytes, 0) == JOURNAL_VERSION
        && journal_u16(bytes, 2) == len as u16
        && bytes[4] == kind
        && journal_u16(bytes, 6) == 0
        && journal_u64(bytes, 8) != 0
        && journal_u64(bytes, 16) != 0
}

/// The H7 handle rule for one copied entry word: a finite status, VALUE if
/// and only if the word is nonzero, and no high bits on ia32.
fn valid_word(status: u8, word: u64, layout: u8) -> bool {
    if status > OBJECT_HANDLE_STATUS_MAX {
        return false;
    }
    if layout == OBJECT_LAYOUT_ILP32 && word > u64::from(u32::MAX) {
        return false;
    }
    if status == 1 {
        word != 0
    } else {
        word == 0
    }
}

fn journal_u16(bytes: &[u8], offset: usize) -> u16 {
    u16::from_le_bytes([bytes[offset], bytes[offset + 1]])
}

fn journal_u32(bytes: &[u8], offset: usize) -> u32 {
    u32::from_le_bytes([
        bytes[offset],
        bytes[offset + 1],
        bytes[offset + 2],
        bytes[offset + 3],
    ])
}

fn journal_u64(bytes: &[u8], offset: usize) -> u64 {
    u64::from_le_bytes([
        bytes[offset],
        bytes[offset + 1],
        bytes[offset + 2],
        bytes[offset + 3],
        bytes[offset + 4],
        bytes[offset + 5],
        bytes[offset + 6],
        bytes[offset + 7],
    ])
}

/// Statically pin the frozen wire sizes against the H7 tail and payload.
#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn object_journal_sizes_match_h7_payload() {
        use crate::object_wire::{OBJECT_ATTR_STATUS_MAX, OBJECT_CALL_BYTES};
        assert_eq!(OBJECT_CALL_BYTES as usize, OBJECT_TAIL_BYTES);
        assert_eq!(
            JOURNAL_END_FULL_BYTES,
            JOURNAL_COMMON_BYTES + 368 + OBJECT_TAIL_BYTES
        );
        assert_eq!(
            JOURNAL_END_COMPACT_BYTES,
            JOURNAL_END_FULL_BYTES - (COMPACT_OMIT_END - COMPACT_OMIT_START)
        );
        assert_eq!(COMPACT_OMIT_END - COMPACT_OMIT_START, 160);
        assert_eq!(OBJECT_ATTR_STATUS_MAX, 10);
    }
}
