//! SPDX-License-Identifier: GPL-2.0-or-later
//! Finite object wire contracts (H7). Exact kernel/userspace layouts for
//! object-call facts plus their pure validators. These types pin the frozen
//! wire; they activate no capture and authorize no read by themselves.
//!
//! Wire structs deliberately implement no `Debug`/`Serialize`: several hold
//! raw target words (pointers, handles, lengths) that must never be logged
//! verbatim. Validators return plain verdicts instead.

use crate::object_policy::{object_descriptor, ObjectAction, ResultProtocolGuard};
use crate::{EventRecord, ImageIdentity, LinuxLayout, ARG_NONE, FUNCTION_NONE, MAX_DESCRIPTORS};

/// Object-call tail protocol version and exact byte length.
pub const OBJECT_CALL_VERSION: u16 = 1;
pub const OBJECT_CALL_BYTES: u16 = 240;
/// Complete 608-byte object CALL record and its 240-byte object tail.
pub const OBJECT_RECORD_BYTES: usize = 608;
pub const OBJECT_TAIL_BYTES: usize = 240;
/// Largest syntactically valid START object marker (`descriptor_index + 1`).
pub const START_MARKER_MAX: u64 = MAX_DESCRIPTORS as u64;

/// Frozen object action codes.
pub const OBJECT_ACTION_NONE: u8 = 0;
pub const OBJECT_ACTION_CREATE: u8 = 1;
pub const OBJECT_ACTION_COPY: u8 = 2;
pub const OBJECT_ACTION_GENERATE: u8 = 3;
pub const OBJECT_ACTION_PAIR: u8 = 4;
pub const OBJECT_ACTION_DERIVE: u8 = 5;
pub const OBJECT_ACTION_UNWRAP: u8 = 6;
pub const OBJECT_ACTION_DESTROY: u8 = 7;
pub const OBJECT_ACTION_ACCESS: u8 = 8;
pub const OBJECT_ACTION_IMPORT: u8 = 9;
pub const OBJECT_ACTION_FIND: u8 = 10;
pub const OBJECT_ACTION_GET: u8 = 11;
pub const OBJECT_ACTION_SET: u8 = 12;
pub const OBJECT_ACTION_MAX: u8 = OBJECT_ACTION_SET;

/// Frozen result-protocol guard codes.
pub const OBJECT_GUARD_NONE: u8 = 0;
pub const OBJECT_GUARD_NAMED: u8 = 1;
pub const OBJECT_GUARD_SCALAR_DERIVE: u8 = 2;

/// Frozen layout codes.
pub const OBJECT_LAYOUT_LP64: u8 = 1;
pub const OBJECT_LAYOUT_ILP32: u8 = 2;

/// Frozen entry-derive codes.
pub const OBJECT_DERIVE_UNAVAILABLE: u8 = 0;
pub const OBJECT_DERIVE_DH_PKCS: u8 = 1;
pub const OBJECT_DERIVE_SHA256: u8 = 2;
pub const OBJECT_DERIVE_ECDH1: u8 = 3;
pub const OBJECT_DERIVE_ECDH1_COFACTOR: u8 = 4;

/// Largest valid attribute kind, attribute status and handle status codes.
pub const OBJECT_ATTR_KIND_MAX: u8 = 6;
pub const OBJECT_ATTR_STATUS_MAX: u8 = 10;
pub const OBJECT_HANDLE_STATUS_MAX: u8 = 9;
/// Only object-flags bits 0..=7 and find-flags bits 0..=5 are defined.
pub const OBJECT_FLAGS_MASK: u32 = 0xFF;
/// Private side-row bits for the four Get entry-list flags. These never
/// cross the public object tail and do not change any layout or wire code.
pub const GET_ENTRY_FLAGS_SHIFT: u32 = 8;
pub const GET_ENTRY_FLAGS_MASK: u16 = 0x0F << GET_ENTRY_FLAGS_SHIFT;
pub const OBJECT_FIND_FLAGS_MASK: u8 = 0x3F;
/// Attribute-list flags bit 4: the list's inspection never ran, so its
/// all-zero cells are uninspected, never inspected-empty. Slice-D
/// emission marks request lists (BPF performs no entry template
/// inspection); the brief's bits 0..=3 keep their inspected meaning.
pub const OBJECT_ATTR_LIST_FLAGS_MASK: u8 = 0x1F;
pub const OBJECT_ATTR_LIST_UNINSPECTED: u8 = 0x10;
/// Find results carry at most eight handles; `find_len` and `find_valid`
/// are finite (`find_valid` is 0/1 only).
pub const OBJECT_FIND_HANDLES_MAX: u8 = 8;

/// One frozen 16-byte object protocol row: which arguments a named function
/// may contribute under the object protocol. `NONE` uses `FUNCTION_NONE`,
/// `ARG_NONE` in every argument position and zero action/guard.
#[repr(C)]
#[derive(Clone, Copy, Default, PartialEq, Eq)]
pub struct ObjectDescriptorWire {
    pub function: u32,
    pub input_args: [u8; 2],
    pub result_args: [u8; 2],
    pub template_args: [u8; 4],
    pub find_capacity_arg: u8,
    pub find_count_arg: u8,
    pub action: u8,
    pub guard: u8,
}

/// One classified 4-byte attribute cell. Only a classified value status
/// permits a nonzero value; unknown selectors leave an all-zero cell.
#[repr(C)]
#[derive(Clone, Copy, Default, PartialEq, Eq)]
pub struct ObjectAttributeWire {
    pub kind: u8,
    pub status: u8,
    pub value: u16,
}

/// Eight cells plus inspection counts/flags; 36 bytes. Slot order and
/// duplicate observations are preserved; `inspected <= 8`.
#[repr(C)]
#[derive(Clone, Copy, Default, PartialEq, Eq)]
pub struct ObjectAttributeListWire {
    pub cells: [ObjectAttributeWire; 8],
    pub inspected: u8,
    pub flags: u8,
    pub reserved: u16,
}

/// One retained GetAttribute entry-header slot; 32 bytes. Only selected
/// slots persist here; `returned_len` is return-phase scratch.
#[repr(C)]
#[derive(Clone, Copy, Default, PartialEq, Eq)]
pub struct ObjectAttributeSlot {
    pub value_ptr: u64,
    pub entry_capacity: u64,
    pub returned_len: u64,
    pub kind: u8,
    pub slot_index: u8,
    pub status: u8,
    pub reserved: [u8; 5],
}

/// Bounded 432-byte subordinate owner row for one required object call.
#[repr(C)]
#[derive(Clone, Copy, Default, PartialEq, Eq)]
pub struct ObjectStart {
    pub image: ImageIdentity,
    pub entry_ns: u64,
    pub descriptor_index: u32,
    pub layout: u8,
    pub action: u8,
    pub derive: u8,
    pub phase: u8,
    pub inputs: [u64; 2],
    pub result_ptrs: [u64; 2],
    pub get_template_base: u64,
    pub inspected_header_end: u64,
    pub find_capacity: u64,
    pub find_count_ptr: u64,
    pub slots: [ObjectAttributeSlot; 8],
    pub requested: [ObjectAttributeListWire; 2],
    pub input_statuses: [u8; 2],
    pub result_statuses: [u8; 2],
    pub flags: u16,
    pub get_inspected: u8,
    pub reserved: u8,
}

/// The validated 240-byte object tail of a completed CALL record. No
/// pointer, capacity, raw selector, raw length or arbitrary attribute word.
#[repr(C)]
#[derive(Clone, Copy, Default, PartialEq, Eq)]
pub struct ObjectCallWire {
    pub version: u16,
    pub bytes: u16,
    pub descriptor_index: u32,
    pub flags: u32,
    pub layout: u8,
    pub action: u8,
    pub entry_derive: u8,
    pub reserved0: u8,
    pub input_handles: [u64; 2],
    pub result_handles: [u64; 2],
    pub find_handles: [u64; 8],
    pub input_status: [u8; 2],
    pub result_status: [u8; 2],
    pub find_status: [u8; 8],
    pub find_len: u8,
    pub find_flags: u8,
    pub find_valid: u8,
    pub reserved1: u8,
    pub requested: [ObjectAttributeListWire; 2],
    pub result_attributes: ObjectAttributeListWire,
    pub reserved2: u32,
}

/// The complete 608-byte object CALL record form: the existing base record
/// plus the object tail. Only CALL uses this form.
#[repr(C)]
#[derive(Clone, Copy, Default)]
pub struct ObjectEventRecord {
    pub base: EventRecord,
    pub object: ObjectCallWire,
}

/// Descriptor rows hold frozen policy only (ordinals, indices, codes), never
/// raw target words, so an explicit `Debug` is safe here. Runtime-word
/// structs below it stay `Debug`-free.
impl core::fmt::Debug for ObjectDescriptorWire {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("ObjectDescriptorWire")
            .field("function", &self.function)
            .field("input_args", &self.input_args)
            .field("result_args", &self.result_args)
            .field("template_args", &self.template_args)
            .field("find_capacity_arg", &self.find_capacity_arg)
            .field("find_count_arg", &self.find_count_arg)
            .field("action", &self.action)
            .field("guard", &self.guard)
            .finish()
    }
}

/// The ineligible/empty protocol row: `FUNCTION_NONE`, `ARG_NONE` in every
/// argument position, zero action/guard.
pub const fn none_object_wire() -> ObjectDescriptorWire {
    ObjectDescriptorWire {
        function: FUNCTION_NONE,
        input_args: [ARG_NONE; 2],
        result_args: [ARG_NONE; 2],
        template_args: [ARG_NONE; 4],
        find_capacity_arg: ARG_NONE,
        find_count_arg: ARG_NONE,
        action: OBJECT_ACTION_NONE,
        guard: OBJECT_GUARD_NONE,
    }
}

/// Which record form raw ring bytes carry. Content validation of the
/// ordinary form stays with the existing decoder; the object form requires
/// a fully valid tail (never accepted on its prefix alone).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ObjectRecordForm {
    Ordinary,
    Object,
}

/// One validated 240-byte object tail. Constructible only through
/// [`validate_object_tail`], so possession proves full validation against
/// the frozen row. Holds raw target words: deliberately no `Debug`.
#[derive(Clone, Copy)]
pub struct ValidatedObjectCall {
    tail: [u8; OBJECT_TAIL_BYTES],
}

impl ValidatedObjectCall {
    /// Validate one complete tail against its frozen descriptor row.
    pub fn validate(tail: &[u8], descriptor: &ObjectDescriptorWire) -> Option<Self> {
        if !validate_object_tail(tail, descriptor) {
            return None;
        }
        let mut owned = [0u8; OBJECT_TAIL_BYTES];
        owned.copy_from_slice(tail);
        Some(Self { tail: owned })
    }

    /// The exact validated tail bytes.
    pub fn tail_bytes(&self) -> &[u8; OBJECT_TAIL_BYTES] {
        &self.tail
    }

    /// Canonical descriptor index the tail validated against.
    pub fn descriptor_index(&self) -> u32 {
        tail_u32(&self.tail, 4)
    }

    /// Validated action code.
    pub fn action(&self) -> u8 {
        self.tail[13]
    }

    /// Validated layout code.
    pub fn layout(&self) -> u8 {
        self.tail[12]
    }
}

/// Meaning of a START `object_required` marker word against the frozen
/// table: zero is ordinary, a required marker names its table index, and
/// anything else (NONE row, out of range, reserved bits) is invalid.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum StartMarkerVerdict {
    Ordinary,
    Required { index: u32 },
    Invalid,
}

/// Canonical wire encoding of one function ordinal's object protocol, or
/// the NONE row for unknown/ineligible functions. Pure: no reads.
pub fn canonical_object_wire(function: u32) -> ObjectDescriptorWire {
    let Some(policy) = object_descriptor(function) else {
        return none_object_wire();
    };
    let action = match policy.action {
        ObjectAction::Create => OBJECT_ACTION_CREATE,
        ObjectAction::Copy => OBJECT_ACTION_COPY,
        ObjectAction::Generate => OBJECT_ACTION_GENERATE,
        ObjectAction::GeneratePair => OBJECT_ACTION_PAIR,
        ObjectAction::Derive => OBJECT_ACTION_DERIVE,
        ObjectAction::Unwrap => OBJECT_ACTION_UNWRAP,
        ObjectAction::Destroy => OBJECT_ACTION_DESTROY,
        ObjectAction::Access => OBJECT_ACTION_ACCESS,
        ObjectAction::OperationImport => OBJECT_ACTION_IMPORT,
        ObjectAction::Find => OBJECT_ACTION_FIND,
        ObjectAction::GetAttributes => OBJECT_ACTION_GET,
        ObjectAction::SetAttributes => OBJECT_ACTION_SET,
    };
    let guard = match policy.result_protocol_guard {
        ResultProtocolGuard::NamedFunction => OBJECT_GUARD_NAMED,
        ResultProtocolGuard::ScalarDeriveMechanism => OBJECT_GUARD_SCALAR_DERIVE,
    };
    ObjectDescriptorWire {
        function,
        input_args: policy.input_args,
        result_args: policy.result_pointer_args,
        template_args: [
            policy.template_args[0].0,
            policy.template_args[0].1,
            policy.template_args[1].0,
            policy.template_args[1].1,
        ],
        find_capacity_arg: policy.find_capacity_arg,
        find_count_arg: policy.find_count_ptr_arg,
        action,
        guard,
    }
}

/// Publish the frozen 105-row descriptor table: row 0 is NONE, rows
/// 1..=104 are the canonical rows in canonical-index order.
pub fn publish_object_descriptors() -> [ObjectDescriptorWire; MAX_DESCRIPTORS as usize] {
    let mut rows = [none_object_wire(); MAX_DESCRIPTORS as usize];
    for function in 0..MAX_DESCRIPTORS - 1 {
        rows[(function + 1) as usize] = canonical_object_wire(function);
    }
    rows
}

/// Every row must equal its canonical encoding; any disagreement refuses.
pub fn verify_object_descriptors(rows: &[ObjectDescriptorWire; MAX_DESCRIPTORS as usize]) -> bool {
    if rows[0] != none_object_wire() {
        return false;
    }
    for function in 0..MAX_DESCRIPTORS - 1 {
        if rows[(function + 1) as usize] != canonical_object_wire(function) {
            return false;
        }
    }
    true
}

/// Validate one complete 240-byte tail against its frozen descriptor row:
/// exact version/length, finite codes only, zero padding, possible
/// action/field combinations and the exact canonical descriptor.
pub fn validate_object_tail(tail: &[u8], descriptor: &ObjectDescriptorWire) -> bool {
    if tail.len() != OBJECT_TAIL_BYTES {
        return false;
    }
    if tail_u16(tail, 0) != OBJECT_CALL_VERSION || tail_u16(tail, 2) != OBJECT_CALL_BYTES {
        return false;
    }
    // Exact canonical descriptor: the row's function ordinal is the tail's
    // index minus one, with matching action. Index 0 has no object
    // protocol (ordinary calls use the 368-byte form).
    let index = tail_u32(tail, 4);
    if index == 0 || index >= MAX_DESCRIPTORS {
        return false;
    }
    if u64::from(descriptor.function) != u64::from(index) - 1 {
        return false;
    }
    if descriptor.action == OBJECT_ACTION_NONE
        || descriptor.action > OBJECT_ACTION_MAX
        || descriptor.guard == OBJECT_GUARD_NONE
        || descriptor.guard > OBJECT_GUARD_SCALAR_DERIVE
    {
        return false;
    }
    if tail[13] != descriptor.action {
        return false;
    }
    if tail_u32(tail, 8) & !OBJECT_FLAGS_MASK != 0 {
        return false;
    }
    let layout = tail[12];
    if layout != OBJECT_LAYOUT_LP64 && layout != OBJECT_LAYOUT_ILP32 {
        return false;
    }
    let action = tail[13];
    if action > OBJECT_ACTION_MAX {
        return false;
    }
    let entry_derive = tail[14];
    if entry_derive > OBJECT_DERIVE_ECDH1_COFACTOR {
        return false;
    }
    if action != OBJECT_ACTION_DERIVE && entry_derive != OBJECT_DERIVE_UNAVAILABLE {
        return false;
    }
    if tail[15] != 0 {
        return false;
    }
    // Input positions: descriptor-absent positions stay absent with zero
    // words; present positions carry a non-absent status, except import
    // inputs, which are absent for zero words.
    for i in 0..2 {
        let status = tail[112 + i];
        if status > OBJECT_HANDLE_STATUS_MAX {
            return false;
        }
        if descriptor.input_args[i] == ARG_NONE {
            if status != 0 {
                return false;
            }
        } else if action != OBJECT_ACTION_IMPORT && status == 0 {
            return false;
        }
        if !valid_handle_word(status, tail_u64(tail, 16 + 8 * i), layout) {
            return false;
        }
    }
    // Result positions: descriptor-present results always carry a
    // non-absent status (unavailable covers unobserved results); descriptor
    // absent positions stay absent with zero words.
    for i in 0..2 {
        let status = tail[114 + i];
        if status > OBJECT_HANDLE_STATUS_MAX {
            return false;
        }
        if descriptor.result_args[i] == ARG_NONE {
            if status != 0 {
                return false;
            }
        } else if status == 0 {
            return false;
        }
        if !valid_handle_word(status, tail_u64(tail, 32 + 8 * i), layout) {
            return false;
        }
    }
    if !valid_find_section(tail, action, layout) {
        return false;
    }
    // Requested lists: descriptor-absent pairs stay all-zero; present pairs
    // carry a valid list (possibly empty). A half-present pair is corrupt.
    for i in 0..2 {
        let pair = &descriptor.template_args[2 * i..2 * i + 2];
        let present = pair[0] != ARG_NONE && pair[1] != ARG_NONE;
        if (pair[0] != ARG_NONE) != (pair[1] != ARG_NONE) {
            return false;
        }
        let list = &tail[128 + 36 * i..128 + 36 * (i + 1)];
        if !present {
            if list.iter().any(|byte| *byte != 0) {
                return false;
            }
        } else if !valid_attribute_list(list) {
            return false;
        }
    }
    // Only Get populates the result-attribute list.
    let results = &tail[200..236];
    if action != OBJECT_ACTION_GET {
        if results.iter().any(|byte| *byte != 0) {
            return false;
        }
    } else if !valid_attribute_list(results) {
        return false;
    }
    if tail_u32(tail, 236) != 0 {
        return false;
    }
    true
}

/// A value status requires a nonzero word (a zero observation carries the
/// invalid-zero status instead); every other status requires a zero word.
/// ia32 tails reject words with high bits on every handle.
fn valid_handle_word(status: u8, word: u64, layout: u8) -> bool {
    if layout == OBJECT_LAYOUT_ILP32 && word > u64::from(u32::MAX) {
        return false;
    }
    if status == 1 {
        word != 0
    } else {
        word == 0
    }
}

/// Only Find populates the Find section. Cells before `find_len` carry a
/// non-absent status, cells at and after it stay absent with zero words;
/// an invalid Find carries no length, and truncation implies eight cells.
fn valid_find_section(tail: &[u8], action: u8, layout: u8) -> bool {
    let find_len = tail[124];
    let find_flags = tail[125];
    let find_valid = tail[126];
    if tail[127] != 0 {
        return false;
    }
    if find_len > OBJECT_FIND_HANDLES_MAX
        || find_flags & !OBJECT_FIND_FLAGS_MASK != 0
        || find_valid > 1
    {
        return false;
    }
    if action != OBJECT_ACTION_FIND {
        if find_len != 0 || find_flags != 0 || find_valid != 0 {
            return false;
        }
        for i in 0..8 {
            if tail[116 + i] != 0 || tail_u64(tail, 48 + 8 * i) != 0 {
                return false;
            }
        }
        return true;
    }
    if find_valid == 0 && find_len != 0 {
        return false;
    }
    if find_flags & 1 != 0 && find_len != OBJECT_FIND_HANDLES_MAX {
        return false;
    }
    for i in 0..8 {
        let status = tail[116 + i];
        if status > OBJECT_HANDLE_STATUS_MAX {
            return false;
        }
        if i < find_len as usize {
            if status == 0 {
                return false;
            }
        } else if status != 0 {
            return false;
        }
        if !valid_handle_word(status, tail_u64(tail, 48 + 8 * i), layout) {
            return false;
        }
    }
    true
}

/// Finite codes, zero padding, an inspected count within the cells, a set
/// present bit for any inspected cell, truncation only at eight cells, and
/// zero cells at and after the inspected count. A nonzero value requires
/// the value status (scalar zero stays valid through its status). The
/// uninspected marker accepts only the honest never-inspected shape:
/// zero cells, zero inspected count and no inspected flag bits.
pub(crate) fn valid_attribute_list(list: &[u8]) -> bool {
    let inspected = list[32];
    let flags = list[33];
    if inspected > 8 || list[34] != 0 || list[35] != 0 || flags & !OBJECT_ATTR_LIST_FLAGS_MASK != 0
    {
        return false;
    }
    if flags & OBJECT_ATTR_LIST_UNINSPECTED != 0 {
        return inspected == 0
            && flags == OBJECT_ATTR_LIST_UNINSPECTED
            && list[..32].iter().all(|byte| *byte == 0);
    }
    if inspected > 0 && flags & 1 == 0 {
        return false;
    }
    if flags & 2 != 0 && inspected != 8 {
        return false;
    }
    for i in 0..8 {
        let base = 4 * i;
        let kind = list[base];
        let status = list[base + 1];
        let value = u16::from_le_bytes([list[base + 2], list[base + 3]]);
        if kind > OBJECT_ATTR_KIND_MAX || status > OBJECT_ATTR_STATUS_MAX {
            return false;
        }
        if status != 1 && value != 0 {
            return false;
        }
        if i >= inspected as usize && (kind != 0 || status != 0 || value != 0) {
            return false;
        }
    }
    true
}

fn tail_u16(tail: &[u8], offset: usize) -> u16 {
    u16::from_le_bytes([tail[offset], tail[offset + 1]])
}

fn tail_u32(tail: &[u8], offset: usize) -> u32 {
    u32::from_le_bytes([
        tail[offset],
        tail[offset + 1],
        tail[offset + 2],
        tail[offset + 3],
    ])
}

fn tail_u64(tail: &[u8], offset: usize) -> u64 {
    u64::from_le_bytes([
        tail[offset],
        tail[offset + 1],
        tail[offset + 2],
        tail[offset + 3],
        tail[offset + 4],
        tail[offset + 5],
        tail[offset + 6],
        tail[offset + 7],
    ])
}

/// Dispatch raw ring bytes to their record form: exactly 368 bytes is
/// ordinary, exactly 608 bytes requires a fully valid object tail against
/// the frozen table, and every other length is malformed.
pub fn object_record_form(
    bytes: &[u8],
    descriptors: &[ObjectDescriptorWire; MAX_DESCRIPTORS as usize],
) -> Option<ObjectRecordForm> {
    if bytes.len() == core::mem::size_of::<EventRecord>() {
        return Some(ObjectRecordForm::Ordinary);
    }
    if bytes.len() != OBJECT_RECORD_BYTES {
        return None;
    }
    let index = tail_u32(bytes, 372);
    if index == 0 || index >= MAX_DESCRIPTORS {
        return None;
    }
    validate_object_tail(&bytes[368..], &descriptors[index as usize])
        .then_some(ObjectRecordForm::Object)
}

/// Validate a START marker word against the frozen table.
pub fn validate_start_marker(
    marker: u64,
    descriptors: &[ObjectDescriptorWire; MAX_DESCRIPTORS as usize],
) -> StartMarkerVerdict {
    if marker == 0 {
        return StartMarkerVerdict::Ordinary;
    }
    if marker > START_MARKER_MAX {
        return StartMarkerVerdict::Invalid;
    }
    let row = &descriptors[(marker - 1) as usize];
    let action_ok = row.action != OBJECT_ACTION_NONE && row.action <= OBJECT_ACTION_MAX;
    let guard_ok = row.guard != OBJECT_GUARD_NONE && row.guard <= OBJECT_GUARD_SCALAR_DERIVE;
    if marker >= 2 && u64::from(row.function) == marker - 2 && action_ok && guard_ok {
        StartMarkerVerdict::Required {
            index: (marker - 1) as u32,
        }
    } else {
        StartMarkerVerdict::Invalid
    }
}

/// Address of the named object-result argument 7 for pair-private and
/// unwrap descriptors only: LP64 SP+16, ia32 SP+32, with the complete word
/// span checked. Any other descriptor, a wrapping address or an address
/// outside the target word range refuses. Arguments 8/9 have no reader:
/// this helper takes no index, and the ordinary reader still refuses them.
pub fn object_result_arg7_address(
    descriptor: &ObjectDescriptorWire,
    stack_pointer: u64,
    layout: LinuxLayout,
) -> Option<u64> {
    let pair_or_unwrap =
        descriptor.action == OBJECT_ACTION_PAIR || descriptor.action == OBJECT_ACTION_UNWRAP;
    if !pair_or_unwrap || !descriptor.result_args.contains(&7) {
        return None;
    }
    match layout {
        LinuxLayout::Lp64 => {
            let address = stack_pointer.checked_add(16)?;
            crate::target_word_end(address, layout)?;
            Some(address)
        }
        LinuxLayout::Ilp32 => {
            let address = (stack_pointer & u64::from(u32::MAX)).checked_add(32)?;
            crate::target_word_end(address, layout)?;
            Some(address)
        }
    }
}

#[cfg(test)]
mod tests;
