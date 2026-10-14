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
pub const OBJECT_FIND_FLAGS_MASK: u8 = 0x3F;
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
    let _ = (
        function,
        ObjectAction::Create,
        ResultProtocolGuard::NamedFunction,
    );
    let _ = object_descriptor;
    todo!("H7 slice A: encode the closed policy catalog as wire rows")
}

/// Publish the frozen 105-row descriptor table: row 0 is NONE, rows
/// 1..=104 are the canonical rows in canonical-index order.
pub fn publish_object_descriptors() -> [ObjectDescriptorWire; MAX_DESCRIPTORS as usize] {
    todo!("H7 slice A: publish the frozen descriptor table")
}

/// Every row must equal its canonical encoding; any disagreement refuses.
pub fn verify_object_descriptors(rows: &[ObjectDescriptorWire; MAX_DESCRIPTORS as usize]) -> bool {
    let _ = rows;
    todo!("H7 slice A: verify every published row")
}

/// Validate one complete 240-byte tail against its frozen descriptor row:
/// exact version/length, finite codes only, zero padding, possible
/// action/field combinations and the exact canonical descriptor.
pub fn validate_object_tail(tail: &[u8], descriptor: &ObjectDescriptorWire) -> bool {
    let _ = (tail, descriptor);
    todo!("H7 slice A: validate the complete object tail")
}

/// Dispatch raw ring bytes to their record form: exactly 368 bytes is
/// ordinary, exactly 608 bytes requires a fully valid object tail against
/// the frozen table, and every other length is malformed.
pub fn object_record_form(
    bytes: &[u8],
    descriptors: &[ObjectDescriptorWire; MAX_DESCRIPTORS as usize],
) -> Option<ObjectRecordForm> {
    let _ = (bytes, descriptors);
    todo!("H7 slice A: dispatch the two exact record forms")
}

/// Validate a START marker word against the frozen table.
pub fn validate_start_marker(
    marker: u64,
    descriptors: &[ObjectDescriptorWire; MAX_DESCRIPTORS as usize],
) -> StartMarkerVerdict {
    let _ = (marker, descriptors);
    todo!("H7 slice A: validate the finite START marker")
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
    let _ = (descriptor, stack_pointer, layout);
    todo!("H7 slice A: name and bound the object-result arg7 address")
}

#[cfg(test)]
mod tests;
