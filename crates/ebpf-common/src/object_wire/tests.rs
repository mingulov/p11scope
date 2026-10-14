//! SPDX-License-Identifier: GPL-2.0-or-later

use super::*;
use crate::{LinuxLayout, ARG_NONE as N};

fn put_u16(buf: &mut [u8; OBJECT_TAIL_BYTES], offset: usize, value: u16) {
    buf[offset..offset + 2].copy_from_slice(&value.to_le_bytes());
}

fn put_u32(buf: &mut [u8; OBJECT_TAIL_BYTES], offset: usize, value: u32) {
    buf[offset..offset + 4].copy_from_slice(&value.to_le_bytes());
}

fn put_u64(buf: &mut [u8; OBJECT_TAIL_BYTES], offset: usize, value: u64) {
    buf[offset..offset + 8].copy_from_slice(&value.to_le_bytes());
}

/// Hand-built Create protocol row. Function 20 is `C_CreateObject`; the
/// integration catalog test pins every hardcoded function ordinal.
fn create_descriptor() -> ObjectDescriptorWire {
    ObjectDescriptorWire {
        function: 20,
        input_args: [N; 2],
        result_args: [3, N],
        template_args: [1, 2, N, N],
        find_capacity_arg: N,
        find_count_arg: N,
        action: OBJECT_ACTION_CREATE,
        guard: OBJECT_GUARD_NAMED,
    }
}

/// Hand-built pair-private row (function 59 is `C_GenerateKeyPair`).
fn pair_descriptor() -> ObjectDescriptorWire {
    ObjectDescriptorWire {
        function: 59,
        input_args: [N; 2],
        result_args: [6, 7],
        template_args: [2, 3, 4, 5],
        find_capacity_arg: N,
        find_count_arg: N,
        action: OBJECT_ACTION_PAIR,
        guard: OBJECT_GUARD_NAMED,
    }
}

/// Hand-built unwrap row (function 61 is `C_UnwrapKey`).
fn unwrap_descriptor() -> ObjectDescriptorWire {
    ObjectDescriptorWire {
        function: 61,
        input_args: [2, N],
        result_args: [7, N],
        template_args: [5, 6, N, N],
        find_capacity_arg: N,
        find_count_arg: N,
        action: OBJECT_ACTION_UNWRAP,
        guard: OBJECT_GUARD_NAMED,
    }
}

/// A valid Create tail encoded byte by byte (independent of the wire
/// struct): version 1, 240 bytes, index 21, LP64, one value result.
fn valid_create_tail() -> [u8; OBJECT_TAIL_BYTES] {
    let mut tail = [0u8; OBJECT_TAIL_BYTES];
    put_u16(&mut tail, 0, OBJECT_CALL_VERSION);
    put_u16(&mut tail, 2, OBJECT_CALL_BYTES);
    put_u32(&mut tail, 4, 21);
    tail[12] = OBJECT_LAYOUT_LP64;
    tail[13] = OBJECT_ACTION_CREATE;
    put_u64(&mut tail, 32, 0x1234);
    tail[114] = 1;
    tail
}

#[test]
fn object_producer_wire_layout_and_zero_padding() {
    use core::mem::{align_of, offset_of, size_of};
    assert_eq!(size_of::<ObjectDescriptorWire>(), 16);
    assert_eq!(size_of::<ObjectAttributeWire>(), 4);
    assert_eq!(size_of::<ObjectAttributeListWire>(), 36);
    assert_eq!(size_of::<ObjectAttributeSlot>(), 32);
    assert_eq!(size_of::<ObjectStart>(), 432);
    assert_eq!(size_of::<ObjectCallWire>(), 240);
    assert_eq!(size_of::<ObjectEventRecord>(), 608);
    assert_eq!(align_of::<ObjectStart>(), 8);
    assert_eq!(align_of::<ObjectCallWire>(), 8);
    assert_eq!(align_of::<ObjectEventRecord>(), 8);

    assert_eq!(offset_of!(ObjectDescriptorWire, function), 0);
    assert_eq!(offset_of!(ObjectDescriptorWire, input_args), 4);
    assert_eq!(offset_of!(ObjectDescriptorWire, result_args), 6);
    assert_eq!(offset_of!(ObjectDescriptorWire, template_args), 8);
    assert_eq!(offset_of!(ObjectDescriptorWire, find_capacity_arg), 12);
    assert_eq!(offset_of!(ObjectDescriptorWire, find_count_arg), 13);
    assert_eq!(offset_of!(ObjectDescriptorWire, action), 14);
    assert_eq!(offset_of!(ObjectDescriptorWire, guard), 15);

    assert_eq!(offset_of!(ObjectAttributeWire, kind), 0);
    assert_eq!(offset_of!(ObjectAttributeWire, status), 1);
    assert_eq!(offset_of!(ObjectAttributeWire, value), 2);

    assert_eq!(offset_of!(ObjectAttributeListWire, cells), 0);
    assert_eq!(offset_of!(ObjectAttributeListWire, inspected), 32);
    assert_eq!(offset_of!(ObjectAttributeListWire, flags), 33);
    assert_eq!(offset_of!(ObjectAttributeListWire, reserved), 34);

    assert_eq!(offset_of!(ObjectAttributeSlot, value_ptr), 0);
    assert_eq!(offset_of!(ObjectAttributeSlot, entry_capacity), 8);
    assert_eq!(offset_of!(ObjectAttributeSlot, returned_len), 16);
    assert_eq!(offset_of!(ObjectAttributeSlot, kind), 24);
    assert_eq!(offset_of!(ObjectAttributeSlot, slot_index), 25);
    assert_eq!(offset_of!(ObjectAttributeSlot, status), 26);
    assert_eq!(offset_of!(ObjectAttributeSlot, reserved), 27);

    assert_eq!(offset_of!(ObjectStart, image), 0);
    assert_eq!(offset_of!(ObjectStart, entry_ns), 16);
    assert_eq!(offset_of!(ObjectStart, descriptor_index), 24);
    assert_eq!(offset_of!(ObjectStart, layout), 28);
    assert_eq!(offset_of!(ObjectStart, action), 29);
    assert_eq!(offset_of!(ObjectStart, derive), 30);
    assert_eq!(offset_of!(ObjectStart, phase), 31);
    assert_eq!(offset_of!(ObjectStart, inputs), 32);
    assert_eq!(offset_of!(ObjectStart, result_ptrs), 48);
    assert_eq!(offset_of!(ObjectStart, get_template_base), 64);
    assert_eq!(offset_of!(ObjectStart, inspected_header_end), 72);
    assert_eq!(offset_of!(ObjectStart, find_capacity), 80);
    assert_eq!(offset_of!(ObjectStart, find_count_ptr), 88);
    assert_eq!(offset_of!(ObjectStart, slots), 96);
    assert_eq!(offset_of!(ObjectStart, requested), 352);
    assert_eq!(offset_of!(ObjectStart, input_statuses), 424);
    assert_eq!(offset_of!(ObjectStart, result_statuses), 426);
    assert_eq!(offset_of!(ObjectStart, flags), 428);
    assert_eq!(offset_of!(ObjectStart, get_inspected), 430);
    assert_eq!(offset_of!(ObjectStart, reserved), 431);

    assert_eq!(offset_of!(ObjectCallWire, version), 0);
    assert_eq!(offset_of!(ObjectCallWire, bytes), 2);
    assert_eq!(offset_of!(ObjectCallWire, descriptor_index), 4);
    assert_eq!(offset_of!(ObjectCallWire, flags), 8);
    assert_eq!(offset_of!(ObjectCallWire, layout), 12);
    assert_eq!(offset_of!(ObjectCallWire, action), 13);
    assert_eq!(offset_of!(ObjectCallWire, entry_derive), 14);
    assert_eq!(offset_of!(ObjectCallWire, reserved0), 15);
    assert_eq!(offset_of!(ObjectCallWire, input_handles), 16);
    assert_eq!(offset_of!(ObjectCallWire, result_handles), 32);
    assert_eq!(offset_of!(ObjectCallWire, find_handles), 48);
    assert_eq!(offset_of!(ObjectCallWire, input_status), 112);
    assert_eq!(offset_of!(ObjectCallWire, result_status), 114);
    assert_eq!(offset_of!(ObjectCallWire, find_status), 116);
    assert_eq!(offset_of!(ObjectCallWire, find_len), 124);
    assert_eq!(offset_of!(ObjectCallWire, find_flags), 125);
    assert_eq!(offset_of!(ObjectCallWire, find_valid), 126);
    assert_eq!(offset_of!(ObjectCallWire, reserved1), 127);
    assert_eq!(offset_of!(ObjectCallWire, requested), 128);
    assert_eq!(offset_of!(ObjectCallWire, result_attributes), 200);
    assert_eq!(offset_of!(ObjectCallWire, reserved2), 236);

    assert_eq!(offset_of!(ObjectEventRecord, base), 0);
    assert_eq!(offset_of!(ObjectEventRecord, object), 368);

    // Behavior below: a zeroed tail is not valid, reserved words reject.
    let descriptor = create_descriptor();
    assert!(validate_object_tail(&valid_create_tail(), &descriptor));
    assert!(!validate_object_tail(
        &[0u8; OBJECT_TAIL_BYTES],
        &descriptor
    ));
    assert!(!validate_object_tail(
        &valid_create_tail(),
        &none_object_wire()
    ));
    for offset in [15, 127, 232, 233, 234, 235, 236, 237, 238, 239] {
        let mut tail = valid_create_tail();
        tail[offset] = 1;
        assert!(!validate_object_tail(&tail, &descriptor), "offset {offset}");
    }
    for offset in [128 + 34, 128 + 35, 164 + 34, 164 + 35, 200 + 34, 200 + 35] {
        let mut tail = valid_create_tail();
        tail[offset] = 1;
        assert!(!validate_object_tail(&tail, &descriptor), "offset {offset}");
    }
    // ia32 tails reject handles with high bits; u32::MAX stays valid and
    // LP64 keeps full words.
    let mut ia32 = valid_create_tail();
    ia32[12] = OBJECT_LAYOUT_ILP32;
    assert!(validate_object_tail(&ia32, &descriptor));
    let mut ia32max = valid_create_tail();
    ia32max[12] = OBJECT_LAYOUT_ILP32;
    put_u64(&mut ia32max, 32, u64::from(u32::MAX));
    assert!(validate_object_tail(&ia32max, &descriptor));
    let mut high = valid_create_tail();
    high[12] = OBJECT_LAYOUT_ILP32;
    put_u64(&mut high, 32, 0x1_0000_1234);
    assert!(!validate_object_tail(&high, &descriptor));
}

#[test]
fn object_producer_decoder_rejects_malformed_tail() {
    let table = publish_object_descriptors();
    for len in [0, 1, 367, 369, 607, 609, 1000] {
        let bytes = [0xAAu8; 1000];
        assert_eq!(object_record_form(&bytes[..len], &table), None, "len {len}");
    }
    // Length-only dispatch for the ordinary form; base-content validation
    // stays with the existing host decoder (conjoined in slice D).
    assert_eq!(
        object_record_form(&[0u8; 368], &table),
        Some(ObjectRecordForm::Ordinary)
    );
    assert_eq!(
        object_record_form(&[0xAAu8; 368], &table),
        Some(ObjectRecordForm::Ordinary)
    );
    assert_eq!(object_record_form(&[0u8; 608], &table), None);

    let mut record = [0u8; OBJECT_RECORD_BYTES];
    record[368..].copy_from_slice(&valid_create_tail());
    assert_eq!(
        object_record_form(&record, &table),
        Some(ObjectRecordForm::Object)
    );
    // A plausible nonzero prefix never rescues a malformed tail.
    let mut prefixed = [0xAAu8; OBJECT_RECORD_BYTES];
    prefixed[368..].copy_from_slice(&[0u8; OBJECT_TAIL_BYTES]);
    assert_eq!(object_record_form(&prefixed, &table), None);

    // Unknown version/length, illegal codes, wrong descriptor row.
    for (offset, value) in [(368, 2), (368, 0), (370, 239), (370, 241), (381, 13)] {
        let mut bad = record;
        bad[offset] = value;
        assert_eq!(object_record_form(&bad, &table), None, "offset {offset}");
    }
    for index in [0u32, 20, 22, 104, 105, u32::MAX] {
        let mut bad = record;
        bad[372..376].copy_from_slice(&index.to_le_bytes());
        assert_eq!(object_record_form(&bad, &table), None, "index {index}");
    }
}

#[test]
fn object_producer_arg7_is_named_and_full_span() {
    let pair = pair_descriptor();
    let unwrap = unwrap_descriptor();
    assert_eq!(
        object_result_arg7_address(&pair, 0x1000, LinuxLayout::Lp64),
        Some(0x1010)
    );
    assert_eq!(
        object_result_arg7_address(&pair, 0x1000, LinuxLayout::Ilp32),
        Some(0x1020)
    );
    assert_eq!(
        object_result_arg7_address(&unwrap, 0x2000, LinuxLayout::Lp64),
        Some(0x2010)
    );
    // Only pair-private and unwrap name argument 7.
    let mut access = create_descriptor();
    access.action = OBJECT_ACTION_ACCESS;
    access.result_args = [7, N];
    assert_eq!(
        object_result_arg7_address(&access, 0x1000, LinuxLayout::Lp64),
        None
    );
    assert_eq!(
        object_result_arg7_address(&create_descriptor(), 0x1000, LinuxLayout::Lp64),
        None
    );
    assert_eq!(
        object_result_arg7_address(&none_object_wire(), 0x1000, LinuxLayout::Lp64),
        None
    );
    // The complete word span is checked: LP64 must not wrap, ia32 masks
    // high bits first and stays within 32 bits.
    assert_eq!(
        object_result_arg7_address(&pair, u64::MAX - 23, LinuxLayout::Lp64),
        Some(u64::MAX - 7)
    );
    assert_eq!(
        object_result_arg7_address(&pair, u64::MAX - 22, LinuxLayout::Lp64),
        None
    );
    assert_eq!(
        object_result_arg7_address(&pair, 0x1_0000_1000, LinuxLayout::Ilp32),
        Some(0x1020)
    );
    assert_eq!(
        object_result_arg7_address(&pair, 0xFFFF_FFDC, LinuxLayout::Ilp32),
        Some(0xFFFF_FFFC)
    );
    assert_eq!(
        object_result_arg7_address(&pair, 0xFFFF_FFE0, LinuxLayout::Ilp32),
        None
    );
    // The ordinary reader still refuses 7/8/9 on both layouts, so 8/9
    // have no read path (this helper takes no index by construction).
    for index in [7u8, 8, 9] {
        assert_eq!(
            crate::target_stack_arg_address(0x1000, index, LinuxLayout::Lp64),
            None
        );
        assert_eq!(
            crate::target_stack_arg_address(0x1000, index, LinuxLayout::Ilp32),
            None
        );
        assert_eq!(crate::ia32_arg_address(0x1000, u32::from(index)), None);
    }
}

#[test]
fn object_producer_start_marker_is_finite_and_required() {
    // Side-state behaviors (required-side absence, unexpected ordinary
    // side, partial insertion) extend this test in slice B with the owner
    // map; slice A pins the marker validation against the frozen table.
    let mut table = [none_object_wire(); MAX_DESCRIPTORS as usize];
    table[21] = create_descriptor();
    assert_eq!(
        validate_start_marker(0, &table),
        StartMarkerVerdict::Ordinary
    );
    assert_eq!(
        validate_start_marker(22, &table),
        StartMarkerVerdict::Required { index: 21 }
    );
    // NONE rows refuse even in range: marker 1 names index 0, marker 2
    // names the ineligible index 1, marker 105 the ineligible index 104.
    for marker in [1u64, 2, 105, 106, 255, 256, 1 << 32, u64::MAX] {
        assert_eq!(
            validate_start_marker(marker, &table),
            StartMarkerVerdict::Invalid,
            "marker {marker}"
        );
    }
    // Every reserved-bit neighbor of a valid marker refuses.
    for bit in 8..64 {
        assert_eq!(
            validate_start_marker(22 | (1 << bit), &table),
            StartMarkerVerdict::Invalid,
            "bit {bit}"
        );
        assert_eq!(
            validate_start_marker(1 << bit, &table),
            StartMarkerVerdict::Invalid,
            "lone bit {bit}"
        );
    }
}

#[test]
fn object_producer_descriptor_publication_matches_closed_catalog() {
    let table = publish_object_descriptors();
    assert!(verify_object_descriptors(&table));
    assert_eq!(table[0], none_object_wire());
    for function in 0..104u32 {
        let row = table[(function + 1) as usize];
        assert_eq!(row, canonical_object_wire(function), "function {function}");
        let eligible = crate::object_policy::object_descriptor(function).is_some();
        assert_eq!(row != none_object_wire(), eligible, "function {function}");
        if eligible {
            assert_eq!(row.function, function);
            assert_ne!(row.action, OBJECT_ACTION_NONE);
            assert_ne!(row.guard, OBJECT_GUARD_NONE);
        }
    }
    // Any disagreement refuses: tampered fields, swapped rows, blank table.
    let mut tampered = table;
    tampered[21].action = OBJECT_ACTION_COPY;
    assert!(!verify_object_descriptors(&tampered));
    let mut swapped = table;
    swapped.swap(21, 22);
    assert!(!verify_object_descriptors(&swapped));
    assert!(!verify_object_descriptors(
        &[none_object_wire(); MAX_DESCRIPTORS as usize]
    ));
}

#[test]
fn object_producer_uninspected_marker_is_honest_only() {
    const UNINSPECTED: u8 = OBJECT_ATTR_LIST_UNINSPECTED;
    assert_eq!(UNINSPECTED, 0x10);
    assert_eq!(OBJECT_ATTR_LIST_FLAGS_MASK, 0x1F);
    assert_eq!(
        crate::object_capture::attr_list_flag::UNINSPECTED,
        UNINSPECTED
    );
    let descriptor = create_descriptor();
    // The marked never-inspected shape validates on a present pair.
    let mut marked = valid_create_tail();
    marked[128 + 33] = UNINSPECTED;
    assert!(validate_object_tail(&marked, &descriptor));
    // Every dishonest combination refuses: inspected counts, inspected
    // bits, nonzero cells or reserved bytes alongside the marker.
    for (offset, value) in [
        (128 + 32, 1),
        (128 + 33, UNINSPECTED | 1),
        (128 + 33, UNINSPECTED | 8),
        (128, 1),
        (128 + 1, 1),
        (128 + 31, 1),
    ] {
        let mut bad = marked;
        bad[offset] = value;
        assert!(
            !validate_object_tail(&bad, &descriptor),
            "offset {offset} value {value}"
        );
    }
    // Reserved flag bits still refuse, with or without the marker.
    for flags in [0x20u8, 0x40, 0x80, UNINSPECTED | 0x20] {
        let mut bad = valid_create_tail();
        bad[128 + 33] = flags;
        assert!(!validate_object_tail(&bad, &descriptor), "flags {flags}");
    }
    // Inspected shapes are unchanged: inspected-empty still validates,
    // and a classified inspected cell still validates.
    assert!(validate_object_tail(&valid_create_tail(), &descriptor));
    let mut inspected = valid_create_tail();
    inspected[128] = 1;
    inspected[128 + 1] = 1;
    inspected[128 + 2] = 3;
    inspected[128 + 32] = 1;
    inspected[128 + 33] = 1;
    assert!(validate_object_tail(&inspected, &descriptor));
}
