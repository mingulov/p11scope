//! SPDX-License-Identifier: GPL-3.0-or-later
//! H8 journal wire contracts: exact BEGIN/END/ABANDON layouts, finite
//! validators, compact/full equivalence and rejection of every malformed
//! combination. Drives only the public shared wire API; the producer that
//! mints these bytes is live only in journal-selected objects.

use p11scope::kinds;
use p11scope_ebpf_common::instance;
use p11scope_ebpf_common::object_journal::{
    JOURNAL_ABANDON_BYTES, JOURNAL_BEGIN_BYTES, JOURNAL_COMMON_BYTES, JOURNAL_END_COMPACT_BYTES,
    JOURNAL_END_FULL_BYTES, JOURNAL_KIND_ABANDON, JOURNAL_KIND_BEGIN, JOURNAL_KIND_END,
    JOURNAL_REASON_EXEC_EXIT, JOURNAL_REASON_SYNC_RETURN_RESULT_LOST, JOURNAL_VERSION,
    ValidatedJournalAbandon, ValidatedJournalBegin, ValidatedJournalEnd,
};
use p11scope_ebpf_common::object_wire::{
    OBJECT_ACTION_CREATE, OBJECT_ATTR_LIST_UNINSPECTED, OBJECT_CALL_BYTES, OBJECT_CALL_VERSION,
    OBJECT_LAYOUT_LP64, canonical_object_wire,
};

const THREAD: u64 = 0x1111_2222_3333_4444;
const SEQUENCE: u64 = 0x5555_6666_7777_8888;

fn create_descriptor() -> p11scope_ebpf_common::object_wire::ObjectDescriptorWire {
    let function = kinds::function_id("C_CreateObject").expect("catalog has C_CreateObject");
    canonical_object_wire(function)
}

fn put_u16(bytes: &mut [u8], offset: usize, value: u16) {
    bytes[offset..offset + 2].copy_from_slice(&value.to_le_bytes());
}

fn put_u32(bytes: &mut [u8], offset: usize, value: u32) {
    bytes[offset..offset + 4].copy_from_slice(&value.to_le_bytes());
}

fn put_u64(bytes: &mut [u8], offset: usize, value: u64) {
    bytes[offset..offset + 8].copy_from_slice(&value.to_le_bytes());
}

fn header(bytes: &mut [u8], kind: u8, len: usize, flags: u8) {
    put_u16(bytes, 0, JOURNAL_VERSION);
    put_u16(bytes, 2, len as u16);
    bytes[4] = kind;
    bytes[5] = flags;
    put_u16(bytes, 6, 0);
    put_u64(bytes, 8, THREAD);
    put_u64(bytes, 16, SEQUENCE);
}

/// Minimal valid BEGIN: Create descriptor, one VALUE input, entry stamp
/// valid, pair0 a valid inspected-empty list, pair1 absent-zero.
fn valid_begin() -> [u8; JOURNAL_BEGIN_BYTES] {
    let descriptor_index =
        kinds::function_id("C_CreateObject").expect("catalog has C_CreateObject") + 1;
    let mut bytes = [0u8; JOURNAL_BEGIN_BYTES];
    header(&mut bytes, JOURNAL_KIND_BEGIN, JOURNAL_BEGIN_BYTES, 0);
    put_u64(&mut bytes, 24, 0xAAAA_BBBB_CCCC_DDDD); // pid_tgid
    put_u64(&mut bytes, 32, 0x1010_1010_1010_1010); // image task_cookie
    put_u64(&mut bytes, 40, 0x2020_2020_2020_2020); // image exec_id
    put_u64(&mut bytes, 48, 0x3030_3030_3030_3030); // entry_ns
    put_u64(&mut bytes, 56, 0x4040_4040_4040_4040); // entry_ip
    put_u32(&mut bytes, 64, 7); // stamp epoch
    put_u32(&mut bytes, 68, 8); // stamp global
    put_u32(&mut bytes, 72, 9); // stamp fault
    put_u16(&mut bytes, 76, 3); // file_slot_plus1
    put_u16(&mut bytes, 78, instance::STAMP_VALID);
    put_u64(&mut bytes, 80, 0x5050_5050_5050_5050); // session
    put_u64(&mut bytes, 88, 0); // inputs[0]
    put_u64(&mut bytes, 96, 0); // inputs[1]
    put_u32(&mut bytes, 104, 11); // slot
    put_u32(&mut bytes, 108, descriptor_index);
    put_u64(&mut bytes, 112, 0); // entry mechanism
    put_u32(&mut bytes, 120, 0); // capture
    bytes[124] = OBJECT_LAYOUT_LP64;
    bytes[125] = 1; // session VALUE
    bytes[126] = 0; // input0 ABSENT
    bytes[127] = 0; // input1 ABSENT
    // requested pair0: valid inspected-empty list (Create template pair0
    // present); pair1 absent-zero.
    bytes[128 + 33] = 0; // inspected
    bytes[128 + 34] = 0; // flags
    put_u64(&mut bytes, 200, 0x6060_6060_6060_6060); // slot_id
    put_u64(&mut bytes, 208, 0x7070_7070_7070_7070); // call flags
    put_u32(&mut bytes, 216, 1); // user_type
    put_u32(&mut bytes, 220, 0); // zero
    bytes
}

/// Minimal valid H7 tail for Create: VALUE result word, everything else
/// absent-zero. Mirrors the H7 validator's finite rules, not its code.
fn valid_tail() -> [u8; OBJECT_CALL_BYTES as usize] {
    let descriptor_index =
        kinds::function_id("C_CreateObject").expect("catalog has C_CreateObject") + 1;
    let mut tail = [0u8; OBJECT_CALL_BYTES as usize];
    put_u16(&mut tail, 0, OBJECT_CALL_VERSION);
    put_u16(&mut tail, 2, OBJECT_CALL_BYTES);
    put_u32(&mut tail, 4, descriptor_index);
    put_u32(&mut tail, 8, 0); // flags
    tail[12] = OBJECT_LAYOUT_LP64;
    tail[13] = OBJECT_ACTION_CREATE;
    tail[14] = 0; // entry_derive unavailable
    tail[15] = 0;
    // result[0]: Create result position present => non-absent status.
    put_u64(&mut tail, 32, 0x9090_9090_9090_9090);
    tail[114] = 1; // VALUE
    tail
}

/// Minimal valid 608-byte completed payload: CALL base + valid tail. The
/// legacy attribute span (Event bytes 120..280) stays all-zero so the
/// compact form is eligible.
fn valid_full_payload() -> [u8; 608] {
    let mut payload = [0u8; 608];
    // Event prefix: ts/duration/pid/cgroup/session/slot_id/mechanism/flags/
    // rv/p0/p1/p2/async/slot/target/user/shape then the zero attr span.
    put_u64(&mut payload, 0, 0x1111_1111_1111_1111); // ts_ns
    put_u64(&mut payload, 8, 0x2222_2222_2222_2222); // duration_ns
    put_u64(&mut payload, 16, 0xAAAA_BBBB_CCCC_DDDD); // pid_tgid
    put_u64(&mut payload, 24, 0x3333_3333_3333_3333); // cgroup_id
    put_u64(&mut payload, 32, 0x5050_5050_5050_5050); // session
    put_u64(&mut payload, 40, 0x6060_6060_6060_6060); // slot_id
    put_u64(&mut payload, 48, 0); // mechanism
    put_u64(&mut payload, 56, 0x7070_7070_7070_7070); // flags
    put_u64(&mut payload, 64, 0); // rv OK
    put_u32(&mut payload, 104, 11); // slot
    put_u32(&mut payload, 108, 0); // target_function
    put_u32(&mut payload, 112, 1); // user_type
    put_u32(&mut payload, 116, 0); // shape
    // Event bytes 120..280: the legacy attribute span, all zero here.
    put_u32(&mut payload, 280, 0); // capture
    put_u32(&mut payload, 284, p11scope_ebpf_common::event_type::CALL);
    put_u64(&mut payload, 288, 0x1010_1010_1010_1010); // image cookie
    put_u64(&mut payload, 296, 0x2020_2020_2020_2020); // image exec
    put_u64(&mut payload, 304, 0); // child cookie
    put_u64(&mut payload, 312, 0); // child exec
    put_u64(&mut payload, 320, 1); // root_affiliation positive
    // continuity 328..368: joined stamps + entry_ip.
    put_u64(&mut payload, 328, 0x4040_4040_4040_4040); // entry_ip
    put_u32(&mut payload, 336, 7);
    put_u32(&mut payload, 340, 8);
    put_u32(&mut payload, 344, 9);
    put_u16(&mut payload, 348, 3);
    put_u16(&mut payload, 350, instance::STAMP_VALID);
    put_u32(&mut payload, 352, 7);
    put_u32(&mut payload, 356, 8);
    put_u32(&mut payload, 360, 9);
    put_u16(&mut payload, 364, 3);
    put_u16(&mut payload, 366, instance::STAMP_VALID);
    payload[368..].copy_from_slice(&valid_tail());
    payload
}

fn valid_end_full() -> [u8; JOURNAL_END_FULL_BYTES] {
    let mut bytes = [0u8; JOURNAL_END_FULL_BYTES];
    header(&mut bytes, JOURNAL_KIND_END, JOURNAL_END_FULL_BYTES, 0);
    bytes[JOURNAL_COMMON_BYTES..].copy_from_slice(&valid_full_payload());
    bytes
}

#[test]
fn object_journal_wire_roundtrip_and_reject() {
    let descriptor = create_descriptor();
    // Sizes and common header shape are exact.
    assert_eq!(JOURNAL_BEGIN_BYTES, 224);
    assert_eq!(JOURNAL_END_FULL_BYTES, 632);
    assert_eq!(JOURNAL_END_COMPACT_BYTES, 472);
    assert_eq!(JOURNAL_ABANDON_BYTES, 64);
    assert_eq!(JOURNAL_COMMON_BYTES, 24);

    // Valid BEGIN round-trips every retained field.
    let begin = valid_begin();
    let valid: ValidatedJournalBegin =
        p11scope_ebpf_common::object_journal::validate_begin(&begin, Some(&descriptor))
            .expect("valid BEGIN validates");
    assert_eq!(valid.thread(), THREAD);
    assert_eq!(valid.sequence(), SEQUENCE);
    assert!(!valid.no_end());
    assert_eq!(valid.slot(), 11);
    assert_eq!(
        valid.descriptor(),
        kinds::function_id("C_CreateObject").expect("catalog") + 1
    );
    assert_eq!(valid.pid_tgid(), 0xAAAA_BBBB_CCCC_DDDD);
    assert_eq!(valid.entry_ns(), 0x3030_3030_3030_3030);
    assert_eq!(valid.bytes(), &begin);

    // BEGIN with NO_END validates and reports the commitment.
    let mut no_end = valid_begin();
    no_end[5] = 0x01;
    let valid_no_end: ValidatedJournalBegin =
        p11scope_ebpf_common::object_journal::validate_begin(&no_end, Some(&descriptor))
            .expect("NO_END BEGIN validates");
    assert!(valid_no_end.no_end());

    // Every BEGIN mutation rejects.
    let mutate = |index: usize, value: u8| {
        let mut bytes = valid_begin();
        bytes[index] = value;
        bytes
    };
    // version, length, kind, flags, reserved.
    assert!(
        p11scope_ebpf_common::object_journal::validate_begin(&mutate(0, 0), Some(&descriptor))
            .is_none()
    );
    assert!(
        p11scope_ebpf_common::object_journal::validate_begin(&mutate(0, 2), Some(&descriptor))
            .is_none()
    );
    assert!(
        p11scope_ebpf_common::object_journal::validate_begin(&mutate(2, 223), Some(&descriptor))
            .is_none()
    );
    assert!(
        p11scope_ebpf_common::object_journal::validate_begin(&mutate(4, 0), Some(&descriptor))
            .is_none()
    );
    assert!(
        p11scope_ebpf_common::object_journal::validate_begin(&mutate(4, 2), Some(&descriptor))
            .is_none()
    );
    assert!(
        p11scope_ebpf_common::object_journal::validate_begin(&mutate(5, 0x02), Some(&descriptor))
            .is_none()
    );
    assert!(
        p11scope_ebpf_common::object_journal::validate_begin(&mutate(6, 1), Some(&descriptor))
            .is_none()
    );
    // zero thread or sequence.
    let mut zero_thread = valid_begin();
    zero_thread[8..16].fill(0);
    assert!(
        p11scope_ebpf_common::object_journal::validate_begin(&zero_thread, Some(&descriptor))
            .is_none()
    );
    let mut zero_seq = valid_begin();
    zero_seq[16..24].fill(0);
    assert!(
        p11scope_ebpf_common::object_journal::validate_begin(&zero_seq, Some(&descriptor))
            .is_none()
    );
    // layout, statuses, descriptor, stamp, lists, padding, truncation.
    assert!(
        p11scope_ebpf_common::object_journal::validate_begin(&mutate(124, 0), Some(&descriptor))
            .is_none()
    );
    assert!(
        p11scope_ebpf_common::object_journal::validate_begin(&mutate(124, 3), Some(&descriptor))
            .is_none()
    );
    assert!(
        p11scope_ebpf_common::object_journal::validate_begin(&mutate(125, 10), Some(&descriptor))
            .is_none()
    );
    assert!(
        p11scope_ebpf_common::object_journal::validate_begin(&mutate(126, 10), Some(&descriptor))
            .is_none()
    );
    // VALUE status with a zero word rejects (H7 handle rule).
    let mut zero_value = valid_begin();
    zero_value[80..88].fill(0);
    assert!(
        p11scope_ebpf_common::object_journal::validate_begin(&zero_value, Some(&descriptor))
            .is_none()
    );
    // descriptor zero or out of range.
    let mut desc_zero = valid_begin();
    desc_zero[108..112].fill(0);
    assert!(
        p11scope_ebpf_common::object_journal::validate_begin(&desc_zero, Some(&descriptor))
            .is_none()
    );
    // entry stamp must be VALID with known bits only.
    let mut stamp_clear = valid_begin();
    stamp_clear[78..80].fill(0);
    assert!(
        p11scope_ebpf_common::object_journal::validate_begin(&stamp_clear, Some(&descriptor))
            .is_none()
    );
    let mut stamp_wide = valid_begin();
    stamp_wide[79] = 0xFF;
    assert!(
        p11scope_ebpf_common::object_journal::validate_begin(&stamp_wide, Some(&descriptor))
            .is_none()
    );
    // absent pair must stay all-zero; present pair must be a valid list.
    let mut pair1 = valid_begin();
    pair1[164] = 1;
    assert!(
        p11scope_ebpf_common::object_journal::validate_begin(&pair1, Some(&descriptor)).is_none()
    );
    let mut inspected = valid_begin();
    inspected[128 + 32] = 9;
    assert!(
        p11scope_ebpf_common::object_journal::validate_begin(&inspected, Some(&descriptor))
            .is_none()
    );
    // trailing reserved must be zero; short/long buffers reject.
    assert!(
        p11scope_ebpf_common::object_journal::validate_begin(&mutate(220, 1), Some(&descriptor))
            .is_none()
    );
    assert!(
        p11scope_ebpf_common::object_journal::validate_begin(
            &valid_begin()[..JOURNAL_BEGIN_BYTES - 1],
            Some(&descriptor)
        )
        .is_none()
    );
    let mut long = valid_begin().to_vec();
    long.push(0);
    assert!(
        p11scope_ebpf_common::object_journal::validate_begin(&long, Some(&descriptor)).is_none()
    );
    // wrong descriptor row rejects an otherwise valid BEGIN.
    let destroy = {
        let function = kinds::function_id("C_DestroyObject").expect("catalog");
        canonical_object_wire(function)
    };
    assert!(
        p11scope_ebpf_common::object_journal::validate_begin(&valid_begin(), Some(&destroy))
            .is_none()
    );
    // Lifecycle/neutral BEGINs (no object row) require a known non-object
    // descriptor and all-zero requested lists.
    let neutral = valid_neutral_begin();
    assert!(
        p11scope_ebpf_common::object_journal::validate_begin(&neutral, None).is_some(),
        "neutral BEGIN validates on the no-row path"
    );
    assert!(
        p11scope_ebpf_common::object_journal::validate_begin(&neutral, Some(&descriptor)).is_none(),
        "neutral BEGIN rejects an object row"
    );
    assert!(
        p11scope_ebpf_common::object_journal::validate_begin(&valid_begin(), None).is_none(),
        "object BEGIN rejects the no-row path"
    );
    let mut zero_lists = valid_begin();
    zero_lists[128..200].fill(0);
    assert!(
        p11scope_ebpf_common::object_journal::validate_begin(&zero_lists, None).is_none(),
        "zero lists do not admit an object descriptor on the no-row path"
    );
    let mut neutral_dirty = neutral;
    neutral_dirty[128] = 1;
    assert!(
        p11scope_ebpf_common::object_journal::validate_begin(&neutral_dirty, None).is_none(),
        "neutral BEGIN rejects nonzero requested lists"
    );
    // Out-of-range descriptor ordinals reject on both paths.
    let mut unknown = valid_begin();
    put_u32(&mut unknown, 108, 105);
    assert!(
        p11scope_ebpf_common::object_journal::validate_begin(&unknown, Some(&descriptor)).is_none()
    );
    assert!(p11scope_ebpf_common::object_journal::validate_begin(&unknown, None).is_none());

    // Valid full END round-trips and reconstructs its payload exactly.
    let end = valid_end_full();
    let valid_end: ValidatedJournalEnd =
        p11scope_ebpf_common::object_journal::validate_end(&end, Some(&descriptor))
            .expect("valid END validates");
    assert_eq!(valid_end.thread(), THREAD);
    assert_eq!(valid_end.sequence(), SEQUENCE);
    assert!(!valid_end.compact());
    assert!(!valid_end.tail_absent());
    assert_eq!(valid_end.payload_bytes(), valid_full_payload());

    // Every END mutation rejects.
    let mutate_end = |index: usize, value: u8| {
        let mut bytes = valid_end_full();
        bytes[index] = value;
        bytes
    };
    assert!(
        p11scope_ebpf_common::object_journal::validate_end(&mutate_end(4, 1), Some(&descriptor))
            .is_none()
    );
    assert!(
        p11scope_ebpf_common::object_journal::validate_end(&mutate_end(5, 0x01), Some(&descriptor))
            .is_none()
    );
    assert!(
        p11scope_ebpf_common::object_journal::validate_end(&mutate_end(5, 0x04), Some(&descriptor))
            .is_none()
    );
    // event_type must be CALL; root_affiliation at most 1.
    let mut not_call = valid_end_full();
    not_call[24 + 284] = 1;
    assert!(
        p11scope_ebpf_common::object_journal::validate_end(&not_call, Some(&descriptor)).is_none()
    );
    let mut affiliation = valid_end_full();
    affiliation[24 + 320] = 2;
    assert!(
        p11scope_ebpf_common::object_journal::validate_end(&affiliation, Some(&descriptor))
            .is_none()
    );
    // corrupt tail rejects even with a valid base.
    let mut tail_bad = valid_end_full();
    tail_bad[24 + 368 + 13] = 99;
    assert!(
        p11scope_ebpf_common::object_journal::validate_end(&tail_bad, Some(&descriptor)).is_none()
    );

    // Absent-tail END: only with no object row, the bit set and 240 zero bytes.
    let mut absent = valid_end_full();
    absent[5] = 0x02;
    absent[24 + 368..].fill(0);
    let valid_absent: ValidatedJournalEnd =
        p11scope_ebpf_common::object_journal::validate_end(&absent, None)
            .expect("absent-tail END validates without a row");
    assert!(valid_absent.tail_absent());
    assert!(
        p11scope_ebpf_common::object_journal::validate_end(&absent, Some(&descriptor)).is_none()
    );
    let mut absent_dirty = absent;
    absent_dirty[24 + 368] = 1;
    assert!(p11scope_ebpf_common::object_journal::validate_end(&absent_dirty, None).is_none());
    let mut absent_nobit = absent;
    absent_nobit[5] = 0;
    assert!(p11scope_ebpf_common::object_journal::validate_end(&absent_nobit, None).is_none());
    assert!(p11scope_ebpf_common::object_journal::validate_end(&valid_end_full(), None).is_none());

    // Compact END: eligible payload reconstructs byte-for-byte.
    let payload = valid_full_payload();
    assert!(p11scope_ebpf_common::object_journal::end_compact_eligible(
        &payload
    ));
    let compact =
        p11scope_ebpf_common::object_journal::pack_compact_end(THREAD, SEQUENCE, 0, &payload)
            .expect("eligible payload packs");
    assert_eq!(compact.len(), JOURNAL_END_COMPACT_BYTES);
    let valid_compact: ValidatedJournalEnd =
        p11scope_ebpf_common::object_journal::validate_end(&compact, Some(&descriptor))
            .expect("compact END validates");
    assert!(valid_compact.compact());
    assert_eq!(valid_compact.payload_bytes(), payload);
    // nonzero legacy attributes force the full form: eligibility refuses.
    let mut dirty = payload;
    dirty[120] = 1;
    assert!(!p11scope_ebpf_common::object_journal::end_compact_eligible(
        &dirty
    ));
    assert!(
        p11scope_ebpf_common::object_journal::pack_compact_end(THREAD, SEQUENCE, 0, &dirty)
            .is_none()
    );
    let mut dirty_last = payload;
    dirty_last[279] = 1;
    assert!(!p11scope_ebpf_common::object_journal::end_compact_eligible(
        &dirty_last
    ));
    // compact length/kind mutations reject.
    assert!(
        p11scope_ebpf_common::object_journal::validate_end(
            &compact[..JOURNAL_END_COMPACT_BYTES - 1],
            Some(&descriptor)
        )
        .is_none()
    );

    // ABANDON: every finite reason validates; anything else rejects.
    let mut abandon = [0u8; JOURNAL_ABANDON_BYTES];
    header(&mut abandon, JOURNAL_KIND_ABANDON, JOURNAL_ABANDON_BYTES, 0);
    put_u64(&mut abandon, 24, 0xAAAA_BBBB_CCCC_DDDD);
    put_u64(&mut abandon, 32, 0x1010_1010_1010_1010);
    put_u64(&mut abandon, 40, 0x2020_2020_2020_2020);
    put_u32(&mut abandon, 48, 11);
    put_u32(&mut abandon, 52, JOURNAL_REASON_EXEC_EXIT);
    put_u64(&mut abandon, 56, 0x3030_3030_3030_3030);
    let valid_abandon: ValidatedJournalAbandon =
        p11scope_ebpf_common::object_journal::validate_abandon(&abandon)
            .expect("valid ABANDON validates");
    assert_eq!(valid_abandon.thread(), THREAD);
    assert_eq!(valid_abandon.sequence(), SEQUENCE);
    assert_eq!(valid_abandon.reason(), JOURNAL_REASON_EXEC_EXIT);
    assert_eq!(valid_abandon.slot(), 11);
    for reason in 1..=9u32 {
        let mut bytes = abandon;
        put_u32(&mut bytes, 52, reason);
        assert!(
            p11scope_ebpf_common::object_journal::validate_abandon(&bytes).is_some(),
            "reason {reason} validates"
        );
        assert_eq!(
            p11scope_ebpf_common::object_journal::reason_name(reason),
            match reason {
                1 => Some("entry-collision"),
                2 => Some("insert-failed"),
                3 => Some("scope-lost"),
                4 => Some("abi-refused"),
                5 => Some("identity-refused"),
                6 => Some("exec-exit"),
                7 => Some("stop-cleanup"),
                8 => Some("partial-transaction"),
                _ => Some("sync-return-result-lost"),
            }
        );
    }
    assert_eq!(
        JOURNAL_REASON_SYNC_RETURN_RESULT_LOST, 9,
        "bounded-witness reason keeps its frozen code"
    );
    for reason in [0u32, 10, 99, u32::MAX] {
        let mut bytes = abandon;
        put_u32(&mut bytes, 52, reason);
        assert!(
            p11scope_ebpf_common::object_journal::validate_abandon(&bytes).is_none(),
            "reason {reason} rejects"
        );
    }
    let mutate_abandon = |index: usize, value: u8| {
        let mut bytes = abandon;
        bytes[index] = value;
        bytes
    };
    assert!(
        p11scope_ebpf_common::object_journal::validate_abandon(&mutate_abandon(4, 1)).is_none()
    );
    assert!(
        p11scope_ebpf_common::object_journal::validate_abandon(&mutate_abandon(5, 1)).is_none()
    );
    assert!(
        p11scope_ebpf_common::object_journal::validate_abandon(
            &abandon[..JOURNAL_ABANDON_BYTES - 1]
        )
        .is_none()
    );

    // Wrong-kind combinations reject: BEGIN bytes are not an END, an END is
    // not an ABANDON, and journal bytes are not an H7 tail.
    assert!(
        p11scope_ebpf_common::object_journal::validate_end(&valid_begin(), Some(&descriptor))
            .is_none()
    );
    assert!(p11scope_ebpf_common::object_journal::validate_abandon(&valid_end_full()).is_none());
    assert!(
        p11scope_ebpf_common::object_journal::validate_begin(&abandon, Some(&descriptor)).is_none()
    );
    // Decoding is idempotent: the same bytes validate to equal values.
    let again: ValidatedJournalBegin =
        p11scope_ebpf_common::object_journal::validate_begin(&begin, Some(&descriptor))
            .expect("second decode validates");
    assert_eq!(again.bytes(), valid.bytes());
    let _ = OBJECT_ATTR_LIST_UNINSPECTED;
}

#[test]
fn object_journal_decode_dispatches_forms() {
    use p11scope_ebpf_common::object_journal::{
        JOURNAL_END_TAIL_ABSENT, JournalRecord, decode_journal_record,
    };
    use p11scope_ebpf_common::object_wire::{
        OBJECT_ACTION_DESTROY, publish_object_descriptors, verify_object_descriptors,
    };

    let descriptors = publish_object_descriptors();
    assert!(verify_object_descriptors(&descriptors));
    let decode = |bytes: &[u8]| decode_journal_record(bytes, &descriptors);

    // Each wire form decodes to its variant, including the no-row paths.
    assert!(matches!(
        decode(&valid_begin()),
        Some(JournalRecord::Begin(_))
    ));
    assert!(matches!(
        decode(&valid_neutral_begin()),
        Some(JournalRecord::Begin(_))
    ));
    assert!(matches!(
        decode(&valid_end_full()),
        Some(JournalRecord::End(_))
    ));
    let mut absent = valid_end_full();
    absent[5] = JOURNAL_END_TAIL_ABSENT;
    absent[24 + 368..].fill(0);
    assert!(matches!(decode(&absent), Some(JournalRecord::End(_))));
    let payload = valid_full_payload();
    let compact =
        p11scope_ebpf_common::object_journal::pack_compact_end(THREAD, SEQUENCE, 0, &payload)
            .expect("eligible payload packs");
    assert!(matches!(decode(&compact), Some(JournalRecord::End(_))));
    let mut abandon = [0u8; JOURNAL_ABANDON_BYTES];
    header(&mut abandon, JOURNAL_KIND_ABANDON, JOURNAL_ABANDON_BYTES, 0);
    put_u64(&mut abandon, 24, 0xAAAA_BBBB_CCCC_DDDD);
    put_u64(&mut abandon, 32, 0x1010_1010_1010_1010);
    put_u64(&mut abandon, 40, 0x2020_2020_2020_2020);
    put_u32(&mut abandon, 48, 11);
    put_u32(&mut abandon, 52, 1);
    put_u64(&mut abandon, 56, 0x3030_3030_3030_3030);
    assert!(matches!(decode(&abandon), Some(JournalRecord::Abandon(_))));

    // Ordinary and unknown lengths are not journal records.
    assert!(decode(&[0u8; 368]).is_none());
    assert!(decode(&[0u8; 608]).is_none());
    assert!(decode(&[0u8; 100]).is_none());
    assert!(decode(&[]).is_none());

    // The compact tail-index selection reads the real tail: corrupting
    // the tail index or action inside a compact END refuses decode.
    let mut bad_index = compact;
    bad_index[236] ^= 0xFF;
    assert!(decode(&bad_index).is_none());
    let mut bad_action = compact;
    bad_action[232 + 13] = OBJECT_ACTION_DESTROY;
    assert!(decode(&bad_action).is_none());
}

#[test]
fn object_journal_unjournaled_identity_is_disjoint() {
    use p11scope_ebpf_common::object_journal::{
        JOURNAL_END_TAIL_ABSENT, JOURNAL_END_UNJOURNALED, JournalRecord, decode_journal_record,
        pack_compact_end,
    };
    use p11scope_ebpf_common::object_wire::publish_object_descriptors;

    let rows = publish_object_descriptors();
    for absent in [false, true] {
        let mut tracked = valid_end_full();
        if absent {
            tracked[5] = JOURNAL_END_TAIL_ABSENT;
            tracked[24 + 368..].fill(0);
        }
        let expected = &tracked[24..];
        for compact in [false, true] {
            let wire = if compact {
                pack_compact_end(THREAD, SEQUENCE, tracked[5], expected)
                    .unwrap()
                    .to_vec()
            } else {
                tracked.to_vec()
            };
            let Some(JournalRecord::End(end)) = decode_journal_record(&wire, &rows) else {
                panic!("tracked END remains valid")
            };
            assert!(!end.unjournaled());
            assert_eq!((end.thread(), end.sequence()), (THREAD, SEQUENCE));
            assert_eq!(end.payload_bytes().as_slice(), expected);

            let mut unjournaled = wire.clone();
            unjournaled[5] |= JOURNAL_END_UNJOURNALED;
            unjournaled[8..24].fill(0);
            let Some(JournalRecord::End(end)) = decode_journal_record(&unjournaled, &rows) else {
                panic!("only the flagged END can carry the zero key")
            };
            assert!(end.unjournaled());
            assert_eq!((end.thread(), end.sequence()), (0, 0));
            assert_eq!(end.payload_bytes().as_slice(), expected);
            assert_eq!(end.tail_absent(), absent);
            assert_eq!(end.compact(), compact);

            for (thread, sequence) in [(0, 0), (THREAD, 0), (0, SEQUENCE)] {
                let mut bad = wire.clone();
                put_u64(&mut bad, 8, thread);
                put_u64(&mut bad, 16, sequence);
                assert!(decode_journal_record(&bad, &rows).is_none());
            }
            for (thread, sequence) in [(THREAD, 0), (0, SEQUENCE), (THREAD, SEQUENCE)] {
                let mut bad = unjournaled.clone();
                put_u64(&mut bad, 8, thread);
                put_u64(&mut bad, 16, sequence);
                assert!(decode_journal_record(&bad, &rows).is_none());
            }
            for bit in [0x01, 0x08, 0x80] {
                let mut bad = unjournaled.clone();
                bad[5] |= bit;
                assert!(decode_journal_record(&bad, &rows).is_none());
            }
            let mut reserved = unjournaled;
            reserved[6] = 1;
            assert!(decode_journal_record(&reserved, &rows).is_none());
        }

        let packed = pack_compact_end(0, 0, tracked[5] | JOURNAL_END_UNJOURNALED, expected)
            .expect("the compact packer uses the same flag/key relation");
        assert!(decode_journal_record(&packed, &rows).is_some());
        for (thread, sequence, flags) in [
            (0, 0, tracked[5]),
            (THREAD, 0, tracked[5]),
            (0, SEQUENCE, tracked[5]),
            (THREAD, SEQUENCE, tracked[5] | JOURNAL_END_UNJOURNALED),
            (THREAD, 0, tracked[5] | JOURNAL_END_UNJOURNALED),
            (0, SEQUENCE, tracked[5] | JOURNAL_END_UNJOURNALED),
            (0, 0, tracked[5] | JOURNAL_END_UNJOURNALED | 0x08),
        ] {
            assert!(pack_compact_end(thread, sequence, flags, expected).is_none());
        }
    }

    let mut begin = valid_begin();
    begin[5] |= JOURNAL_END_UNJOURNALED;
    assert!(decode_journal_record(&begin, &rows).is_none());
    let mut abandon = [0u8; JOURNAL_ABANDON_BYTES];
    header(&mut abandon, JOURNAL_KIND_ABANDON, JOURNAL_ABANDON_BYTES, 0);
    put_u32(&mut abandon, 52, 1);
    assert!(decode_journal_record(&abandon, &rows).is_some());
    abandon[5] = JOURNAL_END_UNJOURNALED;
    assert!(decode_journal_record(&abandon, &rows).is_none());
}

/// Minimal valid neutral BEGIN: C_Sign descriptor on the no-row path with
/// all-zero requested lists and a VALUE session.
fn valid_neutral_begin() -> [u8; JOURNAL_BEGIN_BYTES] {
    let mut bytes = valid_begin();
    let sign = kinds::function_id("C_Sign").expect("catalog has C_Sign") + 1;
    put_u32(&mut bytes, 108, sign);
    bytes[128..200].fill(0);
    bytes
}

#[test]
fn object_journal_ilp32_abi_layout() {
    use p11scope_ebpf_common::object_journal::{validate_begin, validate_end};
    use p11scope_ebpf_common::object_wire::OBJECT_LAYOUT_ILP32;

    let descriptor = create_descriptor();
    // A 32-bit BEGIN with narrow handle words validates.
    let mut ilp32 = valid_begin();
    ilp32[124] = OBJECT_LAYOUT_ILP32;
    put_u64(&mut ilp32, 80, 0x5050_5050);
    assert!(validate_begin(&ilp32, Some(&descriptor)).is_some());
    // High bits on any handle word reject under ilp32.
    let mut wide_session = ilp32;
    put_u64(&mut wide_session, 80, 0x1_0000_0000);
    assert!(validate_begin(&wide_session, Some(&descriptor)).is_none());
    let mut wide_input = ilp32;
    put_u64(&mut wide_input, 88, 0x1_0000_0000);
    wide_input[126] = 1;
    assert!(validate_begin(&wide_input, Some(&descriptor)).is_none());
    let mut narrow_input = ilp32;
    put_u64(&mut narrow_input, 88, 0x1111_1111);
    narrow_input[126] = 1;
    assert!(validate_begin(&narrow_input, Some(&descriptor)).is_some());
    // The 32-bit END tail enforces the same width rule on result words.
    let mut end = valid_end_full();
    end[JOURNAL_COMMON_BYTES + 368 + 12] = OBJECT_LAYOUT_ILP32;
    put_u64(&mut end, JOURNAL_COMMON_BYTES + 368 + 32, 0x9090_9090);
    assert!(validate_end(&end, Some(&descriptor)).is_some());
    put_u64(
        &mut end,
        JOURNAL_COMMON_BYTES + 368 + 32,
        0x9090_9090_9090_9090,
    );
    assert!(validate_end(&end, Some(&descriptor)).is_none());
}

/// Journal custody: the native lifetime words, JOURNAL_START
/// side-map and ring-leaf skeleton compile for every object flavor and
/// the actual native-owner fixture passes unprivileged. The producer
/// that calls this is live only in journal-selected objects; this host
/// fixture enables no production define or BPF load.
#[test]
fn object_journal_physical_thread_identity() {
    use std::process::Command;

    let temporary = tempfile::tempdir().expect("native journal test directory");
    let matrix: &[(&str, &[&str])] = &[
        ("default", &[]),
        ("small", &["-DP11SCOPE_SMALL_STATE_MAPS"]),
        ("wide", &["-DP11SCOPE_OWNER_SLOT_BOUND=2112"]),
        ("inventory", &["-DP11SCOPE_INVENTORY_ONLY"]),
        (
            "small-inventory",
            &["-DP11SCOPE_SMALL_STATE_MAPS", "-DP11SCOPE_INVENTORY_ONLY"],
        ),
    ];
    for (name, defines) in matrix {
        let binary = temporary.path().join(format!("journal-owner-{name}"));
        let mut compiler = Command::new("clang-18");
        compiler
            .args([
                "-O2",
                "-g",
                "-Wall",
                "-Wextra",
                "-Werror",
                "-pthread",
                "-I",
                "crates/ebpf/native",
                "tests/fixtures/object-journal/journal_owner_tests.c",
                "-o",
            ])
            .arg(&binary)
            .args(*defines);
        let output = compiler.output().expect("execute clang-18");
        assert!(
            output.status.success(),
            "native compile [{name}]: {}",
            String::from_utf8_lossy(&output.stderr)
        );
        let output = Command::new(binary)
            .output()
            .expect("execute native journal test");
        assert!(
            output.status.success(),
            "native journal test [{name}]: {}",
            String::from_utf8_lossy(&output.stderr)
        );
    }
}

/// C4: every record the combined transactions submit is a VALID wire
/// transaction — the existing validators (the oracle) accept each one.
/// The fixture dumps its submitted records; this test decodes all of
/// them, pins the per-kind counts (no missing or extra dispositions)
/// and the first BEGIN's framed identity.
#[test]
fn object_journal_combined_transactions_publish_valid_wire_records() {
    use p11scope_ebpf_common::object_journal::{JournalRecord, decode_journal_record};
    use p11scope_ebpf_common::object_wire::{
        publish_object_descriptors, verify_object_descriptors,
    };
    use std::process::Command;

    let temporary = tempfile::tempdir().expect("native journal dump directory");
    let binary = temporary.path().join("journal-owner-dump");
    let dump = temporary.path().join("dump");
    std::fs::create_dir(&dump).expect("create dump directory");
    let mut compiler = Command::new("clang-18");
    compiler
        .args([
            "-O2",
            "-g",
            "-Wall",
            "-Wextra",
            "-Werror",
            "-pthread",
            "-I",
            "crates/ebpf/native",
            "tests/fixtures/object-journal/journal_owner_tests.c",
            "-o",
        ])
        .arg(&binary);
    let output = compiler.output().expect("execute clang-18");
    assert!(
        output.status.success(),
        "native compile [dump]: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    let output = Command::new(&binary)
        .env("P11_JOURNAL_DUMP_DIR", &dump)
        .output()
        .expect("execute native journal test");
    // The dump carries the verdict here (exit status is pinned by the
    // physical-thread-identity test): every submitted record must
    // decode, whatever the fixture's own asserts say.
    let _ = output.status;
    let descriptors = publish_object_descriptors();
    assert!(verify_object_descriptors(&descriptors));
    let mut files: Vec<_> = std::fs::read_dir(&dump)
        .expect("read dump directory")
        .map(|entry| entry.expect("dump entry").path())
        .collect();
    files.sort();
    let mut begins = 0;
    let mut ends = 0;
    let mut compacts = 0;
    let mut abandons = 0;
    for (index, path) in files.iter().enumerate() {
        let bytes = std::fs::read(path).expect("read dumped record");
        let record = decode_journal_record(&bytes, &descriptors);
        assert!(
            record.is_some(),
            "record {index} ({} bytes) validates",
            bytes.len()
        );
        match record {
            Some(JournalRecord::Begin(begin)) => {
                begins += 1;
                if index == 0 {
                    assert_eq!(begin.thread(), 1);
                    assert_eq!(begin.sequence(), 1);
                    assert_eq!(begin.descriptor(), 21);
                    assert_eq!(begin.slot(), 5);
                }
            }
            Some(JournalRecord::End(end)) => {
                ends += 1;
                if end.compact() {
                    compacts += 1;
                }
            }
            Some(JournalRecord::Abandon(abandon)) => {
                abandons += 1;
                assert_eq!(abandon.reason(), 6, "cleanup abandonment reason");
            }
            None => unreachable!(),
        }
    }
    assert_eq!(files.len(), 24, "dumped record count");
    assert_eq!(begins, 17, "BEGIN count");
    assert_eq!(ends, 4, "END count");
    assert_eq!(compacts, 1, "compact END count");
    assert_eq!(abandons, 3, "ABANDON count");
}

/// P1 executes the real journal-selected native globals. No production
/// define, BPF load or live authority is enabled by this host fixture.
#[test]
fn object_journal_native_producer_preserves_wire_and_custody() {
    use p11scope_ebpf_common::object_journal::{JournalRecord, decode_journal_record};
    use p11scope_ebpf_common::object_wire::publish_object_descriptors;
    use std::process::Command;
    let work = tempfile::tempdir().expect("native producer fixture");
    for (name, defines) in [
        ("default", vec![]),
        ("small", vec!["-DP11SCOPE_SMALL_STATE_MAPS"]),
        ("wide", vec!["-DP11SCOPE_OWNER_SLOT_BOUND=2112U"]),
    ] {
        let executable = work.path().join(name);
        let output = Command::new("clang-18")
            .args([
                "-O2",
                "-g",
                "-Wall",
                "-Wextra",
                "-Werror",
                "-pthread",
                "-DP11SCOPE_OBJECT_JOURNAL",
                "-I",
                "crates/ebpf/native",
                "tests/fixtures/object-journal/journal_owner_tests.c",
                "-o",
            ])
            .arg(&executable)
            .args(defines)
            .output()
            .expect("compile producer fixture");
        assert!(
            output.status.success(),
            "{name}: {}",
            String::from_utf8_lossy(&output.stderr)
        );
        let dump = work.path().join(format!("dump-{name}"));
        std::fs::create_dir(&dump).unwrap();
        let output = Command::new(executable)
            .arg("producer")
            .env("P11_JOURNAL_PRODUCER_DUMP_DIR", &dump)
            .output()
            .expect("run producer fixture");
        assert!(
            output.status.success(),
            "{name}: {}",
            String::from_utf8_lossy(&output.stderr)
        );
        let descriptors = publish_object_descriptors();
        let mut counts = [0usize; 3];
        for entry in std::fs::read_dir(&dump).unwrap() {
            let path = entry.unwrap().path();
            let bytes = std::fs::read(&path).unwrap();
            let record = decode_journal_record(&bytes, &descriptors).unwrap_or_else(|| {
                panic!(
                    "{name}: {} ({} bytes) does not validate",
                    path.display(),
                    bytes.len()
                )
            });
            counts[match record {
                JournalRecord::Begin(_) => 0,
                JournalRecord::End(_) => 1,
                JournalRecord::Abandon(_) => 2,
            }] += 1;
        }
        // The small flavor's one-entry side map admits one fewer live
        // BEGIN (and its cleanup ABANDON) in the multi-slot cleanup case.
        // The two single-slot stop-gate sections run only through the
        // FFI batteries (production admission verdicts need the Rust
        // driver), so this battery carries no closed-gate BEGIN and no
        // open-gate BEGIN/ABANDON pair.
        let expected = if name == "small" {
            [33, 1, 20]
        } else {
            [34, 1, 21]
        };
        assert_eq!(counts, expected, "exact producer record selection");
    }
    assert_eq!(
        std::mem::size_of::<p11scope_ebpf_common::SlotSemantics>(),
        18
    );
    assert_eq!(
        std::mem::offset_of!(p11scope_ebpf_common::SlotSemantics, session_arg),
        6
    );
    assert_eq!(
        std::mem::size_of::<p11scope_ebpf_common::InstanceEntry>(),
        24
    );
    assert_eq!(
        std::mem::offset_of!(p11scope_ebpf_common::InstanceEntry, entry_stamp),
        8
    );
    use p11scope_ebpf_common::CallStart;
    assert_eq!(std::mem::size_of::<CallStart>(), 288);
    assert_eq!(
        [
            std::mem::offset_of!(CallStart, ts_ns),
            std::mem::offset_of!(CallStart, session),
            std::mem::offset_of!(CallStart, slot_id),
            std::mem::offset_of!(CallStart, mechanism),
            std::mem::offset_of!(CallStart, flags),
            std::mem::offset_of!(CallStart, user_type),
            std::mem::offset_of!(CallStart, capture),
            std::mem::offset_of!(CallStart, object_required),
            std::mem::offset_of!(CallStart, image),
        ],
        [0, 8, 16, 24, 40, 56, 256, 264, 272],
        "actual retained START words copied by the native producer"
    );
    let source = include_str!("../crates/ebpf/native/object_journal.c");
    for forbidden in [
        "probe_read",
        "core_read",
        "preserve_access_index",
        "get_current_task",
        "get_current_pid_tgid",
        "ktime_get_ns",
    ] {
        assert!(!source.contains(forbidden), "new target read: {forbidden}");
    }
}

/// N4: the journal unit's BPF-subprogram call shape is covered, not
/// just its host behavior. The real pipeline compiles native units
/// with `-emit-llvm` (no backend), which cannot see the BPF
/// five-scalar-argument limit — a six-argument noinline leaf passed
/// both the real build and the host suite. Full backend codegen per
/// object flavor fails such leaves here instead. task_owner.c stays
/// out: its standalone backend stack estimate is stricter than the
/// real -emit-llvm pipeline it ships through (pre-existing,
/// unrelated to this restriction).
#[test]
fn object_journal_bpf_call_shape() {
    use std::process::Command;

    let temporary = tempfile::tempdir().expect("native BPF shape directory");
    let matrix: &[(&str, &[&str])] = &[
        ("default", &[]),
        ("small", &["-DP11SCOPE_SMALL_STATE_MAPS"]),
        ("wide", &["-DP11SCOPE_OWNER_SLOT_BOUND=2112"]),
        ("inventory", &["-DP11SCOPE_INVENTORY_ONLY"]),
        (
            "small-inventory",
            &["-DP11SCOPE_SMALL_STATE_MAPS", "-DP11SCOPE_INVENTORY_ONLY"],
        ),
    ];
    for (name, defines) in matrix {
        let object = temporary.path().join(format!("object-journal-{name}.o"));
        let mut compiler = Command::new("clang-18");
        compiler
            .args([
                "-target",
                "bpf",
                "-O2",
                "-Wall",
                "-Wextra",
                "-Werror",
                "-c",
                "-I",
                "crates/ebpf/native",
                "crates/ebpf/native/object_journal.c",
                "-o",
            ])
            .arg(&object)
            .args(*defines);
        let output = compiler.output().expect("execute clang-18");
        assert!(
            output.status.success(),
            "native BPF codegen [{name}]: {}",
            String::from_utf8_lossy(&output.stderr)
        );
    }
}

/// N8/C4/N9: the reserve/fault/cleanup/submit matrix is pinned by
/// ORDERING, not names. Combined transactions and their helpers never
/// discard. The historical root handles uncommitted reservations; the new
/// outer P1 BEGIN handles its own reservation after raising gap/loss,
/// checked by the fixture's discard callback. Each combined transaction reports
/// its fault cell BEFORE handing its uncommitted reservation back;
/// terminals submit only after their required cleanup commits; and
/// each operation accepts only its own publication kind.
#[test]
fn object_journal_transaction_ordering_matrix() {
    let source = std::fs::read_to_string("crates/ebpf/native/object_journal.c")
        .expect("read native journal transactions");
    let lines: Vec<&str> = source.lines().collect();
    // This file opens every function body with a lone `{` (control-flow
    // braces stay same-line): the nearest signature above a lone `{`
    // names the enclosing function.
    let mut current = String::from("none");
    let mut functions: std::collections::HashMap<String, Vec<(usize, &str)>> =
        std::collections::HashMap::new();
    for (index, line) in lines.iter().enumerate() {
        if line.trim() == "{" {
            for candidate in lines[..index].iter().rev() {
                if let Some(paren) = candidate.rfind('(') {
                    let before = candidate[..paren].trim_end();
                    if let Some(name) = before
                        .split(|c: char| !c.is_alphanumeric() && c != '_')
                        .next_back()
                    {
                        current = name.to_string();
                    }
                    break;
                }
            }
            continue;
        }
        functions
            .entry(current.clone())
            .or_default()
            .push((index + 1, line.trim_start()));
    }
    // N8: only the ring delegation and the new outer P1 BEGIN may discard.
    // Combined transactions and their helpers still return reservations.
    for (name, body) in &functions {
        for (number, text) in body {
            if !(text.starts_with("p11_journal_discard(")
                || text.starts_with("journal_ring_discard("))
            {
                continue;
            }
            assert!(
                name == "p11_journal_discard" || name == "p11_journal_begin",
                "discard site in {name} (line {number}): combined transactions never discard",
            );
        }
    }
    for operation in [
        "p11_journal_combined_entry",
        "p11_journal_combined_return",
        "p11_journal_combined_remove",
    ] {
        let body = functions.get(operation).expect("combined body present");
        // N8: the fault cell reports BEFORE every handoff: each
        // `uncommitted = record` line has a fault-cell store above it
        // in the same body.
        let handoffs: Vec<usize> = body
            .iter()
            .filter(|(_, text)| text.contains("uncommitted = record"))
            .map(|(number, _)| *number)
            .collect();
        assert!(
            !handoffs.is_empty(),
            "{operation} must hand its reservation back to the root"
        );
        let stores: Vec<usize> = body
            .iter()
            .filter(|(_, text)| text.contains("*txn->fault_out =") && !text.contains("=="))
            .map(|(number, _)| *number)
            .collect();
        for handoff in &handoffs {
            assert!(
                stores.iter().any(|store| store < handoff),
                "{operation} line {handoff}: handoff without a fault store above it"
            );
        }
    }
    // N9: END submits only after the START leg commits; ABANDON only
    // after the START leg runs (past the `start_leg` label).
    let body = functions
        .get("p11_journal_combined_return")
        .expect("return body present");
    let submit = body
        .iter()
        .find(|(_, text)| text.starts_with("p11_journal_submit("))
        .map(|(number, _)| *number)
        .expect("return submits its terminal");
    let retired = body
        .iter()
        .find(|(_, text)| text.contains("p11_owner_start_remove"))
        .map(|(number, _)| *number)
        .expect("return retires its START leg");
    assert!(
        retired < submit,
        "return submits END (line {submit}) before its START leg commits (line {retired})"
    );
    let body = functions
        .get("p11_journal_combined_remove")
        .expect("remove body present");
    let submit = body
        .iter()
        .filter(|(_, text)| text.starts_with("p11_journal_submit("))
        .map(|(number, _)| *number)
        .collect::<Vec<_>>();
    assert_eq!(
        submit.len(),
        1,
        "remove holds exactly one terminal submit, found {submit:?}"
    );
    let leg = body
        .iter()
        .find(|(_, text)| text.starts_with("start_leg:"))
        .map(|(number, _)| *number)
        .expect("remove sequences its START leg");
    assert!(
        leg < submit[0],
        "remove submits ABANDON (line {}) before its START leg (line {leg})",
        submit[0]
    );
    // C4: each operation gates its own publication kind at its entry
    // point — a wrong-kind template never reaches the shared fill.
    for (operation, kind) in [
        ("p11_journal_combined_entry", "JOURNAL_KIND_BEGIN"),
        ("p11_journal_combined_return", "JOURNAL_KIND_END"),
        ("p11_journal_combined_remove", "JOURNAL_KIND_ABANDON"),
    ] {
        let body = functions.get(operation).expect("combined body present");
        assert!(
            body.iter().any(|(_, text)| text.contains(kind)),
            "{operation} must gate its {kind} publication kind"
        );
    }
}

/// Ordinary roots stay journal-free: no ordinary BPF root wires the
/// journal transaction leaves; only the cfg-gated journal roots module
/// reaches the producer. The slice-D birth marker globals are live
/// (wired from the exec, entry and return roots through
/// `p11_instance_*` names that carry none of these literals). The ban
/// covers the whole file text, including comments and extern names, so
/// marker call sites must keep those words out of their spellings. The
/// positive control below pins the one gated module that does wire the
/// producer, so this contract cannot pass by deleting the producer.
#[test]
fn object_journal_leaves_are_inactive() {
    for program in ["main.rs", "inventory.rs", "inventory_callers.rs"] {
        let path = format!("crates/ebpf/src/{program}");
        let source = std::fs::read_to_string(&path).expect("read BPF program");
        // Pure shared wire types/reason constants carry no native producer.
        // The only root module inclusion is independently private-gated;
        // actual OFF/ON object isolation is checked by the private ELF suite.
        let source = if program == "main.rs" {
            assert!(source.contains("#[cfg(p11scope_journal_roots)]\nmod journal_roots;"));
            source.replace(
                "p11scope_ebpf_common::object_journal",
                "SHARED_JOURNAL_WIRE",
            )
        } else {
            source
        };
        for symbol in [
            "p11_journal_",
            "JOURNAL_START",
            "journal_thread",
            "journal_sequence",
            "journal_bootstrap",
            "journal_marker",
            "JOURNAL_MARKER_CTL",
            "object_journal",
        ] {
            assert!(
                !source.contains(symbol),
                "{program} must not wire journal custody ({symbol})"
            );
        }
    }
    let roots = std::fs::read_to_string("crates/ebpf/src/journal_roots.rs")
        .expect("read journal roots module");
    for symbol in [
        "p11_journal_begin",
        "p11_journal_returning",
        "p11_owner_start_remove_reason",
        "p11_entry_journal",
        "p11_return_journal",
    ] {
        assert!(
            roots.contains(symbol),
            "journal roots must wire the real producer ({symbol})"
        );
    }
}

/// H8-D atomic birth marker: the native publication/dirty/readback/
/// admission implementation compiles and its actual fixture passes
/// unprivileged. This host fixture enables no production define or load.
#[test]
fn object_journal_birth_marker() {
    use std::process::Command;

    let temporary = tempfile::tempdir().expect("native marker test directory");
    let binary = temporary.path().join("journal-marker");
    let output = Command::new("clang-18")
        .args([
            "-O2",
            "-g",
            "-Wall",
            "-Wextra",
            "-Werror",
            "-pthread",
            "-I",
            "crates/ebpf/native",
            "tests/fixtures/object-journal/journal_marker_tests.c",
            "-o",
        ])
        .arg(&binary)
        .output()
        .expect("execute clang-18");
    assert!(
        output.status.success(),
        "native marker compile: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    let output = Command::new(binary)
        .output()
        .expect("execute native marker test");
    assert!(
        output.status.success(),
        "native marker test: {}",
        String::from_utf8_lossy(&output.stderr)
    );
}

/// H8-D birth marker budget: the native cap and the shared Rust cap are
/// one number, so a later budget change is a single small commit. The
/// ruled budget is 2^24 admissions per recording.
#[test]
fn object_journal_marker_cap_matches_native() {
    let header = std::fs::read_to_string("crates/ebpf/native/journal_marker.h")
        .expect("read native marker header");
    let define = "#define P11_JOURNAL_MARKER_ADMIT_CAP";
    let line = header
        .lines()
        .find(|line| line.starts_with(define))
        .expect("native cap define");
    let literal = line[define.len()..].trim().trim_end_matches("ULL").trim();
    let native: u64 = literal.parse().expect("native cap parses");
    assert_eq!(
        native,
        p11scope_ebpf_common::journal_marker::MARKER_ADMIT_CAP,
        "native and Rust marker caps must match"
    );
    assert_eq!(
        p11scope_ebpf_common::journal_marker::MARKER_ADMIT_CAP,
        1 << 24,
        "the ruled marker budget is 2^24 per recording"
    );
}

/// Abandoned-call signal: the native cleanup outcome and the exit root's
/// copy are one number, so a later renumbering is a single small commit.
/// 2 means a healthy settle abandoned at least one live START; only 1 is
/// failure.
#[test]
fn object_journal_cleanup_abandoned_code_matches_native() {
    let header = std::fs::read_to_string("crates/ebpf/native/task_owner.h")
        .expect("read native owner header");
    let define = "#define P11_OWNER_CLEANUP_ABANDONED_START";
    let line = header
        .lines()
        .find(|line| line.starts_with(define))
        .expect("native abandoned-start code define");
    let literal = line[define.len()..].trim().trim_end_matches('U').trim();
    let native: u32 = literal.parse().expect("native code parses");
    let source = std::fs::read_to_string("crates/ebpf/src/main.rs").expect("read BPF roots");
    let binding = "const OWNER_CLEANUP_ABANDONED_START: u32 = ";
    let line = source
        .lines()
        .map(str::trim)
        .find(|line| line.starts_with(binding))
        .expect("exit root abandoned-start code");
    let literal = line[binding.len()..].trim().trim_end_matches(';').trim();
    let bound: u32 = literal.parse().expect("bound code parses");
    assert_eq!(
        native, bound,
        "native and exit-root abandoned-start codes must match"
    );
    assert_eq!(bound, 2, "the abandoned-start code is 2 (only 1 fails)");
}

/// H8-D marker build gate: the native unit, the instance-epoch define and
/// the two global exports share one predicate, so a future Detailed bank
/// object cannot half-link the marker (unit without exports, or the
/// reverse).
#[test]
fn object_journal_marker_build_uses_one_gate() {
    let build = std::fs::read_to_string("build.rs").expect("read build script");
    let lines: Vec<&str> = build.lines().collect();
    let binding = "let journal_marker =";
    let predicates: Vec<&&str> = lines
        .iter()
        .filter(|line| line.trim_start().starts_with(binding))
        .collect();
    assert_eq!(
        predicates.len(),
        1,
        "the marker build must share one predicate"
    );
    assert!(build.contains("const BIRTH_MARKER_ENABLED: bool = false;"));
    let predicate = build
        .split_once(binding)
        .expect("single marker predicate")
        .1
        .split(';')
        .next()
        .expect("terminated marker predicate");
    assert!(
        predicate.contains("BIRTH_MARKER_ENABLED")
            && predicate.contains("BpfFlavor::Detailed")
            && predicate.contains("!counter_bank_proof"),
        "the shared gate must select Detailed non-bank builds: {}",
        predicate
    );
    for anchor in [
        "selected_native_units.push(\"journal_marker\")",
        "\"-DP11SCOPE_JOURNAL_MARKER\"",
        "\"link-arg=--export=p11_instance_scope_gap\"",
        "\"--cfg=p11scope_birth_marker\"",
    ] {
        let at = lines
            .iter()
            .position(|line| line.contains(anchor))
            .unwrap_or_else(|| panic!("marker build site is missing: {anchor}"));
        let guard = lines[at.saturating_sub(8)..at]
            .iter()
            .rev()
            .find(|line| line.trim_start().starts_with("if "))
            .unwrap_or_else(|| panic!("marker build site has no gate: {anchor}"));
        assert!(
            guard.contains("journal_marker") && !guard.contains("matches!"),
            "marker build site must use the shared gate: {anchor} under {guard}"
        );
    }
    let host = build
        .split("cargo:rustc-cfg=p11scope_birth_marker")
        .next()
        .expect("host cfg site");
    assert!(build.contains("cargo:rustc-cfg=p11scope_birth_marker"));
    assert!(
        host.lines()
            .rev()
            .take(2)
            .any(|line| line.contains("if BIRTH_MARKER_ENABLED"))
    );
}

#[test]
fn object_journal_marker_calls_and_declarations_share_the_gate() {
    let source = std::fs::read_to_string("crates/ebpf/src/main.rs").expect("read BPF roots");
    let lines: Vec<_> = source.lines().collect();
    // Each return implementation is bounded separately: the head (entry
    // roots, native shims and declarations), the entry root, the return
    // dispatch, the ordinary half, the monomorphic ordinary object copy
    // (one ring-loss gap arm) and the generic object copy (one ring-loss
    // gap arm). The whole-file total below guards against added sites;
    // every site is justified in its own region.
    let boundaries: &[(&str, &str)] = &[
        ("head", ""),
        ("entry", "fn p11_entry_impl"),
        ("dispatch", "fn p11_return_impl"),
        ("ordinary", "fn ordinary_return("),
        ("object_ordinary", "fn object_return_ordinary("),
        (
            "generic",
            "fn object_return<const JOURNAL: bool, Record: ReturnPayload>(",
        ),
    ];
    let mut starts = Vec::new();
    for (name, anchor) in boundaries {
        if anchor.is_empty() {
            starts.push((*name, 0));
            continue;
        }
        let at = lines
            .iter()
            .position(|line| line.trim_start().starts_with(anchor))
            .unwrap_or_else(|| panic!("marker region {name} must start at {anchor}"));
        starts.push((*name, at));
    }
    let region_of = |index: usize| -> &str {
        let mut region = "head";
        for (name, at) in &starts {
            if *at <= index {
                region = *name;
            } else {
                break;
            }
        }
        region
    };
    let mut calls = 0;
    let mut declarations = 0;
    let mut private_gap_calls = 0;
    let mut region_calls = std::collections::BTreeMap::new();
    for (index, line) in lines.iter().enumerate() {
        let line = line.trim();
        let call = matches!(
            line,
            "p11_instance_exec_birth();" | "p11_instance_scope_gap();"
        );
        let declaration = line.starts_with("fn p11_instance_exec_birth(")
            || line.starts_with("fn p11_instance_scope_gap(");
        if call || declaration {
            let prefix = &lines[index.saturating_sub(6)..index];
            let combined = prefix.iter().any(|line| {
                line.trim() == "#[cfg(any(p11scope_birth_marker, p11scope_journal_roots))]"
            });
            if line.starts_with("fn p11_instance_scope_gap(") {
                assert!(combined, "gap declaration needs both private selectors");
            } else if combined {
                assert_eq!(
                    line, "p11_instance_scope_gap();",
                    "private selector cannot enable birth"
                );
                assert!(
                    prefix
                        .iter()
                        .any(|line| line.contains("JOURNAL || cfg!(p11scope_birth_marker)")),
                    "ordinary specialization must retain its birth-only gate"
                );
                private_gap_calls += 1;
            } else {
                assert!(
                    prefix
                        .iter()
                        .any(|line| line.trim() == "#[cfg(p11scope_birth_marker)]"),
                    "marker site must retain its compile-time gate: {line}"
                );
            }
            calls += usize::from(call);
            declarations += usize::from(declaration);
            if call {
                *region_calls.entry(region_of(index)).or_insert(0) += 1;
            }
        }
    }
    for (region, expected) in [
        ("head", 3),
        ("entry", 6),
        ("dispatch", 3),
        ("ordinary", 2),
        ("object_ordinary", 1),
        ("generic", 1),
    ] {
        assert_eq!(
            region_calls.get(region).copied().unwrap_or(0),
            expected,
            "{region} must hold exactly its documented marker calls"
        );
    }
    assert_eq!(calls, 16);
    assert_eq!(declarations, 2);
    assert_eq!(private_gap_calls, 10);
}

/// H8-D marker drop arms: every silent in-scope drop arm calls the scope
/// gap at its own site, not just somewhere in its root. The entry ABI
/// refusals, the entry identity and START failures, the return ABI
/// refusal and missing START, and the four in-halves lost-call arms
/// (ordinary identity mismatch, ordinary ring loss, and one object
/// ring loss with settled removal in each object copy) each name their
/// arm; deleting any one call fails. Each copy's refused-base
/// output-loss arm instead runs the shared fault callback before
/// attempting output, so it already refuses births. The halves keep
/// their gaps in place. E2/R2 are covered live, and the fault-only
/// object arms are a different row class.
#[test]
fn object_journal_marker_drop_arms_call_the_gap() {
    const GAP: &str = "p11_instance_scope_gap();";
    let source = std::fs::read_to_string("crates/ebpf/src/main.rs").expect("read BPF roots");
    // The release selector is checked independently for every marker call.
    // Keep the original local-arm bound after omitting only that selector.
    let lines: Vec<&str> = source
        .lines()
        .filter(|line| {
            !matches!(
                line.trim(),
                "#[cfg(p11scope_birth_marker)]"
                    | "#[cfg(any(p11scope_birth_marker, p11scope_journal_roots))]"
                    | "if JOURNAL || cfg!(p11scope_birth_marker) {"
            )
        })
        .collect();
    let entry_at = lines
        .iter()
        .position(|line| line.starts_with("fn p11_entry_impl"))
        .expect("entry impl");
    let return_at = lines
        .iter()
        .position(|line| line.starts_with("fn p11_return_impl"))
        .expect("return impl");
    let accounting_at = lines
        .iter()
        .position(|line| line.starts_with("struct ReturnAccounting"))
        .expect("return impl end");
    let ordinary_at = lines
        .iter()
        .position(|line| line.starts_with("fn ordinary_return("))
        .expect("ordinary half");
    let object_ordinary_at = lines
        .iter()
        .position(|line| line.starts_with("fn object_return_ordinary("))
        .expect("ordinary object half");
    let object_at = lines
        .iter()
        .position(|line| {
            line.starts_with("fn object_return<const JOURNAL: bool, Record: ReturnPayload>(")
        })
        .expect("object half");
    let fork_at = lines
        .iter()
        .position(|line| line.starts_with("pub extern \"C\" fn p11_link_fork_allowed"))
        .expect("halves end");
    let entry = &lines[entry_at..return_at];
    let returned = &lines[return_at..accounting_at];
    let ordinary = &lines[ordinary_at..object_ordinary_at];
    let object_ordinary = &lines[object_ordinary_at..object_at];
    let object = &lines[object_at..fork_at];
    // Each object copy holds its own reserve-failure ring-loss arm (gap
    // below) and its own refused-base output-loss arm (fault-covered,
    // no gap). The retire/output shapes differ per copy: the ordinary
    // copy retires through the owned removal with a direct output
    // closure, the generic copy through the journal removal with a
    // block output closure.
    for (name, body, retire, output) in [
        (
            "ordinary",
            object_ordinary,
            "preserve_refused_base(||owned_start_remove(&key,true).is_ok(),||unsafe{p11_object_fault()},",
            "||EVENTS.output::<EventRecord>(unsafe{&(*raw).base},0).is_ok(),",
        ),
        (
            "generic",
            object,
            "preserve_refused_base(||start_remove_for::<JOURNAL>(&key,true,JOURNAL_REASON_IDENTITY_REFUSED).is_ok(),||unsafe{p11_object_fault()},",
            "||{EVENTS.output::<EventRecord>(unsafe{&(*raw).base},0).is_ok()},",
        ),
    ] {
        assert_eq!(
            body.iter()
                .filter(|line| line.contains("bump_evidence(EVIDENCE_RING_LOSS);"))
                .count(),
            2,
            "both {name} object ring-loss arms need their own birth-refusal accounting"
        );
        assert!(
            refused_base_ring_loss_is_fault_covered(&body.join("\n"), retire, output),
            "{name} refused-base loss must stay fault-covered"
        );
    }
    let refused_at = object
        .iter()
        .position(|line| line.trim() == "if !joined {")
        .expect("refused object continuity arm");
    let refused_ordinary_at = object_ordinary
        .iter()
        .position(|line| line.trim() == "if !joined {")
        .expect("refused ordinary-object continuity arm");
    // (region, arm anchor, expected arms, gap above the anchor).
    let arms: &[(&[&str], &str, usize, bool)] = &[
        (entry, "bump_evidence(EVIDENCE_ABI_REFUSALS);", 3, true),
        (
            entry,
            "bump_evidence(EVIDENCE_SEMANTIC_CAPTURE_FAILURES);",
            1,
            true,
        ),
        (entry, "if start_pointer.is_null() {", 1, false),
        (returned, "bump_evidence(EVIDENCE_ABI_REFUSALS);", 1, true),
        (returned, "if start.is_null() {", 1, false),
        (
            ordinary,
            "bump_evidence(EVIDENCE_SEMANTIC_CAPTURE_FAILURES);",
            1,
            false,
        ),
        (ordinary, "bump_evidence(EVIDENCE_RING_LOSS);", 1, false),
        (
            &object_ordinary[..refused_ordinary_at],
            "bump_evidence(EVIDENCE_RING_LOSS);",
            1,
            false,
        ),
        (
            &object[..refused_at],
            "bump_evidence(EVIDENCE_RING_LOSS);",
            1,
            false,
        ),
    ];
    for (region, anchor, expected, above) in arms {
        let hits: Vec<usize> = region
            .iter()
            .enumerate()
            .filter(|(_, line)| line.trim().contains(anchor))
            .map(|(index, _)| index)
            .collect();
        assert_eq!(
            hits.len(),
            *expected,
            "expected {expected} {anchor} arms, found {}",
            hits.len()
        );
        for hit in hits {
            let window = if *above {
                &region[hit.saturating_sub(6)..hit]
            } else {
                &region[hit + 1..(hit + 7).min(region.len())]
            };
            assert!(
                window.iter().any(|line| line.contains(GAP)),
                "drop arm {anchor} must call the scope gap within six lines"
            );
        }
    }
}

fn refused_base_ring_loss_is_fault_covered(object: &str, fault: &str, output: &str) -> bool {
    let Some((_, refused)) = object.split_once("if !joined {") else {
        return false;
    };
    let Some((refused, _)) = refused.split_once("let tail =") else {
        return false;
    };
    let code: String = refused
        .lines()
        .filter(|line| !line.trim_start().starts_with("//"))
        .flat_map(str::split_whitespace)
        .collect();
    let loss = "ifoutcome==RefusedBaseOutcome::OutputFailed{bump_evidence(EVIDENCE_RING_LOSS);}";
    match (
        code.find(fault),
        code.find(output),
        code.find("entry.discard(0);"),
        code.find(loss),
    ) {
        (Some(fault), Some(output), Some(discard), Some(loss)) => {
            fault < output
                && output < discard
                && discard < loss
                && code.matches("bump_evidence(EVIDENCE_RING_LOSS);").count() == 1
        }
        _ => false,
    }
}

#[test]
fn object_journal_refused_base_loss_stays_fault_covered() {
    use p11scope_ebpf_common::object_flow::{RefusedBaseOutcome, preserve_refused_base};

    let source = std::fs::read_to_string("crates/ebpf/src/main.rs").expect("read BPF roots");
    let (_, object_ordinary) = source
        .split_once("fn object_return_ordinary(")
        .expect("ordinary object half");
    let (object_ordinary, _) = object_ordinary
        .split_once("fn object_return<const JOURNAL: bool, Record: ReturnPayload>(")
        .expect("ordinary object half end");
    let (_, object) = source
        .split_once("fn object_return<const JOURNAL: bool, Record: ReturnPayload>(")
        .expect("object half");
    let (object, _) = object
        .split_once("pub extern \"C\" fn p11_link_fork_allowed")
        .expect("object half end");
    for (name, body, fault, output) in [
        (
            "ordinary copy",
            object_ordinary,
            "preserve_refused_base(||owned_start_remove(&key,true).is_ok(),||unsafe{p11_object_fault()},",
            "||EVENTS.output::<EventRecord>(unsafe{&(*raw).base},0).is_ok(),",
        ),
        (
            "generic copy",
            object,
            "preserve_refused_base(||start_remove_for::<JOURNAL>(&key,true,JOURNAL_REASON_IDENTITY_REFUSED).is_ok(),||unsafe{p11_object_fault()},",
            "||{EVENTS.output::<EventRecord>(unsafe{&(*raw).base},0).is_ok()},",
        ),
    ] {
        assert!(
            refused_base_ring_loss_is_fault_covered(body, fault, output),
            "{name} refused-base loss must stay fault-covered"
        );
        for (before, after) in [
            ("|| unsafe { p11_object_fault() },", "|| {},"),
            (
                "RefusedBaseOutcome::OutputFailed",
                "RefusedBaseOutcome::Emitted",
            ),
            ("            bump_evidence(EVIDENCE_RING_LOSS);", ""),
        ] {
            let (head, refused) = body.split_once("if !joined {").expect("refused arm");
            assert!(
                refused.contains(before),
                "{name} mutant must change the refused arm"
            );
            let mutant = format!("{head}if !joined {{ {}", refused.replacen(before, after, 1));
            assert!(
                !refused_base_ring_loss_is_fault_covered(&mutant, fault, output),
                "{name}: the refused-base loss guard must reject mutation of {before}"
            );
        }
    }
    for (retired, emitted, expected) in [
        (false, false, RefusedBaseOutcome::RetirementFailed),
        (true, false, RefusedBaseOutcome::OutputFailed),
        (true, true, RefusedBaseOutcome::Emitted),
    ] {
        let calls = std::cell::RefCell::new(Vec::new());
        let actual = preserve_refused_base(
            || {
                calls.borrow_mut().push("retire");
                retired
            },
            || calls.borrow_mut().push("fault"),
            || {
                calls.borrow_mut().push("output");
                emitted
            },
        );
        assert_eq!(actual, expected);
        assert_eq!(
            calls.into_inner(),
            if retired {
                vec!["retire", "fault", "output"]
            } else {
                vec!["retire", "fault"]
            },
            "every refused base faults before output; failed retirement cannot output"
        );
    }
}

/// H8-D object ring-loss guard: the in-place scope gap runs only when
/// the START removal settled (`if !failed`), because the fault arm
/// above already refuses births when removal failed. Flipping the guard
/// to `if failed` loses the only birth-refusal signal on the settled
/// path; dropping it gaps spuriously on the fault path. This helper
/// checks the exact `bump -> cfg -> guard -> gap` block for one copy.
fn ring_loss_gap_guard_holds(body: &[&str], guard: &str) -> bool {
    const GAP: &str = "p11_instance_scope_gap();";
    const CFG: &str = "#[cfg(not(feature = \"counter-broad\"))]";
    let Some(bump_at) = body
        .iter()
        .position(|line| line.trim().contains("bump_evidence(EVIDENCE_RING_LOSS);"))
    else {
        return false;
    };
    let window = &body[bump_at + 1..(bump_at + 9).min(body.len())];
    let trimmed: Vec<&str> = window.iter().map(|line| line.trim()).collect();
    let (Some(cfg_at), Some(guard_at), Some(gap_at)) = (
        trimmed.iter().position(|line| *line == CFG),
        trimmed.iter().position(|line| *line == guard),
        window.iter().position(|line| line.contains(GAP)),
    ) else {
        return false;
    };
    cfg_at < guard_at
        && guard_at < gap_at
        && !trimmed
            .iter()
            .any(|line| *line == "if failed {" || line.starts_with("if failed "))
}

/// Both object copies keep the settled-only ring-loss gap: the
/// ordinary copy on the plain guard, the generic copy on the
/// journal-conjoined guard. Per-copy mutants (flipped guard, dropped
/// guard, dropped gap) fail the check.
#[test]
fn object_journal_object_ring_loss_gap_requires_settled_guard() {
    let source = std::fs::read_to_string("crates/ebpf/src/main.rs").expect("read BPF roots");
    let lines: Vec<&str> = source.lines().collect();
    let object_ordinary_at = lines
        .iter()
        .position(|line| line.starts_with("fn object_return_ordinary("))
        .expect("ordinary object half");
    let object_at = lines
        .iter()
        .position(|line| {
            line.starts_with("fn object_return<const JOURNAL: bool, Record: ReturnPayload>(")
        })
        .expect("object half");
    let fork_at = lines
        .iter()
        .position(|line| line.starts_with("pub extern \"C\" fn p11_link_fork_allowed"))
        .expect("halves end");
    // Each object copy gaps only on the settled path: the ordinary copy
    // on the plain `if !failed` guard, the generic copy on the
    // journal-conjoined guard. Per-copy mutants prove each pin is live:
    // flipping the copy's guard to `if failed`, dropping the guard, or
    // dropping the gap call must fail that copy's check.
    for (name, body, guard) in [
        (
            "ordinary copy",
            &lines[object_ordinary_at..object_at],
            "if !failed {",
        ),
        (
            "generic copy",
            &lines[object_at..fork_at],
            "if !failed && (JOURNAL || cfg!(p11scope_birth_marker)) {",
        ),
    ] {
        assert!(
            ring_loss_gap_guard_holds(body, guard),
            "{name} ring-loss arm must read bump -> cfg -> settled guard -> gap"
        );
        let joined = body.join("\n");
        let flipped = guard.replacen("!failed", "failed", 1);
        assert_ne!(flipped, guard, "{name} flipped guard must differ");
        for (mutant, what) in [
            (
                joined.replacen(guard, &flipped, 1),
                format!("{name} flipped guard `{flipped}`"),
            ),
            (
                joined
                    .lines()
                    .filter(|line| line.trim() != guard)
                    .collect::<Vec<_>>()
                    .join("\n"),
                format!("{name} dropped guard"),
            ),
            (
                joined
                    .lines()
                    .filter(|line| !line.contains("p11_instance_scope_gap();"))
                    .collect::<Vec<_>>()
                    .join("\n"),
                format!("{name} dropped gap call"),
            ),
        ] {
            assert_ne!(mutant, joined, "{what} must change the copy");
            let lines: Vec<&str> = mutant.lines().collect();
            assert!(
                !ring_loss_gap_guard_holds(&lines, guard),
                "{what} must fail the settled-guard check"
            );
        }
    }
}

/// H8-D birth marker wiring: only the Detailed object carries the
/// control map and the two marker globals; inventory and counter
/// objects carry neither; no built object carries a transaction
/// symbol (a linked transaction leaf would add its map or a
/// `p11_journal_*` function). Counter objects are checked when this
/// build produced them; every class present checks a nonzero
/// object count, so the test cannot pass with an empty selection.
#[test]
fn object_journal_release_has_no_birth_marker_paths() {
    let object =
        aya_obj::Object::parse(p11scope::EBPF_OBJECT).expect("parse release Detailed object");
    assert!(
        !object.maps.contains_key("JOURNAL_MARKER_CTL"),
        "the release must not allocate the deferred birth-marker control map"
    );
    for name in ["p11_instance_exec_birth", "p11_instance_scope_gap"] {
        assert!(
            !object
                .functions
                .values()
                .any(|function| function.name == name),
            "the release must not retain a marker body, including a no-op stub: {name}"
        );
    }
}

#[test]
fn object_journal_marker_wired_detailed_only() {
    const MARKER_MAP: &str = "JOURNAL_MARKER_CTL";
    const MARKER_GLOBALS: [&str; 2] = ["p11_instance_exec_birth", "p11_instance_scope_gap"];
    const TRANSACTION_SYMBOLS: [&str; 4] = [
        "JOURNAL_START",
        "journal_thread",
        "journal_sequence",
        "object_journal",
    ];
    let counter_requested = match option_env!("P11SCOPE_COUNTER_ARTIFACTS") {
        None | Some("0") => false,
        Some("1") => true,
        other => panic!("malformed private counter artifact request {other:?}"),
    };
    assert_eq!(
        counter_requested,
        match env!("P11SCOPE_COUNTER_ARTIFACTS_ENABLED") {
            "0" => false,
            "1" => true,
            other => panic!("invalid private counter artifact selection {other:?}"),
        },
        "the emitted counter set must follow this compilation"
    );
    let mut counter_bodies = Vec::new();
    if counter_requested {
        for name in [
            "p11scope-ebpf-counter-counts",
            "p11scope-ebpf-counter-timestamps",
            "p11scope-ebpf-counter-latency",
        ] {
            let path = std::path::Path::new(env!("OUT_DIR"))
                .join("counter-artifacts")
                .join(name);
            counter_bodies.push(std::fs::read(&path).unwrap());
        }
    }
    let detailed: Vec<(&str, &[u8])> = vec![("p11scope-ebpf", p11scope::EBPF_OBJECT)];
    let inventory: Vec<(&str, &[u8])> = vec![
        ("p11scope-ebpf-inventory", p11scope::EBPF_INVENTORY_OBJECT),
        (
            "p11scope-ebpf-inventory-callers",
            p11scope::EBPF_INVENTORY_CALLERS_OBJECT,
        ),
    ];
    let counter: Vec<(&str, &[u8])> = counter_bodies
        .iter()
        .enumerate()
        .map(|(index, body)| {
            (
                [
                    "p11scope-ebpf-counter-counts",
                    "p11scope-ebpf-counter-timestamps",
                    "p11scope-ebpf-counter-latency",
                ][index],
                body.as_slice(),
            )
        })
        .collect();
    assert_eq!(detailed.len(), 1, "the Detailed class checks one object");
    assert_eq!(inventory.len(), 2, "the inventory class checks two objects");
    assert_eq!(
        counter.len(),
        if counter_requested { 3 } else { 0 },
        "the counter class checks every built counter object"
    );
    for (class, objects, wired) in [
        ("detailed", detailed.as_slice(), cfg!(p11scope_birth_marker)),
        ("inventory", inventory.as_slice(), false),
        ("counter", counter.as_slice(), false),
    ] {
        for (name, bytes) in objects {
            let object = aya_obj::Object::parse(bytes).expect("parse built object");
            assert_eq!(
                object.maps.contains_key(MARKER_MAP),
                wired,
                "{class} {name} marker map"
            );
            for global in MARKER_GLOBALS {
                assert_eq!(
                    object
                        .functions
                        .values()
                        .any(|function| function.name == global),
                    wired,
                    "{class} {name} {global}"
                );
            }
            let symbols: Vec<&str> = object
                .maps
                .keys()
                .map(String::as_str)
                .chain(
                    object
                        .functions
                        .values()
                        .map(|function| function.name.as_str()),
                )
                .collect();
            for symbol in TRANSACTION_SYMBOLS {
                assert!(
                    !symbols.iter().any(|candidate| candidate.contains(symbol)),
                    "{class} {name} carries transaction symbol {symbol}"
                );
            }
        }
    }
}

/// Every finite ABANDON reason is either emitted by a named producer
/// site or explicitly reserved in the shared contract. A reason with
/// neither would let the fixture's wire coverage (removal reasons
/// 0..=9) silently outrun the live producer. Emission means an
/// executable reason-bearing removal/settlement site, never bare
/// token presence: the import block already names every token, so a
/// scope-loss mutant that keeps its import must be rejected.
#[test]
fn object_journal_every_reason_has_an_emitter_or_a_reservation() {
    use p11scope_ebpf_common::object_journal::{
        JOURNAL_REASON_ABI_REFUSED, JOURNAL_REASON_ENTRY_COLLISION, JOURNAL_REASON_EXEC_EXIT,
        JOURNAL_REASON_IDENTITY_REFUSED, JOURNAL_REASON_INSERT_FAILED,
        JOURNAL_REASON_PARTIAL_TRANSACTION, JOURNAL_REASON_SCOPE_LOST, JOURNAL_REASON_STOP_CLEANUP,
        JOURNAL_REASON_SYNC_RETURN_RESULT_LOST,
    };
    assert_eq!(
        [
            JOURNAL_REASON_ENTRY_COLLISION,
            JOURNAL_REASON_INSERT_FAILED,
            JOURNAL_REASON_SCOPE_LOST,
            JOURNAL_REASON_ABI_REFUSED,
            JOURNAL_REASON_IDENTITY_REFUSED,
            JOURNAL_REASON_EXEC_EXIT,
            JOURNAL_REASON_STOP_CLEANUP,
            JOURNAL_REASON_PARTIAL_TRANSACTION,
            JOURNAL_REASON_SYNC_RETURN_RESULT_LOST,
        ],
        [1, 2, 3, 4, 5, 6, 7, 8, 9],
        "the finite reason set is exactly 1..=9"
    );
    let read = |path: &str| std::fs::read_to_string(path).unwrap_or_else(|_| panic!("read {path}"));
    let main_rs = read("crates/ebpf/src/main.rs");
    let roots_rs = read("crates/ebpf/src/journal_roots.rs");
    let owner_c = read("crates/ebpf/native/task_owner.c");
    let owner_h = read("crates/ebpf/native/task_owner.h");
    let journal_c = read("crates/ebpf/native/object_journal.c");
    let fixture_c = read("tests/fixtures/object-journal/journal_owner_tests.c");
    let common = read("crates/ebpf-common/src/object_journal.rs");
    for (define, expected) in [
        (
            "#define P11_OWNER_START_REASON_COLLISION",
            JOURNAL_REASON_ENTRY_COLLISION,
        ),
        (
            "#define P11_OWNER_START_REASON_EXEC_EXIT",
            JOURNAL_REASON_EXEC_EXIT,
        ),
    ] {
        let line = owner_h
            .lines()
            .find(|line| line.starts_with(define))
            .unwrap_or_else(|| panic!("native define {define}"));
        let literal = line[define.len()..].trim().trim_end_matches('U').trim();
        let native: u32 = literal.parse().expect("native reason parses");
        assert_eq!(native, expected, "native and wire reason numbers agree");
    }
    /// Executable reason-bearing call sites: comment-stripped
    /// source lines that carry both the reason token and a
    /// removal/settlement call shape. Import lines, prose, and
    /// commented-out calls never match: they carry no live call.
    fn executable_sites(text: &str, token: &str, calls: &[&str]) -> Vec<String> {
        strip_comments(text)
            .lines()
            .filter(|line| line.contains(token) && calls.iter().any(|call| line.contains(call)))
            .map(str::to_string)
            .collect()
    }
    /// Strip C/Rust line (`//`) and block (`/* */`) comments,
    /// honoring quoted strings and char literals. Commented-out
    /// emitters and calls never classify as executable. Newlines
    /// survive, so reported line numbers stay stable.
    fn strip_comments(text: &str) -> String {
        enum State {
            Code,
            Line,
            Block,
            Str,
        }
        let mut out = String::with_capacity(text.len());
        let mut state = State::Code;
        let mut escape = false;
        let chars: Vec<char> = text.chars().collect();
        let mut index = 0;
        // A quote opens a char literal only with its closer in
        // reach (`'x'`, `'\n'`): Rust lifetimes (`&'a`) stay code.
        let char_len = |chars: &[char]| {
            if chars.len() > 2 && chars[1] != '\\' && chars[2] == '\'' {
                Some(3)
            } else if chars.len() > 3 && chars[1] == '\\' && chars[3] == '\'' {
                Some(4)
            } else {
                None
            }
        };
        while index < chars.len() {
            let c = chars[index];
            match state {
                State::Code => {
                    if c == '/' && chars.get(index + 1) == Some(&'/') {
                        index += 2;
                        state = State::Line;
                        continue;
                    }
                    if c == '/' && chars.get(index + 1) == Some(&'*') {
                        index += 2;
                        state = State::Block;
                        continue;
                    }
                    if c == '"' {
                        out.push(c);
                        index += 1;
                        state = State::Str;
                        continue;
                    }
                    if c == '\''
                        && let Some(len) = char_len(&chars[index..])
                    {
                        out.push_str(&chars[index..index + len].iter().collect::<String>());
                        index += len;
                        continue;
                    }
                    out.push(c);
                    index += 1;
                }
                State::Line => {
                    if c == '\n' {
                        out.push(c);
                        state = State::Code;
                    }
                    index += 1;
                }
                State::Block => {
                    if c == '*' && chars.get(index + 1) == Some(&'/') {
                        index += 2;
                        state = State::Code;
                    } else {
                        if c == '\n' {
                            out.push(c);
                        }
                        index += 1;
                    }
                }
                State::Str => {
                    out.push(c);
                    if escape {
                        escape = false;
                    } else if c == '\\' {
                        escape = true;
                    } else if c == '"' {
                        state = State::Code;
                    }
                    index += 1;
                }
            }
        }
        out
    }
    /// A bare reserved numeric (7/8): decimal or hex, one outer cast
    /// and integer suffixes tolerated, nothing else.
    fn is_reserved_numeric(argument: &str) -> bool {
        let mut argument = argument.trim();
        // One outer cast prefix (`(u32)7`) tolerated.
        if argument.contains(')') {
            argument = argument.rsplit(')').next().unwrap_or(argument).trim();
        }
        let digits = argument.trim_end_matches(['U', 'u', 'L', 'l']);
        let value = if let Some(hex) = digits
            .strip_prefix("0x")
            .or_else(|| digits.strip_prefix("0X"))
        {
            u32::from_str_radix(hex, 16).ok()
        } else {
            digits.parse::<u32>().ok()
        };
        matches!(value, Some(7 | 8))
    }
    /// Reserved numerics (7/8) in native reason positions: every
    /// offending assignment spelling and every whole (possibly
    /// wrapped) reason-taking call whose reason argument is a bare
    /// 7/8, for production (must be none) and mutants (must be
    /// some). Comment-stripped throughout.
    fn reserved_numeric_sites(text: &str) -> Vec<String> {
        let code = strip_comments(text);
        let mut sites = Vec::new();
        for (index, line) in code.lines().enumerate() {
            for spelling in ["= 7", "=7", "= 8", "=8"] {
                if line.contains("reason") && line.contains(spelling) {
                    sites.push(format!("{}: {line}", index + 1));
                }
            }
        }
        for shape in ["remove_start(", "start_remove_reason("] {
            let mut rest = code.as_str();
            while let Some(at) = rest.find(shape) {
                let lineno = code.len() - rest.len() + at;
                let lineno = code[..lineno].matches('\n').count() + 1;
                rest = &rest[at + shape.len()..];
                // Balance to the call's own closing paren, across
                // wrapped lines; the reason is the last argument.
                let mut depth = 1u32;
                let mut end = None;
                for (offset, c) in rest.char_indices() {
                    match c {
                        '(' => depth += 1,
                        ')' => {
                            depth -= 1;
                            if depth == 0 {
                                end = Some(offset);
                                break;
                            }
                        }
                        _ => {}
                    }
                }
                let Some(end) = end else {
                    sites.push(format!("{lineno}: unbalanced {shape} call"));
                    break;
                };
                let args = &rest[..end];
                let mut depth = 0u32;
                let mut last_comma = None;
                for (offset, c) in args.char_indices() {
                    match c {
                        '(' => depth += 1,
                        ')' => depth = depth.saturating_sub(1),
                        ',' if depth == 0 => last_comma = Some(offset),
                        _ => {}
                    }
                }
                let reason = match last_comma {
                    Some(offset) => &args[offset + 1..],
                    None => args,
                };
                if is_reserved_numeric(reason) {
                    let call: String = args.chars().filter(|c| !c.is_whitespace()).collect();
                    sites.push(format!("{lineno}: {shape}{call})"));
                }
                rest = &rest[end + 1..];
            }
        }
        sites
    }
    // The main import block names every Rust-side token, so whole-file
    // presence cannot tell an emitter from an import. Pin that trap:
    // the import must still carry all five tokens, and only the
    // call-shaped lines below count as emitters.
    let import_marker = "use p11scope_ebpf_common::object_journal::{";
    let import_at = main_rs.find(import_marker).expect("reason import block");
    let import_end = main_rs[import_at..].find("};").expect("import end") + import_at + "};".len();
    let import_block = &main_rs[import_at..import_end];
    for token in [
        "JOURNAL_REASON_INSERT_FAILED",
        "JOURNAL_REASON_SCOPE_LOST",
        "JOURNAL_REASON_ABI_REFUSED",
        "JOURNAL_REASON_IDENTITY_REFUSED",
        "JOURNAL_REASON_SYNC_RETURN_RESULT_LOST",
    ] {
        assert!(import_block.contains(token), "import still names {token}");
    }
    // Native calls may wrap the reason onto the next line; join wrapped
    // call lines so the shape check sees whole calls.
    let owner_joined = owner_c.replace(",\n", ", ");
    // Each named emitter, individually: at least one executable
    // reason-bearing removal/settlement site in its producer file.
    assert!(
        !executable_sites(
            &owner_joined,
            "P11_OWNER_START_REASON_COLLISION",
            &["remove_start("]
        )
        .is_empty(),
        "entry-collision emitter: reason-bearing remove_start in task_owner.c"
    );
    assert!(
        !executable_sites(
            &main_rs,
            "JOURNAL_REASON_INSERT_FAILED",
            &["start_remove_for::<JOURNAL>("]
        )
        .is_empty(),
        "insert-failed emitter: reason-bearing removal in main.rs"
    );
    assert!(
        !executable_sites(
            &main_rs,
            "JOURNAL_REASON_SCOPE_LOST",
            &["start_remove_rc_for::<JOURNAL>("]
        )
        .is_empty(),
        "scope-lost emitter: reason-bearing removal in main.rs"
    );
    assert!(
        !executable_sites(
            &main_rs,
            "JOURNAL_REASON_ABI_REFUSED",
            &[
                "start_remove_for::<JOURNAL>(",
                "start_discard_for::<JOURNAL>("
            ]
        )
        .is_empty(),
        "abi-refused emitter: reason-bearing removal in main.rs"
    );
    assert!(
        !executable_sites(
            &main_rs,
            "JOURNAL_REASON_IDENTITY_REFUSED",
            &["start_remove_for::<JOURNAL>("]
        )
        .is_empty(),
        "identity-refused emitter: reason-bearing removal in main.rs"
    );
    assert!(
        !executable_sites(
            &roots_rs,
            "JOURNAL_REASON_IDENTITY_REFUSED",
            &["remove(&key"]
        )
        .is_empty(),
        "identity-refused emitter: reason-bearing remove in journal_roots.rs"
    );
    assert!(
        !executable_sites(
            &owner_joined,
            "P11_OWNER_START_REASON_EXEC_EXIT",
            &["remove_start("]
        )
        .is_empty(),
        "exec-exit emitter: reason-bearing remove_start in task_owner.c"
    );
    assert!(
        !executable_sites(
            &main_rs,
            "JOURNAL_REASON_SYNC_RETURN_RESULT_LOST",
            &["start_remove_for::<JOURNAL>("]
        )
        .is_empty(),
        "sync-return-result-lost emitter: reason-bearing removal in main.rs"
    );
    assert!(
        !executable_sites(
            &roots_rs,
            "JOURNAL_REASON_SYNC_RETURN_RESULT_LOST",
            &["remove(&key"]
        )
        .is_empty(),
        "sync-return-result-lost emitter: reason-bearing remove in journal_roots.rs"
    );
    let completion = roots_rs
        .split("fn completion_reason")
        .nth(1)
        .and_then(|tail| tail.split("\n}\n").next())
        .expect("completion_reason body");
    assert!(
        completion.contains("JOURNAL_REASON_SYNC_RETURN_RESULT_LOST"),
        "unsettled completion names sync-return-result-lost"
    );
    let settle = journal_c
        .split("u32 p11_journal_settle_prepare")
        .nth(1)
        .and_then(|tail| tail.split("u32 p11_journal_settle_finish").next())
        .expect("settle prepare body");
    assert!(
        settle.contains("reason = 9;"),
        "unsettled normal removal coerces to sync-return-result-lost"
    );
    assert_eq!(
        journal_c.matches("reason = 9;").count(),
        1,
        "the settle coercion is the only numeric reason emission"
    );
    // Negative control: the review's counterexample — every scope-loss
    // use outside the import re-pointed at another finite reason.
    // Whole-file presence stays green on this mutant; the
    // executable-site check must reject it.
    let scope_site = "start_remove_rc_for::<JOURNAL>(&key, false, JOURNAL_REASON_SCOPE_LOST)";
    assert!(
        main_rs[import_end..].contains(scope_site),
        "mutant removes a real scope-loss site"
    );
    let mutant = format!(
        "{import_block}{}",
        main_rs[import_end..].replace("JOURNAL_REASON_SCOPE_LOST", "JOURNAL_REASON_INSERT_FAILED")
    );
    assert!(
        mutant.contains("JOURNAL_REASON_SCOPE_LOST"),
        "mutant keeps the import: whole-file presence stays green"
    );
    assert!(
        executable_sites(
            &mutant,
            "JOURNAL_REASON_SCOPE_LOST",
            &["start_remove_rc_for::<JOURNAL>("]
        )
        .is_empty(),
        "scope-loss mutant rejected"
    );
    // Negative controls: the scope-loss emitter lost, its former call
    // surviving only in a comment — line, block, and multi-line block
    // spellings. Line matching counts each comment as an emitter;
    // comment-stripped classification must reject all three.
    assert_eq!(
        main_rs[import_end..].matches(scope_site).count(),
        1,
        "scope-loss call anchor"
    );
    for (label, commented_site) in [
        (
            "line",
            "//start_remove_rc_for::<JOURNAL>(&key, false, JOURNAL_REASON_SCOPE_LOST)",
        ),
        (
            "block",
            "/*start_remove_rc_for::<JOURNAL>(&key, false, JOURNAL_REASON_SCOPE_LOST)*/",
        ),
        (
            "multi-line block",
            "/* open\n        match start_remove_rc_for::<JOURNAL>(&key, false, JOURNAL_REASON_SCOPE_LOST);\n        close */",
        ),
    ] {
        let commented = format!(
            "{import_block}{}",
            main_rs[import_end..].replacen(scope_site, commented_site, 1)
        );
        assert!(
            commented.contains("JOURNAL_REASON_SCOPE_LOST"),
            "{label} comment preserves the token"
        );
        assert!(
            executable_sites(
                &commented,
                "JOURNAL_REASON_SCOPE_LOST",
                &["start_remove_rc_for::<JOURNAL>("]
            )
            .is_empty(),
            "{label} commented-out emitter rejected"
        );
    }
    for reserved in [
        "JOURNAL_REASON_STOP_CLEANUP",
        "JOURNAL_REASON_PARTIAL_TRANSACTION",
    ] {
        assert!(
            !main_rs.contains(reserved)
                && !roots_rs.contains(reserved)
                && !owner_c.contains(reserved)
                && !journal_c.contains(reserved),
            "{reserved} stays unemitted while it is reserved"
        );
        let documented = common
            .lines()
            .any(|line| line.contains(reserved) && line.to_lowercase().contains("reserved"));
        assert!(
            documented,
            "{reserved} carries its reservation in the shared contract"
        );
    }
    // Numeric C positions: production C emits no reserved numeric
    // reason, neither as an assignment spelling nor as a reason
    // argument to a whole (possibly wrapped) native call. The settle
    // coercion above is the only numeric reason assignment, and it
    // names 9.
    for (name, text) in [("task_owner.c", &owner_c), ("object_journal.c", &journal_c)] {
        assert!(
            reserved_numeric_sites(text).is_empty(),
            "{name}: numeric reserved reason in production C: {:?}",
            reserved_numeric_sites(text)
        );
    }
    // Negative controls: a reserved numeric smuggled into one real
    // reason argument — `7U` at a single-line slot-bound call, `8U`
    // at the wrapped exec-exit call — with the other named emitters
    // intact. The assignment-spelling scan passes both mutants; the
    // reason-argument check must reject them.
    let slot_bound = "remove_start(ctl, owner, key, P11_OWNER_START_REASON_COLLISION);";
    assert_eq!(
        owner_c.matches(slot_bound).count(),
        4,
        "slot-bound call sites"
    );
    for (label, mutant) in [
        (
            "7U",
            owner_c.replacen(slot_bound, "remove_start(ctl, owner, key, 7U);", 1),
        ),
        (
            "8U-wrapped",
            owner_c.replacen("P11_OWNER_START_REASON_EXEC_EXIT", "8U", 1),
        ),
    ] {
        assert!(
            mutant.contains("P11_OWNER_START_REASON_COLLISION")
                && mutant.contains("P11_OWNER_START_REASON_EXEC_EXIT"),
            "{label} keeps named emitters: token presence stays green"
        );
        assert!(
            !reserved_numeric_sites(&mutant).is_empty(),
            "{label} numeric reason argument rejected"
        );
    }
    // Native reason numbers stay out of the reserved codes.
    for line in owner_h.lines() {
        if let Some(rest) = line.strip_prefix("#define P11_OWNER_START_REASON_") {
            let literal = rest
                .split_whitespace()
                .nth(1)
                .expect("native reason value")
                .trim_end_matches('U');
            let native: u32 = literal.parse().expect("native reason parses");
            assert!(
                !matches!(native, 7 | 8),
                "native reason avoids reserved codes: {line}"
            );
        }
    }
    // Reserved numerics stay distinct from fixture injection: the
    // producer matrix injects every wire reason 0..=9 through the
    // public removal entry (wire coverage, not emission evidence),
    // while production C above emits no numeric 7/8.
    assert!(
        fixture_c.contains("for (u32 reason = 0; reason <= 9; reason++)"),
        "fixture injects the full wire reason range"
    );
}

/// Closed stop gate preserves tracked custody, decided by the shared
/// production admission: the fixture's lifecycle/return entries call
/// back into `stop_gate_admit_with` + production constants over an
/// FFI ops table, driving the same native custody state. Closed-gate
/// entries retire nothing and publish no terminal, while the
/// open-gate control settles through the same wrapped entries.
/// Hostile ops (always-admit / always-deny) must flip the verdicts
/// they govern, proving custody rides on the linked admission.
#[test]
fn object_journal_stop_gate_closed_preserves_custody() {
    use p11scope_ebpf_common::{STOP_GATE_COUNT_MASK, STOP_GATE_STOP, stop_gate_admit_with};
    use std::ffi::CString;
    use std::os::raw::c_int;
    use std::process::Command;
    use std::sync::atomic::{AtomicU64, Ordering};
    let common = std::fs::read_to_string("crates/ebpf-common/src/object_journal.rs")
        .expect("read shared journal contract");
    // The shared reservation qualifies its settlement claim: open-gate
    // cleanup settles retained calls, while a closed gate supplies no
    // such witness.
    assert!(
        common.contains("a closed stop gate admits no such witness"),
        "stop reservation qualified to open-gate settlement"
    );
    let fixture = std::fs::read_to_string("tests/fixtures/object-journal/journal_owner_tests.c")
        .expect("read journal fixture");
    // The fixture carries the FFI admission seam and no handwritten
    // gate of its own: every verdict below comes from the shared
    // `stop_gate_admit_with` linked into this test.
    for token in [
        "struct stop_gate_ops",
        "p11scope_stop_gate_closed",
        "p11scope_stop_gate_open",
    ] {
        assert!(fixture.contains(token), "stop-gate seam present: {token}");
    }
    for shadow in [
        "stop_gate_word",
        "static int stop_gate_enter",
        "static void stop_gate_leave",
        "static void stop_gate_request_stop",
        "1ULL << 63",
    ] {
        assert!(
            !fixture.contains(shadow),
            "no handwritten gate remains: {shadow}"
        );
    }
    // The bridge: production admission + production constants over one
    // shared word, exposed to the fixture through the ops table.
    static WORD: AtomicU64 = AtomicU64::new(0);
    fn read() -> u64 {
        WORD.compare_exchange(0, 0, Ordering::SeqCst, Ordering::SeqCst)
            .unwrap_or_else(|previous| previous)
    }
    fn add(delta: i64) {
        WORD.fetch_add(delta as u64, Ordering::SeqCst);
    }
    unsafe extern "C" fn gate_reset() {
        WORD.store(0, Ordering::SeqCst);
    }
    unsafe extern "C" fn gate_request_stop() {
        WORD.fetch_or(STOP_GATE_STOP, Ordering::SeqCst);
    }
    unsafe extern "C" fn gate_enter() -> c_int {
        stop_gate_admit_with(read, add) as c_int
    }
    unsafe extern "C" fn gate_leave() {
        add(-1);
    }
    unsafe extern "C" fn gate_always_admit() -> c_int {
        1
    }
    unsafe extern "C" fn gate_always_deny() -> c_int {
        0
    }
    #[repr(C)]
    #[derive(Clone, Copy)]
    struct StopGateOps {
        reset: unsafe extern "C" fn(),
        request_stop: unsafe extern "C" fn(),
        enter: unsafe extern "C" fn() -> c_int,
        leave: unsafe extern "C" fn(),
    }
    // The bridge carries production semantics: pin its word
    // transitions before the fixture runs through them.
    assert_eq!(STOP_GATE_STOP, 1 << 63);
    assert_eq!(STOP_GATE_STOP & STOP_GATE_COUNT_MASK, 0);
    assert_eq!(STOP_GATE_STOP | STOP_GATE_COUNT_MASK, u64::MAX);
    unsafe {
        gate_reset();
        assert_eq!(WORD.load(Ordering::SeqCst), 0);
        assert_eq!(gate_enter(), 1);
        assert_eq!(WORD.load(Ordering::SeqCst), 1);
        gate_request_stop();
        assert_eq!(gate_enter(), 0);
        assert_eq!(WORD.load(Ordering::SeqCst), STOP_GATE_STOP | 1);
        gate_leave();
        assert_eq!(WORD.load(Ordering::SeqCst), STOP_GATE_STOP);
        assert_eq!(gate_enter(), 0);
        gate_reset();
    }
    // The same native fixture state, loaded in-process: the custody
    // sections run against the real native maps, admitted by the
    // bridge above.
    let work = tempfile::tempdir().expect("stop-gate work directory");
    let shared = work.path().join("fixture.so");
    let output = Command::new("clang-18")
        .args([
            "-O2",
            "-g",
            "-Wall",
            "-Wextra",
            "-Werror",
            "-pthread",
            "-fPIC",
            "-shared",
            "-DP11SCOPE_OBJECT_JOURNAL",
            "-I",
            "crates/ebpf/native",
            "tests/fixtures/object-journal/journal_owner_tests.c",
            "-o",
        ])
        .arg(&shared)
        .output()
        .expect("compile stop-gate fixture");
    assert!(
        output.status.success(),
        "fixture compile: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    let path = CString::new(shared.as_os_str().as_encoded_bytes()).expect("NUL-free .so path");
    // SAFETY: the path is a valid NUL-free object path; the handle is
    // checked before any symbol resolves through it.
    let handle = unsafe { libc::dlopen(path.as_ptr(), libc::RTLD_NOW | libc::RTLD_LOCAL) };
    assert!(!handle.is_null(), "dlopen stop-gate fixture");
    let symbol = |name: &str| {
        let name = CString::new(name).expect("NUL-free symbol");
        // SAFETY: the handle is live; dlsym only reads it.
        let pointer = unsafe { libc::dlsym(handle, name.as_ptr()) };
        assert!(!pointer.is_null(), "fixture entry present: {name:?}");
        pointer
    };
    type Battery = unsafe extern "C" fn(*const StopGateOps) -> c_int;
    // SAFETY: the entries are the `int (const struct stop_gate_ops *)`
    // batteries pinned above; the ops table outlives every call.
    let closed: Battery = unsafe { std::mem::transmute(symbol("p11scope_stop_gate_closed")) };
    let open: Battery = unsafe { std::mem::transmute(symbol("p11scope_stop_gate_open")) };
    let production = StopGateOps {
        reset: gate_reset,
        request_stop: gate_request_stop,
        enter: gate_enter,
        leave: gate_leave,
    };
    // Healthy controls: the closed gate preserves custody and the
    // open gate settles, both admitted by production verdicts.
    // SAFETY: each entry runs its custody section against the
    // fixture's own native state with the ops table above.
    assert_eq!(
        unsafe { closed(&production) },
        0,
        "closed gate preserves custody"
    );
    assert_eq!(unsafe { open(&production) }, 0, "open gate settles");
    // Hostile controls: verdicts that defy the gate must flip the
    // sections they govern — custody rides on the linked admission,
    // never on fixture self-checks.
    let always_admit = StopGateOps {
        enter: gate_always_admit,
        ..production
    };
    assert_ne!(
        unsafe { closed(&always_admit) },
        0,
        "always-admit ops fail the closed section"
    );
    let always_deny = StopGateOps {
        enter: gate_always_deny,
        ..production
    };
    assert_ne!(
        unsafe { open(&always_deny) },
        0,
        "always-deny ops fail the open section"
    );
    // SAFETY: the handle is live and no entry runs past this point.
    unsafe {
        libc::dlclose(handle);
    }
}

/// Lifecycle and journal-return roots admit through the stop gate
/// before touching custody: exec/exit roots return before cleanup and
/// the journal return root returns before the return body when
/// admission fails. The pin matches the ACTUAL admission condition
/// (`if !stop_gate_enter() { return 0; }`), never bare token
/// presence: a disconnected (`&& false`), inverted, or removed gate
/// must fail it, separately for each of the three roots.
#[test]
fn object_journal_lifecycle_roots_gate_cleanup_on_stop() {
    let main_rs = std::fs::read_to_string("crates/ebpf/src/main.rs").expect("read BPF roots");
    let roots_rs =
        std::fs::read_to_string("crates/ebpf/src/journal_roots.rs").expect("read journal roots");
    /// A root gates its delegated call: the ACTUAL admission
    /// condition — admission failure returns before the gated call,
    /// with nothing in between — inside the root's own head.
    /// Whitespace-insensitive; a disconnected (`&& false`),
    /// inverted, or missing condition never matches.
    fn root_gates_before_call(text: &str, root_fn: &str, gated_call: &str) -> bool {
        let root = format!("fn {root_fn}(");
        let Some(start) = text.find(root.as_str()) else {
            return false;
        };
        let after = &text[start..];
        let Some(call) = after.find(gated_call) else {
            return false;
        };
        let head = &after[..call];
        let flat: String = head.chars().filter(|c| !c.is_whitespace()).collect();
        flat.contains("if!stop_gate_enter(){return0;}")
    }
    struct Root<'a> {
        file: &'static str,
        text: &'a str,
        anchor: &'static str,
        block: &'static str,
        root_fn: &'static str,
        gated_call: &'static str,
    }
    let roots = [
        Root {
            file: "main.rs",
            text: &main_rs,
            anchor: "pub fn sched_process_exec(_ctx: RawTracePointContext) -> u32 {\n    if !stop_gate_enter() {\n        return 0;\n    }\n",
            block: "    if !stop_gate_enter() {\n        return 0;\n    }\n",
            root_fn: "sched_process_exec",
            gated_call: "sched_process_exec_impl",
        },
        Root {
            file: "main.rs",
            text: &main_rs,
            anchor: "pub fn sched_process_exit(_ctx: RawTracePointContext) -> u32 {\n    if !stop_gate_enter() {\n        return 0;\n    }\n",
            block: "    if !stop_gate_enter() {\n        return 0;\n    }\n",
            root_fn: "sched_process_exit",
            gated_call: "sched_process_exit_impl",
        },
        Root {
            file: "journal_roots.rs",
            text: &roots_rs,
            anchor: "pub fn p11_return_journal(ctx: RetProbeContext) -> u32 {\n        keep_endpoint_stack(&ctx);\n        if !stop_gate_enter() {\n            return 0;\n        }\n",
            block: "        if !stop_gate_enter() {\n            return 0;\n        }\n",
            root_fn: "p11_return_journal",
            gated_call: "p11_return_impl",
        },
    ];
    for root in &roots {
        assert!(
            root_gates_before_call(root.text, root.root_fn, root.gated_call),
            "{} {} returns before its gated call when admission fails",
            root.file,
            root.root_fn
        );
    }
    // Both lifecycle impls actually reach cleanup: without that, the
    // gate pin above would hold vacuously.
    for (impl_fn, next_fn) in [
        ("fn sched_process_exec_impl", "fn sched_process_exit"),
        ("fn sched_process_exit_impl", "fn cookie_of"),
    ] {
        let start = main_rs.find(impl_fn).expect("lifecycle impl");
        let tail = &main_rs[start..];
        let end = tail[impl_fn.len()..].find(next_fn).expect("impl end") + impl_fn.len();
        assert!(
            tail[..end].contains("p11_owner_cleanup()"),
            "{impl_fn} reaches cleanup"
        );
    }
    // The journal return pin holds non-vacuously too: the gated return
    // reaches native returning through `complete`.
    assert!(
        main_rs.contains("journal_roots::program::complete("),
        "the gated return reaches journal completion"
    );
    let complete_at = roots_rs
        .find("pub(crate) unsafe fn complete(")
        .expect("complete fn");
    let complete_tail = &roots_rs[complete_at..];
    let complete_end = complete_tail
        .find("pub(crate) fn ordinary_return")
        .expect("complete end");
    assert!(
        complete_tail[..complete_end].contains("p11_journal_returning(key, &mut words)"),
        "completion reaches native returning"
    );
    // Negative controls, one triple per root: a bypassed gate (the
    // admission block removed), a disconnected condition (`&& false`:
    // every token present, the verdict unused) and an inverted
    // condition (returns when ADMITTED). Whole-file gate presence
    // stays green on every mutant; the per-root pin must reject the
    // mutated root while its siblings still gate.
    let mut accepted = Vec::new();
    for root in &roots {
        assert_eq!(
            root.text.matches(root.anchor).count(),
            1,
            "{} {} gate anchor",
            root.file,
            root.root_fn
        );
        assert_eq!(
            root.anchor.matches(root.block).count(),
            1,
            "{} {} gate block anchor",
            root.file,
            root.root_fn
        );
        let mutants = [
            ("bypass", root.anchor.replace(root.block, "")),
            (
                "disconnected",
                root.anchor.replace(
                    "if !stop_gate_enter() {",
                    "if !stop_gate_enter() && false {",
                ),
            ),
            (
                "inverted",
                root.anchor
                    .replace("if !stop_gate_enter() {", "if stop_gate_enter() {"),
            ),
        ];
        for (kind, anchor) in &mutants {
            assert_ne!(
                anchor, root.anchor,
                "{} {} {kind} mutant differs",
                root.file, root.root_fn
            );
            let mutant = root.text.replacen(root.anchor, anchor, 1);
            assert!(
                mutant.contains("stop_gate_enter()"),
                "{} {} {kind} keeps gates elsewhere: whole-file presence stays green",
                root.file,
                root.root_fn
            );
            if root_gates_before_call(&mutant, root.root_fn, root.gated_call) {
                accepted.push(format!("{} {} {kind}", root.file, root.root_fn));
            }
            for sibling in &roots {
                let text = if sibling.file == root.file && sibling.root_fn != root.root_fn {
                    &mutant
                } else if sibling.root_fn == root.root_fn {
                    continue;
                } else {
                    sibling.text
                };
                assert!(
                    root_gates_before_call(text, sibling.root_fn, sibling.gated_call),
                    "{} {} {kind}: sibling {} still gates (control)",
                    root.file,
                    root.root_fn,
                    sibling.root_fn
                );
            }
        }
    }
    assert!(
        accepted.is_empty(),
        "mutants the pin accepts (must reject all):\n{}",
        accepted.join("\n")
    );
}

/// Causal mutants against the linked native producer: each mutation is
/// compiled into the actual fixture binary and must turn a passing run
/// red. Source-text presence alone proves none of these orderings.
#[test]
fn object_journal_producer_mutants_are_causal() {
    use std::process::Command;
    let source = std::fs::read_to_string("crates/ebpf/native/object_journal.c")
        .expect("read native journal");
    let work = tempfile::tempdir().expect("mutant work directory");
    // (label, mutation, journal define, fixture argument). The flag
    // selects journal-enabled native code, which the proof and
    // production journal selections share — never "production" alone.
    type MutantCase<'a> = (&'a str, Option<(&'a str, &'a str)>, bool, Option<&'a str>);
    let cases: [MutantCase<'_>; 5] = [
        ("control-combined", None, false, None),
        ("control-producer", None, true, Some("producer")),
        (
            "finish-ignores-cleanup",
            Some((
                "    if (cleanup_committed != 1) {",
                "    if (cleanup_committed == 99U) {",
            )),
            true,
            Some("producer"),
        ),
        (
            "owner-bind-dropped",
            Some((
                "    return owner && key && owner->flags == OWNER_LEASED &&\n        key->pid_tgid == owner->original_pid_tgid;",
                "    return owner && key;",
            )),
            false,
            None,
        ),
        (
            "header-reserved-poisoned",
            Some(("    out[6] = 0;", "    out[6] = 1;")),
            false,
            None,
        ),
    ];
    for (index, (label, mutant, journal, argument)) in cases.into_iter().enumerate() {
        let directory = work.path().join(index.to_string());
        std::fs::create_dir(&directory).unwrap();
        for file in ["task_owner.c", "task_owner.h", "object_journal.h"] {
            std::fs::copy(
                std::path::Path::new("crates/ebpf/native").join(file),
                directory.join(file),
            )
            .unwrap();
        }
        let native = if let Some((before, after)) = mutant {
            assert_eq!(source.matches(before).count(), 1, "{label} mutation anchor");
            source.replace(before, after)
        } else {
            source.clone()
        };
        std::fs::write(directory.join("object_journal.c"), native).unwrap();
        let binary = directory.join("fixture");
        let mut compiler = Command::new("clang-18");
        compiler.args(["-O2", "-g", "-Wall", "-Wextra", "-Werror", "-pthread"]);
        if journal {
            compiler.arg("-DP11SCOPE_OBJECT_JOURNAL");
        }
        compiler
            .arg("-I")
            .arg(&directory)
            .arg("tests/fixtures/object-journal/journal_owner_tests.c")
            .arg("-o")
            .arg(&binary);
        let output = compiler.output().expect("compile mutant fixture");
        assert!(
            output.status.success(),
            "{label} compile: {}",
            String::from_utf8_lossy(&output.stderr)
        );
        let mut run = Command::new(&binary);
        if let Some(argument) = argument {
            run.arg(argument);
        }
        let output = run.output().expect("run mutant fixture");
        assert_eq!(
            output.status.success(),
            mutant.is_none(),
            "{label}: {}",
            String::from_utf8_lossy(&output.stderr)
        );
    }
}
