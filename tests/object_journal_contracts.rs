//! SPDX-License-Identifier: GPL-3.0-or-later
//! H8 journal wire contracts: exact BEGIN/END/ABANDON layouts, finite
//! validators, compact/full equivalence and rejection of every malformed
//! combination. Drives only the public shared wire API; the producer that
//! mints these bytes stays inactive.

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

/// Minimal valid neutral BEGIN: C_Sign descriptor on the no-row path with
/// all-zero requested lists and a VALUE session.
fn valid_neutral_begin() -> [u8; JOURNAL_BEGIN_BYTES] {
    let mut bytes = valid_begin();
    let sign = kinds::function_id("C_Sign").expect("catalog has C_Sign") + 1;
    put_u32(&mut bytes, 108, sign);
    bytes[128..200].fill(0);
    bytes
}
