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

/// Slice-A inactive custody: the native lifetime words, JOURNAL_START
/// side-map and ring-leaf skeleton compile for every object flavor and
/// the actual native-owner fixture passes unprivileged. The producer
/// that would call this stays inactive: no live root wires these
/// leaves.
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
/// ORDERING, not names. Nothing at or below the combined level
/// discards (the only discard call in this file is the leaf's own ring
/// delegation; the root — outside this file — raises the checked fault
/// before every discard, proven at runtime by the fixture's
/// checked-generation hooks). Each combined transaction instead reports
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
    // N8: no discard call site anywhere below the root. The leaf's own
    // ring delegation is the single exception; every other function —
    // combined or helper — must hold zero.
    for (name, body) in &functions {
        for (number, text) in body {
            if !(text.starts_with("p11_journal_discard(")
                || text.starts_with("journal_ring_discard("))
            {
                continue;
            }
            assert_eq!(
                name, "p11_journal_discard",
                "discard site in {name} (line {number}): nothing below the root discards",
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

/// Slice-A custody stays inactive: no live BPF root wires the journal
/// transaction leaves until slice B authorizes the transactions. The
/// slice-D birth marker globals are live (wired from the exec, entry
/// and return roots through `p11_instance_*` names that carry none of
/// these literals); only the transaction set below stays unwired. The
/// ban covers the whole file text, including comments and extern names,
/// so marker call sites must keep those words out of their spellings.
#[test]
fn object_journal_leaves_are_inactive() {
    for program in ["main.rs", "inventory.rs", "inventory_callers.rs"] {
        let path = format!("crates/ebpf/src/{program}");
        let source = std::fs::read_to_string(&path).expect("read BPF program");
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
                "{program} must not wire inactive journal custody ({symbol})"
            );
        }
    }
}

/// H8-D atomic birth marker: the native publication/dirty/readback/
/// admission implementation compiles and its actual fixture passes
/// unprivileged. The producer that would call this stays inactive: no
/// live root wires these leaves.
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
    let binding = "let journal_marker = ";
    let predicates: Vec<&&str> = lines
        .iter()
        .filter(|line| line.trim_start().starts_with(binding))
        .collect();
    assert_eq!(
        predicates.len(),
        1,
        "the marker build must share one predicate"
    );
    assert!(
        predicates[0].contains("BpfFlavor::Detailed") && predicates[0].contains("!bank_proof"),
        "the shared gate must select Detailed non-bank builds: {}",
        predicates[0]
    );
    for anchor in [
        "selected_native_units.push(\"journal_marker\")",
        "\"-DP11SCOPE_JOURNAL_MARKER\"",
        "\"link-arg=--export=p11_instance_scope_gap\"",
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
}

/// H8-D marker drop arms: every silent in-scope drop arm calls the scope
/// gap at its own site, not just somewhere in its root. The entry ABI
/// refusals, the entry identity and START failures, the return ABI
/// refusal and missing START, and the three in-halves lost-call arms
/// (ordinary identity mismatch, ordinary ring loss, object ring loss
/// with settled removal) each name their arm; deleting any one call
/// fails. The refused-base output-loss arm instead runs the shared
/// fault callback before attempting output, so it already refuses births.
/// The halves keep their gaps in place. E2/R2 are covered live, and the
/// fault-only object arms are a different row class.
#[test]
fn object_journal_marker_drop_arms_call_the_gap() {
    const GAP: &str = "p11_instance_scope_gap();";
    let source = std::fs::read_to_string("crates/ebpf/src/main.rs").expect("read BPF roots");
    let lines: Vec<&str> = source.lines().collect();
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
    let object_at = lines
        .iter()
        .position(|line| line.starts_with("fn object_return("))
        .expect("object half");
    let fork_at = lines
        .iter()
        .position(|line| line.starts_with("pub extern \"C\" fn p11_link_fork_allowed"))
        .expect("halves end");
    let entry = &lines[entry_at..return_at];
    let returned = &lines[return_at..accounting_at];
    let ordinary = &lines[ordinary_at..object_at];
    let object = &lines[object_at..fork_at];
    let refused_at = object
        .iter()
        .position(|line| line.trim() == "if !joined {")
        .expect("refused object continuity arm");
    assert_eq!(
        object
            .iter()
            .filter(|line| line.contains("bump_evidence(EVIDENCE_RING_LOSS);"))
            .count(),
        2,
        "both object ring-loss arms need their own birth-refusal accounting"
    );
    assert!(refused_base_ring_loss_is_fault_covered(&object.join("\n")));
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

fn refused_base_ring_loss_is_fault_covered(object: &str) -> bool {
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
    let fault = "preserve_refused_base(||owned_start_remove(&key,true).is_ok(),||unsafe{p11_object_fault()},";
    let output = "||EVENTS.output::<EventRecord>(unsafe{&(*raw).base},0).is_ok(),";
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
    let (_, object) = source.split_once("fn object_return(").expect("object half");
    let (object, _) = object
        .split_once("pub extern \"C\" fn p11_link_fork_allowed")
        .expect("object half end");
    assert!(refused_base_ring_loss_is_fault_covered(object));
    for (before, after) in [
        ("|| unsafe { p11_object_fault() },", "|| {},"),
        (
            "RefusedBaseOutcome::OutputFailed",
            "RefusedBaseOutcome::Emitted",
        ),
        ("            bump_evidence(EVIDENCE_RING_LOSS);", ""),
    ] {
        let (head, refused) = object.split_once("if !joined {").expect("refused arm");
        assert!(
            refused.contains(before),
            "mutant must change the refused arm"
        );
        let mutant = format!("{head}if !joined {{ {}", refused.replacen(before, after, 1));
        assert!(
            !refused_base_ring_loss_is_fault_covered(&mutant),
            "the refused-base loss guard must reject mutation of {before}"
        );
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
/// path; dropping it gaps spuriously on the fault path. The pin holds
/// the exact `bump -> cfg -> if !failed -> gap` block, and both mutants
/// fail it.
#[test]
fn object_journal_object_ring_loss_gap_requires_settled_guard() {
    const GAP: &str = "p11_instance_scope_gap();";
    const CFG: &str = "#[cfg(not(feature = \"counter-broad\"))]";
    const GUARD: &str = "if !failed {";
    let source = std::fs::read_to_string("crates/ebpf/src/main.rs").expect("read BPF roots");
    let lines: Vec<&str> = source.lines().collect();
    let object_at = lines
        .iter()
        .position(|line| line.starts_with("fn object_return("))
        .expect("object half");
    let fork_at = lines
        .iter()
        .position(|line| line.starts_with("pub extern \"C\" fn p11_link_fork_allowed"))
        .expect("halves end");
    let object = &lines[object_at..fork_at];
    let bump_at = object
        .iter()
        .position(|line| line.trim().contains("bump_evidence(EVIDENCE_RING_LOSS);"))
        .expect("object ring-loss bump");
    let window = &object[bump_at + 1..(bump_at + 9).min(object.len())];
    let trimmed: Vec<&str> = window.iter().map(|line| line.trim()).collect();
    let cfg_at = trimmed
        .iter()
        .position(|line| *line == CFG)
        .expect("object ring-loss gap keeps its counter-broad cfg");
    let guard_at = trimmed
        .iter()
        .position(|line| *line == GUARD)
        .expect("object ring-loss gap needs its `if !failed` guard");
    let gap_at = window
        .iter()
        .position(|line| line.contains(GAP))
        .expect("object ring-loss gap call");
    assert!(
        cfg_at < guard_at && guard_at < gap_at,
        "the object ring-loss arm must read bump -> cfg -> `if !failed` -> gap"
    );
    assert!(
        !trimmed
            .iter()
            .any(|line| *line == "if failed {" || line.starts_with("if failed ")),
        "the object ring-loss guard must not be the flipped `if failed`"
    );
}

/// H8-D birth marker wiring: only the Detailed object carries the
/// control map and the two marker globals; inventory and counter
/// objects carry neither; no built object carries a transaction
/// symbol (a linked transaction leaf would add its map or a
/// `p11_journal_*` function). Counter objects are checked when this
/// build produced them; every class present checks a nonzero
/// object count, so the test cannot pass with an empty selection.
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
        ("detailed", detailed.as_slice(), true),
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
