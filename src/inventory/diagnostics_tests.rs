//! SPDX-License-Identifier: GPL-3.0-or-later
use super::*;
use crate::attach::capture::NativeDomainId;

fn config(ordinary_capacity: usize, exceptional_capacity: usize) -> DiagnosticConfig {
    DiagnosticConfig {
        ordinary_capacity,
        exceptional_capacity,
        ..DiagnosticConfig::default()
    }
}
fn observation(count: u64) -> DiagnosticRecord {
    let mut record = DiagnosticRecord::new(DiagnosticKind::CountObservation);
    record.absolute = Some(count);
    record
}
fn exceptional() -> DiagnosticRecord {
    let mut record = DiagnosticRecord::new(DiagnosticKind::CountDecision);
    record.decision = Some(Decision::Withheld);
    record.reason = Some(DiagnosticReason::OwnershipTransition);
    record
}
fn outcome() -> DiagnosticOutcome {
    DiagnosticOutcome {
        capture_outcome: CaptureOutcome::Completed,
        capture_settlement: CaptureSettlement::Settled,
    }
}
struct NoLabels;
impl RetainedIdentityView for NoLabels {
    fn application(&self, _: u32) -> Option<&str> {
        None
    }
    fn module(&self, _: u32) -> Option<&str> {
        None
    }
}
fn export(recorder: Recorder) -> (Vec<serde_json::Value>, DiagnosticSummary) {
    let mut bytes = Vec::new();
    let summary = recorder
        .finish(outcome())
        .write_jsonl(&mut bytes, &NoLabels, || false)
        .unwrap();
    let lines = bytes
        .split(|byte| *byte == b'\n')
        .filter(|line| !line.is_empty())
        .map(|line| serde_json::from_slice(line).unwrap())
        .collect();
    (lines, summary)
}
#[test]
fn both_rings_roll_and_ordinary_flood_preserves_recent_transition() {
    let mut recorder = Recorder::try_new(config(2, 2)).unwrap();
    for _ in 0..3 {
        recorder.record(exceptional());
    }
    for count in 0..9 {
        recorder.record(observation(count));
    }
    assert_eq!(recorder.exceptional.records.len(), 2);
    assert_eq!(recorder.ordinary.records.len(), 2);
    let (lines, summary) = export(recorder);
    let sequences: Vec<_> = lines
        .iter()
        .filter_map(|line| line["seq"].as_u64())
        .collect();
    assert_eq!(sequences, [2, 3, 11, 12]);
    assert_eq!(
        summary.kinds[DiagnosticKind::CountDecision as usize].evicted,
        1
    );
    assert_eq!(
        summary.kinds[DiagnosticKind::CountObservation as usize].evicted,
        7
    );
}
#[test]
fn unchanged_polling_and_repeated_refusal_do_not_fill_rings() {
    let mut recorder = Recorder::try_new(config(2, 2)).unwrap();
    assert_eq!(recorder.record_changed(None, observation(5)), Some(1));
    for _ in 0..100 {
        assert_eq!(recorder.record_changed(Some(5), observation(5)), None);
        recorder.note_reason(DiagnosticReason::StaleObservation);
    }
    assert_eq!(recorder.ordinary.records.len(), 1);
    assert_eq!(
        recorder.summary.reasons[DiagnosticReason::StaleObservation as usize],
        100
    );
}
#[test]
fn retained_late_pair_correlates_without_exposing_native_keys() {
    let mut recorder = Recorder::try_new(config(2, 2)).unwrap();
    let old_pair = NativePairKey::new(DomainCookie::new(NativeDomainId::mint(), 7), 8, 9);
    for count in 0..10 {
        recorder.record(observation(count).with_pair(old_pair));
    }
    let raw = 987654321234567890;
    let image = DomainCookie::new(NativeDomainId::mint(), raw);
    let pair = NativePairKey::new(image, raw, 123456789);
    for count in 10..12 {
        let mut record =
            observation(count)
                .with_pair(pair)
                .with_private_ids(Some(raw), Some(raw), Some(raw));
        record.caller = Some(77);
        record.pid = Some(77);
        recorder.record(record);
    }
    let (lines, _) = export(recorder);
    let data: Vec<_> = lines
        .iter()
        .filter(|line| line["seq"].is_number())
        .collect();
    assert_eq!(data.len(), 2);
    assert_eq!(data[0]["pair"], data[1]["pair"]);
    assert_eq!(data[0]["caller"], "c77");
    assert_eq!(data[1]["caller"], "c77");
    let text = serde_json::to_string(&lines).unwrap();
    assert!(!text.contains(&raw.to_string()));
    assert!(!text.contains("123456789"));
    assert!(!text.contains("task_cookie"));
}

#[test]
fn filter_keeps_global_health_and_does_not_guess_missing_reference_cause() {
    let mut recorder = Recorder::try_new(DiagnosticConfig {
        pid_filter: Some(42),
        ..config(2, 2)
    })
    .unwrap();
    // An observation can be unbound until a later decision knows its PID.
    let excluded = observation(1);
    let observation_ref = recorder.record(excluded).unwrap();
    let mut included = exceptional();
    included.pid = Some(42);
    included.observation_ref = Some(observation_ref);
    recorder.record(included);
    recorder.record(DiagnosticRecord::new(DiagnosticKind::CaptureHealth));
    let (lines, summary) = export(recorder);
    assert_eq!(
        summary.kinds[DiagnosticKind::CountObservation as usize].filtered,
        1
    );
    assert_eq!(lines[1]["observation_ref"]["status"], "not_retained");
    assert_eq!(lines[1]["history_complete"], false);
    assert_eq!(lines[2]["kind"], "capture_health");
    assert_eq!(lines.last().unwrap()["diagnostics_complete"], true);
}
#[test]
fn raw_scalar_ids_are_scoped_to_pairs_and_domains() {
    let mut recorder = Recorder::try_new(config(4, 2)).unwrap();
    let first = DomainCookie::new(NativeDomainId::mint(), 9);
    let other = DomainCookie::new(NativeDomainId::mint(), 9);
    for image in [first, other] {
        recorder.record(
            observation(3)
                .with_pair(NativePairKey::new(image, 11, 7))
                .with_private_ids(Some(5), Some(5), Some(5)),
        );
    }
    let (lines, _) = export(recorder);
    assert_ne!(lines[1]["pair"], lines[2]["pair"]);
    assert_ne!(lines[1]["read"], lines[2]["read"]);
    assert_ne!(lines[1]["epoch"], lines[2]["epoch"]);
    assert_ne!(lines[1]["pending"], lines[2]["pending"]);
}
#[test]
fn actual_sizes_and_all_simultaneous_allocations_fit_the_bound() {
    assert!(size_of::<DiagnosticRecord>() <= 384);
    let (recorder, allocations, bytes) = crate::test_alloc::count_allocs_during(|| {
        Recorder::try_new(DiagnosticConfig::default()).unwrap()
    });
    assert_eq!(allocations, 6);
    assert_eq!(recorder.heap_bytes(), bytes);
    assert!(bytes + SCRATCH_BYTES <= MAX_HEAP_BYTES);
    assert_eq!(recorder.ordinary.records.capacity(), ORDINARY_CAPACITY);
    assert_eq!(
        recorder.exceptional.records.capacity(),
        EXCEPTIONAL_CAPACITY
    );
    assert_eq!(recorder.indexes.pairs.capacity(), MAX_RECORDS);
    let (_, hot_allocations, _) = crate::test_alloc::count_allocs_during(|| {
        let mut recorder = recorder;
        for count in 0..100_000 {
            recorder.record(observation(count));
        }
        recorder
    });
    assert_eq!(hot_allocations, 0);
}
#[test]
fn invalid_limits_and_each_allocation_failure_return_typed_error() {
    assert!(matches!(
        Recorder::try_new(config(0, 1)),
        Err(InitError::InvalidLimits)
    ));
    assert!(matches!(
        Recorder::try_new(config(ORDINARY_CAPACITY + 1, 1)),
        Err(InitError::InvalidLimits)
    ));
    for failure in 0..6 {
        let mut remaining = failure;
        let result = Recorder::try_new_with_allocation_check(config(2, 2), |_: usize| {
            if remaining == 0 {
                false
            } else {
                remaining -= 1;
                true
            }
        });
        assert!(matches!(result, Err(InitError::AllocationRefused)));
    }
}
#[test]
fn counters_saturate_and_sequence_exhaustion_stops_recording() {
    let mut recorder = Recorder::try_new(config(2, 2)).unwrap();
    recorder.summary.reasons[DiagnosticReason::StaleObservation as usize] = u64::MAX;
    recorder.note_reason(DiagnosticReason::StaleObservation);
    assert!(recorder.summary.counter_overflow);
    recorder.next_seq = u64::MAX;
    assert_eq!(recorder.record(observation(5)), Some(u64::MAX));
    assert_eq!(recorder.record(observation(6)), None);
    assert!(recorder.summary.sequence_exhausted);
    assert!(!recorder.summary.diagnostics_complete);
}
struct Labels<'a> {
    application: &'a str,
    module: &'a str,
}
impl RetainedIdentityView for Labels<'_> {
    fn application(&self, _: u32) -> Option<&str> {
        Some(self.application)
    }
    fn module(&self, _: u32) -> Option<&str> {
        Some(self.module)
    }
}
#[test]
fn unicode_and_controls_are_safe_truncated_and_streamed_with_no_export_allocation() {
    let mut recorder = Recorder::try_new(config(2, 2)).unwrap();
    let mut record = observation(5);
    record.caller = Some(1);
    record.module = Some(2);
    recorder.record(record);
    let label = format!(
        "{}{}",
        "界".repeat(40),
        "\u{0001}secret-shaped trailing suffix"
    );
    let mut storage = [0u8; 16384];
    let mut writer = io::Cursor::new(&mut storage[..]);
    let labels = Labels {
        application: &label,
        module: "mod\n\t\u{007f}\\\"",
    };
    let (result, allocations, _) = crate::test_alloc::count_allocs_during(|| {
        recorder
            .finish(outcome())
            .write_jsonl(&mut writer, &labels, || false)
    });
    let summary = result.unwrap();
    assert_eq!(allocations, 0);
    let bytes = &storage[..summary.bytes_written as usize];
    let lines: Vec<serde_json::Value> = bytes
        .split(|byte| *byte == b'\n')
        .filter(|line| !line.is_empty())
        .map(|line| serde_json::from_slice(line).unwrap())
        .collect();
    assert!(lines[1]["application"].as_str().unwrap().len() <= LABEL_BYTES);
    assert_eq!(lines[1]["application_truncated"], true);
    assert!(
        !lines[1]["module"]
            .as_str()
            .unwrap()
            .chars()
            .any(char::is_control)
    );
    assert!(bytes.split(|byte| *byte == b'\n').nth(1).unwrap().len() < MAX_LINE_BYTES);
}
#[test]
fn writer_failure_and_cancellation_propagate_without_retries() {
    struct Broken(usize);
    impl Write for Broken {
        fn write(&mut self, _: &[u8]) -> io::Result<usize> {
            self.0 += 1;
            Err(io::Error::other("full"))
        }
        fn flush(&mut self) -> io::Result<()> {
            Ok(())
        }
    }
    let recorder = Recorder::try_new(config(2, 2)).unwrap();
    let mut broken = Broken(0);
    assert!(matches!(
        recorder
            .finish(outcome())
            .write_jsonl(&mut broken, &NoLabels, || false),
        Err(ExportError::Io(_))
    ));
    assert_eq!(broken.0, 1);
    let recorder = Recorder::try_new(config(2, 2)).unwrap();
    let mut bytes = Vec::new();
    assert!(matches!(
        recorder
            .finish(outcome())
            .write_jsonl(&mut bytes, &NoLabels, || true),
        Err(ExportError::Cancelled)
    ));
    assert!(bytes.is_empty());
}

#[test]
fn same_hash_distinct_native_keys_do_not_join() {
    let image = DomainCookie::new(NativeDomainId::mint(), 3);
    let first = NativePairKey::new(image, 1, 1);
    let second = NativePairKey::new(image, 1, 2);
    let mut indexes = ExportIndexes::try_new(4, &mut |_| true).unwrap();
    indexes.pairs.extend([
        PairIndex {
            key: first,
            hash: 0,
        },
        PairIndex {
            key: second,
            hash: 0,
        },
        PairIndex {
            key: first,
            hash: 0,
        },
        PairIndex {
            key: second,
            hash: 0,
        },
    ]);
    indexes.compact_pairs();
    assert_eq!(indexes.pairs.len(), 2);
    assert_ne!(
        indexes.pair_with_hash(first, 0),
        indexes.pair_with_hash(second, 0)
    );
}
#[test]
fn retained_predecessor_context_is_resolved_but_evicted_context_is_unknown() {
    let mut recorder = Recorder::try_new(config(1, 2)).unwrap();
    let original = recorder.record(observation(3)).unwrap();
    let mut decision = exceptional();
    decision.observation_ref = Some(original);
    recorder.record(decision);
    let (lines, _) = export(recorder);
    assert_eq!(lines[2]["observation_ref"]["status"], "retained");
    assert_eq!(lines[2]["history_complete"], true);
    let mut recorder = Recorder::try_new(config(1, 2)).unwrap();
    let original = recorder.record(observation(3)).unwrap();
    recorder.record(observation(4));
    decision.observation_ref = Some(original);
    recorder.record(decision);
    let (lines, _) = export(recorder);
    assert_eq!(lines[2]["observation_ref"]["status"], "not_retained");
    assert_eq!(lines[2]["context_unavailable"], true);
    assert_eq!(lines[2]["history_complete"], false);
}
#[test]
fn duplicate_labels_keep_distinct_public_identity_and_unknown_labels_are_explicit() {
    let mut recorder = Recorder::try_new(config(3, 2)).unwrap();
    for caller in [1, 2] {
        let mut record = observation(5);
        record.caller = Some(caller);
        record.module = Some(caller);
        record.pid = Some(41 + caller);
        record.incarnation = Some(7);
        recorder.record(record);
    }
    let mut bytes = Vec::new();
    recorder
        .finish(outcome())
        .write_jsonl(
            &mut bytes,
            &Labels {
                application: "same",
                module: "same",
            },
            || false,
        )
        .unwrap();
    let lines: Vec<serde_json::Value> = bytes
        .split(|byte| *byte == b'\n')
        .filter(|line| !line.is_empty())
        .map(|line| serde_json::from_slice(line).unwrap())
        .collect();
    assert_eq!(lines[1]["application"], lines[2]["application"]);
    assert_ne!(lines[1]["caller"], lines[2]["caller"]);
    let mut recorder = Recorder::try_new(config(1, 1)).unwrap();
    recorder.record(observation(6));
    let (lines, _) = export(recorder);
    assert_eq!(lines[1]["application"], "Unknown executable");
    assert_eq!(lines[1]["module"], "Unknown module");
}
#[test]
fn fully_populated_escape_heavy_record_is_bounded_or_explicitly_omitted() {
    let mut recorder = Recorder::try_new(config(1, 1)).unwrap();
    let mut record = exceptional();
    record.caller = Some(u32::MAX);
    record.module = Some(u32::MAX);
    record.pid = Some(u32::MAX);
    record.incarnation = Some(u64::MAX);
    record.absolute = Some(u64::MAX);
    record.base = Some(u64::MAX);
    record.staged = Some(u64::MAX);
    record.after = Some(u64::MAX);
    record.through = Some(u64::MAX);
    record.pre = Some(u64::MAX);
    record.post = Some(u64::MAX);
    record.fence = Some(u64::MAX);
    record.baseline_pre = Some(u64::MAX);
    record.baseline_post = Some(u64::MAX);
    record.edge_total = Some(u64::MAX);
    record.observation_ref = Some(u64::MAX);
    record.transition_ref = Some(u64::MAX);
    recorder.record(record);
    let labels = "\\\"".repeat(48);
    let mut bytes = Vec::new();
    let summary = recorder
        .finish(outcome())
        .write_jsonl(
            &mut bytes,
            &Labels {
                application: &labels,
                module: &labels,
            },
            || false,
        )
        .unwrap();
    let lines: Vec<_> = bytes
        .split(|byte| *byte == b'\n')
        .filter(|line| !line.is_empty())
        .collect();
    for line in &lines {
        let _: serde_json::Value = serde_json::from_slice(line).unwrap();
    }
    for line in lines.iter().skip(1).take(lines.len() - 2) {
        assert!(line.len() < MAX_LINE_BYTES);
    }
    assert_eq!(summary.records_written + summary.oversized_records, 1);
    assert_eq!(
        summary.kinds[DiagnosticKind::CountDecision as usize].omitted,
        summary.oversized_records
    );
}
