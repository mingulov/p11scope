//! SPDX-License-Identifier: GPL-3.0-or-later
//! Optional bounded copies of inventory decisions. This module never decides attribution.

use crate::attach::capture::DomainCookie;
use serde::Serialize;
use std::collections::hash_map::DefaultHasher;
use std::hash::{Hash, Hasher};
use std::io::{self, Write};
use std::mem::size_of;

pub(crate) const SCHEMA: &str = "p11scope/inventory-diagnostics/v1";
pub(crate) const ORDINARY_CAPACITY: usize = 24_576;
pub(crate) const EXCEPTIONAL_CAPACITY: usize = 8_192;
#[cfg(test)]
pub(crate) const MAX_RECORDS: usize = ORDINARY_CAPACITY + EXCEPTIONAL_CAPACITY;
pub(crate) const MAX_HEAP_BYTES: usize = 16 * 1024 * 1024;
pub(crate) const MAX_LINE_BYTES: usize = 1_800;
pub(crate) const SCRATCH_BYTES: usize = 8 * 1024;
pub(crate) const MAX_FILE_BYTES: u64 = 64 * 1024 * 1024;
const FOOTER_RESERVE: u64 = 64 * 1024;
const LABEL_BYTES: usize = 96;
const KIND_COUNT: usize = 5;
const REASON_COUNT: usize = 18;

macro_rules! vocabulary {
    ($name:ident { $($variant:ident),+ $(,)? }) => {
        #[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize)]
        #[serde(rename_all = "snake_case")]
        pub(crate) enum $name { $($variant),+ }
    };
}
vocabulary!(DiagnosticKind {
    CountObservation,
    OwnershipTransition,
    CountDecision,
    Publication,
    CaptureHealth
});
vocabulary!(DiagnosticReason {
    SoleOwner,
    SharedOwner,
    OwnershipUnknown,
    OwnershipTransition,
    BindingUnproven,
    IdentityChanged,
    ScanIncomplete,
    AwaitingFence,
    StaleObservation,
    PendingPublication,
    StaleDecision,
    NotAdmitted,
    CountInvalid,
    BudgetRefused,
    CaptureLoss,
    CaptureStopped,
    NativeUnavailable,
    ContextUnavailable
});
vocabulary!(ReadOrigin { Initial, Refresh });
vocabulary!(Decision {
    Staged,
    Placed,
    Rejected,
    Withheld,
    Pending
});
vocabulary!(Eligibility {
    SoleOwner,
    SharedOwner,
    Unknown,
    Unproven
});
vocabulary!(CaptureOutcome {
    Completed,
    Stopped,
    Failed,
    NativeUnavailable
});
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub(crate) enum CaptureSettlement {
    // Reserved schema value. Current capture cannot prove application quiescence.
    #[cfg_attr(not(test), expect(dead_code, reason = "reserved settlement contract"))]
    Settled,
    Unsettled,
    Unavailable,
}
vocabulary!(CaptureMode { Native, Auto });
vocabulary!(DiagnosticScope {
    System,
    Pid,
    Cgroup
});

/// Domain-tagged native identity remains opaque and is never formatted or serialized.
#[derive(Clone, Copy, PartialEq, Eq, Hash)]
pub(crate) struct NativePairKey {
    image: DomainCookie,
    exec: u64,
    object: u32,
}
impl NativePairKey {
    pub(crate) fn new(image: DomainCookie, exec: u64, object: u32) -> Self {
        Self {
            image,
            exec,
            object,
        }
    }
}

/// Finite, constant-size production projection; no strings, ownership pins or catalogs.
/// The private IDs below are only inputs to capture-local export indexes.
#[derive(Clone, Copy)]
pub(crate) struct DiagnosticRecord {
    seq: u64,
    export_omitted: bool,
    pub(crate) kind: DiagnosticKind,
    pub(crate) reason: Option<DiagnosticReason>,
    pair: Option<NativePairKey>,
    read: Option<u64>,
    epoch: Option<u64>,
    pending: Option<u64>,
    pub(crate) pid: Option<u32>,
    pub(crate) incarnation: Option<u64>,
    pub(crate) caller: Option<u32>,
    pub(crate) module: Option<u32>,
    pub(crate) origin: Option<ReadOrigin>,
    pub(crate) decision: Option<Decision>,
    pub(crate) prior_eligibility: Option<Eligibility>,
    pub(crate) new_eligibility: Option<Eligibility>,
    pub(crate) absolute: Option<u64>,
    pub(crate) base: Option<u64>,
    pub(crate) staged: Option<u64>,
    pub(crate) after: Option<u64>,
    pub(crate) through: Option<u64>,
    pub(crate) pre: Option<u64>,
    pub(crate) post: Option<u64>,
    pub(crate) fence: Option<u64>,
    pub(crate) baseline_pre: Option<u64>,
    pub(crate) baseline_post: Option<u64>,
    pub(crate) edge_total: Option<u64>,
    pub(crate) observation_ref: Option<u64>,
    pub(crate) transition_ref: Option<u64>,
    pub(crate) context_unavailable: bool,
}
impl DiagnosticRecord {
    pub(crate) fn new(kind: DiagnosticKind) -> Self {
        Self {
            seq: 0,
            export_omitted: false,
            kind,
            reason: None,
            pair: None,
            read: None,
            epoch: None,
            pending: None,
            pid: None,
            incarnation: None,
            caller: None,
            module: None,
            origin: None,
            decision: None,
            prior_eligibility: None,
            new_eligibility: None,
            absolute: None,
            base: None,
            staged: None,
            after: None,
            through: None,
            pre: None,
            post: None,
            fence: None,
            baseline_pre: None,
            baseline_post: None,
            edge_total: None,
            observation_ref: None,
            transition_ref: None,
            context_unavailable: false,
        }
    }
    pub(crate) fn with_pair(mut self, pair: NativePairKey) -> Self {
        self.pair = Some(pair);
        self
    }
    pub(crate) fn with_private_ids(
        mut self,
        read: Option<u64>,
        epoch: Option<u64>,
        pending: Option<u64>,
    ) -> Self {
        self.read = read;
        self.epoch = epoch;
        self.pending = pending;
        self
    }
    fn exceptional(self) -> bool {
        matches!(
            self.kind,
            DiagnosticKind::OwnershipTransition | DiagnosticKind::CaptureHealth
        ) || matches!(
            self.decision,
            Some(Decision::Rejected | Decision::Withheld | Decision::Pending)
        )
    }
}

#[derive(Clone, Copy)]
pub(crate) struct DiagnosticConfig {
    pub(crate) pid_filter: Option<u32>,
    pub(crate) ordinary_capacity: usize,
    pub(crate) exceptional_capacity: usize,
    pub(crate) mode: CaptureMode,
    pub(crate) scope: DiagnosticScope,
}
impl Default for DiagnosticConfig {
    fn default() -> Self {
        Self {
            pid_filter: None,
            ordinary_capacity: ORDINARY_CAPACITY,
            exceptional_capacity: EXCEPTIONAL_CAPACITY,
            mode: CaptureMode::Native,
            scope: DiagnosticScope::System,
        }
    }
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum InitError {
    InvalidLimits,
    AllocationRefused,
    HeapLimit,
}
#[derive(Clone, Copy, Serialize)]
pub(crate) struct DiagnosticOutcome {
    pub(crate) capture_outcome: CaptureOutcome,
    pub(crate) capture_settlement: CaptureSettlement,
}
#[derive(Clone, Copy, Default, Debug, Serialize)]
pub(crate) struct KindCounts {
    pub(crate) produced: u64,
    pub(crate) retained: u64,
    pub(crate) evicted: u64,
    pub(crate) filtered: u64,
    pub(crate) omitted: u64,
}
#[derive(Clone, Copy, Debug, Serialize)]
pub(crate) struct DiagnosticSummary {
    pub(crate) kinds: [KindCounts; KIND_COUNT],
    pub(crate) reasons: [u64; REASON_COUNT],
    pub(crate) counter_overflow: bool,
    pub(crate) sequence_exhausted: bool,
    pub(crate) diagnostics_complete: bool,
    pub(crate) records_written: u64,
    pub(crate) bytes_written: u64,
    pub(crate) oversized_records: u64,
    pub(crate) retained_spans: [Option<SequenceSpan>; 2],
}
impl Default for DiagnosticSummary {
    fn default() -> Self {
        Self {
            kinds: [KindCounts::default(); KIND_COUNT],
            reasons: [0; REASON_COUNT],
            counter_overflow: false,
            sequence_exhausted: false,
            diagnostics_complete: true,
            records_written: 0,
            bytes_written: 0,
            oversized_records: 0,
            retained_spans: [None; 2],
        }
    }
}
#[derive(Clone, Copy, Debug, Serialize)]
pub(crate) struct SequenceSpan {
    first: u64,
    last: u64,
}

struct Ring {
    records: Vec<DiagnosticRecord>,
    start: usize,
    limit: usize,
}
impl Ring {
    fn try_new(capacity: usize, check: &mut impl FnMut(usize) -> bool) -> Result<Self, InitError> {
        if !check(capacity * size_of::<DiagnosticRecord>()) {
            return Err(InitError::AllocationRefused);
        }
        let mut records = Vec::new();
        records
            .try_reserve_exact(capacity)
            .map_err(|_| InitError::AllocationRefused)?;
        Ok(Self {
            records,
            start: 0,
            limit: capacity,
        })
    }
    fn at(&self, index: usize) -> Option<&DiagnosticRecord> {
        (index < self.records.len())
            .then(|| &self.records[(self.start + index) % self.records.len()])
    }
    fn push(&mut self, record: DiagnosticRecord) -> Option<DiagnosticRecord> {
        if self.records.len() < self.limit {
            self.records.push(record);
            return None;
        }
        let old = std::mem::replace(&mut self.records[self.start], record);
        self.start = (self.start + 1) % self.records.len();
        Some(old)
    }
}
#[derive(Clone, Copy)]
struct PairIndex {
    key: NativePairKey,
    hash: u64,
}
#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
struct ScopedId {
    pair: u32,
    value: u64,
}
struct ExportIndexes {
    pairs: Vec<PairIndex>,
    reads: Vec<ScopedId>,
    epochs: Vec<ScopedId>,
    pending: Vec<ScopedId>,
}
impl ExportIndexes {
    fn compact_pairs(&mut self) {
        self.pairs.sort_unstable_by_key(|entry| entry.hash);
        let mut used = 0;
        let mut group_start = 0;
        for index in 0..self.pairs.len() {
            let entry = self.pairs[index];
            if used == 0 || self.pairs[used - 1].hash != entry.hash {
                group_start = used;
            }
            if !self.pairs[group_start..used]
                .iter()
                .any(|old| old.key == entry.key)
            {
                self.pairs[used] = entry;
                used += 1;
            }
        }
        self.pairs.truncate(used);
    }
    fn pair_with_hash(&self, key: NativePairKey, hash: u64) -> Option<u32> {
        let start = self.pairs.partition_point(|entry| entry.hash < hash);
        self.pairs[start..]
            .iter()
            .take_while(|entry| entry.hash == hash)
            .position(|entry| entry.key == key)
            .map(|offset| (start + offset + 1) as u32)
    }
    fn pair(&self, key: NativePairKey) -> Option<u32> {
        self.pair_with_hash(key, pair_hash(key))
    }
    fn populate(&mut self, ordinary: &Ring, exceptional: &Ring) {
        for ring in [ordinary, exceptional] {
            for record in &ring.records {
                if let Some(key) = record.pair {
                    self.pairs.push(PairIndex {
                        key,
                        hash: pair_hash(key),
                    });
                }
            }
        }
        self.compact_pairs();
        for ring in [ordinary, exceptional] {
            for record in &ring.records {
                let Some(pair) = record.pair.and_then(|key| self.pair(key)) else {
                    continue;
                };
                if let Some(value) = record.read {
                    self.reads.push(ScopedId { pair, value });
                }
                if let Some(value) = record.epoch {
                    self.epochs.push(ScopedId { pair, value });
                }
                if let Some(value) = record.pending {
                    self.pending.push(ScopedId { pair, value });
                }
            }
        }
        for index in [&mut self.reads, &mut self.epochs, &mut self.pending] {
            index.sort_unstable();
            index.dedup();
        }
    }
    fn scoped(
        index: &[ScopedId],
        pair: Option<u32>,
        value: Option<u64>,
        prefix: &'static str,
    ) -> Option<PublicId> {
        let key = ScopedId {
            pair: pair?,
            value: value?,
        };
        index.binary_search(&key).ok().map(|position| PublicId {
            prefix,
            value: position as u32 + 1,
        })
    }
    fn try_new(capacity: usize, check: &mut impl FnMut(usize) -> bool) -> Result<Self, InitError> {
        fn reserve<T>(
            capacity: usize,
            check: &mut impl FnMut(usize) -> bool,
        ) -> Result<Vec<T>, InitError> {
            if !check(capacity * size_of::<T>()) {
                return Err(InitError::AllocationRefused);
            }
            let mut vector = Vec::new();
            vector
                .try_reserve_exact(capacity)
                .map_err(|_| InitError::AllocationRefused)?;
            Ok(vector)
        }
        Ok(Self {
            pairs: reserve(capacity, check)?,
            reads: reserve(capacity, check)?,
            epochs: reserve(capacity, check)?,
            pending: reserve(capacity, check)?,
        })
    }
    fn heap_bytes(&self) -> usize {
        self.pairs.capacity() * size_of::<PairIndex>()
            + (self.reads.capacity() + self.epochs.capacity() + self.pending.capacity())
                * size_of::<ScopedId>()
    }
}

pub(crate) struct Recorder {
    config: DiagnosticConfig,
    ordinary: Ring,
    exceptional: Ring,
    indexes: ExportIndexes,
    summary: DiagnosticSummary,
    next_seq: u64,
}
impl Recorder {
    pub(crate) fn try_new(config: DiagnosticConfig) -> Result<Self, InitError> {
        Self::try_new_with_allocation_check(config, |_| true)
    }
    fn try_new_with_allocation_check(
        config: DiagnosticConfig,
        mut check: impl FnMut(usize) -> bool,
    ) -> Result<Self, InitError> {
        if config.ordinary_capacity == 0
            || config.exceptional_capacity == 0
            || config.ordinary_capacity > ORDINARY_CAPACITY
            || config.exceptional_capacity > EXCEPTIONAL_CAPACITY
            || config.pid_filter == Some(0)
        {
            return Err(InitError::InvalidLimits);
        }
        let capacity = config.ordinary_capacity + config.exceptional_capacity;
        let requested = capacity
            * (size_of::<DiagnosticRecord>() + size_of::<PairIndex>() + 3 * size_of::<ScopedId>());
        if requested + SCRATCH_BYTES > MAX_HEAP_BYTES {
            return Err(InitError::HeapLimit);
        }
        let recorder = Self {
            config,
            ordinary: Ring::try_new(config.ordinary_capacity, &mut check)?,
            exceptional: Ring::try_new(config.exceptional_capacity, &mut check)?,
            indexes: ExportIndexes::try_new(capacity, &mut check)?,
            summary: DiagnosticSummary::default(),
            next_seq: 1,
        };
        if recorder.heap_bytes() + SCRATCH_BYTES > MAX_HEAP_BYTES {
            return Err(InitError::HeapLimit);
        }
        Ok(recorder)
    }
    pub(crate) fn heap_bytes(&self) -> usize {
        (self.ordinary.records.capacity() + self.exceptional.records.capacity())
            * size_of::<DiagnosticRecord>()
            + self.indexes.heap_bytes()
    }
    /// Assign an observation reference even when the PID filter excludes the record.
    /// A returned sequence proves assignment, not retention or successful delivery.
    pub(crate) fn record(&mut self, mut record: DiagnosticRecord) -> Option<u64> {
        let kind = record.kind as usize;
        increment(
            &mut self.summary.kinds[kind].produced,
            &mut self.summary.counter_overflow,
        );
        if self.summary.counter_overflow {
            self.summary.diagnostics_complete = false;
        }
        if let Some(reason) = record.reason {
            self.note_reason(reason);
        }
        if self.next_seq == 0 {
            increment(
                &mut self.summary.kinds[kind].omitted,
                &mut self.summary.counter_overflow,
            );
            self.summary.diagnostics_complete = false;
            return None;
        }
        record.seq = self.next_seq;
        match self.next_seq.checked_add(1) {
            Some(next) => self.next_seq = next,
            None => {
                self.next_seq = 0;
                self.summary.sequence_exhausted = true;
                self.summary.diagnostics_complete = false;
            }
        }
        if record.kind != DiagnosticKind::CaptureHealth
            && self.config.pid_filter.is_some()
            && record.pid != self.config.pid_filter
        {
            increment(
                &mut self.summary.kinds[kind].filtered,
                &mut self.summary.counter_overflow,
            );
            return Some(record.seq);
        }
        let ring = if record.exceptional() {
            &mut self.exceptional
        } else {
            &mut self.ordinary
        };
        if let Some(old) = ring.push(record) {
            let counts = &mut self.summary.kinds[old.kind as usize];
            match counts.retained.checked_sub(1) {
                Some(value) => counts.retained = value,
                None => self.summary.counter_overflow = true,
            }
            increment(&mut counts.evicted, &mut self.summary.counter_overflow);
        }
        increment(
            &mut self.summary.kinds[kind].retained,
            &mut self.summary.counter_overflow,
        );
        if self.summary.counter_overflow {
            self.summary.diagnostics_complete = false;
        }
        Some(record.seq)
    }
    pub(crate) fn record_changed(
        &mut self,
        previous: Option<u64>,
        record: DiagnosticRecord,
    ) -> Option<u64> {
        if record.kind == DiagnosticKind::CountObservation
            && previous.is_some()
            && previous == record.absolute
        {
            return None;
        }
        self.record(record)
    }
    pub(crate) fn note_reason(&mut self, reason: DiagnosticReason) {
        increment(
            &mut self.summary.reasons[reason as usize],
            &mut self.summary.counter_overflow,
        );
        if self.summary.counter_overflow {
            self.summary.diagnostics_complete = false;
        }
    }
    pub(crate) fn finish(self, outcome: DiagnosticOutcome) -> FinishedDiagnostics {
        FinishedDiagnostics {
            recorder: self,
            outcome,
        }
    }
}
fn increment(counter: &mut u64, overflow: &mut bool) {
    match counter.checked_add(1) {
        Some(value) => *counter = value,
        None => *overflow = true,
    }
}

pub(crate) trait RetainedIdentityView {
    fn application(&self, caller: u32) -> Option<&str>;
    fn module(&self, module: u32) -> Option<&str>;
}
pub(crate) struct FinishedDiagnostics {
    recorder: Recorder,
    outcome: DiagnosticOutcome,
}
#[derive(Debug)]
pub(crate) enum ExportError {
    Io(io::Error),
    Serialization(serde_json::Error),
    Cancelled,
    EnvelopeTooLarge,
}
impl std::fmt::Display for ExportError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Io(error) => write!(f, "{error}"),
            Self::Serialization(error) => write!(f, "{error}"),
            Self::Cancelled => f.write_str("diagnostics export cancelled"),
            Self::EnvelopeTooLarge => f.write_str("diagnostics envelope exceeds byte limit"),
        }
    }
}
impl std::error::Error for ExportError {}
impl FinishedDiagnostics {
    pub(crate) fn write_jsonl(
        mut self,
        writer: &mut impl Write,
        view: &impl RetainedIdentityView,
        mut cancel: impl FnMut() -> bool,
    ) -> Result<DiagnosticSummary, ExportError> {
        if cancel() {
            return Err(ExportError::Cancelled);
        }
        let recorder = &mut self.recorder;
        recorder
            .indexes
            .populate(&recorder.ordinary, &recorder.exceptional);
        let mut scratch = LineBuffer::new();
        let header = Header {
            schema: SCHEMA,
            kind: "header",
            tool_version: env!("CARGO_PKG_VERSION"),
            mode: recorder.config.mode,
            scope: recorder.config.scope,
            pid_filter: recorder.config.pid_filter,
            clock_basis: "monotonic_nanoseconds",
            limits: Limits {
                ordinary_records: recorder.config.ordinary_capacity,
                exceptional_records: recorder.config.exceptional_capacity,
                record_bytes: size_of::<DiagnosticRecord>(),
                heap_bytes: recorder.heap_bytes(),
                max_heap_bytes: MAX_HEAP_BYTES,
                max_data_line_bytes: MAX_LINE_BYTES,
                scratch_bytes: SCRATCH_BYTES,
                max_file_bytes: MAX_FILE_BYTES,
                envelope_reserve_bytes: FOOTER_RESERVE,
                label_input_bytes: LABEL_BYTES,
            },
        };
        if !scratch.serialize(&header, SCRATCH_BYTES)? {
            return Err(ExportError::EnvelopeTooLarge);
        }
        writer
            .write_all(scratch.as_bytes())
            .map_err(ExportError::Io)?;
        recorder.summary.bytes_written = scratch.len as u64;
        recorder.summary.retained_spans = [span(&recorder.ordinary), span(&recorder.exceptional)];
        let mut ordinary_position = 0;
        let mut exceptional_position = 0;
        loop {
            let ordinary = recorder.ordinary.at(ordinary_position);
            let exceptional = recorder.exceptional.at(exceptional_position);
            let ordinary_next = match (ordinary, exceptional) {
                (None, None) => break,
                (Some(_), None) => true,
                (None, Some(_)) => false,
                (Some(left), Some(right)) => left.seq < right.seq,
            };
            if cancel() {
                return Err(ExportError::Cancelled);
            }
            let (record, position) = if ordinary_next {
                let record = *ordinary.expect("selected retained ordinary record");
                let position = ordinary_position;
                ordinary_position += 1;
                (record, position)
            } else {
                let record = *exceptional.expect("selected retained exceptional record");
                let position = exceptional_position;
                exceptional_position += 1;
                (record, position)
            };
            let application = Label::new(
                record
                    .caller
                    .and_then(|id| view.application(id))
                    .unwrap_or("Unknown executable"),
            );
            let module = Label::new(
                record
                    .module
                    .and_then(|id| view.module(id))
                    .unwrap_or("Unknown module"),
            );
            let projection = project(
                &record,
                &recorder.indexes,
                &recorder.ordinary,
                &recorder.exceptional,
                &application,
                &module,
            );
            let fits = scratch.serialize(&projection, MAX_LINE_BYTES)?;
            if !fits
                || recorder.summary.bytes_written + scratch.len as u64
                    > MAX_FILE_BYTES - FOOTER_RESERVE
            {
                let counts = &mut recorder.summary.kinds[record.kind as usize];
                increment(&mut counts.omitted, &mut recorder.summary.counter_overflow);
                if !fits {
                    increment(
                        &mut recorder.summary.oversized_records,
                        &mut recorder.summary.counter_overflow,
                    );
                }
                recorder.summary.diagnostics_complete = false;
                let ring = if ordinary_next {
                    &mut recorder.ordinary
                } else {
                    &mut recorder.exceptional
                };
                let physical = (ring.start + position) % ring.records.len();
                ring.records[physical].export_omitted = true;
                continue;
            }
            writer
                .write_all(scratch.as_bytes())
                .map_err(ExportError::Io)?;
            increment(
                &mut recorder.summary.records_written,
                &mut recorder.summary.counter_overflow,
            );
            recorder.summary.bytes_written += scratch.len as u64;
        }
        if cancel() {
            return Err(ExportError::Cancelled);
        }
        if recorder.summary.counter_overflow {
            recorder.summary.diagnostics_complete = false;
        }
        let before_footer = recorder.summary.bytes_written;
        // The footer includes its own final byte total. Decimal width stabilizes
        // within two refinements; a fixed limit avoids any unbounded iteration.
        for _ in 0..4 {
            let footer = Footer {
                schema: SCHEMA,
                kind: "footer",
                outcome: self.outcome,
                summary: &recorder.summary,
            };
            if !scratch.serialize(&footer, SCRATCH_BYTES)? {
                return Err(ExportError::EnvelopeTooLarge);
            }
            let total = before_footer + scratch.len as u64;
            if total == recorder.summary.bytes_written {
                break;
            }
            recorder.summary.bytes_written = total;
        }
        if recorder.summary.bytes_written != before_footer + scratch.len as u64
            || recorder.summary.bytes_written > MAX_FILE_BYTES
        {
            return Err(ExportError::EnvelopeTooLarge);
        }
        writer
            .write_all(scratch.as_bytes())
            .map_err(ExportError::Io)?;
        Ok(recorder.summary)
    }
}

fn pair_hash(key: NativePairKey) -> u64 {
    let mut hasher = DefaultHasher::new();
    key.hash(&mut hasher);
    hasher.finish()
}
fn span(ring: &Ring) -> Option<SequenceSpan> {
    Some(SequenceSpan {
        first: ring.at(0)?.seq,
        last: ring.at(ring.records.len() - 1)?.seq,
    })
}
fn retained_sequence(ring: &Ring, seq: u64) -> bool {
    let mut left = 0;
    let mut right = ring.records.len();
    while left < right {
        let middle = left + (right - left) / 2;
        let record = ring.at(middle).expect("bounded ring index");
        if record.seq < seq {
            left = middle + 1;
        } else {
            right = middle;
        }
    }
    ring.at(left)
        .is_some_and(|record| record.seq == seq && !record.export_omitted)
}
#[derive(Clone, Copy)]
struct PublicId {
    prefix: &'static str,
    value: u32,
}
impl std::fmt::Display for PublicId {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}{}", self.prefix, self.value)
    }
}
impl Serialize for PublicId {
    fn serialize<S: serde::Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        serializer.collect_str(self)
    }
}
struct Label {
    bytes: [u8; LABEL_BYTES],
    len: usize,
    truncated: bool,
}
impl Label {
    fn new(value: &str) -> Self {
        let mut label = Self {
            bytes: [0; LABEL_BYTES],
            len: 0,
            truncated: false,
        };
        let mut consumed = 0;
        for character in value.chars() {
            if consumed + character.len_utf8() > LABEL_BYTES {
                break;
            }
            consumed += character.len_utf8();
            let mut encoded = [0; 4];
            let text = if character.is_control() {
                "?"
            } else {
                character.encode_utf8(&mut encoded)
            };
            label.bytes[label.len..label.len + text.len()].copy_from_slice(text.as_bytes());
            label.len += text.len();
        }
        label.truncated = consumed < value.len();
        label
    }
    fn as_str(&self) -> &str {
        std::str::from_utf8(&self.bytes[..self.len]).expect("only encoded UTF-8 copied")
    }
}
struct LineBuffer {
    bytes: [u8; SCRATCH_BYTES],
    len: usize,
    limit: usize,
    too_large: bool,
}
impl LineBuffer {
    fn new() -> Self {
        Self {
            bytes: [0; SCRATCH_BYTES],
            len: 0,
            limit: SCRATCH_BYTES,
            too_large: false,
        }
    }
    fn as_bytes(&self) -> &[u8] {
        &self.bytes[..self.len]
    }
    fn serialize(&mut self, value: &impl Serialize, limit: usize) -> Result<bool, ExportError> {
        self.len = 0;
        self.limit = limit;
        self.too_large = false;
        if let Err(error) = serde_json::to_writer(&mut *self, value) {
            if self.too_large {
                return Ok(false);
            }
            return Err(ExportError::Serialization(error));
        }
        if let Err(error) = self.write_all(b"\n") {
            if self.too_large {
                return Ok(false);
            }
            return Err(ExportError::Io(error));
        }
        Ok(true)
    }
}
impl Write for LineBuffer {
    fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
        if bytes.len() > self.limit - self.len {
            self.too_large = true;
            return Err(io::ErrorKind::WriteZero.into());
        }
        self.bytes[self.len..self.len + bytes.len()].copy_from_slice(bytes);
        self.len += bytes.len();
        Ok(bytes.len())
    }
    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}
#[derive(Serialize)]
struct Limits {
    ordinary_records: usize,
    exceptional_records: usize,
    record_bytes: usize,
    heap_bytes: usize,
    max_heap_bytes: usize,
    max_data_line_bytes: usize,
    scratch_bytes: usize,
    max_file_bytes: u64,
    envelope_reserve_bytes: u64,
    label_input_bytes: usize,
}
#[derive(Serialize)]
struct Header {
    schema: &'static str,
    kind: &'static str,
    tool_version: &'static str,
    mode: CaptureMode,
    scope: DiagnosticScope,
    pid_filter: Option<u32>,
    clock_basis: &'static str,
    limits: Limits,
}
#[derive(Serialize)]
struct Footer<'a> {
    schema: &'static str,
    kind: &'static str,
    #[serde(flatten)]
    outcome: DiagnosticOutcome,
    #[serde(flatten)]
    summary: &'a DiagnosticSummary,
}
#[derive(Serialize)]
struct Reference {
    seq: u64,
    status: &'static str,
}
fn reference(
    seq: Option<u64>,
    current: u64,
    ordinary: &Ring,
    exceptional: &Ring,
) -> Option<Reference> {
    let seq = seq?;
    let retained =
        seq < current && (retained_sequence(ordinary, seq) || retained_sequence(exceptional, seq));
    Some(Reference {
        seq,
        status: if retained { "retained" } else { "not_retained" },
    })
}
#[derive(Serialize)]
struct DiagnosticLine<'a> {
    schema: &'static str,
    seq: u64,
    kind: DiagnosticKind,
    application: &'a str,
    application_truncated: bool,
    pid: Option<u32>,
    incarnation: Option<u64>,
    caller: Option<PublicId>,
    module: &'a str,
    module_truncated: bool,
    module_id: Option<PublicId>,
    pair: Option<PublicId>,
    read: Option<PublicId>,
    epoch: Option<PublicId>,
    pending: Option<PublicId>,
    origin: Option<ReadOrigin>,
    decision: Option<Decision>,
    reason: Option<DiagnosticReason>,
    prior_eligibility: Option<Eligibility>,
    new_eligibility: Option<Eligibility>,
    absolute: Option<u64>,
    base: Option<u64>,
    staged: Option<u64>,
    after: Option<u64>,
    through: Option<u64>,
    pre: Option<u64>,
    post: Option<u64>,
    fence: Option<u64>,
    baseline_pre: Option<u64>,
    baseline_post: Option<u64>,
    edge_total: Option<u64>,
    observation_ref: Option<Reference>,
    transition_ref: Option<Reference>,
    context_unavailable: bool,
    history_complete: bool,
}
fn project<'a>(
    record: &DiagnosticRecord,
    indexes: &ExportIndexes,
    ordinary: &Ring,
    exceptional: &Ring,
    application: &'a Label,
    module: &'a Label,
) -> DiagnosticLine<'a> {
    let pair = record.pair.and_then(|key| indexes.pair(key));
    let observation_ref = reference(record.observation_ref, record.seq, ordinary, exceptional);
    let transition_ref = reference(record.transition_ref, record.seq, ordinary, exceptional);
    let context_unavailable = record.context_unavailable
        || pair.is_none()
            && (record.read.is_some() || record.epoch.is_some() || record.pending.is_some())
        || observation_ref
            .as_ref()
            .is_some_and(|reference| reference.status != "retained")
        || transition_ref
            .as_ref()
            .is_some_and(|reference| reference.status != "retained");
    DiagnosticLine {
        schema: SCHEMA,
        seq: record.seq,
        kind: record.kind,
        application: application.as_str(),
        application_truncated: application.truncated,
        pid: record.pid,
        incarnation: record.incarnation,
        caller: record.caller.map(|value| PublicId { prefix: "c", value }),
        module: module.as_str(),
        module_truncated: module.truncated,
        module_id: record.module.map(|value| PublicId { prefix: "m", value }),
        pair: pair.map(|value| PublicId { prefix: "p", value }),
        read: ExportIndexes::scoped(&indexes.reads, pair, record.read, "r"),
        epoch: ExportIndexes::scoped(&indexes.epochs, pair, record.epoch, "e"),
        pending: ExportIndexes::scoped(&indexes.pending, pair, record.pending, "h"),
        origin: record.origin,
        decision: record.decision,
        reason: record.reason,
        prior_eligibility: record.prior_eligibility,
        new_eligibility: record.new_eligibility,
        absolute: record.absolute,
        base: record.base,
        staged: record.staged,
        after: record.after,
        through: record.through,
        pre: record.pre,
        post: record.post,
        fence: record.fence,
        baseline_pre: record.baseline_pre,
        baseline_post: record.baseline_post,
        edge_total: record.edge_total,
        observation_ref,
        transition_ref,
        context_unavailable,
        history_complete: !context_unavailable,
    }
}

#[cfg(test)]
#[path = "inventory_diagnostics_tests.rs"]
mod tests;
