//! SPDX-License-Identifier: GPL-3.0-or-later
//! Incremental-discovery responsiveness telemetry (Phase 2).
//!
//! Per-stage timers, the inter-drain gap distribution, newcomer queue ages,
//! capture-process resource samples, and the pin-sweep gate. All clocks are
//! injected as `Option<u64>` monotonic nanoseconds in the style of the
//! discovery scheduler hooks (`begin_deep_scan_tick(Option<u64>)`): `None`
//! is a failed clock read, and a span with a missing endpoint is counted as
//! unknown — never recorded as a zero-duration sample. Production call sites
//! pass `crate::attach::monotonic_ns()`; unit tests pass fake values.
//!
//! Sampling rules (each published number carries these in the schema docs):
//!
//! - A stage total is the saturating sum of its *recorded* spans only. Spans
//!   whose clock read failed are counted in `stage_unknown_clock` and
//!   contribute nothing to totals, counts, or the longest operation.
//! - Every span is a leaf operation: container wall time (a live frame, the
//!   terminal dispatch) is never recorded as a stage span, so stage totals
//!   never double-count. The one derived span is the terminal cleanup
//!   overhead: terminal wall time minus the inner spans it contains.
//! - Spans on early-error paths are recorded when the fallible call was
//!   issued and its endpoints read; a `?` before the trailing clock read
//!   drops that span (counted nowhere — an unrecorded region, not a zero).
//! - Gap-quantile estimates are bucket upper bounds, not interpolations.
//! - Newcomer ages are whole milliseconds, `saturating_sub`, floor division.
//! - Resource samples are `/proc/self` reads at defined points (capture
//!   start, attach readiness, loop end, every [`RESOURCE_SAMPLE_EVERY_N_TICKS`]
//!   ticks). A failed read or parse yields `None` per field, never zero.
//! - Missing samples publish as `null`, never as zero. A stage that never
//!   ran publishes total `0` with `0` invocations (an exact empty sum, not a
//!   missing sample).

use std::collections::BTreeMap;

/// Discovery/capture stages with per-stage timers. Order is fixed: it is the
/// evidence order and the `StageMs` serialization order.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum StageKind {
    Scan,
    Pin,
    Bind,
    Plan,
    Merge,
    Projection,
    Attach,
    Drain,
    Cleanup,
}

/// How many stages [`StageKind`] names. `StageTimings` stores one total and
/// one invocation count per stage: bounded by construction.
pub const STAGE_COUNT: usize = 9;

impl StageKind {
    /// Every stage, in evidence order.
    pub const ALL: [StageKind; STAGE_COUNT] = [
        StageKind::Scan,
        StageKind::Pin,
        StageKind::Bind,
        StageKind::Plan,
        StageKind::Merge,
        StageKind::Projection,
        StageKind::Attach,
        StageKind::Drain,
        StageKind::Cleanup,
    ];

    /// The evidence key for this stage.
    pub fn as_str(self) -> &'static str {
        match self {
            StageKind::Scan => "scan",
            StageKind::Pin => "pin",
            StageKind::Bind => "bind",
            StageKind::Plan => "plan",
            StageKind::Merge => "merge",
            StageKind::Projection => "projection",
            StageKind::Attach => "attach",
            StageKind::Drain => "drain",
            StageKind::Cleanup => "cleanup",
        }
    }

    fn index(self) -> usize {
        match self {
            StageKind::Scan => 0,
            StageKind::Pin => 1,
            StageKind::Bind => 2,
            StageKind::Plan => 3,
            StageKind::Merge => 4,
            StageKind::Projection => 5,
            StageKind::Attach => 6,
            StageKind::Drain => 7,
            StageKind::Cleanup => 8,
        }
    }
}

/// The longest single recorded span: the capture's longest indivisible
/// operation. Ties keep the earliest span.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct LongestOp {
    pub stage: StageKind,
    /// The leaf operation label (e.g. `"attach_targets"`).
    pub op: &'static str,
    pub duration_ns: u64,
}

/// Per-stage wall-time accumulation with an injected clock.
#[derive(Debug, Clone, Default)]
pub struct StageTimings {
    totals_ns: [u64; STAGE_COUNT],
    invocations: [u64; STAGE_COUNT],
    unknown_clock: u64,
    longest: Option<LongestOp>,
    /// Per-operation totals `(op, total_ns, spans)` in first-recorded
    /// order. Bounded by the finite set of static op labels.
    ops: Vec<(&'static str, u64, u64)>,
}

impl StageTimings {
    pub fn new() -> Self {
        Self::default()
    }

    /// Records one leaf span. `None` endpoints (a failed clock read) count
    /// the span as unknown and record nothing else.
    pub fn span(
        &mut self,
        stage: StageKind,
        op: &'static str,
        start_ns: Option<u64>,
        end_ns: Option<u64>,
    ) {
        let (Some(start), Some(end)) = (start_ns, end_ns) else {
            self.unknown_clock = self.unknown_clock.saturating_add(1);
            return;
        };
        self.span_known(stage, op, Some(end.saturating_sub(start)));
    }

    /// Records one span whose duration the caller already derived (the
    /// terminal cleanup overhead: wall time minus contained spans). `None`
    /// counts the span as unknown, exactly like a failed clock read.
    pub fn span_known(&mut self, stage: StageKind, op: &'static str, duration_ns: Option<u64>) {
        let Some(duration) = duration_ns else {
            self.unknown_clock = self.unknown_clock.saturating_add(1);
            return;
        };
        let slot = stage.index();
        self.totals_ns[slot] = self.totals_ns[slot].saturating_add(duration);
        self.invocations[slot] = self.invocations[slot].saturating_add(1);
        let longer = self.longest.is_none_or(|best| duration > best.duration_ns);
        if longer {
            self.longest = Some(LongestOp {
                stage,
                op,
                duration_ns: duration,
            });
        }
        self.add_op(op, duration, 1);
    }

    fn add_op(&mut self, op: &'static str, duration_ns: u64, spans: u64) {
        match self.ops.iter_mut().find(|(known, _, _)| *known == op) {
            Some((_, total, count)) => {
                *total = total.saturating_add(duration_ns);
                *count = count.saturating_add(spans);
            }
            None => self.ops.push((op, duration_ns, spans)),
        }
    }

    /// Per-operation totals `(op, total_ns, spans)`, in first-recorded
    /// order: the per-stage cost breakdown one pass prints.
    pub fn ops(&self) -> &[(&'static str, u64, u64)] {
        &self.ops
    }

    /// One human line of per-operation totals in milliseconds, in
    /// first-recorded order (`sweep 1.234ms, select 0.010ms, …`).
    pub fn ops_line(&self) -> String {
        self.ops
            .iter()
            .map(|(op, total, _)| {
                format!("{op} {}.{:03}ms", total / 1_000_000, total / 1_000 % 1_000)
            })
            .collect::<Vec<_>>()
            .join(", ")
    }

    /// Folds another accumulator in (the run loop merges the engine's stage
    /// totals into its own at snapshot time). Saturating; the longest span
    /// wins, ties keeping `self`'s.
    pub fn merge(&mut self, other: &StageTimings) {
        for (slot, _) in StageKind::ALL.iter().enumerate() {
            self.totals_ns[slot] = self.totals_ns[slot].saturating_add(other.totals_ns[slot]);
            self.invocations[slot] = self.invocations[slot].saturating_add(other.invocations[slot]);
        }
        self.unknown_clock = self.unknown_clock.saturating_add(other.unknown_clock);
        for (op, total, spans) in &other.ops {
            self.add_op(op, *total, *spans);
        }
        if let Some(candidate) = other.longest
            && self
                .longest
                .is_none_or(|best| candidate.duration_ns > best.duration_ns)
        {
            self.longest = Some(candidate);
        }
    }

    /// A copy of the per-stage totals, in [`StageKind::ALL`] order: the
    /// before/after snapshots behind the terminal exclusive-cleanup span.
    pub fn totals_ns(&self) -> [u64; STAGE_COUNT] {
        self.totals_ns
    }

    pub fn total_ns(&self, stage: StageKind) -> u64 {
        self.totals_ns[stage.index()]
    }

    pub fn invocations(&self, stage: StageKind) -> u64 {
        self.invocations[stage.index()]
    }

    /// Spans dropped for a missing clock endpoint.
    pub fn unknown_clock(&self) -> u64 {
        self.unknown_clock
    }

    pub fn longest(&self) -> Option<LongestOp> {
        self.longest
    }
}

/// Inter-drain gap distribution buckets: powers of two in milliseconds plus
/// one overflow bucket. Sixteen buckets cover 1 ms through 32 s; bucket 16
/// holds every gap above that. Bounded memory by construction: 17 counters.
pub const GAP_HISTOGRAM_BUCKETS: usize = 17;

/// Upper bounds, in milliseconds, of buckets `0..16`. Bucket 16 is the
/// overflow bucket (every gap above 32,768 ms).
pub const GAP_BUCKET_BOUNDS_MS: [u64; GAP_HISTOGRAM_BUCKETS - 1] = [
    1, 2, 4, 8, 16, 32, 64, 128, 256, 512, 1024, 2048, 4096, 8192, 16384, 32768,
];

/// The bounded inter-drain gap distribution. Fed alongside the existing
/// lifetime-maximum gap; frozen at loop end by the caller, like the maximum.
#[derive(Debug, Clone, Default)]
pub struct GapHistogram {
    buckets: [u64; GAP_HISTOGRAM_BUCKETS],
    samples: u64,
    max_ms: u64,
}

impl GapHistogram {
    pub fn new() -> Self {
        Self::default()
    }

    /// Observes one inter-drain gap. The first drain of a capture observes
    /// no gap (there is no predecessor), exactly like the maximum.
    pub fn observe_ms(&mut self, gap_ms: u64) {
        let bucket = GAP_BUCKET_BOUNDS_MS
            .iter()
            .position(|bound| gap_ms <= *bound)
            .unwrap_or(GAP_HISTOGRAM_BUCKETS - 1);
        self.buckets[bucket] = self.buckets[bucket].saturating_add(1);
        self.samples = self.samples.saturating_add(1);
        self.max_ms = self.max_ms.max(gap_ms);
    }

    pub fn samples(&self) -> u64 {
        self.samples
    }

    /// The exact maximum observed gap, or `None` when no gap was sampled.
    pub fn max_ms(&self) -> Option<u64> {
        (self.samples > 0).then_some(self.max_ms)
    }

    /// The p50 bucket-upper-bound estimate, or `None` when empty or when the
    /// quantile falls in the overflow bucket (reported missing, with the
    /// exact maximum alongside — never an invented interpolation).
    pub fn p50_ms(&self) -> Option<u64> {
        self.quantile_ms(50)
    }

    /// The p99 bucket-upper-bound estimate, with the same missing rules.
    pub fn p99_ms(&self) -> Option<u64> {
        self.quantile_ms(99)
    }

    fn quantile_ms(&self, percent: u64) -> Option<u64> {
        if self.samples == 0 {
            return None;
        }
        // 1-based rank of the quantile, rounded up: the first sample whose
        // cumulative count reaches it decides the bucket.
        let rank = self.samples.saturating_mul(percent).div_ceil(100).max(1);
        let mut cumulative = 0u64;
        for (bucket, bound) in GAP_BUCKET_BOUNDS_MS.iter().enumerate() {
            cumulative = cumulative.saturating_add(self.buckets[bucket]);
            if cumulative >= rank {
                return Some(*bound);
            }
        }
        // The quantile falls in the overflow bucket: above the bucketed
        // range, reported missing (the exact maximum still publishes).
        None
    }

    #[cfg(test)]
    pub(crate) fn bucket_for_test(&self, bucket: usize) -> u64 {
        self.buckets[bucket]
    }
}

/// Cumulative newcomer/refresh queue-age evidence. Arrival marks live on the
/// engine (pending refresh pids, deferred diff-discovered newcomers); this
/// accumulator holds the sampled ages. Ages are whole milliseconds from
/// first-seen to first-observed-ready (admission) or to the drop tick.
/// Clock-unknown samples count separately and never enter a mean or maximum.
#[derive(Debug, Clone, Default)]
pub struct NewcomerStats {
    /// Newcomers admitted with a known first-seen mark.
    pub admitted: u64,
    /// Newcomers admitted without one (clock unavailable or mark dropped).
    pub admitted_unknown: u64,
    /// Maximum known admission age.
    pub max_admitted_age_ms: Option<u64>,
    total_admitted_age_ms: u64,
    /// Pids still waiting at the last snapshot (pending refresh requests
    /// plus deferred diff-discovered newcomers).
    pub pending: u64,
    /// Oldest known pending age at the last snapshot.
    pub oldest_pending_age_ms: Option<u64>,
    /// Refresh requests dropped past the queue cap with a known age.
    pub dropped: u64,
    /// Refresh requests dropped without one.
    pub dropped_unknown: u64,
    /// Maximum known drop age.
    pub max_dropped_age_ms: Option<u64>,
    /// Arrival marks dropped past the mark cap (bounded memory).
    pub marks_dropped: u64,
}

impl NewcomerStats {
    pub fn new() -> Self {
        Self::default()
    }

    /// Samples one admission. `None` is a clock-unknown admission: counted,
    /// never averaged.
    pub fn note_admitted(&mut self, age_ms: Option<u64>) {
        match age_ms {
            Some(age) => {
                self.admitted = self.admitted.saturating_add(1);
                self.total_admitted_age_ms = self.total_admitted_age_ms.saturating_add(age);
                self.max_admitted_age_ms =
                    Some(self.max_admitted_age_ms.max(Some(age)).unwrap_or(age));
            }
            None => {
                self.admitted_unknown = self.admitted_unknown.saturating_add(1);
            }
        }
    }

    /// Samples one queue-cap drop. Overflow drops keep their loss markers
    /// (recorded by the caller); this records the dropped age alongside.
    pub fn note_dropped(&mut self, age_ms: Option<u64>) {
        match age_ms {
            Some(age) => {
                self.dropped = self.dropped.saturating_add(1);
                self.max_dropped_age_ms =
                    Some(self.max_dropped_age_ms.max(Some(age)).unwrap_or(age));
            }
            None => {
                self.dropped_unknown = self.dropped_unknown.saturating_add(1);
            }
        }
    }

    pub fn note_mark_dropped(&mut self) {
        self.marks_dropped = self.marks_dropped.saturating_add(1);
    }

    /// Mean known admission age, floored, or `None` when no known age was
    /// sampled.
    pub fn mean_admitted_age_ms(&self) -> Option<u64> {
        (self.admitted > 0).then(|| self.total_admitted_age_ms / self.admitted)
    }
}

/// One capture-process resource sample. Every field is `None` when its read
/// or parse failed — a missing sample, never a zero.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct ResourceSample {
    pub rss_kb: Option<u64>,
    pub utime_ms: Option<u64>,
    pub stime_ms: Option<u64>,
    pub read_bytes: Option<u64>,
    pub write_bytes: Option<u64>,
}

impl ResourceSample {
    pub fn missing() -> Self {
        Self::default()
    }
}

/// Where in the capture a resource sample was taken.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ResourcePoint {
    /// Capture start (before the first tick).
    Start,
    /// Attach readiness (the loop-start stamp).
    Readiness,
    /// Capture-loop end.
    End,
    /// One periodic sample.
    Periodic,
}

/// Periodic resource cadence: one sample every N capture ticks. The periodic
/// series is not retained per tick (unbounded); only its count, maximum RSS,
/// and latest sample publish.
pub const RESOURCE_SAMPLE_EVERY_N_TICKS: u64 = 100;

/// The capture's resource timeline: three defined-point samples plus the
/// bounded periodic summary.
#[derive(Debug, Clone, Default)]
pub struct ResourceTimeline {
    pub start: ResourceSample,
    pub readiness: ResourceSample,
    pub end: ResourceSample,
    pub periodic_samples: u64,
    pub max_rss_kb: Option<u64>,
    pub last_periodic: ResourceSample,
}

impl ResourceTimeline {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn note(&mut self, point: ResourcePoint, sample: ResourceSample) {
        match point {
            ResourcePoint::Start => self.start = sample,
            ResourcePoint::Readiness => self.readiness = sample,
            ResourcePoint::End => self.end = sample,
            ResourcePoint::Periodic => {
                self.periodic_samples = self.periodic_samples.saturating_add(1);
                if let Some(rss) = sample.rss_kb {
                    self.max_rss_kb = Some(self.max_rss_kb.max(Some(rss)).unwrap_or(rss));
                }
                self.last_periodic = sample;
            }
        }
    }
}

/// Parses the resident set (field 2, in pages) from `/proc/self/statm`.
/// Pure: unit tests drive it with fixture strings.
pub fn parse_statm_rss_kb(statm: &str, page_kb: u64) -> Option<u64> {
    let resident_pages: u64 = statm.split_ascii_whitespace().nth(1)?.parse().ok()?;
    resident_pages.checked_mul(page_kb)
}

/// Parses utime/stime (fields 14/15, in clock ticks) from `/proc/self/stat`
/// into whole milliseconds. The comm field (field 2) may contain spaces and
/// parentheses, so fields are counted from the *last* `)`.
pub fn parse_stat_cpu_ms(stat: &str, ticks_per_sec: u64) -> Option<(u64, u64)> {
    if ticks_per_sec == 0 {
        return None;
    }
    let after_comm = stat.rsplit_once(')')?.1;
    let mut fields = after_comm.split_ascii_whitespace();
    // Fields 3..=13 precede utime.
    let utime: u64 = fields.nth(11)?.parse().ok()?;
    let stime: u64 = fields.next()?.parse().ok()?;
    let to_ms = |ticks: u64| ticks.saturating_mul(1000).checked_div(ticks_per_sec);
    Some((to_ms(utime)?, to_ms(stime)?))
}

/// Parses `read_bytes`/`write_bytes` from `/proc/self/io`.
pub fn parse_io_bytes(io: &str) -> Option<(u64, u64)> {
    let mut read_bytes = None;
    let mut write_bytes = None;
    for line in io.lines() {
        let (key, value) = line.split_once(':')?;
        match key {
            "read_bytes" => read_bytes = Some(value.trim().parse().ok()?),
            "write_bytes" => write_bytes = Some(value.trim().parse().ok()?),
            _ => {}
        }
    }
    Some((read_bytes?, write_bytes?))
}

fn read_proc_file(path: &str) -> Option<String> {
    std::fs::read_to_string(path).ok()
}

/// Reads one resource sample for the capture process (Linux-first: `/proc`
/// reads; other targets report every field missing).
pub fn read_resource_sample() -> ResourceSample {
    #[cfg(not(target_os = "linux"))]
    {
        return ResourceSample::missing();
    }
    #[cfg(target_os = "linux")]
    {
        // SAFETY: `sysconf` with a valid name is memory-safe; a -1 return is
        // reported as a failed read (missing sample), never zero.
        let page_kb = unsafe { libc::sysconf(libc::_SC_PAGESIZE) }
            .try_into()
            .ok()
            .and_then(|bytes: u64| bytes.checked_div(1024));
        // SAFETY: same contract as above.
        let ticks_per_sec: Option<u64> =
            unsafe { libc::sysconf(libc::_SC_CLK_TCK) }.try_into().ok();
        let rss_kb = page_kb.and_then(|page| {
            read_proc_file("/proc/self/statm").and_then(|text| parse_statm_rss_kb(&text, page))
        });
        let (utime_ms, stime_ms) = ticks_per_sec
            .and_then(|tps| {
                read_proc_file("/proc/self/stat").and_then(|text| parse_stat_cpu_ms(&text, tps))
            })
            .unzip();
        let (read_bytes, write_bytes) = read_proc_file("/proc/self/io")
            .as_deref()
            .and_then(parse_io_bytes)
            .unzip();
        ResourceSample {
            rss_kb,
            utime_ms,
            stime_ms,
            read_bytes,
            write_bytes,
        }
    }
}

/// The pin-sweep gate (B2): the per-tick `check_unchanged` sweep runs when
/// the pin-set membership revision advanced since the last sweep, or on a
/// frame tick (the profile loop's bounded-staleness backstop: live display
/// lags at most one frame). The trace loop passes no backstop — its live
/// output never reads the latch — and the terminal path always sweeps, so
/// final `provider_changed` evidence is identical with or without skips.
#[derive(Debug, Clone)]
pub struct PinSweepGate {
    last_revision: u64,
    sweeps: u64,
    skips: u64,
}

impl PinSweepGate {
    pub fn new() -> Self {
        Self {
            // The first tick always sweeps (today's behavior): no pin-set
            // revision can equal the sentinel.
            last_revision: u64::MAX,
            sweeps: 0,
            skips: 0,
        }
    }

    /// Whether this tick sweeps. Records the decision (counter, not timing).
    pub fn should_sweep(&mut self, revision: u64, frame_backstop: bool) -> bool {
        if revision != self.last_revision || frame_backstop {
            self.last_revision = revision;
            self.sweeps = self.sweeps.saturating_add(1);
            true
        } else {
            self.skips = self.skips.saturating_add(1);
            false
        }
    }

    pub fn sweeps(&self) -> u64 {
        self.sweeps
    }

    pub fn skips(&self) -> u64 {
        self.skips
    }
}

impl Default for PinSweepGate {
    fn default() -> Self {
        Self::new()
    }
}

/// First-seen arrival marks for diff-discovered newcomers, keyed by pid.
/// Bounded by [`MAX_NEWCOMER_MARKS`]; pruned to the enumerated scope every
/// inventory tick (the same bound argument as the scheduler's cooling map).
pub type NewcomerMarks = BTreeMap<u32, Option<u64>>;

/// Hard cap on retained newcomer arrival marks. Past it, marks drop (counted
/// in [`NewcomerStats::marks_dropped`]) and those admissions sample unknown.
pub const MAX_NEWCOMER_MARKS: usize = 4096;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn stage_spans_accumulate_totals_counts_and_longest() {
        let mut timings = StageTimings::new();
        timings.span(StageKind::Scan, "scan_view", Some(100), Some(150));
        timings.span(StageKind::Scan, "scan_view", Some(200), Some(230));
        timings.span(StageKind::Attach, "attach_targets", Some(300), Some(500));
        assert_eq!(timings.total_ns(StageKind::Scan), 80);
        assert_eq!(timings.invocations(StageKind::Scan), 2);
        assert_eq!(timings.total_ns(StageKind::Attach), 200);
        assert_eq!(timings.invocations(StageKind::Attach), 1);
        assert_eq!(timings.total_ns(StageKind::Pin), 0);
        assert_eq!(timings.invocations(StageKind::Pin), 0);
        assert_eq!(
            timings.longest(),
            Some(LongestOp {
                stage: StageKind::Attach,
                op: "attach_targets",
                duration_ns: 200,
            })
        );
    }

    #[test]
    fn per_op_totals_keep_first_recorded_order_and_merge() {
        let mut timings = StageTimings::new();
        timings.span(StageKind::Scan, "sweep", Some(0), Some(2_500_000));
        timings.span(StageKind::Plan, "assemble", Some(0), Some(1_000));
        timings.span(StageKind::Scan, "sweep", Some(0), Some(500_000));
        timings.span(StageKind::Scan, "sweep", None, Some(1));
        assert_eq!(
            timings.ops(),
            &[("sweep", 3_000_000, 2), ("assemble", 1_000, 1)]
        );
        assert_eq!(timings.ops_line(), "sweep 3.000ms, assemble 0.001ms");
        let mut other = StageTimings::new();
        other.span(StageKind::Projection, "project", Some(0), Some(7));
        other.span(StageKind::Scan, "sweep", Some(0), Some(1));
        timings.merge(&other);
        assert_eq!(
            timings.ops(),
            &[
                ("sweep", 3_000_001, 3),
                ("assemble", 1_000, 1),
                ("project", 7, 1)
            ]
        );
    }

    #[test]
    fn stage_spans_with_a_missing_clock_stay_unknown_never_zero() {
        let mut timings = StageTimings::new();
        timings.span(StageKind::Scan, "scan_view", None, Some(150));
        timings.span(StageKind::Scan, "scan_view", Some(100), None);
        timings.span_known(StageKind::Scan, "scan_view", None);
        assert_eq!(timings.total_ns(StageKind::Scan), 0);
        assert_eq!(timings.invocations(StageKind::Scan), 0);
        assert_eq!(timings.unknown_clock(), 3);
        assert_eq!(timings.longest(), None);
    }

    #[test]
    fn stage_merge_folds_totals_and_keeps_the_longest() {
        let mut engine = StageTimings::new();
        engine.span(StageKind::Scan, "scan_view", Some(0), Some(100));
        let mut run = StageTimings::new();
        run.span(StageKind::Drain, "drain_live", Some(0), Some(400));
        run.merge(&engine);
        assert_eq!(run.total_ns(StageKind::Scan), 100);
        assert_eq!(run.total_ns(StageKind::Drain), 400);
        assert_eq!(run.longest().map(|longest| longest.op), Some("drain_live"));
    }

    #[test]
    fn gap_histogram_reports_quantiles_max_and_count() {
        let mut gaps = GapHistogram::new();
        assert_eq!(gaps.samples(), 0);
        assert_eq!(gaps.p50_ms(), None);
        assert_eq!(gaps.p99_ms(), None);
        assert_eq!(gaps.max_ms(), None);
        for gap in [1, 2, 3, 4, 5, 6, 7, 8, 9, 100] {
            gaps.observe_ms(gap);
        }
        assert_eq!(gaps.samples(), 10);
        // Rank ceil(0.50*10)=5 lands in the ≤8 bucket; p99 (rank 10) in ≤128.
        assert_eq!(gaps.p50_ms(), Some(8));
        assert_eq!(gaps.p99_ms(), Some(128));
        assert_eq!(gaps.max_ms(), Some(100));
        // Buckets: ≤1 ×1, ≤2 ×1, ≤4 ×2, ≤8 ×4, ≤16 ×1, ≤128 ×1.
        assert_eq!(
            gaps.bucket_for_test(0)
                + gaps.bucket_for_test(1)
                + gaps.bucket_for_test(2)
                + gaps.bucket_for_test(3)
                + gaps.bucket_for_test(4)
                + gaps.bucket_for_test(7),
            10
        );
        assert_eq!(gaps.bucket_for_test(3), 4);
        assert_eq!(gaps.bucket_for_test(16), 0);
    }

    #[test]
    fn gap_quantile_above_the_bucket_range_is_missing_not_invented() {
        let mut gaps = GapHistogram::new();
        gaps.observe_ms(100_000);
        assert_eq!(gaps.samples(), 1);
        assert_eq!(gaps.p50_ms(), None);
        assert_eq!(gaps.p99_ms(), None);
        assert_eq!(gaps.max_ms(), Some(100_000));
    }

    #[test]
    fn newcomer_ages_keep_unknown_samples_out_of_means_and_maxima() {
        let mut stats = NewcomerStats::new();
        assert_eq!(stats.mean_admitted_age_ms(), None);
        stats.note_admitted(Some(10));
        stats.note_admitted(Some(20));
        stats.note_admitted(None);
        assert_eq!(stats.admitted, 2);
        assert_eq!(stats.admitted_unknown, 1);
        assert_eq!(stats.mean_admitted_age_ms(), Some(15));
        assert_eq!(stats.max_admitted_age_ms, Some(20));
        stats.note_dropped(Some(7));
        stats.note_dropped(None);
        assert_eq!(stats.dropped, 1);
        assert_eq!(stats.dropped_unknown, 1);
        assert_eq!(stats.max_dropped_age_ms, Some(7));
    }

    #[test]
    fn statm_parses_the_resident_field() {
        assert_eq!(parse_statm_rss_kb("100 200 0 0 0 0 0", 4), Some(800));
        assert_eq!(parse_statm_rss_kb("100", 4), None);
        assert_eq!(parse_statm_rss_kb("", 4), None);
    }

    #[test]
    fn stat_parses_cpu_fields_past_a_tricky_comm() {
        // comm with spaces and a paren; utime=100 stime=50 at 100 ticks/s.
        let stat = "123 (my (proc)) R 1 2 3 4 5 6 7 8 9 10 100 50 0 0";
        assert_eq!(parse_stat_cpu_ms(stat, 100), Some((1000, 500)));
        assert_eq!(parse_stat_cpu_ms(stat, 0), None);
        assert_eq!(parse_stat_cpu_ms("123 no_paren_here", 100), None);
    }

    #[test]
    fn io_parses_read_and_write_bytes() {
        let io = "rchar: 1\nwchar: 2\nread_bytes: 4096\nwrite_bytes: 8192\n";
        assert_eq!(parse_io_bytes(io), Some((4096, 8192)));
        assert_eq!(parse_io_bytes("read_bytes: 1\n"), None);
    }

    #[test]
    fn pin_gate_sweeps_on_revision_change_or_frame_only() {
        let mut gate = PinSweepGate::new();
        // First tick always sweeps.
        assert!(gate.should_sweep(0, false));
        // Quiet inter-frame ticks skip.
        assert!(!gate.should_sweep(0, false));
        assert!(!gate.should_sweep(0, false));
        // A membership change sweeps even off-frame.
        assert!(gate.should_sweep(1, false));
        assert!(!gate.should_sweep(1, false));
        // A frame tick sweeps even when quiet (the live-display backstop).
        assert!(gate.should_sweep(1, true));
        assert!(!gate.should_sweep(1, false));
        // A backward revision still sweeps (restored pin sets differ).
        assert!(gate.should_sweep(0, false));
        assert_eq!(gate.sweeps(), 4);
        assert_eq!(gate.skips(), 4);
    }
}
