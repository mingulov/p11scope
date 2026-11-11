//! SPDX-License-Identifier: GPL-3.0-or-later
//! SPDX-FileCopyrightText: 2026 Denis Mingulov <denis@mingulov.com>
//! Deep-freeze long-run detector (T2, G-14): notices long-runtime failure
//! modes the per-capture verdict cannot see.
//!
//! What it watches: per-tick wall time against the worst observed
//! forced-sweep tick, inter-drain gaps against a stall bound (a loop that
//! stops draining is a deep freeze), first-drain loss shares (ramp-up
//! loss vs steady-state loss, for the early-ring-loss diagnosis), the
//! kernel identity budget (a spent budget blinds the capture to new
//! processes) and the newcomer queue (newcomers still waiting past the
//! stall bound never got admitted). Pure: every observation is passed
//! in, so the detector is fully testable with synthetic streams. The
//! capture loop feeds it per tick and attempts one `p11scope: longrun:`
//! stderr line at loop end. Delivery is best effort; absence is not a
//! clean result. These diagnostics do not change the capture verdict or
//! report schema.

use p11scope_ebpf_common::IMAGE_IDENTITY_TICKET_LIMIT;

/// Historical forced-sweep maximum (`31r-esys4`, measured 2026-09-20).
/// This is a diagnostic threshold, not a latency guarantee; see
/// `docs/qualification/first-use-contract.md` for its interpretation.
pub const TICK_LATENCY_MAX_MS: u64 = 1_895;
/// A drain gap this long means the loop stopped draining: ~5x the worst
/// observed tick, 10x the profile cadence, 50x the trace cadence.
pub const STALL_GAP_MS: u64 = 10_000;

pub const FINDING_TICK_OVER_BUDGET: &str = "tick_over_budget";
pub const FINDING_LOOP_STALLED: &str = "loop_stalled";
pub const FINDING_EARLY_EVENT_LOSS: &str = "early_event_loss";
pub const FINDING_EARLY_DISCOVERY_LOSS: &str = "early_discovery_loss";
pub const FINDING_IDENTITY_BUDGET_EXHAUSTED: &str = "identity_budget_exhausted";
pub const FINDING_NEWCOMER_QUEUE_STALLED: &str = "newcomer_queue_stalled";

/// A newcomer still waiting past this age at loop end never got
/// admitted: admission normally completes within a scan, so this is
/// 60x that, and far under the observed 115-minute stall. Bounds are
/// strict, like the stall gap: exactly at the bound is not a stall.
/// Self-limiting on short runs: a pending age can never exceed the
/// run length, so only runs past a minute can trip it.
pub const NEWCOMER_STALL_AGE_MS: u64 = 60_000;

/// True when the end-of-run newcomer point-in-time proves a stall:
/// pids still waiting with a known oldest age past the bound. An
/// unknown oldest age stays unknown, never a stall.
pub fn newcomer_stalled(pending: u64, oldest_pending_age_ms: Option<u64>) -> bool {
    pending > 0 && oldest_pending_age_ms.is_some_and(|age| age > NEWCOMER_STALL_AGE_MS)
}

/// Detector thresholds. Defaults are the module constants; soak policy
/// can tighten or loosen them without touching the detector.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct LongRunConfig {
    pub tick_latency_max_ms: u64,
    pub stall_gap_ms: u64,
}

impl Default for LongRunConfig {
    fn default() -> Self {
        Self {
            tick_latency_max_ms: TICK_LATENCY_MAX_MS,
            stall_gap_ms: STALL_GAP_MS,
        }
    }
}

/// One noticed long-runtime failure mode. `at_tick` is `Some` when the
/// finding attributes to one tick (slowest tick, first drain) and `None`
/// for run-aggregate findings (stall).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LongRunFinding {
    pub code: &'static str,
    pub detail: String,
    pub at_tick: Option<u64>,
}

/// The detector's end-of-loop verdict: findings plus the numbers every
/// finding is derived from.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LongRunReport {
    pub findings: Vec<LongRunFinding>,
    pub ticks_observed: u64,
    pub max_tick_ms: u64,
    /// None when no inter-drain interval was sampled (including metrics).
    pub max_gap_ms: Option<u64>,
    pub early_event_loss: Option<u64>,
    pub steady_event_loss: Option<u64>,
    pub early_discovery_loss: Option<u64>,
    pub steady_discovery_loss: Option<u64>,
}

impl LongRunReport {
    pub fn is_clean(&self) -> bool {
        self.findings.is_empty()
    }

    fn fmt_split(early: Option<u64>, steady: Option<u64>) -> String {
        match (early, steady) {
            (Some(early), Some(steady)) => format!("early {early} steady {steady}"),
            _ => "early n/a steady n/a".to_string(),
        }
    }

    /// The stderr line attempted at loop end when samples are available.
    /// A soak must distinguish its absence from a delivered clean result.
    /// "Clean" needs zero measured loss besides no findings: the line
    /// prints the loss splits beside the verdict, so "clean" next to a
    /// nonzero split would contradict the capture's own loss report.
    /// Unmeasured splits (`None`) stay "clean": nothing observed, nothing
    /// claimed.
    pub fn report_line(&self) -> String {
        let gap = self
            .max_gap_ms
            .map_or_else(|| "n/a".to_string(), |ms| format!("{ms}ms"));
        let numbers = format!(
            "ticks {}, max tick {}ms, max gap {}, events {}, discovery {}",
            self.ticks_observed,
            self.max_tick_ms,
            gap,
            Self::fmt_split(self.early_event_loss, self.steady_event_loss),
            Self::fmt_split(self.early_discovery_loss, self.steady_discovery_loss),
        );
        if self.findings.is_empty() {
            let measured = [
                self.early_event_loss,
                self.steady_event_loss,
                self.early_discovery_loss,
                self.steady_discovery_loss,
            ];
            if measured
                .iter()
                .any(|split| split.is_some_and(|loss| loss > 0))
            {
                return format!("p11scope: longrun: no long-run findings ({numbers})");
            }
            format!("p11scope: longrun: clean ({numbers})")
        } else {
            let findings: Vec<String> = self
                .findings
                .iter()
                .map(|finding| format!("{}[{}]", finding.code, finding.detail))
                .collect();
            format!(
                "p11scope: longrun: {} finding{} ({numbers}): {}",
                self.findings.len(),
                if self.findings.len() == 1 { "" } else { "s" },
                findings.join("; "),
            )
        }
    }
}

/// The detector: fed per-tick observations, finished once at loop end.
#[derive(Debug, Clone, Default)]
pub struct LongRunDetector {
    config: LongRunConfig,
    ticks: u64,
    max_tick_ms: u64,
    max_tick_at: u64,
    over_budget_ticks: u64,
    max_gap_ms: Option<u64>,
    first_event_loss: Option<u64>,
    first_discovery_loss: Option<u64>,
    identity_budget_exhausted: bool,
    identity_unavailable: u64,
    newcomer_pending: u64,
    newcomer_oldest_pending_age_ms: Option<u64>,
}

impl LongRunDetector {
    pub fn new(config: LongRunConfig) -> Self {
        Self {
            config,
            ..Self::default()
        }
    }

    /// One completed tick's wall time. Errored ticks (the loop's `?` and
    /// `break` paths) are never noted: the detector observes completed
    /// ticks only.
    pub fn note_tick(&mut self, tick: u64, wall_ms: u64) {
        self.ticks += 1;
        if wall_ms > self.max_tick_ms {
            self.max_tick_ms = wall_ms;
            self.max_tick_at = tick;
        }
        if wall_ms > self.config.tick_latency_max_ms {
            self.over_budget_ticks += 1;
        }
    }

    /// One inter-drain gap, as computed by the scheduling accumulator.
    pub fn note_gap(&mut self, gap_ms: u64) {
        self.max_gap_ms = Some(self.max_gap_ms.map_or(gap_ms, |max| max.max(gap_ms)));
    }

    /// Loss counters read once, after the first drain: the ramp-up share.
    /// `event_loss` is `None` in metrics mode (no EVENTS drain); discovery
    /// drains in every mode, so its first reading is always present.
    pub fn note_first_drain_loss(&mut self, event_loss: Option<u64>, discovery_loss: u64) {
        self.first_event_loss = event_loss;
        self.first_discovery_loss = Some(discovery_loss);
    }

    /// Latest kernel identity health (COOKIE_CTL): whether the
    /// lifetime budget is spent and how many identities were refused.
    /// Replaced, never merged: the loop syncs the latest snapshot,
    /// with a final read at loop end.
    pub fn note_identity_budget(&mut self, exhausted: bool, unavailable: u64) {
        self.identity_budget_exhausted = exhausted;
        self.identity_unavailable = unavailable;
    }

    /// Latest newcomer point-in-time: pids still waiting and their
    /// oldest known pending age. Replaced per sync, like the budget.
    pub fn note_newcomer(&mut self, pending: u64, oldest_pending_age_ms: Option<u64>) {
        self.newcomer_pending = pending;
        self.newcomer_oldest_pending_age_ms = oldest_pending_age_ms;
    }

    /// Splits one loss counter into ramp-up (first drain) and steady
    /// shares, returning the steady share plus any finding. A first
    /// reading above its total is a counter inconsistency: reported as a
    /// finding, never rendered as a nonsense share.
    fn split_loss(
        code: &'static str,
        first: Option<u64>,
        total: u64,
    ) -> (Option<u64>, Option<LongRunFinding>) {
        let Some(early) = first else {
            return (None, None);
        };
        if early == 0 {
            return (Some(total), None);
        }
        if early > total {
            return (
                None,
                Some(LongRunFinding {
                    code,
                    detail: format!(
                        "first-drain {early} over total {total}: counter inconsistency, steady share uncomputable"
                    ),
                    at_tick: Some(1),
                }),
            );
        }
        let steady = total - early;
        let detail = if steady == 0 {
            format!("all {total} lost in first drain")
        } else {
            format!("first-drain {early}/{total}, steady {steady}")
        };
        (
            Some(steady),
            Some(LongRunFinding {
                code,
                detail,
                at_tick: Some(1),
            }),
        )
    }

    /// Derives findings from the recorded extrema and loss splits.
    /// Totals are the loop-end counters (the same values the scheduling
    /// snapshot publishes); first-drain readings never exceed them.
    /// Bounds are strict: a tick or gap exactly at its bound is clean.
    pub fn finish(&self, total_event_loss: u64, total_discovery_loss: u64) -> LongRunReport {
        let mut findings = Vec::new();
        if self.max_tick_ms > self.config.tick_latency_max_ms {
            findings.push(LongRunFinding {
                code: FINDING_TICK_OVER_BUDGET,
                detail: format!(
                    "{}ms at tick {} ({} of {} ticks over {}ms)",
                    self.max_tick_ms,
                    self.max_tick_at,
                    self.over_budget_ticks,
                    self.ticks,
                    self.config.tick_latency_max_ms
                ),
                at_tick: Some(self.max_tick_at),
            });
        }
        if let Some(gap_ms) = self.max_gap_ms
            && gap_ms > self.config.stall_gap_ms
        {
            findings.push(LongRunFinding {
                code: FINDING_LOOP_STALLED,
                detail: format!(
                    "max gap {}ms over {}ms stall bound",
                    gap_ms, self.config.stall_gap_ms
                ),
                at_tick: None,
            });
        }
        let (steady_event_loss, event_finding) = Self::split_loss(
            FINDING_EARLY_EVENT_LOSS,
            self.first_event_loss,
            total_event_loss,
        );
        findings.extend(event_finding);
        let (steady_discovery_loss, discovery_finding) = Self::split_loss(
            FINDING_EARLY_DISCOVERY_LOSS,
            self.first_discovery_loss,
            total_discovery_loss,
        );
        findings.extend(discovery_finding);
        if self.identity_budget_exhausted || self.identity_unavailable > 0 {
            let detail = if self.identity_budget_exhausted {
                format!(
                    "lifetime budget of {IMAGE_IDENTITY_TICKET_LIMIT} identities spent; {} refused",
                    self.identity_unavailable
                )
            } else {
                format!(
                    "{} refused without a spent budget",
                    self.identity_unavailable
                )
            };
            findings.push(LongRunFinding {
                code: FINDING_IDENTITY_BUDGET_EXHAUSTED,
                detail,
                at_tick: None,
            });
        }
        if newcomer_stalled(self.newcomer_pending, self.newcomer_oldest_pending_age_ms) {
            findings.push(LongRunFinding {
                code: FINDING_NEWCOMER_QUEUE_STALLED,
                detail: format!(
                    "{} pending, oldest {}ms (stall bound {NEWCOMER_STALL_AGE_MS}ms)",
                    self.newcomer_pending,
                    self.newcomer_oldest_pending_age_ms
                        .expect("a stall has a known oldest age"),
                ),
                at_tick: None,
            });
        }
        LongRunReport {
            findings,
            ticks_observed: self.ticks,
            max_tick_ms: self.max_tick_ms,
            max_gap_ms: self.max_gap_ms,
            early_event_loss: self.first_event_loss,
            steady_event_loss,
            early_discovery_loss: self.first_discovery_loss,
            steady_discovery_loss,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ordinary_detector() -> LongRunDetector {
        let mut detector = LongRunDetector::new(LongRunConfig::default());
        for tick in 1..=120 {
            detector.note_tick(tick, 2);
        }
        detector.note_gap(2);
        detector.note_gap(45);
        detector.note_first_drain_loss(Some(0), 0);
        detector
    }

    #[test]
    fn clean_run_reports_numbers_without_findings() {
        let report = ordinary_detector().finish(0, 0);
        assert!(report.is_clean());
        assert_eq!(report.ticks_observed, 120);
        assert_eq!(report.max_tick_ms, 2);
        assert_eq!(report.max_gap_ms, Some(45));
        assert_eq!(report.steady_event_loss, Some(0));
        assert_eq!(report.steady_discovery_loss, Some(0));
        let line = report.report_line();
        assert!(line.contains("p11scope: longrun: clean"), "{line}");
        assert!(line.contains("ticks 120"), "{line}");
    }

    #[test]
    fn unobserved_drain_gap_never_reports_a_measured_zero() {
        let mut detector = LongRunDetector::default();
        detector.note_tick(1, 2);
        detector.note_first_drain_loss(None, 0);
        let line = detector.finish(0, 0).report_line();
        assert!(line.contains("max gap n/a"), "{line}");
    }

    #[test]
    fn observed_zero_drain_gap_remains_a_measured_zero() {
        let mut detector = LongRunDetector::default();
        detector.note_tick(1, 2);
        detector.note_first_drain_loss(Some(0), 0);
        detector.note_gap(0);
        let line = detector.finish(0, 0).report_line();
        assert!(line.contains("max gap 0ms"), "{line}");
    }

    // T2 (RED): a tick past the forced-sweep max is a finding.
    #[test]
    fn tick_over_budget_finding_names_worst_tick() {
        let mut detector = ordinary_detector();
        detector.note_tick(88, 2_010);
        detector.note_tick(89, 1_950);
        let report = detector.finish(0, 0);
        assert!(!report.is_clean());
        let finding = report
            .findings
            .iter()
            .find(|finding| finding.code == FINDING_TICK_OVER_BUDGET)
            .expect("tick_over_budget finding");
        assert_eq!(finding.at_tick, Some(88));
        assert!(
            finding.detail.contains("2010ms at tick 88"),
            "unexpected detail: {}",
            finding.detail
        );
        assert!(finding.detail.contains("2 ticks"), "{}", finding.detail);
    }

    // T2 (RED): a gap past the stall bound is a deep freeze.
    #[test]
    fn stall_gap_finding_fires_past_bound() {
        let mut detector = ordinary_detector();
        detector.note_gap(12_000);
        let report = detector.finish(0, 0);
        let finding = report
            .findings
            .iter()
            .find(|finding| finding.code == FINDING_LOOP_STALLED)
            .expect("loop_stalled finding");
        assert_eq!(finding.at_tick, None);
        assert!(finding.detail.contains("12000ms"), "{}", finding.detail);
        assert_eq!(report.max_gap_ms, Some(12_000));
    }

    #[test]
    fn gap_at_bound_is_not_a_stall() {
        let mut detector = ordinary_detector();
        detector.note_gap(STALL_GAP_MS);
        let report = detector.finish(0, 0);
        assert!(report.is_clean(), "{report:?}");
    }

    // T2 (RED): first-drain loss splits ramp-up from steady state.
    #[test]
    fn early_event_loss_reports_ramp_up_share() {
        let mut detector = ordinary_detector();
        detector.note_first_drain_loss(Some(7_521), 0);
        let report = detector.finish(20_006, 0);
        assert_eq!(report.early_event_loss, Some(7_521));
        assert_eq!(report.steady_event_loss, Some(12_485));
        let finding = report
            .findings
            .iter()
            .find(|finding| finding.code == FINDING_EARLY_EVENT_LOSS)
            .expect("early_event_loss finding");
        assert_eq!(finding.at_tick, Some(1));
        assert!(finding.detail.contains("7521/20006"), "{}", finding.detail);
    }

    // T2 (RED): loss carried entirely by the first drain says so.
    #[test]
    fn all_ramp_up_loss_says_so() {
        let mut detector = ordinary_detector();
        detector.note_first_drain_loss(Some(100), 0);
        let report = detector.finish(100, 0);
        let finding = report
            .findings
            .iter()
            .find(|finding| finding.code == FINDING_EARLY_EVENT_LOSS)
            .expect("early_event_loss finding");
        assert!(finding.detail.contains("all 100"), "{}", finding.detail);
    }

    #[test]
    fn zero_first_drain_loss_is_clean_with_steady_split() {
        let report = ordinary_detector().finish(5, 7);
        assert!(report.is_clean(), "{report:?}");
        assert_eq!(report.steady_event_loss, Some(5));
        assert_eq!(report.steady_discovery_loss, Some(7));
    }

    #[test]
    fn steady_discovery_loss_is_not_called_clean() {
        // No long-run findings, but discovery loss was reported: the
        // line must not say "clean" while the numbers show the loss.
        // `is_clean` still holds (no findings), so default stderr
        // stays quiet and only -v shows this line.
        let report = ordinary_detector().finish(0, 12_742);
        assert!(report.is_clean(), "{report:?}");
        let line = report.report_line();
        assert!(!line.contains("clean"), "{line}");
        assert!(line.contains("no long-run findings"), "{line}");
        assert!(line.contains("steady 12742"), "{line}");
    }

    #[test]
    fn steady_event_loss_is_not_called_clean() {
        // Symmetric twin: measured event loss likewise blocks "clean".
        let report = ordinary_detector().finish(300, 0);
        assert!(report.is_clean(), "{report:?}");
        let line = report.report_line();
        assert!(!line.contains("clean"), "{line}");
        assert!(line.contains("no long-run findings"), "{line}");
        assert!(line.contains("steady 300"), "{line}");
    }

    // T2 (RED): metrics mode leaves event loss unmeasured but still
    // splits discovery loss.
    #[test]
    fn metrics_mode_event_loss_stays_unmeasured() {
        let mut detector = LongRunDetector::new(LongRunConfig::default());
        detector.note_tick(1, 2);
        detector.note_first_drain_loss(None, 3);
        let report = detector.finish(0, 10);
        assert_eq!(report.early_event_loss, None);
        assert_eq!(report.steady_event_loss, None);
        assert_eq!(report.steady_discovery_loss, Some(7));
        assert!(
            report
                .findings
                .iter()
                .all(|finding| finding.code != FINDING_EARLY_EVENT_LOSS),
            "{report:?}"
        );
        assert!(
            report
                .findings
                .iter()
                .any(|finding| finding.code == FINDING_EARLY_DISCOVERY_LOSS),
            "{report:?}"
        );
        assert!(report.report_line().contains("early n/a"), "{report:?}");
    }

    // T2 (RED): a first reading above its total is reported, never
    // rendered as a nonsense share.
    #[test]
    fn inconsistent_counters_stay_honest() {
        let mut detector = ordinary_detector();
        detector.note_first_drain_loss(Some(10), 0);
        let report = detector.finish(5, 0);
        let finding = report
            .findings
            .iter()
            .find(|finding| finding.code == FINDING_EARLY_EVENT_LOSS)
            .expect("early_event_loss finding");
        assert!(
            finding.detail.contains("inconsistency"),
            "{}",
            finding.detail
        );
    }

    // T2 (RED): the stderr line lists every finding with its numbers.
    #[test]
    fn report_line_lists_every_finding() {
        let mut detector = ordinary_detector();
        detector.note_tick(88, 2_010);
        detector.note_first_drain_loss(Some(7_521), 0);
        let report = detector.finish(20_006, 0);
        let line = report.report_line();
        assert!(line.contains("p11scope: longrun: 2 findings"), "{line}");
        assert!(line.contains(FINDING_TICK_OVER_BUDGET), "{line}");
        assert!(line.contains(FINDING_EARLY_EVENT_LOSS), "{line}");
        assert!(line.contains("max tick 2010ms"), "{line}");
    }

    // Identity budget (RED): a spent lifetime budget is a finding
    // with counts, never a clean line. The 66-pending/115-minute stall
    // below is the observed long-run shape.
    #[test]
    fn identity_budget_exhaustion_is_a_finding_with_counts() {
        let mut detector = ordinary_detector();
        detector.note_identity_budget(true, 168_027);
        let report = detector.finish(0, 0);
        assert!(!report.is_clean(), "{report:?}");
        let finding = report
            .findings
            .iter()
            .find(|finding| finding.code == FINDING_IDENTITY_BUDGET_EXHAUSTED)
            .expect("identity_budget_exhausted finding");
        assert_eq!(finding.at_tick, None);
        assert!(
            finding.detail.contains("168027"),
            "unexpected detail: {}",
            finding.detail
        );
        assert!(
            finding.detail.contains("262144"),
            "unexpected detail: {}",
            finding.detail
        );
        let line = report.report_line();
        assert!(line.contains(FINDING_IDENTITY_BUDGET_EXHAUSTED), "{line}");
        assert!(!line.contains("clean"), "{line}");
    }

    // Identity budget (RED): refusals without a spent budget (a bad
    // cell, a failed create) still thinned capture, so they are a
    // finding too.
    #[test]
    fn identity_refusals_without_spent_budget_are_a_finding() {
        let mut detector = ordinary_detector();
        detector.note_identity_budget(false, 3);
        let report = detector.finish(0, 0);
        assert!(!report.is_clean(), "{report:?}");
        let finding = report
            .findings
            .iter()
            .find(|finding| finding.code == FINDING_IDENTITY_BUDGET_EXHAUSTED)
            .expect("identity_budget_exhausted finding");
        assert!(
            finding.detail.contains('3'),
            "unexpected detail: {}",
            finding.detail
        );
    }

    // Identity budget (RED): a budget spent with nothing refused yet
    // lost nothing, but the next process goes unseen, so the line
    // names the spent budget instead of reporting clean.
    #[test]
    fn spent_budget_without_refusals_is_named() {
        let mut detector = ordinary_detector();
        detector.note_identity_budget(true, 0);
        let report = detector.finish(0, 0);
        assert!(!report.is_clean(), "{report:?}");
        assert!(
            report
                .findings
                .iter()
                .any(|finding| finding.code == FINDING_IDENTITY_BUDGET_EXHAUSTED),
            "{report:?}"
        );
    }

    // Identity budget (RED twin): healthy identity and newcomer
    // inputs keep the clean line.
    #[test]
    fn identity_health_quiet_twin_stays_clean() {
        let mut detector = ordinary_detector();
        detector.note_identity_budget(false, 0);
        detector.note_newcomer(0, None);
        let report = detector.finish(0, 0);
        assert!(report.is_clean(), "{report:?}");
    }

    // Newcomer stall (RED): newcomers still waiting past the stall
    // bound at loop end never got admitted, so they are a finding
    // with counts, never a clean line.
    #[test]
    fn newcomer_stall_is_a_finding_with_counts() {
        let mut detector = ordinary_detector();
        detector.note_newcomer(66, Some(6_916_817));
        let report = detector.finish(0, 0);
        assert!(!report.is_clean(), "{report:?}");
        let finding = report
            .findings
            .iter()
            .find(|finding| finding.code == FINDING_NEWCOMER_QUEUE_STALLED)
            .expect("newcomer_queue_stalled finding");
        assert_eq!(finding.at_tick, None);
        assert!(
            finding.detail.contains("66"),
            "unexpected detail: {}",
            finding.detail
        );
        assert!(
            finding.detail.contains("6916817"),
            "unexpected detail: {}",
            finding.detail
        );
        let line = report.report_line();
        assert!(line.contains(FINDING_NEWCOMER_QUEUE_STALLED), "{line}");
        assert!(!line.contains("clean"), "{line}");
    }

    // Newcomer stall (RED twins): an empty queue, young pending
    // newcomers and an age exactly at the bound are not a stall.
    #[test]
    fn newcomer_quiet_twins_stay_clean() {
        for (pending, oldest) in [
            (0, None),
            (0, Some(9_999_999)),
            (3, None),
            (3, Some(500)),
            (5, Some(NEWCOMER_STALL_AGE_MS)),
        ] {
            let mut detector = ordinary_detector();
            detector.note_newcomer(pending, oldest);
            let report = detector.finish(0, 0);
            assert!(
                report.is_clean(),
                "pending={pending} oldest={oldest:?}: {report:?}"
            );
        }
    }

    // Newcomer stall (RED): the stall predicate bounds are strict.
    #[test]
    fn newcomer_stall_predicate_bounds() {
        assert!(newcomer_stalled(1, Some(NEWCOMER_STALL_AGE_MS + 1)));
        assert!(!newcomer_stalled(1, Some(NEWCOMER_STALL_AGE_MS)));
        assert!(!newcomer_stalled(0, Some(NEWCOMER_STALL_AGE_MS + 1)));
        assert!(!newcomer_stalled(1, None));
        assert!(!newcomer_stalled(0, None));
    }

    // Identity health (RED): no usable COOKIE_CTL sample — the final
    // read failed and no tick sampled one — is a named finding, never
    // a clean line. The detector must not substitute its healthy
    // default for an unread state.
    #[test]
    fn unread_identity_health_is_a_finding_never_clean() {
        let mut detector = ordinary_detector();
        detector.note_newcomer(0, None);
        let report = detector.finish(0, 0);
        assert!(!report.is_clean(), "{report:?}");
        let finding = report
            .findings
            .iter()
            .find(|finding| finding.code == "identity_health_unknown")
            .expect("identity_health_unknown finding");
        assert_eq!(finding.at_tick, None);
        let line = report.report_line();
        assert!(line.contains("identity_health_unknown"), "{line}");
        assert!(!line.contains("clean"), "{line}");
    }

    // Identity health (twin): one healthy sample clears the unread
    // state and keeps the clean line.
    #[test]
    fn sampled_healthy_identity_keeps_the_clean_line() {
        let mut detector = ordinary_detector();
        detector.note_identity_budget(false, 0);
        detector.note_newcomer(0, None);
        let report = detector.finish(0, 0);
        assert!(report.is_clean(), "{report:?}");
        assert!(
            report.report_line().contains("p11scope: longrun: clean"),
            "{report:?}"
        );
    }

    // T2 (RED): thresholds come from the config, not the constants.
    #[test]
    fn custom_config_moves_thresholds() {
        let mut detector = LongRunDetector::new(LongRunConfig {
            tick_latency_max_ms: 100,
            stall_gap_ms: 50,
        });
        detector.note_tick(1, 150);
        detector.note_gap(60);
        detector.note_first_drain_loss(Some(0), 0);
        let report = detector.finish(0, 0);
        assert!(
            report
                .findings
                .iter()
                .any(|finding| finding.code == FINDING_TICK_OVER_BUDGET),
            "{report:?}"
        );
        assert!(
            report
                .findings
                .iter()
                .any(|finding| finding.code == FINDING_LOOP_STALLED),
            "{report:?}"
        );
    }
}
