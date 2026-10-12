//! SPDX-License-Identifier: GPL-3.0-or-later
//! Capture-local, optional metadata. Never consulted for capture authority.

#[cfg(not(feature = "h6-reexec-diagnostic"))]
macro_rules! observe {
    ($receiver:expr, |$observer:ident| $body:block) => {{}};
}
#[cfg(feature = "h6-reexec-diagnostic")]
macro_rules! observe {
    ($receiver:expr, |$observer:ident| $body:block) => {{
        if let Some($observer) = $receiver.reexec_diagnostic()
            && $observer.active()
        {
            $body
        }
    }};
}
pub(crate) use observe;

#[cfg(feature = "h6-reexec-diagnostic")]
mod enabled {
    use crate::{metrics::SlotReport, sink::SinkDrops};
    use std::{
        fmt::{self, Write as _},
        sync::{Arc, Mutex},
    };

    pub(crate) const RECORD_CAP: u64 = 1024;
    pub(crate) const LINE_CAP: usize = 192;
    // One clipping record, eight terminal data records and the final summary.
    const RESERVED: u64 = 10;

    #[derive(Clone, Copy)]
    pub(crate) enum Phase {
        Exec,
        Request,
        Refresh,
        Scan,
        ContextRetire,
        Candidate,
        Identity,
        Rearm,
        Preflight,
        Apply,
        DetachSlots,
        NewAttach,
        ReplaceAttach,
        NativeEntry,
        NativeReturn,
        NativeOther,
        AttachState,
        Gap,
        SettleMarker,
        SettleRequest,
        TraceHistory,
        TraceOutput,
        CanaryCompleted,
        CanaryInflight,
        CanaryDerived,
        TraceCounts,
        Sink,
        Terminal,
        Cap,
        Setup,
    }
    impl Phase {
        fn label(self) -> &'static str {
            match self {
                Self::Exec => "exec",
                Self::Request => "request",
                Self::Refresh => "refresh",
                Self::Scan => "scan",
                Self::ContextRetire => "context_retire",
                Self::Candidate => "candidate",
                Self::Identity => "identity",
                Self::Rearm => "rearm",
                Self::Preflight => "preflight",
                Self::Apply => "apply",
                Self::DetachSlots => "detach_slots",
                Self::NewAttach => "new_attach",
                Self::ReplaceAttach => "replace_attach",
                Self::NativeEntry => "native_entry",
                Self::NativeReturn => "native_return",
                Self::NativeOther => "native_other",
                Self::AttachState => "attach_state",
                Self::Gap => "gap",
                Self::SettleMarker => "settle_marker",
                Self::SettleRequest => "settle_request",
                Self::TraceHistory => "trace_history",
                Self::TraceOutput => "trace_output",
                Self::CanaryCompleted => "canary_completed",
                Self::CanaryInflight => "canary_inflight",
                Self::CanaryDerived => "canary_derived",
                Self::TraceCounts => "trace_counts",
                Self::Sink => "sink",
                Self::Terminal => "terminal",
                Self::Cap => "cap",
                Self::Setup => "setup",
            }
        }
    }
    #[derive(Clone, Copy)]
    pub(crate) enum Outcome {
        Begin,
        Ok,
        Error,
        Unavailable,
        Queued,
        Refused,
        Renewed,
        NoOwner,
        NoBinding,
        NoTargets,
        SerialChanged,
        Moot,
        Preserved,
        Forced,
        NoHealth,
        NoPairs,
        NoValidation,
        Stopped,
        Overtaken,
        Incomplete,
        Clipped,
        Accepted,
        Rejected,
        Attempted,
        PriorErrorSkip,
        LimitSkip,
    }
    impl Outcome {
        fn label(self) -> &'static str {
            match self {
                Self::Begin => "begin",
                Self::Ok => "ok",
                Self::Error => "error",
                Self::Unavailable => "unavailable",
                Self::Queued => "queued",
                Self::Refused => "refused",
                Self::Renewed => "renewed",
                Self::NoOwner => "no_owner",
                Self::NoBinding => "no_binding",
                Self::NoTargets => "no_targets",
                Self::SerialChanged => "serial_changed",
                Self::Moot => "moot",
                Self::Preserved => "preserved",
                Self::Forced => "forced",
                Self::NoHealth => "no_health",
                Self::NoPairs => "no_pairs",
                Self::NoValidation => "no_validation",
                Self::Stopped => "stopped",
                Self::Overtaken => "overtaken",
                Self::Incomplete => "incomplete",
                Self::Clipped => "clipped",
                Self::Accepted => "accepted",
                Self::Rejected => "rejected",
                Self::Attempted => "attempted",
                Self::PriorErrorSkip => "prior_error_skip",
                Self::LimitSkip => "limit_skip",
            }
        }
    }
    #[derive(Clone, Copy)]
    pub(crate) struct Record {
        pub(crate) phase: Phase,
        pub(crate) outcome: Outcome,
        pub(crate) serial: Option<u64>,
        pub(crate) time_ms: Option<u64>,
        pub(crate) counts: [Option<u64>; 4],
    }
    #[derive(Clone, Copy, Debug, Default)]
    pub(crate) struct Summary {
        pub(crate) attempts: u64,
        pub(crate) failures: u64,
        pub(crate) dropped_bytes: u64,
        pub(crate) clipped: u64,
        pub(crate) format_failures: u64,
        pub(crate) unknown_times: u64,
    }
    #[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
    pub(crate) struct TraceCounts {
        pub(crate) calls: u64,
        pub(crate) accepted: u64,
        pub(crate) rejected: u64,
        pub(crate) attempted: u64,
        pub(crate) limit_skipped: u64,
        pub(crate) prior_error_skipped: u64,
        pub(crate) write_errors: u64,
        pub(crate) stdout_closed: u64,
    }
    #[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
    pub(crate) struct CanaryCounts {
        pub(crate) completed: Option<u64>,
        pub(crate) in_flight: Option<u64>,
        pub(crate) derived_entered: Option<u64>,
        pub(crate) slots: u64,
    }
    pub(crate) fn canary_counts(reports: &[SlotReport]) -> CanaryCounts {
        let mut counts = CanaryCounts {
            completed: Some(0),
            in_flight: Some(0),
            derived_entered: Some(0),
            slots: 0,
        };
        for report in reports
            .iter()
            .filter(|r| r.names.iter().any(|name| name == "C_GetInfo"))
        {
            counts.slots = counts.slots.saturating_add(1);
            counts.completed = counts.completed.and_then(|n| n.checked_add(report.calls));
            counts.in_flight = counts
                .in_flight
                .and_then(|n| n.checked_add(report.in_flight));
        }
        counts.derived_entered = counts
            .completed
            .zip(counts.in_flight)
            .and_then(|(done, flight)| done.checked_add(flight));
        counts
    }
    pub(crate) fn elapsed_ms(start: Option<u64>, end: Option<u64>) -> Option<u64> {
        end?.checked_sub(start?).map(|n| n / 1_000_000)
    }
    #[derive(Default)]
    struct State {
        active: bool,
        finished: bool,
        execs: u64,
        serial: Option<u64>,
        origin_ns: Option<u64>,
        cap_noted: bool,
        summary: Summary,
        trace: TraceCounts,
    }
    #[derive(Clone, Default)]
    pub(crate) struct Diagnostic(Arc<Mutex<State>>);

    struct Number(Option<u64>);
    impl fmt::Display for Number {
        fn fmt(&self, out: &mut fmt::Formatter<'_>) -> fmt::Result {
            match self.0 {
                Some(n) => write!(out, "{n}"),
                None => out.write_str("?"),
            }
        }
    }
    struct Line {
        bytes: [u8; LINE_CAP - 1],
        len: usize,
    }
    impl Default for Line {
        fn default() -> Self {
            Self {
                bytes: [0; LINE_CAP - 1],
                len: 0,
            }
        }
    }
    impl fmt::Write for Line {
        fn write_str(&mut self, value: &str) -> fmt::Result {
            let end = self.len.checked_add(value.len()).ok_or(fmt::Error)?;
            let range = self.bytes.get_mut(self.len..end).ok_or(fmt::Error)?;
            range.copy_from_slice(value.as_bytes());
            self.len = end;
            Ok(())
        }
    }
    impl Diagnostic {
        pub(crate) fn selected(pid: bool, explicit_singles: bool) -> Option<Self> {
            (pid && explicit_singles).then(Self::default)
        }
        pub(crate) fn matched_exec(&self) {
            let mut state = self.0.lock().unwrap_or_else(|e| e.into_inner());
            state.execs = state.execs.saturating_add(1);
            state.active = state.execs == 1 && !state.finished;
            let overtaken = state.execs > 1 && !state.finished;
            let serial = state.serial;
            let execs = state.execs;
            drop(state);
            if overtaken {
                self.record_with(
                    Record {
                        phase: Phase::Exec,
                        outcome: Outcome::Overtaken,
                        serial,
                        time_ms: None,
                        counts: [Some(execs), None, None, None],
                    },
                    true,
                    crate::sink::try_stderr_line,
                );
            }
        }
        pub(crate) fn active(&self) -> bool {
            self.0.lock().unwrap_or_else(|e| e.into_inner()).active
        }
        pub(crate) fn serial(&self, serial: Option<u64>) -> bool {
            let mut state = self.0.lock().unwrap_or_else(|e| e.into_inner());
            let renewed = state.serial.is_some() && state.serial != serial;
            state.serial = serial;
            renewed
        }
        pub(crate) fn summary(&self) -> Summary {
            self.0.lock().unwrap_or_else(|e| e.into_inner()).summary
        }
        #[cfg(test)]
        pub(crate) fn trace_counts(&self) -> TraceCounts {
            self.0.lock().unwrap_or_else(|e| e.into_inner()).trace
        }
        pub(crate) fn trace_observation(
            &self,
            accepted: bool,
            attempted: bool,
            prior_error: bool,
            write_error: bool,
            stdout_open: bool,
        ) {
            if !self.active() {
                return;
            }
            let counts = {
                let mut state = self.0.lock().unwrap_or_else(|e| e.into_inner());
                let t = &mut state.trace;
                t.calls = t.calls.saturating_add(1);
                if accepted {
                    t.accepted = t.accepted.saturating_add(1);
                } else {
                    t.rejected = t.rejected.saturating_add(1);
                }
                if prior_error {
                    t.prior_error_skipped = t.prior_error_skipped.saturating_add(1);
                } else if attempted {
                    t.attempted = t.attempted.saturating_add(1);
                } else {
                    t.limit_skipped = t.limit_skipped.saturating_add(1);
                }
                if write_error {
                    t.write_errors = t.write_errors.saturating_add(1);
                }
                if !stdout_open {
                    t.stdout_closed = t.stdout_closed.saturating_add(1);
                }
                *t
            };
            self.note(
                Phase::TraceHistory,
                if accepted {
                    Outcome::Accepted
                } else {
                    Outcome::Rejected
                },
                [
                    Some(counts.calls),
                    Some(counts.accepted),
                    Some(counts.rejected),
                    None,
                ],
            );
            self.note(
                Phase::TraceOutput,
                if prior_error {
                    Outcome::PriorErrorSkip
                } else if attempted {
                    Outcome::Attempted
                } else {
                    Outcome::LimitSkip
                },
                [
                    Some(counts.attempted),
                    Some(counts.limit_skipped),
                    Some(counts.write_errors),
                    Some(u64::from(stdout_open)),
                ],
            );
        }

        pub(crate) fn note(&self, phase: Phase, outcome: Outcome, counts: [Option<u64>; 4]) {
            if !self.active() {
                return;
            }
            let now = crate::attach::monotonic_ns();
            let (serial, origin) = {
                let mut state = self.0.lock().unwrap_or_else(|e| e.into_inner());
                if state.origin_ns.is_none() && state.summary.attempts == 0 {
                    state.origin_ns = now;
                }
                (state.serial, state.origin_ns)
            };
            self.record_with(
                Record {
                    phase,
                    outcome,
                    serial,
                    time_ms: elapsed_ms(origin, now),
                    counts,
                },
                false,
                crate::sink::try_stderr_line,
            );
            let cap = {
                let mut state = self.0.lock().unwrap_or_else(|e| e.into_inner());
                let cap = state.summary.clipped > 0 && !state.cap_noted;
                state.cap_noted |= cap;
                cap
            };
            if cap {
                self.record_with(
                    Record {
                        phase: Phase::Cap,
                        outcome: Outcome::Clipped,
                        serial,
                        time_ms: elapsed_ms(origin, now),
                        counts: [Some(RECORD_CAP), Some(LINE_CAP as u64), None, None],
                    },
                    true,
                    crate::sink::try_stderr_line,
                );
            }
        }
        pub(crate) fn begin(&self, phase: Phase, counts: [Option<u64>; 4]) -> Span {
            let start = crate::attach::monotonic_ns();
            self.note(phase, Outcome::Begin, counts);
            Span {
                diag: self.clone(),
                phase,
                counts,
                start,
                finished: false,
            }
        }
        pub(crate) fn record_with(
            &self,
            record: Record,
            terminal: bool,
            mut write: impl FnMut(&str) -> std::io::Result<SinkDrops>,
        ) {
            {
                let mut state = self.0.lock().unwrap_or_else(|e| e.into_inner());
                if state.finished || (!state.active && (!terminal || state.execs == 0)) {
                    return;
                }
                let limit = if terminal {
                    RECORD_CAP
                } else {
                    RECORD_CAP - RESERVED
                };
                if state.summary.attempts >= limit {
                    state.summary.clipped = state.summary.clipped.saturating_add(1);
                    return;
                }
                state.summary.attempts += 1;
                if record.time_ms.is_none() {
                    state.summary.unknown_times = state.summary.unknown_times.saturating_add(1);
                }
            }
            let mut line = Line::default();
            let formatted = write!(
                line,
                "h6diag p={} r={} q={} t={} n={},{},{},{}",
                record.phase.label(),
                record.outcome.label(),
                Number(record.serial),
                Number(record.time_ms),
                Number(record.counts[0]),
                Number(record.counts[1]),
                Number(record.counts[2]),
                Number(record.counts[3])
            );
            if formatted.is_err() {
                let mut state = self.0.lock().unwrap_or_else(|e| e.into_inner());
                state.summary.format_failures = state.summary.format_failures.saturating_add(1);
                state.summary.failures = state.summary.failures.saturating_add(1);
                return;
            }
            // Only the fixed ASCII labels and decimal numbers reach the line.
            let text = std::str::from_utf8(&line.bytes[..line.len]).unwrap_or("");
            let result = write(text);
            let mut state = self.0.lock().unwrap_or_else(|e| e.into_inner());
            match result {
                Ok(drops) => {
                    state.summary.dropped_bytes = state
                        .summary
                        .dropped_bytes
                        .saturating_add(drops.dropped_bytes);
                    if drops.dropped_bytes != 0 || drops.timeouts != 0 {
                        state.summary.failures = state.summary.failures.saturating_add(1);
                    }
                }
                Err(_) => state.summary.failures = state.summary.failures.saturating_add(1),
            }
        }
        pub(crate) fn finish(
            &self,
            canary: CanaryCounts,
            raw_calls: u64,
            sink: [u64; 4],
            gap: [Option<u64>; 4],
        ) {
            let (serial, origin, trace, execs, finished) = {
                let state = self.0.lock().unwrap_or_else(|e| e.into_inner());
                (
                    state.serial,
                    state.origin_ns,
                    state.trace,
                    state.execs,
                    state.finished,
                )
            };
            if execs == 0 || finished {
                return;
            }
            let time = elapsed_ms(origin, crate::attach::monotonic_ns());
            let records = [
                (
                    Phase::CanaryCompleted,
                    [canary.completed, Some(canary.slots), None, None],
                ),
                (
                    Phase::CanaryInflight,
                    [canary.in_flight, Some(canary.slots), None, None],
                ),
                (
                    Phase::CanaryDerived,
                    [canary.derived_entered, Some(canary.slots), None, None],
                ),
                (
                    Phase::TraceCounts,
                    [
                        Some(trace.calls),
                        Some(trace.accepted),
                        Some(trace.rejected),
                        Some(raw_calls),
                    ],
                ),
                (
                    Phase::TraceOutput,
                    [
                        Some(trace.attempted),
                        Some(trace.limit_skipped),
                        Some(trace.prior_error_skipped),
                        Some(trace.write_errors),
                    ],
                ),
                (Phase::Sink, sink.map(Some)),
                (Phase::Gap, gap),
                (
                    Phase::Terminal,
                    [
                        Some(trace.stdout_closed),
                        Some(execs),
                        Some(self.summary().unknown_times),
                        Some(self.summary().format_failures),
                    ],
                ),
            ];
            for (phase, counts) in records {
                self.record_with(
                    Record {
                        phase,
                        outcome: Outcome::Ok,
                        serial,
                        time_ms: time,
                        counts,
                    },
                    true,
                    crate::sink::try_stderr_line,
                );
            }
            let summary = self.summary();
            self.record_with(
                Record {
                    phase: Phase::Terminal,
                    outcome: if summary.failures > 0 || summary.clipped > 0 {
                        Outcome::Incomplete
                    } else {
                        Outcome::Ok
                    },
                    serial,
                    time_ms: time,
                    counts: [
                        Some(summary.attempts.saturating_add(1)),
                        Some(summary.failures),
                        Some(summary.dropped_bytes),
                        Some(summary.clipped),
                    ],
                },
                true,
                crate::sink::try_stderr_line,
            );
            let mut state = self.0.lock().unwrap_or_else(|e| e.into_inner());
            state.finished = true;
            state.active = false;
        }
    }
    pub(crate) struct Span {
        diag: Diagnostic,
        phase: Phase,
        counts: [Option<u64>; 4],
        start: Option<u64>,
        finished: bool,
    }
    impl Span {
        pub(crate) fn finish(mut self, outcome: Outcome) {
            self.emit(outcome);
            self.finished = true;
        }
        pub(crate) fn finish_result<T, E>(self, result: &Result<T, E>) {
            self.finish(if result.is_ok() {
                Outcome::Ok
            } else {
                Outcome::Error
            });
        }
        fn emit(&self, outcome: Outcome) {
            let time = elapsed_ms(self.start, crate::attach::monotonic_ns());
            let serial = self.diag.0.lock().unwrap_or_else(|e| e.into_inner()).serial;
            self.diag.record_with(
                Record {
                    phase: self.phase,
                    outcome,
                    serial,
                    time_ms: time,
                    counts: self.counts,
                },
                false,
                crate::sink::try_stderr_line,
            );
        }
    }
    impl Drop for Span {
        fn drop(&mut self) {
            if !self.finished {
                self.emit(Outcome::Unavailable);
            }
        }
    }
}
#[cfg(feature = "h6-reexec-diagnostic")]
pub(crate) use enabled::*;

#[cfg(test)]
mod tests {
    #[cfg(not(feature = "h6-reexec-diagnostic"))]
    #[test]
    fn reexec_diagnostic_off_evaluates_neither_receiver_nor_metadata() {
        let touched = std::cell::Cell::new(0);
        super::observe!(
            {
                touched.set(1);
                panic!("receiver evaluated")
            },
            |diag| {
                touched.set(2);
                let _clock = crate::attach::monotonic_ns();
                panic!("metadata evaluated");
            }
        );
        assert_eq!(touched.get(), 0);
    }

    #[cfg(feature = "h6-reexec-diagnostic")]
    mod on {
        use super::super::*;
        use crate::sink::SinkDrops;

        fn event(time_ms: Option<u64>) -> Record {
            Record {
                phase: Phase::Refresh,
                outcome: Outcome::Ok,
                serial: Some(4),
                time_ms,
                counts: [Some(1), Some(2), Some(3), Some(4)],
            }
        }
        #[test]
        fn reexec_diagnostic_requires_explicit_pid_singles_and_matched_exec() {
            for (pid, singles) in [(false, false), (false, true), (true, false)] {
                assert!(Diagnostic::selected(pid, singles).is_none());
            }
            let diag = Diagnostic::selected(true, true).unwrap();
            let mut lines = Vec::new();
            diag.record_with(event(Some(1)), false, |line| {
                lines.push(line.to_owned());
                Ok(SinkDrops::default())
            });
            assert!(lines.is_empty());
            diag.matched_exec();
            diag.record_with(event(Some(1)), false, |line| {
                lines.push(line.to_owned());
                Ok(SinkDrops::default())
            });
            assert_eq!(lines.len(), 1);
            let other = Diagnostic::selected(true, true).unwrap();
            assert!(!other.active(), "one capture must not activate another");
            diag.matched_exec();
            assert!(
                !diag.active(),
                "a second exec must end the first-exec window"
            );
        }
        #[test]
        fn reexec_diagnostic_failed_writes_consume_cap_and_reserve_terminal() {
            let diag = Diagnostic::selected(true, true).unwrap();
            diag.matched_exec();
            let mut attempted = 0;
            for _ in 0..2000 {
                diag.record_with(event(Some(1)), false, |_| {
                    attempted += 1;
                    Err(std::io::ErrorKind::BrokenPipe.into())
                });
            }
            assert_eq!(attempted, 1014);
            for _ in 0..12 {
                diag.record_with(event(Some(2)), true, |_| {
                    attempted += 1;
                    Err(std::io::ErrorKind::BrokenPipe.into())
                });
            }
            assert_eq!(attempted, 1024);
            let s = diag.summary();
            assert_eq!(s.attempts, 1024);
            assert_eq!(s.failures, 1024);
            assert!(s.clipped >= 986);
        }
        #[test]
        fn reexec_diagnostic_drops_are_counted_and_time_failure_is_unknown() {
            let diag = Diagnostic::selected(true, true).unwrap();
            diag.matched_exec();
            let mut line = String::new();
            diag.record_with(event(None), false, |text| {
                line = text.to_owned();
                Ok(SinkDrops {
                    timeouts: 1,
                    dropped_bytes: 23,
                    stall_ms: 0,
                })
            });
            assert!(
                line.contains(" t=? "),
                "failed time must not become zero: {line}"
            );
            assert_eq!(diag.summary().attempts, 1);
            assert_eq!(diag.summary().dropped_bytes, 23);
            assert_eq!(diag.summary().failures, 1);
        }
        #[test]
        fn reexec_diagnostic_maximum_numbers_fit_including_newline() {
            let diag = Diagnostic::selected(true, true).unwrap();
            diag.matched_exec();
            let record = Record {
                phase: Phase::CanaryCompleted,
                outcome: Outcome::PriorErrorSkip,
                serial: Some(u64::MAX),
                time_ms: Some(u64::MAX),
                counts: [Some(u64::MAX); 4],
            };
            diag.record_with(record, true, |line| {
                assert!(line.len() < 192);
                Ok(SinkDrops::default())
            });
            assert_eq!(diag.summary().format_failures, 0);
        }
        fn report(names: &[&str], completed: u64, in_flight: u64) -> crate::metrics::SlotReport {
            crate::metrics::SlotReport {
                names: names.iter().map(|n| (*n).to_owned()).collect(),
                aliased: names.len() > 1,
                semantic_authorized: false,
                module: None,
                module_ambiguous: false,
                module_unresolved: true,
                calls: completed,
                errors: 0,
                in_flight,
                total_ns: 0,
                max_ns: 0,
                buckets: [0; p11scope_ebpf_common::LATENCY_BUCKETS],
                rv_counts: Default::default(),
                file_offset: 0,
                target_object: None,
                ordinals: vec![],
            }
        }
        #[test]
        fn reexec_diagnostic_canary_counts_each_retained_current_alias_slot_once() {
            let counts = canary_counts(&[
                report(&["C_GetInfo", "C_GetInfo", "alias"], 20, 5),
                report(&["C_GetInfo"], 30, 2),
                report(&["C_Sign"], 999, 1),
            ]);
            assert_eq!(
                counts,
                CanaryCounts {
                    completed: Some(50),
                    in_flight: Some(7),
                    derived_entered: Some(57),
                    slots: 2
                }
            );
        }
        #[test]
        fn reexec_diagnostic_canary_overflow_and_clock_reversal_stay_unknown() {
            let counts = canary_counts(&[report(&["C_GetInfo"], u64::MAX, 1)]);
            assert_eq!(counts.completed, Some(u64::MAX));
            assert_eq!(counts.in_flight, Some(1));
            assert_eq!(counts.derived_entered, None);
            let counts = canary_counts(&[
                report(&["C_GetInfo"], u64::MAX, 0),
                report(&["C_GetInfo"], 1, 0),
            ]);
            assert_eq!(counts.completed, None);
            assert_eq!(counts.in_flight, Some(0));
            assert_eq!(counts.derived_entered, None);
            assert_eq!(elapsed_ms(None, Some(10)), None);
            assert_eq!(elapsed_ms(Some(10), Some(9)), None);
            assert_eq!(elapsed_ms(Some(10), Some(10)), Some(0));
        }
        #[test]
        fn reexec_diagnostic_inactive_hook_does_not_evaluate_metadata_or_clock() {
            struct Receiver(Diagnostic);
            impl Receiver {
                fn reexec_diagnostic(&self) -> Option<Diagnostic> {
                    Some(self.0.clone())
                }
            }
            let receiver = Receiver(Diagnostic::selected(true, true).unwrap());
            let count = std::cell::Cell::new(0);
            super::super::observe!(receiver, |diag| {
                count.set(count.get() + 1);
                diag.note(Phase::Refresh, Outcome::Ok, [None; 4]);
            });
            assert_eq!(count.get(), 0);
            receiver.0.matched_exec();
            super::super::observe!(receiver, |diag| {
                count.set(count.get() + 1);
                let _ = diag.summary();
            });
            assert_eq!(count.get(), 1);
        }
    }
}
