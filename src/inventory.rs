//! SPDX-License-Identifier: GPL-3.0-or-later
//! `p11scope inventory`: which module is used by whom.
//!
//! One snapshot pass, or a `--duration` observation window of passes,
//! over `--pid` or `--system`: every pass collects the scope, reconciles
//! caller incarnations, and publishes caller/module/edge facts through
//! the coordinator batch. The JSON document (`p11scope/inventory/v1`)
//! carries stable capture-local IDs, timestamps on the capture clock,
//! lifecycle state, and explicit gaps. `--capture` picks the usage lane:
//! the scan lane reads `/proc` only (usage columns read unknown), the
//! native lane (`inventory_capture`) adds the Inventory BPF object's
//! witnesses. Mappings are never reported as observed calls.

use crate::attach::Scope;
use crate::capacity::{InventoryBudget, inventory_endpoint_budget};
use crate::cli::{CaptureMode, InspectScope};
use crate::discovery::caller_registry::{
    CallerEvent, ImageAuthority, ModuleId, OsProcessSource, ProcessSource, RegistryLimits,
    UseCoverage, now_ns,
};
#[cfg(test)]
use crate::discovery::caller_registry::{CallerId, MappingState, ModuleKey};
use crate::discovery::engine::inventory::UnavailableImageGuard;
use crate::discovery::engine::inventory_coordinator::{
    InventoryCoordinator, InventoryScope, JointCommitProgress, PassReport,
};
use crate::discovery::hooks::HookRegistry;
use crate::discovery::native_binding::NativeIdentity;
#[cfg(test)]
use crate::inventory_capture::run_classic;
use crate::inventory_capture::{
    BlockDisposition, CgroupJobFailure, ClassicCompletion, ClassicOutcome, CollectJob,
    CollectedPass, ExitRelease, ExitRetention, FacadeLane, LaneSummary, LaneWindows, LoopClock,
    NativeLane, PassCommitProgress, PassDriver, Publish, RetainedBlock, RetainedClassicRun,
    RetainedWorkBudget, SERVICE_TICK, Stopped, ZeroPassStop, poll_retained_classic,
    run_classic_finalizing,
};
use crate::inventory_dashboard::{
    DashboardIo, Display, DisplayAccount, RESCAN_INTERVAL, RESTORE_RETRY_BUDGET, StderrRoute,
    StopFlag,
};
use crate::inventory_diagnostics::{
    CaptureOutcome, CaptureSettlement, DiagnosticConfig, DiagnosticOutcome, DiagnosticScope,
    RetainedIdentityView,
};
use crate::inventory_diagnostics_output::{DiagnosticsDestination, PrepareError};
use crate::inventory_event_identity::IdentityIndex;
use crate::inventory_events::{
    EdgeEmitter, EventWriter, GapEmitter, InstanceEmitter, KeyOperationEmitter,
    caller_event_payload, combined_dump_fits, ended_payload, pass_payload, settle_ended_combined,
    started_payload,
};
#[cfg(test)]
use crate::inventory_output::WriterStdout;
use crate::inventory_output::{FdStdout, FinalStdout, StdoutFailureReason, StdoutResult};
use crate::inventory_present::{DASHBOARD_ACTIVITY_WINDOW_NS, Presentation, render_snapshot};
use crate::output::AtomicFile;
use crate::process::PidPin;
use anyhow::{Context as _, Result};
#[cfg(test)]
use p11scope_ebpf_common::ImageIdentity;
use std::collections::BTreeMap;
use std::io::Write as _;
use std::path::{Path, PathBuf};
use std::time::{Duration, Instant};

const DOC_ID: &str = "p11scope/inventory/v1";

/// Rescan interval inside a `--duration` observation window.
const POLL_INTERVAL: Duration = Duration::from_secs(1);

// G21's explicit engine pilot can accelerate scans without changing the
// production cadence, clock, native lane, coordinator, or recorder capacities.
// Thread-local scoped custody prevents concurrent tests from changing each other.
#[cfg(test)]
std::thread_local! {
    static TEST_INVENTORY_POLL_INTERVAL: std::cell::Cell<Option<Duration>> = const { std::cell::Cell::new(None) };
}

#[cfg(test)]
fn inventory_test_poll_interval() -> Duration {
    TEST_INVENTORY_POLL_INTERVAL.with(|value| value.get().unwrap_or(POLL_INTERVAL))
}

#[cfg(test)]
fn with_inventory_test_poll_interval<T>(interval: Duration, action: impl FnOnce() -> T) -> T {
    assert!(
        !interval.is_zero(),
        "the real engine pilot needs a positive cadence"
    );
    struct Restore(Option<Duration>);
    impl Drop for Restore {
        fn drop(&mut self) {
            TEST_INVENTORY_POLL_INTERVAL.with(|value| value.set(self.0));
        }
    }
    let _restore =
        Restore(TEST_INVENTORY_POLL_INTERVAL.with(|value| value.replace(Some(interval))));
    action()
}

#[cfg(test)]
#[test]
fn inventory_test_poll_interval_is_scoped_and_thread_local() {
    assert_eq!(inventory_test_poll_interval(), POLL_INTERVAL);
    with_inventory_test_poll_interval(Duration::from_millis(10), || {
        assert_eq!(inventory_test_poll_interval(), Duration::from_millis(10));
        assert_eq!(
            std::thread::spawn(inventory_test_poll_interval)
                .join()
                .unwrap(),
            POLL_INTERVAL
        );
        with_inventory_test_poll_interval(Duration::from_millis(20), || {
            assert_eq!(inventory_test_poll_interval(), Duration::from_millis(20));
        });
        assert_eq!(inventory_test_poll_interval(), Duration::from_millis(10));
        let failed = std::panic::catch_unwind(|| {
            with_inventory_test_poll_interval(Duration::from_millis(30), || {
                std::panic::resume_unwind(Box::new("controlled cadence unwind"));
            });
        });
        assert!(failed.is_err());
        assert_eq!(inventory_test_poll_interval(), Duration::from_millis(10));
    });
    assert_eq!(inventory_test_poll_interval(), POLL_INTERVAL);
}

/// Gate-selected inter-pass cadence for G21 legs (S lever): integer
/// milliseconds in `P11SCOPE_G21_POLL_INTERVAL_MS`, applied through the
/// same scoped override as the pilot. Unset means the production default;
/// the production `POLL_INTERVAL` itself is never changed by this knob.
#[cfg(test)]
const GATE_POLL_INTERVAL_ENV: &str = "P11SCOPE_G21_POLL_INTERVAL_MS";

/// Parse a gate cadence value: `None` (unset) is exactly the production
/// default. Anything else must be a positive integer millisecond count; an
/// invalid value is a loud error naming the variable, never a silent
/// fallback to a different cadence.
#[cfg(test)]
fn parse_gate_poll_interval(value: Option<&str>) -> Result<Duration> {
    let Some(value) = value else {
        return Ok(POLL_INTERVAL);
    };
    let millis: u64 = value.trim().parse().map_err(|_| {
        anyhow::anyhow!(
            "{GATE_POLL_INTERVAL_ENV}={value:?} is not a positive integer millisecond count"
        )
    })?;
    if millis == 0 {
        return Err(anyhow::anyhow!(
            "{GATE_POLL_INTERVAL_ENV}={value:?} is not a positive integer millisecond count"
        ));
    }
    Ok(Duration::from_millis(millis))
}

/// The honest-split declaration every gate run prints up front: the
/// cadence it runs at, the production default beside it, and whether the
/// two differ. Cost claims need this label.
#[cfg(test)]
fn declare_gate_poll_interval(source: &str, interval: Duration) -> String {
    format!(
        "G21_CADENCE_DECLARED cadence_ms={} default_ms={} accelerated={} source={source}",
        interval.as_millis(),
        POLL_INTERVAL.as_millis(),
        interval != POLL_INTERVAL,
    )
}

/// Run `action` at the gate-selected cadence, declaring it first. Split
/// from the environment read so tests pin values without touching the
/// process environment.
#[cfg(test)]
fn with_gate_poll_interval_value<T>(value: Option<&str>, action: impl FnOnce() -> T) -> Result<T> {
    let interval = parse_gate_poll_interval(value)?;
    let source = match value {
        None => format!("default(unset {GATE_POLL_INTERVAL_ENV})"),
        Some(set) => format!("{GATE_POLL_INTERVAL_ENV}={set}"),
    };
    eprintln!("{}", declare_gate_poll_interval(&source, interval));
    Ok(with_inventory_test_poll_interval(interval, action))
}

/// Run `action` at the `P11SCOPE_G21_POLL_INTERVAL_MS` cadence (unset =
/// production default), declaring it first.
#[cfg(test)]
fn with_gate_poll_interval<T>(action: impl FnOnce() -> T) -> Result<T> {
    let value = std::env::var(GATE_POLL_INTERVAL_ENV).ok();
    with_gate_poll_interval_value(value.as_deref(), action)
}

#[cfg(test)]
#[test]
fn gate_poll_interval_unset_is_production_default() {
    // The S lever never moves the production cadence: an unset gate is
    // exactly the 1s classic-loop interval.
    assert_eq!(POLL_INTERVAL, Duration::from_secs(1));
    assert_eq!(
        parse_gate_poll_interval(None).unwrap(),
        Duration::from_secs(1)
    );
}

#[cfg(test)]
#[test]
fn gate_poll_interval_parses_millis() {
    assert_eq!(
        parse_gate_poll_interval(Some("250")).unwrap(),
        Duration::from_millis(250)
    );
    assert_eq!(
        parse_gate_poll_interval(Some("10")).unwrap(),
        Duration::from_millis(10)
    );
    assert_eq!(
        parse_gate_poll_interval(Some("1000")).unwrap(),
        POLL_INTERVAL
    );
}

#[cfg(test)]
#[test]
fn gate_poll_interval_rejects_invalid_loudly() {
    for value in ["", "0", "-1", "abc", "1.5", "18446744073709551616"] {
        let message = parse_gate_poll_interval(Some(value))
            .unwrap_err()
            .to_string();
        assert!(
            message.contains(GATE_POLL_INTERVAL_ENV),
            "invalid gate value {value:?} must name its variable: {message}"
        );
    }
}

#[cfg(test)]
#[test]
fn gate_cadence_declaration_states_interval_and_default() {
    let accelerated = declare_gate_poll_interval(
        "P11SCOPE_G21_POLL_INTERVAL_MS=250",
        Duration::from_millis(250),
    );
    assert!(
        accelerated.contains("G21_CADENCE_DECLARED"),
        "{accelerated}"
    );
    assert!(accelerated.contains("cadence_ms=250"), "{accelerated}");
    assert!(accelerated.contains("default_ms=1000"), "{accelerated}");
    assert!(accelerated.contains("accelerated=true"), "{accelerated}");
    let control = declare_gate_poll_interval("default(unset)", POLL_INTERVAL);
    assert!(control.contains("cadence_ms=1000"), "{control}");
    assert!(control.contains("accelerated=false"), "{control}");
}

#[cfg(test)]
#[test]
fn gate_override_applies_configured_cadence_and_restores() {
    let inside = with_gate_poll_interval_value(Some("250"), inventory_test_poll_interval).unwrap();
    assert_eq!(inside, Duration::from_millis(250));
    assert_eq!(inventory_test_poll_interval(), POLL_INTERVAL);
    with_gate_poll_interval_value(None, || {
        assert_eq!(inventory_test_poll_interval(), POLL_INTERVAL);
    })
    .unwrap();
    assert!(with_gate_poll_interval_value(Some("0"), || {}).is_err());
}

/// Maximum wait for staged semantic evidence without current receipts.
/// Receipt-bearing batches publish during the tick that stages them.
const STAGED_SEMANTIC_MAX_AGE: Duration = Duration::from_secs(1);

// Promotion-cancel native cleanup reaps across ticks (§8.6): the
// winding lane polls its detach once per hook instead of driving it
// against a deadline, and its whole owner is retained for process
// exit on a genuine failure, never waited out indefinitely.

/// Selected preparation quantum (DR37 resolver): bounds the bootstrap
/// queries plus one joined fallback settle for a single original.
/// Generous over healthy preparation (sub-second queries, a
/// seconds-long settle); BPF loads run outside this window like the
/// manifest lane. Expiry fails closed through the existing
/// preparation checks, never a hang.
const SELECTED_PREPARATION_WINDOW: Duration = Duration::from_secs(30);

/// One scheduled pre-view baseline acquisition's read window (DR37
/// scheduler): the single-target query shares the service tick, like
/// a metadata observation quantum (JOB_BUDGET). Expiry fails the one
/// attempt, which retries only for a new frame/pair.
const PROMOTION_BASELINE_WINDOW: Duration = Duration::from_millis(25);

/// Wall bound on a continuously pending Joint commit inside the
/// retained drain: a healthy commit publishes in milliseconds, so a
/// commit still Pending past this is stuck and the drain holds the
/// lane (named gap, Partial summary) so the report still writes.
/// Sixty seconds aligns with the normal-stop figure; it is a
/// backstop, not a pacing target.
const RETAINED_JOINT_PUBLICATION_TIMEOUT: Duration = Duration::from_secs(60);

struct DiagnosticRequest<'a> {
    path: Option<&'a Path>,
    pid_filter: Option<u32>,
    second_signal: &'a dyn Fn() -> bool,
}

impl DiagnosticRequest<'_> {
    #[cfg(test)]
    fn disabled() -> Self {
        Self {
            path: None,
            pid_filter: None,
            second_signal: &|| false,
        }
    }
}

/// Destination names and filesystem errors can contain target-controlled
/// text. Keep the single diagnostic notice control-safe and bounded.
fn diagnostics_notice(line: &str, notice: &mut dyn FnMut(&str)) {
    let mut end = line.len().min(512);
    while !line.is_char_boundary(end) {
        end -= 1;
    }
    let mut safe = crate::render::escape_controls(&line[..end]);
    if end < line.len() {
        safe.to_mut().push_str(" [truncated]");
    }
    notice(&safe);
}

/// Requested delivery remains independent from capture and primary sinks.
/// A refused diagnostics setup is remembered for the final exit status.
struct DiagnosticsState {
    path: PathBuf,
    destination: Option<DiagnosticsDestination>,
    failed: bool,
}

impl DiagnosticsState {
    fn prepare(path: &Path, report: Option<&Path>, event_log: Option<&Path>) -> Result<Self> {
        let destination = match DiagnosticsDestination::prepare(path, report, event_log) {
            Ok(destination) => Some(destination),
            Err(PrepareError::Conflict(error)) => return Err(anyhow::anyhow!(error)),
            Err(PrepareError::Unavailable(error)) => {
                diagnostics_notice(
                    &format!("p11scope: diagnostics {} disabled: {error}", path.display()),
                    &mut inventory_diagnostic,
                );
                None
            }
        };
        Ok(Self {
            path: path.to_path_buf(),
            failed: destination.is_none(),
            destination,
        })
    }

    fn enable<Source: ProcessSource>(
        &mut self,
        coordinator: &mut InventoryCoordinator<Source>,
        mode: CaptureMode,
        scope: impl Into<InventoryRunScope>,
        pid_filter: Option<u32>,
    ) {
        let scope = scope.into();
        if self.destination.is_none() {
            return;
        }
        let config = DiagnosticConfig {
            pid_filter,
            mode: match mode {
                CaptureMode::Native => crate::inventory_diagnostics::CaptureMode::Native,
                CaptureMode::Auto => crate::inventory_diagnostics::CaptureMode::Auto,
                CaptureMode::Scan => unreachable!("scan diagnostics are refused before setup"),
            },
            scope: match scope {
                InventoryRunScope::Pid(_) => DiagnosticScope::Pid,
                InventoryRunScope::System => DiagnosticScope::System,
                InventoryRunScope::Cgroup => DiagnosticScope::Cgroup,
            },
            ..DiagnosticConfig::default()
        };
        if let Err(error) = coordinator.enable_diagnostics(config) {
            self.destination = None;
            self.failed = true;
            diagnostics_notice(
                &format!(
                    "p11scope: diagnostics {} disabled: recorder initialization {error:?}",
                    self.path.display()
                ),
                &mut inventory_diagnostic,
            );
        }
    }

    fn finish<Source: ProcessSource>(
        self,
        coordinator: &mut InventoryCoordinator<Source>,
        outcome: DiagnosticOutcome,
        second_signal: &dyn Fn() -> bool,
        notice: &mut dyn FnMut(&str),
    ) -> bool {
        let Some(destination) = self.destination else {
            return self.failed;
        };
        let Some(finished) = coordinator.take_diagnostics(outcome) else {
            diagnostics_notice(
                &format!(
                    "p11scope: diagnostics {} failed: recorder unavailable",
                    self.path.display()
                ),
                notice,
            );
            return true;
        };
        let result = destination.deliver(
            finished,
            &RetainedDiagnosticsIdentity(coordinator),
            second_signal,
        );
        match result {
            Ok(summary) => {
                let evicted = summary
                    .kinds
                    .iter()
                    .fold(0u64, |total, kind| total.saturating_add(kind.evicted));
                let settlement = match outcome.capture_settlement {
                    CaptureSettlement::Settled => "settled",
                    CaptureSettlement::Unsettled => "unsettled",
                    CaptureSettlement::Unavailable => "unavailable",
                };
                diagnostics_notice(
                    &format!(
                        "Diagnostics: {}; {} records; {evicted} older records evicted; capture {settlement}",
                        self.path.display(),
                        summary.records_written,
                    ),
                    notice,
                );
                false
            }
            Err(error) => {
                diagnostics_notice(&format!("p11scope: {error}"), notice);
                true
            }
        }
    }
}

/// Direct retained-ID lookups borrow labels without cloning catalogs or
/// rereading target processes during export.
struct RetainedDiagnosticsIdentity<'a, Source: ProcessSource>(&'a InventoryCoordinator<Source>);

impl<Source: ProcessSource> RetainedIdentityView for RetainedDiagnosticsIdentity<'_, Source> {
    fn application(&self, caller: u32) -> Option<&str> {
        self.0
            .adapter()
            .record(crate::discovery::caller_registry::CallerId(caller))?
            .exe
            .as_ref()?
            .path
            .as_deref()
    }

    fn module(&self, module: u32) -> Option<&str> {
        self.0
            .registry()
            .module(ModuleId(module))?
            .paths
            .first()
            .map(String::as_str)
    }
}

fn diagnostic_outcome(native_available: bool, failed: bool, stopped: bool) -> DiagnosticOutcome {
    DiagnosticOutcome {
        capture_outcome: if failed {
            CaptureOutcome::Failed
        } else if !native_available {
            CaptureOutcome::NativeUnavailable
        } else if stopped {
            CaptureOutcome::Stopped
        } else {
            CaptureOutcome::Completed
        },
        // Link retirement cannot establish application quiescence.
        capture_settlement: if native_available {
            CaptureSettlement::Unsettled
        } else {
            CaptureSettlement::Unavailable
        },
    }
}

/// Inventory-local diagnostics must not wait on an aliased stopped terminal.
fn inventory_diagnostic(line: &str) {
    let _ = crate::sink::try_stderr_line(&crate::render::escape_controls(line));
}

/// Shared by the real classic/dashboard Retiring callbacks and scripted lane
/// controls. The boundary must precede the action that restores/notifies.
pub(crate) fn retiring_stdout(stdout: &mut dyn FinalStdout, action: impl FnOnce()) {
    stdout.begin_finalization();
    action();
}

/// Scan has no Retiring callback; native retains its earlier boundary.
pub(crate) fn begin_scan_stdout(stdout: &mut dyn FinalStdout, native_stopped: bool) {
    if !native_stopped {
        stdout.begin_finalization();
    }
}

/// An event transport failure does not invalidate captured facts. Retire
/// the writer once and keep the first error through ordinary finalization.
pub(crate) struct EventLogState {
    writer: Option<EventWriter>,
    first_error: Option<String>,
}

impl EventLogState {
    pub(crate) fn new(writer: Option<EventWriter>) -> Self {
        Self {
            writer,
            first_error: None,
        }
    }

    pub(crate) fn attempt(
        &mut self,
        stage: &'static str,
        action: impl FnOnce(&mut EventWriter) -> Result<(), String>,
    ) -> Option<String> {
        let writer = self.writer.as_mut()?;
        if let Err(error) = action(writer) {
            return Some(self.retire(stage, error));
        }
        None
    }

    fn retire(&mut self, stage: &'static str, error: String) -> String {
        let error = format!("p11scope: inventory event log {stage} failed: {error}");
        self.first_error.get_or_insert_with(|| error.clone());
        self.writer = None;
        error
    }

    pub(crate) fn first_error(&self) -> Option<&str> {
        self.first_error.as_deref()
    }
}

/// The event prologue shared by classic and dashboard startup. Shared
/// with the loop-regression harness, which opens the real prologue.
pub(crate) fn start_event_log<Source: ProcessSource>(
    stream: &mut EventLogState,
    coordinator: &InventoryCoordinator<Source>,
    scope_label: &str,
    started_ns: u64,
) -> Option<anyhow::Error> {
    // No publication exists before the first pass, so startup never
    // pends; the guarded form pins the contract for reopened logs.
    start_event_log_guarded(stream, coordinator, scope_label, started_ns, false)
}

/// The guarded prologue: while a publication pends, no `started`
/// record is written and no live read runs. The stream then opens
/// with the first real pass publication, which carries the full
/// baseline; a prologue written from a partial read would mislabel
/// the run's observation baseline, and a blank one would fake an
/// empty observation, so showing nothing yet is the honest view.
pub(crate) fn start_event_log_guarded<Source: ProcessSource>(
    stream: &mut EventLogState,
    coordinator: &InventoryCoordinator<Source>,
    scope_label: &str,
    started_ns: u64,
    pending: bool,
) -> Option<anyhow::Error> {
    if pending {
        return None;
    }
    stream.writer.as_ref()?;
    let prologue = Presentation::capture(coordinator, scope_label, started_ns, started_ns, 0);
    stream
        .attempt("startup", |writer| {
            writer.append(
                "started",
                started_payload(scope_label, started_ns, &prologue),
                started_ns,
            )
        })
        .map(anyhow::Error::msg)
}

/// None means not requested; false means failed or not sync-confirmed.
#[derive(Debug)]
pub(crate) struct FinalOutputOutcome {
    event_log_confirmed: Option<bool>,
    report_committed: Option<bool>,
    stdout_result: Option<StdoutResult>,
    failures: Vec<String>,
    diagnostics_failed: bool,
}

impl FinalOutputOutcome {
    pub(crate) fn exit_code(&self) -> i32 {
        i32::from(!self.failures.is_empty() || self.diagnostics_failed)
    }

    pub(crate) fn stdout_cancelled(&self) -> bool {
        matches!(
            self.stdout_result,
            Some(Err(crate::inventory_output::StdoutFailure {
                reason: StdoutFailureReason::Cancelled,
                ..
            }))
        )
    }

    /// Recorded failures (tests assert sink-failure disclosure).
    #[cfg(test)]
    pub(crate) fn failures(&self) -> &[String] {
        &self.failures
    }

    /// Whether the event stream confirmed completion (tests).
    #[cfg(test)]
    pub(crate) fn event_log_confirmed(&self) -> Option<bool> {
        self.event_log_confirmed
    }

    fn notices(&self, previously_reported: Option<&str>, notice: &mut dyn FnMut(&str)) {
        for error in &self.failures {
            if Some(error.as_str()) != previously_reported {
                notice(&crate::render::escape_controls(error));
            }
        }
        if self.failures.is_empty() {
            return;
        }
        let mut statuses = Vec::new();
        if let Some(confirmed) = self.event_log_confirmed {
            statuses.push(if confirmed {
                "event log complete and synced"
            } else {
                "event log incomplete or sync unconfirmed"
            });
        }
        if let Some(committed) = self.report_committed {
            statuses.push(if committed {
                "-o report saved"
            } else {
                "-o report commit failed"
            });
        }
        if let Some(result) = &self.stdout_result {
            statuses.push(if result.is_ok() {
                "stdout complete"
            } else {
                "stdout incomplete (may contain a prefix)"
            });
        }
        notice(&format!(
            "p11scope: inventory outputs: {}",
            statuses.join("; ")
        ));
    }
}

/// Resolve the registry gap bound: the `--max-gaps` override when the
/// operator passed one, else the unchanged 1024 default. Every other
/// limit stays at its default either way.
fn registry_limits(max_gaps: Option<usize>) -> RegistryLimits {
    let mut limits = RegistryLimits::default_limits();
    if let Some(max_gaps) = max_gaps {
        limits.max_gaps = max_gaps;
    }
    limits
}

/// `p11scope inventory` — observe, render, report. Exit 0 with the text
/// summary (or the JSON document under `--json`) on stdout; `-o` writes
/// the JSON document atomically. `--dashboard` runs the live read-only
/// dashboard when stdout is a terminal and degrades honestly to
/// snapshots/JSON on a pipe, never ANSI. `--event-log` appends the
/// JSONL observation-event stream. Hard failures (an unreadable
/// target, an unwritable `-o` or event stream) are errors, never
/// empty-success reports.
#[allow(clippy::too_many_arguments)]
pub fn run(
    scope: impl Into<crate::cli::ScopeArg>,
    modules: &[PathBuf],
    manifests: &[PathBuf],
    hooks: &HookRegistry,
    json: bool,
    max_scan_pids: Option<usize>,
    max_gaps: Option<usize>,
    max_endpoints: Option<u64>,
    duration: Option<Duration>,
    out: Option<&Path>,
    dashboard: bool,
    event_log: Option<&Path>,
    event_rotate_bytes: Option<u64>,
    event_max_files: Option<usize>,
    capture: CaptureMode,
    attach_backend: crate::attach::BackendSelection,
    diagnostics: Option<&Path>,
    diagnostics_pid: Option<u32>,
    identity_backend: crate::cli::IdentityBackendSelection,
    identity_backend_explicit: bool,
    caller_metadata: crate::cli::CallerMetadataMode,
) -> Result<i32> {
    if !manifests.is_empty() && capture == CaptureMode::Scan {
        anyhow::bail!("--manifest requires --capture auto or native");
    }
    let scope: crate::cli::ScopeArg = scope.into();
    if identity_backend_explicit && !matches!(scope, crate::cli::ScopeArg::System) {
        anyhow::bail!(
            "--identity-backend cannot be used outside system inventory (use inventory --system)"
        );
    }
    let endpoint_budget = inventory_endpoint_budget(max_endpoints).map_err(anyhow::Error::msg)?;
    let stdout_tty = crate::inventory_dashboard::fd_is_tty(1);
    // SIGINT/SIGTERM/SIGHUP end the loop, classic or dashboard, through
    // its stop path (the final sinks are still written).
    let stop = StopFlag::install();
    let signals = || stop.signal_count();
    let mut stdout = FdStdout::new(1, &signals);
    let identity = matches!(scope, crate::cli::ScopeArg::System).then_some(identity_backend);
    run_with_terminal_budget(
        scope,
        modules,
        manifests,
        hooks,
        json,
        max_scan_pids,
        max_gaps,
        endpoint_budget,
        duration,
        out,
        dashboard,
        event_log,
        event_rotate_bytes,
        event_max_files,
        capture,
        attach_backend,
        identity,
        caller_metadata == crate::cli::CallerMetadataMode::Cgroup,
        &|| stop.stopped(),
        &|| stop.exit_on_next_signal(),
        stdout_tty,
        &mut stdout,
        &DashboardIo::stdio(),
        DiagnosticRequest {
            path: diagnostics,
            pid_filter: diagnostics_pid,
            second_signal: &|| stop.signal_count() >= 2,
        },
        Some(stop.signal_source()),
        #[cfg(test)]
        None,
        #[cfg(test)]
        None,
    )
}

#[cfg(test)]
#[allow(clippy::too_many_arguments)]
fn run_with_writer(
    scope: InspectScope,
    modules: &[PathBuf],
    hooks: &HookRegistry,
    json: bool,
    max_scan_pids: Option<usize>,
    max_gaps: Option<usize>,
    duration: Option<Duration>,
    out: Option<&Path>,
    dashboard: bool,
    event_log: Option<&Path>,
    event_rotate_bytes: Option<u64>,
    event_max_files: Option<usize>,
    capture: CaptureMode,
    attach_backend: crate::attach::BackendSelection,
    stop: &dyn Fn() -> bool,
    outputs_attempted: &dyn Fn(),
    stdout_tty: bool,
    stdout: &mut dyn FinalStdout,
) -> Result<i32> {
    run_with_terminal(
        scope,
        modules,
        hooks,
        json,
        max_scan_pids,
        max_gaps,
        duration,
        out,
        dashboard,
        event_log,
        event_rotate_bytes,
        event_max_files,
        capture,
        attach_backend,
        stop,
        outputs_attempted,
        stdout_tty,
        stdout,
        &DashboardIo::stdio(),
    )
}

/// `run_with_writer` with the interactive dashboard's terminal named
/// (production: stdout and stdin; the privileged slow-terminal cell: a
/// pty).
#[cfg(test)]
#[allow(clippy::too_many_arguments)]
fn run_with_terminal(
    scope: InspectScope,
    modules: &[PathBuf],
    hooks: &HookRegistry,
    json: bool,
    max_scan_pids: Option<usize>,
    max_gaps: Option<usize>,
    duration: Option<Duration>,
    out: Option<&Path>,
    dashboard: bool,
    event_log: Option<&Path>,
    event_rotate_bytes: Option<u64>,
    event_max_files: Option<usize>,
    capture: CaptureMode,
    attach_backend: crate::attach::BackendSelection,
    stop: &dyn Fn() -> bool,
    outputs_attempted: &dyn Fn(),
    stdout_tty: bool,
    stdout: &mut dyn FinalStdout,
    terminal: &DashboardIo,
) -> Result<i32> {
    run_with_terminal_inner(
        scope,
        modules,
        hooks,
        json,
        max_scan_pids,
        max_gaps,
        duration,
        out,
        dashboard,
        event_log,
        event_rotate_bytes,
        event_max_files,
        capture,
        attach_backend,
        stop,
        outputs_attempted,
        stdout_tty,
        stdout,
        terminal,
        #[cfg(test)]
        None,
    )
}

#[cfg(test)]
#[allow(clippy::too_many_arguments)]
fn run_with_terminal_inner(
    scope: InspectScope,
    modules: &[PathBuf],
    hooks: &HookRegistry,
    json: bool,
    max_scan_pids: Option<usize>,
    max_gaps: Option<usize>,
    duration: Option<Duration>,
    out: Option<&Path>,
    dashboard: bool,
    event_log: Option<&Path>,
    event_rotate_bytes: Option<u64>,
    event_max_files: Option<usize>,
    capture: CaptureMode,
    attach_backend: crate::attach::BackendSelection,
    stop: &dyn Fn() -> bool,
    outputs_attempted: &dyn Fn(),
    stdout_tty: bool,
    stdout: &mut dyn FinalStdout,
    terminal: &DashboardIo,
    #[cfg(test)] event_fault: Option<crate::inventory_events::EventFault>,
) -> Result<i32> {
    run_with_terminal_diagnostics(
        scope,
        modules,
        hooks,
        json,
        max_scan_pids,
        max_gaps,
        duration,
        out,
        dashboard,
        event_log,
        event_rotate_bytes,
        event_max_files,
        capture,
        attach_backend,
        None,
        stop,
        outputs_attempted,
        stdout_tty,
        stdout,
        terminal,
        DiagnosticRequest::disabled(),
        event_fault,
    )
}

#[cfg(test)]
#[allow(clippy::too_many_arguments)]
fn run_with_terminal_diagnostics(
    scope: InspectScope,
    modules: &[PathBuf],
    hooks: &HookRegistry,
    json: bool,
    max_scan_pids: Option<usize>,
    max_gaps: Option<usize>,
    duration: Option<Duration>,
    out: Option<&Path>,
    dashboard: bool,
    event_log: Option<&Path>,
    event_rotate_bytes: Option<u64>,
    event_max_files: Option<usize>,
    capture: CaptureMode,
    attach_backend: crate::attach::BackendSelection,
    identity: Option<crate::cli::IdentityBackendSelection>,
    stop: &dyn Fn() -> bool,
    outputs_attempted: &dyn Fn(),
    stdout_tty: bool,
    stdout: &mut dyn FinalStdout,
    terminal: &DashboardIo,
    request: DiagnosticRequest<'_>,
    event_fault: Option<crate::inventory_events::EventFault>,
) -> Result<i32> {
    run_with_terminal_budget(
        scope,
        modules,
        &[],
        hooks,
        json,
        max_scan_pids,
        max_gaps,
        inventory_endpoint_budget(None).map_err(anyhow::Error::msg)?,
        duration,
        out,
        dashboard,
        event_log,
        event_rotate_bytes,
        event_max_files,
        capture,
        attach_backend,
        identity,
        false,
        stop,
        outputs_attempted,
        stdout_tty,
        stdout,
        terminal,
        request,
        None,
        event_fault,
        None,
    )
}

// A primary-destination validation must not add an unbounded directory walk.
const PRIMARY_ALIAS_MAX_DIRECTORY_VISITS: usize = 4096;

/// Sol-full F2: the report (`-o`) and the event stream finalize
/// independently — the stream finishes, then the report commits over its
/// destination. If both names reach one file (or the report lands in the
/// event rotation namespace), the finished JSONL stream is destroyed while
/// both sinks report success. Reject those collisions before either sink
/// opens (the event open truncates), mirroring the diagnostics alias
/// policy: lexical equality, normalized equality, existing-file identity,
/// and the exact `<live>.<canonical-u64>` rotation namespace (see
/// `inventory_events::rotated_path`). Both sinks refuse `..` and symlink
/// ancestors at open, so a side that fails normalization is refused loudly
/// by its own open below; only comparable sides can collide here. An
/// unreadable check refuses loudly rather than risking a silent overwrite.
fn validate_primary_destinations(report: Option<&Path>, event_log: Option<&Path>) -> Result<()> {
    let (Some(report), Some(event_log)) = (report, event_log) else {
        return Ok(());
    };
    if report == event_log {
        return Err(primary_alias_conflict(report, "event-log", event_log));
    }
    let normalized_report = crate::output::normalize_output_path(report.to_path_buf()).ok();
    let normalized_event = crate::output::normalize_output_path(event_log.to_path_buf()).ok();
    if let (Some(normalized_report), Some(normalized_event)) =
        (normalized_report.as_deref(), normalized_event.as_deref())
    {
        if normalized_report == normalized_event {
            return Err(primary_alias_conflict(report, "event-log", event_log));
        }
        // rotated_path spells the basename through to_string_lossy, then adds
        // the canonical decimal u64 sequence. Preserve that exact namespace.
        let prefix = format!(
            "{}.",
            normalized_event.file_name().unwrap().to_string_lossy()
        );
        if normalized_report.parent() == normalized_event.parent()
            && primary_rotation_name(normalized_report.file_name().unwrap(), &prefix)
        {
            return Err(primary_alias_conflict(
                report,
                "event-log rotation",
                event_log,
            ));
        }
    }
    let report_identity = primary_existing_identity(report)?;
    let event_identity = primary_existing_identity(event_log)?;
    if let (Some(report_identity), Some(event_identity)) = (report_identity, event_identity)
        && report_identity == event_identity
    {
        return Err(primary_alias_conflict(report, "event-log", event_log));
    }
    // A report hardlinked to an existing rotation is the namespace
    // collision under an unrelated name; the commit would still replace a
    // retained rotation. A missing parent holds no rotations; anything else
    // unreadable refuses loudly.
    if let (Some(identity), Some(live)) = (report_identity, normalized_event.as_deref()) {
        let parent = live.parent().unwrap();
        let prefix = format!("{}.", live.file_name().unwrap().to_string_lossy());
        let entries = match std::fs::read_dir(parent) {
            Ok(entries) => entries,
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(()),
            Err(error) => {
                return Err(anyhow::anyhow!(
                    "checking report {} against event-log rotations in {} failed: {error}",
                    report.display(),
                    parent.display()
                ));
            }
        };
        for (visits, entry) in entries.enumerate() {
            if visits >= PRIMARY_ALIAS_MAX_DIRECTORY_VISITS {
                return Err(anyhow::anyhow!(
                    "checking report {} against event-log rotations in {} could not complete within {PRIMARY_ALIAS_MAX_DIRECTORY_VISITS} directory visits",
                    report.display(),
                    parent.display()
                ));
            }
            let entry = entry.map_err(|error| {
                anyhow::anyhow!(
                    "checking report {} against event-log rotations in {} failed: {error}",
                    report.display(),
                    parent.display()
                )
            })?;
            if primary_rotation_name(&entry.file_name(), &prefix)
                && primary_existing_identity(&entry.path())? == Some(identity)
            {
                return Err(primary_alias_conflict(
                    report,
                    "event-log rotation",
                    &entry.path(),
                ));
            }
        }
    }
    Ok(())
}

/// Exact rotation-namespace spelling from `inventory_events::rotated_path`:
/// `<live basename>.<canonical decimal u64>`. Keep in sync with the
/// diagnostics alias check.
fn primary_rotation_name(name: &std::ffi::OsStr, prefix: &str) -> bool {
    let Some(number) = name.to_str().and_then(|name| name.strip_prefix(prefix)) else {
        return false;
    };
    number
        .parse::<u64>()
        .is_ok_and(|sequence| sequence.to_string() == number)
}

fn primary_existing_identity(path: &Path) -> Result<Option<(u64, u64)>> {
    use std::os::unix::fs::MetadataExt as _;
    match std::fs::metadata(path) {
        Ok(metadata) => Ok(Some((metadata.dev(), metadata.ino()))),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(None),
        Err(error) => Err(anyhow::anyhow!(
            "checking report/event-log destination aliases at {} failed: {error}",
            path.display()
        )),
    }
}

fn primary_alias_conflict(report: &Path, kind: &str, other: &Path) -> anyhow::Error {
    anyhow::anyhow!(
        "report {} aliases {kind} destination {}",
        report.display(),
        other.display()
    )
}

#[allow(clippy::too_many_arguments)]
fn run_with_terminal_budget(
    scope: impl Into<InventorySelection>,
    modules: &[PathBuf],
    manifests: &[PathBuf],
    hooks: &HookRegistry,
    json: bool,
    max_scan_pids: Option<usize>,
    max_gaps: Option<usize>,
    endpoint_budget: InventoryBudget,
    duration: Option<Duration>,
    out: Option<&Path>,
    dashboard: bool,
    event_log: Option<&Path>,
    event_rotate_bytes: Option<u64>,
    event_max_files: Option<usize>,
    capture: CaptureMode,
    attach_backend: crate::attach::BackendSelection,
    identity: Option<crate::cli::IdentityBackendSelection>,
    caller_metadata: bool,
    stop: &dyn Fn() -> bool,
    outputs_attempted: &dyn Fn(),
    stdout_tty: bool,
    stdout: &mut dyn FinalStdout,
    terminal: &DashboardIo,
    request: DiagnosticRequest<'_>,
    operator_stop_source: Option<std::sync::Arc<std::sync::atomic::AtomicUsize>>,
    #[cfg(test)] event_fault: Option<crate::inventory_events::EventFault>,
    #[cfg(test)] identity_checks: Option<Box<dyn crate::inspect_system::IdentityChecks>>,
) -> Result<i32> {
    let (engine_scope, numbering) = scope.into().resolve()?;
    let scope = InventoryRunScope::from(&engine_scope);
    // DR-K8S-1: the kernel-side PID filter numbers tasks in the initial PID
    // namespace; a mismatched observer's --pid would match nothing, so it
    // is refused by name before anything is opened or scanned.
    match scope {
        InventoryRunScope::Pid(pid) => {
            crate::pidns::require_numbering_agrees(&numbering, &format!("inventory --pid {pid}"))?;
        }
        InventoryRunScope::System => {
            if let Some(warning) = crate::pidns::nested_warning(&numbering) {
                inventory_diagnostic(&warning);
            }
            // Resolve the proof-stat and shard diagnostic knobs now: their
            // one stderr note each then lands before a dashboard can take the terminal,
            // never over a frame from a later pass's collection.
            let _ = crate::discovery::proof_stats::proof_stat_threads();
            let _ = crate::discovery::sweep_shards::shard_threads();
        }
        InventoryRunScope::Cgroup => crate::pidns::require_inventory_cgroup_numbering(&numbering)?,
    }
    if request.path.is_some() && capture == CaptureMode::Scan {
        anyhow::bail!("--diagnostics requires native capture or auto fallback");
    }
    // D3d: forced-kernel preflight before any sink exists. A refused
    // kernel is a named nonzero error, never a successful empty
    // capture; no `-o`, event, or diagnostics file is created.
    let identity_shared: Option<crate::inspect_system::IdentityShared> = match (scope, identity) {
        (InventoryRunScope::System, Some(selection)) => {
            #[cfg(test)]
            let checks: Box<dyn crate::inspect_system::IdentityChecks> = identity_checks
                .unwrap_or_else(|| Box::new(crate::inspect_system::LiveIdentityChecks));
            #[cfg(not(test))]
            let checks: Box<dyn crate::inspect_system::IdentityChecks> =
                Box::new(crate::inspect_system::LiveIdentityChecks);
            if selection == crate::cli::IdentityBackendSelection::Kernel {
                // The preflight session becomes the capture-owned session:
                // the eligibility probe ran once, before sinks existed.
                match crate::inspect_system::preflight_forced_kernel(checks.as_ref()) {
                    Ok(session) => Some(std::sync::Arc::new(std::sync::Mutex::new(
                        crate::inspect_system::IdentityRunShared::new_with_session(
                            selection, checks, session,
                        ),
                    ))),
                    Err(reason) => {
                        anyhow::bail!("{}", crate::inspect_system::forced_kernel_refusal(reason));
                    }
                }
            } else {
                Some(std::sync::Arc::new(std::sync::Mutex::new(
                    crate::inspect_system::IdentityRunShared::new(selection, checks),
                )))
            }
        }
        _ => None,
    };
    // Sol-full F2: the report commits over its destination after the
    // event stream finishes; colliding primaries would silently destroy the
    // finished stream (or a retained rotation). Refuse them before the
    // diagnostics setup and before either sink opens (the event open
    // truncates).
    validate_primary_destinations(out, event_log)?;
    let mut diagnostics = request
        .path
        .map(|path| DiagnosticsState::prepare(path, out, event_log))
        .transpose()?;
    // Fail fast before scanning: an unwritable `-o` or event stream
    // must not cost a pass.
    let sink = match out {
        Some(path) => Some(
            AtomicFile::create(path)
                .map_err(|error| anyhow::anyhow!("{error}"))
                .with_context(|| format!("opening inventory report {}", path.display()))?,
        ),
        None => None,
    };
    let writer = match event_log {
        Some(path) => Some(
            crate::inventory_events::EventWriter::create(
                path,
                event_rotate_bytes.unwrap_or(crate::inventory_events::DEFAULT_ROTATE_BYTES),
                event_max_files.unwrap_or(crate::inventory_events::DEFAULT_MAX_FILES),
            )
            .map_err(|error| anyhow::anyhow!("{error}"))
            .with_context(|| format!("opening inventory event stream {}", path.display()))?,
        ),
        None => None,
    };
    let mut stream = EventLogState::new(writer);
    #[cfg(test)]
    if let Some(writer) = stream.writer.as_mut() {
        writer.fault = event_fault;
    }
    let (inventory_scope, scope_label) = match scope {
        InventoryRunScope::Pid(pid) => (Some(InventoryScope::Pid(pid)), format!("pid:{pid}")),
        InventoryRunScope::System => (Some(InventoryScope::System), "system".to_string()),
        InventoryRunScope::Cgroup => (None, "cgroup".to_string()),
    };
    let started_ns = now_ns();
    let mut coordinator = InventoryCoordinator::new_with_budget(
        engine_scope.clone(),
        hooks.clone(),
        modules.to_vec(),
        OsProcessSource,
        registry_limits(max_gaps),
        endpoint_budget,
    )?;
    if caller_metadata {
        coordinator.enable_caller_metadata(started_ns)?;
    }
    coordinator.set_semantic_manifests(manifests.to_vec());
    // F4 (review): a document with no `exact` flag still says, as a
    // scope-level gap, that /proc PIDs are not the kernel's here.
    stage_numbering_gap(&mut coordinator, &numbering);
    // The scan lane stages no usage coverage: every edge reads
    // `unknown (scan only)`. The native lane stages per-edge coverage
    // notes and witnesses; `auto` falls back to scan with a named gap.
    if let Some(diagnostics) = diagnostics.as_mut() {
        diagnostics.enable(&mut coordinator, capture, scope, request.pid_filter);
    }
    let cgroup = matches!(scope, InventoryRunScope::Cgroup)
        .then(|| CgroupDriverState::new(deadline_for_duration(duration), operator_stop_source))
        .transpose()?;
    let lane = match open_native_lane(
        capture,
        attach_backend,
        engine_scope.clone(),
        &mut coordinator,
    ) {
        Ok(lane) => lane,
        Err(error) => {
            // There is no native lane to retire, but available diagnostics
            // still describe the failed startup after primary report attempts.
            if diagnostics.is_some() {
                let identity_summary = identity_shared.as_ref().map(|shared| {
                    shared
                        .lock()
                        .unwrap_or_else(|poison| poison.into_inner())
                        .summary()
                });
                let outcome = finish_failed_startup(
                    &mut coordinator,
                    &scope_label,
                    started_ns,
                    sink,
                    &mut stream,
                    diagnostics,
                    json,
                    stdout,
                    &error,
                    request.second_signal,
                    outputs_attempted,
                    identity_summary.as_ref(),
                );
                outcome.notices(None, &mut inventory_diagnostic);
            }
            return Err(error);
        }
    };
    if capture == CaptureMode::Auto && lane.is_none() {
        coordinator.note_diagnostics_native_unavailable();
    }
    let native_available = lane.is_some();
    // The optional Detailed lane starts beside the native lane. No
    // manifests means no Session and no semantic gap at all; a refused
    // startup keeps broad Inventory running with an honest gap.
    let semantic = if manifests.is_empty() {
        None
    } else {
        start_semantic_lane(&mut coordinator, &engine_scope, attach_backend)
    };
    // Interactive dashboard takes over stdout's terminal; a pipe
    // degrades honestly to snapshots/JSON below (never ANSI).
    let mut degraded = dashboard.then(|| "needs a terminal on stdout".to_string());
    if dashboard && stdout_tty {
        match Display::open(terminal, &scope_label) {
            Ok(display) => {
                return run_dashboard(
                    DashboardRun {
                        scope,
                        inventory_scope,
                        cgroup,
                        scope_label,
                        started_ns,
                        max_scan_pids,
                        duration,
                        json,
                        attach_backend,
                    },
                    coordinator,
                    lane,
                    display,
                    sink,
                    stream,
                    stop,
                    outputs_attempted,
                    stdout,
                    terminal,
                    diagnostics,
                    request.second_signal,
                    native_available,
                    semantic,
                    identity_shared,
                );
            }
            // A terminal the run cannot open privately (another user's
            // tty) or put in raw mode: the classic path, honestly.
            Err(error) => {
                degraded = Some(format!(
                    "cannot take over the terminal ({})",
                    crate::render::escape_controls(&format!("{error}"))
                ));
            }
        }
    }
    if let Some(why) = degraded {
        inventory_diagnostic(&format!(
            "p11scope: --dashboard {why}; degraded to {} (no ANSI emitted)",
            if json {
                "the JSON document"
            } else {
                "pager snapshots"
            }
        ));
    }
    let initial_error = start_event_log(&mut stream, &coordinator, &scope_label, started_ns);
    let initial_error = match (diagnostics.is_some(), initial_error) {
        (false, Some(error)) => return Err(error),
        (_, error) => error,
    };
    let mut stream_state = StreamState::new();
    // The opening prior for pending views and the final: the same
    // pass-zero read as the prologue, so a final always has a prior
    // even when no pass completed.
    stream_state.last_stream_view = Some(Presentation::capture(
        &coordinator,
        &scope_label,
        started_ns,
        started_ns,
        0,
    ));
    let deadline = cgroup
        .as_ref()
        .map_or_else(|| deadline_for_duration(duration), |state| state.deadline);
    let mut driver = ClassicDriver {
        coordinator: &mut coordinator,
        inventory_scope,
        scope,
        cgroup,
        max_scan_pids,
        guard: UnavailableImageGuard,
        deadline,
        attach_backend,
        display: None,
        semantic,
        semantic_staged: false,
        seated_summary: None,
        second_signal: Some(request.second_signal),
        lifecycle: crate::inventory_promotion::lifecycle::SelectedLifecycleService::new(),
        completion_source: None,
        pending_install: None,
        installed_promotion: None,
        retiring: None,
        joint_finish: JointFinishDriver::NotBegun,
        stop_requested: false,
        joint_first_error: None,
        suspended: false,
        joint_commit_pending: false,
        joint_tick_refusal: None,
        joint_commit_retries: 0,
        #[cfg(test)]
        terminal_seq_calls: 0,
        #[cfg(test)]
        reclaim_calls: Vec::new(),
        #[cfg(test)]
        joint_begin_calls: 0,
        #[cfg(test)]
        joint_step_calls: 0,
        #[cfg(test)]
        joint_commit_polls: 0,
        #[cfg(test)]
        take_promotion_work_calls: 0,
        #[cfg(test)]
        drive_pending_install_calls: 0,
        #[cfg(test)]
        service_caller_metadata_calls: 0,
        #[cfg(test)]
        commit_calls: 0,
        identity: identity_shared.clone(),
    };
    driver.set_completion_source(Box::new(crate::attach::NativeCompletionMinter::new()));
    driver.initialize_joint_lane();
    let clock = LoopClock {
        deadline,
        stop,
        now: &Instant::now,
        #[cfg(not(test))]
        interval: POLL_INTERVAL,
        #[cfg(test)]
        interval: inventory_test_poll_interval(),
        tick: SERVICE_TICK,
        collection_tick: SERVICE_TICK,
    };
    let mut publish = |driver: &mut ClassicDriver<'_>, point: Publish<'_>| {
        let coordinator = &*driver.coordinator;
        match point {
            Publish::Pass { report, now_ns } => {
                let Some(presentation) = stream_view_guarded(
                    driver,
                    &mut stream_state,
                    &scope_label,
                    started_ns,
                    now_ns,
                ) else {
                    return Ok(());
                };
                for line in progress_lines(coordinator, report) {
                    inventory_diagnostic(&line);
                }
                if let Some(error) = stream.attempt("pass publication", |writer| {
                    emit_pass_events(writer, &mut stream_state, report, &presentation, now_ns)
                }) {
                    let _ = crate::sink::try_stderr_line(&crate::render::escape_controls(&error));
                }
            }
            Publish::Retiring {
                attached,
                links,
                budget,
            } => retiring_stdout(stdout, || {
                inventory_diagnostic(&format!(
                    "p11scope: stopping: detaching the native probes of {attached} endpoints \
                     in {links} links (up to {} s)",
                    budget.as_secs()
                ))
            }),
            Publish::Stop { events, now_ns } => {
                let Some(presentation) = stream_view_guarded(
                    driver,
                    &mut stream_state,
                    &scope_label,
                    started_ns,
                    now_ns,
                ) else {
                    return Ok(());
                };
                if let Some(error) = stream.attempt("stop publication", |writer| {
                    emit_stop_events(
                        writer,
                        &mut stream_state,
                        events,
                        coordinator.passes(),
                        &presentation,
                        now_ns,
                    )
                }) {
                    let _ = crate::sink::try_stderr_line(&crate::render::escape_controls(&error));
                }
            }
        }
        Ok(())
    };
    let running = run_classic_finalizing(&mut driver, lane, &clock, initial_error, &mut publish);
    let (stopped, capture_error, zero_pass) = driver.consume_outcome(running, &clock, &mut publish);
    let presentation =
        final_view_guarded(&driver, &stream_state, &scope_label, started_ns, now_ns());
    // Both owners stay alive through the final commit, the immutable
    // presentation and every sink attempt; the lane releases after
    // output, beside the native capture it never certified.
    let semantic_lane = driver.semantic.take();
    drop(driver);
    begin_scan_stdout(stdout, stopped.is_some());
    if let Some(stopped) = &stopped {
        inventory_diagnostic(&stop_line(&stopped.summary));
    }
    if let Some(zero) = &zero_pass {
        inventory_diagnostic(&zero.stderr_line());
    }
    // Output attempts first; only then may an unsettled retirement's drop
    // block (invariant 5), and a further signal then exits at once
    // (R-C51-4).
    let previously_reported = stream.first_error().map(str::to_string);
    let diagnostic_outcome = diagnostic_outcome(
        native_available,
        capture_error.is_some(),
        diagnostics.is_some() && stop(),
    );
    let identity_summary = identity_shared.as_ref().map(|shared| {
        shared
            .lock()
            .unwrap_or_else(|poison| poison.into_inner())
            .summary()
    });
    let outcome = crate::inventory_capture::finish_native(
        stopped,
        |summary| {
            finish_runtime_output(
                sink,
                &mut stream,
                &mut stream_state,
                &presentation,
                json,
                false,
                stdout,
                summary,
                identity_summary.as_ref(),
                &mut coordinator,
                diagnostics,
                diagnostic_outcome,
                request.second_signal,
                &mut inventory_diagnostic,
            )
        },
        outputs_attempted,
        &mut |line| {
            let _ = crate::sink::try_stderr_line(&line);
        },
        |s| {
            ExitRetention::hold(s);
            ExitRelease::RetainedForExit
        },
    );
    outcome.notices(previously_reported.as_deref(), &mut |line| {
        let _ = crate::sink::try_stderr_line(line);
    });
    finish_caller_metadata_cleanup(&mut coordinator, request.second_signal);
    let cleanup = finish_semantic_native_cleanup(semantic_lane, request.second_signal);
    combine_semantic_terminal_errors(capture_error, cleanup)?;
    Ok(outcome.exit_code())
}

fn finish_caller_metadata_cleanup(
    coordinator: &mut InventoryCoordinator<OsProcessSource>,
    second_signal: &dyn Fn() -> bool,
) {
    // Outputs have already been attempted. Join the cancelled optional job
    // through its real owner; another operator signal leaves owned custody
    // in the helper's process-lifetime slot rather than detaching its thread.
    let deadline = Instant::now() + Duration::from_millis(100);
    while !coordinator.poll_caller_metadata_stop(now_ns()) {
        if second_signal() || Instant::now() >= deadline {
            return;
        }
        std::thread::sleep(Duration::from_millis(10));
    }
}

#[cfg(test)]
pub(crate) fn finish_caller_metadata_cleanup_for_test(
    coordinator: &mut InventoryCoordinator<OsProcessSource>,
    second_signal: &dyn Fn() -> bool,
) {
    finish_caller_metadata_cleanup(coordinator, second_signal);
}

fn finish_semantic_native_cleanup(
    lane: Option<crate::inventory_semantics::AttestedSemanticLane>,
    second_signal: &dyn Fn() -> bool,
) -> Result<()> {
    lane.map_or(Ok(()), |lane| {
        lane.finish_owned_terminal_cleanup(second_signal, &mut std::io::stderr())
    })
}

fn combine_semantic_terminal_errors(
    primary: Option<anyhow::Error>,
    cleanup: Result<()>,
) -> Result<()> {
    match (primary, cleanup) {
        (None, result) => result,
        (Some(primary), Ok(())) => Err(primary),
        (Some(primary), Err(cleanup)) => {
            if cleanup
                .downcast_ref::<crate::attach::CleanupInterrupted>()
                .is_some()
            {
                // Keep the original failure as root cause so main still
                // reports it, and the typed interrupt so its status is 130.
                Err(primary
                    .context("Detailed cleanup also failed")
                    .context(crate::attach::CleanupInterrupted))
            } else {
                Err(primary.context(format!("Detailed cleanup also failed: {cleanup:#}")))
            }
        }
    }
}

/// A native startup failure still attempts requested final sinks. Capture
/// never started, so an event stream cannot claim a completed observation.
#[allow(clippy::too_many_arguments)]
fn finish_failed_startup<Source: ProcessSource>(
    coordinator: &mut InventoryCoordinator<Source>,
    scope_label: &str,
    started_ns: u64,
    sink: Option<AtomicFile>,
    stream: &mut EventLogState,
    diagnostics: Option<DiagnosticsState>,
    json: bool,
    stdout: &mut dyn FinalStdout,
    error: &anyhow::Error,
    second_signal: &dyn Fn() -> bool,
    outputs_attempted: &dyn Fn(),
    identity: Option<&crate::inspect_system::IdentitySummary>,
) -> FinalOutputOutcome {
    // Capture failed before any driver existed, so no publication
    // can pend here; the guarded form pins the contract.
    finish_failed_startup_guarded(
        false,
        None,
        coordinator,
        scope_label,
        started_ns,
        sink,
        stream,
        diagnostics,
        json,
        stdout,
        error,
        second_signal,
        outputs_attempted,
        identity,
    )
}

/// The guarded failed-startup final: the failure bookkeeping (the
/// retired stream, the committed failure gap) always runs, but the
/// rendered report reuses the prior view while a publication pends
/// instead of a fresh live read. Pending without a prior falls
/// back to a fresh capture: the failure must still be reported.
#[allow(clippy::too_many_arguments)]
fn finish_failed_startup_guarded<Source: ProcessSource>(
    pending: bool,
    prior: Option<&Presentation>,
    coordinator: &mut InventoryCoordinator<Source>,
    scope_label: &str,
    started_ns: u64,
    sink: Option<AtomicFile>,
    stream: &mut EventLogState,
    diagnostics: Option<DiagnosticsState>,
    json: bool,
    stdout: &mut dyn FinalStdout,
    error: &anyhow::Error,
    second_signal: &dyn Fn() -> bool,
    outputs_attempted: &dyn Fn(),
    identity: Option<&crate::inspect_system::IdentitySummary>,
) -> FinalOutputOutcome {
    if stream.writer.is_some() {
        stream.retire(
            "startup",
            format!("capture failed before event stream started: {error:#}"),
        );
    }
    coordinator.note_scope_gap("inventory capture failed".into(), format!("{error:#}"));
    let _ = coordinator.commit_batch(false);
    stdout.begin_finalization();
    let presentation = match (pending, prior) {
        (true, Some(prior)) => prior.clone(),
        _ => Presentation::capture(
            coordinator,
            scope_label,
            started_ns,
            now_ns(),
            coordinator.passes(),
        ),
    };
    crate::inventory_capture::finish_native::<FacadeLane, _>(
        None,
        |_| {
            finish_runtime_output(
                sink,
                stream,
                &mut StreamState::new(),
                &presentation,
                json,
                false,
                stdout,
                None,
                identity,
                coordinator,
                diagnostics,
                DiagnosticOutcome {
                    capture_outcome: CaptureOutcome::Failed,
                    capture_settlement: CaptureSettlement::Unavailable,
                },
                second_signal,
                &mut inventory_diagnostic,
            )
        },
        outputs_attempted,
        &mut |line| inventory_diagnostic(&line),
        |s| {
            ExitRetention::hold(s);
            ExitRelease::RetainedForExit
        },
    )
}

#[derive(Clone, Copy)]
enum InventoryRunScope {
    Pid(u32),
    System,
    Cgroup,
}

enum InventorySelection {
    Operator(crate::cli::ScopeArg),
    #[cfg(test)]
    Retained {
        scope: Scope,
        numbering: crate::pidns::PidNumbering,
    },
}

impl From<crate::cli::ScopeArg> for InventorySelection {
    fn from(scope: crate::cli::ScopeArg) -> Self {
        Self::Operator(scope)
    }
}

impl From<InspectScope> for InventorySelection {
    fn from(scope: InspectScope) -> Self {
        Self::Operator(scope.into())
    }
}

impl From<InspectScope> for InventoryRunScope {
    fn from(scope: InspectScope) -> Self {
        match scope {
            InspectScope::Pid(pid) => Self::Pid(pid),
            InspectScope::System => Self::System,
        }
    }
}

impl From<InspectScope> for Scope {
    fn from(scope: InspectScope) -> Self {
        match scope {
            InspectScope::Pid(pid) => Self::Pid(pid),
            InspectScope::System => Self::System,
        }
    }
}

impl From<&Scope> for InventoryRunScope {
    fn from(scope: &Scope) -> Self {
        match scope {
            Scope::Pid(pid) => Self::Pid(*pid),
            Scope::System => Self::System,
            Scope::Cgroup { .. } => Self::Cgroup,
        }
    }
}

impl InventorySelection {
    fn resolve(self) -> Result<(Scope, crate::pidns::PidNumbering)> {
        match self {
            Self::Operator(scope) => {
                let numbering = crate::pidns::numbering().clone();
                let scope = match scope {
                    crate::cli::ScopeArg::Pid(pid) => Scope::Pid(pid),
                    crate::cli::ScopeArg::System => Scope::System,
                    crate::cli::ScopeArg::Cgroup(path) => {
                        crate::pidns::require_inventory_cgroup_numbering(&numbering)?;
                        crate::scope::capture_cgroup(&path).map_err(|error| {
                            anyhow::anyhow!(
                                "{}",
                                crate::render::escape_controls(&format!("{error:#}"))
                            )
                        })?
                    }
                };
                Ok((scope, numbering))
            }
            #[cfg(test)]
            Self::Retained { scope, numbering } => {
                if !matches!(scope, Scope::Cgroup { .. }) {
                    anyhow::bail!("retained cgroup test input requires an explicit cgroup scope");
                }
                crate::pidns::require_inventory_cgroup_numbering(&numbering)?;
                Ok((scope, numbering))
            }
        }
    }
}

struct CgroupDriverState {
    continuation: Option<crate::scope::inventory_cgroup::CgroupWalkState>,
    limits: crate::scope::inventory_cgroup::CgroupWalkLimits,
    control: crate::scope::inventory_cgroup::CollectionControl,
    deadline: Option<Instant>,
    observer: Option<crate::cgroup_stop_acceptance::Observer>,
}

impl CgroupDriverState {
    fn new(
        deadline: Option<Instant>,
        source: Option<std::sync::Arc<std::sync::atomic::AtomicUsize>>,
    ) -> Result<Self> {
        let control = crate::scope::inventory_cgroup::CollectionControl::new(deadline);
        let control = match source {
            Some(source) => control.with_operator_stop_source(source),
            None => control,
        };
        Ok(Self {
            continuation: Some(crate::scope::inventory_cgroup::CgroupWalkState::default()),
            limits: crate::scope::inventory_cgroup::CgroupWalkLimits::default(),
            control,
            deadline,
            observer: crate::cgroup_stop_acceptance::Observer::from_environment()?,
        })
    }
}

/// The classic loop's pass side over the production coordinator.
/// The promotion that installed the live slot lane: the capture and
/// request the end confirmation names, and the exact pair installed.
#[derive(Debug, Clone, Copy)]
struct InstalledPromotion {
    capture: crate::inventory_promotion::CaptureId,
    request: crate::inventory_promotion::RequestId,
    pair: crate::inventory_promotion::PromotionPair,
}

/// The Joint finish driver (§8.3): one finish per lane, begun once
/// at a stop, cancel or post-retirement hook, stepped once per
/// 10 ms hook within a 1024-action budget. Legacy lanes never leave
/// `NotBegun`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum JointFinishDriver {
    /// No finish begun: the begin sites begin the lane's finish once.
    NotBegun,
    /// The finish is polling toward publication.
    Polling,
    /// The finish published: only the wound-down is polled.
    Published,
    /// The finite stop abandoned the finish: nothing runs.
    Abandoned,
}

/// What one finish step did.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum JointStepOutcome {
    /// Still polling, reaping, or already abandoned.
    Stayed,
    /// The detach joined: the caller retires or completes the lane.
    WoundDown,
    /// The finite stop abandoned and held the lane.
    Abandoned,
}

/// What one NotBegun §8.3 step did: nothing without a lane, one
/// commit poll that stayed or failed, or a poll plus a begin.
enum NotBegunStep {
    Idle,
    Stepped,
    Began,
}

/// The §8.3 item-7 commit rule: storage-retryable refusals stay up
/// to 100 hooks; anything else fails the finish. Shared by the
/// winding and final-lane NotBegun steps.
fn note_commit_refusal_once(
    retries: &mut u16,
    reason: crate::inventory_semantics::SemanticRefusal,
) -> bool {
    if reason == crate::inventory_semantics::SemanticRefusal::ProviderStorage && *retries < 100 {
        *retries += 1;
        true
    } else {
        false
    }
}

/// A promotion lane winding down inside its retiring domain (§8.6):
/// the whole lane stays owned across ticks while its detach reaps
/// (legacy) or its finish steps (Joint).
struct WindingLane {
    /// The winding lane; `None` after the typed exit held it.
    lane: Option<crate::inventory_semantics::AttestedSemanticLane>,
    /// A's promotion finish state.
    finish: JointFinishDriver,
    /// Whether A carries a Joint promotion finish (legacy lanes wind
    /// through the wound-down phase only).
    joint: bool,
    /// The first WoundDown handed the session off (the take carried
    /// it away): later ticks skip the finish step — the session is
    /// gone, so reaping again would fail closed — and retry the
    /// completion/retire tail with the retained proof.
    joined: bool,
    /// This winding's counts are already disclosed (by a stop path or
    /// a winding exit hold): later stop calls stay silent, and the
    /// join tail and the exit hold skip their own disclosure when a
    /// stray tick steps the winding past the stop. The three winding
    /// legs share the one once-gate.
    stop_disclosed: bool,
}

/// A wound-down domain whose coordinator namespace still retires. The
/// completion minter delivers once, so a proof spent on a refused
/// attempt is retained here for the retry, never re-polled.
struct RetiringDomain {
    domain: crate::attach::capture::NativeDomainId,
    completion: Option<crate::inventory_promotion::lifecycle::SessionNativeCompletion>,
    /// A lane still winding down (legacy detach or Joint promotion
    /// finish); `None` once the lane handed its session off.
    winding: Option<WindingLane>,
}

impl RetiringDomain {
    /// Lane-less retire tail, kept for the pre-T14 tests that pin it;
    /// production always winds a lane down first (§8.6).
    #[cfg(test)]
    fn wound_down(domain: crate::attach::capture::NativeDomainId) -> Self {
        Self {
            domain,
            completion: None,
            winding: None,
        }
    }

    /// Keep A's whole lane for its promotion wind-down (§8.6).
    fn winding(lane: crate::inventory_semantics::AttestedSemanticLane, joint: bool) -> Self {
        let domain = lane.domain();
        Self {
            domain,
            completion: None,
            winding: Some(WindingLane {
                lane: Some(lane),
                finish: JointFinishDriver::NotBegun,
                joint,
                joined: false,
                stop_disclosed: false,
            }),
        }
    }
}

struct ClassicDriver<'a> {
    coordinator: &'a mut InventoryCoordinator<OsProcessSource>,
    inventory_scope: Option<InventoryScope>,
    scope: InventoryRunScope,
    cgroup: Option<CgroupDriverState>,
    max_scan_pids: Option<usize>,
    guard: UnavailableImageGuard,
    deadline: Option<Instant>,
    /// The operator's `--attach-backend`: selected preparation honors
    /// the same backend selection as the manifest lane.
    attach_backend: crate::attach::BackendSelection,
    /// D3d capture-owned identity state (`--system` only): shared with
    /// each collection job, read for the final document after the loop.
    identity: Option<crate::inspect_system::IdentityShared>,
    /// The interactive dashboard's display (C5.3): it draws on the loop's
    /// service ticks and takes the pass warnings into its log tail.
    display: Option<Display>,
    /// The optional attested Detailed lane: present when `--manifest`
    /// attested a subset. Ticks drive H0; commits finalize beside the
    /// physical evidence; the stop path owns its terminal sequence.
    semantic: Option<crate::inventory_semantics::AttestedSemanticLane>,
    /// A lane batch is already staged ahead of the next commit: at most
    /// one ordinary collection quantum is owned at a time, so later
    /// ticks in the same pass stay quiet instead of backpressuring.
    semantic_staged: bool,
    /// The seated lane's summary at its last hold or completion: a
    /// held or completed final lane leaves no seat, but the run
    /// still serves what was seated instead of the default. Each
    /// hold or completion overwrites it with its own lane; a seated
    /// lane always reads live.
    seated_summary: Option<crate::inventory_semantics::SemanticCaptureSummary>,
    /// DR37 selected-lane lifecycle: the single-flight preparation
    /// worker service, polled every tick. Idle without promotion.
    lifecycle: crate::inventory_promotion::lifecycle::SelectedLifecycleService,
    /// The native completion minter (DR37 A→B): polled for a wound-down
    /// domain's genuine disposal. `None` until the native lane lands
    /// it; without it, retiring domains hold (never forced).
    completion_source:
        Option<Box<dyn crate::inventory_promotion::lifecycle::NativeCompletionSource>>,
    /// A proof-gated install handoff awaiting a free slot and a
    /// retired predecessor. Held across ticks; cancelled work is
    /// reclaimed into the service for genuine disposal, never dropped.
    pending_install: Option<crate::inventory_promotion::lifecycle::PendingInstall>,
    /// The promotion that installed the live slot lane, for
    /// operator-cancel wind-down and genuine end confirmation.
    installed_promotion: Option<InstalledPromotion>,
    /// A wound-down domain whose coordinator namespace still retires:
    /// its completion is polled every tick (a refused proof is
    /// retained for the retry) and the namespace retires before any
    /// held install runs.
    retiring: Option<RetiringDomain>,
    /// The Joint finish driver (§8.3): `NotBegun` until a begin site
    /// begins a Joint lane's finish. Legacy lanes never leave it.
    joint_finish: JointFinishDriver,
    /// A stop was already requested: the second stop escalates a
    /// begun-but-unfinished Joint finish to the typed exit instead of
    /// re-running the stop path.
    stop_requested: bool,
    /// The second operator signal probe: when it fires at the lane
    /// stop, a begun-but-unfinished Joint finish escalates to the
    /// typed exit instead of stepping on. `None` without a signal
    /// source.
    second_signal: Option<&'a dyn Fn() -> bool>,
    /// The first Joint finish error, kept for the retained
    /// consumer's exit (§6.4): the abandon reason, the wound-down
    /// refusal, or the escalation note. Never overwritten by later
    /// best-effort work.
    joint_first_error: Option<String>,
    /// The retained consumer owns this driver (§6.3): native service
    /// stops, ticks service only the display and the Joint finish,
    /// and no new work is admitted. Set by the suspension gate and
    /// by the consumer on retention; never cleared.
    suspended: bool,
    /// A Joint commit is begun but unpublished (§6.1, §6.3): the
    /// retained finish step polls it instead of beginning.
    /// `poll_commit` sets it on begin and clears it on publication;
    /// tests pose it directly.
    joint_commit_pending: bool,
    /// The first Joint tick-service refusal, kept instead of dropped:
    /// the machine owns its latch and retries, but the reason names
    /// the lane's stop if the lane later holds with no latched reason
    /// of its own. Never cleared; later refusals keep the first.
    joint_tick_refusal: Option<crate::inventory_semantics::SemanticRefusal>,
    /// Storage-retryable commit refusals on the final lane's
    /// retained step (§8.3 item 7): ProviderStorage retries up to
    /// 100 hooks, mirroring the winding counter.
    joint_commit_retries: u16,
    /// Tests-only spies: terminal-sequence runs, reclaim takes with
    /// their end (recorded after the take, never for a bare attempt),
    /// finish-begin attempts, driver steps, joint commit polls,
    /// promotion-work takes, held-install drives, caller metadata
    /// services, classic commits.
    #[cfg(test)]
    terminal_seq_calls: usize,
    #[cfg(test)]
    reclaim_calls: Vec<crate::inventory_promotion::PromotionEnd>,
    #[cfg(test)]
    joint_begin_calls: usize,
    #[cfg(test)]
    joint_step_calls: usize,
    #[cfg(test)]
    joint_commit_polls: usize,
    #[cfg(test)]
    take_promotion_work_calls: usize,
    #[cfg(test)]
    drive_pending_install_calls: usize,
    #[cfg(test)]
    service_caller_metadata_calls: usize,
    #[cfg(test)]
    commit_calls: usize,
}

/// Exercise the actual caller refresh/admission path with substituted lane I/O.
#[cfg(test)]
pub(crate) fn bind_semantic_callers_for_test(
    coordinator: &mut InventoryCoordinator<OsProcessSource>,
    lane: &mut crate::inventory_semantics::AttestedSemanticLane,
    raw: &mut crate::semantics_objects::journal::joint_driver::RawJointQuantum,
    producers: &crate::attach::SessionDrainProducers,
) -> Result<(), crate::semantics_objects::journal::joint_driver::RawQuantumRefusal> {
    crate::inventory_semantics::bind_collected_semantic_callers(coordinator, lane, raw, producers)
}

/// Exercise the production driver tick with substituted lane I/O.
#[cfg(test)]
pub(crate) fn classic_semantic_tick_for_test(
    coordinator: &mut InventoryCoordinator<OsProcessSource>,
    lane: crate::inventory_semantics::AttestedSemanticLane,
) -> crate::inventory_semantics::AttestedSemanticLane {
    let mut driver = ClassicDriver {
        coordinator,
        inventory_scope: None,
        scope: InventoryRunScope::Pid(std::process::id()),
        cgroup: None,
        max_scan_pids: None,
        guard: UnavailableImageGuard,
        deadline: None,
        attach_backend: crate::attach::BackendSelection::Auto,
        identity: None,
        display: None,
        semantic: Some(lane),
        semantic_staged: false,
        seated_summary: None,
        second_signal: None,
        lifecycle: crate::inventory_promotion::lifecycle::SelectedLifecycleService::new(),
        completion_source: None,
        pending_install: None,
        installed_promotion: None,
        retiring: None,
        joint_finish: JointFinishDriver::NotBegun,
        stop_requested: false,
        joint_first_error: None,
        suspended: false,
        joint_commit_pending: false,
        joint_tick_refusal: None,
        joint_commit_retries: 0,
        #[cfg(test)]
        terminal_seq_calls: 0,
        #[cfg(test)]
        reclaim_calls: Vec::new(),
        #[cfg(test)]
        joint_begin_calls: 0,
        #[cfg(test)]
        joint_step_calls: 0,
        #[cfg(test)]
        joint_commit_polls: 0,
        #[cfg(test)]
        take_promotion_work_calls: 0,
        #[cfg(test)]
        drive_pending_install_calls: 0,
        #[cfg(test)]
        service_caller_metadata_calls: 0,
        #[cfg(test)]
        commit_calls: 0,
    };
    driver.on_tick();
    driver.semantic.take().unwrap()
}

/// Drive the real apply/commit boundary without the native loop or a worker.
/// The caller supplies a real collected catalog/owned cgroup transaction;
/// neither this seam nor its native identity can pre-bind a Detailed caller.
#[cfg(test)]
pub(crate) fn classic_semantic_pass_for_test(
    coordinator: &mut InventoryCoordinator<OsProcessSource>,
    lane: crate::inventory_semantics::AttestedSemanticLane,
    scope: &Scope,
    collected: CollectedPass,
    identity: &mut dyn NativeIdentity<PidPin>,
) -> crate::inventory_semantics::AttestedSemanticLane {
    let mut driver = ClassicDriver {
        coordinator,
        inventory_scope: None,
        scope: scope.into(),
        cgroup: None,
        max_scan_pids: None,
        guard: UnavailableImageGuard,
        deadline: None,
        attach_backend: crate::attach::BackendSelection::Auto,
        identity: None,
        display: None,
        semantic: Some(lane),
        semantic_staged: false,
        seated_summary: None,
        second_signal: None,
        lifecycle: crate::inventory_promotion::lifecycle::SelectedLifecycleService::new(),
        completion_source: None,
        pending_install: None,
        installed_promotion: None,
        retiring: None,
        joint_finish: JointFinishDriver::NotBegun,
        stop_requested: false,
        joint_first_error: None,
        suspended: false,
        joint_commit_pending: false,
        joint_tick_refusal: None,
        joint_commit_retries: 0,
        #[cfg(test)]
        terminal_seq_calls: 0,
        #[cfg(test)]
        reclaim_calls: Vec::new(),
        #[cfg(test)]
        joint_begin_calls: 0,
        #[cfg(test)]
        joint_step_calls: 0,
        #[cfg(test)]
        joint_commit_polls: 0,
        #[cfg(test)]
        take_promotion_work_calls: 0,
        #[cfg(test)]
        drive_pending_install_calls: 0,
        #[cfg(test)]
        service_caller_metadata_calls: 0,
        #[cfg(test)]
        commit_calls: 0,
    };
    let report = driver.apply(collected, identity, now_ns()).unwrap();
    driver.commit(report.engine_changed).unwrap();
    driver.on_tick();
    driver.commit(false).unwrap();
    driver.semantic.take().unwrap()
}

#[cfg(test)]
thread_local! {
    // Substitute only the fallible publication boundary, after real H0
    // Finish exists. No receipt, semantic row or native success is scripted.
    static FAIL_TERMINAL_PUBLICATION: std::cell::Cell<bool> = const { std::cell::Cell::new(false) };
}

#[cfg(test)]
thread_local! {
    static FAIL_NEXT_CLASSIC_COMMIT: std::cell::RefCell<Option<String>> =
        const { std::cell::RefCell::new(None) };
}

/// Arm one classic commit failure: the next `ClassicDriver::commit`
/// attempt counts, then fails with `text` instead of publishing.
/// Tests a capture-side fault without touching the commit path.
#[cfg(test)]
pub(crate) fn fail_next_classic_commit_for_test(text: &str) {
    FAIL_NEXT_CLASSIC_COMMIT.with(|fault| fault.replace(Some(text.to_string())));
}

#[cfg(test)]
fn take_classic_commit_fault_for_test() -> Option<String> {
    FAIL_NEXT_CLASSIC_COMMIT.with(|fault| fault.take())
}

#[cfg(test)]
thread_local! {
    /// Every line passed to `ClassicDriver::warn`, in order. Tests
    /// drain it through `take_warned_for_test` (thread-local, like
    /// the commit fault above: no driver field, so no literal churn).
    static WARNED_FOR_TEST: std::cell::RefCell<Vec<String>> =
        const { std::cell::RefCell::new(Vec::new()) };
}

/// Drain the warned-lines record (tests).
#[cfg(test)]
fn take_warned_for_test() -> Vec<String> {
    WARNED_FOR_TEST.with(|warned| warned.take())
}

/// Record one warned line (tests).
#[cfg(test)]
fn record_warned_for_test(line: &str) {
    WARNED_FOR_TEST.with(|warned| warned.borrow_mut().push(line.to_string()));
}

#[cfg(test)]
thread_local! {
    /// Every seal-readiness line the startup noted, in order. Tests
    /// drain it through `take_sealed_for_test` (thread-local, like
    /// the warned record above: no shared sink, so no churn in the
    /// stop twins' exact vectors).
    static SEALED_FOR_TEST: std::cell::RefCell<Vec<String>> =
        const { std::cell::RefCell::new(Vec::new()) };
}

/// Drain the seal-line record (tests).
#[cfg(test)]
fn take_sealed_for_test() -> Vec<String> {
    SEALED_FOR_TEST.with(|sealed| sealed.take())
}

/// Record one seal-readiness line (tests).
#[cfg(test)]
fn record_sealed_for_test(line: &str) {
    SEALED_FOR_TEST.with(|sealed| sealed.borrow_mut().push(line.to_string()));
}

#[cfg(test)]
pub(crate) fn classic_semantic_stop_refusing_publication_for_test(
    coordinator: &mut InventoryCoordinator<OsProcessSource>,
    lane: crate::inventory_semantics::AttestedSemanticLane,
) -> crate::inventory_semantics::AttestedSemanticLane {
    FAIL_TERMINAL_PUBLICATION.with(|fail| fail.set(true));
    let lane = classic_semantic_stop_for_test(coordinator, lane);
    assert!(
        !FAIL_TERMINAL_PUBLICATION.with(|fail| fail.get()),
        "the real terminal commit boundary must be reached"
    );
    lane
}

/// Drive the production stop hook over real H0 with substituted native I/O.
#[cfg(test)]
pub(crate) fn classic_semantic_stop_for_test(
    coordinator: &mut InventoryCoordinator<OsProcessSource>,
    lane: crate::inventory_semantics::AttestedSemanticLane,
) -> crate::inventory_semantics::AttestedSemanticLane {
    let mut driver = ClassicDriver {
        coordinator,
        inventory_scope: None,
        scope: InventoryRunScope::Pid(std::process::id()),
        cgroup: None,
        max_scan_pids: None,
        guard: UnavailableImageGuard,
        deadline: None,
        attach_backend: crate::attach::BackendSelection::Auto,
        identity: None,
        display: None,
        semantic: Some(lane),
        semantic_staged: false,
        seated_summary: None,
        second_signal: None,
        lifecycle: crate::inventory_promotion::lifecycle::SelectedLifecycleService::new(),
        completion_source: None,
        pending_install: None,
        installed_promotion: None,
        retiring: None,
        joint_finish: JointFinishDriver::NotBegun,
        stop_requested: false,
        joint_first_error: None,
        suspended: false,
        joint_commit_pending: false,
        joint_tick_refusal: None,
        joint_commit_retries: 0,
        #[cfg(test)]
        terminal_seq_calls: 0,
        #[cfg(test)]
        reclaim_calls: Vec::new(),
        #[cfg(test)]
        joint_begin_calls: 0,
        #[cfg(test)]
        joint_step_calls: 0,
        #[cfg(test)]
        joint_commit_polls: 0,
        #[cfg(test)]
        take_promotion_work_calls: 0,
        #[cfg(test)]
        drive_pending_install_calls: 0,
        #[cfg(test)]
        service_caller_metadata_calls: 0,
        #[cfg(test)]
        commit_calls: 0,
    };
    driver.on_stop_requested();
    // Repeated stop hooks cannot submit the same native owners again.
    driver.on_lane_stopped();
    driver.semantic.take().unwrap()
}

/// Drive one promotion request through the real driver loop to Active
/// and back through cancel, wind-down and retire (DR37 privileged
/// loop): queue on a headless display, tick until the lane installs
/// via the production path (resolve, worker preparation, native CAS,
/// proof), cancel, then tick until the domain retires through the
/// genuine completion mint. Returns the installed pair plus the
/// retired domain. Bounds are wall-clock; expiry panics with the
/// stalled state. The caller supplies the qualified view (with a
/// genuine pre-view baseline) and pair; everything downstream runs
/// production code.
#[cfg(test)]
pub(crate) fn classic_promotion_full_loop_for_test(
    coordinator: &mut InventoryCoordinator<OsProcessSource>,
    scope: &crate::attach::Scope,
    view: crate::inventory_promotion::PromotionView,
    caller: crate::discovery::caller_registry::CallerId,
    provider: crate::discovery::caller_registry::ModuleId,
    active_within: Duration,
    retire_within: Duration,
) -> (
    crate::inventory_promotion::PromotionPair,
    crate::attach::capture::NativeDomainId,
) {
    use crate::inventory_promotion::PromotionState;
    use std::os::fd::AsRawFd as _;
    let null = std::fs::File::open("/dev/null").expect("/dev/null opens");
    let io = DashboardIo {
        output: null.as_raw_fd(),
        input: None,
        account: None,
        stderr_fd: 2,
        stderr: StderrRoute::Leave,
    };
    let mut display = Display::open(&io, "test").expect("headless display opens");
    let capture = view.capture();
    assert!(
        display.promotion_enable(capture),
        "promotion enables for the viewed capture"
    );
    display
        .queue_promotion_request_for_test(std::sync::Arc::new(view), caller, provider)
        .expect("the qualified pair queues");
    let mut driver = ClassicDriver {
        coordinator,
        inventory_scope: None,
        scope: scope.into(),
        cgroup: None,
        max_scan_pids: None,
        guard: UnavailableImageGuard,
        deadline: None,
        attach_backend: crate::attach::BackendSelection::Auto,
        identity: None,
        display: Some(display),
        semantic: None,
        semantic_staged: false,
        seated_summary: None,
        second_signal: None,
        lifecycle: crate::inventory_promotion::lifecycle::SelectedLifecycleService::new(),
        completion_source: Some(Box::new(crate::attach::NativeCompletionMinter::new())),
        pending_install: None,
        installed_promotion: None,
        retiring: None,
        joint_finish: JointFinishDriver::NotBegun,
        stop_requested: false,
        joint_first_error: None,
        suspended: false,
        joint_commit_pending: false,
        joint_tick_refusal: None,
        joint_commit_retries: 0,
        #[cfg(test)]
        terminal_seq_calls: 0,
        #[cfg(test)]
        reclaim_calls: Vec::new(),
        #[cfg(test)]
        joint_begin_calls: 0,
        #[cfg(test)]
        joint_step_calls: 0,
        #[cfg(test)]
        joint_commit_polls: 0,
        #[cfg(test)]
        take_promotion_work_calls: 0,
        #[cfg(test)]
        drive_pending_install_calls: 0,
        #[cfg(test)]
        service_caller_metadata_calls: 0,
        #[cfg(test)]
        commit_calls: 0,
    };
    let started = Instant::now();
    loop {
        driver.on_tick();
        match driver.display.as_ref().expect("display").promotion_state() {
            PromotionState::Active => break,
            PromotionState::Refused(refusal) => panic!(
                "live promotion refused: {refusal:?}; gaps: {:?}",
                scope_gaps_for_test(&mut driver),
            ),
            PromotionState::Ended(reason) => panic!(
                "live promotion ended before install: {reason:?}; gaps: {:?}",
                scope_gaps_for_test(&mut driver),
            ),
            other => {
                assert!(
                    started.elapsed() < active_within,
                    "live promotion stalled before install: {other:?}; gaps: {:?}",
                    scope_gaps_for_test(&mut driver),
                );
                std::thread::sleep(Duration::from_millis(10));
            }
        }
    }
    let pair = driver
        .installed_promotion
        .as_ref()
        .expect("an Active display has an installed promotion")
        .pair;
    // The installed domain, read before teardown: wind-down and retire
    // can complete in the same tick the cancel lands, so inferring it
    // from the retiring slot afterwards races. Exit below implies the
    // wind-down recorded and retired exactly this domain.
    let installed_domain = driver.semantic.as_ref().map(|lane| lane.domain());
    assert_eq!(
        pair.caller(),
        caller.0,
        "the installed pair names the request"
    );
    assert_eq!(
        pair.provider(),
        provider.0,
        "the installed pair names the request"
    );
    driver
        .display
        .as_mut()
        .expect("display")
        .cancel_promotion_for_test();
    let stopping = Instant::now();
    loop {
        driver.on_tick();
        if driver.installed_promotion.is_none()
            && driver.retiring.is_none()
            && driver.lifecycle.is_idle()
        {
            break;
        }
        assert!(
            stopping.elapsed() < retire_within,
            "live promotion stalled before retire: installed={:?} retiring={:?} idle={}; gaps: {:?}",
            driver.installed_promotion.is_some(),
            driver.retiring.as_ref().map(|retiring| retiring.domain),
            driver.lifecycle.is_idle(),
            scope_gaps_for_test(&mut driver),
        );
        std::thread::sleep(Duration::from_millis(10));
    }
    (
        pair,
        installed_domain.expect("an Active promotion installed a lane"),
    )
}

/// Drain the coordinator's scope gaps for a test failure message.
#[cfg(test)]
fn scope_gaps_for_test(driver: &mut ClassicDriver<'_>) -> Vec<(String, String)> {
    driver.coordinator.registry_mut().publish();
    driver
        .coordinator
        .registry()
        .gaps()
        .iter()
        .map(|gap| (gap.subject.clone(), gap.reason.clone()))
        .collect()
}

/// The display borrow a stop disclosure warns through. The Joint
/// finish driver is associated functions without `self`, so the
/// method call sites build this from the split display borrow and
/// pass it down to the hold.
struct WarnSink<'a> {
    display: &'a mut Option<Display>,
}

impl WarnSink<'_> {
    fn emit(&mut self, line: &str) {
        ClassicDriver::warn_recorded(self.display, line);
    }
}

/// Lifetime counts for one honest stop disclosure, read from the
/// lane (plus the coordinator's binding count) before any handoff
/// that would clear them. Counts only; no identities, paths or
/// payloads.
struct SemanticStopCounts {
    refusals: [u64; 12],
    collected: u64,
    joined: u64,
    shed: u64,
    bindings: u64,
    refused: u64,
}

impl SemanticStopCounts {
    fn read(
        lane: &crate::inventory_semantics::AttestedSemanticLane,
        coordinator: &mut InventoryCoordinator<OsProcessSource>,
    ) -> Self {
        let refusals = lane.scan_refusal_counts();
        let (collected, joined, shed, refused) = lane.semantic_stop_call_counts();
        let bindings = coordinator.semantic_bindings_mut().len() as u64;
        Self {
            refusals,
            collected,
            joined,
            shed,
            bindings,
            refused,
        }
    }
}

/// One honest stop disclosure, shared by the legacy terminal
/// sequence and the Joint finish driver: the aggregate scan-refusal
/// gap (nothing recorded when nothing was refused) plus the
/// lifetime call-count line. Counts only; no identities, paths or
/// payloads.
fn disclose_semantic_stop(
    counts: &SemanticStopCounts,
    coordinator: &mut InventoryCoordinator<OsProcessSource>,
    warn: &mut WarnSink<'_>,
) {
    coordinator.record_scan_refusals_gap(&counts.refusals);
    warn.emit(&crate::inventory_semantics::semantic_stop_line(
        counts.collected,
        counts.joined,
        counts.shed,
        counts.bindings,
        counts.refused,
    ));
}

/// The shared once-gate predicate for winding stop disclosures: a
/// disclosure is still owed unless a stop path already disclosed it.
/// The stop path, the join tail and the exit hold consult this one
/// predicate, so a future edit cannot desync the callers; arming stays
/// at the call sites (the stop path and the hold arm, the join tail
/// deliberately never does, since a later stop still owes its
/// held-for-exit gap).
fn stop_counts_owed(disclosed: bool) -> bool {
    !disclosed
}

/// Disclose a winding lane's stop counts unless a stop path already
/// disclosed them: the join tail, the stop path and the exit hold
/// share this one gate, so each winding discloses exactly once. The
/// gate only reads the flag: the stop path arms it, and the exit hold
/// arms the flag threaded to it, while the join tail deliberately
/// never arms it (a later stop still owes its held-for-exit gap).
fn disclose_stop_counts_once(
    winding: &mut WindingLane,
    counts: &SemanticStopCounts,
    coordinator: &mut InventoryCoordinator<OsProcessSource>,
    warn: &mut WarnSink<'_>,
) {
    if !stop_counts_owed(winding.stop_disclosed) {
        return;
    }
    disclose_semantic_stop(counts, coordinator, warn);
}

impl ClassicDriver<'_> {
    /// A pass warning: stderr on the classic path; under the dashboard
    /// (which must never scribble beside its screen) the log tail, kept
    /// for stderr past the screen.
    fn warn(&mut self, warning: &str) {
        Self::warn_recorded(&mut self.display, warning);
    }

    /// One warning through a split display borrow (the stop
    /// disclosure calls this where `warn` cannot borrow `self`):
    /// stderr on the classic path, the log tail under the dashboard.
    fn warn_recorded(display: &mut Option<Display>, warning: &str) {
        match display.as_mut() {
            Some(display) => display.warn(warning),
            None => inventory_diagnostic(warning),
        }
        #[cfg(test)]
        record_warned_for_test(warning);
    }

    /// The lane's sanitized summary for this pass's presentation:
    /// disabled without manifests, never permission-bearing.
    fn semantic_summary(&self) -> crate::inventory_semantics::SemanticCaptureSummary {
        self.semantic
            .as_ref()
            .map(|lane| lane.semantic_summary())
            .or(self.seated_summary)
            .unwrap_or_default()
    }

    /// Snapshot the seated lane's summary before a hold or
    /// completion removes it: the run serves the snapshot past the
    /// handoff instead of the default. Each removal overwrites it
    /// with its own lane.
    fn snapshot_seated_summary(&mut self) {
        if let Some(lane) = self.semantic.as_ref() {
            self.seated_summary = Some(lane.semantic_summary());
        }
    }

    /// D5 (§5): bind the seated lane's Joint machine before its first
    /// tick. Each lane reaches this exactly once: the run's lane at
    /// driver construction (classic or dashboard, never both), a
    /// promoted lane at install. Success makes the lane Joint; refusal
    /// keeps the legacy one-sided path with one disclosure gap.
    /// In v0.5.0 (R-50) the bound machine installs no key-operation feed: the lane stays S1-only with one `joint_journal_unavailable` disclosure.
    fn initialize_joint_lane(&mut self) {
        let (coordinator, semantic) = (&mut *self.coordinator, &mut self.semantic);
        let Some(lane) = semantic.as_mut() else {
            return;
        };
        if lane.has_joint_machine() {
            return;
        }
        if let Err(reason) = lane.initialize_joint(coordinator) {
            coordinator.note_scope_gap("joint machine unavailable".into(), format!("{reason}"));
        }
    }

    /// The lane's independent terminal sequence: publish any
    /// pass-staged quantum, drain owned cursors to Q, then stop H0
    /// once. Every drained batch commits promptly during the drain,
    /// beside the lane's stop and before the Finish batch; a terminal
    /// failure records a gap instead of losing Inventory's stop. Runs
    /// at stop request (before native retirement) with the
    /// post-retirement hook as a no-op safety net.
    fn run_semantic_terminal_sequence(&mut self) {
        if !self
            .semantic
            .as_ref()
            .is_some_and(|lane| lane.is_live() && !lane.is_finished())
        {
            return;
        }
        #[cfg(test)]
        {
            self.terminal_seq_calls += 1;
        }
        // Publish any pass-staged quantum first: the terminal drain
        // must never backpressure behind it.
        if self.semantic_staged
            && let Err(error) = self.commit(false)
        {
            self.coordinator.note_scope_gap(
                "semantic terminal commit failed".into(),
                format!("{error:#}"),
            );
        }
        let pins: Vec<std::sync::Arc<PidPin>> = self
            .coordinator
            .semantic_bindings_mut()
            .bindings_for_tick()
            .iter()
            .filter(|binding| binding.scope_current())
            .map(|binding| binding.pin())
            .collect();
        // Borrow-split: the drain borrows the lane per quantum and the
        // coordinator between quanta, committing every drained batch
        // while H0 still runs instead of buffering through the wait.
        // Buffering would expire drained receipts (2s pending window)
        // inside a long quiescence wait (5s budget) before validation.
        let (coordinator, semantic) = (&mut self.coordinator, &mut self.semantic);
        let Some(lane) = semantic.as_mut() else {
            return;
        };
        lane.run_semantic_drain_committing(coordinator, &pins, std::time::Instant::now);
        // H0 stops once. Finish publication must succeed before its stamp
        // clears and native retirement begins; failed commits remain gaps.
        if let Some(finish) = self
            .semantic
            .as_mut()
            .and_then(|lane| lane.finish_semantic_stop())
        {
            self.coordinator.stage_semantic_batch(finish);
            self.semantic_staged = true;
            let lane = self
                .semantic
                .as_mut()
                .expect("the live Finish lane remains owned");
            lane.note_semantic_staged();
            let publication = commit_semantic_finish(self.coordinator, lane);
            match publication {
                Ok(_) => {
                    self.semantic_staged = false;
                    lane.note_semantic_published();
                    if let Err(error) = lane.begin_owned_terminal_cleanup() {
                        self.coordinator.note_scope_gap(
                            "semantic native cleanup could not begin".into(),
                            format!("{error:#}"),
                        );
                    }
                }
                Err(error) => self.coordinator.note_scope_gap(
                    "semantic terminal commit failed".into(),
                    format!("{error:#}"),
                ),
            }
        }
        // One honest stop disclosure through the shared helper: the
        // same aggregate scan-refusal gap plus lifetime call-count
        // line the Joint finish driver emits.
        let counts = self
            .semantic
            .as_ref()
            .map(|lane| SemanticStopCounts::read(lane, &mut *self.coordinator));
        if let Some(counts) = counts {
            let mut warn = WarnSink {
                display: &mut self.display,
            };
            disclose_semantic_stop(&counts, &mut *self.coordinator, &mut warn);
        }
    }

    /// DR37 promotion polling, every tick after the display tick:
    /// stopping observations, one service event, held-install drive,
    /// eager retire, then new takes. Displayless runs skip the
    /// display legs but still poll the service, installs and retire.
    fn poll_promotion(&mut self) {
        use crate::inventory_promotion::{PromotionEnd, PromotionState};
        let stopping = self
            .display
            .as_ref()
            .is_some_and(|display| display.promotion_state() == PromotionState::Stopping);
        if stopping {
            self.lifecycle.note_cancel(PromotionEnd::Cancelled);
            self.reclaim_pending_install(PromotionEnd::Cancelled);
            self.wind_down_installed_promotion(PromotionEnd::Cancelled);
        }
        let mut sink = std::io::sink();
        if let Some(event) = self.lifecycle.poll(&mut sink) {
            self.apply_lifecycle_event(event);
        }
        self.drive_pending_install();
        self.poll_retiring_domain();
        self.take_promotion_work();
    }

    /// Apply one lifecycle event: statuses go to the mailbox (stale
    /// or foreign updates apply to nothing there) with every terminal
    /// transition recorded in the bounded report path; install
    /// handoffs park until the slot is free and the predecessor
    /// retired.
    fn apply_lifecycle_event(
        &mut self,
        event: crate::inventory_promotion::lifecycle::LifecycleEvent,
    ) {
        use crate::inventory_promotion::PromotionOutcome;
        use crate::inventory_promotion::lifecycle::LifecycleEvent;
        match event {
            LifecycleEvent::Status(update) => {
                let gap = match update.outcome {
                    PromotionOutcome::Refused { reason } => {
                        Some(("selected promotion refused", reason.label().to_string()))
                    }
                    PromotionOutcome::Ended { reason } => {
                        Some(("selected promotion ended", reason.label().to_string()))
                    }
                    _ => None,
                };
                if let Some(display) = self.display.as_mut() {
                    display.set_promotion_status(update);
                }
                if let Some((subject, reason)) = gap {
                    self.coordinator.note_scope_gap(subject.into(), reason);
                }
            }
            LifecycleEvent::Install(pending) => {
                debug_assert!(
                    self.pending_install.is_none(),
                    "the service is single-flight: one handoff at a time"
                );
                self.pending_install = Some(pending);
            }
        }
    }

    /// Drive a held install handoff: install now when the slot is
    /// free and no predecessor retires, retire-then-install when a
    /// completion proves the predecessor done, hold otherwise. An
    /// occupied slot never auto-displaces: displacing a live lane
    /// (today always the manifest lane, since the control refuses
    /// takes while a promotion is active) awaits the operator
    /// displacement policy at unification; the handoff waits,
    /// cancellable, and the live lane keeps serving.
    fn drive_pending_install(&mut self) {
        #[cfg(test)]
        {
            self.drive_pending_install_calls += 1;
        }
        if self.pending_install.is_none() {
            return;
        }
        if self.semantic.is_some() {
            return;
        }
        if self.retiring.is_some() && !self.poll_retiring_domain() {
            return;
        }
        let pending = self
            .pending_install
            .take()
            .expect("held handoff checked above");
        let pair = pending.pair();
        let (proof, lane, capacity) = pending.into_parts();
        match self
            .coordinator
            .install_selected_lane(proof, lane, capacity)
        {
            Ok(live) => {
                self.semantic = Some(live);
                // D5: lane B initializes before its first service.
                self.initialize_joint_lane();
                if let Some(update) = self.lifecycle.note_installed() {
                    self.installed_promotion = Some(InstalledPromotion {
                        capture: update.capture,
                        request: update.request,
                        pair,
                    });
                    if let Some(display) = self.display.as_mut() {
                        display.set_promotion_status(update);
                    }
                }
            }
            Err(failure) => {
                use crate::inventory_promotion::lifecycle::PendingInstall;
                let reason = format!("{:?}", failure.reason);
                let pending =
                    PendingInstall::from_parts(failure.proof, failure.lane, failure.capacity);
                if self.lifecycle.reclaim_install(pending, None).is_err() {
                    debug_assert!(false, "install implies an outstanding handoff");
                }
                self.coordinator
                    .note_scope_gap("selected promotion install refused".into(), reason);
            }
        }
    }

    /// Poll a wound-down domain's genuine completion; retire on
    /// proof. Returns false while retirement still pends. No minter
    /// (or unquiesced work) holds the namespace, never forces it; a
    /// namespace that never staged clears quietly. A proof refused
    /// for pending work is retained for the next attempt: the minter
    /// delivers once, so the retry reuses it instead of re-polling.
    fn poll_retiring_domain(&mut self) -> bool {
        use crate::discovery::engine::inventory_coordinator::semantics::JointRetireRefusal;
        let winding = self
            .retiring
            .as_ref()
            .and_then(|retiring| retiring.winding.as_ref().map(|winding| winding.joint));
        match winding {
            Some(true) => return self.poll_joint_winding(),
            Some(false) if !self.poll_legacy_winding() => return false,
            Some(false) | None => {}
        }
        let Some(retiring) = self.retiring.as_mut() else {
            return true;
        };
        let domain = retiring.domain;
        let completion = match retiring.completion.take() {
            Some(retained) => retained,
            None => {
                let Some(source) = self.completion_source.as_mut() else {
                    return false;
                };
                let Some(minted) = source.poll_completion(domain) else {
                    // A failed mint holds the namespace but reports
                    // its preserved cause once through the gap path;
                    // a merely pending poll takes nothing.
                    if let Some(failure) = source.take_first_failure() {
                        self.coordinator
                            .note_scope_gap("selected promotion completion failed".into(), failure);
                    }
                    return false;
                };
                minted
            }
        };
        match self.coordinator.retire_joint_domain(completion) {
            Ok(()) => {
                self.retiring = None;
                true
            }
            Err((_, JointRetireRefusal::NotLiveDomain)) => {
                self.retiring = None;
                true
            }
            Err((completion, JointRetireRefusal::PendingWork)) => {
                self.retiring
                    .as_mut()
                    .expect("retiring checked above")
                    .completion = Some(completion);
                false
            }
        }
    }

    /// Take one queued request: reserve install capacity, resolve the
    /// preparation bundle, run the three pre-start gates (subset
    /// shape, baseline agreement, live pair liveness plus the subset
    /// proof over the live provider key), then start the worker and
    /// report preparing. Every refusal reports through the mailbox
    /// and the bounded report path; the reservation refunds by drop.
    fn take_promotion_work(&mut self) {
        #[cfg(test)]
        {
            self.take_promotion_work_calls += 1;
        }
        use crate::inventory_promotion::PromotionRefusal;
        use crate::inventory_promotion::lifecycle::validate_subset_shape;
        // A's promotion wind-down holds B: no preparation or
        // admission until A retires (§8.6).
        if !self.lifecycle.is_idle()
            || self.pending_install.is_some()
            || self
                .retiring
                .as_ref()
                .is_some_and(|retiring| retiring.winding.is_some())
        {
            return;
        }
        let Some(display) = self.display.as_mut() else {
            return;
        };
        let Some(request) = display.take_promotion_request() else {
            return;
        };
        let capacity = match self.coordinator.reserve_promotion_install() {
            Ok(capacity) => capacity,
            Err(_) => {
                self.refuse_promotion_request(&request, PromotionRefusal::Capacity);
                return;
            }
        };
        let (bundle, source) = match self.resolve_preparation_job(&request) {
            Ok(resolved) => resolved,
            Err(reason) => {
                drop(capacity);
                self.refuse_promotion_request(&request, reason);
                return;
            }
        };
        if let Err(reason) = validate_subset_shape(bundle.convert_subset()) {
            drop(capacity);
            self.refuse_promotion_request(&request, reason);
            return;
        }
        if !bundle.baseline.matches_request(&request) {
            drop(capacity);
            self.refuse_promotion_request(&request, PromotionRefusal::StaleView);
            return;
        }
        let pair = crate::inventory_promotion::PromotionPair::new(
            request.caller().0,
            request.provider().0,
        );
        let key = match self
            .coordinator
            .validate_selected_pair_liveness(pair, &bundle.original)
        {
            Ok(key) => key,
            Err(reason) => {
                drop(capacity);
                self.refuse_promotion_request(&request, reason);
                return;
            }
        };
        let proved = bundle
            .convert_subset()
            .required()
            .keys()
            .next()
            .is_some_and(|object| {
                bundle
                    .convert_subset()
                    .proves_provider_module(*object, &key)
            });
        if !proved {
            drop(capacity);
            self.refuse_promotion_request(&request, PromotionRefusal::ProviderChanged);
            return;
        }
        let update = request.status_update(crate::inventory_promotion::PromotionOutcome::Preparing);
        self.lifecycle
            .start(request, capacity, source, || bundle.prepare())
            .expect("take requires an idle service");
        if let Some(display) = self.display.as_mut() {
            display.set_promotion_status(update);
        }
    }

    /// Report one refusal through the mailbox and the bounded report
    /// path. Stale or foreign updates apply to nothing; the gap
    /// still records the genuine refusal.
    fn refuse_promotion_request(
        &mut self,
        request: &crate::inventory_promotion::PromotionRequest,
        reason: crate::inventory_promotion::PromotionRefusal,
    ) {
        let update =
            request.status_update(crate::inventory_promotion::PromotionOutcome::Refused { reason });
        if let Some(display) = self.display.as_mut() {
            display.set_promotion_status(update);
        }
        self.coordinator.note_scope_gap(
            "selected promotion refused".into(),
            reason.label().to_string(),
        );
    }

    /// Reclaim a held install handoff into the service for genuine
    /// disposal. A handoff the service will not take back (never:
    /// install implies outstanding) parks again rather than stranding
    /// the lane.
    fn reclaim_pending_install(&mut self, end: crate::inventory_promotion::PromotionEnd) {
        let Some(pending) = self.pending_install.take() else {
            return;
        };
        // The spy sits after the take: it records a handoff actually
        // taken for reclaim (I4), never a bare attempt.
        #[cfg(test)]
        {
            self.reclaim_calls.push(end);
        }
        if let Err(pending) = self.lifecycle.reclaim_install(pending, Some(end)) {
            self.pending_install = Some(pending);
        }
    }

    /// Whether the lane takes the Joint finish path: a live machine
    /// or a retained frame. Production-identical to
    /// `has_joint_machine`: outside tests the frame implies the
    /// machine (`has_joint_frame` is machine && !finished), so the
    /// disjunction collapses to the machine. Tests drive the branch
    /// through the retained-frame seam, which unit tests can set.
    fn is_joint_lane(lane: &crate::inventory_semantics::AttestedSemanticLane) -> bool {
        lane.has_joint_machine() || lane.has_joint_frame()
    }

    /// Begin a Joint lane's finish once (§8.3): a begun finish
    /// polls; a refused begin on a finished lane resumes at the
    /// wound-down phase; any other refusal leaves the latch in the
    /// lane (§1.11) for the caller to abandon.
    fn begin_lane_finish(
        lane: &mut crate::inventory_semantics::AttestedSemanticLane,
        coordinator: &mut InventoryCoordinator<OsProcessSource>,
    ) -> JointFinishDriver {
        match lane.begin_joint_finish(coordinator) {
            Ok(()) => JointFinishDriver::Polling,
            Err(_) if lane.is_finished() => JointFinishDriver::Published,
            Err(_) => JointFinishDriver::Abandoned,
        }
    }

    /// One stderr line for a held lane whose live Joint publication
    /// wedged or was abandoned: a running no-progress trip names its
    /// stall, the abandon its outcome. Counts only; no identities,
    /// paths or payloads. `None` without an abandon means the hold
    /// owes no line (no trip fired, nothing stood to abandon).
    fn held_live_publication_line(stalled_secs: Option<u64>, abandoned: bool) -> Option<String> {
        match (stalled_secs, abandoned) {
            (None, false) => None,
            (Some(secs), true) => Some(format!(
                "p11scope: live publication made no progress for {secs} s; abandoned it, coverage is partial"
            )),
            (Some(secs), false) => Some(format!(
                "p11scope: live publication made no progress for {secs} s; the lane is held for exit, coverage is partial"
            )),
            (None, true) => Some(
                "p11scope: abandoned the unfinished live publication, coverage is partial"
                    .to_string(),
            ),
        }
    }

    /// Hold a Joint lane for exit after its finish failed (item 7,
    /// §6.4): disclose the lane's stop counts once, abandon where
    /// admitted (best-effort commit, whose failure is kept as its
    /// own gap; first error kept), then hold the whole lane. The
    /// disclosure runs before the abandon commit so its gap rides
    /// that commit. A winding hold threads its winding's disclosed
    /// flag and joins the shared once-gate (silent past a stop,
    /// arming when it discloses); a live-lane hold passes `None` and
    /// always discloses. Each caller names the abandon gap subject:
    /// exit holds say "for exit"; a mid-run lane-stop conversion
    /// says "for lane stop", so the gap never claims the run is
    /// leaving while it continues. Returns the first error: the
    /// disposition where latched, else the trigger cause. Callers
    /// disclose the skips (finished or unadmitted holds).
    fn hold_joint_lane_for_exit(
        mut lane: crate::inventory_semantics::AttestedSemanticLane,
        coordinator: &mut InventoryCoordinator<OsProcessSource>,
        cause: &str,
        abandon_subject: &str,
        warn: &mut WarnSink<'_>,
        winding_disclosed: Option<&mut bool>,
    ) -> String {
        // A recorded terminal graph refusal predates any later
        // verdict, so it wins as the abandon reason (§1.9, §6.4).
        let reason = coordinator
            .collected_graph_refused()
            .unwrap_or("joint finish disposition required");
        let latched = lane.joint_finish_disposition_required();
        // Name a tripped no-progress wedge on stderr: the wedged
        // publication stands in front of the commit, so the staged gap
        // cannot commit while the wedge stands, and this warning is the
        // user-visible name. Outside the counts once-gate: the wedge is
        // new information even past a counts disclosure.
        if let Some(trip) = lane.joint_finish_no_progress_trip() {
            warn.emit(&format!(
                "joint finish made no progress for {}s across {} polls; the lane is held for exit",
                trip.stalled.as_secs(),
                trip.polls,
            ));
        }
        // Abandon the unfinished Joint publication first: its prepared
        // frame can never resume past the latched machine, and every
        // later plain commit (including the abandon commit below)
        // refuses while it stands. The abandon publishes the prepared
        // physical work, resolves stranded semantic batches (their
        // shed counts land before the disclosure below), and stages
        // its named loss gap, so the abandon commit succeeds and the
        // staged gaps publish. Nothing pending is a quiet no-op.
        let publication_stood = coordinator.publication_pending();
        let frame = lane.take_joint_frame_for_abandon();
        coordinator.abandon_unfinished_joint_publication(&mut lane, frame, reason.to_string());
        // Name a wedged live publication on stderr: a running
        // no-progress trip fired, or the abandon above cleared a
        // standing publication. One line per hold: the trip latches
        // once in the machine and the hold runs once per lane, so
        // this never repeats per poll. Outside the counts once-gate,
        // beside the finish wedge above: the wedge is new
        // information even past a counts disclosure.
        let running_trip = lane.joint_audit_no_progress_trip();
        let abandoned = publication_stood && !coordinator.publication_pending();
        if let Some(line) = Self::held_live_publication_line(
            running_trip.map(|trip| trip.stalled.as_secs()),
            abandoned,
        ) {
            warn.emit(&line);
        }
        let counts = SemanticStopCounts::read(&lane, coordinator);
        match winding_disclosed {
            // A stop path already disclosed this winding: stay silent.
            Some(disclosed) if !stop_counts_owed(*disclosed) => {}
            // A winding hold discloses through the shared once-gate and
            // arms it; a live lane always discloses, as before.
            winding => {
                disclose_semantic_stop(&counts, coordinator, warn);
                if let Some(disclosed) = winding {
                    *disclosed = true;
                }
            }
        }
        if !lane.is_finished()
            && latched
            && let Ok(batch) =
                lane.abandon_finish_with_subject(coordinator, abandon_subject, reason)
        {
            coordinator.stage_semantic_batch(batch);
            if let Err(error) = commit_semantic_finish(coordinator, &mut lane) {
                coordinator.note_scope_gap(
                    "joint abandon commit failed".to_string(),
                    format!("{error:#}"),
                );
            }
        }
        ExitRetention::hold(lane);
        if latched {
            reason.to_string()
        } else {
            cause.to_string()
        }
    }

    /// Direct-step entrypoint for the live privileged tests, which
    /// drive the step without a driver display: the same step with a
    /// stderr disclosure sink (those drivers carry no display, so
    /// this matches their production route).
    #[cfg(test)]
    fn step_begun_joint_finish(
        lane: &mut Option<crate::inventory_semantics::AttestedSemanticLane>,
        finish: &mut JointFinishDriver,
        coordinator: &mut InventoryCoordinator<OsProcessSource>,
        first_error: &mut Option<String>,
    ) -> JointStepOutcome {
        let mut display = None;
        let mut warn = WarnSink {
            display: &mut display,
        };
        Self::step_begun_joint_finish_with_warn(
            lane,
            finish,
            coordinator,
            first_error,
            &mut warn,
            None,
        )
    }

    /// Step a begun Joint finish once within the 10 ms /
    /// 1024-action budget (§8.3): Polling polls the finish (a
    /// disposition abandons through the finite stop, a finished lane
    /// resumes at Published, anything else stays for the latch to
    /// bound); Published polls only the wound-down (a refusal skips
    /// the abandon per §6.4 and holds); Abandoned does nothing. A
    /// winding step threads its winding's disclosed flag to the exit
    /// hold; a live-lane step passes `None`.
    fn step_begun_joint_finish_with_warn(
        lane: &mut Option<crate::inventory_semantics::AttestedSemanticLane>,
        finish: &mut JointFinishDriver,
        coordinator: &mut InventoryCoordinator<OsProcessSource>,
        first_error: &mut Option<String>,
        warn: &mut WarnSink<'_>,
        winding_disclosed: Option<&mut bool>,
    ) -> JointStepOutcome {
        let mut budget = crate::inventory_semantics::JointWorkBudget {
            remaining_actions: 1024,
            deadline: Instant::now() + Duration::from_millis(10),
        };
        match *finish {
            JointFinishDriver::NotBegun | JointFinishDriver::Abandoned => JointStepOutcome::Stayed,
            JointFinishDriver::Polling => {
                if lane
                    .as_ref()
                    .is_some_and(|lane| lane.joint_finish_disposition_required())
                {
                    if let Some(owned) = lane.take() {
                        let error = Self::hold_joint_lane_for_exit(
                            owned,
                            coordinator,
                            "joint finish disposition required",
                            "joint finish abandoned for exit",
                            warn,
                            winding_disclosed,
                        );
                        first_error.get_or_insert(error);
                    }
                    *finish = JointFinishDriver::Abandoned;
                    return JointStepOutcome::Abandoned;
                }
                // A finished lane has nothing left to poll: the
                // finish it began already published, so resume at
                // the wound-down phase instead of spinning on a
                // refusal the latch can never bound.
                if lane.as_ref().is_some_and(|lane| lane.is_finished()) {
                    *finish = JointFinishDriver::Published;
                    return JointStepOutcome::Stayed;
                }
                let Some(lane) = lane.as_mut() else {
                    return JointStepOutcome::Stayed;
                };
                match lane.poll_joint_finish(coordinator, &mut budget) {
                    Ok(crate::discovery::engine::inventory_coordinator::JointCommitProgress::Published(_)) => {
                        *finish = JointFinishDriver::Published;
                        JointStepOutcome::Stayed
                    }
                    Ok(crate::discovery::engine::inventory_coordinator::JointCommitProgress::Pending)
                    | Err(_) => JointStepOutcome::Stayed,
                }
            }
            JointFinishDriver::Published => {
                let wound = match lane.as_mut() {
                    Some(lane) => lane.poll_wound_down(coordinator, &mut std::io::stderr()),
                    None => return JointStepOutcome::Stayed,
                };
                match wound {
                    Ok(true) => JointStepOutcome::WoundDown,
                    Ok(false) => JointStepOutcome::Stayed,
                    Err(refusal) => {
                        // The gap carries the detach error text; the
                        // mapped refusal code is only the fallback
                        // when no detach ran, mirroring the legacy path.
                        let cause = lane
                            .as_mut()
                            .and_then(|lane| lane.take_wound_down_error_text())
                            .unwrap_or_else(|| format!("wound-down refused: {}", refusal.code()));
                        coordinator
                            .note_scope_gap("joint wound-down failed".to_string(), cause.clone());
                        if let Some(owned) = lane.take() {
                            // The first error is kept: a pre-set
                            // disposition survives this later failure.
                            // The hold always runs; only the error keeps.
                            first_error.get_or_insert(Self::hold_joint_lane_for_exit(
                                owned,
                                coordinator,
                                &cause,
                                "joint finish abandoned for exit",
                                warn,
                                winding_disclosed,
                            ));
                        }
                        *finish = JointFinishDriver::Abandoned;
                        JointStepOutcome::Abandoned
                    }
                }
            }
        }
    }

    /// Begin the live lane's Joint finish once; an abandoned begin
    /// holds the lane immediately.
    fn begin_final_joint_finish(&mut self) {
        self.snapshot_seated_summary();
        let (coordinator, semantic) = (&mut *self.coordinator, &mut self.semantic);
        let Some(lane) = semantic.as_mut() else {
            return;
        };
        #[cfg(test)]
        {
            self.joint_begin_calls += 1;
        }
        let mut warn = WarnSink {
            display: &mut self.display,
        };
        match Self::begin_lane_finish(lane, coordinator) {
            JointFinishDriver::Abandoned => {
                let lane = semantic.take().expect("joint lane");
                let error = Self::hold_joint_lane_for_exit(
                    lane,
                    coordinator,
                    "joint finish disposition required",
                    "joint finish abandoned for exit",
                    &mut warn,
                    None,
                );
                self.joint_first_error.get_or_insert(error);
                self.joint_finish = JointFinishDriver::Abandoned;
            }
            begun => {
                self.joint_finish = begun;
            }
        }
    }

    /// Escalate a begun Joint finish to the typed exit: abandon
    /// where admitted, hold the lane for exit, keep the first error.
    /// Anything else (no lane, a legacy lane, already held) is a no-op.
    /// Each caller names its own trigger: the second operator signal
    /// passes "second stop during joint finish", the settle bound
    /// passes its own cause, so the held gap never names a signal
    /// that never happened.
    fn escalate_joint_finish(&mut self, cause: &str) {
        if !self.semantic.as_ref().is_some_and(Self::is_joint_lane) {
            return;
        }
        if matches!(self.joint_finish, JointFinishDriver::Abandoned) {
            return;
        }
        self.snapshot_seated_summary();
        let Some(lane) = self.semantic.take() else {
            return;
        };
        let latched = lane.joint_finish_disposition_required();
        let finished = lane.is_finished();
        let mut warn = WarnSink {
            display: &mut self.display,
        };
        let error = Self::hold_joint_lane_for_exit(
            lane,
            &mut *self.coordinator,
            cause,
            "joint finish abandoned for exit",
            &mut warn,
            None,
        );
        self.joint_first_error.get_or_insert(error);
        if finished || !latched {
            self.coordinator
                .note_scope_gap("joint finish held for exit".to_string(), cause.to_string());
        }
        self.joint_finish = JointFinishDriver::Abandoned;
    }

    /// Complete a wound-down final Joint lane: take the joined
    /// session and drop it (the detach already joined), then release
    /// the lane shell. Only a handoff releases: production took its
    /// live Session, substituted lanes cleared their seams. A
    /// not-ready take (framed, or a re-polled pending detach) or a
    /// refusal keeps the lane for the next hook, whose wound-down
    /// poll re-verifies it. A handoff discloses the lane's stop
    /// counts once, before the release.
    fn complete_final_joint_lane(&mut self) {
        self.snapshot_seated_summary();
        let Some(lane) = self.semantic.as_mut() else {
            return;
        };
        // Read the lifetime counts before the take hands the live
        // Session away: after it the lane reads zeros.
        let counts = SemanticStopCounts::read(lane, &mut *self.coordinator);
        let handed_off = match lane.take_joined_session() {
            Ok(_) => !lane.is_finished(),
            Err(_) => return,
        };
        if handed_off {
            let mut warn = WarnSink {
                display: &mut self.display,
            };
            disclose_semantic_stop(&counts, &mut *self.coordinator, &mut warn);
            self.semantic = None;
        }
    }

    /// Reap a legacy winding lane once: Pending holds; a joined
    /// detach consumes through the synchronous boundary; a failed
    /// detach reports once and holds the owner for exit. True means
    /// the lane handed off and the shared tail may retire.
    fn poll_legacy_winding(&mut self) -> bool {
        enum Outcome {
            Pending,
            Joined,
            Failed(String),
        }
        let outcome = {
            let retiring = self.retiring.as_mut().expect("a winding lane retires");
            let winding = retiring.winding.as_mut().expect("a winding lane retires");
            let Some(lane) = winding.lane.as_mut() else {
                return false;
            };
            match lane.poll_wound_down(&mut *self.coordinator, &mut std::io::stderr()) {
                Ok(false) => Outcome::Pending,
                Ok(true) => Outcome::Joined,
                Err(error) => {
                    // The gap carries the detach error text; the
                    // mapped refusal code is only the fallback when
                    // no detach ran (exit-retained or unfinished).
                    let cause = lane
                        .take_wound_down_error_text()
                        .unwrap_or_else(|| format!("{error:#}"));
                    Outcome::Failed(cause)
                }
            }
        };
        match outcome {
            Outcome::Pending => false,
            Outcome::Joined => {
                let retiring = self.retiring.as_mut().expect("a winding lane retires");
                let lane = retiring
                    .winding
                    .as_mut()
                    .expect("winding")
                    .lane
                    .take()
                    .expect("winding lane");
                match lane.into_wound_down_session(&|| true, &mut std::io::sink()) {
                    Ok(session) => {
                        if let Some(session) = session {
                            let domain = retiring.domain;
                            if let Some(source) = self.completion_source.as_mut() {
                                source.note_wound_down(domain, session);
                            }
                        }
                        retiring.winding = None;
                        true
                    }
                    Err(error) => {
                        // The boundary already retained the failed
                        // owner for exit; the legacy downstream
                        // retires the namespace.
                        self.coordinator.note_scope_gap(
                            "selected lane native cleanup failed".to_string(),
                            format!("{error:#}"),
                        );
                        retiring.winding = None;
                        true
                    }
                }
            }
            Outcome::Failed(cause) => {
                self.coordinator
                    .note_scope_gap("selected lane native cleanup failed".to_string(), cause);
                let retiring = self.retiring.as_mut().expect("a winding lane retires");
                let lane = retiring
                    .winding
                    .as_mut()
                    .expect("winding")
                    .lane
                    .take()
                    .expect("winding lane");
                ExitRetention::hold(lane);
                retiring.winding = None;
                true
            }
        }
    }

    /// Step A's Joint promotion finish once (§8.6): NotBegun drains
    /// the pending commit, Polling polls the finish, Published polls
    /// only the wound-down. A joined detach hands its session to the
    /// minter and retires through the seal-drained gate; only an Ok
    /// retire clears the promotion flag and releases B. True retires.
    fn poll_joint_winding(&mut self) -> bool {
        #[cfg(test)]
        {
            self.joint_step_calls += 1;
        }
        // No NotBegun arm: the wind-down always begins or transfers
        // (§8.3), so a production winding is never NotBegun here; a
        // directly posed one stays through the begun step below. Item
        // 7's commit polls run on the retained final lane.
        let joined = self
            .retiring
            .as_ref()
            .expect("a winding lane retires")
            .winding
            .as_ref()
            .expect("a winding lane retires")
            .joined;
        if !joined {
            let mut warn = WarnSink {
                display: &mut self.display,
            };
            let outcome = {
                let retiring = self.retiring.as_mut().expect("a winding lane retires");
                let winding = retiring.winding.as_mut().expect("a winding lane retires");
                Self::step_begun_joint_finish_with_warn(
                    &mut winding.lane,
                    &mut winding.finish,
                    &mut *self.coordinator,
                    &mut self.joint_first_error,
                    &mut warn,
                    Some(&mut winding.stop_disclosed),
                )
            };
            if !matches!(outcome, JointStepOutcome::WoundDown) {
                return false;
            }
            // Read the lifetime counts before the take hands the live
            // Session away: after it the lane reads zeros.
            let counts = {
                let retiring = self.retiring.as_mut().expect("a winding lane retires");
                let lane = retiring
                    .winding
                    .as_ref()
                    .expect("winding")
                    .lane
                    .as_ref()
                    .expect("winding lane");
                SemanticStopCounts::read(lane, &mut *self.coordinator)
            };
            let session = {
                let retiring = self.retiring.as_mut().expect("a winding lane retires");
                let lane = retiring
                    .winding
                    .as_mut()
                    .expect("winding")
                    .lane
                    .as_mut()
                    .expect("winding lane");
                match lane.take_joined_session() {
                    Ok(session) => session,
                    Err(_) => return false,
                }
            };
            // The take carried the session away exactly when the lane
            // no longer reads finished: production took its live
            // Session, substituted lanes cleared their seams. A
            // not-ready take (framed, or a re-polled pending detach)
            // keeps the lane finishable, so the next tick reaps
            // again; only a handoff arms the joined tail — and
            // discloses the lane's stop counts once, unless a stop
            // path already disclosed them.
            {
                let retiring = self.retiring.as_mut().expect("a winding lane retires");
                let winding = retiring.winding.as_mut().expect("winding");
                if winding
                    .lane
                    .as_ref()
                    .is_some_and(|lane| !lane.is_finished())
                {
                    winding.joined = true;
                    // The join reads the shared once-gate but never arms
                    // it: a later stop still owes its held-for-exit gap.
                    let mut warn = WarnSink {
                        display: &mut self.display,
                    };
                    disclose_stop_counts_once(winding, &counts, &mut *self.coordinator, &mut warn);
                }
            }
            if let Some(session) = session {
                let retiring = self.retiring.as_mut().expect("a winding lane retires");
                let domain = retiring.domain;
                if let Some(source) = self.completion_source.as_mut() {
                    source.note_wound_down(domain, session);
                }
            }
        }
        let (completion, fresh) = {
            let retiring = self.retiring.as_mut().expect("a winding lane retires");
            match retiring.completion.take() {
                Some(retained) => (retained, false),
                None => {
                    let domain = retiring.domain;
                    match self
                        .completion_source
                        .as_mut()
                        .and_then(|source| source.poll_completion(domain))
                    {
                        Some(completion) => (completion, true),
                        None => return false,
                    }
                }
            }
        };
        let retiring = self.retiring.as_mut().expect("a winding lane retires");
        let lane = retiring
            .winding
            .as_ref()
            .expect("winding")
            .lane
            .as_ref()
            .expect("winding lane");
        match self
            .coordinator
            .retire_joint_domain_with_lane(lane, completion)
        {
            Ok(()) => {
                self.coordinator.set_promotion_finish(false);
                self.retiring = None;
                true
            }
            Err((completion, refusal)) => {
                // Only a completion for another domain is foreign:
                // A's own late completion with no live finalizer
                // state stays silent. The gap words the foreign
                // domain relationally: NativeDomainId is
                // equality-only (no Display; numeric access is
                // journal-only), so no id is printed.
                let foreign = self
                    .retiring
                    .as_ref()
                    .is_some_and(|retiring| retiring.domain != completion.domain());
                let not_live = matches!(
                    refusal,
                    crate::discovery::engine::inventory_coordinator::semantics::JointRetireRefusal::NotLiveDomain
                );
                if fresh && foreign && not_live {
                    self.coordinator.note_scope_gap(
                        "selected promotion completion failed".to_string(),
                        "foreign completion for a domain with no live finalizer state".to_string(),
                    );
                }
                // An own-domain completion that finds no live
                // finalizer clears like the lane-less tail: drained
                // with nothing to retire is done, and no path can
                // make the domain's finalizer live again, so
                // holding would block the successor silently.
                if !foreign && not_live {
                    self.coordinator.set_promotion_finish(false);
                    self.retiring = None;
                    return true;
                }
                let retiring = self.retiring.as_mut().expect("a winding lane retires");
                retiring.completion = Some(completion);
                false
            }
        }
    }

    /// One running-pass Joint commit poll (§9 item 3): begin once
    /// per publication (only the first call carries the applied
    /// engine change), then poll until it publishes. A lane with no
    /// machine to begin on commits the legacy way, like D5's Err
    /// path (production Joint lanes always carry their machine
    /// here; only substituted lanes arrive machineless, and the
    /// retained pump needs their progress-or-pend, never an error it
    /// would resolve and re-raise forever). An outstanding demand
    /// without the flag repairs the flag and resumes polling. A
    /// refused begin (DispositionRequired) or a refused poll is a
    /// semantic-lane stop, never a whole-capture failure: the lane is
    /// held for exit, disclosed once, and the pass commits past it
    /// and publishes, so later passes continue on the legacy path.
    fn poll_joint_commit_path(&mut self, engine_changed: bool) -> Result<PassCommitProgress> {
        use crate::inventory_semantics::JointCommitRefusal;
        if !self.joint_commit_pending {
            let begin = {
                let lane = self.semantic.as_mut().expect("a joint lane is seated");
                lane.begin_joint_commit(engine_changed)
            };
            match begin {
                Ok(()) => self.joint_commit_pending = true,
                Err(JointCommitRefusal::NotInitialized) => {
                    return self
                        .commit(engine_changed)
                        .map(|()| PassCommitProgress::Published);
                }
                Err(JointCommitRefusal::OutstandingRequest) => {
                    self.joint_commit_pending = true;
                }
                Err(JointCommitRefusal::DispositionRequired) => {
                    let reason = self
                        .semantic
                        .as_ref()
                        .and_then(|lane| lane.joint_disposition_reason())
                        .or(self.joint_tick_refusal)
                        .map(|refusal| refusal.code())
                        .unwrap_or("DispositionRequired");
                    return self.hold_joint_commit_lane_and_publish(engine_changed, reason);
                }
            }
        }
        #[cfg(test)]
        {
            self.joint_commit_polls += 1;
        }
        let mut budget = crate::inventory_semantics::JointWorkBudget {
            remaining_actions: 1024,
            deadline: Instant::now() + Duration::from_millis(10),
        };
        let (coordinator, semantic) = (&mut *self.coordinator, &mut self.semantic);
        let lane = semantic.as_mut().expect("a joint lane is seated");
        let progress = lane.poll_joint_commit(coordinator, &mut budget);
        match progress {
            Ok(JointCommitProgress::Published(_)) => {
                self.joint_commit_pending = false;
                Ok(PassCommitProgress::Published)
            }
            Ok(JointCommitProgress::Pending) => Ok(PassCommitProgress::Pending),
            Err(reason) => self.hold_joint_commit_lane_and_publish(engine_changed, reason.code()),
        }
    }

    /// Convert a semantic-lane Joint commit refusal into a held lane
    /// plus a published pass: snapshot what was seated (marked Partial:
    /// the lane stopped with declared loss for the rest of the run),
    /// hold the lane for exit (its stop counts disclose once), clear
    /// the pending commit, name the stop in its own gap, and commit
    /// the pass's native evidence past the held lane. Later passes
    /// continue on the legacy path. The hold's first error is dropped
    /// on purpose: the gap carries the disclosure, and
    /// `joint_first_error` stays for the finish path, so a continued
    /// run never surfaces this stale refusal as a later retained
    /// error. A broad commit failure still fails the call; a
    /// wedged-publication failure (the machine latched after
    /// physically preparing) names the semantic cause instead of the
    /// internal message.
    fn hold_joint_commit_lane_and_publish(
        &mut self,
        engine_changed: bool,
        reason: &str,
    ) -> Result<PassCommitProgress> {
        self.snapshot_seated_summary();
        if let Some(summary) = self.seated_summary.as_mut() {
            summary.status = crate::inventory_semantics::SemanticCaptureStatus::Partial;
        }
        let mut warn = WarnSink {
            display: &mut self.display,
        };
        let lane = self.semantic.take().expect("a joint lane is seated");
        Self::hold_joint_lane_for_exit(
            lane,
            &mut *self.coordinator,
            "joint commit disposition required",
            "joint finish abandoned for lane stop",
            &mut warn,
            None,
        );
        self.joint_commit_pending = false;
        self.coordinator.note_scope_gap(
            "semantic lane stopped".to_string(),
            format!(
                "{reason}; broad inventory continues; semantic probes stay attached until exit"
            ),
        );
        match self.commit(engine_changed) {
            Ok(()) => Ok(PassCommitProgress::Published),
            Err(error)
                if Self::commit_hit_unfinished_joint_publication(&error, &*self.coordinator) =>
            {
                // The machine latched after physically preparing the
                // commit: the coordinator still holds the unfinished
                // Joint publication, so this plain commit (and every
                // later one) refuses. Name the semantic cause on
                // stderr and in the error — never the internal
                // resume-original-frame message. A full
                // hold-and-publish past this wedge needs a coordinator
                // abandon API (no inventory-side call clears the
                // prepared publication); until then the run fails
                // honestly with its cause named.
                self.warn(&format!(
                    "p11scope: the semantic lane stopped ({reason}) but its unfinished joint publication still blocks the broad commit; the run cannot continue past it",
                ));
                Err(anyhow::anyhow!(
                    "semantic lane stopped ({reason}); the unfinished joint publication still blocks the broad commit and this run cannot continue past it"
                ))
            }
            Err(error) => Err(error),
        }
    }

    /// Whether a conversion-commit failure is the wedged-publication
    /// shape: the coordinator still holds an unfinished Joint
    /// publication, or the failure names it (fault-injected tests
    /// pose the message without preparing a real publication).
    fn commit_hit_unfinished_joint_publication(
        error: &anyhow::Error,
        coordinator: &InventoryCoordinator<OsProcessSource>,
    ) -> bool {
        coordinator.publication_pending()
            || format!("{error:#}").contains("unfinished Joint publication")
    }

    /// One NotBegun promotion step (item 7): poll the pending commit.
    /// Running passes begin through poll_commit; Published begins the
    /// finish while Pending stays (T16b refines Pending with its
    /// publication query); a retryable refusal stays, anything else
    /// notes the failure and takes the finite stop. Never retires directly.
    /// One NotBegun §8.3 step over an explicit lane slot (§6.1,
    /// §6.3): poll the pending commit — stay while it pends, begin
    /// once it publishes. A non-retryable refusal on a running
    /// commit converts like the Poll path (hold, named stop gap, no
    /// run error); only a finished lane's refusal fails the finish
    /// through I2. The winding and final-lane retained steps share
    /// it; callers count polls and begins.
    fn step_not_begun_joint_finish(
        lane: &mut Option<crate::inventory_semantics::AttestedSemanticLane>,
        finish: &mut JointFinishDriver,
        coordinator: &mut InventoryCoordinator<OsProcessSource>,
        first_error: &mut Option<String>,
        commit_retries: &mut u16,
        warn: &mut WarnSink<'_>,
        seated_summary: &mut Option<crate::inventory_semantics::SemanticCaptureSummary>,
    ) -> NotBegunStep {
        let mut budget = crate::inventory_semantics::JointWorkBudget {
            remaining_actions: 1024,
            deadline: Instant::now() + Duration::from_millis(10),
        };
        enum Outcome {
            Begin,
            Stayed,
            Fail(crate::inventory_semantics::SemanticRefusal),
        }
        let outcome = match lane.as_mut() {
            None => return NotBegunStep::Idle,
            Some(lane) => match lane.poll_joint_commit(coordinator, &mut budget) {
                Ok(JointCommitProgress::Published(_)) => Outcome::Begin,
                Ok(JointCommitProgress::Pending) => Outcome::Stayed,
                Err(reason) if note_commit_refusal_once(commit_retries, reason) => Outcome::Stayed,
                Err(reason) => Outcome::Fail(reason),
            },
        };
        match outcome {
            Outcome::Stayed => NotBegunStep::Stepped,
            Outcome::Begin => {
                let begun = match lane.as_mut() {
                    Some(lane) => Self::begin_lane_finish(lane, coordinator),
                    None => return NotBegunStep::Idle,
                };
                match begun {
                    JointFinishDriver::Abandoned => {
                        let live = lane.take().expect("a begun lane holds");
                        let error = Self::hold_joint_lane_for_exit(
                            live,
                            coordinator,
                            "joint finish disposition required",
                            "joint finish abandoned for exit",
                            warn,
                            None,
                        );
                        first_error.get_or_insert(error);
                        *finish = JointFinishDriver::Abandoned;
                    }
                    begun => {
                        *finish = begun;
                    }
                }
                NotBegunStep::Began
            }
            Outcome::Fail(reason) => {
                let finished = match lane.as_mut() {
                    Some(inner) => inner.is_finished(),
                    None => return NotBegunStep::Idle,
                };
                // A finished lane's refusal latches a finish failure
                // and keeps the finite-stop verdict. A running-commit
                // refusal converts exactly like the Poll path (F2,
                // ruling E1): hold, name the stop, publish past it —
                // no latched finish failure, no run error. The gap
                // carries the disclosure, so whichever cursor sees
                // the refusal first, the run ends the same way.
                if finished {
                    if let Some(inner) = lane.as_mut() {
                        inner.note_joint_finish_failure(reason);
                    }
                    let live = lane.take().expect("a failed lane holds");
                    let error = Self::hold_joint_lane_for_exit(
                        live,
                        coordinator,
                        "joint finish disposition required",
                        "joint finish abandoned for exit",
                        warn,
                        None,
                    );
                    first_error.get_or_insert(error);
                    let held = coordinator
                        .collected_graph_refused()
                        .unwrap_or("joint finish disposition required");
                    coordinator
                        .note_scope_gap("joint finish held for exit".to_string(), held.to_string());
                } else {
                    let live = lane.take().expect("a failed lane holds");
                    Self::hold_joint_lane_for_exit(
                        live,
                        coordinator,
                        "joint commit disposition required",
                        "joint finish abandoned for lane stop",
                        warn,
                        None,
                    );
                    // The lane stopped with declared loss: the served
                    // snapshot reads Partial, like the Poll path.
                    if let Some(summary) = seated_summary.as_mut() {
                        summary.status = crate::inventory_semantics::SemanticCaptureStatus::Partial;
                    }
                    coordinator.note_scope_gap(
                        "semantic lane stopped".to_string(),
                        format!(
                            "{}; broad inventory continues; semantic probes stay attached until exit",
                            reason.code()
                        ),
                    );
                }
                *finish = JointFinishDriver::Abandoned;
                NotBegunStep::Stepped
            }
        }
    }

    /// One retained §8.3 step for the final Joint lane (§6.1, §6.3),
    /// shared by the suspended tick and Publication disposal:
    /// NotBegun polls a pending commit or begins; a begun finish
    /// steps; an abandoned finish rests.
    fn step_retained_joint_finish(&mut self) {
        if !self.semantic.as_ref().is_some_and(Self::is_joint_lane) {
            return;
        }
        if matches!(self.joint_finish, JointFinishDriver::NotBegun) {
            if self.joint_commit_pending {
                // Snapshot before the step: a converting refusal
                // holds the lane, and the final report serves the
                // snapshot past the handoff, like the Poll path.
                self.snapshot_seated_summary();
                let mut warn = WarnSink {
                    display: &mut self.display,
                };
                let stepped = Self::step_not_begun_joint_finish(
                    &mut self.semantic,
                    &mut self.joint_finish,
                    &mut *self.coordinator,
                    &mut self.joint_first_error,
                    &mut self.joint_commit_retries,
                    &mut warn,
                    &mut self.seated_summary,
                );
                match stepped {
                    NotBegunStep::Began => {
                        self.joint_commit_pending = false;
                        #[cfg(test)]
                        {
                            self.joint_commit_polls += 1;
                            self.joint_begin_calls += 1;
                        }
                    }
                    NotBegunStep::Stepped => {
                        // A converting refusal held the lane: the
                        // commit pends nothing further, like F2.
                        if self.semantic.is_none() {
                            self.joint_commit_pending = false;
                        }
                        #[cfg(test)]
                        {
                            self.joint_commit_polls += 1;
                        }
                    }
                    NotBegunStep::Idle => {}
                }
            } else {
                self.begin_final_joint_finish();
            }
            return;
        }
        if matches!(self.joint_finish, JointFinishDriver::Abandoned) {
            return;
        }
        #[cfg(test)]
        {
            self.joint_step_calls += 1;
        }
        self.snapshot_seated_summary();
        let mut warn = WarnSink {
            display: &mut self.display,
        };
        let outcome = Self::step_begun_joint_finish_with_warn(
            &mut self.semantic,
            &mut self.joint_finish,
            &mut *self.coordinator,
            &mut self.joint_first_error,
            &mut warn,
            None,
        );
        if matches!(outcome, JointStepOutcome::WoundDown) {
            self.complete_final_joint_lane();
        }
    }

    /// Wind down the promotion-installed lane after an operator
    /// cancel: request stop and run the terminal sequence (whose
    /// drain is time-budgeted, never indefinite), then — once the
    /// Finish genuinely publishes with no pending semantic work left
    /// — release the lane, finish native cleanup under a bounded
    /// cancel budget with diagnostics bypassed past stderr, record
    /// the domain for completion-polled retire, and confirm the
    /// genuine end. Until publication
    /// completes the validating lane and its staged evidence stay:
    /// removing them would orphan pending work that no later
    /// publication could discharge. Joint lanes skip that gate and
    /// begin their Finish at once (the retire gate holds pending
    /// work instead). Manifest lanes are not promotion-managed and
    /// never wind down here.
    fn wind_down_installed_promotion(&mut self, end: crate::inventory_promotion::PromotionEnd) {
        use crate::inventory_promotion::{PromotionOutcome, PromotionStatusUpdate};
        let Some(installed) = self.installed_promotion else {
            return;
        };
        if let Some(lane) = self.semantic.as_mut() {
            lane.request_semantic_stop();
        }
        // Joint lanes skip the blocking terminal sequence: the finish
        // driver owns them from here (§8.3).
        if !self.semantic.as_ref().is_some_and(Self::is_joint_lane) {
            self.run_semantic_terminal_sequence();
        }
        // A staged batch that has not published yet retries through
        // the kept lane at the staleness cadence, like the tick's
        // staged commit: never gap-spamming, never dropping.
        if self.semantic_staged && self.semantic.is_some() {
            let stale = self
                .semantic
                .as_ref()
                .and_then(|lane| lane.staged_semantic_age())
                .is_some_and(|age| age >= STAGED_SEMANTIC_MAX_AGE);
            if stale && let Err(error) = self.commit(false) {
                self.coordinator.note_scope_gap(
                    "semantic terminal commit failed".into(),
                    format!("{error:#}"),
                );
                if let Some(lane) = self.semantic.as_mut() {
                    lane.note_semantic_staged();
                }
            }
        }
        let domain = self.semantic.as_ref().map(|lane| lane.domain());
        let joint = self.semantic.as_ref().is_some_and(Self::is_joint_lane);
        // Joint lanes skip the legacy staged-work gate and begin the
        // Finish at once: staged evidence cannot drain through a
        // gated lane, so holding here would wedge the wind-down
        // behind B forever. Pending work is handled by the retire
        // gate instead.
        let published = joint
            || (!self.semantic_staged
                && domain
                    .is_none_or(|domain| !self.coordinator.joint_domain_has_pending_work(domain)));
        if !published {
            // Terminal publication is incomplete: keep the validating
            // lane and its staged evidence; the next tick retries.
            // Nothing is confirmed and nothing retires yet.
            return;
        }
        self.installed_promotion = None;
        let Some(lane) = self.semantic.take() else {
            let update = PromotionStatusUpdate::new(
                installed.capture,
                installed.request,
                PromotionOutcome::Ended { reason: end },
            );
            if let Some(display) = self.display.as_mut() {
                display.set_promotion_status(update);
            }
            self.coordinator.note_scope_gap(
                "selected promotion ended".into(),
                format!(
                    "{} for c{} m{}",
                    end.label(),
                    installed.pair.caller(),
                    installed.pair.provider()
                ),
            );
            return;
        };
        if joint {
            // A's promotion finish (§8.6): the flag sets before a
            // fresh begin; the whole lane winds down in its retiring
            // domain. An in-flight finish keeps its state and
            // transfers into the winding; the flag stays clear (a
            // transferred finish is not A's promotion finish).
            let mut retiring = RetiringDomain::winding(lane, true);
            if matches!(self.joint_finish, JointFinishDriver::NotBegun) {
                self.coordinator.set_promotion_finish(true);
                #[cfg(test)]
                {
                    self.joint_begin_calls += 1;
                }
                let winding = retiring.winding.as_mut().expect("winding");
                let lane = winding.lane.as_mut().expect("winding lane");
                let mut warn = WarnSink {
                    display: &mut self.display,
                };
                match Self::begin_lane_finish(lane, &mut *self.coordinator) {
                    JointFinishDriver::Abandoned => {
                        let lane = winding.lane.take().expect("winding lane");
                        let error = Self::hold_joint_lane_for_exit(
                            lane,
                            &mut *self.coordinator,
                            "joint finish disposition required",
                            "joint finish abandoned for exit",
                            &mut warn,
                            Some(&mut winding.stop_disclosed),
                        );
                        self.joint_first_error.get_or_insert(error);
                        winding.finish = JointFinishDriver::Abandoned;
                    }
                    begun => {
                        winding.finish = begun;
                    }
                }
            } else {
                retiring.winding.as_mut().expect("winding").finish = self.joint_finish;
                self.joint_finish = JointFinishDriver::NotBegun;
            }
            self.retiring = Some(retiring);
        } else {
            // Legacy lanes wind down at the wound-down phase; ticks
            // reap the detach and retire through the shared tail.
            let mut retiring = RetiringDomain::winding(lane, false);
            retiring.winding.as_mut().expect("winding").finish = JointFinishDriver::Published;
            self.retiring = Some(retiring);
        }
        let update = PromotionStatusUpdate::new(
            installed.capture,
            installed.request,
            PromotionOutcome::Ended { reason: end },
        );
        if let Some(display) = self.display.as_mut() {
            display.set_promotion_status(update);
        }
        self.coordinator.note_scope_gap(
            "selected promotion ended".into(),
            format!(
                "{} for c{} m{}",
                end.label(),
                installed.pair.caller(),
                installed.pair.provider()
            ),
        );
    }

    /// The domain currently retiring, if any: tests assert through
    /// this instead of the retained proof.
    #[cfg(test)]
    fn retiring_domain(&self) -> Option<crate::attach::capture::NativeDomainId> {
        self.retiring.as_ref().map(|retiring| retiring.domain)
    }

    /// Arm the retiring winding's stop-disclosed flag: the winding was
    /// checked above at every caller.
    fn arm_winding_stop_disclosed(retiring: &mut Option<RetiringDomain>) {
        retiring
            .as_mut()
            .expect("winding checked above")
            .winding
            .as_mut()
            .expect("winding checked above")
            .stop_disclosed = true;
    }

    /// Disclose a promotion lane that never joined its wind-down: no
    /// ticks follow the stop, so the lane is held for exit at drop
    /// and this gap — recorded before the final commit — publishes
    /// that. A Joint winding that never disclosed also discloses its
    /// stop counts here, like every other hold; a lane that already
    /// disclosed (joined, held, or a legacy lane disclosed at
    /// wind-down) stays quiet. Once-only per winding: the disclosed
    /// flag keeps every later call — from any stop path — silent. The
    /// flag arms after the counts leg uses the shared once-gate, so
    /// the join tail, the stop path and the exit hold all disclose
    /// through the one gate.
    fn record_unjoined_winding_gap(&mut self) {
        let joint = self.retiring.as_ref().and_then(|retiring| {
            retiring
                .winding
                .as_ref()
                .filter(|winding| winding.lane.is_some())
                .map(|winding| winding.joint)
        });
        let Some(joint) = joint else {
            return;
        };
        if !stop_counts_owed(
            self.retiring
                .as_ref()
                .expect("winding checked above")
                .winding
                .as_ref()
                .expect("winding checked above")
                .stop_disclosed,
        ) {
            return;
        }
        self.coordinator.note_scope_gap(
            "promotion wind-down held for exit".to_string(),
            if joint {
                "stop during a Joint promotion finish; the lane is held for exit".to_string()
            } else {
                "stop during a legacy wind-down; the lane is held for exit".to_string()
            },
        );
        // The drop hold stays silent, so the stop path is an
        // undisclosed winding's only disclosure: readable counts go
        // through the shared helper before the final commit, while
        // unreadable counts name a gap instead of printing invented
        // zeros.
        let undisclosed = self.retiring.as_ref().and_then(|retiring| {
            retiring.winding.as_ref().filter(|winding| {
                winding.joint
                    && winding.lane.is_some()
                    && !winding.joined
                    && !matches!(winding.finish, JointFinishDriver::Abandoned)
            })
        });
        let Some(undisclosed) = undisclosed else {
            Self::arm_winding_stop_disclosed(&mut self.retiring);
            return;
        };
        if !undisclosed.lane.as_ref().is_some_and(|lane| lane.is_live()) {
            self.coordinator.note_scope_gap(
                "winding lane key-operation counts unknown".to_string(),
                "stop held the winding lane with its counts unreadable; \
                 its key-operation counts after the promotion began are unknown"
                    .to_string(),
            );
            Self::arm_winding_stop_disclosed(&mut self.retiring);
            return;
        }
        let counts = {
            let retiring = self
                .retiring
                .as_ref()
                .expect("undisclosed winding checked above");
            let lane = retiring
                .winding
                .as_ref()
                .expect("undisclosed winding checked above")
                .lane
                .as_ref()
                .expect("undisclosed winding checked above");
            SemanticStopCounts::read(lane, &mut *self.coordinator)
        };
        let mut warn = WarnSink {
            display: &mut self.display,
        };
        {
            let winding = self
                .retiring
                .as_mut()
                .expect("undisclosed winding checked above")
                .winding
                .as_mut()
                .expect("undisclosed winding checked above");
            disclose_stop_counts_once(winding, &counts, &mut *self.coordinator, &mut warn);
        }
        Self::arm_winding_stop_disclosed(&mut self.retiring);
    }

    /// Bind the dashboard's promotion control to this run's capture
    /// (DR37 ordinary enable). Headless runs have no display and stay
    /// unbound; a bound display keeps its capture (a second enable
    /// never rebinds it). Returns whether the control is bound to
    /// `capture` afterwards.
    fn enable_run_promotion(&mut self, capture: crate::inventory_promotion::CaptureId) -> bool {
        self.display
            .as_mut()
            .is_some_and(|display| display.promotion_enable(capture))
    }

    /// Install the native completion minter (DR37 A→B). Run setup
    /// calls this once the native lane lands its source; until then
    /// the field stays `None` and retiring domains hold.
    fn set_completion_source(
        &mut self,
        source: Box<dyn crate::inventory_promotion::lifecycle::NativeCompletionSource>,
    ) {
        self.completion_source = Some(source);
    }

    /// Schedule one pre-view baseline acquisition (DR37 ordinary
    /// scheduling): while the display's candidate frame carries a
    /// cursor pair no batch names, acquire a single-target batch for
    /// that pair through the retained capture and stage it for the
    /// next draw, which commits it with that draw's revision. The
    /// service hook runs before the display tick, so a demand raised
    /// for a still-undrawn frame acquires ahead of its qualifying
    /// draw. At most one attempt per frame/caller (failures stay
    /// quiet until a new frame or cursor); scan-only runs (no
    /// capture), cgroup scope (the resolver refuses it) and missing
    /// custody skip without native work. Called from the
    /// capture-service hook, sharing the service tick.
    fn schedule_promotion_baseline(
        &mut self,
        capture: Option<&mut dyn crate::inventory_capture::CaptureLane<crate::process::PidPin>>,
    ) {
        let Some(display) = self.display.as_ref() else {
            return;
        };
        let Some((capture_id, frame, pair)) = display.baseline_demand() else {
            return;
        };
        // Selected preparation supports PID and system parents only;
        // the resolver fails cgroup closed, so no acquisition starts
        // for it.
        if matches!(self.scope, InventoryRunScope::Cgroup) {
            return;
        }
        let Some(lane) = capture else {
            return;
        };
        let caller = crate::discovery::caller_registry::CallerId(pair.caller());
        let Ok((original, incarnation)) = self.coordinator.prepare_selected_caller_custody(caller)
        else {
            return;
        };
        let Ok(window) =
            crate::attach::capture::ReadWindow::new(1, Instant::now() + PROMOTION_BASELINE_WINDOW)
        else {
            return;
        };
        let target = crate::attach::selected_detailed::baseline::BaselineTarget {
            caller,
            incarnation,
            original,
        };
        let registry = self.coordinator.registry();
        let mut reserve = |bytes| registry.reserve_semantic_storage(bytes);
        match lane.query_promotion_baselines(
            capture_id,
            frame,
            std::slice::from_ref(&target),
            window,
            &mut reserve,
        ) {
            Ok(batch) => {
                if let Some(display) = self.display.as_mut() {
                    display.note_baseline_batch(std::sync::Arc::new(batch), pair);
                }
            }
            Err(_) => {
                if let Some(display) = self.display.as_mut() {
                    display.note_baseline_failed(pair);
                }
            }
        }
    }

    /// Resolve one taken request into its preparation bundle plus the
    /// native CAS source (DR37 resolver): the qualified parent scope,
    /// a live run window, the clicked provider's attested subset
    /// minted twice over the same retained sources, the caller's
    /// original custody, and the pre-view baseline the viewed frame
    /// carries. Every missing input fails closed on its own axis;
    /// permission is checked before custody and baseline, so an
    /// uncovered pair reports no manifest permission even when the
    /// caller or view would also refuse.
    fn resolve_preparation_job(
        &mut self,
        request: &crate::inventory_promotion::PromotionRequest,
    ) -> Result<
        (
            crate::inventory_promotion::lifecycle::PreparationBundle,
            Box<dyn crate::inventory_promotion::lifecycle::NativeActivationSource>,
        ),
        crate::inventory_promotion::PromotionRefusal,
    > {
        use crate::inventory_promotion::PromotionRefusal;
        // Selected preparation supports PID and system parents; cgroup
        // migration is unqualified (the native owner refuses it), so
        // resolve fails closed before loading any BPF.
        let parent = match self.scope {
            InventoryRunScope::Pid(pid) => Scope::Pid(pid),
            InventoryRunScope::System => Scope::System,
            InventoryRunScope::Cgroup => return Err(PromotionRefusal::ScopeUnsupported),
        };
        // A dead run takes no new preparation: starting BPF loads for
        // it wastes seconds and can never install.
        if self
            .deadline
            .is_some_and(|deadline| Instant::now() >= deadline)
        {
            return Err(PromotionRefusal::ScopeEnded);
        }
        // One preparation quantum: a single original bounds the rows;
        // the deadline bounds the bootstrap queries plus one joined
        // fallback settle. BPF loads run outside this window, like the
        // manifest lane; run-end cancel still wins via the service.
        let window = crate::attach::capture::ReadWindow::new(
            1,
            Instant::now() + SELECTED_PREPARATION_WINDOW,
        )
        .map_err(|_| PromotionRefusal::ScopeEnded)?;
        // Manifest permission for the clicked provider, minted twice:
        // the attach seal consumes one mint, the other stays the
        // conversion envelope.
        let attach = self
            .coordinator
            .prepare_selected_subset(request.provider())?;
        let convert = self
            .coordinator
            .prepare_selected_subset(request.provider())?;
        let (original, incarnation) = self
            .coordinator
            .prepare_selected_caller_custody(request.caller())?;
        // Pre-view agreement: the request's immutable viewed frame
        // must carry the genuine acquisition batch for this original.
        let baseline = request
            .viewed()
            .baseline()
            .ok_or(PromotionRefusal::StaleView)
            .and_then(|batch| {
                batch
                    .for_request(request, &original, incarnation)
                    .map_err(|_| PromotionRefusal::StaleView)
            })?;
        Ok((
            crate::inventory_promotion::lifecycle::PreparationBundle {
                attach,
                convert,
                baseline,
                original,
                parent,
                backend: self.attach_backend,
                window,
            },
            Box::new(crate::attach::selected_detailed::NativeActivationMinter::new()),
        ))
    }
}

impl Drop for ClassicDriver<'_> {
    /// Teardown retention: a held install handoff reclaims into the
    /// service for genuine disposal, and the service's own drop
    /// retains it for process lifetime. A handoff the service will
    /// not take back (unreachable: install implies outstanding)
    /// retains its lane directly rather than stranding it. A
    /// promotion lane still winding down is held for exit the same
    /// way: no ticks follow the stop, so the detach would otherwise
    /// drop unjoined mid-cleanup; the stop path already recorded its
    /// gap and stop counts before the final commit.
    fn drop(&mut self) {
        if let Some(retiring) = self.retiring.as_mut()
            && let Some(winding) = retiring.winding.as_mut()
            && let Some(lane) = winding.lane.take()
        {
            ExitRetention::hold(lane);
        }
        let Some(pending) = self.pending_install.take() else {
            return;
        };
        if let Err(pending) = self.lifecycle.reclaim_install(
            pending,
            Some(crate::inventory_promotion::PromotionEnd::RunStopped),
        ) {
            let (_proof, lane, capacity) = pending.into_parts();
            drop(capacity);
            crate::inventory_promotion::lifecycle::SelectedLifecycleService::retain_lane_for_process_exit(
                lane,
            );
        }
    }
}

fn commit_semantic_finish(
    coordinator: &mut InventoryCoordinator<OsProcessSource>,
    lane: &mut crate::inventory_semantics::AttestedSemanticLane,
) -> Result<()> {
    #[cfg(test)]
    if FAIL_TERMINAL_PUBLICATION.with(|fail| fail.replace(false)) {
        anyhow::bail!("injected terminal publication refusal");
    }
    coordinator
        .commit_batch_with_semantics(false, Some(lane))
        .map(|_| ())
}

/// The stderr line a sealed semantic lane starts with: from now on,
/// mechanisms and API results are recorded. Startup only: the seal runs
/// before the display opens, so the classic sink is correct on both
/// paths. A promotion seals its new lane silently (its install and
/// end already disclose through gaps); only the run's first seal
/// readies users and scripts. v0.5.0 seals no key-operation lane
/// (OD33/R-50), so the line says so plainly.
const SEMANTIC_SEAL_LINE: &str = "p11scope: semantic lane ready; mechanisms and API results are recorded from now on (key operations: planned for 0.5.1)";

/// Note the lane seal once, through the classic stderr sink.
fn note_semantic_lane_sealed() {
    inventory_diagnostic(SEMANTIC_SEAL_LINE);
    #[cfg(test)]
    record_sealed_for_test(SEMANTIC_SEAL_LINE);
}

/// Optional lane startup: no manifests means no Detailed Session, maps,
/// links or cursor. A refused live startup keeps the shell lane for
/// its honest `unavailable` summary; broad Inventory runs either way.
fn start_semantic_lane(
    coordinator: &mut InventoryCoordinator<OsProcessSource>,
    scope: &Scope,
    backend: crate::attach::BackendSelection,
) -> Option<crate::inventory_semantics::AttestedSemanticLane> {
    // The bytes rule before any semantic-lane BPF work: a stale or
    // mismatched embedded object degrades here with the plain mismatch
    // message (never the bare attachment code); broad inventory continues.
    if let Err(error) = crate::attach::checked_embedded_flavor() {
        let message = format!("{error:#}");
        coordinator.note_scope_gap(
            "semantic lane unavailable".into(),
            format!("{message}; broad inventory continues without instance semantics"),
        );
        inventory_diagnostic(&format!(
            "p11scope: {message}; broad inventory continues without instance semantics"
        ));
        return fallback_shell(coordinator, scope, backend);
    }
    let preparation = seal_prepare_subset(coordinator);
    for refusal in &preparation.refusals {
        coordinator.note_scope_gap(
            "semantic subset refused".into(),
            format!("{refusal}; broad inventory continues without instance semantics"),
        );
    }
    let attach_subset = preparation.subset?;
    // The second mint over the same retained sources stays the lane's
    // conversion envelope; it fails only when the retained inputs
    // moved under the startup.
    let second = seal_prepare_subset(coordinator);
    let convert_subset = match second.subset {
        Some(subset) => subset,
        None => {
            for refusal in &second.refusals {
                coordinator.note_scope_gap(
                    "semantic subset refused".into(),
                    format!("{refusal}; broad inventory continues without instance semantics"),
                );
            }
            return None;
        }
    };
    match seal_start_live(attach_subset, convert_subset, scope, backend) {
        Ok(lane) => {
            note_semantic_lane_sealed();
            Some(lane)
        }
        Err(refusal) => {
            coordinator.note_scope_gap(
                "semantic lane unavailable".into(),
                format!("{refusal}; broad inventory continues without instance semantics"),
            );
            fallback_shell(coordinator, scope, backend)
        }
    }
}

/// The shell lane a refused live startup keeps for its honest
/// `unavailable` summary; `None` when no subset mints.
fn fallback_shell(
    coordinator: &mut InventoryCoordinator<OsProcessSource>,
    scope: &Scope,
    backend: crate::attach::BackendSelection,
) -> Option<crate::inventory_semantics::AttestedSemanticLane> {
    use crate::inventory_semantics::AttestedSemanticLane;
    seal_prepare_subset(coordinator)
        .subset
        .and_then(|subset| AttestedSemanticLane::start(subset, scope, backend).ok())
        .map(|mut shell| {
            shell.mark_startup_failed();
            shell
        })
}

/// The subset-mint boundary of the lane startup: the coordinator's
/// real mint in production; tests queue scripted preparations
/// through `seal_startup_test::with` instead of attesting manifests.
fn seal_prepare_subset(
    coordinator: &mut InventoryCoordinator<OsProcessSource>,
) -> crate::discovery::engine::inventory_coordinator::semantics::SubsetPreparation {
    #[cfg(test)]
    if let Some(prepared) = seal_startup_test::take_prepared() {
        return prepared;
    }
    coordinator.prepare_semantic_subset()
}

/// The seal boundary of the lane startup (BPF): the live lane start
/// in production; tests script the verdict through
/// `seal_startup_test::with` instead of loading BPF.
fn seal_start_live(
    attach_subset: crate::discovery::engine::inventory_coordinator::semantics::AttestedSubset,
    convert_subset: crate::discovery::engine::inventory_coordinator::semantics::AttestedSubset,
    scope: &Scope,
    backend: crate::attach::BackendSelection,
) -> Result<
    crate::inventory_semantics::AttestedSemanticLane,
    crate::inventory_semantics::SemanticRefusal,
> {
    #[cfg(test)]
    if let Some(verdict) = seal_startup_test::take_start_verdict() {
        return verdict;
    }
    crate::inventory_semantics::AttestedSemanticLane::start_live(
        attach_subset,
        convert_subset,
        scope,
        backend,
    )
}

#[cfg(test)]
mod seal_startup_test {
    //! Scripted lane startups: queued subset preparations plus one
    //! live-start verdict, consumed in order by the startup above, so
    //! the seal twins drive the real match arms without manifests or
    //! BPF. The `with` guard clears leftovers, so a twin that returns
    //! early cannot leak scripts into the next test on its thread.
    use super::*;
    use std::collections::VecDeque;
    type Preparation =
        crate::discovery::engine::inventory_coordinator::semantics::SubsetPreparation;
    type StartVerdict = Result<
        crate::inventory_semantics::AttestedSemanticLane,
        crate::inventory_semantics::SemanticRefusal,
    >;
    thread_local! {
        static PREPARE: std::cell::RefCell<VecDeque<Preparation>> =
            const { std::cell::RefCell::new(VecDeque::new()) };
        static START: std::cell::RefCell<Option<StartVerdict>> =
            const { std::cell::RefCell::new(None) };
    }
    pub(super) fn take_prepared() -> Option<Preparation> {
        PREPARE.with(|queued| queued.borrow_mut().pop_front())
    }
    pub(super) fn take_start_verdict() -> Option<StartVerdict> {
        START.with(|verdict| verdict.borrow_mut().take())
    }
    pub(super) fn with<R>(
        prepares: Vec<Preparation>,
        start: Option<StartVerdict>,
        run: impl FnOnce() -> R,
    ) -> R {
        struct Restore;
        impl Drop for Restore {
            fn drop(&mut self) {
                PREPARE.with(|queued| queued.borrow_mut().clear());
                START.with(|verdict| verdict.borrow_mut().take());
            }
        }
        PREPARE.with(|queued| queued.borrow_mut().extend(prepares));
        START.with(|verdict| *verdict.borrow_mut() = start);
        let _restore = Restore;
        run()
    }
}

/// Test-facing selection control: physical retained provider identity, never
/// the attachment FD pathname. Production uses the bounded rotating selector.
#[cfg(test)]
pub(crate) fn refresh_target_for_candidate(
    coordinator: &InventoryCoordinator<OsProcessSource>,
    lane: &crate::inventory_semantics::AttestedSemanticLane,
    caller: CallerId,
) -> Option<(u32, ModuleKey)> {
    for (object, slots) in lane.subset().required() {
        let slot = *slots.first()?;
        if let Some(module) = coordinator.registry().modules().find(|module| {
            lane.subset().proves_provider_module(*object, &module.key)
                && coordinator
                    .registry()
                    .edge(caller, module.id)
                    .is_some_and(|edge| edge.mapping == MappingState::Mapped)
        }) {
            return Some((slot, module.key.clone()));
        }
    }
    None
}

/// Bootstrap through the Detailed owner receipt, independently of the native
/// Inventory identity facade. Cgroup uses this same preparation inside its
/// original final-sample transaction, in commit_batch_inner.
fn bind_semantic_callers(
    coordinator: &mut InventoryCoordinator<OsProcessSource>,
    lane: &mut crate::inventory_semantics::AttestedSemanticLane,
) {
    bind_semantic_callers_inner(coordinator, lane, None);
}

fn bind_semantic_callers_inner(
    coordinator: &mut InventoryCoordinator<OsProcessSource>,
    lane: &mut crate::inventory_semantics::AttestedSemanticLane,
    collected: Option<(
        &mut crate::semantics_objects::journal::joint_driver::RawJointQuantum,
        &crate::attach::SessionDrainProducers,
    )>,
) {
    crate::inventory_semantics::bind_semantic_callers_inner(coordinator, lane, collected)
}

/// Refresh one pass's precomputed candidates and bind every accepted
/// image through the coordinator proof. Each candidate duplicates its
/// live pin fresh, but the stored binding shares the EFFECTIVE custody
/// Arc the refresh reports: after an accepted-refresh/failed-bind pass,
/// H0 retains the first pass's Arc and the retry adopts it, so binding
/// the fresh duplicate would strand the caller behind H0's `ptr_eq`
/// gate. The refresh seam substitutes only H0's I/O in tests; all
/// decisions stay in this shared production loop.
#[cfg(test)]
pub(crate) fn bind_semantic_candidates(
    coordinator: &mut InventoryCoordinator<OsProcessSource>,
    domain: crate::attach::capture::NativeDomainId,
    identity: &mut dyn NativeIdentity<PidPin>,
    targets: &[(CallerId, u32, u32, ModuleKey)],
    mut refresh: impl FnMut(
        std::sync::Arc<PidPin>,
        u32,
    ) -> Result<
        (Vec<ImageIdentity>, std::sync::Arc<PidPin>),
        crate::inventory_semantics::SemanticRefusal,
    >,
) {
    for (caller, pid, slot, module) in targets {
        let Some(pin) = coordinator
            .adapter()
            .live_pin(*pid)
            .and_then(|(_, pin)| pin.try_clone().ok())
            .map(std::sync::Arc::new)
        else {
            continue;
        };
        // One custody Arc through refresh and binding: H0 retains the
        // effective Arc, so the stored binding must share it (H0's
        // `ptr_eq` gates refuse any re-duplication).
        let (images, effective) = match refresh(pin, *slot) {
            Ok(report) => report,
            Err(_) => continue,
        };
        for image in images {
            // The image hint is a claim only; the bind proof
            // re-verifies everything.
            let _ = coordinator.bind_semantic_caller_with_pin(
                *caller,
                module.clone(),
                domain,
                image,
                identity,
                effective.clone(),
            );
        }
    }
}

/// The retained consumer (§6.4): a finished outcome keeps
/// today's reads; a retained run drains beside its driver, and a
/// malformed mixture holds its owners and reports.
impl ClassicDriver<'_> {
    fn consume_outcome(
        &mut self,
        outcome: ClassicOutcome<FacadeLane>,
        clock: &LoopClock,
        publish: &mut dyn FnMut(&mut Self, Publish<'_>) -> Result<()>,
    ) -> (
        Option<Stopped<FacadeLane>>,
        Option<anyhow::Error>,
        Option<ZeroPassStop>,
    ) {
        match outcome.into_completion() {
            Ok(ClassicCompletion::Finalized {
                stopped,
                error,
                zero_pass,
            }) => {
                self.complete_published_joint_lane();
                (stopped, self.fold_retained_joint_error(error), zero_pass)
            }
            Ok(ClassicCompletion::Retained { run, error }) => {
                self.consume_retained_run(run, error, clock, publish)
            }
            Err(mixed) => {
                // Defensive: neither loop mixes retained owners with
                // stopped evidence. Hold the run for exit and report.
                if let Some(run) = mixed.retained {
                    ExitRetention::hold(run);
                }
                let error = mixed.error.or_else(|| {
                    Some(anyhow::anyhow!(
                        "retained completion mixed stopped and unfinished owners"
                    ))
                });
                (mixed.stopped, error, mixed.zero_pass)
            }
        }
    }

    /// Fold the Joint first error into a retained outcome's error
    /// channel: the retained error (if any) predates the I2 verdict,
    /// so it stays first. Synchronous outcomes keep today's reads.
    fn fold_retained_joint_error(&mut self, error: Option<anyhow::Error>) -> Option<anyhow::Error> {
        if self.suspended {
            error.or_else(|| {
                self.joint_first_error
                    .take()
                    .map(|first| anyhow::anyhow!(first))
            })
        } else {
            error
        }
    }

    /// Release a Published Joint lane at the terminal consume: no
    /// further hook will reap it. Steps the wound-down on the 10 ms
    /// cadence while the detach still runs; a quick join completes
    /// with no hold. The wait mirrors the legacy owned-detach wait:
    /// it runs until the detach completes, interruptible only by the
    /// second operator signal (each waiting step escalates like the
    /// lane stop). The run deadline ends the capture window, not the
    /// stop, so a normal timed stop gains no hold past it. Polling
    /// and unbegun lanes stay seated for their hooks.
    fn complete_published_joint_lane(&mut self) {
        while matches!(self.joint_finish, JointFinishDriver::Published) && self.semantic.is_some() {
            let started = Instant::now();
            self.step_retained_joint_finish();
            if matches!(self.joint_finish, JointFinishDriver::Published) && self.semantic.is_some()
            {
                if self.second_signal.is_some_and(|signal| signal()) {
                    self.escalate_joint_finish("second stop during joint finish");
                    return;
                }
                let elapsed = started.elapsed();
                if elapsed < Duration::from_millis(10) {
                    std::thread::sleep(Duration::from_millis(10) - elapsed);
                }
            }
        }
    }

    /// Hold a Joint commit stuck Pending past the retained wall
    /// bound: snapshot Partial, hold the lane for exit (dropping the
    /// hold error like a conversion, so the run exits 0), clear the
    /// pending flag, and name the hold in its own gap plus a stderr
    /// line. The pump's next Poll then legacy-commits past the held
    /// lane and the report writes.
    fn hold_stuck_retained_joint_publication(&mut self, stalled: Duration) {
        self.snapshot_seated_summary();
        if let Some(summary) = self.seated_summary.as_mut() {
            summary.status = crate::inventory_semantics::SemanticCaptureStatus::Partial;
        }
        let mut warn = WarnSink {
            display: &mut self.display,
        };
        if let Some(lane) = self.semantic.take() {
            Self::hold_joint_lane_for_exit(
                lane,
                &mut *self.coordinator,
                "retained joint publication timed out",
                "joint finish abandoned for exit",
                &mut warn,
                None,
            );
        }
        self.joint_commit_pending = false;
        self.coordinator.note_scope_gap(
            "retained joint publication timed out".to_string(),
            format!(
                "the joint publication was still pending {}s after the deadline; the semantic lane was held and the report written without its latest pass",
                stalled.as_secs(),
            ),
        );
        self.warn(&format!(
            "p11scope: the joint publication was still pending {}s after the deadline; the semantic lane is held so the report can be written",
            stalled.as_secs(),
        ));
    }

    /// Drain a retained run beside its driver: every 10 ms poll with
    /// a 1024-action budget until the run finalizes. An abandoned
    /// Joint finish exits through the folded first error; the lane
    /// stays held, never joined or minted.
    fn consume_retained_run(
        &mut self,
        run: RetainedClassicRun<FacadeLane>,
        error: Option<anyhow::Error>,
        clock: &LoopClock,
        publish: &mut dyn FnMut(&mut Self, Publish<'_>) -> Result<()>,
    ) -> (
        Option<Stopped<FacadeLane>>,
        Option<anyhow::Error>,
        Option<ZeroPassStop>,
    ) {
        self.consume_retained_run_with_bound(
            run,
            error,
            clock,
            publish,
            RETAINED_JOINT_PUBLICATION_TIMEOUT,
        )
    }

    /// The drain above with an explicit wall bound on a continuously
    /// pending Joint commit (tests pose a short one; production
    /// passes the retained publication timeout). Past the bound the
    /// drain holds the stuck lane — named gap, Partial summary, no
    /// run error — so the report still writes instead of hanging.
    fn consume_retained_run_with_bound(
        &mut self,
        run: RetainedClassicRun<FacadeLane>,
        error: Option<anyhow::Error>,
        clock: &LoopClock,
        publish: &mut dyn FnMut(&mut Self, Publish<'_>) -> Result<()>,
        bound: Duration,
    ) -> (
        Option<Stopped<FacadeLane>>,
        Option<anyhow::Error>,
        Option<ZeroPassStop>,
    ) {
        self.suspended = true;
        // Name a deadline-retained pending publication: a slow drain
        // is visible instead of a silent hang.
        if run.stop_cause == Some(crate::inventory_capture::ZeroPassCause::Deadline)
            && self.publication_pending()
        {
            self.warn(
                "p11scope: the deadline arrived while a joint publication was still pending; draining the retained run to write the report",
            );
        }
        let mut outcome = ClassicOutcome {
            stopped: None,
            error,
            zero_pass: None,
            retained: Some(run),
        };
        // Start of the current continuously pending Joint commit, if
        // any; any Published, refusal or conversion resets it.
        let mut pending_since: Option<Instant> = None;
        loop {
            match outcome.into_completion() {
                Ok(ClassicCompletion::Finalized {
                    stopped,
                    error,
                    zero_pass,
                }) => {
                    self.complete_published_joint_lane();
                    return (stopped, self.fold_retained_joint_error(error), zero_pass);
                }
                Ok(ClassicCompletion::Retained { run, error }) => {
                    if self.joint_commit_pending && self.semantic.is_some() {
                        let now = Instant::now();
                        let since = *pending_since.get_or_insert(now);
                        if now.duration_since(since) >= bound {
                            self.hold_stuck_retained_joint_publication(now.duration_since(since));
                            pending_since = None;
                        }
                    } else {
                        pending_since = None;
                    }
                    let started = Instant::now();
                    let mut budget = RetainedWorkBudget {
                        remaining_actions: 1024,
                        deadline: started + Duration::from_millis(10),
                    };
                    outcome = poll_retained_classic(self, run, error, clock, &mut budget, publish);
                    // A finalizing poll calls no driver hooks, so the
                    // consumer keeps the dashboard live once per cycle.
                    if let Some(display) = self.display.as_mut() {
                        display.tick();
                    }
                    // Pace the wait only: a terminal poll returns now.
                    if outcome.retained.is_some() {
                        let elapsed = started.elapsed();
                        if elapsed < Duration::from_millis(10) {
                            std::thread::sleep(Duration::from_millis(10) - elapsed);
                        }
                    }
                }
                Err(mixed) => {
                    if let Some(run) = mixed.retained {
                        ExitRetention::hold(run);
                    }
                    let error = mixed.error.or_else(|| {
                        Some(anyhow::anyhow!(
                            "retained completion mixed stopped and unfinished owners"
                        ))
                    });
                    return (mixed.stopped, error, mixed.zero_pass);
                }
            }
        }
    }
}

impl PassDriver<PidPin> for ClassicDriver<'_> {
    type Host = InventoryCoordinator<OsProcessSource>;

    fn host(&mut self) -> &mut Self::Host {
        self.coordinator
    }

    /// Whether a publication is still owed: a begun-but-unpublished
    /// Joint commit, or a Joint finish mid-poll, beside a live lane.
    /// A held lane owes nothing further.
    fn publication_pending(&self) -> bool {
        self.semantic.is_some()
            && (self.joint_commit_pending
                || matches!(self.joint_finish, JointFinishDriver::Polling))
    }

    /// The suspension gate (§6.2): latch only, never terminal I/O.
    fn on_publication_suspended(&mut self) {
        self.suspended = true;
    }

    /// Spend one retained hook on a blocked publication (§6.1): a
    /// Joint lane steps its §8.3 driver once, then the block holds
    /// while anything stays pending. Blocks the loop's table owns —
    /// collected, scoped completion, native — resolve with no step;
    /// the N1 wait lives in the table, not here.
    fn dispose_retained<L>(
        &mut self,
        block: RetainedBlock,
        _run: &mut RetainedClassicRun<L>,
        _budget: &mut RetainedWorkBudget,
    ) -> Result<BlockDisposition> {
        if !matches!(block, RetainedBlock::Publication)
            || !self.semantic.as_ref().is_some_and(Self::is_joint_lane)
        {
            return Ok(BlockDisposition::Resolved);
        }
        self.step_retained_joint_finish();
        if self.publication_pending() {
            Ok(BlockDisposition::Pending)
        } else {
            Ok(BlockDisposition::Resolved)
        }
    }

    fn collector(&mut self) -> crate::inventory_capture::CollectJob {
        if let Some(cgroup) = &mut self.cgroup {
            let task = cgroup
                .continuation
                .take()
                .ok_or(CgroupJobFailure::Preparation)
                .and_then(|state| {
                    self.coordinator
                        .cgroup_collector_observed(
                            state,
                            cgroup.limits.clone(),
                            cgroup.control.clone(),
                            self.max_scan_pids,
                            cgroup.observer.clone(),
                        )
                        .map(|job| Box::new(job) as crate::inventory_capture::CgroupCollectJob)
                        .map_err(|_| CgroupJobFailure::Preparation)
                });
            return CollectJob::Cgroup {
                control: cgroup.control.clone(),
                task,
            };
        }
        match self.inventory_scope {
            Some(scope) => {
                let job = match (&scope, self.identity.clone()) {
                    // D3d: `--system` collections share the capture-owned
                    // identity state; `--pid` stays on the plain path.
                    (InventoryScope::System, Some(shared)) => {
                        Box::new(self.coordinator.collector_with_identity(
                            scope,
                            self.max_scan_pids,
                            shared,
                            self.semantic.as_ref().is_some_and(|lane| lane.is_live()),
                        )) as crate::inventory_capture::LegacyCollectJob
                    }
                    _ => Box::new(self.coordinator.collector(scope, self.max_scan_pids))
                        as crate::inventory_capture::LegacyCollectJob,
                };
                CollectJob::Legacy(job)
            }
            None => CollectJob::Cgroup {
                control: crate::scope::inventory_cgroup::CollectionControl::new(self.deadline),
                task: Err(CgroupJobFailure::Preparation),
            },
        }
    }

    fn collection_control(&self) -> Option<crate::scope::inventory_cgroup::CollectionControl> {
        self.cgroup.as_ref().map(|cgroup| cgroup.control.clone())
    }

    fn apply(
        &mut self,
        collected: CollectedPass,
        identity: &mut dyn NativeIdentity<PidPin>,
        now_ns: u64,
    ) -> Result<PassReport> {
        let collected = match collected {
            CollectedPass::Cgroup(Ok(collection)) => {
                return self
                    .coordinator
                    .apply_cgroup_collection(*collection, now_ns);
            }
            CollectedPass::Cgroup(Err(failure)) => {
                self.coordinator
                    .note_scope_gap("cgroup collection failed".into(), failure.reason().into());
                anyhow::bail!("{}", failure.reason());
            }
            CollectedPass::Legacy(catalog) => catalog.map(|catalog| *catalog),
        };
        let scope = match self.scope {
            InventoryRunScope::Pid(pid) => InspectScope::Pid(pid),
            InventoryRunScope::System => InspectScope::System,
            InventoryRunScope::Cgroup => {
                anyhow::bail!("cgroup requires a scoped collection result")
            }
        };
        let (report, warning) = apply_one_pass(
            self.coordinator,
            collected,
            scope,
            &mut self.guard,
            self.deadline,
            identity,
            now_ns,
        )?;
        if let Some(warning) = warning {
            self.warn(&warning);
        }
        if let Some(lane) = self.semantic.as_mut() {
            bind_semantic_callers(self.coordinator, lane);
        }
        Ok(report)
    }

    fn commit(&mut self, engine_changed: bool) -> Result<()> {
        #[cfg(test)]
        {
            self.commit_calls += 1;
            if let Some(text) = take_classic_commit_fault_for_test() {
                return Err(anyhow::anyhow!(text));
            }
        }
        let receipt = match self.semantic.as_mut() {
            Some(lane) => self
                .coordinator
                .commit_batch_with_semantics(engine_changed, Some(lane)),
            None => self.coordinator.commit_batch(engine_changed),
        };
        receipt.map(|_| {
            // The staged quantum published: the next tick may stage again.
            self.semantic_staged = false;
            if let Some(lane) = self.semantic.as_mut() {
                lane.note_semantic_published();
            }
        })
    }

    /// T18 (§9 item 3): a Joint lane publishes through its machine
    /// (begin once per publication, then poll); a legacy lane keeps
    /// today's sync commit plus Published.
    fn poll_commit(&mut self, engine_changed: bool) -> Result<PassCommitProgress> {
        if self
            .semantic
            .as_ref()
            .is_some_and(|lane| lane.has_joint_machine())
        {
            return self.poll_joint_commit_path(engine_changed);
        }
        if let Err(error) = self.commit(engine_changed) {
            // Terminal-commit wedge (soak shape): the lane is already
            // held but the coordinator still holds its unfinished
            // Joint publication, so the plain commit refuses. Name the
            // semantic cause — never the internal message. A live
            // lane keeps the raw failure: it is not stopped.
            if self.semantic.is_none()
                && Self::commit_hit_unfinished_joint_publication(&error, &*self.coordinator)
            {
                self.warn(
                    "p11scope: the semantic lane is held but its unfinished joint publication still blocks the broad commit; the run cannot continue past it",
                );
                return Err(anyhow::anyhow!(
                    "semantic lane held; the unfinished joint publication still blocks the broad commit and this run cannot continue past it"
                ));
            }
            return Err(error);
        }
        Ok(PassCommitProgress::Published)
    }

    fn finish_pass(&mut self, report: &mut PassReport) -> Result<()> {
        if let Some(cgroup) = &mut self.cgroup {
            let completion = self.coordinator.take_cgroup_completion().ok_or_else(|| {
                anyhow::anyhow!("cgroup publication did not supply its owned completion")
            })?;
            cgroup.continuation = Some(completion.state);
            report.scan_callers = completion.scan_callers;
            report.events.extend(completion.events);
            if completion.outcome
                != crate::inspect_system::inventory_cgroup::ScopedCollectionOutcome::Complete
            {
                self.warn(&format!(
                    "p11scope: cgroup collection incomplete: {}",
                    completion.outcome.reason()
                ));
            }
        }
        Ok(())
    }

    fn on_tick(&mut self) {
        if let Some(display) = self.display.as_mut() {
            display.tick();
        }
        // While suspended the hook services only the display above
        // and one retained step of the Joint finish (§6.3): no
        // promotion, no lane ticks, no new work.
        if self.suspended {
            self.step_retained_joint_finish();
            return;
        }
        // Item 9: while the final Joint finish polls or reaps, the
        // hook runs only the display tick above and one driver
        // step. No promotion conjunct: the promotion flag arms only
        // on a fresh wind-down begin (which leaves the driver
        // finish NotBegun) and disarms when the winding retires,
        // before any new lane seats — so a begun driver finish
        // never coincides with an armed flag (R1.4 minor ruling:
        // the old `!promotion_finish()` conjunct was dead by
        // design; mutant H is inapplicable).
        if matches!(
            self.joint_finish,
            JointFinishDriver::Polling | JointFinishDriver::Published
        ) {
            #[cfg(test)]
            {
                self.joint_step_calls += 1;
            }
            self.snapshot_seated_summary();
            let mut warn = WarnSink {
                display: &mut self.display,
            };
            let outcome = Self::step_begun_joint_finish_with_warn(
                &mut self.semantic,
                &mut self.joint_finish,
                &mut *self.coordinator,
                &mut self.joint_first_error,
                &mut warn,
                None,
            );
            if matches!(outcome, JointStepOutcome::WoundDown) {
                self.complete_final_joint_lane();
            }
            return;
        }
        self.poll_promotion();
        // T18 (§9 item 4): an initialized Joint lane services its
        // machine every hook instead of the staged commit and
        // `lane.tick` below. The staged flag never suppresses this
        // service: it gates only fresh legacy collection.
        if self
            .semantic
            .as_ref()
            .is_some_and(|lane| lane.has_joint_machine())
        {
            let mut budget = crate::inventory_semantics::JointWorkBudget {
                remaining_actions: 1024,
                deadline: Instant::now() + Duration::from_millis(10),
            };
            let (coordinator, semantic) = (&mut *self.coordinator, &mut self.semantic);
            if let Some(lane) = semantic.as_mut() {
                // The machine owns its latch and retries; a refused
                // hook simply services again on the next tick. The
                // first refusal is kept instead of dropped: it names
                // the lane's stop if the lane later holds with no
                // latched reason of its own.
                if let Err(reason) = lane.service_joint(
                    coordinator,
                    crate::inventory_semantics::JointServiceMode::Running,
                    &mut budget,
                ) {
                    self.joint_tick_refusal.get_or_insert(reason);
                }
            }
            return;
        }
        // Bound the wait for staged evidence even when collection runs
        // long. Failed commits retry at the next staleness deadline
        // instead of gap-spamming.
        let stale = self.semantic_staged
            && self
                .semantic
                .as_ref()
                .and_then(|lane| lane.staged_semantic_age())
                .is_some_and(|age| age >= STAGED_SEMANTIC_MAX_AGE);
        if stale && let Err(error) = self.commit(false) {
            self.coordinator
                .note_scope_gap("semantic staged commit failed".into(), format!("{error:#}"));
            if let Some(lane) = self.semantic.as_mut() {
                lane.note_semantic_staged();
            }
        }
        // Regular and collection-time lane ticks share this hook: the
        // loop calls it between passes and while the pass's collection
        // runs. At most one quantum stages ahead of the next commit.
        if self.semantic_staged {
            return;
        }
        let Some(lane) = self.semantic.as_mut() else {
            return;
        };
        if !lane.is_live() || lane.is_finished() {
            return;
        }
        let pins = self.coordinator.semantic_bindings_mut().bindings_for_tick();
        // The borrow ends with the tick: the batch owns its outcomes.
        let staged = match lane.tick(pins) {
            Ok(batch) => {
                // Original receipt lifetimes include time already spent
                // in the refresh stash. Publish during this tick: no
                // later service interval can guarantee timely validation.
                let publish_now = batch.has_current_receipts();
                self.coordinator.stage_semantic_batch(batch);
                lane.note_semantic_staged();
                if publish_now {
                    match self.commit(false) {
                        Ok(()) => false,
                        Err(error) => {
                            self.coordinator.note_scope_gap(
                                "semantic staged commit failed".into(),
                                format!("{error:#}"),
                            );
                            true
                        }
                    }
                } else {
                    true
                }
            }
            Err(_) => false,
        };
        self.semantic_staged = staged;
    }

    fn on_native_service(
        &mut self,
        mut capture: Option<&mut dyn crate::inventory_capture::CaptureLane<PidPin>>,
    ) {
        if self.suspended {
            return;
        }
        #[cfg(test)]
        {
            self.service_caller_metadata_calls += 1;
        }
        self.coordinator.service_caller_metadata(
            |original, window| match capture.as_mut() {
                Some(capture) => capture.observe_caller_image(original, window),
                None => Err(anyhow::anyhow!("caller image observation unavailable")),
            },
            now_ns(),
        );
        self.schedule_promotion_baseline(capture);
    }

    fn on_stop_requested(&mut self) {
        // A second stop escalates a begun-but-unfinished Joint finish
        // to the typed exit instead of re-running the stop path.
        if self.stop_requested && !matches!(self.joint_finish, JointFinishDriver::NotBegun) {
            self.escalate_joint_finish("second stop during joint finish");
            return;
        }
        let first_stop = !self.stop_requested;
        self.stop_requested = true;
        self.coordinator.stop_caller_metadata();
        if let Some(observer) = self
            .cgroup
            .as_ref()
            .and_then(|cgroup| cgroup.observer.as_ref())
        {
            observer.retiring();
        }
        // Gate Detailed immediately, before the (possibly slow) native
        // retirement: one producer's stop never certifies the other.
        if let Some(lane) = self.semantic.as_mut() {
            lane.request_semantic_stop();
        }
        if self.semantic.as_ref().is_some_and(Self::is_joint_lane) {
            // Joint lanes skip the blocking terminal sequence: the
            // finish driver owns them from here (§8.3). An in-flight
            // finish is kept, never re-begun.
            if matches!(self.joint_finish, JointFinishDriver::NotBegun) {
                self.begin_final_joint_finish();
            }
        } else {
            // Flush staged and stashed evidence NOW, before native
            // retirement runs: retirement's 5-10s budget exceeds the 2s
            // receipt window, so evidence must finalize here instead of
            // after it. The post-retirement hook below is then a no-op.
            self.run_semantic_terminal_sequence();
        }
        // DR37: cancel promotion work and reclaim held installs, then
        // poll the service once per hook without installing: teardown
        // never starts new lanes, and later ticks drain the service.
        self.lifecycle
            .note_cancel(crate::inventory_promotion::PromotionEnd::RunStopped);
        self.reclaim_pending_install(crate::inventory_promotion::PromotionEnd::RunStopped);
        let mut sink = std::io::sink();
        if let Some(event) = self.lifecycle.poll(&mut sink) {
            self.apply_lifecycle_event(event);
            self.reclaim_pending_install(crate::inventory_promotion::PromotionEnd::RunStopped);
        }
        // A stop during A's promotion finish keeps that finish and
        // discloses once that later process exits retire nothing (§8.6).
        if first_stop
            && self.retiring.as_ref().is_some_and(|retiring| {
                retiring.winding.as_ref().is_some_and(|winding| {
                    winding.joint
                        && winding.lane.is_some()
                        && !matches!(winding.finish, JointFinishDriver::Abandoned)
                })
            })
        {
            self.coordinator.note_scope_gap(
                "terminal stop during promotion".to_string(),
                "process exits after the last inventory scan were not retired at the stop"
                    .to_string(),
            );
        }
        // A winding of either kind never joins past the stop: hold
        // it at drop and disclose that once, before the final
        // commit, so the hold publishes.
        if first_stop {
            self.record_unjoined_winding_gap();
        }
    }

    fn on_lane_stopped(&mut self) {
        // A stop request already disclosed the unjoined winding; a
        // bare lane stop discloses it here instead, still once and
        // still before the final commit.
        if !self.stop_requested {
            self.record_unjoined_winding_gap();
        }
        if let Some(observer) = self
            .cgroup
            .as_ref()
            .and_then(|cgroup| cgroup.observer.as_ref())
        {
            observer.retired();
        }
        if self.semantic.as_ref().is_some_and(Self::is_joint_lane) {
            // The Joint finish begins once here when the stop request
            // did not begin it; a begun finish steps once (§8.3).
            // The second operator signal escalates a begun finish
            // instead of stepping it: the run is leaving, so the
            // finish is held for exit rather than reaped.
            if self.second_signal.is_some_and(|signal| signal())
                && !matches!(self.joint_finish, JointFinishDriver::NotBegun)
            {
                self.escalate_joint_finish("second stop during joint finish");
                return;
            }
            if matches!(self.joint_finish, JointFinishDriver::NotBegun) {
                self.begin_final_joint_finish();
                return;
            }
            if matches!(
                self.joint_finish,
                JointFinishDriver::Polling | JointFinishDriver::Published
            ) {
                let outcome = self.step_final_joint_finish_once();
                if matches!(outcome, JointStepOutcome::WoundDown) {
                    self.complete_final_joint_lane();
                }
            }
            return;
        }
        // Safety net for the same terminal sequence (a no-op once the
        // stop request above already ran it before native retirement).
        self.run_semantic_terminal_sequence();
    }

    /// Drive a begun (Polling) Joint finish to Published or Abandoned
    /// before the native retirement. The pre-retirement settle runs on
    /// the 10 ms cadence; a second operator signal escalates instead
    /// of stepping further: the run is leaving, so the finish is held
    /// for exit rather than reaped. An explicit wall backstop (twice
    /// the machine's Audited no-progress timeout plus a margin)
    /// escalates with its own cause even when the machine never
    /// latches, so a wedged finish always ends finitely without an
    /// operator. The machine's own trip fires first on a true stall;
    /// the settle only backstops finishes that keep progressing yet
    /// never complete. Unbegun, published, abandoned and legacy lanes
    /// are untouched: the post-retirement hook and the terminal
    /// consume own those.
    fn settle_joint_finish(&mut self) {
        self.settle_joint_finish_with_bound(
            crate::inventory_semantics::JOINT_FINISH_SETTLE_TIMEOUT,
        );
    }
}

impl ClassicDriver<'_> {
    /// The settle above with an explicit wall bound (tests pose a
    /// short one; production passes the settle backstop). At the
    /// bound the finish abandons with its own settle-bound gap,
    /// worded as the total time it measures (never "without
    /// progress", which only the machine's stall clock may claim),
    /// and escalates with its own cause. The Polling step returns
    /// only Stayed or Abandoned, so no wound-down arm belongs here:
    /// the terminal consume reaps a Published lane through its own
    /// hook.
    fn settle_joint_finish_with_bound(&mut self, bound: Duration) {
        let start = Instant::now();
        let mut polls = 0u64;
        while matches!(self.joint_finish, JointFinishDriver::Polling)
            && self.semantic.as_ref().is_some_and(Self::is_joint_lane)
        {
            if self.second_signal.is_some_and(|signal| signal()) {
                self.escalate_joint_finish("second stop during joint finish");
                return;
            }
            if start.elapsed() >= bound {
                self.coordinator.note_scope_gap(
                    "joint finish settle bound reached".to_string(),
                    format!(
                        "finish did not complete within {}s across {} settle polls; abandoning the finish for exit",
                        start.elapsed().as_secs(),
                        polls,
                    ),
                );
                self.escalate_joint_finish("joint finish settle bound reached");
                return;
            }
            let started = Instant::now();
            let outcome = self.step_final_joint_finish_once();
            polls += 1;
            if !matches!(outcome, JointStepOutcome::Stayed)
                || !matches!(self.joint_finish, JointFinishDriver::Polling)
            {
                return;
            }
            let elapsed = started.elapsed();
            if elapsed < Duration::from_millis(10) {
                std::thread::sleep(Duration::from_millis(10) - elapsed);
            }
        }
    }

    /// One begun-finish step (§8.3) with the seated summary snapshot:
    /// shared by the post-retirement hook and the pre-retirement
    /// settle above.
    fn step_final_joint_finish_once(&mut self) -> JointStepOutcome {
        #[cfg(test)]
        {
            self.joint_step_calls += 1;
        }
        self.snapshot_seated_summary();
        let mut warn = WarnSink {
            display: &mut self.display,
        };
        Self::step_begun_joint_finish_with_warn(
            &mut self.semantic,
            &mut self.joint_finish,
            &mut *self.coordinator,
            &mut self.joint_first_error,
            &mut warn,
            None,
        )
    }
}

/// Opens the native usage lane `mode` asks for. `native` that cannot start
/// is an error naming why; `auto` falls back to the scan lane with the gap
/// `native usage feed unavailable` (plan ruling D1). The interactive
/// dashboard services the lane through the same loop as the classic path
/// (C5.3). In a foreign PID namespace `--system` runs native (cookies bind
/// callers, never PID numbers) but no watch is ever claimed (ruling D1:
/// the run stays lossy).
fn open_native_lane(
    mode: CaptureMode,
    attach_backend: crate::attach::BackendSelection,
    scope: impl Into<Scope>,
    coordinator: &mut InventoryCoordinator<OsProcessSource>,
) -> Result<Option<NativeLane<FacadeLane>>> {
    open_native_lane_with(
        mode,
        attach_backend,
        scope,
        coordinator,
        |scope, budget, backend| {
            #[cfg(test)]
            if let Some(prepare) = native_preparation_test::take() {
                return prepare(scope, budget, backend);
            }
            FacadeLane::prepare(scope, budget, backend)
        },
    )
}

#[cfg(test)]
mod native_preparation_test {
    use super::*;
    type Prepare = Box<
        dyn FnOnce(
            crate::attach::capture::CaptureScope,
            InventoryBudget,
            crate::attach::BackendSelection,
        ) -> Result<FacadeLane>,
    >;
    thread_local! {
        static PREPARE: std::cell::RefCell<Option<Prepare>> = const { std::cell::RefCell::new(None) };
    }
    pub(super) fn take() -> Option<Prepare> {
        PREPARE.with(|slot| slot.borrow_mut().take())
    }
    pub(super) fn with<R>(
        prepare: impl FnOnce(
            crate::attach::capture::CaptureScope,
            InventoryBudget,
            crate::attach::BackendSelection,
        ) -> Result<FacadeLane>
        + 'static,
        run: impl FnOnce() -> R,
    ) -> R {
        struct Restore(Option<Prepare>);
        impl Drop for Restore {
            fn drop(&mut self) {
                PREPARE.with(|slot| *slot.borrow_mut() = self.0.take());
            }
        }
        let _restore = Restore(PREPARE.with(|slot| slot.borrow_mut().replace(Box::new(prepare))));
        run()
    }
}

/// The preparation boundary permits testing its actual arguments and startup
/// refusal without loading BPF. An active lane's later refusals stay native.
fn open_native_lane_with(
    mode: CaptureMode,
    attach_backend: crate::attach::BackendSelection,
    scope: impl Into<Scope>,
    coordinator: &mut InventoryCoordinator<OsProcessSource>,
    prepare: impl FnOnce(
        crate::attach::capture::CaptureScope,
        InventoryBudget,
        crate::attach::BackendSelection,
    ) -> Result<FacadeLane>,
) -> Result<Option<NativeLane<FacadeLane>>> {
    let unavailable =
        |coordinator: &mut InventoryCoordinator<OsProcessSource>, reason: String| match mode {
            CaptureMode::Native => Err(anyhow::anyhow!(
                "--capture native: the native usage lane cannot run: {reason}"
            )),
            _ => {
                inventory_diagnostic(&format!(
                    "p11scope: native usage feed unavailable, continuing with the scan lane: {}",
                    crate::render::escape_controls(&reason)
                ));
                coordinator.note_scope_gap("native usage feed unavailable".into(), reason);
                Ok(None)
            }
        };
    if mode == CaptureMode::Scan {
        return Ok(None);
    }
    let capture_scope = match scope.into() {
        Scope::Pid(pid) => match PidPin::open(pid) {
            Ok(pin) => crate::attach::capture::CaptureScope::Pid(pin),
            Err(reason) => return unavailable(coordinator, reason),
        },
        Scope::System => crate::attach::capture::CaptureScope::System,
        scope @ Scope::Cgroup { .. } => crate::attach::capture::CaptureScope::cgroup(scope)?,
    };
    let capture = match prepare(
        capture_scope,
        coordinator.attach_set().budget(),
        attach_backend,
    ) {
        Ok(capture) => capture,
        Err(error) => {
            return unavailable(
                coordinator,
                crate::attach::summarize_native_preparation_error(&error),
            );
        }
    };
    let backend = crate::inventory_capture::CaptureLane::<PidPin>::backend(&capture);
    let numbering = crate::pidns::numbering();
    let lossy = (!numbering.agrees()).then(|| {
        format!(
            "observer PID namespace {}, /proc numbering {}: native witnesses bind callers \
             through pidfd cookies, but a caller's absence of use cannot be proven \
             (pid_namespace)",
            numbering.observer.label(),
            numbering.proc_view.label()
        )
    });
    match NativeLane::start(capture, coordinator, LaneWindows::PROVISIONAL, lossy) {
        Ok(lane) => {
            inventory_diagnostic(&lane_active_line(&backend));
            Ok(Some(lane))
        }
        Err((mut capture, reason)) => {
            crate::inventory_capture::retire_refused(&mut capture, Duration::from_secs(2));
            drop(capture);
            unavailable(coordinator, reason)
        }
    }
}

/// The stderr line a native lane starts with: its attach mechanism and,
/// under `auto`, why it fell back to per-offset links.
fn lane_active_line(backend: &crate::inventory_capture::LaneBackend) -> String {
    let fallback = backend.fallback.as_deref().map_or(String::new(), |reason| {
        format!(
            "; uprobe-multi fallback: {}",
            crate::render::escape_controls(reason)
        )
    });
    format!(
        "p11scope: native usage lane active (Inventory capture activated, {} links, \
         --attach-backend {}{fallback})",
        backend.mechanism(),
        backend.selection_label()
    )
}

/// The stage-timings suffix for a lifecycle-ring high-water: bytes and
/// share of this build's ring. Timings output only, never schema.
fn lifecycle_high_water_suffix(high_water_bytes: u64) -> String {
    let ring = u64::from(crate::attach::EXPECTED_INVENTORY_DISCOVERY_BYTES);
    let percent = high_water_bytes.saturating_mul(100) / ring.max(1);
    format!("; lifecycle ring high-water: {high_water_bytes} B ({percent}% of {ring} B)")
}

/// The stderr line a native run ends with: what it attached, how its
/// retirement ended, and its settlement (plus, under stage timings, the
/// run's lifecycle-ring high-water).
fn stop_line(summary: &LaneSummary) -> String {
    let retirement = match &summary.retirement {
        crate::inventory_capture::Retirement::Closed(cleanup) => format!(
            "retirement closed ({} of {} links closed{})",
            cleanup.closed,
            cleanup.attempted,
            if cleanup.failures.is_empty() {
                String::new()
            } else {
                format!(", {} close failures", cleanup.failures.len())
            }
        ),
        crate::inventory_capture::Retirement::Unsettled(reason) => format!(
            "retirement unsettled: {}",
            crate::render::escape_controls(reason)
        ),
    };
    let mut line = format!(
        "p11scope: native capture stopped after {} pass{}: {} endpoints attached ({} links), \
         {} failed; {retirement}; settlement {}",
        summary.passes,
        if summary.passes == 1 { "" } else { "es" },
        summary.attached,
        summary.backend.mechanism(),
        summary.failed,
        crate::inventory_capture::SETTLEMENT,
    );
    if crate::inspect_system::stage_timings_requested()
        && let Some(high_water) = summary.lifecycle_high_water_bytes
    {
        line.push_str(&lifecycle_high_water_suffix(high_water));
    }
    line
}

/// Final sinks, shared by the classic and dashboard paths: the event
/// stream's `ended` marker, the atomic `-o` report, then stdout (the
/// JSON document under `--json`, the pager snapshot otherwise —
/// silent in dashboard mode, whose live view already showed it).
#[allow(clippy::too_many_arguments)]
pub(crate) fn finish_output(
    sink: Option<AtomicFile>,
    stream: &mut EventLogState,
    stream_state: &mut StreamState,
    presentation: &Presentation,
    json: bool,
    silent_text: bool,
    stdout: &mut dyn FinalStdout,
    native: Option<&LaneSummary>,
    identity: Option<&crate::inspect_system::IdentitySummary>,
) -> FinalOutputOutcome {
    let mut document = render_json_from_presentation(presentation);
    if let Some(summary) = native {
        note_native_observation(&mut document, summary);
    }
    if let Some(summary) = identity {
        note_identity_observation(&mut document, summary);
    }
    // Render the immutable JSON payload once. Both destinations receive
    // exactly these bytes; one transport cannot suppress the other's attempt.
    let mut document_bytes = Vec::new();
    if sink.is_some() || json {
        document_bytes = serde_json::to_vec_pretty(&document)
            .expect("an inventory document contains only serializable JSON values");
        document_bytes.push(b'\n');
    }
    let event_requested = stream.writer.is_some() || stream.first_error().is_some();
    stream.attempt("completion", |writer| {
        // Exact repeat counts, then the final combined sweep of physical
        // edges plus both instance kinds plus key-operation rows, then
        // ended: preserve healthy ordering and the sweep's retention
        // reservation. Every kind joins before retention settles, so an
        // eviction is either repaired by the combined dump or disclosed
        // in the exact unretained counts — never silent for any kind.
        stream_state
            .gaps
            .emit(writer, &presentation.gaps, true, presentation.ended_ns)?;
        let metadata_events =
            stream_state
                .metadata
                .emit(writer, presentation, presentation.ended_ns, true)?;
        let tail = ended_tail(presentation, writer);
        let identities = IdentityIndex::new(presentation);
        let swept = stream_state.edges.sweep(
            writer,
            &presentation.edges,
            &identities,
            presentation.budgets.edges_limit,
            presentation.ended_ns,
            tail,
        )?;
        let swept_instances = stream_state.instances.sweep_exact(
            writer,
            &presentation.instances,
            &presentation.semantic_edges,
            presentation.budgets.instances_limit,
            presentation.ended_ns,
        )?;
        // The H9 third of the exact final sweep: every uncarried
        // projection row from the gated publication, before `ended`.
        stream_state
            .key_publisher
            .publish(presentation.object_observations.clone());
        let published = stream_state
            .key_publisher
            .publication()
            .expect("the publisher retains a publication")
            .clone();
        let swept_key_operations =
            stream_state
                .key_operations
                .sweep_exact(writer, &published, presentation.ended_ns)?;
        writer.reserve(tail)?;
        let mut estimate =
            combined_unretained_after(stream_state, writer, presentation, &published, tail);
        if estimate.0 + estimate.1 + estimate.2 + estimate.3 > 0
            && combined_dump_fits(
                &stream_state.edges,
                &stream_state.instances,
                &stream_state.key_operations,
                writer,
                tail,
            )
        {
            stream_state.edges.dump_all(
                writer,
                &presentation.edges,
                &identities,
                presentation.budgets.edges_limit,
                presentation.ended_ns,
            )?;
            stream_state.instances.dump_all(
                writer,
                &presentation.instances,
                &presentation.semantic_edges,
                presentation.budgets.instances_limit,
                presentation.ended_ns,
            )?;
            stream_state
                .key_operations
                .dump_all(writer, &published, presentation.ended_ns)?;
            // No second reserve: the fit bound already holds the tail.
            estimate =
                combined_unretained_after(stream_state, writer, presentation, &published, tail);
        }
        let edge_events = swept.emitted;
        let instance_events = swept_instances.instance_emitted;
        let semantic_edge_events = swept_instances.edge_emitted;
        let key_operation_events = swept_key_operations;
        let (_, payload) = settle_ended_combined(
            &stream_state.edges,
            &stream_state.instances,
            &stream_state.key_operations,
            writer,
            presentation,
            &published,
            estimate,
            presentation.ended_ns,
            |(edges_unretained, instances_unretained, semantic_unretained, key_unretained)| {
                let mut payload = ended_payload(presentation, presentation.ended_ns, writer);
                payload["caller_metadata_events"] = metadata_events.into();
                payload["edge_events"] = edge_events.into();
                payload["edges_unretained"] = edges_unretained.into();
                payload["instance_events"] = instance_events.into();
                payload["instances_unretained"] = instances_unretained.into();
                payload["semantic_edge_events"] = semantic_edge_events.into();
                payload["semantic_edges_unretained"] = semantic_unretained.into();
                payload["key_operation_events"] = key_operation_events.into();
                payload["key_operations_unretained"] = key_unretained.into();
                payload
            },
        );
        // A sync error after append still retires the writer: a visible
        // ended record is not proof that finish confirmed completion.
        writer.finish(payload, presentation.ended_ns)
    });
    let mut outcome = FinalOutputOutcome {
        diagnostics_failed: false,
        event_log_confirmed: event_requested.then(|| stream.first_error().is_none()),
        report_committed: None,
        stdout_result: None,
        failures: stream
            .first_error()
            .map(str::to_string)
            .into_iter()
            .collect(),
    };
    if let Some(mut sink) = sink {
        let result = sink
            .file()
            .write_all(&document_bytes)
            .map_err(|error| format!("writing inventory report failed: {error}"))
            .and_then(|()| sink.commit());
        outcome.report_committed = Some(result.is_ok());
        if let Err(error) = result {
            outcome
                .failures
                .push(format!("p11scope: inventory -o report failed: {error}"));
        }
    }
    if json || !silent_text {
        let text;
        let bytes = if json {
            document_bytes.as_slice()
        } else {
            text = render_snapshot(presentation);
            text.as_bytes()
        };
        let result = stdout.write_document(bytes);
        if let Err(error) = &result {
            let reason = match &error.reason {
                StdoutFailureReason::NoProgress => "no progress for 5 seconds".to_string(),
                StdoutFailureReason::Cancelled => "cancelled by a later signal".to_string(),
                StdoutFailureReason::Io(error) => format!("I/O error: {error}"),
            };
            outcome
                .failures
                .push(format!("p11scope: inventory stdout failed: {reason}; accepted {} of {} bytes; remaining {} not written",
                    error.accepted, error.total, error.total - error.accepted));
        }
        outcome.stdout_result = Some(result);
    }
    outcome
}

/// Primary sinks and diagnostics are attempted independently. Keep this
/// inside finish_native's write closure: arming the second-signal exit or
/// dropping native ownership before export would skip useful diagnostics.
#[allow(clippy::too_many_arguments)]
fn finish_runtime_output<Source: ProcessSource>(
    sink: Option<AtomicFile>,
    stream: &mut EventLogState,
    stream_state: &mut StreamState,
    presentation: &Presentation,
    json: bool,
    silent_text: bool,
    stdout: &mut dyn FinalStdout,
    native: Option<&LaneSummary>,
    identity: Option<&crate::inspect_system::IdentitySummary>,
    coordinator: &mut InventoryCoordinator<Source>,
    diagnostics: Option<DiagnosticsState>,
    diagnostic_outcome: DiagnosticOutcome,
    second_signal: &dyn Fn() -> bool,
    notice: &mut dyn FnMut(&str),
) -> FinalOutputOutcome {
    let mut outcome = finish_output(
        sink,
        stream,
        stream_state,
        presentation,
        json,
        silent_text,
        stdout,
        native,
        identity,
    );
    if let Some(diagnostics) = diagnostics {
        outcome.diagnostics_failed =
            diagnostics.finish(coordinator, diagnostic_outcome, second_signal, notice);
    }
    outcome
}

/// All four kinds' rows whose last record will not be retained
/// once the `tail` bytes still to come are written: `(physical edges,
/// instances, semantic edges, key-operation rows)`.
fn combined_unretained_after(
    stream_state: &StreamState,
    writer: &EventWriter,
    presentation: &Presentation,
    key_observations: &crate::key_operation_projection::ObjectObservations,
    tail: u64,
) -> (usize, usize, usize, usize) {
    let edges_unretained = stream_state
        .edges
        .unretained_after(writer, &presentation.edges, tail);
    let (instances_unretained, semantic_unretained) = stream_state.instances.unretained_after(
        writer,
        &presentation.instances,
        &presentation.semantic_edges,
        tail,
    );
    // The key disclosure counts the SELECTED publication (N11) — the
    // same rows the sweep wrote — never the newer presentation.
    let key_unretained =
        stream_state
            .key_operations
            .unretained_after(writer, key_observations, tail);
    (
        edges_unretained,
        instances_unretained,
        semantic_unretained,
        key_unretained,
    )
}

/// Bytes the `ended` line may take: its payload as measured now plus
/// [`ENDED_TAIL_SLACK`] (the envelope and counters that may still grow).
fn ended_tail(presentation: &Presentation, writer: &EventWriter) -> u64 {
    let mut payload = ended_payload(presentation, presentation.ended_ns, writer);
    payload["edge_events"] = u64::MAX.into();
    payload["edges_unretained"] = u64::MAX.into();
    payload["instance_events"] = u64::MAX.into();
    payload["instances_unretained"] = u64::MAX.into();
    payload["semantic_edge_events"] = u64::MAX.into();
    payload["semantic_edges_unretained"] = u64::MAX.into();
    payload["key_operation_events"] = u64::MAX.into();
    payload["key_operations_unretained"] = u64::MAX.into();
    (payload.to_string().len() as u64).saturating_add(crate::inventory_events::ENDED_TAIL_SLACK)
}

/// One pass's application after its collection, with the shared failure
/// policy: the collection may have run on a worker thread (C5.7); its
/// catalog, or its error, is applied here.
fn apply_one_pass(
    coordinator: &mut InventoryCoordinator<OsProcessSource>,
    collected: Result<crate::inspect_system::Catalog>,
    scope: InspectScope,
    guard: &mut UnavailableImageGuard,
    deadline: Option<Instant>,
    identity: &mut dyn NativeIdentity<PidPin>,
    now: u64,
) -> Result<(PassReport, Option<String>)> {
    // The run's deadline on the pass clock, read after the collection (it
    // may have taken a while on its worker): it bounds the owner scans.
    let pass_deadline = match deadline {
        Some(end) => {
            let remaining = end.saturating_duration_since(Instant::now());
            now_ns().saturating_add(remaining.as_nanos().min(u128::from(u64::MAX)) as u64)
        }
        None => u64::MAX,
    };
    let scope_context = match scope {
        InspectScope::Pid(pid) => format!("inventory --pid {pid}"),
        InspectScope::System => "inventory --system".to_string(),
    };
    match collected.map(|catalog| {
        coordinator.apply_catalog(catalog, guard, &mut *identity, pass_deadline, now)
    }) {
        Ok(report) => Ok((report, None)),
        Err(error) if coordinator.passes() == 0 => Err(error).with_context(|| scope_context),
        Err(error) => {
            // The error text can carry target-controlled strings (paths):
            // escaped once here for stderr and the dashboard log alike.
            let warning = format!(
                "p11scope: pass failed, continuing without its scan: {}",
                crate::render::escape_controls(&format!("{error:#}"))
            );
            let report =
                coordinator.observe_empty_pass(guard, identity, &format!("{error:#}"), now);
            Ok((report, Some(warning)))
        }
    }
}

/// Incremental stream position: gaps are push-only until the bound,
/// so an index plus the suppressed counter replays exactly the new
/// loss on every pass; edges keep one digest each (bounded by the edge
/// limit) so only changes are streamed (DR-C5-EDGE); instances keep one
/// tracked record each with separate dirty flags for the two instance
/// kinds under one shared per-pass quota.
pub(crate) struct StreamState {
    gaps: GapEmitter,
    metadata: crate::caller_metadata::consumer::MetadataEmitter,
    edges: EdgeEmitter,
    instances: InstanceEmitter,
    key_operations: KeyOperationEmitter,
    key_publisher: crate::key_operation_projection::ObservationPublisher,
    /// The last stream-window view a pass published: the prior every
    /// user-visible view reuses while a Joint publication pends. The
    /// run functions seed it with the opening capture; `None` only
    /// before seeding (and in harnesses that never publish).
    last_stream_view: Option<Presentation>,
    emitted_suppressed: u64,
    /// Unbound witness rows per (module, reason) already counted on a
    /// pass marker.
    emitted_unbound: BTreeMap<(ModuleId, &'static str), u64>,
}

impl StreamState {
    pub(crate) fn new() -> Self {
        Self {
            gaps: GapEmitter::new(),
            metadata: crate::caller_metadata::consumer::MetadataEmitter::default(),
            edges: EdgeEmitter::new(),
            instances: InstanceEmitter::new(),
            key_operations: KeyOperationEmitter::new(),
            key_publisher: crate::key_operation_projection::ObservationPublisher::new(),
            last_stream_view: None,
            emitted_suppressed: 0,
            emitted_unbound: BTreeMap::new(),
        }
    }

    /// Install a pre-loaded key publisher (N11 stale-publication
    /// tests): the finish path publishes the current presentation
    /// into this publisher, which may retain an older selection.
    #[cfg(test)]
    pub(crate) fn reference_key_publisher(
        &mut self,
        publisher: crate::key_operation_projection::ObservationPublisher,
    ) {
        self.key_publisher = publisher;
    }
}

/// (module, reason) entries one pass marker lists before it sums the rest
/// as `unbound_rows_truncated`.
const UNBOUND_ROWS_PER_PASS: usize = 256;

/// R-C51-2: the unbound witness rows staged since the previous pass
/// marker, per (module, reason) — the delta of the modules' cumulative
/// `unbound_use.reasons` — listed up to `limit` entries in (module,
/// reason) order, the rest summed as truncated. Rows never name a pid.
fn unbound_rows_delta<'a>(
    state: &mut StreamState,
    modules: impl Iterator<Item = (ModuleId, &'a crate::discovery::caller_registry::UnboundUse)>,
    limit: usize,
) -> (Vec<serde_json::Value>, u64) {
    let mut listed = Vec::new();
    let mut truncated = 0u64;
    for (id, unbound) in modules {
        for (&reason, &count) in &unbound.reasons {
            let emitted = state.emitted_unbound.entry((id, reason)).or_default();
            let delta = count.saturating_sub(*emitted);
            *emitted = (*emitted).max(count);
            if delta == 0 {
                continue;
            }
            if listed.len() < limit {
                listed.push(serde_json::json!({
                    "module": id.label(),
                    "reason": reason,
                    "rows": delta,
                }));
            } else {
                truncated = truncated.saturating_add(delta);
            }
        }
    }
    (listed, truncated)
}

/// Adds this pass's unbound witness rows to a pass marker.
fn add_unbound_rows(
    payload: &mut serde_json::Value,
    state: &mut StreamState,
    presentation: &Presentation,
) {
    let (rows, truncated) = unbound_rows_delta(
        state,
        presentation.modules.iter().filter_map(|module| {
            module
                .unbound_use
                .as_ref()
                .map(|unbound| (module.id, unbound))
        }),
        UNBOUND_ROWS_PER_PASS,
    );
    payload["unbound_rows"] = serde_json::Value::from(rows);
    payload["unbound_rows_truncated"] = serde_json::Value::from(truncated);
}

/// Append one committed pass to the event stream: caller turnover,
/// every new gap verbatim, then the pass marker with this pass's loss
/// accounting. A refused capture produces stream gaps identical in
/// meaning to snapshot gaps (same subject/reason/budget). Shared with
/// the loop-regression harness, which streams through the real emitters.
pub(crate) fn emit_pass_events(
    writer: &mut EventWriter,
    state: &mut StreamState,
    report: &PassReport,
    presentation: &Presentation,
    now_ns: u64,
) -> Result<(), String> {
    emit_commit(writer, state, report, presentation, false, now_ns)
}

/// The one commit emitter (C5.9's single gap emitter): caller events, the
/// fresh gaps through `state.gaps` (unflushed: the classic path's
/// `finish_output` flushes), the changed edges through `state.edges`
/// (capped per pass; `finish_output` sweeps the rest), then the pass
/// marker with its loss accounting, edge record counts and unbound row
/// counts; `final` marks the native stop's commit.
fn emit_commit(
    writer: &mut EventWriter,
    state: &mut StreamState,
    report: &PassReport,
    presentation: &Presentation,
    stop: bool,
    now_ns: u64,
) -> Result<(), String> {
    let identities = IdentityIndex::new(presentation);
    for event in &report.events {
        writer.append(
            "caller_event",
            caller_event_payload(event, &identities),
            now_ns,
        )?;
    }
    let metadata_events = state.metadata.emit(writer, presentation, now_ns, false)?;
    let fresh = state.gaps.emit(writer, &presentation.gaps, false, now_ns)?;
    let edges = state.edges.emit(
        writer,
        &presentation.edges,
        &identities,
        presentation.budgets.edges_limit,
        now_ns,
    )?;
    let instances = state.instances.emit(
        writer,
        &presentation.instances,
        &presentation.semantic_edges,
        presentation.budgets.instances_limit,
        now_ns,
    )?;
    // H9 rows ride from the gated publication (stale-aware), never
    // straight from the fresh presentation: the stream must freeze
    // with a retained publication, not skip ahead of it.
    state
        .key_publisher
        .publish(presentation.object_observations.clone());
    let published = state
        .key_publisher
        .publication()
        .expect("the publisher retains a publication")
        .clone();
    let key_operations = state.key_operations.emit(writer, &published, now_ns)?;
    let suppressed_delta = presentation
        .gaps_suppressed
        .saturating_sub(state.emitted_suppressed);
    state.emitted_suppressed = presentation.gaps_suppressed;
    let mut payload = pass_payload(report, presentation, &published, fresh, suppressed_delta);
    payload["caller_metadata_events"] = metadata_events.into();
    payload["caller_metadata"] = presentation.caller_metadata.summary.json();
    payload["edge_events"] = edges.emitted.into();
    payload["edge_events_deferred"] = edges.deferred.into();
    payload["instance_events"] = instances.instance_emitted.into();
    payload["instance_events_deferred"] = instances.instance_deferred.into();
    payload["semantic_edge_events"] = instances.edge_emitted.into();
    payload["semantic_edge_events_deferred"] = instances.edge_deferred.into();
    payload["key_operation_events"] = key_operations.emitted.into();
    payload["key_operation_events_deferred"] = key_operations.deferred.into();
    add_unbound_rows(&mut payload, state, presentation);
    if stop {
        payload["final"] = serde_json::Value::Bool(true);
    }
    writer.append("pass_committed", payload, now_ns)
}

/// Append the native stop's commit to the event stream: the incarnation
/// events and fresh gaps its final staging produced, then one
/// `pass_committed` marked `final` (it commits after the last pass and
/// scans nothing), so the stream's gap accounting stays exact.
pub(crate) fn emit_stop_events(
    writer: &mut EventWriter,
    state: &mut StreamState,
    events: &[CallerEvent],
    passes: u64,
    presentation: &Presentation,
    now_ns: u64,
) -> Result<(), String> {
    let report = PassReport {
        pass: passes.saturating_sub(1),
        scanned: 0,
        maps_matched: 0,
        native_callers: 0,
        scan_callers: 0,
        engine_changed: false,
        pending_refresh: Vec::new(),
        events: events.to_vec(),
        timings: crate::timing::StageTimings::new(),
    };
    emit_commit(writer, state, &report, presentation, true, now_ns)
}

/// A native run's observation statement: the lane, its settlement (always
/// `unsettled`, ruling D3), how its retirement ended, and the lifecycle
/// feed's own account (C5.7). Absent in the scan lane, whose document is
/// unchanged.
fn note_native_observation(document: &mut serde_json::Value, summary: &LaneSummary) {
    let observation = &mut document["observation"];
    observation["lane"] = "native".into();
    observation["settlement"] = crate::inventory_capture::SETTLEMENT.into();
    observation["retirement"] = summary.retirement.label().into();
    // C5.11: the attach mechanism, as the classic `attach_mechanisms`
    // spells it, the operator's selection, and any `auto` fallback reason.
    observation["attach"] = serde_json::json!({
        "selection": summary.backend.selection_label(),
        "mechanism": summary.backend.mechanism(),
        "fallback": summary.backend.fallback,
        "scope_filter": summary.backend.scope_filter.label(),
    });
    let lifecycle = &summary.lifecycle;
    observation["lifecycle"] = serde_json::json!({
        "records": lifecycle.records,
        "ring_loss": lifecycle.ring_loss,
        "malformed": lifecycle.malformed,
        "failed_quanta": lifecycle.failed_quanta,
        "recovery_rescans": lifecycle.recovery_rescans,
    });
}

/// A system run's identity statement (D3d): the resolved sweep proof
/// backend and its first finite fallback, or null. Absent under
/// `--pid`/`--cgroup`, whose implicit default loads nothing.
fn note_identity_observation(
    document: &mut serde_json::Value,
    summary: &crate::inspect_system::IdentitySummary,
) {
    document["observation"]["identity"] = summary.json();
}

/// What the interactive dashboard run is over.
struct DashboardRun {
    scope: InventoryRunScope,
    inventory_scope: Option<InventoryScope>,
    cgroup: Option<CgroupDriverState>,
    scope_label: String,
    started_ns: u64,
    max_scan_pids: Option<usize>,
    duration: Option<Duration>,
    json: bool,
    attach_backend: crate::attach::BackendSelection,
}

/// The event stream's view of a pass: the classic cumulative window, on
/// both front ends. The stream must not depend on whether `--dashboard` was
/// given (C5.3 review M2): activity is window-dependent, and C5.4's
/// `edge_observed` records carry it.
fn stream_presentation<S: ProcessSource>(
    coordinator: &InventoryCoordinator<S>,
    scope_label: &str,
    started_ns: u64,
    now_ns: u64,
) -> Presentation {
    Presentation::capture(
        coordinator,
        scope_label,
        started_ns,
        now_ns,
        coordinator.passes(),
    )
}

/// The dashboard's two views of a pass: the stream's
/// ([`stream_presentation`]) and the display's, whose activity reads
/// through the trailing [`DASHBOARD_ACTIVITY_WINDOW_NS`] (a growing window
/// would pin every historical entry as "recent" forever on screen).
fn dashboard_pass_views<S: ProcessSource>(
    coordinator: &InventoryCoordinator<S>,
    scope_label: &str,
    started_ns: u64,
    now_ns: u64,
    semantic: crate::inventory_semantics::SemanticCaptureSummary,
) -> (Presentation, Presentation) {
    let mut display = Presentation::capture_dashboard(
        coordinator,
        scope_label,
        started_ns,
        now_ns,
        coordinator.passes(),
        now_ns,
        DASHBOARD_ACTIVITY_WINDOW_NS,
    );
    display.semantic_capture = semantic;
    let mut stream_view = stream_presentation(coordinator, scope_label, started_ns, now_ns);
    stream_view.semantic_capture = semantic;
    (stream_view, display)
}

/// One dashboard pass on the stream side: the pass's events go out from the
/// classic view ([`stream_presentation`]), never the display's trailing
/// window (C5.3 re-check R2: `edge_observed` carries activity), and only
/// then is the display view handed back for the screen.
#[allow(clippy::too_many_arguments)]
fn dashboard_stream_pass<S: ProcessSource>(
    stream: &mut EventLogState,
    state: &mut StreamState,
    report: &PassReport,
    coordinator: &InventoryCoordinator<S>,
    scope_label: &str,
    started_ns: u64,
    now_ns: u64,
    semantic: crate::inventory_semantics::SemanticCaptureSummary,
) -> (Presentation, Option<String>) {
    let (stream_view, display_view) =
        dashboard_pass_views(coordinator, scope_label, started_ns, now_ns, semantic);
    state.last_stream_view = Some(stream_view.clone());
    let error = stream.attempt("pass publication", |writer| {
        emit_pass_events(writer, state, report, &stream_view, now_ns)
    });
    (display_view, error)
}

/// Whether a live read must wait: the Joint driver still owes a
/// publication, or the coordinator still holds an unfinished one
/// the driver already abandoned (a held lane owes nothing, but its
/// wedge still refuses a fresh capture). The stream and the
/// dashboard keep their prior bytes; the final reuses its prior
/// view — so a stuck publication degrades the report instead of
/// panicking past the stop.
fn publication_pending_for_view(driver: &ClassicDriver<'_>) -> bool {
    driver.publication_pending() || driver.coordinator.publication_pending()
}

/// The stream view for one pass or stop publication: `None` while
/// a publication pends ([`publication_pending_for_view`]), so the
/// caller emits nothing and the stream keeps its prior bytes and
/// baselines (no commit, no key-operation, caller-event or baseline
/// mutation, no live registry read). Otherwise the fresh view,
/// retained as the prior for later pending views and the finals.
fn stream_view_guarded(
    driver: &ClassicDriver<'_>,
    state: &mut StreamState,
    scope_label: &str,
    started_ns: u64,
    now_ns: u64,
) -> Option<Presentation> {
    if publication_pending_for_view(driver) {
        return None;
    }
    let mut presentation = stream_presentation(driver.coordinator, scope_label, started_ns, now_ns);
    presentation.semantic_capture = driver.semantic_summary();
    state.last_stream_view = Some(presentation.clone());
    Some(presentation)
}

/// The dashboard pass views: `None` while a publication pends
/// ([`publication_pending_for_view`]), so the caller skips both the
/// stream emit and the display offer and both keep their prior view.
/// Otherwise the display view with its stream error, as
/// [`dashboard_stream_pass`].
fn dashboard_pass_guarded(
    driver: &ClassicDriver<'_>,
    stream: &mut EventLogState,
    state: &mut StreamState,
    report: &PassReport,
    scope_label: &str,
    started_ns: u64,
    now_ns: u64,
) -> Option<(Presentation, Option<String>)> {
    if publication_pending_for_view(driver) {
        return None;
    }
    Some(dashboard_stream_pass(
        stream,
        state,
        report,
        driver.coordinator,
        scope_label,
        started_ns,
        now_ns,
        driver.semantic_summary(),
    ))
}

/// The final report view shared by the classic and dashboard
/// finals: the prior stream view while a publication pends
/// ([`publication_pending_for_view`], with the current lane-side
/// summary, which is not a registry read), so the report reuses the
/// last completed observation instead of a partial live read.
/// Pending without a prior (only before the opening seed, which the
/// run functions always install) falls back to a fresh capture: the
/// stop must still write its report.
fn final_view_guarded(
    driver: &ClassicDriver<'_>,
    state: &StreamState,
    scope_label: &str,
    started_ns: u64,
    ended_ns: u64,
) -> Presentation {
    if publication_pending_for_view(driver)
        && let Some(prior) = state.last_stream_view.as_ref()
    {
        let mut view = prior.clone();
        view.semantic_capture = driver.semantic_summary();
        return view;
    }
    let mut presentation = Presentation::capture(
        driver.coordinator,
        scope_label,
        started_ns,
        ended_ns,
        driver.coordinator.passes(),
    );
    presentation.semantic_capture = driver.semantic_summary();
    presentation
}

/// With no `--duration` the dashboard runs until a key or a signal: its
/// loop clock gets a deadline it never reaches.
const DASHBOARD_UNBOUNDED: Duration = Duration::from_secs(100 * 365 * 24 * 3600);

/// The observation deadline for a `--duration` window. `checked_add`
/// like the classic wait (`run.rs`): a window that overflows the clock
/// degrades to no deadline instead of panicking. Unreachable via the
/// CLI (`parse_duration` bounds every duration); the classic path reads
/// no deadline as a single snapshot, the dashboard as its unbounded
/// sentinel below.
fn deadline_for_duration(duration: Option<Duration>) -> Option<Instant> {
    duration.and_then(|window| Instant::now().checked_add(window))
}

/// The dashboard's unbounded deadline: a century out, `checked_add`
/// like every other clock addition here (the fallback mirrors the
/// classic settlement deadline and is unreachable on a supported
/// host — a century never overflows the clock).
fn unbounded_dashboard_deadline() -> Instant {
    Instant::now()
        .checked_add(DASHBOARD_UNBOUNDED)
        .unwrap_or_else(Instant::now)
}

/// The interactive dashboard (C5.3), over the `display` the caller opened:
/// the classic loop (`run_classic`) with the display on its service ticks. Passes, the native lane's
/// service ticks, witness reads and the stop run exactly as on the
/// classic path; the display only draws inside a tick, with a frame
/// writer that sheds what a stalled terminal does not take within its
/// budget, so a terminal that stops reading never delays a service tick.
/// Keys (stdin TTY only), `--duration`, or SIGINT/SIGTERM/SIGHUP end it.
/// The terminal is given back (bounded) before the native stop, so the
/// stop's notices are readable; the report follows R-C51-4 like the
/// classic path's.
#[allow(clippy::too_many_arguments)]
fn run_dashboard(
    run: DashboardRun,
    mut coordinator: InventoryCoordinator<OsProcessSource>,
    lane: Option<NativeLane<FacadeLane>>,
    display: Display,
    sink: Option<AtomicFile>,
    mut stream: EventLogState,
    stop: &dyn Fn() -> bool,
    outputs_attempted: &dyn Fn(),
    stdout: &mut dyn FinalStdout,
    terminal: &DashboardIo,
    diagnostics: Option<DiagnosticsState>,
    second_signal: &dyn Fn() -> bool,
    native_available: bool,
    semantic: Option<crate::inventory_semantics::AttestedSemanticLane>,
    identity_shared: Option<crate::inspect_system::IdentityShared>,
) -> Result<i32> {
    let DashboardRun {
        scope,
        inventory_scope,
        cgroup,
        scope_label,
        started_ns,
        max_scan_pids,
        duration,
        json,
        attach_backend,
    } = run;
    let quit = display.quit_flag();
    let mut stream_state = StreamState::new();
    // The opening prior for pending views and the final: the same
    // pass-zero read as the prologue, so a final always has a prior
    // even when no pass completed.
    stream_state.last_stream_view = Some(Presentation::capture(
        &coordinator,
        &scope_label,
        started_ns,
        started_ns,
        0,
    ));
    let initial_error = start_event_log(&mut stream, &coordinator, &scope_label, started_ns);
    let initial_error = match (diagnostics.is_some(), initial_error) {
        (false, Some(error)) => return Err(error),
        (_, error) => error,
    };
    let deadline = cgroup
        .as_ref()
        .map_or_else(|| deadline_for_duration(duration), |state| state.deadline);
    let mut driver = ClassicDriver {
        coordinator: &mut coordinator,
        inventory_scope,
        scope,
        cgroup,
        max_scan_pids,
        guard: UnavailableImageGuard,
        deadline,
        attach_backend,
        display: Some(display),
        semantic,
        semantic_staged: false,
        seated_summary: None,
        second_signal: Some(second_signal),
        lifecycle: crate::inventory_promotion::lifecycle::SelectedLifecycleService::new(),
        completion_source: None,
        pending_install: None,
        installed_promotion: None,
        retiring: None,
        joint_finish: JointFinishDriver::NotBegun,
        stop_requested: false,
        joint_first_error: None,
        suspended: false,
        joint_commit_pending: false,
        joint_tick_refusal: None,
        joint_commit_retries: 0,
        #[cfg(test)]
        terminal_seq_calls: 0,
        #[cfg(test)]
        reclaim_calls: Vec::new(),
        #[cfg(test)]
        joint_begin_calls: 0,
        #[cfg(test)]
        joint_step_calls: 0,
        #[cfg(test)]
        joint_commit_polls: 0,
        #[cfg(test)]
        take_promotion_work_calls: 0,
        #[cfg(test)]
        drive_pending_install_calls: 0,
        #[cfg(test)]
        service_caller_metadata_calls: 0,
        #[cfg(test)]
        commit_calls: 0,
        identity: identity_shared.clone(),
    };
    driver.set_completion_source(Box::new(crate::attach::NativeCompletionMinter::new()));
    driver.initialize_joint_lane();
    // The run's promotion capture: the dashboard's DR37 control binds
    // once per run. `started_ns` is nonzero on any live clock; the max
    // closes the theoretical zero the baseline binder refuses.
    driver.enable_run_promotion(crate::inventory_promotion::CaptureId::new(
        started_ns.max(1),
    ));
    let ending = || stop() || quit.get();
    let clock = LoopClock {
        deadline: Some(deadline.unwrap_or_else(unbounded_dashboard_deadline)),
        stop: &ending,
        now: &Instant::now,
        interval: RESCAN_INTERVAL,
        tick: SERVICE_TICK,
        collection_tick: SERVICE_TICK,
    };
    let mut publish = |driver: &mut ClassicDriver<'_>, point: Publish<'_>| {
        match point {
            Publish::Pass { report, now_ns } => {
                let Some((display_view, event_error)) = dashboard_pass_guarded(
                    driver,
                    &mut stream,
                    &mut stream_state,
                    report,
                    &scope_label,
                    started_ns,
                    now_ns,
                ) else {
                    return Ok(());
                };
                let coordinator = &*driver.coordinator;
                if let Some(display) = driver.display.as_mut() {
                    if let Some(error) = event_error {
                        display.notice(&crate::render::escape_controls(&error));
                    }
                    // The pass line is progress; its events and gaps
                    // must outlive the screen.
                    for (index, line) in progress_lines(coordinator, report).iter().enumerate() {
                        if index == 0 {
                            display.log(line);
                        } else {
                            display.warn(line);
                        }
                    }
                    display.offer(display_view);
                }
            }
            Publish::Retiring {
                attached,
                links,
                budget,
            } => {
                retiring_stdout(stdout, || {
                    // Termios and the bounded screen restore precede JSON.
                    if let Some(display) = driver.display.as_mut() {
                        display.restore();
                        display.notice(&format!(
                            "p11scope: stopping: detaching the native probes of {attached} \
                             endpoints in {links} links (up to {} s)",
                            budget.as_secs()
                        ));
                    }
                });
            }
            Publish::Stop { events, now_ns } => {
                let coordinator = &*driver.coordinator;
                let Some(presentation) = stream_view_guarded(
                    driver,
                    &mut stream_state,
                    &scope_label,
                    started_ns,
                    now_ns,
                ) else {
                    return Ok(());
                };
                if let Some(error) = stream.attempt("stop publication", |writer| {
                    emit_stop_events(
                        writer,
                        &mut stream_state,
                        events,
                        coordinator.passes(),
                        &presentation,
                        now_ns,
                    )
                }) && let Some(display) = driver.display.as_mut()
                {
                    display.notice(&crate::render::escape_controls(&error));
                }
            }
        }
        Ok(())
    };
    let running = run_classic_finalizing(&mut driver, lane, &clock, initial_error, &mut publish);
    let (stopped, capture_error, zero_pass) = driver.consume_outcome(running, &clock, &mut publish);
    let presentation =
        final_view_guarded(&driver, &stream_state, &scope_label, started_ns, now_ns());
    begin_scan_stdout(stdout, stopped.is_some());
    let mut display = driver
        .display
        .take()
        .expect("the dashboard driver keeps its display");
    let semantic_lane = driver.semantic.take();
    drop(driver);
    display.restore();
    let failure = display.take_failure();
    if let Some(stopped) = &stopped {
        display.notice(&stop_line(&stopped.summary));
    }
    if let Some(zero) = &zero_pass {
        display.notice(&zero.stderr_line());
    }
    // Output attempts first (R-C51-4), silent text: the live view showed it.
    let previously_reported = stream.first_error().map(str::to_string);
    let diagnostic_outcome = diagnostic_outcome(
        native_available,
        capture_error.is_some(),
        diagnostics.is_some() && ending(),
    );
    let display_notices = std::cell::RefCell::new(&mut display);
    let identity_summary = identity_shared.as_ref().map(|shared| {
        shared
            .lock()
            .unwrap_or_else(|poison| poison.into_inner())
            .summary()
    });
    let outcome = crate::inventory_capture::finish_native(
        stopped,
        |summary| {
            finish_runtime_output(
                sink,
                &mut stream,
                &mut stream_state,
                &presentation,
                json,
                true,
                stdout,
                summary,
                identity_summary.as_ref(),
                &mut coordinator,
                diagnostics,
                diagnostic_outcome,
                second_signal,
                &mut |line| display_notices.borrow_mut().notice(line),
            )
        },
        outputs_attempted,
        &mut |line| display_notices.borrow_mut().notice(&line),
        |s| {
            ExitRetention::hold(s);
            ExitRelease::RetainedForExit
        },
    );
    finish_caller_metadata_cleanup(&mut coordinator, second_signal);
    let cleanup = finish_semantic_native_cleanup(semantic_lane, second_signal);
    // A restore the terminal shed (Ctrl-S then `q`) leaves the shell in
    // the alternate screen: after output attempts, it can wait longer.
    display.retry_restore(if outcome.stdout_cancelled() {
        Duration::ZERO
    } else {
        RESTORE_RETRY_BUDGET
    });
    outcome.notices(previously_reported.as_deref(), &mut |line| {
        display.notice(line)
    });
    if outcome.exit_code() != 0
        && let Some(error) = &failure
    {
        display.notice(&format!(
            "p11scope: writing the dashboard terminal failed: {}",
            crate::render::escape_controls(&error.to_string())
        ));
    }
    // Closing accounting describes the final restore and output notices,
    // including a retry that succeeds after the initial restore was shed.
    let passes = coordinator.passes();
    for line in dashboard_account_lines(passes, &display.account()) {
        display.notice(&line);
    }
    if let Some(slot) = &terminal.account {
        slot.set(Some(display.account()));
    }
    // Sink errors use the bounded notices above, including a simultaneous
    // display error. Preserve the existing display-only error policy and
    // carry an interrupted Detailed cleanup as a typed secondary outcome.
    let primary = capture_error.or_else(|| {
        (outcome.exit_code() == 0)
            .then_some(failure)
            .flatten()
            .map(|error| anyhow::anyhow!(error).context("writing the dashboard terminal"))
    });
    combine_semantic_terminal_errors(primary, cleanup)?;
    Ok(outcome.exit_code())
}

/// The stderr account a dashboard run ends with: its passes, the frame
/// handoff, what the terminal writer shed, and the longest gaps between
/// two service ticks, without and across a pass (C5.3: a stalled
/// terminal sheds frames, never ticks).
fn dashboard_account_lines(passes: u64, account: &DisplayAccount) -> Vec<String> {
    let terminal = &account.terminal;
    vec![
        format!(
            "p11scope: dashboard exited after {passes} pass{}",
            if passes == 1 { "" } else { "es" }
        ),
        format!(
            "p11scope: dashboard frames: {} offered, {} consumed, {} shed (shed frames are \
             obsolete display work; capture is unaffected)",
            account.offered, account.consumed, account.superseded,
        ),
        format!(
            "p11scope: dashboard terminal: {} frames written, {} shed by a terminal that did \
             not keep up ({} cut short, {} bytes, {} ms waited); screen {}; service ticks {}, \
             longest gap {} ms ({} ms across a pass)",
            terminal.frames_written,
            terminal.frames_shed,
            terminal.frames_cut,
            terminal.bytes_shed,
            terminal.stall_ms,
            if terminal.restored {
                "restored"
            } else {
                "restore shed"
            },
            account.ticks,
            account.longest_gap.as_millis(),
            account.longest_pass_gap.as_millis(),
        ),
        dashboard_stderr_line(account),
    ]
}

/// What became of the run's stderr lines (C5.3, review M1): replayed
/// after the screen, mirrored beside it, or left alone; and what was
/// dropped or shed on the way.
fn dashboard_stderr_line(account: &DisplayAccount) -> String {
    let stderr = &account.stderr;
    let route = match stderr.route {
        StderrRoute::Capture => format!(
            "captured from the terminal, {} lines replayed, {} dropped{}{}",
            stderr.replayed,
            stderr.dropped,
            if stderr.undrained {
                ", a helper still held the capture (its later lines are unread)"
            } else {
                ""
            },
            if stderr.restore_failed {
                ", stderr not put back"
            } else {
                ""
            },
        ),
        StderrRoute::Mirror => format!(
            "left alone, {} log lines mirrored to it, {} shed",
            stderr.mirrored, stderr.mirror_shed
        ),
        StderrRoute::Leave => "left alone".to_string(),
    };
    format!(
        "p11scope: dashboard stderr: {route}; {} closing lines shed so far",
        account.notices_shed
    )
}

/// Per-pass progress lines (stdout stays parseable): what the pass
/// scanned, which caller incarnations turned over, and what the pass
/// cost — gaps, budget refusals, and suppressed gaps are reported, so a
/// refused or partial run can never look clean. ONE computation with
/// two sinks: stderr on the classic path, the sanitized log tail on
/// the dashboard (which must never scribble beside its screen).
fn progress_lines<Source: ProcessSource>(
    coordinator: &InventoryCoordinator<Source>,
    report: &PassReport,
) -> Vec<String> {
    let mut lines = vec![format!(
        "p11scope: pass {}: {} scanned ({} maps-matched; {} native, {} scan-pinned){}",
        report.pass,
        report.scanned,
        report.maps_matched,
        report.native_callers,
        report.scan_callers,
        if report.pending_refresh.is_empty() {
            String::new()
        } else {
            format!("; {} refresh pending", report.pending_refresh.len())
        }
    )];
    let gaps = coordinator.registry().gaps().len();
    let suppressed = coordinator.registry().gaps_suppressed();
    if gaps > 0 || suppressed > 0 {
        let refusals = coordinator
            .registry()
            .gaps()
            .iter()
            .filter(|gap| gap.budget.is_some())
            .count();
        lines.push(format!(
            "p11scope: pass {}: {} gap{} ({} budget refusal{}, {} suppressed)",
            report.pass,
            gaps,
            if gaps == 1 { "" } else { "s" },
            refusals,
            if refusals == 1 { "" } else { "s" },
            suppressed,
        ));
    }
    if crate::inspect_system::stage_timings_requested() {
        let mut timings = format!(
            "p11scope: pass {}: stage timings: {}",
            report.pass,
            report.timings.ops_line()
        );
        if let Some(high_water) = coordinator.lifecycle_high_water_bytes() {
            timings.push_str(&lifecycle_high_water_suffix(high_water));
        }
        lines.push(timings);
    }
    // Admission failures aggregate past one per pass, like their gaps.
    let failed: Vec<(u32, &str)> = report
        .events
        .iter()
        .filter_map(|event| match event {
            CallerEvent::AdmitFailed { pid, reason, .. } => Some((*pid, reason.as_str())),
            _ => None,
        })
        .collect();
    if let [(first, reason), _, ..] = failed.as_slice() {
        lines.push(format!(
            "p11scope: pass {}: {} caller admissions failed; first: pid {first}: {}",
            report.pass,
            failed.len(),
            crate::render::escape_controls(reason)
        ));
    }
    for event in &report.events {
        if failed.len() > 1 && matches!(event, CallerEvent::AdmitFailed { .. }) {
            continue;
        }
        let line = match event {
            CallerEvent::Admitted { id } => {
                let pid = coordinator
                    .adapter()
                    .record(*id)
                    .map(|record| record.pid)
                    .map_or_else(|| "unknown".to_string(), |pid| pid.to_string());
                format!("caller {} admitted (pid {pid})", id.label())
            }
            CallerEvent::Exited { id, reason } => {
                format!(
                    "caller {} exited: {}",
                    id.label(),
                    crate::render::escape_controls(reason)
                )
            }
            CallerEvent::Retired { id, reason } => {
                format!(
                    "caller {} retired: {}",
                    id.label(),
                    crate::render::escape_controls(reason)
                )
            }
            CallerEvent::ExecRetired { old, new } => {
                format!("caller {} exec-retired, now {}", old.label(), new.label())
            }
            CallerEvent::Reused { old, new } => {
                format!("caller {} reused, now {}", old.label(), new.label())
            }
            CallerEvent::AdmitFailed { pid, reason, .. } => {
                // The reason carries error text (paths, OS messages).
                format!(
                    "caller admission failed for pid {pid}: {}",
                    crate::render::escape_controls(reason)
                )
            }
        };
        lines.push(format!("p11scope: pass {}: {line}", report.pass));
    }
    lines
}

fn caller_json(
    caller: &crate::inventory_present::CallerView,
    metadata: &crate::caller_metadata::runtime::MetadataFrame,
) -> serde_json::Value {
    let record = caller;
    let (task_cookie, exec_id) = match record.authority {
        ImageAuthority::NativeExact {
            task_cookie,
            exec_id,
        } => (
            serde_json::Value::from(task_cookie),
            serde_json::Value::from(exec_id),
        ),
        ImageAuthority::ScanPinned => (serde_json::Value::Null, serde_json::Value::Null),
    };
    let exe = record.exe.as_ref().map(|exe| {
        serde_json::json!({
            "dev": exe.dev,
            "ino": exe.ino,
            "mtime_secs": exe.mtime_secs,
            "mtime_nanos": exe.mtime_nanos,
            "path": exe.path,
        })
    });
    let mut value = serde_json::json!({
        "id": record.id.label(),
        "pid": record.pid,
        "start_time": record.start_time,
        "start_time_unit": "clock_ticks_since_boot",
        "incarnation": record.incarnation,
        "image": {
            "authority": record.authority.label(),
            "task_cookie": task_cookie,
            "exec_id": exec_id,
            "exe": exe,
            "exec_observed": record.exec_observed,
        },
        "lifecycle": record.lifecycle.label(),
        "lifecycle_reason": record.lifecycle_reason,
        "first_seen_ns": record.first_seen_ns,
        "last_seen_ns": record.last_seen_ns,
        "retired": record.retired,
    });
    if let Some(metadata) = metadata.metadata(record.id) {
        value["metadata"] = serde_json::to_value(metadata).expect("finite metadata");
    }
    value
}

fn module_json(module: &crate::inventory_present::ModuleView) -> serde_json::Value {
    let record = module;
    let sha256 = record
        .sha256
        .clone()
        .map(serde_json::Value::from)
        .unwrap_or(serde_json::Value::Null);
    serde_json::json!({
        "id": record.id.label(),
        "paths": record.paths.iter().collect::<Vec<_>>(),
        "identity": {
            "device": {"major": record.device_major, "minor": record.device_minor},
            "inode": record.inode,
            "sha256": sha256,
            "build_id": record.build_id,
            "source": record.identity_source,
        },
        "admission": {
            "state": record.admission.label(),
            "class": record.admission_class,
            "endpoints": record.admission_endpoints,
            "reasons": record.admission_reasons,
            "note": crate::inspect_system::SCAN_ONLY_NOTE,
            // Additive (v1): admission-state changes after the first
            // verdict, in order; `[]` while the first verdict stands.
            "history": record.admission_history.iter().map(|change| serde_json::json!({
                "from": change.from.label(),
                "to": change.to.label(),
                "at_ns": change.at_ns,
            })).collect::<Vec<_>>(),
        },
        "lifecycle": record.lifecycle.label(),
        "unloaded_observed": record.unloaded_observed,
        "unbound_use": record.unbound_use.as_ref().map(|unbound| serde_json::json!({
            "first_ns": unbound.first_ns,
            "rows": unbound.rows,
            "reasons": unbound.reasons,
        })),
    })
}

pub(crate) fn edge_json(edge: &crate::inventory_present::EdgeView) -> serde_json::Value {
    serde_json::json!({
        "caller": edge.caller.label(),
        "module": edge.module.label(),
        "mapping": {
            "state": edge.mapping.label(),
            "evidence": edge.mapping_evidence.label(),
            "reason": edge.mapping_reason,
            "first_seen_ns": edge.mapping_first_seen_ns,
            "last_seen_ns": edge.mapping_last_seen_ns,
            "interruptions": edge.mapping_interruptions,
        },
        "entries": {
            "count": edge.entry_count,
            "saturated": edge.entry_saturated,
            "cap": crate::discovery::caller_registry::MAX_EDGE_ENTRY_COUNT,
            "first_seen_ns": edge.entry_first_seen_ns,
            "last_seen_ns": edge.entry_last_seen_ns,
            "in_flight": edge.entry_in_flight,
            "observation": edge.entry_observation,
            "coverage": coverage_json(&edge.coverage),
        },
        // S1: the summary label (`observed`, or the `unknown` reason),
        // plus — only when the edge holds claims — the mechanism rows
        // and operation aggregates. Unknown edges keep the exact U0
        // label with null details, never an invented state.
        "semantics": edge.semantics.label,
        "mechanisms": mechanisms_json(&edge.semantics.mechanisms),
        "operations": operations_json(edge.semantics.operations.as_ref()),
    })
}

pub(crate) fn instance_json(
    instance: &crate::inventory_present::InstanceView,
) -> serde_json::Value {
    serde_json::json!({
        "id": instance.id.label(), "caller": instance.caller.label(),
        "module": instance.module.label(), "state": instance.state.label(),
        "reason": instance.reason, "first_seen_ns": instance.first_seen_ns,
        "last_seen_ns": instance.last_seen_ns,
    })
}

pub(crate) fn instance_semantic_json(
    edge: &crate::inventory_present::InstanceSemanticView,
) -> serde_json::Value {
    serde_json::json!({
        "caller": edge.caller.label(), "module": edge.module.label(),
        "instance": edge.instance.label(),
        "entries": { "unit": "api_entries", "count": null, "observation": "unavailable" },
        "api_returns": { "unit": "api_returns", "count": edge.api_returns,
            "saturated": edge.saturated, "historical_only_returns": edge.historical_only_returns },
        "semantics": edge.semantics.label,
        "mechanisms": mechanisms_json(&edge.semantics.mechanisms),
        "operations": operations_json(edge.semantics.operations.as_ref()),
        "coverage": { "lossy": edge.lossy, "reasons": edge.reasons },
    })
}

/// Additive (v1) per-edge usage coverage: the state, its instants
/// (`since_ns` for counted and watched, `until_ns` for a watch that
/// ended — the last proven-clean instant — and `first_ns` for
/// witnessed), the lossy flag (counted only; `null` otherwise), and —
/// for unknown — the reason code plus its detail. Every key is always
/// present (`null` when it does not apply), so consumers see one shape.
fn coverage_json(coverage: &UseCoverage) -> serde_json::Value {
    let (since_ns, until_ns, first_ns, lossy, reason, detail) = match coverage {
        UseCoverage::Counted { since_ns, lossy } => {
            (Some(*since_ns), None, None, Some(*lossy), None, None)
        }
        UseCoverage::Witnessed { first_ns } => (None, None, Some(*first_ns), None, None, None),
        UseCoverage::WatchedNoUse { since_ns, until_ns } => {
            (Some(*since_ns), *until_ns, None, None, None, None)
        }
        UseCoverage::Unknown(reason) => {
            (None, None, None, None, Some(reason.code()), reason.detail())
        }
    };
    serde_json::json!({
        "state": coverage.state(),
        "since_ns": since_ns,
        "until_ns": until_ns,
        "first_ns": first_ns,
        "lossy": lossy,
        "reason": reason,
        "detail": detail,
    })
}

/// S1 mechanism rows: verbatim ids (+ hex), registered names (null
/// for vendor/unregistered ids), operation categories, counts,
/// recency, and provenance. `null` when no mechanism was attributed
/// (unknown edges, or operation-only evidence) — never `[]`-as-fact.
fn mechanisms_json(mechanisms: &[crate::inventory_present::MechanismView]) -> serde_json::Value {
    if mechanisms.is_empty() {
        return serde_json::Value::Null;
    }
    serde_json::Value::Array(
        mechanisms
            .iter()
            .map(|mech| {
                serde_json::json!({
                    "mechanism": mech.id,
                    "mechanism_hex": format!("0x{:x}", mech.id),
                    "name": mech.name,
                    "operations": mech.operations,
                    "calls": mech.calls,
                    "errors": mech.errors,
                    "last_seen_ns": mech.last_seen_ns,
                    "evidence": {
                        "functions": mech.functions,
                        "returns": mech.returns.iter().map(|rv| serde_json::json!({
                            "rv": rv,
                            "rv_hex": format!("0x{rv:x}"),
                            "name": crate::semantics_edge::rv_name(*rv),
                        })).collect::<Vec<_>>(),
                        "truncated": mech.truncated,
                    },
                })
            })
            .collect(),
    )
}

/// S1 operation aggregates: separate API-call and operation counts,
/// explicit end states, unknown-origin orphans, bound refusals, and
/// the live machines. `null` exactly when the edge holds no claims.
fn operations_json(
    operations: Option<&crate::inventory_present::OperationsView>,
) -> serde_json::Value {
    let Some(operations) = operations else {
        return serde_json::Value::Null;
    };
    serde_json::json!({
        "calls": operations.calls,
        "started": operations.started,
        "completed": operations.completed,
        "cancelled": operations.cancelled,
        "failed": operations.failed,
        "unknown": operations.unknown,
        "orphans": operations.orphans,
        "dropped": operations.dropped,
        "last_seen_ns": operations.last_seen_ns,
        "active": operations.active.iter().map(|op| serde_json::json!({
            "category": op.category,
            "state": op.state,
            "count": op.count,
        })).collect::<Vec<_>>(),
        "evidence": {
            "state_reconciliations": operations.evidence.state_reconciliations,
            "session_cancel_ambiguities": operations.evidence.session_cancel_ambiguities,
            "session_cancel_unknown_flags": operations.evidence.session_cancel_unknown_flags,
            "operation_state_imports": operations.evidence.operation_state_imports,
            "auth_state_ambiguities": operations.evidence.auth_state_ambiguities,
            "semantic_capture_failures": operations.evidence.semantic_capture_failures,
            "async_duplicates": operations.evidence.async_duplicates,
            "async_evictions": operations.evidence.async_evictions,
            "unmatched_closes": operations.evidence.unmatched_closes,
        },
    })
}

/// Render the published snapshot as `p11scope/inventory/v1` from the
/// ONE presentation model. Every edge endpoint resolves: a dangling
/// reference is a coordinator bug, and the debug assertion names it
/// instead of emitting a partial document. Generic over the process
/// source so scripted scale workloads render through this same path —
/// never a second renderer. Test-gated: the in-crate harness renders
/// through here; production captures once and renders JSON, snapshot,
/// dashboard, and stream from the shared [`Presentation`].
#[cfg(test)]
pub(crate) fn render_json<Source: ProcessSource>(
    coordinator: &InventoryCoordinator<Source>,
    scope_label: &str,
    started_ns: u64,
    ended_ns: u64,
    passes: u64,
) -> serde_json::Value {
    let presentation =
        Presentation::capture(coordinator, scope_label, started_ns, ended_ns, passes);
    render_json_from_presentation(&presentation)
}

/// Stages the scope-level `pid namespace` gap when `/proc` PIDs are not
/// the kernel's (nested observer or foreign `/proc`); it publishes with the
/// first pass, so the snapshot and the event stream carry it alike.
fn stage_numbering_gap<S: ProcessSource>(
    coordinator: &mut InventoryCoordinator<S>,
    numbering: &crate::pidns::PidNumbering,
) {
    if let Some((subject, reason)) = crate::pidns::numbering_gap(numbering) {
        coordinator.note_scope_gap(subject.to_string(), reason);
    }
}

/// The JSON document from an already-captured presentation: the same
/// bytes `render_json` emits, callable wherever a snapshot is already
/// in hand (dashboard agreement checks, event emission).
pub(crate) fn render_json_from_presentation(presentation: &Presentation) -> serde_json::Value {
    debug_assert!(
        presentation.edges.iter().all(|edge| presentation
            .callers
            .iter()
            .any(|caller| caller.id == edge.caller)),
        "every rendered edge caller resolves in the presentation"
    );
    let gaps: Vec<serde_json::Value> = presentation
        .gaps
        .iter()
        .map(|gap| {
            serde_json::json!({
                "caller": gap.caller.map(|caller| caller.label()),
                "module": gap.module.map(|module| module.label()),
                "pid": gap.pid,
                "subject": gap.subject,
                "reason": gap.reason,
                "budget": gap.budget.map(|refusal| serde_json::json!({
                    "resource": refusal.resource,
                    "limit": refusal.limit,
                    "requested": refusal.requested,
                })).unwrap_or(serde_json::Value::Null),
                "repeats": gap.repeats,
            })
        })
        .collect();
    serde_json::json!({
        "schema": DOC_ID,
        "caller_metadata": presentation.caller_metadata.summary.json(),
        "scope": presentation.scope_label,
        "clock": {
            "basis": crate::discovery::caller_registry::CLOCK_BASIS,
            "unit": crate::discovery::caller_registry::CLOCK_UNIT,
        },
        "observation": {
            "started_ns": presentation.started_ns,
            "ended_ns": presentation.ended_ns,
            "passes": presentation.passes,
            "usage_feed": presentation.usage_feed,
            "native_witnesses": native_witnesses_json(
                &presentation.native_witnesses,
                presentation.witness_placement,
            ),
            "semantic_capture": presentation.semantic_capture.json(),
        },
        "budgets": budgets_json(&presentation.budgets),
        "callers": presentation.callers.iter().map(|caller| caller_json(caller, &presentation.caller_metadata)).collect::<Vec<_>>(),
        "modules": presentation.modules.iter().map(module_json).collect::<Vec<_>>(),
        "edges": presentation.edges.iter().map(edge_json).collect::<Vec<_>>(),
        "instances": presentation.instances.iter().map(instance_json).collect::<Vec<_>>(),
        "semantic_edges": presentation.semantic_edges.iter().map(instance_semantic_json).collect::<Vec<_>>(),
        "object_observations": crate::key_operation_projection::object_observations_json(&presentation.object_observations),
        "gaps": gaps,
        "gaps_suppressed": presentation.gaps_suppressed,
        // Additive (v1, DR-K8S-2): caller PIDs are this observer's /proc
        // numbering; the kernel's are the initial namespace's.
        "pid_namespace": crate::pidns::PidNamespaceEvidence::of(crate::pidns::numbering()),
    })
}

/// The native binder census (Task 6 C4): every witness row once, bound to a
/// caller incarnation or unbound with its reason, plus rows still waiting
/// for their lifecycle horizon and rows that failed validation. All zero in
/// the scan lane. The unbound ratio is `unbound / rows`.
fn native_witnesses_json(
    census: &crate::discovery::native_binding::BindingCensus,
    placement: crate::discovery::caller_registry::WitnessPlacement,
) -> serde_json::Value {
    serde_json::json!({
        "placement": {
            "edge": placement.edge,
            "module": placement.module,
            "ambiguous": placement.ambiguous,
            "unresolved": placement.unresolved,
        },
        "rows": census.rows,
        "bound": census.bound,
        "unbound": census.unbound_total(),
        "pending": census.pending,
        "integrity": census.integrity,
        "unbound_reasons": census
            .unbound
            .iter()
            .map(|(reason, count)| (reason.code().to_string(), serde_json::json!(count)))
            .collect::<serde_json::Map<_, _>>(),
    })
}

/// Every budgeted resource with its own limit, occupancy source, and
/// loss counter. Semantic state renders its real occupancy: zero with
/// `withheld` status while the scan lane runs alone, held states with
/// `observed` status once the semantic feed materializes any.
fn budgets_json(budgets: &crate::inventory_present::BudgetView) -> serde_json::Value {
    let resources = &budgets.instance_semantic_resources;
    let charges = resources.charges;
    let usage = resources.occupancy;
    serde_json::json!({
        "callers": {
            "limit": budgets.callers_limit,
            "occupied": budgets.callers_occupied,
            "refused": budgets.callers_refused,
        },
        "modules": {
            "limit": budgets.modules_limit,
            "occupied": budgets.modules_occupied,
            "refused": budgets.modules_refused,
        },
        "edges": {
            "limit": budgets.edges_limit,
            "occupied": budgets.edges_occupied,
            "refused": budgets.edges_refused,
        },
        "endpoints": {
            "limit": budgets.endpoints_limit,
            "occupied": budgets.endpoints_occupied,
            "refused": budgets.endpoints_refused,
        },
        // Additive (v1): the run's Inventory attach set — the
        // capture-lifetime endpoint budget its admission verdicts are
        // judged against, and the endpoints it holds.
        "inventory_endpoints": {
            "limit": budgets.inventory_endpoints_limit,
            "occupied": budgets.inventory_endpoints_occupied,
            "refused": budgets.inventory_endpoints_refused,
        },
        "inventory_attach_modules": {
            "limit": budgets.inventory_modules_limit,
            "occupied": budgets.inventory_modules_occupied,
            "refused": budgets.inventory_modules_refused,
        },
        "counters": {
            "cap": crate::discovery::caller_registry::MAX_EDGE_ENTRY_COUNT,
            "observed_edges": budgets.counters_observed,
            "saturated_edges": budgets.counters_saturated,
        },
        "semantic_state": {
            "limit": budgets.semantic_limit,
            "occupied": budgets.semantic_occupied,
            "status": crate::inventory_present::semantic_status(budgets),
            "unknown_edges": budgets.semantic_unknown_edges,
            "refused": budgets.semantic_refused,
        },
        "instances": {
            "limit": budgets.instances_limit, "occupied": budgets.instances_occupied,
            "refused": budgets.instances_refused,
        },
        "instance_semantic_state": {
            "limit": budgets.semantic_limit.min(budgets.instances_limit),
            "occupied": budgets.instance_semantic_occupied,
            "unknown_edges": budgets.instance_semantic_unknown_edges,
            "refused": budgets.instance_semantic_refused,
            "shared_limit": budgets.semantic_limit,
            "shared_occupied": budgets.semantic_occupied + budgets.instance_semantic_occupied,
        },
        "instance_negative_state": {
            "limit": budgets.instance_negative_limit, "occupied": budgets.instance_negative_occupied,
            "refused": budgets.instance_negative_refused, "exhausted": budgets.instance_negative_exhausted,
        },
        "instance_semantic_resources": {
            "limit_bytes": charges.limit_bytes,
            "charged_bytes": charges.charged_bytes,
            "peak_charged_bytes": charges.peak_charged_bytes,
            "refused": charges.refused,
            "occupancy": {
                "open_bindings": usage.open_bindings,
                "active_machines": usage.active_machines,
                "pending_calls": usage.pending_calls,
                "detached_calls": usage.detached_calls,
                "mechanisms": usage.mechanisms,
                "operation_categories": usage.operation_categories,
                "provenance_functions": usage.provenance_functions,
                "provenance_function_bytes": usage.provenance_function_bytes,
                "provenance_function_capacity_bytes": usage.provenance_function_capacity_bytes,
                "provenance_returns": usage.provenance_returns,
                "async_function_bytes": usage.async_function_bytes,
                "async_function_capacity_bytes": usage.async_function_capacity_bytes,
                "origin_vectors": usage.origin_vectors,
                "origin_elements": usage.origin_elements,
                "origin_capacity_elements": usage.origin_capacity_elements,
            },
        },
        "retained_history": {
            "limit": budgets.retained_limit,
            "retained": budgets.retained,
            "suppressed": budgets.retained_suppressed,
        },
        // Additive (v1, R-C51-5): the native lane's pre-admission stash;
        // absent in the scan lane.
        "native_preadmission": budgets.preadmission.map(|stash| serde_json::json!({
            "limit": stash.limit,
            "occupied": stash.held,
            "refused": stash.refused,
            "pruned": stash.pruned,
        })),
    })
}

/// Test-gated companion to [`render_json`]: the pager snapshot from a
/// live coordinator. Production renders from the shared
/// [`Presentation`] via [`render_snapshot`].
#[cfg(test)]
pub(crate) fn render_text<Source: ProcessSource>(
    coordinator: &InventoryCoordinator<Source>,
    scope_label: &str,
    started_ns: u64,
    ended_ns: u64,
    passes: u64,
) -> String {
    // The pager-friendly snapshot IS the text summary: the same
    // presentation model the JSON renders, in diffable text form.
    let presentation =
        Presentation::capture(coordinator, scope_label, started_ns, ended_ns, passes);
    render_snapshot(&presentation)
}

#[cfg(test)]
mod tests {
    #[test]
    fn owner_terminal_error_preserves_primary_and_typed_interruption() {
        let error = super::combine_semantic_terminal_errors(
            Some(anyhow::anyhow!("capture failed")),
            Err(crate::attach::CleanupInterrupted.into()),
        )
        .unwrap_err();
        assert_eq!(crate::run::failure_exit_code(&error), 130);
        assert!(!crate::run::failure_already_reported(&error));
        assert!(format!("{error:#}").contains("capture failed"));
        let error = super::combine_semantic_terminal_errors(
            None,
            Err(crate::attach::CleanupInterrupted.into()),
        )
        .unwrap_err();
        assert_eq!(crate::run::failure_exit_code(&error), 130);
        assert!(crate::run::failure_already_reported(&error));
    }

    #[test]
    fn edge_json_repeats_the_entries_coverage_at_the_edge_level() {
        // Ledger consumers judge the edge as a whole: the top-level
        // coverage repeats the entries coverage object, so both paths
        // carry the same state.
        let edge = crate::inventory_present::EdgeView {
            caller: crate::discovery::caller_registry::CallerId(0),
            module: crate::discovery::caller_registry::ModuleId(1),
            mapping: crate::discovery::caller_registry::MappingState::Mapped,
            mapping_reason: None,
            mapping_evidence: crate::discovery::caller_registry::MappingEvidence::DeepScan,
            mapping_first_seen_ns: 100,
            mapping_last_seen_ns: 200,
            mapping_interruptions: 0,
            entry_count: 1,
            entry_saturated: false,
            entry_first_seen_ns: Some(120),
            entry_last_seen_ns: Some(180),
            entry_in_flight: false,
            entry_observation: "observed",
            coverage: crate::discovery::caller_registry::UseCoverage::Counted {
                since_ns: 110,
                lossy: false,
            },
            presence: crate::inventory_present::Presence::Mapped,
            capture: crate::inventory_present::Capture::Armed,
            activity: crate::inventory_present::Activity::RecentlyObserved,
            semantics: crate::inventory_present::EdgeSemanticsView {
                label: crate::discovery::caller_registry::SEMANTIC_UNKNOWN,
                mechanisms: Vec::new(),
                operations: None,
            },
        };
        let payload = super::edge_json(&edge);
        assert_eq!(
            payload["coverage"], payload["entries"]["coverage"],
            "the edge level repeats the entries coverage object"
        );
        assert_eq!(payload["coverage"]["state"], "counted");
        assert_eq!(payload["coverage"]["lossy"], false);
    }

    #[test]
    fn cgroup_stop_acceptance_inherited_fd_child() {
        if std::env::var_os("P11SCOPE_CGROUP_STOP_TEST_CHILD").is_none() {
            return;
        }
        let _state = super::CgroupDriverState::new(None, None).unwrap();
    }

    #[test]
    fn cgroup_stop_acceptance_inherited_controller_fd_is_armed() {
        use std::io::{Read, Write};
        use std::os::fd::AsRawFd;
        use std::os::unix::net::UnixStream;
        use std::os::unix::process::CommandExt;
        let (mut controller, observer) = UnixStream::pair().unwrap();
        controller
            .set_read_timeout(Some(std::time::Duration::from_secs(2)))
            .unwrap();
        controller
            .write_all(b"{\"version\":1,\"stage\":\"traversed\",\"timeout_ms\":2000,\"pid\":0,\"start_time\":0}\n")
            .unwrap();
        let fd = observer.as_raw_fd();
        let mut command = std::process::Command::new(std::env::current_exe().unwrap());
        command
            .args([
                "--exact",
                "inventory::tests::cgroup_stop_acceptance_inherited_fd_child",
            ])
            .env("P11SCOPE_CGROUP_STOP_TEST_CHILD", "1")
            .env("P11SCOPE_CGROUP_STOP_FD", fd.to_string());
        // Only the selected socket is inherited by this isolated test child.
        unsafe {
            command.pre_exec(move || {
                if libc::fcntl(fd, libc::F_SETFD, 0) == -1 {
                    return Err(std::io::Error::last_os_error());
                }
                Ok(())
            });
        }
        let mut child = command.spawn().unwrap();
        drop(observer);
        let mut first = [0_u8; 1];
        let observed = controller.read(&mut first);
        let status = child.wait().unwrap();
        assert!(status.success(), "observer setup child failed");
        assert!(
            matches!(observed, Ok(1)) && first[0] == b'{',
            "inherited controller socket must receive an armed stage observer, got {observed:?}"
        );
    }

    #[test]
    fn cgroup_stop_acceptance_absent_selector_performs_no_socket_io() {
        use std::io::{Read, Write};
        use std::os::fd::AsRawFd;
        use std::os::unix::net::UnixStream;
        use std::os::unix::process::CommandExt;
        let (mut controller, mut unselected) = UnixStream::pair().unwrap();
        controller.write_all(b"untouched").unwrap();
        unselected
            .set_read_timeout(Some(std::time::Duration::from_secs(1)))
            .unwrap();
        let fd = unselected.as_raw_fd();
        let mut command = std::process::Command::new(std::env::current_exe().unwrap());
        command
            .args([
                "--exact",
                "inventory::tests::cgroup_stop_acceptance_inherited_fd_child",
            ])
            .env("P11SCOPE_CGROUP_STOP_TEST_CHILD", "1")
            .env_remove("P11SCOPE_CGROUP_STOP_FD");
        unsafe {
            command.pre_exec(move || {
                if libc::fcntl(fd, libc::F_SETFD, 0) < 0 {
                    return Err(std::io::Error::last_os_error());
                }
                Ok(())
            });
        }
        assert!(command.status().unwrap().success());
        let mut bytes = [0; 9];
        unselected.read_exact(&mut bytes).unwrap();
        assert_eq!(&bytes, b"untouched");
    }

    #[test]
    fn cgroup_stop_acceptance_malformed_or_unavailable_descriptor_refuses() {
        for value in ["1", "-1", "not-a-descriptor", "2147483647"] {
            let output = std::process::Command::new(std::env::current_exe().unwrap())
                .args([
                    "--exact",
                    "inventory::tests::cgroup_stop_acceptance_inherited_fd_child",
                ])
                .env("P11SCOPE_CGROUP_STOP_TEST_CHILD", "1")
                .env("P11SCOPE_CGROUP_STOP_FD", value)
                .output()
                .unwrap();
            assert!(
                !output.status.success(),
                "invalid descriptor {value} was accepted"
            );
        }
    }

    #[test]
    fn cgroup_stop_acceptance_regular_file_descriptor_refuses() {
        use std::os::fd::AsRawFd;
        use std::os::unix::process::CommandExt;
        let file = tempfile::tempfile().unwrap();
        let fd = file.as_raw_fd();
        let mut command = std::process::Command::new(std::env::current_exe().unwrap());
        command
            .args([
                "--exact",
                "inventory::tests::cgroup_stop_acceptance_inherited_fd_child",
            ])
            .env("P11SCOPE_CGROUP_STOP_TEST_CHILD", "1")
            .env("P11SCOPE_CGROUP_STOP_FD", fd.to_string());
        unsafe {
            command.pre_exec(move || {
                if libc::fcntl(fd, libc::F_SETFD, 0) < 0 {
                    return Err(std::io::Error::last_os_error());
                }
                Ok(())
            });
        }
        assert!(!command.output().unwrap().status.success());
    }

    use super::*;
    use crate::discovery::caller_registry::{
        AdmissionState, ImageAuthority, ModuleInfo, ModuleKey,
    };

    /// A tempdir the event-writer trust check accepts under any umask:
    /// `tempfile` honors the process umask (0775 under the default 0002),
    /// and the writer refuses group-writable ancestors.
    fn private_tempdir() -> tempfile::TempDir {
        let dir = tempfile::tempdir().unwrap();
        std::fs::set_permissions(
            dir.path(),
            std::os::unix::fs::PermissionsExt::from_mode(0o700),
        )
        .unwrap();
        dir
    }

    fn coordinator() -> InventoryCoordinator<OsProcessSource> {
        InventoryCoordinator::new(
            Scope::Pid(std::process::id()),
            HookRegistry::builtin(),
            Vec::new(),
            OsProcessSource,
            RegistryLimits::default_limits(),
        )
        .unwrap()
    }

    /// Extract one top-level function body from this file's source for the
    /// wiring pin below (the uretprobe loader-contract shape).
    fn pin_body<'a>(
        source: &'a str,
        signature: &str,
        end: &str,
    ) -> std::result::Result<&'a str, String> {
        source
            .split_once(signature)
            .ok_or_else(|| format!("{signature} not found"))?
            .1
            .split_once(end)
            .map(|(body, _)| body)
            .ok_or_else(|| format!("{signature} body end not found"))
    }

    /// A flavor mismatch degrades the semantic lane instead of refusing the
    /// inventory: the lane never goes live, and the gap carries the plain
    /// mismatch message (never the bare attachment code). Fails while the
    /// lane startup skips the flavor check.
    #[test]
    fn semantic_lane_degrades_on_flavor_mismatch_with_plain_message() {
        let planted = crate::attach::EmbeddedFlavor {
            stubbed: !cfg!(feature = "stub-object-attributes"),
            unsafe_present: cfg!(feature = "unsafe-unvalidated-metadata"),
        };
        let _guard = crate::attach::hold_embedded_flavor_for_test(Ok(planted));
        let mut coordinator = coordinator();
        let lane = super::start_semantic_lane(
            &mut coordinator,
            &Scope::Pid(std::process::id()),
            crate::attach::BackendSelection::Auto,
        );
        assert!(
            lane.as_ref().is_none_or(|lane| !lane.is_live()),
            "a flavor mismatch must not start a live lane"
        );
        coordinator.registry_mut().publish();
        let gaps: Vec<(String, String)> = coordinator
            .registry()
            .gaps()
            .iter()
            .map(|gap| (gap.subject.clone(), gap.reason.clone()))
            .collect();
        let (_, reason) = gaps
            .iter()
            .find(|(subject, _)| subject == "semantic lane unavailable")
            .expect("a flavor mismatch must note a semantic-lane gap");
        assert!(reason.contains("stale or mismatched"), "{reason}");
        assert!(reason.contains("FULL"), "{reason}");
        assert!(reason.contains("P0"), "{reason}");
        assert!(!reason.contains("semantic_attachment_refused"), "{reason}");
        let startup = pin_body(
            include_str!("inventory.rs"),
            "fn start_semantic_lane(",
            "\n}\n",
        )
        .unwrap();
        assert!(
            startup.contains("checked_embedded_flavor"),
            "the flavor check runs up front in start_semantic_lane"
        );
        assert!(
            startup.contains("inventory_diagnostic"),
            "the mismatch also reaches stderr"
        );
    }

    #[test]
    fn inventory_selected_budget_reaches_native_preparation_and_fallback() {
        use crate::attach::BackendSelection;
        for n in [1, 4097, 6531, 8192] {
            let budget = inventory_endpoint_budget(Some(n)).unwrap();
            for mode in [CaptureMode::Scan, CaptureMode::Auto, CaptureMode::Native] {
                for backend in [
                    BackendSelection::Auto,
                    BackendSelection::Multi,
                    BackendSelection::Singles,
                ] {
                    let mut coordinator = InventoryCoordinator::new_with_budget(
                        Scope::System,
                        HookRegistry::builtin(),
                        Vec::new(),
                        OsProcessSource,
                        RegistryLimits::default_limits(),
                        budget,
                    )
                    .unwrap();
                    let prepared = std::cell::Cell::new(None);
                    let result = open_native_lane_with(
                        mode,
                        backend,
                        InspectScope::System,
                        &mut coordinator,
                        |scope, actual_budget, actual_backend| {
                            assert!(matches!(
                                scope,
                                crate::attach::capture::CaptureScope::System
                            ));
                            assert_eq!(actual_backend, backend);
                            prepared.set(Some(actual_budget));
                            anyhow::bail!("controlled native preparation refusal")
                        },
                    );
                    assert_eq!(
                        prepared.get(),
                        (mode != CaptureMode::Scan).then_some(budget)
                    );
                    if mode == CaptureMode::Native {
                        let error = result
                            .err()
                            .expect("forced native must refuse preparation failure");
                        assert!(error.to_string().contains("--capture native"));
                    } else {
                        assert!(result.unwrap().is_none());
                    }
                    assert_eq!(coordinator.attach_set().budget(), budget);
                    coordinator.commit_batch(false).unwrap();
                    let document = render_json(&coordinator, "system", 1, 2, 0);
                    assert_eq!(document["budgets"]["inventory_endpoints"]["limit"], n);
                    assert_eq!(document["budgets"]["endpoints"]["limit"], 1_048_576);
                }
            }
        }
    }

    /// A raw verifier dump must never land in a user-visible gap reason:
    /// a 267 KiB dump once broke `inventory diff` (16,384-byte per-string
    /// limit). The reason names the program, the errno and the processed
    /// count, points at doctor, and stays far below the diff limit; the
    /// synthetic log body must not survive. Both user-visible surfaces
    /// (the auto-mode gap and the native-mode error) carry the summary.
    #[test]
    fn native_preparation_failure_keeps_a_bounded_named_reason() {
        const MARKER: &str = "SYNTHETIC_VERIFIER_BODY_MARKER_9f3c";
        let log = format!(
            "0: R1=ctx R10=fp0\n{MARKER} {}\nprocessed 1000001 insns (limit 1000000) max_states_per_insn 1\n",
            "x".repeat(300 * 1024)
        );
        assert!(
            log.len() > 267 * 1024,
            "the synthetic log must dwarf the dump"
        );
        let failure = || {
            anyhow::Error::from(aya::programs::ProgramError::LoadError {
                io_error: std::io::Error::from_raw_os_error(libc::E2BIG),
                verifier_log: aya_obj::VerifierLog::new(log.clone()),
            })
            .context("Inventory program interface_list_worker")
            .context("preparing Inventory: LoadProgram(\"interface_list_worker\", UProbe)")
        };
        let budget = inventory_endpoint_budget(None).unwrap();
        for mode in [CaptureMode::Auto, CaptureMode::Native] {
            let mut coordinator = InventoryCoordinator::new_with_budget(
                Scope::System,
                HookRegistry::builtin(),
                Vec::new(),
                OsProcessSource,
                RegistryLimits::default_limits(),
                budget,
            )
            .unwrap();
            let result = open_native_lane_with(
                mode,
                crate::attach::BackendSelection::Auto,
                InspectScope::System,
                &mut coordinator,
                |_, _, _| Err(failure()),
            );
            let reason = match mode {
                CaptureMode::Native => {
                    let error = result
                        .err()
                        .expect("forced native must refuse preparation failure");
                    assert!(error.to_string().contains("--capture native"));
                    format!("{error:#}")
                }
                _ => {
                    assert!(result.unwrap().is_none());
                    coordinator.commit_batch(false).unwrap();
                    let document = render_json(&coordinator, "system", 1, 2, 0);
                    document["gaps"]
                        .as_array()
                        .unwrap()
                        .iter()
                        .find(|gap| gap["subject"] == "native usage feed unavailable")
                        .unwrap_or_else(|| panic!("{}", document["gaps"]))["reason"]
                        .as_str()
                        .unwrap()
                        .to_string()
                }
            };
            assert!(
                reason.len() < 16_384,
                "reason must fit the diff per-string limit: {} bytes",
                reason.len()
            );
            assert!(reason.contains("interface_list_worker"), "{reason}");
            assert!(reason.contains("E2BIG"), "{reason}");
            assert!(reason.contains("1000001"), "{reason}");
            assert!(reason.contains("doctor"), "{reason}");
            assert!(!reason.contains(MARKER), "raw log body leaked: {reason}");
            assert!(!reason.contains("SYNTHETIC"), "raw log body leaked");
        }
    }

    #[test]
    fn invalid_inventory_endpoint_budget_precedes_runtime_sinks() {
        let dir = private_tempdir();
        let report = dir.path().join("report.json");
        let event_log = dir.path().join("events.jsonl");
        let diagnostics = dir.path().join("diagnostics.jsonl");
        for capture in [CaptureMode::Scan, CaptureMode::Auto, CaptureMode::Native] {
            for dashboard in [false, true] {
                let error = run(
                    InspectScope::System,
                    &[],
                    &[],
                    &HookRegistry::builtin(),
                    true,
                    None,
                    None,
                    Some(8193),
                    None,
                    Some(&report),
                    dashboard,
                    Some(&event_log),
                    None,
                    None,
                    capture,
                    crate::attach::BackendSelection::Auto,
                    Some(&diagnostics),
                    None,
                    crate::cli::IdentityBackendSelection::Auto,
                    false,
                    crate::cli::CallerMetadataMode::None,
                )
                .unwrap_err();
                assert!(
                    error.to_string().contains("--max-endpoints")
                        && error.to_string().contains("1..=8192")
                );
                assert_eq!(std::fs::read_dir(dir.path()).unwrap().count(), 0);
            }
        }
    }

    fn event_fault(kind: &'static str, after_ended: bool) -> crate::inventory_events::EventFault {
        crate::inventory_events::EventFault {
            kind,
            final_pass_only: false,
            after_ended,
            attempts: Default::default(),
        }
    }

    fn event_records(path: &Path) -> Vec<serde_json::Value> {
        std::fs::read_to_string(path)
            .unwrap()
            .lines()
            .map(|line| serde_json::from_str(line).unwrap())
            .collect()
    }

    #[test]
    fn pass_event_failure_reaches_ordinary_finalization_with_and_without_report() {
        for with_report in [true, false] {
            let dir = private_tempdir();
            let events = dir.path().join("events.jsonl");
            let report = dir.path().join("report.json");
            let fault = event_fault("pass_committed", false);
            let attempts = fault.attempts.clone();
            let finalized = std::cell::Cell::new(false);
            let mut stdout = Vec::new();
            let result = run_with_terminal_inner(
                InspectScope::Pid(std::process::id()),
                &[],
                &HookRegistry::builtin(),
                true,
                None,
                None,
                Some(Duration::from_millis(1100)),
                with_report.then_some(report.as_path()),
                false,
                Some(&events),
                None,
                None,
                CaptureMode::Scan,
                crate::attach::BackendSelection::Auto,
                &|| false,
                &|| finalized.set(true),
                false,
                &mut WriterStdout(&mut stdout),
                &DashboardIo::stdio(),
                Some(fault),
            );
            assert!(
                finalized.get(),
                "a returned event error skipped the finalizer: {result:?}"
            );
            assert_eq!(result.unwrap(), 1);
            let document: serde_json::Value = serde_json::from_slice(&stdout).unwrap();
            assert_eq!(document["observation"]["passes"], 2);
            if with_report {
                assert_eq!(std::fs::read(&report).unwrap(), stdout);
            }
            assert_eq!(
                attempts
                    .borrow()
                    .iter()
                    .filter(|kind| *kind == "pass_committed")
                    .count(),
                1
            );
            assert!(!attempts.borrow().iter().any(|kind| kind == "ended"));
            assert_eq!(event_records(&events).first().unwrap()["kind"], "started");
        }
    }

    #[test]
    fn healthy_scan_outputs_agree_and_event_order_is_complete() {
        let dir = private_tempdir();
        let events = dir.path().join("events.jsonl");
        let report = dir.path().join("report.json");
        let mut stdout = Vec::new();
        let result = run_with_terminal_inner(
            InspectScope::Pid(std::process::id()),
            &[],
            &HookRegistry::builtin(),
            true,
            None,
            None,
            None,
            Some(&report),
            false,
            Some(&events),
            None,
            None,
            CaptureMode::Scan,
            crate::attach::BackendSelection::Auto,
            &|| false,
            &|| {},
            false,
            &mut WriterStdout(&mut stdout),
            &DashboardIo::stdio(),
            None,
        )
        .unwrap();
        assert_eq!(result, 0);
        assert_eq!(std::fs::read(&report).unwrap(), stdout);
        let records = event_records(&events);
        assert_eq!(records.first().unwrap()["kind"], "started");
        assert_eq!(records.last().unwrap()["kind"], "ended");
        assert_eq!(
            records
                .iter()
                .filter(|record| record["kind"] == "pass_committed")
                .count(),
            1
        );
        assert_eq!(
            records
                .iter()
                .filter(|record| record["kind"] == "ended")
                .count(),
            1
        );
    }

    /// Sol-full F2: `-o` and `--event-log` naming one file must be refused
    /// before either sink opens. The event open truncates, and finalization
    /// would otherwise commit the snapshot over the finished JSONL stream
    /// while both sinks report success.
    #[test]
    fn primary_output_collision_is_refused_before_either_sink_opens() {
        let dir = private_tempdir();
        let shared = dir.path().join("result.json");
        std::fs::write(&shared, b"existing event log\n").unwrap();
        let mut stdout = Vec::new();
        let result = run_with_terminal_inner(
            InspectScope::Pid(std::process::id()),
            &[],
            &HookRegistry::builtin(),
            true,
            None,
            None,
            None,
            Some(&shared),
            false,
            Some(&shared),
            None,
            None,
            CaptureMode::Scan,
            crate::attach::BackendSelection::Auto,
            &|| false,
            &|| {},
            false,
            &mut WriterStdout(&mut stdout),
            &DashboardIo::stdio(),
            None,
        );
        assert_eq!(std::fs::read(&shared).unwrap(), b"existing event log\n");
        assert!(
            result.unwrap_err().to_string().contains("aliases"),
            "same-path report/event destinations must be refused loudly"
        );
        assert!(stdout.is_empty());
    }

    /// Sol-full F2: a report inside the event rotation namespace
    /// (`<live>.<seq>`) would replace a retained rotation at commit.
    #[test]
    fn primary_output_in_rotation_namespace_is_refused_before_event_creation() {
        let dir = private_tempdir();
        let events = dir.path().join("events.jsonl");
        let report = dir.path().join("events.jsonl.1");
        let mut stdout = Vec::new();
        let result = run_with_terminal_inner(
            InspectScope::Pid(std::process::id()),
            &[],
            &HookRegistry::builtin(),
            true,
            None,
            None,
            None,
            Some(&report),
            false,
            Some(&events),
            None,
            None,
            CaptureMode::Scan,
            crate::attach::BackendSelection::Auto,
            &|| false,
            &|| {},
            false,
            &mut WriterStdout(&mut stdout),
            &DashboardIo::stdio(),
            None,
        );
        let message = result.unwrap_err().to_string();
        assert!(
            message.contains("rotation"),
            "unexpected rotation-namespace refusal: {message}"
        );
        assert!(!events.exists(), "event stream must not be created");
        assert!(!report.exists(), "report must not be created");
        assert!(stdout.is_empty());
    }

    /// Sol-full F2: a report hardlinked to the live event file is the same
    /// collision under distinct names; the pre-existing stream survives.
    #[test]
    fn primary_output_hardlink_alias_is_refused_without_truncation() {
        let dir = private_tempdir();
        let events = dir.path().join("events.jsonl");
        let report = dir.path().join("report.json");
        std::fs::write(&events, b"existing event log\n").unwrap();
        std::fs::hard_link(&events, &report).unwrap();
        let mut stdout = Vec::new();
        let result = run_with_terminal_inner(
            InspectScope::Pid(std::process::id()),
            &[],
            &HookRegistry::builtin(),
            true,
            None,
            None,
            None,
            Some(&report),
            false,
            Some(&events),
            None,
            None,
            CaptureMode::Scan,
            crate::attach::BackendSelection::Auto,
            &|| false,
            &|| {},
            false,
            &mut WriterStdout(&mut stdout),
            &DashboardIo::stdio(),
            None,
        );
        assert_eq!(std::fs::read(&events).unwrap(), b"existing event log\n");
        assert!(
            result.unwrap_err().to_string().contains("aliases"),
            "hardlinked report/event destinations must be refused loudly"
        );
        assert!(stdout.is_empty());
    }

    /// Sol-full F2 validator twins: normalized spellings and rotation names
    /// collide without existing files; unrelated or absent destinations pass
    /// and create nothing.
    #[test]
    fn primary_destination_aliases_reject_collisions_and_keep_unrelated() {
        let dir = private_tempdir();
        let events = dir.path().join("events.jsonl");
        let report = dir.path().join("report.json");
        validate_primary_destinations(Some(&report), Some(&events)).unwrap();
        assert!(!events.exists() && !report.exists());
        validate_primary_destinations(Some(&events), Some(&events)).unwrap_err();
        let dotted = dir.path().join("./events.jsonl");
        validate_primary_destinations(Some(&dotted), Some(&events)).unwrap_err();
        let rotated = dir.path().join("events.jsonl.2");
        validate_primary_destinations(Some(&rotated), Some(&events)).unwrap_err();
        // A non-canonical suffix is outside the rotation namespace.
        let padded = dir.path().join("events.jsonl.02");
        validate_primary_destinations(Some(&padded), Some(&events)).unwrap();
        validate_primary_destinations(None, Some(&events)).unwrap();
        validate_primary_destinations(Some(&report), None).unwrap();
        validate_primary_destinations(None, None).unwrap();
    }

    #[test]
    fn initial_event_failure_remains_fail_fast() {
        let dir = private_tempdir();
        let events = dir.path().join("events.jsonl");
        let report = dir.path().join("report.json");
        std::fs::write(&report, "old report").unwrap();
        let finalized = std::cell::Cell::new(false);
        let fault = event_fault("started", false);
        let attempts = fault.attempts.clone();
        let mut stdout = Vec::new();
        let result = run_with_terminal_inner(
            InspectScope::Pid(std::process::id()),
            &[],
            &HookRegistry::builtin(),
            true,
            None,
            None,
            None,
            Some(&report),
            false,
            Some(&events),
            None,
            None,
            CaptureMode::Scan,
            crate::attach::BackendSelection::Auto,
            &|| false,
            &|| finalized.set(true),
            false,
            &mut WriterStdout(&mut stdout),
            &DashboardIo::stdio(),
            Some(fault),
        );
        assert!(
            result
                .unwrap_err()
                .to_string()
                .contains("started append failure")
        );
        assert!(!finalized.get());
        assert!(stdout.is_empty());
        assert_eq!(std::fs::read_to_string(&report).unwrap(), "old report");
        assert_eq!(attempts.borrow().as_slice(), ["started"]);
    }

    /// A partial final write must disclose the exact local prefix, including
    /// when the event sink has independently failed.
    #[test]
    fn incomplete_stdout_discloses_exact_accepted_bytes() {
        struct Prefix {
            accepted: usize,
            total: usize,
        }
        impl std::io::Write for Prefix {
            fn write(&mut self, bytes: &[u8]) -> std::io::Result<usize> {
                if self.accepted == 0 {
                    self.total = bytes.len();
                    let n = bytes.len().min(7);
                    self.accepted = n;
                    Ok(n)
                } else {
                    Err(std::io::ErrorKind::BrokenPipe.into())
                }
            }
            fn flush(&mut self) -> std::io::Result<()> {
                Ok(())
            }
        }
        let mut coordinator = coordinator();
        coordinator.commit_batch(false).unwrap();
        let view = Presentation::capture(&coordinator, "system", 1, 2, 1);
        let mut out = Prefix {
            accepted: 0,
            total: 0,
        };
        let result = finish_output(
            None,
            &mut EventLogState::new(None),
            &mut StreamState::new(),
            &view,
            true,
            false,
            &mut WriterStdout(&mut out),
            None,
            None,
        );
        assert_eq!(result.exit_code(), 1);
        let total = out.total;
        let mut notices = Vec::new();
        result.notices(None, &mut |s| notices.push(s.to_string()));
        assert!(
            notices.iter().any(|s| s.contains(&format!(
                "accepted 7 of {total} bytes; remaining {} not written",
                total - 7
            ))),
            "missing exact prefix account: {notices:?}"
        );
        assert!(!notices.iter().any(|s| s.contains("stdout complete")));
    }

    #[test]
    fn scan_finalization_captures_after_loop_once() {
        use std::os::fd::AsRawFd;
        struct Recorded<'a> {
            inner: FdStdout<'a>,
            begins: usize,
        }
        impl FinalStdout for Recorded<'_> {
            fn begin_finalization(&mut self) {
                self.begins += 1;
                self.inner.begin_finalization();
            }
            fn write_document(&mut self, bytes: &[u8]) -> StdoutResult {
                assert_eq!(
                    self.begins, 1,
                    "scan stdout began before/after the wrong boundary"
                );
                self.inner.write_document(bytes)
            }
        }
        let file = tempfile::NamedTempFile::new().unwrap();
        let mut stdout = Recorded {
            inner: FdStdout::new(file.as_raw_fd(), &|| 0),
            begins: 0,
        };
        let code = run_with_writer(
            InspectScope::System,
            &[],
            &HookRegistry::builtin(),
            true,
            Some(1),
            None,
            None,
            None,
            false,
            None,
            None,
            None,
            CaptureMode::Scan,
            crate::attach::BackendSelection::Auto,
            &|| false,
            &|| {},
            false,
            &mut stdout,
        )
        .unwrap();
        assert_eq!(code, 0);
        assert_eq!(stdout.begins, 1);
        let document: serde_json::Value =
            serde_json::from_slice(&std::fs::read(file.path()).unwrap()).unwrap();
        assert_eq!(document["schema"], DOC_ID);
        assert!(document["observation"].get("lane").is_none());
    }

    #[test]
    fn retired_event_failure_and_incomplete_stdout_remain_independent() {
        use crate::inventory_output::StdoutFailure;
        struct Incomplete {
            cancelled: bool,
            called: bool,
            total: usize,
        }
        impl FinalStdout for Incomplete {
            fn begin_finalization(&mut self) {}
            fn write_document(&mut self, bytes: &[u8]) -> StdoutResult {
                self.called = true;
                self.total = bytes.len();
                Err(StdoutFailure {
                    accepted: 3,
                    total: bytes.len(),
                    reason: if self.cancelled {
                        StdoutFailureReason::Cancelled
                    } else {
                        StdoutFailureReason::NoProgress
                    },
                })
            }
        }
        let mut coordinator = coordinator();
        coordinator.commit_batch(false).unwrap();
        let view = Presentation::capture(&coordinator, "system", 1, 2, 1);
        for cancelled in [false, true] {
            for (json, silent_text) in [(true, false), (false, false), (false, true)] {
                let mut stdout = Incomplete {
                    cancelled,
                    called: false,
                    total: 0,
                };
                let mut stream = EventLogState {
                    writer: None,
                    first_error: Some(
                        "p11scope: inventory event log pass publication failed: injected".into(),
                    ),
                };
                let result = finish_output(
                    None,
                    &mut stream,
                    &mut StreamState::new(),
                    &view,
                    json,
                    silent_text,
                    &mut stdout,
                    None,
                    None,
                );
                let requested = json || !silent_text;
                assert_eq!(result.exit_code(), 1);
                assert_eq!(result.event_log_confirmed, Some(false));
                assert_eq!(result.report_committed, None);
                assert_eq!(stdout.called, requested);
                assert_eq!(result.stdout_cancelled(), requested && cancelled);
                let mut notices = Vec::new();
                result.notices(None, &mut |line| notices.push(line.to_string()));
                assert!(
                    !notices
                        .iter()
                        .any(|line| line.contains("stdout complete")
                            || line.contains("report saved"))
                );
                if requested {
                    assert!(notices.iter().any(|line| line.contains(&format!(
                        "accepted 3 of {} bytes; remaining {} not written",
                        stdout.total,
                        stdout.total - 3
                    ))));
                    assert_eq!(result.failures.len(), 2);
                    assert_eq!(
                        result
                            .stdout_result
                            .as_ref()
                            .unwrap()
                            .as_ref()
                            .unwrap_err()
                            .accepted,
                        3
                    );
                } else {
                    assert!(result.stdout_result.is_none());
                    assert_eq!(result.failures.len(), 1);
                }
            }
        }
    }

    /// Requested sinks settle before stdout is allowed to acquire or cancel.
    /// This remains a strict normal-host gate; output ancestor trust is intact.
    #[test]
    fn requested_sinks_precede_incomplete_stdout() {
        use crate::inventory_events::EventFault;
        use crate::inventory_output::StdoutFailure;
        struct Check<'a> {
            cancelled: bool,
            verify: &'a dyn Fn(&[u8]),
            called: bool,
        }
        impl FinalStdout for Check<'_> {
            fn begin_finalization(&mut self) {}
            fn write_document(&mut self, bytes: &[u8]) -> StdoutResult {
                self.called = true;
                (self.verify)(bytes);
                Err(StdoutFailure {
                    accepted: 3,
                    total: bytes.len(),
                    reason: if self.cancelled {
                        StdoutFailureReason::Cancelled
                    } else {
                        StdoutFailureReason::NoProgress
                    },
                })
            }
        }
        let mut coordinator = coordinator();
        coordinator.commit_batch(false).unwrap();
        let view = Presentation::capture(&coordinator, "system", 1, 2, 1);
        for event_failed in [false, true] {
            for report_failed in [false, true] {
                for cancelled in [false, true] {
                    for (json, silent) in [(true, false), (false, false), (false, true)] {
                        let dir = private_tempdir();
                        let report = dir.path().join("report.json");
                        let old = dir.path().join("old.json");
                        std::fs::write(&old, b"prior report").unwrap();
                        let sink = AtomicFile::create(&report).unwrap();
                        if report_failed {
                            std::os::unix::fs::symlink(&old, &report).unwrap();
                        }
                        let events = dir.path().join("events.jsonl");
                        let attempts = std::rc::Rc::new(std::cell::RefCell::new(Vec::new()));
                        let mut writer = EventWriter::create(&events, 1 << 20, 2).unwrap();
                        writer.fault = Some(EventFault {
                            kind: if event_failed { "ended" } else { "never" },
                            final_pass_only: false,
                            after_ended: false,
                            attempts: attempts.clone(),
                        });
                        let verify = |bytes: &[u8]| {
                            assert!(
                                attempts.borrow().iter().any(|kind| kind == "ended"),
                                "stdout started before the requested event completion attempt"
                            );
                            if report_failed {
                                assert_eq!(std::fs::read(&old).unwrap(), b"prior report");
                                assert!(
                                    std::fs::symlink_metadata(&report)
                                        .unwrap()
                                        .file_type()
                                        .is_symlink()
                                );
                            } else {
                                let committed = std::fs::read(&report).unwrap();
                                let document: serde_json::Value =
                                    serde_json::from_slice(&committed).unwrap();
                                assert_eq!(document["schema"], DOC_ID);
                                if json {
                                    assert_eq!(committed, bytes);
                                }
                            }
                            assert!(
                                !std::fs::read_dir(dir.path()).unwrap().any(|entry| entry
                                    .unwrap()
                                    .file_name()
                                    .to_string_lossy()
                                    .starts_with(".p11scope.")),
                                "stdout started before the report attempt disposed its temp file"
                            );
                        };
                        let mut stdout = Check {
                            cancelled,
                            verify: &verify,
                            called: false,
                        };
                        let result = finish_output(
                            Some(sink),
                            &mut EventLogState::new(Some(writer)),
                            &mut StreamState::new(),
                            &view,
                            json,
                            silent,
                            &mut stdout,
                            None,
                            None,
                        );
                        let requested = json || !silent;
                        assert_eq!(stdout.called, requested);
                        assert_eq!(result.event_log_confirmed, Some(!event_failed));
                        assert_eq!(result.report_committed, Some(!report_failed));
                        assert_eq!(result.stdout_cancelled(), cancelled && requested);
                        assert_eq!(
                            result.exit_code(),
                            i32::from(requested || event_failed || report_failed)
                        );
                        let mut notices = Vec::new();
                        result.notices(None, &mut |line| notices.push(line.to_string()));
                        assert!(!notices.iter().any(|line| line.contains("stdout complete")));
                        assert_eq!(
                            notices.iter().any(|line| line.contains("report saved")),
                            !report_failed && result.exit_code() != 0
                        );
                    }
                }
            }
        }
    }

    /// A cancelled final stdout must not add five seconds of screen retry.
    /// Only the owned child uses the PTY; the parent watchdog never resumes it.
    #[test]
    fn dashboard_cancelled_stdout_skips_restore_wait() {
        use std::os::fd::{AsRawFd, FromRawFd};
        use std::process::{Command, Stdio};
        if let Some(dir) = std::env::var_os("P11SCOPE_DASHBOARD_CANCEL_CHILD") {
            let dir = PathBuf::from(dir);
            struct Cancelled {
                begins: usize,
            }
            impl FinalStdout for Cancelled {
                fn begin_finalization(&mut self) {
                    self.begins += 1;
                }
                fn write_document(&mut self, bytes: &[u8]) -> StdoutResult {
                    assert_eq!(self.begins, 1);
                    Err(crate::inventory_output::StdoutFailure {
                        accepted: 0,
                        total: bytes.len(),
                        reason: StdoutFailureReason::Cancelled,
                    })
                }
            }
            let notices = std::fs::File::create(dir.join("notices")).unwrap();
            let account = std::rc::Rc::new(std::cell::Cell::new(None));
            let terminal = DashboardIo {
                output: 0,
                input: Some(0),
                account: Some(account.clone()),
                stderr_fd: notices.as_raw_fd(),
                stderr: StderrRoute::Leave,
            };
            let stop = || {
                assert_eq!(unsafe { libc::tcflow(0, libc::TCOOFF) }, 0);
                true
            };
            let result = run_with_terminal(
                InspectScope::System,
                &[],
                &HookRegistry::builtin(),
                true,
                Some(1),
                None,
                None,
                None,
                true,
                None,
                None,
                None,
                CaptureMode::Scan,
                crate::attach::BackendSelection::Auto,
                &stop,
                &|| {},
                true,
                &mut Cancelled { begins: 0 },
                &terminal,
            )
            .unwrap();
            assert_eq!(result, 1);
            let terminal = account.take().unwrap().terminal;
            assert!(terminal.restore_retried && !terminal.restored);
            std::fs::write(dir.join("finished"), b"cancelled; restore retry shed\n").unwrap();
            std::process::exit(0);
        }
        let deadline = Instant::now() + Duration::from_millis(4500);
        let dir = private_tempdir();
        let mut master = -1;
        let mut slave = -1;
        assert_eq!(
            unsafe {
                libc::openpty(
                    &mut master,
                    &mut slave,
                    std::ptr::null_mut(),
                    std::ptr::null(),
                    std::ptr::null(),
                )
            },
            0
        );
        let _master = unsafe { std::fs::File::from_raw_fd(master) };
        let slave = unsafe { std::fs::File::from_raw_fd(slave) };
        let mut saved = std::mem::MaybeUninit::uninit();
        assert_eq!(
            unsafe { libc::tcgetattr(slave.as_raw_fd(), saved.as_mut_ptr()) },
            0
        );
        let saved = unsafe { saved.assume_init() };
        struct Owned(std::process::Child);
        impl Drop for Owned {
            fn drop(&mut self) {
                let _ = self.0.kill();
                let _ = self.0.wait();
            }
        }
        let mut child = Owned(
            Command::new(std::env::current_exe().unwrap())
                .args([
                    "--exact",
                    "inventory::tests::dashboard_cancelled_stdout_skips_restore_wait",
                    "--nocapture",
                    "--test-threads=1",
                ])
                .env("P11SCOPE_DASHBOARD_CANCEL_CHILD", dir.path())
                .stdin(Stdio::from(slave.try_clone().unwrap()))
                .stdout(Stdio::null())
                .stderr(Stdio::null())
                .spawn()
                .unwrap(),
        );
        let status = loop {
            if let Some(status) = child.0.try_wait().unwrap() {
                break status;
            }
            assert!(
                Instant::now() < deadline,
                "cancelled stdout waited for the five-second screen retry"
            );
            std::thread::sleep(Duration::from_millis(10));
        };
        assert!(
            status.success(),
            "dashboard cancellation child failed: {status}"
        );
        assert!(dir.path().join("finished").exists());
        let mut actual = std::mem::MaybeUninit::uninit();
        assert_eq!(
            unsafe { libc::tcgetattr(slave.as_raw_fd(), actual.as_mut_ptr()) },
            0
        );
        let actual = unsafe { actual.assume_init() };
        assert_eq!(
            actual.c_lflag, saved.c_lflag,
            "saved input termios was not restored"
        );
        assert_eq!(actual.c_cc, saved.c_cc);
        // The cell has finished while output is stopped. Resume only in owned cleanup.
        assert_eq!(unsafe { libc::tcflow(slave.as_raw_fd(), libc::TCOON) }, 0);
    }

    /// Only this owned subprocess aliases stdout/stderr onto its own PTY.
    /// A blocked warning must fail the parent watchdog, never be rescued into
    /// a passing final-output control.
    #[test]
    fn namespace_warning_on_stopped_shared_pty_reaches_finalization() {
        namespace_warning_output_control(true, false);
    }

    #[test]
    fn namespace_warning_on_stopped_shared_pty_without_report_reaches_finalization() {
        namespace_warning_output_control(false, false);
    }

    #[test]
    fn namespace_warning_only_on_stopped_shared_pty_without_report_reaches_finalization() {
        namespace_warning_output_control(false, true);
    }

    fn namespace_warning_output_control(with_report: bool, isolate_progress: bool) {
        use std::os::fd::{AsRawFd, FromRawFd};
        use std::process::{Command, Stdio};
        if let Some(dir) = std::env::var_os("P11SCOPE_NAMESPACE_OUTPUT_CHILD") {
            let dir = PathBuf::from(dir);
            // A separate warning-only control isolates default scan progress.
            // The default-path control retains the progress diagnostics.
            if isolate_progress {
                crate::inspect_system::set_progress_lines(false);
            }
            // stdin is the owned inherited slave. The libtest banner was sent
            // to /dev/null before this child-only descriptor redirection.
            assert_eq!(unsafe { libc::dup2(0, 1) }, 1);
            assert_eq!(unsafe { libc::dup2(0, 2) }, 2);
            std::fs::write(dir.join("ready"), b"warning-path\n").unwrap();
            let report = dir.join("report.json");
            let finalized = dir.join("finalized");
            let code =
                crate::pidns::test_seam::with_numbering(crate::pidns::test_seam::nested(), || {
                    run_with_writer(
                        InspectScope::System,
                        &[],
                        &HookRegistry::builtin(),
                        true,
                        Some(1),
                        None,
                        None,
                        with_report.then_some(report.as_path()),
                        false,
                        None,
                        None,
                        None,
                        CaptureMode::Scan,
                        crate::attach::BackendSelection::Auto,
                        &|| false,
                        &|| {
                            std::fs::write(&finalized, b"output-attempts\n").unwrap();
                        },
                        false,
                        &mut FdStdout::new(1, &|| 0),
                    )
                });
            let code = match code {
                Ok(code) => code,
                Err(error) => {
                    std::fs::write(dir.join("error.txt"), format!("{error:#}")).unwrap();
                    2
                }
            };
            std::process::exit(code);
        }
        struct OwnedChild(std::process::Child);
        impl Drop for OwnedChild {
            fn drop(&mut self) {
                if self.0.try_wait().ok().flatten().is_none() {
                    let _ = self.0.kill();
                    let _ = self.0.wait();
                }
            }
        }
        for stopped in [true, false] {
            let dir = private_tempdir();
            let deadline = Instant::now() + Duration::from_secs(9);
            let mut master_fd = -1;
            let mut slave_fd = -1;
            assert_eq!(
                unsafe {
                    libc::openpty(
                        &mut master_fd,
                        &mut slave_fd,
                        std::ptr::null_mut(),
                        std::ptr::null(),
                        std::ptr::null(),
                    )
                },
                0
            );
            let mut master = unsafe { std::fs::File::from_raw_fd(master_fd) };
            let slave = unsafe { std::fs::File::from_raw_fd(slave_fd) };
            let mut attrs = unsafe { std::mem::zeroed::<libc::termios>() };
            assert_eq!(unsafe { libc::tcgetattr(slave.as_raw_fd(), &mut attrs) }, 0);
            attrs.c_oflag &= !(libc::OPOST | libc::ONLCR);
            assert_eq!(
                unsafe { libc::tcsetattr(slave.as_raw_fd(), libc::TCSANOW, &attrs) },
                0
            );
            if stopped {
                assert_eq!(unsafe { libc::tcflow(slave.as_raw_fd(), libc::TCOOFF) }, 0);
            }
            let flags = unsafe { libc::fcntl(master.as_raw_fd(), libc::F_GETFL) };
            assert_eq!(
                unsafe { libc::fcntl(master.as_raw_fd(), libc::F_SETFL, flags | libc::O_NONBLOCK) },
                0
            );
            let mut bytes = Vec::new();
            let mut buf = [0; 4096];
            use std::io::Read;
            let mut child = OwnedChild(Command::new(std::env::current_exe().unwrap())
                .args(["--exact", if with_report { "inventory::tests::namespace_warning_on_stopped_shared_pty_reaches_finalization" }
                    else if isolate_progress { "inventory::tests::namespace_warning_only_on_stopped_shared_pty_without_report_reaches_finalization" }
                    else { "inventory::tests::namespace_warning_on_stopped_shared_pty_without_report_reaches_finalization" },
                    "--nocapture", "--test-threads=1"])
                .env("P11SCOPE_NAMESPACE_OUTPUT_CHILD", dir.path())
                .stdin(Stdio::from(slave.try_clone().unwrap()))
                .stdout(Stdio::null()).stderr(Stdio::null()).spawn().unwrap());
            let status = loop {
                if !stopped {
                    while let Ok(n) = master.read(&mut buf) {
                        if n == 0 {
                            break;
                        }
                        bytes.extend_from_slice(&buf[..n]);
                    }
                }
                if let Some(status) = child.0.try_wait().unwrap() {
                    break status;
                }
                assert!(
                    Instant::now() < deadline,
                    "namespace warning watchdog: stopped={stopped}; owned child killed/reaped on failure"
                );
                std::thread::sleep(Duration::from_millis(10));
            };
            assert!(
                dir.path().join("ready").exists(),
                "child never reached warning path"
            );
            assert_eq!(
                status.code(),
                Some(i32::from(stopped)),
                "child failure: {}",
                std::fs::read_to_string(dir.path().join("error.txt")).unwrap_or_default()
            );
            assert!(
                dir.path().join("finalized").is_file(),
                "warning path skipped output finalization"
            );
            if with_report {
                let document: serde_json::Value =
                    serde_json::from_slice(&std::fs::read(dir.path().join("report.json")).unwrap())
                        .unwrap();
                assert!(
                    document["gaps"]
                        .as_array()
                        .unwrap()
                        .iter()
                        .any(|gap| gap["subject"] == "pid namespace"),
                    "{document}"
                );
            }
            // Output resumes only after the observer exited. Drain the healthy
            // companion to retain the warning text; stalled success never
            // depends on this cleanup.
            if stopped {
                assert_eq!(unsafe { libc::tcflow(slave.as_raw_fd(), libc::TCOON) }, 0);
            }
            drop(slave);
            while let Ok(n) = master.read(&mut buf) {
                if n == 0 {
                    break;
                }
                bytes.extend_from_slice(&buf[..n]);
            }
            if !stopped {
                if !isolate_progress {
                    let text = String::from_utf8_lossy(&bytes);
                    assert!(
                        text.contains("p11scope: enumerating processes..."),
                        "default progress disabled: {text}"
                    );
                    assert!(
                        text.contains("p11scope: lowering scan-only admission and rendering..."),
                        "default lowering progress lost: {text}"
                    );
                }
                assert!(
                    String::from_utf8_lossy(&bytes).contains("PID namespace"),
                    "namespace warning missing: {}",
                    String::from_utf8_lossy(&bytes)
                );
                if !with_report {
                    let start = bytes.windows(2).position(|bytes| bytes == b"{\n").unwrap();
                    let document: serde_json::Value =
                        serde_json::from_slice(&bytes[start..]).unwrap();
                    assert!(
                        document["gaps"]
                            .as_array()
                            .unwrap()
                            .iter()
                            .any(|gap| gap["subject"] == "pid namespace")
                    );
                }
            }
            eprintln!(
                "namespace-output: stopped={stopped}, report_requested={with_report}, watchdog=false, exit={status}, output attempts finished"
            );
        }
    }

    #[test]
    fn final_event_append_or_sync_failure_preserves_report_and_stdout() {
        for after_ended in [false, true] {
            let mut coordinator = coordinator();
            coordinator.commit_batch(false).unwrap();
            let presentation = Presentation::capture(&coordinator, "system", 1, 2, 1);
            let dir = private_tempdir();
            let events = dir.path().join("events.jsonl");
            let report = dir.path().join("report.json");
            let mut writer = EventWriter::create(&events, 1 << 20, 2).unwrap();
            let fault = event_fault("ended", after_ended);
            let attempts = fault.attempts.clone();
            writer.fault = Some(fault);
            let mut stdout = Vec::new();
            let result = finish_output(
                Some(AtomicFile::create(&report).unwrap()),
                &mut EventLogState::new(Some(writer)),
                &mut StreamState::new(),
                &presentation,
                true,
                false,
                &mut WriterStdout(&mut stdout),
                None,
                None,
            );
            assert_eq!(result.exit_code(), 1);
            assert_eq!(result.event_log_confirmed, Some(false));
            assert_eq!(result.report_committed, Some(true));
            assert_eq!(result.stdout_result.as_ref().map(Result::is_ok), Some(true));
            assert_eq!(result.failures.len(), 1);
            assert!(result.failures[0].contains("event log completion"));
            assert!(
                report.exists(),
                "closing event failure discarded -o: {result:?}"
            );
            assert_eq!(std::fs::read(report).unwrap(), stdout);
            assert_eq!(
                attempts
                    .borrow()
                    .iter()
                    .filter(|kind| *kind == "ended")
                    .count(),
                1
            );
            assert_eq!(
                event_records(&events)
                    .iter()
                    .filter(|record| record["kind"] == "ended")
                    .count(),
                usize::from(after_ended)
            );
        }
    }

    struct BrokenStdout {
        writes: usize,
    }
    impl std::io::Write for BrokenStdout {
        fn write(&mut self, _: &[u8]) -> std::io::Result<usize> {
            self.writes += 1;
            Err(std::io::Error::new(
                std::io::ErrorKind::BrokenPipe,
                "injected stdout failure",
            ))
        }
        fn flush(&mut self) -> std::io::Result<()> {
            Ok(())
        }
    }

    #[test]
    fn report_commit_failure_preserves_destination_and_completes_other_sinks() {
        let mut coordinator = coordinator();
        coordinator.commit_batch(false).unwrap();
        let presentation = Presentation::capture(&coordinator, "system", 1, 2, 1);
        let dir = private_tempdir();
        let report = dir.path().join("report.json");
        let old = dir.path().join("old.json");
        std::fs::write(&old, "old report").unwrap();
        let sink = AtomicFile::create(&report).unwrap();
        std::os::unix::fs::symlink(&old, &report).unwrap();
        let events = dir.path().join("events.jsonl");
        let writer = EventWriter::create(&events, 1 << 20, 2).unwrap();
        let mut stdout = Vec::new();
        let result = finish_output(
            Some(sink),
            &mut EventLogState::new(Some(writer)),
            &mut StreamState::new(),
            &presentation,
            true,
            false,
            &mut WriterStdout(&mut stdout),
            None,
            None,
        );
        assert_eq!(result.exit_code(), 1);
        assert_eq!(result.event_log_confirmed, Some(true));
        assert_eq!(result.report_committed, Some(false));
        assert_eq!(result.stdout_result.as_ref().map(Result::is_ok), Some(true));
        let mut notices = Vec::new();
        result.notices(None, &mut |line| notices.push(line.to_string()));
        assert!(notices.iter().any(|line| line.contains("-o report failed")));
        assert!(!notices.iter().any(|line| line.contains("report saved")));
        assert!(
            !stdout.is_empty(),
            "report failure suppressed stdout: {result:?}"
        );
        assert_eq!(std::fs::read_to_string(&old).unwrap(), "old report");
        assert!(
            std::fs::symlink_metadata(&report)
                .unwrap()
                .file_type()
                .is_symlink()
        );
        assert_eq!(event_records(&events).last().unwrap()["kind"], "ended");
        assert!(!std::fs::read_dir(dir.path()).unwrap().any(|entry| {
            entry
                .unwrap()
                .file_name()
                .to_string_lossy()
                .starts_with(".p11scope.")
        }));
    }

    #[test]
    fn event_and_stdout_failures_still_commit_the_report() {
        let mut coordinator = coordinator();
        coordinator.commit_batch(false).unwrap();
        let presentation = Presentation::capture(&coordinator, "system", 1, 2, 1);
        let dir = private_tempdir();
        let report = dir.path().join("report.json");
        let events = dir.path().join("events.jsonl");
        let mut writer = EventWriter::create(&events, 1 << 20, 2).unwrap();
        writer.fault = Some(event_fault("ended", false));
        let mut stdout = BrokenStdout { writes: 0 };
        let result = finish_output(
            Some(AtomicFile::create(&report).unwrap()),
            &mut EventLogState::new(Some(writer)),
            &mut StreamState::new(),
            &presentation,
            true,
            false,
            &mut WriterStdout(&mut stdout),
            None,
            None,
        );
        assert_eq!(result.exit_code(), 1);
        assert_eq!(result.event_log_confirmed, Some(false));
        assert_eq!(result.report_committed, Some(true));
        assert_eq!(
            result.stdout_result.as_ref().map(Result::is_ok),
            Some(false)
        );
        assert_eq!(result.failures.len(), 2);
        assert!(result.failures[0].contains("event log completion"));
        assert!(result.failures[1].contains("stdout failed"));
        let mut notices = Vec::new();
        result.notices(None, &mut |line| notices.push(line.to_string()));
        assert!(notices.iter().any(|line| line.contains("report saved")));
        assert!(
            report.exists(),
            "two sink errors suppressed the report: {result:?}"
        );
        assert!(stdout.writes > 0);
    }

    #[test]
    fn returned_stdout_failure_exits_nonzero_with_healthy_event_and_report() {
        let dir = private_tempdir();
        let events = dir.path().join("events.jsonl");
        let report = dir.path().join("report.json");
        let finalized = std::cell::Cell::new(false);
        let mut stdout = BrokenStdout { writes: 0 };
        let result = run_with_terminal(
            InspectScope::Pid(std::process::id()),
            &[],
            &HookRegistry::builtin(),
            true,
            None,
            None,
            None,
            Some(&report),
            false,
            Some(&events),
            None,
            None,
            CaptureMode::Scan,
            crate::attach::BackendSelection::Auto,
            &|| false,
            &|| finalized.set(true),
            false,
            &mut WriterStdout(&mut stdout),
            &DashboardIo::stdio(),
        );
        assert_eq!(result.unwrap(), 1);
        assert!(finalized.get());
        assert!(stdout.writes > 0);
        let document: serde_json::Value =
            serde_json::from_slice(&std::fs::read(report).unwrap()).unwrap();
        assert_eq!(document["schema"], DOC_ID);
        assert_eq!(event_records(&events).last().unwrap()["kind"], "ended");
    }

    #[test]
    fn dashboard_retries_restore_after_output_failure() {
        use std::os::fd::{AsRawFd as _, FromRawFd as _};
        let mut master = -1;
        let mut slave = -1;
        // SAFETY: valid output pointers; defaults create an owned PTY pair.
        assert_eq!(
            unsafe {
                libc::openpty(
                    &mut master,
                    &mut slave,
                    std::ptr::null_mut(),
                    std::ptr::null(),
                    std::ptr::null(),
                )
            },
            0
        );
        // SAFETY: openpty returned two distinct owned descriptors.
        let _master = unsafe { std::fs::File::from_raw_fd(master) };
        let slave = unsafe { std::fs::File::from_raw_fd(slave) };
        // SAFETY: the PTY is owned by this test; only its flow is stopped.
        assert_eq!(unsafe { libc::tcflow(slave.as_raw_fd(), libc::TCOOFF) }, 0);
        struct ResumeThenFail(i32);
        impl std::io::Write for ResumeThenFail {
            fn write(&mut self, _: &[u8]) -> std::io::Result<usize> {
                // SAFETY: this is the owned PTY, kept live through the run.
                assert_eq!(unsafe { libc::tcflow(self.0, libc::TCOON) }, 0);
                Err(std::io::Error::new(
                    std::io::ErrorKind::BrokenPipe,
                    "injected stdout failure",
                ))
            }
            fn flush(&mut self) -> std::io::Result<()> {
                Ok(())
            }
        }
        let account = std::rc::Rc::new(std::cell::Cell::new(None));
        let dir = private_tempdir();
        let notices = std::fs::File::create(dir.path().join("notices")).unwrap();
        let terminal = DashboardIo {
            output: slave.as_raw_fd(),
            input: None,
            account: Some(account.clone()),
            stderr_fd: notices.as_raw_fd(),
            stderr: StderrRoute::Leave,
        };
        let result = run_with_terminal(
            InspectScope::Pid(std::process::id()),
            &[],
            &HookRegistry::builtin(),
            true,
            None,
            None,
            None,
            None,
            true,
            None,
            None,
            None,
            CaptureMode::Scan,
            crate::attach::BackendSelection::Auto,
            &|| true,
            &|| {},
            true,
            &mut WriterStdout(&mut ResumeThenFail(slave.as_raw_fd())),
            &terminal,
        );
        let account = account
            .take()
            .expect("output failure skipped dashboard cleanup accounting");
        assert_eq!(result.unwrap(), 1);
        assert!(account.terminal.restore_retried);
        assert!(account.terminal.restored);
        let notices = std::fs::read_to_string(dir.path().join("notices")).unwrap();
        assert!(
            notices.contains("; screen restored; service ticks"),
            "final accounting preceded output/restore: {notices}"
        );
    }

    /// B2: the observation deadline never panics. A window that
    /// overflows the clock degrades to no deadline (the classic wait's
    /// `checked_add` shape in `run.rs`); a plain `Instant::now() +
    /// window` would panic on `u64::MAX` here.
    #[test]
    fn an_overflowing_duration_degrades_to_no_deadline_without_panicking() {
        assert_eq!(deadline_for_duration(None), None);
        let end = deadline_for_duration(Some(Duration::from_secs(60)))
            .expect("a bounded window has a deadline");
        assert!(end > Instant::now());
        assert_eq!(
            deadline_for_duration(Some(Duration::from_secs(u64::MAX))),
            None,
            "an overflowing window degrades instead of panicking"
        );
        assert!(unbounded_dashboard_deadline() > Instant::now());
    }

    /// F4 (review): `inventory --system` outside the agreeing numbering
    /// carries a scope-level gap in `gaps[]`, not just the field; an
    /// agreeing numbering stages nothing.
    #[test]
    fn a_mismatched_numbering_is_a_scope_level_gap() {
        use crate::pidns::{ObserverPidNs, PidNumbering, ProcView};
        let mut quiet = coordinator();
        stage_numbering_gap(&mut quiet, &PidNumbering::agreeing());
        quiet.registry_mut().publish();
        assert!(
            render_json(&quiet, "system", 1, 2, 1)["gaps"]
                .as_array()
                .unwrap()
                .is_empty()
        );
        for numbering in [
            PidNumbering {
                observer: ObserverPidNs::Nested,
                proc_view: ProcView::Own,
            },
            PidNumbering {
                observer: ObserverPidNs::Initial,
                proc_view: ProcView::Foreign("/proc/self: gone".into()),
            },
        ] {
            let mut coordinator = coordinator();
            stage_numbering_gap(&mut coordinator, &numbering);
            coordinator.registry_mut().publish();
            let document = render_json(&coordinator, "system", 1, 2, 1);
            let gaps = document["gaps"].as_array().unwrap();
            assert_eq!(gaps.len(), 1, "{document}");
            assert_eq!(gaps[0]["subject"], "pid namespace");
            assert_eq!(gaps[0]["caller"], serde_json::Value::Null);
            assert!(
                gaps[0]["reason"]
                    .as_str()
                    .unwrap()
                    .contains("pid_namespace")
            );
        }
    }

    /// DR-RETRO-PIDNS-1 (review P4) and PIDNS-2 (review 5): the library
    /// itself refuses a mismatched `inventory --pid` before anything is
    /// scanned, and `inventory --system` publishes the numbering gap from
    /// the observer's real `numbering()`, not a fixture.
    #[test]
    fn a_nested_observer_refuses_inventory_pid_and_gaps_inventory_system() {
        use crate::pidns::test_seam::{nested, with_numbering};
        let hooks = HookRegistry::builtin();
        let run = |scope: InspectScope, out: &mut Vec<u8>| {
            run_with_writer(
                scope,
                &[],
                &hooks,
                true,
                Some(1),
                None,
                None,
                None,
                false,
                None,
                None,
                None,
                crate::cli::CaptureMode::Scan,
                crate::attach::BackendSelection::Auto,
                &|| false,
                &|| {},
                false,
                &mut WriterStdout(out),
            )
        };
        let mut out = Vec::new();
        let pid = std::process::id();
        let error = with_numbering(nested(), || run(InspectScope::Pid(pid), &mut out)).unwrap_err();
        assert!(error.is::<crate::pidns::NumberingMismatch>(), "{error:#}");
        assert!(
            format!("{error:#}").starts_with(&format!(
                "pid-namespace-mismatch: refusing inventory --pid {pid}:"
            )),
            "{error:#}"
        );
        assert!(out.is_empty(), "a refused inventory printed a document");

        let gap_subjects = |out: &[u8]| -> Vec<String> {
            let document: serde_json::Value = serde_json::from_slice(out).unwrap();
            document["gaps"]
                .as_array()
                .unwrap()
                .iter()
                .map(|gap| gap["subject"].as_str().unwrap_or_default().to_string())
                .collect()
        };
        let mut out = Vec::new();
        with_numbering(nested(), || run(InspectScope::System, &mut out)).unwrap();
        assert!(
            gap_subjects(&out)
                .iter()
                .any(|subject| subject == "pid namespace"),
            "{}",
            String::from_utf8_lossy(&out)
        );
        let mut out = Vec::new();
        with_numbering(crate::pidns::PidNumbering::agreeing(), || {
            run(InspectScope::System, &mut out)
        })
        .unwrap();
        assert!(
            !gap_subjects(&out)
                .iter()
                .any(|subject| subject == "pid namespace"),
            "an agreeing observer staged a numbering gap"
        );
    }

    #[test]
    fn json_document_carries_the_exact_schema_id_and_clock_basis() {
        let mut coordinator = coordinator();
        let pid = std::process::id();
        let caller = coordinator
            .adapter_mut()
            .admit(pid, ImageAuthority::ScanPinned, 100)
            .unwrap();
        let key = ModuleKey::physical(8, 1, 11, Some("sha0011".into()), "/lib/a.so");
        coordinator.registry_mut().note_mapping(
            caller,
            pid,
            ModuleInfo {
                path: "/lib/a.so".into(),
                key: key.clone(),
                double_loaded: false,
                build_id: None,
                identity_source: Some("mountinfo".into()),
                admission: AdmissionState::Admitted,
                admission_class: Some("exact".into()),
                admission_endpoints: Some(2),
                admission_reasons: Vec::new(),
            },
            100,
        );
        coordinator.commit_batch(false).unwrap();
        let document = render_json(&coordinator, "pid:7", 90, 120, 1);
        assert_eq!(document["schema"], "p11scope/inventory/v1");
        assert_eq!(document["scope"], "pid:7");
        assert_eq!(document["clock"]["basis"], "CLOCK_MONOTONIC");
        assert_eq!(document["clock"]["unit"], "ns");
        assert_eq!(document["observation"]["passes"], 1);
        assert_eq!(document["observation"]["usage_feed"], false);
        assert_eq!(document["callers"].as_array().unwrap().len(), 1);
        assert_eq!(document["callers"][0]["id"], caller.label());
        assert_eq!(document["callers"][0]["image"]["authority"], "scan_pinned");
        assert_eq!(document["modules"].as_array().unwrap().len(), 1);
        assert_eq!(document["modules"][0]["paths"][0], "/lib/a.so");
        assert_eq!(
            document["edges"][0]["entries"]["observation"],
            "unknown (usage observation unavailable)"
        );
        assert_eq!(document["edges"][0]["entries"]["count"], 0);
        // Mappings are never reported as observed calls.
        assert!(document["edges"][0]["entries"]["last_seen_ns"].is_null());
        // The scan lane binds no native witness (Task 6 C4).
        assert_eq!(
            document["observation"]["native_witnesses"],
            serde_json::json!({
                "rows": 0, "bound": 0, "unbound": 0, "pending": 0, "integrity": 0,
                "unbound_reasons": {},
                "placement": {"edge": 0, "module": 0, "ambiguous": 0, "unresolved": 0},
            })
        );
        assert!(document["modules"][0]["unbound_use"].is_null());
        assert!(document["budgets"]["native_preadmission"].is_null());
        // An unbound witness renders as module-level use with its reason,
        // and the census renders the unbound ratio's inputs.
        coordinator.registry_mut().note_unbound_witness(
            vec![key],
            110,
            crate::discovery::native_binding::UnboundReason::BeforeAdmission,
        );
        let mut census = crate::discovery::native_binding::BindingCensus {
            rows: 3,
            bound: 1,
            pending: 1,
            ..Default::default()
        };
        census.unbound.insert(
            crate::discovery::native_binding::UnboundReason::BeforeAdmission,
            1,
        );
        coordinator.registry_mut().note_witness_census(census);
        coordinator.commit_batch(false).unwrap();
        let document = render_json(&coordinator, "pid:7", 90, 130, 2);
        assert_eq!(
            document["modules"][0]["unbound_use"],
            serde_json::json!({"first_ns": 110, "rows": 1, "reasons": {"before_admission": 1}})
        );
        assert_eq!(
            document["observation"]["native_witnesses"],
            serde_json::json!({
                "rows": 3, "bound": 1, "unbound": 1, "pending": 1, "integrity": 0,
                "unbound_reasons": {"before_admission": 1},
                "placement": {"edge": 0, "module": 1, "ambiguous": 0, "unresolved": 0},
            })
        );
        assert!(
            document["gaps"]
                .as_array()
                .unwrap()
                .iter()
                .any(|gap| gap["subject"] == "used by an unidentified caller image"),
            "{}",
            document["gaps"]
        );
    }

    #[test]
    fn the_stop_line_reads_as_one_sentence() {
        let line = stop_line(&lane_summary(
            crate::inventory_capture::Retirement::Unsettled("budget passed".into()),
        ));
        assert_eq!(
            line,
            format!(
                "p11scope: native capture stopped after 2 passes: 4 endpoints attached \
                 (per-offset links), 0 failed; retirement unsettled: budget passed; settlement {}",
                crate::inventory_capture::SETTLEMENT
            )
        );
        assert!(!line.contains("  "), "{line}");
    }

    fn lane_summary(retirement: crate::inventory_capture::Retirement) -> LaneSummary {
        LaneSummary {
            backend: crate::inventory_capture::LaneBackend::singles(),
            retirement,
            passes: 2,
            attached: 4,
            failed: 0,
            lifecycle: crate::inventory_capture::LifecycleTally {
                records: 40,
                ring_loss: 3,
                malformed: 0,
                failed_quanta: 0,
                recovery_rescans: 1,
            },
            lifecycle_high_water_bytes: None,
        }
    }

    /// D3d: a system document discloses the sweep identity backend
    /// and its finite fallback in `-o` and on stdout alike (exact
    /// bytes); without identity the key is absent.
    #[test]
    fn d3d_system_document_discloses_identity_backend_and_fallback() {
        use crate::inspect_system::{IdentityBackend, IdentitySummary};
        let mut coordinator = coordinator();
        coordinator.commit_batch(false).unwrap();
        let presentation = Presentation::capture(&coordinator, "system", 1, 2, 1);
        for (summary, backend, fallback) in [
            (
                IdentitySummary {
                    backend: IdentityBackend::Userspace,
                    fallback: None,
                },
                "userspace",
                serde_json::Value::Null,
            ),
            (
                IdentitySummary {
                    backend: IdentityBackend::Kernel,
                    fallback: None,
                },
                "kernel",
                serde_json::Value::Null,
            ),
            (
                IdentitySummary {
                    backend: IdentityBackend::Kernel,
                    fallback: Some("below_threshold".into()),
                },
                "kernel",
                serde_json::json!("below_threshold"),
            ),
            (
                IdentitySummary {
                    backend: IdentityBackend::Userspace,
                    fallback: Some("no_btf".into()),
                },
                "userspace",
                serde_json::json!("no_btf"),
            ),
        ] {
            let dir = private_tempdir();
            let out = dir.path().join("doc.json");
            let sink = AtomicFile::create(&out).unwrap();
            let mut stdout = Vec::new();
            assert_eq!(
                finish_output(
                    Some(sink),
                    &mut EventLogState::new(None),
                    &mut StreamState::new(),
                    &presentation,
                    true,
                    false,
                    &mut WriterStdout(&mut stdout),
                    None,
                    Some(&summary),
                )
                .exit_code(),
                0
            );
            let file = std::fs::read(&out).unwrap();
            assert_eq!(file, stdout, "-o and stdout agree for {backend}/{fallback}");
            let document: serde_json::Value = serde_json::from_slice(&stdout).unwrap();
            let identity = &document["observation"]["identity"];
            assert_eq!(identity["backend"], backend, "{fallback}");
            assert_eq!(identity["fallback"], fallback, "{backend}");
            // Approved shape only: no counters, no lifecycle, no events.
            assert_eq!(identity.as_object().unwrap().len(), 2, "{identity}");
            let text = identity.to_string();
            assert!(!text.contains('/'), "{text}");
            assert!(!text.contains("pid"), "{text}");
        }
        // Absent without identity (e.g. `--pid`): no key at all.
        let mut stdout = Vec::new();
        assert_eq!(
            finish_output(
                None,
                &mut EventLogState::new(None),
                &mut StreamState::new(),
                &presentation,
                true,
                false,
                &mut WriterStdout(&mut stdout),
                None,
                None,
            )
            .exit_code(),
            0
        );
        let document: serde_json::Value = serde_json::from_slice(&stdout).unwrap();
        assert!(
            document["observation"].get("identity").is_none(),
            "{}",
            document["observation"]
        );
    }

    /// D3d: the fixed target-run-limit detail renders as
    /// `fd_headroom: target_run_limit`, still finite.
    #[test]
    fn d3d_identity_target_limit_detail_is_finite() {
        use crate::inspect_system::{IdentityBackend, IdentitySummary};
        let mut coordinator = coordinator();
        coordinator.commit_batch(false).unwrap();
        let presentation = Presentation::capture(&coordinator, "system", 1, 2, 1);
        let summary = IdentitySummary {
            backend: IdentityBackend::Kernel,
            fallback: Some("fd_headroom: target_run_limit".into()),
        };
        let mut stdout = Vec::new();
        assert_eq!(
            finish_output(
                None,
                &mut EventLogState::new(None),
                &mut StreamState::new(),
                &presentation,
                true,
                false,
                &mut WriterStdout(&mut stdout),
                None,
                Some(&summary),
            )
            .exit_code(),
            0
        );
        let document: serde_json::Value = serde_json::from_slice(&stdout).unwrap();
        assert_eq!(
            document["observation"]["identity"]["fallback"],
            "fd_headroom: target_run_limit"
        );
    }

    /// C5.11: a native document discloses the attach mechanism, the
    /// operator's selection and any `auto` fallback reason; the start and
    /// stop lines name the mechanism too.
    #[test]
    fn a_native_document_discloses_its_attach_backend_and_fallback() {
        use crate::attach::{AttachBackend, BackendSelection};
        use crate::inventory_capture::{LaneBackend, Retirement};
        let mut coordinator = coordinator();
        coordinator.commit_batch(false).unwrap();
        let presentation = Presentation::capture(&coordinator, "system", 1, 2, 1);
        let multi = LaneBackend {
            selection: BackendSelection::Auto,
            backend: AttachBackend::Multi,
            fallback: None,
            scope_filter: crate::inventory_capture::ScopeFilter::None,
        };
        let fell_back = LaneBackend {
            selection: BackendSelection::Auto,
            backend: AttachBackend::Singles,
            fallback: Some("the uprobe-multi functional probe failed: EOPNOTSUPP".into()),
            scope_filter: crate::inventory_capture::ScopeFilter::None,
        };
        for (backend, mechanism, fallback) in [
            (multi.clone(), "uprobe-multi", serde_json::Value::Null),
            (
                fell_back.clone(),
                "per-offset",
                serde_json::json!("the uprobe-multi functional probe failed: EOPNOTSUPP"),
            ),
        ] {
            let mut summary = lane_summary(Retirement::Closed(Default::default()));
            summary.backend = backend.clone();
            let mut stdout = Vec::new();
            assert_eq!(
                finish_output(
                    None,
                    &mut EventLogState::new(None),
                    &mut StreamState::new(),
                    &presentation,
                    true,
                    false,
                    &mut WriterStdout(&mut stdout),
                    Some(&summary),
                    None,
                )
                .exit_code(),
                0
            );
            let document: serde_json::Value = serde_json::from_slice(&stdout).unwrap();
            let attach = &document["observation"]["attach"];
            assert_eq!(attach["selection"], "auto");
            assert_eq!(attach["mechanism"], mechanism);
            assert_eq!(attach["fallback"], fallback);
            assert!(stop_line(&summary).contains(&format!("({mechanism} links)")));
            let active = lane_active_line(&backend);
            assert!(active.contains(mechanism) && active.contains("--attach-backend auto"));
            assert_eq!(
                active.contains("fallback"),
                backend.fallback.is_some(),
                "{active}"
            );
        }
    }

    /// C5.1: a native document states its lane, its settlement (always
    /// unsettled, ruling D3) and how retirement ended, in `-o` and on stdout
    /// alike; a scan document carries none of the three keys.
    #[test]
    fn a_native_document_states_lane_settlement_and_retirement() {
        use crate::inventory_capture::Retirement;
        let mut coordinator = coordinator();
        coordinator.commit_batch(false).unwrap();
        let presentation = Presentation::capture(&coordinator, "system", 1, 2, 1);
        for (summary, retirement) in [
            (
                lane_summary(Retirement::Closed(Default::default())),
                "closed",
            ),
            (
                lane_summary(Retirement::Unsettled("budget".into())),
                "unsettled",
            ),
        ] {
            let dir = private_tempdir();
            let out = dir.path().join("doc.json");
            let sink = AtomicFile::create(&out).unwrap();
            let mut stdout = Vec::new();
            assert_eq!(
                finish_output(
                    Some(sink),
                    &mut EventLogState::new(None),
                    &mut StreamState::new(),
                    &presentation,
                    true,
                    false,
                    &mut WriterStdout(&mut stdout),
                    Some(&summary),
                    None,
                )
                .exit_code(),
                0
            );
            let file = std::fs::read(&out).unwrap();
            assert_eq!(file, stdout, "-o and stdout agree");
            let document: serde_json::Value = serde_json::from_slice(&stdout).unwrap();
            let observation = &document["observation"];
            assert_eq!(observation["lane"], "native");
            assert_eq!(observation["settlement"], "unsettled");
            assert_eq!(observation["retirement"], retirement);
            assert_eq!(
                observation["lifecycle"],
                serde_json::json!({
                    "records": 40,
                    "ring_loss": 3,
                    "malformed": 0,
                    "failed_quanta": 0,
                    "recovery_rescans": 1,
                })
            );
        }
        let mut stdout = Vec::new();
        assert_eq!(
            finish_output(
                None,
                &mut EventLogState::new(None),
                &mut StreamState::new(),
                &presentation,
                true,
                false,
                &mut WriterStdout(&mut stdout),
                None,
                None,
            )
            .exit_code(),
            0
        );
        let document: serde_json::Value = serde_json::from_slice(&stdout).unwrap();
        for key in ["lane", "settlement", "retirement", "lifecycle"] {
            assert!(document["observation"].get(key).is_none(), "{key}");
        }
    }

    /// C5.1: the native stop's commit reaches the stream as its events, its
    /// fresh gaps, and one `pass_committed` marked `final` whose `new_gaps`
    /// counts them, so pass accounting still sums to the streamed gaps.
    /// R-C51-2: each pass marker carries this pass's unbound witness rows
    /// per (module, reason) — the cumulative module counts' delta since
    /// the previous marker — bounded, with the rest summed as truncated.
    #[test]
    fn pass_markers_count_this_passes_unbound_rows_per_module_and_reason() {
        use crate::discovery::caller_registry::UnboundUse;
        let unbound = |pairs: &[(&'static str, u64)]| UnboundUse {
            first_ns: 1,
            rows: pairs.iter().map(|(_, n)| n).sum(),
            reasons: pairs.iter().copied().collect(),
        };
        let mut state = StreamState::new();
        let first = [(ModuleId(3), unbound(&[("no_live_caller", 2)]))];
        let (rows, truncated) =
            unbound_rows_delta(&mut state, first.iter().map(|(id, u)| (*id, u)), 8);
        assert_eq!(
            serde_json::Value::from(rows),
            serde_json::json!([{"module": "m3", "reason": "no_live_caller", "rows": 2}])
        );
        assert_eq!(truncated, 0);
        let second = [
            (
                ModuleId(3),
                unbound(&[("before_admission", 1), ("no_live_caller", 3)]),
            ),
            (ModuleId(4), unbound(&[("no_live_caller", 5)])),
        ];
        let (rows, truncated) =
            unbound_rows_delta(&mut state, second.iter().map(|(id, u)| (*id, u)), 2);
        assert_eq!(
            serde_json::Value::from(rows),
            serde_json::json!([
                {"module": "m3", "reason": "before_admission", "rows": 1},
                {"module": "m3", "reason": "no_live_caller", "rows": 1},
            ])
        );
        assert_eq!(truncated, 5);
        // Nothing new: an empty list.
        let (rows, truncated) =
            unbound_rows_delta(&mut state, second.iter().map(|(id, u)| (*id, u)), 2);
        assert!(rows.is_empty() && truncated == 0);
    }

    #[test]
    fn the_stop_commit_streams_its_events_and_gaps_under_a_final_pass() {
        let mut coordinator = coordinator();
        coordinator.note_scope_gap("first".into(), "pass gap".into());
        coordinator.commit_batch(false).unwrap();
        let dir = private_tempdir();
        let path = dir.path().join("events.jsonl");
        let mut writer = EventWriter::create(&path, 1 << 20, 5).unwrap();
        let mut state = StreamState::new();
        let presentation = Presentation::capture(&coordinator, "system", 1, 2, 1);
        let report = PassReport {
            pass: 0,
            scanned: 1,
            maps_matched: 0,
            native_callers: 0,
            scan_callers: 1,
            engine_changed: false,
            pending_refresh: Vec::new(),
            events: Vec::new(),
            timings: crate::timing::StageTimings::new(),
        };
        emit_pass_events(&mut writer, &mut state, &report, &presentation, 2).unwrap();
        coordinator.note_scope_gap("native capture retirement unsettled".into(), "x".into());
        coordinator.commit_batch(false).unwrap();
        let presentation = Presentation::capture(&coordinator, "system", 1, 3, 1);
        let exited = CallerEvent::Exited {
            id: crate::discovery::caller_registry::CallerId(4),
            reason: "gone".into(),
        };
        emit_stop_events(&mut writer, &mut state, &[exited], 1, &presentation, 3).unwrap();
        let lines: Vec<serde_json::Value> = std::fs::read_to_string(&path)
            .unwrap()
            .lines()
            .map(|line| serde_json::from_str(line).unwrap())
            .collect();
        let kinds: Vec<&str> = lines.iter().map(|l| l["kind"].as_str().unwrap()).collect();
        assert_eq!(
            kinds,
            [
                "gap_recorded",
                "pass_committed",
                "caller_event",
                "gap_recorded",
                "pass_committed"
            ]
        );
        assert_eq!(
            lines[3]["event"]["subject"],
            "native capture retirement unsettled"
        );
        let last = &lines[4]["event"];
        assert_eq!(last["final"], true);
        assert_eq!(last["pass"], 0);
        assert_eq!(last["new_gaps"], 1);
        assert!(lines[1]["event"].get("final").is_none());
        let streamed_new: u64 = lines
            .iter()
            .filter(|line| line["kind"] == "pass_committed")
            .map(|line| line["event"]["new_gaps"].as_u64().unwrap())
            .sum();
        assert_eq!(streamed_new, 2);
    }

    fn stream_identity_fixture(callers: usize) -> (Presentation, Vec<CallerEvent>) {
        use crate::discovery::inventory_workload::{Harness, ScaleSpec};
        let mut harness = Harness::new(RegistryLimits::default_limits()).unwrap();
        let events = harness.stage_scale(&ScaleSpec {
            name: "inline-identity",
            callers,
            modules: 1,
            edges_per_caller: 1,
            endpoints_per_module: 4,
            first_pid: 91_000,
        });
        harness.commit();
        (
            Presentation::capture(harness.coordinator(), "workload", 1, 2, 1),
            events,
        )
    }

    fn stream_identity_sink() -> (EventWriter, std::fs::File) {
        let file = tempfile::tempfile().expect("private disk TMPDIR is writable");
        let reader = file.try_clone().unwrap();
        (EventWriter::anonymous_test_sink(file), reader)
    }

    fn stream_sink_records(reader: &mut std::fs::File) -> Vec<serde_json::Value> {
        use std::io::{Read as _, Seek as _};
        reader.rewind().unwrap();
        let mut bytes = String::new();
        reader.read_to_string(&mut bytes).unwrap();
        bytes
            .lines()
            .map(|line| serde_json::from_str(line).unwrap())
            .collect()
    }

    fn stream_identity_report(events: Vec<CallerEvent>) -> PassReport {
        PassReport {
            pass: 0,
            scanned: 0,
            maps_matched: 0,
            native_callers: 0,
            scan_callers: 0,
            engine_changed: false,
            pending_refresh: Vec::new(),
            events,
            timings: crate::timing::StageTimings::new(),
        }
    }

    fn stream_edge_records(records: &[serde_json::Value]) -> Vec<&serde_json::Value> {
        records
            .iter()
            .filter(|record| record["kind"] == "edge_observed")
            .map(|record| &record["event"])
            .collect()
    }

    fn stream_inline_keys_are_allowed(context: &serde_json::Value) -> bool {
        fn keys(value: &serde_json::Value, expected: &[&str]) -> bool {
            value.as_object().is_some_and(|object| {
                object.len() == expected.len()
                    && expected.iter().all(|key| object.contains_key(*key))
            })
        }
        let caller_keys = [
            "id",
            "pid",
            "incarnation",
            "start_time",
            "authority",
            "lifecycle",
            "executable",
            "status",
        ];
        if !keys(context, &["version", "caller", "module"])
            || context["version"] != 1
            || !keys(&context["caller"], &caller_keys)
            || !keys(
                &context["module"],
                &[
                    "id",
                    "device_major",
                    "device_minor",
                    "inode",
                    "path",
                    "status",
                ],
            )
        {
            return false;
        }
        context["caller"]["executable"].is_null()
            || keys(
                &context["caller"]["executable"],
                &["dev", "ino", "mtime_secs", "mtime_nanos", "path"],
            )
    }

    // Catches a contextless production commit and forbidden adjacent identity
    // fields; the positive expected paths are independent fixture literals.
    #[test]
    fn stream_inline_identity_exact_privacy_keys() {
        let (mut view, events) = stream_identity_fixture(1);
        view.callers[0].authority = ImageAuthority::NativeExact {
            task_cookie: 0xfedc_ba98_7654_3210,
            exec_id: 0xabcd_ef01_2345_6789,
        };
        view.callers[0].lifecycle_reason = Some("FORBIDDEN_ARGV_ENV_COMM".into());
        view.modules[0].admission_reasons = vec!["FORBIDDEN_MODULE_REASON".into()];
        view.modules[0].sha256 = Some("FORBIDDEN_HASH".into());
        let (mut writer, mut reader) = stream_identity_sink();
        let mut state = StreamState::new();
        emit_commit(
            &mut writer,
            &mut state,
            &stream_identity_report(events),
            &view,
            false,
            2,
        )
        .unwrap();
        view.callers[0].lifecycle = crate::discovery::caller_registry::CallerLifecycle::Exited;
        emit_stop_events(
            &mut writer,
            &mut state,
            &[CallerEvent::Exited {
                id: view.callers[0].id,
                reason: "exited".into(),
            }],
            1,
            &view,
            3,
        )
        .unwrap();
        let mut stream = EventLogState::new(Some(writer));
        assert_eq!(
            finish_output(
                None,
                &mut stream,
                &mut state,
                &view,
                false,
                true,
                &mut WriterStdout(&mut Vec::new()),
                None,
                None
            )
            .exit_code(),
            0
        );
        let records = stream_sink_records(&mut reader);
        let edge = stream_edge_records(&records)[0];
        let context = &edge["identity_context"];
        assert!(stream_inline_keys_are_allowed(context), "{context}");
        for edge in stream_edge_records(&records) {
            assert!(stream_inline_keys_are_allowed(&edge["identity_context"]));
            assert_eq!(
                edge["identity_context"]["caller"]["executable"]["path"],
                "/bin/driver"
            );
        }
        for event in records
            .iter()
            .filter(|record| record["kind"] == "caller_event")
        {
            let caller_context = &event["event"]["identity_context"];
            assert_eq!(caller_context.as_object().unwrap().len(), 2);
            assert_eq!(caller_context["version"], 1);
            assert_eq!(
                caller_context["caller"]["executable"]["path"],
                "/bin/driver"
            );
            assert!(stream_inline_keys_are_allowed(&serde_json::json!({
                "version": 1, "caller": caller_context["caller"], "module": context["module"],
            })));
        }
        assert_eq!(context["caller"]["executable"]["path"], "/bin/driver");
        assert_eq!(context["module"]["path"], "/scale/m0.so");
        assert_eq!(context["caller"]["authority"], "native_exact");
        let encoded = context.to_string();
        for forbidden in [
            "FORBIDDEN_",
            "task_cookie",
            "exec_id",
            "tgid",
            "comm",
            "argv",
            "environ",
        ] {
            assert!(!encoded.contains(forbidden), "{encoded}");
        }
        // The checker must detect an otherwise-valid adjacent-field leak.
        for forbidden in ["argv", "environ", "comm", "tgid", "task_cookie", "exec_id"] {
            let mut leaked = context.clone();
            leaked["caller"][forbidden] = "MUST_DETECT_SENTINEL".into();
            assert!(!stream_inline_keys_are_allowed(&leaked));
        }
        for forbidden in [
            "sha256",
            "build_id",
            "admission_reasons",
            "admission_history",
            "paths",
        ] {
            let mut leaked = context.clone();
            leaked["module"][forbidden] = "MUST_DETECT_MODULE_NEIGHBOR".into();
            assert!(!stream_inline_keys_are_allowed(&leaked));
        }
    }

    // Catches borrowed-index implementations that serialize or clone a shared
    // multi-MiB module record for each edge. Total allocation is a conservative
    // upper bound on peak owned allocations within this real production commit.
    #[test]
    fn stream_compact_context_ignores_large_shared_metadata() {
        let (mut view, _) = stream_identity_fixture(4000);
        view.modules[0].admission_reasons = vec!["FORBIDDEN_SHARED_METADATA".repeat(350_000)];
        let (mut writer, mut reader) = stream_identity_sink();
        let mut state = StreamState::new();
        let (_, _, allocated) = crate::test_alloc::count_allocs_during(|| {
            emit_commit(
                &mut writer,
                &mut state,
                &stream_identity_report(Vec::new()),
                &view,
                false,
                2,
            )
            .unwrap();
        });
        assert!(
            allocated < 256 * 1024 * 1024,
            "commit allocated {allocated} bytes"
        );
        let records = stream_sink_records(&mut reader);
        let edges = stream_edge_records(&records);
        assert_eq!(edges.len(), 4000);
        let mut additional_bytes = 0;
        for edge in edges {
            let context = &edge["identity_context"];
            assert_eq!(context["module"]["path"], "/scale/m0.so");
            let bytes = context.to_string().len();
            assert!(bytes <= 65536);
            additional_bytes += bytes;
            assert!(!context.to_string().contains("FORBIDDEN_SHARED_METADATA"));
        }
        eprintln!(
            "compact shared-module: context value bytes={additional_bytes}, allocation upper bound={allocated}"
        );
    }

    // Catches identity-only changes omitted by ordinary due detection and
    // queued reversion, while proving that such changes obey the existing cap.
    #[test]
    fn stream_metadata_only_change_and_reversion_obey_cap() {
        let (mut view, _) = stream_identity_fixture(3);
        let (mut writer, mut reader) = stream_identity_sink();
        let mut state = StreamState::new();
        state.edges = EdgeEmitter::with_cap(1);
        let report = stream_identity_report(Vec::new());
        for now in 2..=4 {
            emit_commit(&mut writer, &mut state, &report, &view, false, now).unwrap();
        }
        for caller in &mut view.callers {
            caller.exe.as_mut().unwrap().path = Some("/bin/renamed".into());
        }
        emit_commit(&mut writer, &mut state, &report, &view, false, 5).unwrap();
        view.callers[1].exe.as_mut().unwrap().path = Some("/bin/driver".into());
        emit_commit(&mut writer, &mut state, &report, &view, false, 6).unwrap();
        emit_commit(&mut writer, &mut state, &report, &view, false, 7).unwrap();
        let records = stream_sink_records(&mut reader);
        let edges = stream_edge_records(&records);
        assert_eq!(
            edges.len(),
            5,
            "three originals, two metadata changes; reverted queued edge is omitted"
        );
        assert_eq!(
            edges[3]["identity_context"]["caller"]["executable"]["path"],
            "/bin/renamed"
        );
        assert_eq!(edges[4]["caller"], "c2");
        let markers: Vec<_> = records
            .iter()
            .filter(|record| record["kind"] == "pass_committed")
            .collect();
        assert_eq!(markers[3]["event"]["edge_events"], 1);
        assert_eq!(markers[3]["event"]["edge_events_deferred"], 2);
        assert_eq!(markers[4]["event"]["edge_events"], 1);
        assert_eq!(markers[4]["event"]["edge_events_deferred"], 0);
        assert_eq!(markers[5]["event"]["edge_events"], 0);
    }

    // Catches turnover contexts read from a later live PID instead of the
    // exact old/new publication records, and a contextless native stop path.
    #[test]
    fn stream_exec_and_reuse_preserve_old_names() {
        let (mut view, _) = stream_identity_fixture(2);
        view.callers[0].exe.as_mut().unwrap().path = Some("/bin/old".into());
        view.callers[0].lifecycle = crate::discovery::caller_registry::CallerLifecycle::ExecRetired;
        view.callers[1].exe.as_mut().unwrap().path = Some("/bin/new".into());
        let old = view.callers[0].id;
        let new = view.callers[1].id;
        let (mut writer, mut reader) = stream_identity_sink();
        let mut state = StreamState::new();
        emit_commit(
            &mut writer,
            &mut state,
            &stream_identity_report(vec![CallerEvent::ExecRetired { old, new }]),
            &view,
            false,
            2,
        )
        .unwrap();
        emit_stop_events(
            &mut writer,
            &mut state,
            &[CallerEvent::Reused { old, new }],
            1,
            &view,
            3,
        )
        .unwrap();
        let records = stream_sink_records(&mut reader);
        let turnovers: Vec<_> = records
            .iter()
            .filter(|record| record["kind"] == "caller_event")
            .collect();
        assert_eq!(turnovers.len(), 2);
        for turnover in turnovers {
            let context = &turnover["event"]["identity_context"];
            assert_eq!(context.as_object().map(|object| object.len()), Some(3));
            assert_eq!(context["version"], 1);
            for reference in ["old", "new"] {
                let edge_context = serde_json::json!({
                    "version": 1,
                    "caller": context[reference],
                    "module": {
                        "id": "m0", "device_major": 8, "device_minor": 1,
                        "inode": 100000, "path": "/scale/m0.so", "status": "observed",
                    },
                });
                assert!(stream_inline_keys_are_allowed(&edge_context));
            }
            assert_eq!(
                turnover["event"]["identity_context"]["old"]["executable"]["path"],
                "/bin/old"
            );
            assert_eq!(
                turnover["event"]["identity_context"]["new"]["executable"]["path"],
                "/bin/new"
            );
            assert_eq!(
                turnover["event"]["identity_context"]["old"]["lifecycle"],
                "exec_retired"
            );
        }
    }

    #[test]
    fn stream_identity_bytes_count_toward_retention() {
        let (mut view, _) = stream_identity_fixture(1);
        view.callers[0].exe.as_mut().unwrap().path = Some("\u{1}".repeat(4096));
        view.modules[0].paths = vec!["\u{2}".repeat(4096)];
        let (mut writer, mut reader) = stream_identity_sink();
        let mut state = StreamState::new();
        emit_commit(
            &mut writer,
            &mut state,
            &stream_identity_report(Vec::new()),
            &view,
            false,
            9,
        )
        .unwrap();
        let records = stream_sink_records(&mut reader);
        let edge = stream_edge_records(&records)[0];
        let context_bytes = edge["identity_context"].to_string().len();
        assert!((49152..=65536).contains(&context_bytes), "{context_bytes}");
        assert_eq!(writer.live_bytes(), reader.metadata().unwrap().len());
        assert!(writer.live_bytes() > context_bytes as u64);
        // Real finalization emits a metadata-only final change with wider clock
        // digits through the same sweep and ended reservation. Sequence-width
        // and actual rotation boundaries remain separate normal-host gates.
        view.callers[0].lifecycle = crate::discovery::caller_registry::CallerLifecycle::Exited;
        view.ended_ns = 10_000_000_000;
        let mut stream = EventLogState::new(Some(writer));
        let outcome = finish_output(
            None,
            &mut stream,
            &mut state,
            &view,
            false,
            true,
            &mut WriterStdout(&mut Vec::new()),
            None,
            None,
        );
        assert_eq!(outcome.exit_code(), 0);
        let records = stream_sink_records(&mut reader);
        let edges = stream_edge_records(&records);
        assert_eq!(edges.len(), 2);
        assert_eq!(
            edges[1]["identity_context"]["caller"]["lifecycle"],
            "exited"
        );
        assert!(stream_inline_keys_are_allowed(
            &edges[1]["identity_context"]
        ));
        assert_eq!(records.last().unwrap()["kind"], "ended");
        assert_eq!(records.last().unwrap()["event"]["edges_unretained"], 0);
    }

    // This is an actual protected filesystem/rotation gate. An environment
    // refusal stays a failed gate, independent of anonymous-sink controls.
    #[test]
    fn stream_edge_names_survive_dictionary_eviction() {
        let (mut view, events) = stream_identity_fixture(1);
        let dir = private_tempdir();
        let path = dir.path().join("events.jsonl");
        let mut writer = EventWriter::create(&path, 8192, 1).unwrap();
        writer
            .append("started", started_payload("workload", 1, &view), 1)
            .unwrap();
        let mut state = StreamState::new();
        emit_commit(
            &mut writer,
            &mut state,
            &stream_identity_report(events),
            &view,
            false,
            2,
        )
        .unwrap();
        writer
            .append("probe", serde_json::json!({"pad": "x".repeat(9000)}), 3)
            .unwrap();
        view.callers[0].exe.as_mut().unwrap().path = Some("/bin/retained".into());
        emit_stop_events(&mut writer, &mut state, &[], 1, &view, 4).unwrap();
        let mut stream = EventLogState::new(Some(writer));
        assert_eq!(
            finish_output(
                None,
                &mut stream,
                &mut state,
                &view,
                false,
                true,
                &mut WriterStdout(&mut Vec::new()),
                None,
                None
            )
            .exit_code(),
            0
        );
        let records = event_records(&path);
        assert!(
            !records
                .iter()
                .any(|record| record["kind"] == "started" || record["kind"] == "caller_event")
        );
        assert!(
            records
                .iter()
                .any(|record| record["kind"] == "retention_evicted")
        );
        let edges = stream_edge_records(&records);
        assert!(!edges.is_empty());
        for edge in edges {
            assert_eq!(
                edge["identity_context"]["caller"]["executable"]["path"],
                "/bin/retained"
            );
            assert_eq!(edge["identity_context"]["module"]["path"], "/scale/m0.so");
            assert!(stream_inline_keys_are_allowed(&edge["identity_context"]));
        }
        assert_eq!(records.last().unwrap()["event"]["edges_unretained"], 0);
    }

    #[test]
    fn stream_ended_rotation_counts_unretained_edges() {
        let (mut view, _) = stream_identity_fixture(12);
        for caller in &mut view.callers {
            caller.exe.as_mut().unwrap().path = Some("\u{1}".repeat(4096));
        }
        view.ended_ns = 10_000_000_000;
        let dir = private_tempdir();
        let path = dir.path().join("events.jsonl");
        let mut writer = EventWriter::create(&path, 1, 1).unwrap();
        let mut state = StreamState::new();
        emit_commit(
            &mut writer,
            &mut state,
            &stream_identity_report(Vec::new()),
            &view,
            false,
            9,
        )
        .unwrap();
        let mut stream = EventLogState::new(Some(writer));
        assert_eq!(
            finish_output(
                None,
                &mut stream,
                &mut state,
                &view,
                false,
                true,
                &mut WriterStdout(&mut Vec::new()),
                None,
                None
            )
            .exit_code(),
            0
        );
        let records = event_records(&path);
        assert!(stream_edge_records(&records).is_empty());
        let ended = records.last().unwrap();
        assert_eq!(ended["kind"], "ended");
        assert_eq!(ended["event"]["edges_unretained"], 12);
    }

    #[test]
    fn stream_progress_missing_admission_is_unknown() {
        let coordinator = coordinator();
        let report = stream_identity_report(vec![CallerEvent::Admitted {
            id: crate::discovery::caller_registry::CallerId(999),
        }]);
        let lines = progress_lines(&coordinator, &report).join("\n");
        assert!(lines.contains("unknown"), "{lines}");
        assert!(!lines.contains("pid 0"), "{lines}");
    }

    #[test]
    fn text_summary_names_callers_modules_edges_and_gaps() {
        let coordinator = coordinator();
        let text = render_text(&coordinator, "system", 90, 120, 2);
        assert!(
            text.starts_with("inventory system (2 passes, 0 callers, 0 modules, 0 edges)"),
            "{text}"
        );
    }

    #[test]
    fn gap_bound_defaults_to_1024_and_honors_the_override() {
        use crate::discovery::caller_registry::DEFAULT_MAX_GAPS;
        let absent = registry_limits(None);
        assert_eq!(absent, RegistryLimits::default_limits());
        assert_eq!(absent.max_gaps, DEFAULT_MAX_GAPS);
        assert_eq!(absent.max_gaps, 1024);
        // The override touches only the gap bound.
        let set = registry_limits(Some(3));
        assert_eq!(set.max_gaps, 3);
        assert_eq!(set.max_callers, absent.max_callers);
        assert_eq!(set.max_modules, absent.max_modules);
        assert_eq!(set.max_edges, absent.max_edges);
        assert_eq!(set.max_endpoints, absent.max_endpoints);
        assert_eq!(set.max_semantic_states, absent.max_semantic_states);
    }

    #[test]
    fn the_high_water_suffix_names_bytes_and_ring_share() {
        let ring = u64::from(crate::attach::EXPECTED_INVENTORY_DISCOVERY_BYTES);
        assert_eq!(
            lifecycle_high_water_suffix(ring / 2),
            format!(
                "; lifecycle ring high-water: {} B (50% of {ring} B)",
                ring / 2
            )
        );
        assert_eq!(
            lifecycle_high_water_suffix(0),
            format!("; lifecycle ring high-water: 0 B (0% of {ring} B)")
        );
        // Past-full still renders (a torn sample never divides by zero).
        assert!(lifecycle_high_water_suffix(u64::MAX).starts_with("; lifecycle ring high-water: "));
    }

    #[test]
    fn the_stop_line_carries_no_high_water_without_a_native_drain() {
        // With no native drain staged (high-water None) the stop line is
        // unchanged whatever the environment asks for: the suffix only
        // ever appends.
        let line = stop_line(&lane_summary(
            crate::inventory_capture::Retirement::Unsettled("budget passed".into()),
        ));
        assert!(!line.contains("high-water"), "{line}");
    }

    #[test]
    fn progress_lines_escape_target_controlled_reasons() {
        use crate::discovery::engine::inventory_coordinator::PassReport;
        let coordinator = coordinator();
        let report = PassReport {
            pass: 3,
            scanned: 0,
            maps_matched: 0,
            native_callers: 0,
            scan_callers: 0,
            engine_changed: false,
            pending_refresh: Vec::new(),
            events: vec![
                CallerEvent::AdmitFailed {
                    pid: 7,
                    reason: "cannot pin /tmp/evil\u{1b}[2J\u{7}".into(),
                    budget: None,
                },
                CallerEvent::Exited {
                    id: crate::discovery::caller_registry::CallerId(4),
                    reason: "gone\r\nfake".into(),
                },
            ],
            timings: crate::timing::StageTimings::new(),
        };
        let lines = progress_lines(&coordinator, &report);
        for line in &lines {
            assert!(!line.chars().any(char::is_control), "{line:?}");
        }
        assert!(
            lines
                .iter()
                .any(|line| line.ends_with("cannot pin /tmp/evil\\u{1b}[2J\\u{7}")),
            "{lines:?}"
        );
    }

    /// DR-K8S-4 through the real per-pass emitter: one identical gap over
    /// three passes is one `gap_recorded` plus `gap_repeated` deltas, and
    /// replaying the stream reproduces the snapshot's `repeats` exactly.
    #[test]
    fn the_real_pass_emitter_streams_repeats_that_equal_the_snapshot() {
        use crate::discovery::caller_registry::RegistryGap;
        use crate::discovery::engine::inventory_coordinator::PassReport;
        let mut coordinator = coordinator();
        let dir = private_tempdir();
        let path = dir.path().join("events.jsonl");
        let mut writer = EventWriter::create(&path, 1 << 20, 2).unwrap();
        let mut state = StreamState::new();
        for pass in 1..=3u64 {
            coordinator.registry_mut().record_gap(RegistryGap {
                caller: None,
                module: None,
                pid: None,
                subject: "overlay collapse".into(),
                reason: "two overlay instances map one inode".into(),
                budget: None,
            });
            if pass == 2 {
                coordinator.registry_mut().record_gap(RegistryGap {
                    caller: None,
                    module: None,
                    pid: Some(9),
                    subject: "once".into(),
                    reason: "only on pass 2".into(),
                    budget: None,
                });
            }
            coordinator.commit_batch(false).unwrap();
            let report = PassReport {
                pass,
                scanned: 0,
                maps_matched: 0,
                native_callers: 0,
                scan_callers: 0,
                engine_changed: false,
                pending_refresh: Vec::new(),
                events: Vec::new(),
                timings: crate::timing::StageTimings::new(),
            };
            let presentation = Presentation::capture(&coordinator, "pid", 0, pass, pass);
            emit_pass_events(&mut writer, &mut state, &report, &presentation, pass).unwrap();
        }
        // The pre-`ended` flush makes the last value per index exact.
        let last = Presentation::capture(&coordinator, "pid", 0, 3, 3);
        // Through the real terminal path: flush, then `ended`.
        let mut sink = Vec::new();
        assert_eq!(
            finish_output(
                None,
                &mut EventLogState::new(Some(writer)),
                &mut state,
                &last,
                false,
                true,
                &mut WriterStdout(&mut sink),
                None,
                None,
            )
            .exit_code(),
            0
        );
        let document = render_json(&coordinator, "pid", 0, 3, 3);
        let snapshot = document["gaps"].as_array().unwrap();
        let mut replayed: Vec<serde_json::Value> = Vec::new();
        let mut kinds = Vec::new();
        for line in std::fs::read_to_string(&path).unwrap().lines() {
            let line: serde_json::Value = serde_json::from_str(line).unwrap();
            kinds.push(line["kind"].as_str().unwrap().to_string());
            match line["kind"].as_str().unwrap() {
                "gap_recorded" => {
                    let mut gap = line["event"].clone();
                    assert!(gap.get("repeats").is_none(), "identity only: {gap}");
                    assert_eq!(gap["index"], replayed.len(), "ordinal index");
                    gap.as_object_mut().unwrap().remove("index");
                    gap["repeats"] = 1.into();
                    replayed.push(gap);
                }
                "gap_repeated" => {
                    let index = line["event"]["index"].as_u64().unwrap() as usize;
                    replayed[index]["repeats"] = line["event"]["repeats"].clone();
                }
                _ => {}
            }
        }
        assert_eq!(snapshot.len(), 2, "{snapshot:?}");
        assert_eq!(snapshot[0]["repeats"], 3);
        assert_eq!(replayed, *snapshot, "stream replay == snapshot");
        assert_eq!(kinds.last().map(String::as_str), Some("ended"));
        assert_eq!(
            kinds.iter().rposition(|k| k == "gap_repeated").unwrap() + 1,
            kinds.len() - 1,
            "the exact flush sits right before ended: {kinds:?}"
        );
        assert_eq!(kinds.iter().filter(|k| *k == "gap_recorded").count(), 2);
        assert_eq!(kinds.iter().filter(|k| *k == "gap_repeated").count(), 2);
    }

    /// A gap that recurs on every pass must let the stream go quiet:
    /// `gap_repeated` only at power-of-two crossings (O(log passes)
    /// lines), then one exact flush for whatever is outstanding.
    #[test]
    fn a_steady_recurring_gap_emits_logarithmic_repeat_lines() {
        use crate::discovery::caller_registry::RegistryGap;
        use crate::discovery::engine::inventory_coordinator::PassReport;
        let mut coordinator = coordinator();
        let dir = private_tempdir();
        let path = dir.path().join("events.jsonl");
        let mut writer = EventWriter::create(&path, 1 << 20, 2).unwrap();
        let mut state = StreamState::new();
        let passes = 100u64;
        let mut per_pass = Vec::new();
        for pass in 1..=passes {
            coordinator.registry_mut().record_gap(RegistryGap {
                caller: None,
                module: None,
                pid: None,
                subject: "steady".into(),
                reason: "every pass".into(),
                budget: None,
            });
            coordinator.commit_batch(false).unwrap();
            let report = PassReport {
                pass,
                scanned: 0,
                maps_matched: 0,
                native_callers: 0,
                scan_callers: 0,
                engine_changed: false,
                pending_refresh: Vec::new(),
                events: Vec::new(),
                timings: crate::timing::StageTimings::new(),
            };
            let presentation = Presentation::capture(&coordinator, "pid", 0, pass, pass);
            let before = writer.live_events();
            emit_pass_events(&mut writer, &mut state, &report, &presentation, pass).unwrap();
            per_pass.push(writer.live_events() - before);
        }
        let last = Presentation::capture(&coordinator, "pid", 0, passes, passes);
        state
            .gaps
            .emit(&mut writer, &last.gaps, true, passes)
            .unwrap();
        drop(writer);
        let repeated: Vec<u64> = std::fs::read_to_string(&path)
            .unwrap()
            .lines()
            .map(|line| serde_json::from_str::<serde_json::Value>(line).unwrap())
            .filter(|line| line["kind"] == "gap_repeated")
            .map(|line| line["event"]["repeats"].as_u64().unwrap())
            .collect();
        // Crossings 2,4,8,16,32,64, then the flush's exact 100.
        assert_eq!(repeated, vec![2, 4, 8, 16, 32, 64, 100]);
        // A quiet pass is exactly the pass marker (3..=3 means no repeat line).
        assert_eq!(per_pass[69], 1, "pass 70 is only pass_committed");
        assert_eq!(per_pass[98], 1, "pass 99 is only pass_committed");
    }

    /// C5.3: a terminal the dashboard cannot take over (here: an fd that
    /// cannot be reopened) degrades to the classic path with its report,
    /// never to an error or a half-entered screen.
    #[test]
    fn a_terminal_the_dashboard_cannot_take_over_degrades_to_the_classic_path() {
        let mut stdout = Vec::new();
        let terminal = DashboardIo {
            output: -1,
            input: None,
            account: None,
            stderr_fd: 2,
            stderr: StderrRoute::Leave,
        };
        let code = run_with_terminal(
            InspectScope::Pid(std::process::id()),
            &[],
            &HookRegistry::builtin(),
            true,
            None,
            None,
            None,
            None,
            true,
            None,
            None,
            None,
            CaptureMode::Scan,
            crate::attach::BackendSelection::Auto,
            &|| false,
            &|| {},
            true,
            &mut WriterStdout(&mut stdout),
            &terminal,
        )
        .unwrap();
        assert_eq!(code, 0);
        let document: serde_json::Value = serde_json::from_slice(&stdout).unwrap();
        assert_eq!(document["schema"], DOC_ID);
        assert!(!stdout.contains(&0x1b), "no ANSI on the degraded path");
    }

    /// C5.3 review M2: for the same input a dashboard run streams exactly
    /// what a classic run streams. The dashboard's display reads activity
    /// through its trailing 5 s window, the stream through the classic
    /// cumulative one: here a counted edge last used 10 s ago is recent for
    /// the stream and not for the display, and the stream records still
    /// match the classic ones byte for byte.
    #[test]
    fn a_dashboard_run_streams_what_a_classic_run_streams() {
        use crate::discovery::caller_registry::CoverageNote;
        use crate::discovery::inventory_workload::{Harness, ScaleSpec};
        let mut harness = Harness::new(RegistryLimits::default_limits()).unwrap();
        harness.stage_scale(&ScaleSpec {
            name: "m2-stream",
            callers: 1,
            modules: 1,
            edges_per_caller: 1,
            endpoints_per_module: 2,
            first_pid: 83_000,
        });
        harness.commit();
        let started = harness.now_ns();
        let caller = harness.coordinator().adapter().live_id(83_000).unwrap();
        let key = ModuleKey::physical(8, 1, 100_000, Some("sha000000".into()), "/scale/m0.so");
        harness.advance(1_000);
        let at = harness.now_ns();
        {
            let registry = harness.coordinator_mut().registry_mut();
            registry.note_coverage(caller, &key, CoverageNote::Counted { since_ns: at });
            registry.observe_entries(caller, &key, 3, at);
        }
        harness.commit();
        harness.advance(10_000_000_000);
        let now = harness.now_ns();
        let coordinator = harness.coordinator();
        let classic = stream_presentation(coordinator, "pid:83000", started, now);
        let (stream_view, display_view) = dashboard_pass_views(
            coordinator,
            "pid:83000",
            started,
            now,
            crate::inventory_semantics::SemanticCaptureSummary::default(),
        );
        let activity = |view: &Presentation| {
            view.edges
                .iter()
                .map(|edge| format!("{:?}", edge.activity))
                .collect::<Vec<_>>()
        };
        assert_eq!(activity(&classic).len(), 1);
        assert_eq!(activity(&stream_view), activity(&classic));
        assert_ne!(
            activity(&display_view),
            activity(&classic),
            "the scenario must make the windows disagree"
        );
        let report = PassReport {
            pass: 1,
            scanned: 1,
            maps_matched: 1,
            native_callers: 0,
            scan_callers: 1,
            engine_changed: false,
            pending_refresh: Vec::new(),
            events: Vec::new(),
            timings: crate::timing::StageTimings::new(),
        };
        let dir = private_tempdir();
        let stream = |name: &str, view: &Presentation| {
            let path = dir.path().join(name);
            let mut writer = EventWriter::create(&path, 1 << 20, 2).unwrap();
            let mut state = StreamState::new();
            emit_pass_events(&mut writer, &mut state, &report, view, now).unwrap();
            let mut sink = Vec::new();
            assert_eq!(
                finish_output(
                    None,
                    &mut EventLogState::new(Some(writer)),
                    &mut state,
                    view,
                    false,
                    true,
                    &mut WriterStdout(&mut sink),
                    None,
                    None,
                )
                .exit_code(),
                0
            );
            std::fs::read(&path).unwrap()
        };
        assert_eq!(
            stream("dashboard.jsonl", &stream_view),
            stream("classic.jsonl", &classic)
        );
        assert_eq!(
            render_json_from_presentation(&stream_view),
            render_json_from_presentation(&classic)
        );
    }

    mod driver_timing_tests {
        //! Driver commit timing through the production publication path:
        //! ticks commit stale staged batches, and the stop request
        //! flushes staged evidence before native retirement. The
        //! substituted lane I/O below is timing-only (ticks mint
        //! scripted receipts, validation approves): receipt validity is
        //! pinned by the real-H0 tests, while these tests pin commit
        //! timing through the production stage/finalize/commit path.
        use super::*;
        use crate::attach::BackendSelection;
        use crate::attach::capture::NativeDomainId;
        use crate::attach::image_query::CompleteEpochs;
        use crate::discovery::engine::inventory_coordinator::semantics::{
            AttestedSubset, SemanticCallerBinding,
        };
        use crate::discovery::identity::{PinnedObjectId, PinnedObjects};
        use crate::discovery::instances::{
            CallFacts, EntryIp, EpochReading, InstanceId, InstanceRouter, MapRange, Route,
            RouterLimits, StableObservation,
        };
        use crate::inventory_semantics::{
            AttestedSemanticLane, LaneCollectionRefusal, LaneDrainOutcome, LaneNegative,
            LaneTestIo, SemanticBatch, SemanticRefusal,
        };
        use crate::semantic_capture::{
            CurrentPartitionReceipt, CurrentReceiptRefusal, Endpoint, TickReport,
        };
        use p11scope_ebpf_common::InstanceStamp;
        use p11scope_ebpf_common::instance::STAMP_VALID;
        use std::sync::Arc;

        fn router_ids(domain: NativeDomainId, count: usize) -> Vec<InstanceId> {
            let image = ImageIdentity {
                task_cookie: 71,
                exec_id: 0,
            };
            let mut router = InstanceRouter::new(domain, RouterLimits::default());
            let ranges = (0..count)
                .map(|n| {
                    let base = 0x7000_0000 + n as u64 * 0x10000;
                    MapRange::new(base, base + 0x3000, 0, true)
                })
                .collect();
            router.observe_legacy(StableObservation {
                file_slot: 0,
                reading: EpochReading {
                    cookie: 71,
                    local: 1,
                    global: 0,
                    fault: 0,
                    record_flags: 0,
                    sticky: 0,
                },
                ranges,
                fence: 0,
            });
            (0..count)
                .map(|n| {
                    let stamp = InstanceStamp {
                        epoch: 1,
                        file_slot_plus1: 1,
                        flags: STAMP_VALID,
                        ..InstanceStamp::default()
                    };
                    match router.route(CallFacts {
                        token: n as u64 + 1,
                        domain,
                        image,
                        entry: stamp,
                        ret: stamp,
                        ip: EntryIp::new(0x7000_0000 + n as u64 * 0x10000 + 0x1000),
                        attached_offset: Some(0x1000),
                    }) {
                        Route::Joined(id) => id,
                        other => panic!("fixture must route a real instance: {other:?}"),
                    }
                })
                .collect()
        }

        fn stub_subset() -> AttestedSubset {
            let slot = crate::plan::Slot {
                index: 0,
                descriptor_index: crate::kinds::function_id("C_SignInit").unwrap() + 1,
                object: PinnedObjectId(0),
                object_path: "/stub-provider.so".into(),
                file_offset: 0x1200,
                names: vec!["C_SignInit".into()],
                aliased: false,
                semantics: crate::kinds::descriptor("C_SignInit").unwrap(),
                semantic_authorized: true,
                semantic_ambiguous: false,
                fork_safe: true,
                module_ids: vec![crate::plan::ModuleId(0)],
            };
            let plan = crate::plan::AttachPlan::from_slots(vec![slot]);
            AttestedSubset::scripted(
                plan,
                stub_pins(),
                std::collections::BTreeMap::from([(
                    PinnedObjectId(0),
                    std::collections::BTreeSet::from([0]),
                )]),
            )
        }

        fn stub_pins() -> PinnedObjects {
            static PINS: std::sync::OnceLock<std::sync::Mutex<PinnedObjects>> =
                std::sync::OnceLock::new();
            PINS.get_or_init(|| {
                std::sync::Mutex::new({
                    use p11scope_manifest::identity::{
                        inspect_file, mapping_file_key, open_object,
                    };
                    let path = std::env::current_exe().unwrap();
                    let file = open_object(&path).unwrap();
                    let inspected = inspect_file(&file).unwrap();
                    let mapping = mapping_file_key(&file).unwrap();
                    let key = p11scope_manifest::maps::ObjectKey {
                        device: p11scope_manifest::maps::Device {
                            major: mapping.device_major,
                            minor: mapping.device_minor,
                        },
                        inode: mapping.inode,
                    };
                    crate::discovery::identity::test_fixture::real_scan_pin(
                        &path,
                        Some(key),
                        mapping.mount_id,
                        inspected.identity.sha256.as_deref().unwrap(),
                    )
                })
            })
            .lock()
            .unwrap()
            .clone()
        }

        struct StubLaneIo {
            image: ImageIdentity,
            endpoint: Endpoint,
            watched: crate::discovery::identity::RetainedInventoryTarget,
            ids: Vec<InstanceId>,
            quiesce: bool,
            pending: bool,
            receipt_free: bool,
        }

        impl StubLaneIo {
            fn new(image: ImageIdentity, ids: Vec<InstanceId>) -> Self {
                let pins = crate::discovery::identity::test_fixture::real_scan_pin(
                    &std::env::current_exe().unwrap(),
                    None,
                    1,
                    "held-test-image",
                );
                let watched = pins.retain_inventory_target(PinnedObjectId(0)).unwrap();
                Self {
                    image,
                    endpoint: Endpoint {
                        object: PinnedObjectId(0),
                        file_slot: 0,
                        offset: 0x1200,
                    },
                    watched,
                    ids,
                    quiesce: false,
                    pending: false,
                    receipt_free: false,
                }
            }
        }

        impl LaneTestIo for StubLaneIo {
            fn validate_current(
                &mut self,
                _receipt: &CurrentPartitionReceipt,
                _report: &mut TickReport,
            ) -> Result<(), CurrentReceiptRefusal> {
                Ok(())
            }

            fn tick(&mut self, domain: NativeDomainId) -> Result<SemanticBatch, SemanticRefusal> {
                if self.receipt_free {
                    return Ok(SemanticBatch::scripted(
                        domain,
                        vec![LaneNegative::CollectionRefused {
                            reason: LaneCollectionRefusal::CollectionFailed,
                        }],
                        0,
                    ));
                }
                let id = self.ids.pop().expect("stub router ids exhausted");
                let receipt = CurrentPartitionReceipt::scripted(
                    domain,
                    self.image,
                    Arc::new(PidPin::test_proc_only(std::process::id())),
                    self.endpoint,
                    0,
                    self.watched.share(),
                    CompleteEpochs {
                        local: 0,
                        global: 0,
                        fault: 0,
                        sticky: 0,
                        record_flags: 0,
                    },
                    0,
                    Instant::now() + Duration::from_secs(60),
                    vec![id],
                );
                SemanticBatch::from_tick_report(
                    domain,
                    TickReport::scripted(Vec::new(), vec![receipt]),
                    Vec::new(),
                    0,
                )
            }

            fn refresh(
                &mut self,
                pin: Arc<PidPin>,
                _slot: u32,
            ) -> Result<(Vec<ImageIdentity>, Arc<PidPin>), SemanticRefusal> {
                Ok((Vec::new(), pin))
            }

            fn has_pending_evidence(&self) -> bool {
                self.pending
            }

            fn finish(&mut self, domain: NativeDomainId) -> SemanticBatch {
                SemanticBatch::scripted(domain, Vec::new(), 0)
            }

            fn quiescent(&mut self) -> bool {
                self.quiesce
            }

            fn positions(&mut self) -> Option<[(usize, usize); 2]> {
                Some([(0, 0), (0, 0)])
            }

            fn drain_events_to(&mut self, _stop: usize, _quantum: usize) -> LaneDrainOutcome {
                LaneDrainOutcome::default()
            }

            fn drain_discovery_to(&mut self, _stop: usize, _quantum: usize) -> LaneDrainOutcome {
                LaneDrainOutcome::default()
            }
        }

        struct DriverScene {
            coordinator: InventoryCoordinator<OsProcessSource>,
            lane: AttestedSemanticLane,
            stub: StubLaneIo,
        }

        fn driver_scene(id_count: usize) -> DriverScene {
            let image = ImageIdentity {
                task_cookie: 7,
                exec_id: 1,
            };
            let mut coordinator = coordinator();
            let pid = std::process::id();
            let caller = coordinator
                .adapter_mut()
                .admit(pid, ImageAuthority::ScanPinned, 50)
                .unwrap();
            let pins = stub_pins();
            let pin = pins.pinned().next().unwrap();
            let module = ModuleKey::physical(
                pin.key.device.major,
                pin.key.device.minor,
                pin.key.inode,
                Some(pin.sha256.to_owned()),
                pin.path,
            );
            coordinator.registry_mut().note_mapping(
                caller,
                pid,
                ModuleInfo {
                    path: "/task3/provider.so".into(),
                    key: module.clone(),
                    double_loaded: false,
                    build_id: None,
                    identity_source: Some("task3".into()),
                    admission: AdmissionState::Admitted,
                    admission_class: Some("exact".into()),
                    admission_endpoints: Some(1),
                    admission_reasons: Vec::new(),
                },
                60,
            );
            coordinator.commit_batch(false).unwrap();
            let lane = AttestedSemanticLane::start(
                stub_subset(),
                &Scope::Pid(pid),
                BackendSelection::Auto,
            )
            .expect("shell lane starts");
            let domain = lane.domain();
            coordinator
                .semantic_bindings_mut()
                .insert_for_test(SemanticCallerBinding::scripted(
                    caller,
                    module,
                    domain,
                    image,
                    Arc::new(PidPin::test_proc_only(pid)),
                ))
                .unwrap();
            let stub = StubLaneIo::new(image, router_ids(domain, id_count));
            DriverScene {
                coordinator,
                lane,
                stub,
            }
        }

        #[test]
        fn receipt_free_staged_batch_commits_on_tick_while_fresh_stays() {
            let mut scene = driver_scene(2);
            scene.stub.receipt_free = true;
            scene.lane.install_test_io(Box::new(scene.stub));
            let mut driver = ClassicDriver {
                coordinator: &mut scene.coordinator,
                inventory_scope: None,
                scope: InventoryRunScope::Pid(std::process::id()),
                cgroup: None,
                max_scan_pids: None,
                guard: UnavailableImageGuard,
                deadline: None,
                attach_backend: crate::attach::BackendSelection::Auto,
                identity: None,
                display: None,
                semantic: Some(scene.lane),
                semantic_staged: false,
                seated_summary: None,
                second_signal: None,
                lifecycle: crate::inventory_promotion::lifecycle::SelectedLifecycleService::new(),
                completion_source: None,
                pending_install: None,
                installed_promotion: None,
                retiring: None,
                joint_finish: JointFinishDriver::NotBegun,
                stop_requested: false,
                joint_first_error: None,
                suspended: false,
                joint_commit_pending: false,
                joint_tick_refusal: None,
                joint_commit_retries: 0,
                #[cfg(test)]
                terminal_seq_calls: 0,
                #[cfg(test)]
                reclaim_calls: Vec::new(),
                #[cfg(test)]
                joint_begin_calls: 0,
                #[cfg(test)]
                joint_step_calls: 0,
                #[cfg(test)]
                joint_commit_polls: 0,
                #[cfg(test)]
                take_promotion_work_calls: 0,
                #[cfg(test)]
                drive_pending_install_calls: 0,
                #[cfg(test)]
                service_caller_metadata_calls: 0,
                #[cfg(test)]
                commit_calls: 0,
            };
            // The first tick stages; a fresh staged batch stays staged
            // across further ticks instead of committing early.
            driver.on_tick();
            assert!(driver.semantic_staged, "the first tick stages");
            assert!(driver.coordinator.registry().gaps().is_empty());
            driver.on_tick();
            assert!(driver.semantic_staged, "a fresh staged batch stays staged");
            assert_eq!(
                driver.coordinator.registry().gaps().len(),
                0,
                "nothing publishes before the staleness deadline"
            );
            // Age past the deadline: the next tick commits the stale
            // batch first, then stages fresh.
            driver.semantic.as_mut().unwrap().age_staged_for_test(
                Instant::now() - STAGED_SEMANTIC_MAX_AGE - Duration::from_secs(1),
            );
            driver.on_tick();
            assert!(
                driver.semantic_staged,
                "a fresh batch stages after the stale commit"
            );
            assert_eq!(
                driver
                    .coordinator
                    .registry()
                    .gaps()
                    .iter()
                    .filter(|gap| gap.subject == "semantic collection refused")
                    .count(),
                1,
                "the stale batch publishes through the tick commit"
            );
            assert!(
                driver
                    .semantic
                    .as_ref()
                    .unwrap()
                    .staged_semantic_age()
                    .is_some_and(|age| age < STAGED_SEMANTIC_MAX_AGE),
                "the restaged batch is fresh"
            );
        }

        #[test]
        fn stop_request_flushes_staged_evidence_before_retirement() {
            let mut scene = driver_scene(2);
            // Stashed quiet evidence awaits the stop; the producer is
            // already quiet, so the drain pre-flushes then quiesces.
            scene.stub.pending = true;
            scene.stub.quiesce = true;
            scene.lane.install_test_io(Box::new(scene.stub));
            // Seed an unpublished batch to exercise the stop hook's
            // fallback flush (ordinary receipt-bearing ticks now
            // publish immediately).
            let batch = scene
                .lane
                .tick(
                    scene
                        .coordinator
                        .semantic_bindings_mut()
                        .bindings_for_tick(),
                )
                .unwrap();
            scene.coordinator.stage_semantic_batch(batch);
            scene.lane.note_semantic_staged();
            let mut driver = ClassicDriver {
                coordinator: &mut scene.coordinator,
                inventory_scope: None,
                scope: InventoryRunScope::Pid(std::process::id()),
                cgroup: None,
                max_scan_pids: None,
                guard: UnavailableImageGuard,
                deadline: None,
                attach_backend: crate::attach::BackendSelection::Auto,
                identity: None,
                display: None,
                semantic: Some(scene.lane),
                semantic_staged: true,
                seated_summary: None,
                second_signal: None,
                lifecycle: crate::inventory_promotion::lifecycle::SelectedLifecycleService::new(),
                completion_source: None,
                pending_install: None,
                installed_promotion: None,
                retiring: None,
                joint_finish: JointFinishDriver::NotBegun,
                stop_requested: false,
                joint_first_error: None,
                suspended: false,
                joint_commit_pending: false,
                joint_tick_refusal: None,
                joint_commit_retries: 0,
                #[cfg(test)]
                terminal_seq_calls: 0,
                #[cfg(test)]
                reclaim_calls: Vec::new(),
                #[cfg(test)]
                joint_begin_calls: 0,
                #[cfg(test)]
                joint_step_calls: 0,
                #[cfg(test)]
                joint_commit_polls: 0,
                #[cfg(test)]
                take_promotion_work_calls: 0,
                #[cfg(test)]
                drive_pending_install_calls: 0,
                #[cfg(test)]
                service_caller_metadata_calls: 0,
                #[cfg(test)]
                commit_calls: 0,
            };
            assert!(driver.semantic_staged, "one quantum stages");
            assert_eq!(driver.coordinator.registry().instances().count(), 0);
            // The stop request flushes before native retirement would
            // run: the staged quantum publishes, the drain pre-flushes
            // stashed evidence, and H0 finishes.
            driver.on_stop_requested();
            assert!(
                !driver.semantic_staged,
                "the staged quantum publishes at stop request"
            );
            assert_eq!(
                driver.coordinator.registry().instances().count(),
                2,
                "staged plus pre-flushed evidence publish before retirement"
            );
            assert!(
                driver.semantic.as_ref().unwrap().is_finished(),
                "H0 stops at stop request"
            );
            // The post-retirement hook is a no-op once finished.
            driver.on_lane_stopped();
            assert_eq!(
                driver.coordinator.registry().instances().count(),
                2,
                "the safety net publishes nothing twice"
            );
        }
    }

    // Retained dispositions, suspension and the finite-stop consumer
    // (§6.1, §6.3, §6.4, §7): the driver fixtures live beside the
    // promotion tests; only the coordinator stays local (it would
    // collide with this module's own).
    use super::promotion_driver_tests::{
        CountingSource, WindDownIo, driver_with_display, gaps, headless_display, joint_lane,
        queue_request, wind_down_lane,
    };
    use crate::inventory_capture::{
        BlockDisposition, ClassicCompletion, ClassicOutcome, FacadeLane, LoopClock, Publish,
        RetainedBlock, RetainedClassicRun, RetainedWorkBudget, Stopped, ZERO_PASS_GAP_SUBJECT,
        ZeroPassCause, ZeroPassStop,
    };
    use crate::inventory_promotion::PromotionState;

    /// A consumption clock over a caller-held stop closure: the
    /// retained run already sampled its cause, so this clock only
    /// bounds native steps. Shared with the Driver cells.
    pub(crate) fn consume_clock(stop_now: &dyn Fn() -> bool) -> LoopClock<'_> {
        LoopClock {
            deadline: None,
            stop: stop_now,
            now: &std::time::Instant::now,
            interval: super::inventory_test_poll_interval(),
            tick: crate::inventory_capture::SERVICE_TICK,
            collection_tick: crate::inventory_capture::SERVICE_TICK,
        }
    }

    /// Retain through the real classic loop: the caller presets the
    /// pending publication (Polling, or the commit flag) and seats
    /// the lane; the loop suspends at its first wait site with the
    /// requested stop cause, before any collection. Scan lane: no
    /// native owner, no BPF. Shared with the Driver cells.
    pub(crate) fn retain_with_cause(
        driver: &mut ClassicDriver<'_>,
        cause: ZeroPassCause,
        initial_error: Option<anyhow::Error>,
    ) -> crate::inventory_capture::ClassicOutcome<crate::inventory_capture::FacadeLane> {
        let stop = cause == ZeroPassCause::OperatorStop;
        let stop_now = || stop;
        let clock = LoopClock {
            deadline: (cause == ZeroPassCause::Deadline)
                .then(|| std::time::Instant::now() - std::time::Duration::from_secs(1)),
            stop: &stop_now,
            now: &std::time::Instant::now,
            interval: super::inventory_test_poll_interval(),
            tick: crate::inventory_capture::SERVICE_TICK,
            collection_tick: crate::inventory_capture::SERVICE_TICK,
        };
        crate::inventory_capture::run_classic_finalizing(
            driver,
            None,
            &clock,
            initial_error,
            &mut |_, _| Ok(()),
        )
    }

    /// Retain with an error but no stop cause: the initial-error
    /// path suspends on the pending publication without sampling
    /// any stop. The N1 wait needs its causeless run.
    pub(crate) fn retain_with_error_no_stop(
        driver: &mut ClassicDriver<'_>,
        text: &str,
    ) -> crate::inventory_capture::ClassicOutcome<crate::inventory_capture::FacadeLane> {
        let stop_now = || false;
        let clock = LoopClock {
            deadline: None,
            stop: &stop_now,
            now: &std::time::Instant::now,
            interval: super::inventory_test_poll_interval(),
            tick: crate::inventory_capture::SERVICE_TICK,
            collection_tick: crate::inventory_capture::SERVICE_TICK,
        };
        crate::inventory_capture::run_classic_finalizing(
            driver,
            None,
            &clock,
            Some(anyhow::anyhow!("{text}")),
            &mut |_, _| Ok(()),
        )
    }

    /// The retained run beside its driver, or an assertion failure
    /// naming the missing retention. Shared with the Driver cells.
    pub(crate) fn retained_run_of(
        outcome: crate::inventory_capture::ClassicOutcome<crate::inventory_capture::FacadeLane>,
    ) -> (
        RetainedClassicRun<crate::inventory_capture::FacadeLane>,
        Option<anyhow::Error>,
    ) {
        assert!(
            outcome.retained.is_some(),
            "the loop retains its run beside the driver"
        );
        match outcome.into_completion() {
            Ok(ClassicCompletion::Retained { run, error }) => (run, error),
            _ => panic!("retention keeps the run"),
        }
    }

    #[test]
    fn suspended_hooks_service_only_joint_frame_and_finish() {
        use std::cell::Cell;
        use std::rc::Rc;

        // The suspension gate latches only (§6.2): no terminal I/O,
        // no drain, no publication, no owner extraction.
        {
            let mut coord = coordinator();
            let headless = headless_display();
            let mut driver = driver_with_display(&mut coord, headless.display);
            driver.semantic = Some(joint_lane(WindDownIo::completing(), false));
            driver.on_publication_suspended();
            assert!(driver.suspended, "the hook latches suspension");
            assert_eq!(driver.terminal_seq_calls, 0, "no terminal sequence");
            assert_eq!(driver.joint_begin_calls, 0, "no finish begin");
            assert_eq!(driver.joint_step_calls, 0, "no driver step");
            assert_eq!(driver.joint_commit_polls, 0, "no commit poll");
            assert_eq!(driver.commit_calls, 0, "no commit");
            assert!(driver.semantic.is_some(), "no owner extraction at the gate");
            assert!(
                !driver
                    .semantic
                    .as_ref()
                    .expect("lane")
                    .joint_finish_disposition_required(),
                "no latch at the gate"
            );
        }

        // Eight suspended cycles over a polling Joint lane: the
        // finish polls, everything else stays quiet.
        {
            let mut coord = coordinator();
            let headless = headless_display();
            let mut driver = driver_with_display(&mut coord, headless.display);
            let mut io = WindDownIo::completing();
            let ticks = Rc::new(Cell::new(0));
            io.ticks = Rc::clone(&ticks);
            // In-flight through the scripted poll: the finish polls
            // on without latching while suspended.
            let mut lane = joint_lane(io, false);
            lane.set_scripted_finish_poll_for_test(Some(Ok(JointCommitProgress::Pending)));
            driver.semantic = Some(lane);
            driver.joint_finish = JointFinishDriver::Polling;
            driver.suspended = true;
            queue_request(driver.display.as_mut().expect("display"));
            let display_ticks = driver.display.as_ref().expect("display").account().ticks;
            for _ in 0..8 {
                driver.on_native_service(None);
                driver.on_tick();
            }
            assert_eq!(
                driver.take_promotion_work_calls, 0,
                "suspension takes no promotion work"
            );
            assert_eq!(
                driver.drive_pending_install_calls, 0,
                "suspension drives no held install"
            );
            assert_eq!(
                driver.service_caller_metadata_calls, 0,
                "suspension services no caller metadata"
            );
            assert_eq!(ticks.get(), 0, "suspension ticks no lane");
            assert_eq!(
                driver.display.as_ref().expect("display").promotion_state(),
                PromotionState::Queued,
                "the queued request waits untouched"
            );
            assert!(
                driver.lifecycle.is_idle(),
                "no preparation starts while suspended"
            );
            assert!(
                gaps(&mut driver)
                    .iter()
                    .all(|(subject, _)| subject != "selected promotion refused"),
                "no refusal while suspended: {:?}",
                gaps(&mut driver)
            );
            assert_eq!(
                driver.joint_step_calls, 8,
                "every cycle polls the joint finish"
            );
            assert_eq!(
                driver.joint_commit_polls, 0,
                "no pending commit means no commit poll"
            );
            assert_eq!(driver.joint_begin_calls, 0, "polling never re-begins");
            assert_eq!(
                driver.joint_finish,
                JointFinishDriver::Polling,
                "an in-flight lane polls without latching"
            );
            assert!(driver.semantic.is_some(), "the polling lane is kept");
            assert_eq!(
                driver.display.as_ref().expect("display").account().ticks,
                display_ticks + 8,
                "every cycle still ticks the display"
            );
        }

        // A legacy lane gets nothing while suspended: no lane tick,
        // and the lane survives (no finish step exists for it).
        {
            let mut coord = coordinator();
            let headless = headless_display();
            let mut driver = driver_with_display(&mut coord, headless.display);
            let mut io = WindDownIo::completing();
            let ticks = Rc::new(Cell::new(0));
            io.ticks = Rc::clone(&ticks);
            let mut lane = joint_lane(io, false);
            lane.set_test_joint_frame(false);
            lane.set_test_joint_machine(false);
            driver.semantic = Some(lane);
            driver.suspended = true;
            for _ in 0..8 {
                driver.on_tick();
            }
            assert_eq!(ticks.get(), 0, "a legacy lane is not ticked");
            assert_eq!(driver.joint_begin_calls, 0, "no begin for legacy");
            assert_eq!(driver.joint_step_calls, 0, "no step for legacy");
            assert!(
                driver.semantic.is_some(),
                "the legacy lane survives suspension"
            );
            // Positive control: unsuspended, the same lane ticks.
            driver.suspended = false;
            driver.on_tick();
            assert_eq!(ticks.get(), 1, "the spy observes a real lane tick");
        }

        // A pending commit polls the joint commit, never begins.
        {
            let mut coord = coordinator();
            let headless = headless_display();
            let mut driver = driver_with_display(&mut coord, headless.display);
            driver.semantic = Some(joint_lane(WindDownIo::completing(), false));
            driver.joint_commit_pending = true;
            driver.suspended = true;
            driver.on_tick();
            assert_eq!(
                driver.joint_commit_polls, 1,
                "one suspended cycle polls the pending commit"
            );
            assert_eq!(
                driver.joint_begin_calls, 0,
                "a pending commit never begins the finish"
            );
        }

        // After the commit completes, the finish begins once; a
        // polling lane then polls its finish every cycle.
        {
            let mut coord = coordinator();
            let headless = headless_display();
            let mut driver = driver_with_display(&mut coord, headless.display);
            driver.semantic = Some(joint_lane(WindDownIo::completing(), false));
            driver.suspended = true;
            driver.on_tick();
            assert_eq!(
                driver.joint_begin_calls, 1,
                "after the commit completes, the finish begins once"
            );
            assert_eq!(
                driver.joint_commit_polls, 0,
                "no pending commit means no commit poll"
            );

            {
                let mut coordinator2 = coordinator();
                let headless = headless_display();
                let mut driver = driver_with_display(&mut coordinator2, headless.display);
                driver.semantic = Some(joint_lane(WindDownIo::completing(), true));
                driver.joint_finish = JointFinishDriver::Polling;
                driver.suspended = true;
                for _ in 0..8 {
                    driver.on_tick();
                }
                assert!(
                    driver.joint_step_calls >= 1,
                    "a polling lane polls its finish: {}",
                    driver.joint_step_calls
                );
            }
        }

        // Positive controls: unsuspended hooks run everything the
        // suspended cycles above skipped.
        {
            let mut coord = coordinator();
            let headless = headless_display();
            let mut driver = driver_with_display(&mut coord, headless.display);
            driver.semantic = Some(joint_lane(WindDownIo::completing(), false));
            queue_request(driver.display.as_mut().expect("display"));
            driver.on_native_service(None);
            driver.on_tick();
            assert_eq!(
                driver.service_caller_metadata_calls, 1,
                "the metadata spy observes a real service"
            );
            assert_eq!(
                driver.take_promotion_work_calls, 1,
                "the take spy observes a real take"
            );
            assert_eq!(
                driver.drive_pending_install_calls, 1,
                "the install spy observes a real drive"
            );
            assert_ne!(
                driver.display.as_ref().expect("display").promotion_state(),
                PromotionState::Queued,
                "unsuspended, the request is taken"
            );
        }
    }

    #[test]
    fn joint_driver_retained_path_begins_finish_from_suspended_tick() {
        // The retained path begins from the suspended tick, never
        // through the stop request: an unfinished lane abandons
        // through the begin refusal with the stop unlatched.
        {
            let mut coord = coordinator();
            let headless = headless_display();
            let mut driver = driver_with_display(&mut coord, headless.display);
            driver.semantic = Some(joint_lane(WindDownIo::completing(), false));
            driver.suspended = true;
            driver.on_tick();
            assert_eq!(
                driver.joint_begin_calls, 1,
                "the suspended tick begins the retained finish once"
            );
            assert_eq!(
                driver.joint_finish,
                JointFinishDriver::Abandoned,
                "the begin refusal abandons"
            );
            assert!(
                !driver.stop_requested,
                "the retained path never calls on_stop_requested"
            );
            assert_eq!(
                driver.terminal_seq_calls, 0,
                "no terminal sequence on the retained path"
            );
            assert!(driver.suspended, "suspension sticks");
        }
        // Twin: a finished lane resumes at the wound-down phase.
        {
            let mut coord = coordinator();
            let headless = headless_display();
            let mut driver = driver_with_display(&mut coord, headless.display);
            driver.semantic = Some(joint_lane(WindDownIo::completing(), true));
            driver.suspended = true;
            driver.on_tick();
            assert_eq!(driver.joint_begin_calls, 1, "the tick begins once");
            assert_eq!(
                driver.joint_finish,
                JointFinishDriver::Published,
                "a finished lane resumes at the wound-down phase"
            );
            assert!(
                !driver.stop_requested,
                "the retained path never calls on_stop_requested"
            );
            assert!(
                driver.semantic.is_some(),
                "the published lane is kept for the wound-down"
            );
        }
    }

    #[test]
    fn dispose_retained_publication_steps_joint_driver_once_per_call() {
        use std::time::{Duration, Instant};

        fn budget() -> RetainedWorkBudget {
            RetainedWorkBudget {
                remaining_actions: 1024,
                deadline: Instant::now() + Duration::from_millis(10),
            }
        }

        // NotBegun with a pending commit: one commit poll, no begin.
        // The pending commit itself suspends the loop.
        {
            let mut coord = coordinator();
            let headless = headless_display();
            let mut driver = driver_with_display(&mut coord, headless.display);
            driver.semantic = Some(joint_lane(WindDownIo::completing(), false));
            driver.joint_commit_pending = true;
            let outcome = super::tests::retain_with_cause(
                &mut driver,
                crate::inventory_capture::ZeroPassCause::OperatorStop,
                None,
            );
            let (mut run, _) = retained_run_of(outcome);
            assert!(driver.suspended, "retention suspends the driver");
            assert_eq!(
                driver.joint_finish,
                JointFinishDriver::NotBegun,
                "retention begins nothing"
            );
            let mut budget = budget();
            let disposition: Result<BlockDisposition, anyhow::Error> =
                driver.dispose_retained(RetainedBlock::Publication, &mut run, &mut budget);
            assert_eq!(driver.joint_commit_polls, 1, "one call polls once");
            assert_eq!(driver.joint_begin_calls, 0, "a pending commit never begins");
            assert_eq!(driver.joint_step_calls, 0, "no begun step runs");
            // The substituted commit refusal takes the finite stop, so
            // nothing stays pending afterwards.
            assert_eq!(
                disposition.unwrap(),
                BlockDisposition::Resolved,
                "the held lane leaves nothing pending"
            );
            assert_eq!(
                driver.joint_finish,
                JointFinishDriver::Abandoned,
                "the commit refusal abandons"
            );
            assert!(driver.semantic.is_none(), "the lane is held");
        }

        // NotBegun with no pending commit: one begin, no commit poll.
        {
            let mut coord = coordinator();
            let headless = headless_display();
            let mut driver = driver_with_display(&mut coord, headless.display);
            driver.semantic = Some(joint_lane(WindDownIo::completing(), false));
            driver.joint_finish = JointFinishDriver::Polling;
            let outcome = super::tests::retain_with_cause(
                &mut driver,
                crate::inventory_capture::ZeroPassCause::OperatorStop,
                None,
            );
            let (mut run, _) = retained_run_of(outcome);
            driver.joint_finish = JointFinishDriver::NotBegun;
            let mut budget = budget();
            let disposition: Result<BlockDisposition, anyhow::Error> =
                driver.dispose_retained(RetainedBlock::Publication, &mut run, &mut budget);
            assert_eq!(driver.joint_begin_calls, 1, "one call begins once");
            assert_eq!(driver.joint_commit_polls, 0, "no pending commit, no poll");
            assert_eq!(
                disposition.unwrap(),
                BlockDisposition::Resolved,
                "the held lane leaves nothing pending"
            );
        }

        // Polling: each call polls the finish once and stays pending.
        {
            let mut coord = coordinator();
            let headless = headless_display();
            let mut driver = driver_with_display(&mut coord, headless.display);
            // In-flight through the scripted poll: the finish polls
            // on without latching.
            let mut lane = joint_lane(WindDownIo::completing(), false);
            lane.set_scripted_finish_poll_for_test(Some(Ok(JointCommitProgress::Pending)));
            driver.semantic = Some(lane);
            driver.joint_finish = JointFinishDriver::Polling;
            let outcome = super::tests::retain_with_cause(
                &mut driver,
                crate::inventory_capture::ZeroPassCause::OperatorStop,
                None,
            );
            let (mut run, _) = retained_run_of(outcome);
            let mut budget = budget();
            for step in 1..=3 {
                let disposition: Result<BlockDisposition, anyhow::Error> =
                    driver.dispose_retained(RetainedBlock::Publication, &mut run, &mut budget);
                assert_eq!(
                    driver.joint_step_calls, step,
                    "call {step} spends one finish poll"
                );
                assert_eq!(
                    disposition.unwrap(),
                    BlockDisposition::Pending,
                    "a polling finish holds its block"
                );
            }
            assert_eq!(
                driver.joint_finish,
                JointFinishDriver::Polling,
                "an in-flight lane polls without latching"
            );
            assert!(driver.semantic.is_some(), "the polling lane is kept");
            assert_eq!(driver.joint_begin_calls, 0, "polling never re-begins");
            assert_eq!(driver.joint_commit_polls, 0, "polling polls no commit");
        }

        // Published: one wound-down poll; the published publication
        // resolves while the detach keeps reaping on ticks.
        {
            let mut coord = coordinator();
            let headless = headless_display();
            let mut driver = driver_with_display(&mut coord, headless.display);
            let (io, gate) = WindDownIo::gated();
            let polls = std::rc::Rc::clone(&io.polls);
            driver.semantic = Some(joint_lane(io, true));
            driver.joint_finish = JointFinishDriver::Polling;
            let outcome = super::tests::retain_with_cause(
                &mut driver,
                crate::inventory_capture::ZeroPassCause::OperatorStop,
                None,
            );
            let (mut run, _) = retained_run_of(outcome);
            driver.joint_finish = JointFinishDriver::Published;
            let mut budget = budget();
            let disposition: Result<BlockDisposition, anyhow::Error> =
                driver.dispose_retained(RetainedBlock::Publication, &mut run, &mut budget);
            assert_eq!(polls.get(), 1, "one call reaps the detach once");
            assert_eq!(
                disposition.unwrap(),
                BlockDisposition::Resolved,
                "a published finish resolves its publication block"
            );
            assert_eq!(
                driver.joint_finish,
                JointFinishDriver::Published,
                "the pending detach keeps its phase"
            );
            assert!(driver.semantic.is_some(), "the lane is kept");
            assert!(
                driver.joint_first_error.is_none(),
                "no error on the wound-down path"
            );
            // Our gate handle drops; the detach stays pending, never joined.
            drop(gate);
        }
    }

    #[test]
    fn dispose_retained_publication_abandons_on_i2_trigger() {
        use std::time::{Duration, Instant};

        let mut coord = coordinator();
        let headless = headless_display();
        let mut driver = driver_with_display(&mut coord, headless.display);
        let mut io = WindDownIo::completing();
        let drops = std::rc::Rc::new(std::cell::Cell::new(0));
        io.drop_spy = Some(std::rc::Rc::clone(&drops));
        let detach_polls = std::rc::Rc::clone(&io.polls);
        let mut lane = joint_lane(io, false);
        lane.note_joint_finish_failure(crate::inventory_semantics::SemanticRefusal::Unavailable);
        driver.semantic = Some(lane);
        driver.joint_finish = JointFinishDriver::Polling;
        let outcome = super::tests::retain_with_cause(
            &mut driver,
            crate::inventory_capture::ZeroPassCause::OperatorStop,
            None,
        );
        let (mut run, _) = retained_run_of(outcome);
        let revision_before = driver.coordinator.registry().facts_revision();
        let mut budget = RetainedWorkBudget {
            remaining_actions: 1024,
            deadline: Instant::now() + Duration::from_millis(10),
        };
        let disposition: Result<BlockDisposition, anyhow::Error> =
            driver.dispose_retained(RetainedBlock::Publication, &mut run, &mut budget);
        assert_eq!(
            disposition.unwrap(),
            BlockDisposition::Resolved,
            "the abandoned lane leaves nothing pending"
        );
        assert_eq!(
            driver.joint_finish,
            JointFinishDriver::Abandoned,
            "the I2 trigger abandons"
        );
        assert!(driver.semantic.is_none(), "the lane is held");
        assert_eq!(drops.get(), 0, "held means never dropped");
        assert_eq!(
            driver.joint_first_error.as_deref(),
            Some("joint finish disposition required"),
            "the first error is kept"
        );
        assert_eq!(detach_polls.get(), 0, "the abandon never joins");
        assert_eq!(
            driver.coordinator.registry().facts_revision(),
            revision_before + 1,
            "the abandon commits once, best effort"
        );
        let abandons: Vec<(String, String)> = gaps(&mut driver)
            .into_iter()
            .filter(|(subject, _)| subject == "joint finish abandoned for exit")
            .collect();
        assert_eq!(
            abandons.len(),
            1,
            "exactly one abandon gap: {:?}",
            gaps(&mut driver)
        );
    }

    #[test]
    fn dispose_retained_non_joint_blocks_resolve_through_table() {
        use std::time::{Duration, Instant};

        // Blocks the loop's table owns resolve with no driver step,
        // on joint and legacy lanes alike.
        for joint in [true, false] {
            for block in [
                RetainedBlock::Publication,
                RetainedBlock::Collected,
                RetainedBlock::ScopedCompletion,
                RetainedBlock::Native,
            ] {
                // A joint lane only reaches this arm for non-joint
                // blocks; Publication on a joint lane steps above.
                if joint && block == RetainedBlock::Publication {
                    continue;
                }
                let mut coord = coordinator();
                let headless = headless_display();
                let mut driver = driver_with_display(&mut coord, headless.display);
                let mut lane = joint_lane(WindDownIo::completing(), true);
                if !joint {
                    lane.set_test_joint_frame(false);
                    lane.set_test_joint_machine(false);
                }
                driver.semantic = Some(lane);
                driver.joint_finish = JointFinishDriver::Polling;
                let outcome = super::tests::retain_with_cause(
                    &mut driver,
                    crate::inventory_capture::ZeroPassCause::OperatorStop,
                    None,
                );
                let (mut run, _) = retained_run_of(outcome);
                if !joint {
                    driver.joint_finish = JointFinishDriver::NotBegun;
                }
                let mut budget = RetainedWorkBudget {
                    remaining_actions: 1024,
                    deadline: Instant::now() + Duration::from_millis(10),
                };
                let disposition: Result<BlockDisposition, anyhow::Error> =
                    driver.dispose_retained(block, &mut run, &mut budget);
                assert_eq!(
                    disposition.unwrap(),
                    BlockDisposition::Resolved,
                    "joint={joint} block={block:?} resolves without a step"
                );
                assert_eq!(driver.joint_begin_calls, 0, "no begin");
                assert_eq!(driver.joint_step_calls, 0, "no step");
                assert_eq!(driver.joint_commit_polls, 0, "no commit poll");
            }
        }
    }

    #[test]
    fn classic_consumer_retains_run_driver_and_coordinator() {
        let mut coord = coordinator();
        let headless = headless_display();
        let mut driver = driver_with_display(&mut coord, headless.display);
        driver.display = None;
        driver.semantic = Some(joint_lane(WindDownIo::completing(), true));
        driver.joint_finish = JointFinishDriver::Polling;
        let outcome = super::tests::retain_with_cause(
            &mut driver,
            crate::inventory_capture::ZeroPassCause::OperatorStop,
            None,
        );
        // The suspension gate ran inside retention and did nothing else.
        assert!(driver.suspended, "retention suspends the driver");
        assert_eq!(
            driver.terminal_seq_calls, 0,
            "the gate runs no terminal I/O"
        );
        assert_eq!(driver.joint_begin_calls, 0, "the gate begins nothing");
        assert_eq!(driver.joint_step_calls, 0, "the gate steps nothing");
        assert_eq!(driver.commit_calls, 0, "the gate commits nothing");
        // The same run, driver and coordinator stay together.
        let (run, error) = retained_run_of(outcome);
        assert_eq!(run.stop_cause, Some(ZeroPassCause::OperatorStop));
        assert_eq!(run.completed_passes, 0);
        assert!(error.is_none(), "no error on the stop path");
        assert!(driver.semantic.is_some(), "the driver keeps its lane");
        assert_eq!(driver.coordinator.passes(), 0, "the coord stays queryable");
        // The consumer drains the retained run to its terminal outcome.
        let stop = std::cell::Cell::new(false);
        let stop_now = || stop.get();
        let clock = consume_clock(&stop_now);
        let outcome = ClassicOutcome {
            stopped: None,
            error,
            zero_pass: None,
            retained: Some(run),
        };
        let (stopped, error, zero_pass) =
            driver.consume_outcome(outcome, &clock, &mut |_, _| Ok(()));
        assert!(stopped.is_none(), "a scan run stops no native lane");
        assert!(error.is_none(), "no error on the stop path");
        let zero = zero_pass.expect("zero passes by stop report once");
        assert_eq!(zero.cause, ZeroPassCause::OperatorStop, "cause kept");
        assert_eq!(zero.discarded, 0, "nothing collected past the stop");
        let zeros: Vec<(String, String)> = gaps(&mut driver)
            .into_iter()
            .filter(|(subject, _)| subject == ZERO_PASS_GAP_SUBJECT)
            .collect();
        assert_eq!(zeros.len(), 1, "one zero-pass gap: {:?}", gaps(&mut driver));
        assert!(
            driver.semantic.is_some(),
            "the polling lane is kept, never spuriously abandoned"
        );
        assert_eq!(
            driver.joint_finish,
            JointFinishDriver::Polling,
            "no latch means no finite stop"
        );

        // A synchronous outcome keeps today's reads even with a
        // joint first error: the fold is the retained consumer's.
        {
            let mut coordinator2 = coordinator();
            let headless = headless_display();
            let mut driver = driver_with_display(&mut coordinator2, headless.display);
            driver.display = None;
            driver.semantic = Some(joint_lane(WindDownIo::completing(), false));
            let outcome = super::tests::retain_with_cause(
                &mut driver,
                crate::inventory_capture::ZeroPassCause::OperatorStop,
                None,
            );
            assert!(
                outcome.retained.is_none(),
                "no pending publication means no retention"
            );
            assert!(!driver.suspended, "a synchronous run never suspends");
            assert!(
                driver.joint_first_error.is_some(),
                "the stop hook kept its first error"
            );
            let stop = std::cell::Cell::new(false);
            let stop_now = || stop.get();
            let clock = consume_clock(&stop_now);
            let (_, error, zero_pass) = driver.consume_outcome(outcome, &clock, &mut |_, _| Ok(()));
            assert!(error.is_none(), "today's reads keep no error");
            assert!(
                zero_pass.is_some(),
                "today's reads keep the zero-pass report"
            );
        }
    }

    #[test]
    fn dashboard_consumer_retains_run_driver_and_coordinator() {
        let mut coord = coordinator();
        let headless = headless_display();
        let mut driver = driver_with_display(&mut coord, headless.display);
        driver.semantic = Some(joint_lane(WindDownIo::completing(), true));
        driver.joint_finish = JointFinishDriver::Polling;
        let outcome = super::tests::retain_with_cause(
            &mut driver,
            crate::inventory_capture::ZeroPassCause::OperatorStop,
            None,
        );
        let (run, error) = retained_run_of(outcome);
        assert!(driver.display.is_some(), "the dashboard keeps its display");
        let display_ticks = driver.display.as_ref().expect("display").account().ticks;
        let mut passes = 0;
        let mut stops = 0;
        let stop = std::cell::Cell::new(false);
        let stop_now = || stop.get();
        let clock = consume_clock(&stop_now);
        let outcome = ClassicOutcome {
            stopped: None,
            error,
            zero_pass: None,
            retained: Some(run),
        };
        let (stopped, error, zero_pass) =
            driver.consume_outcome(outcome, &clock, &mut |_, point| {
                match point {
                    Publish::Pass { .. } => passes += 1,
                    Publish::Stop { .. } => stops += 1,
                    Publish::Retiring { .. } => {}
                }
                Ok(())
            });
        assert!(stopped.is_none(), "a scan run stops no native lane");
        assert!(error.is_none(), "no error on the stop path");
        assert_eq!(
            zero_pass.map(|zero| zero.cause),
            Some(ZeroPassCause::OperatorStop),
            "cause kept"
        );
        assert_eq!(passes, 0, "retention precedes the first pass");
        assert_eq!(stops, 1, "the stop publishes once");
        assert!(
            driver.display.as_ref().expect("display").account().ticks > display_ticks,
            "retained service still ticks the dashboard display"
        );
        assert!(
            driver.semantic.is_some(),
            "the polling lane is kept, never spuriously abandoned"
        );
    }

    #[test]
    fn uncertain_native_stop_exits_with_first_error_without_mint() {
        use crate::inventory_semantics::SemanticRefusal;
        use std::cell::Cell;
        use std::rc::Rc;
        use std::sync::atomic::Ordering;
        use std::time::{Duration, Instant};

        // The I2 trigger fires on the first retained hook after the
        // verdict: one poll abandons, holds and keeps the first error.
        let mut coord = coordinator();
        let headless = headless_display();
        let mut driver = driver_with_display(&mut coord, headless.display);
        let mut io = WindDownIo::nonempty_completing();
        let drops = Rc::new(Cell::new(0));
        io.drop_spy = Some(Rc::clone(&drops));
        let detach_polls = Rc::clone(&io.polls);
        let mut lane = joint_lane(io, false);
        lane.note_joint_finish_failure(SemanticRefusal::ProviderStorage);
        driver.semantic = Some(lane);
        driver.joint_finish = JointFinishDriver::Polling;
        let (source, mint_polls, _) = CountingSource::scripted(None);
        driver.completion_source = Some(Box::new(source));
        let outcome = super::tests::retain_with_cause(
            &mut driver,
            crate::inventory_capture::ZeroPassCause::OperatorStop,
            None,
        );
        let (mut run, error) = retained_run_of(outcome);
        // G4's closer owes its publication: the retained hook spends
        // its credit stepping the Joint driver, which sees the latch.
        run.block = Some(RetainedBlock::Publication);
        let stop = Cell::new(false);
        let stop_now = || stop.get();
        let clock = consume_clock(&stop_now);
        let mut budget = RetainedWorkBudget {
            remaining_actions: 1024,
            deadline: Instant::now() + Duration::from_millis(10),
        };
        let outcome = crate::inventory_capture::poll_retained_classic(
            &mut driver,
            run,
            error,
            &clock,
            &mut budget,
            &mut |_, _| Ok(()),
        );
        assert_eq!(
            driver.joint_finish,
            JointFinishDriver::Abandoned,
            "one hook after the verdict abandons"
        );
        assert!(driver.semantic.is_none(), "the lane is held");
        assert_eq!(drops.get(), 0, "held means never dropped");
        assert_eq!(
            driver.joint_first_error.as_deref(),
            Some("joint finish disposition required"),
            "the first error is kept"
        );
        assert_eq!(detach_polls.get(), 0, "the abandon never joins");
        // The consumer exits with that first error: no mint, no join.
        let stop = Cell::new(false);
        let stop_now = || stop.get();
        let clock = consume_clock(&stop_now);
        let (stopped, error, _) = driver.consume_outcome(outcome, &clock, &mut |_, _| Ok(()));
        assert!(stopped.is_none(), "nothing minted a completion");
        let error = error.expect("the process outcome carries the first error");
        assert!(
            format!("{error:#}").contains("joint finish disposition required"),
            "the first error exits: {error:#}"
        );
        assert_eq!(mint_polls.load(Ordering::SeqCst), 0, "no mint on abandon");
        assert_eq!(drops.get(), 0, "held means never dropped");
        assert_eq!(detach_polls.get(), 0, "the exit never joins");
        let abandons: Vec<(String, String)> = gaps(&mut driver)
            .into_iter()
            .filter(|(subject, _)| subject == "joint finish abandoned for exit")
            .collect();
        assert_eq!(
            abandons.len(),
            1,
            "exactly one abandon gap: {:?}",
            gaps(&mut driver)
        );

        // Twin: a gated detach never blocks the exit — the finite
        // stop holds without joining while the gate stays shut.
        {
            let mut coordinator2 = coordinator();
            let headless = headless_display();
            let mut driver = driver_with_display(&mut coordinator2, headless.display);
            let (io, gate) = WindDownIo::gated();
            let detach_polls = Rc::clone(&io.polls);
            let mut lane = joint_lane(io, false);
            lane.note_joint_finish_failure(SemanticRefusal::ProviderStorage);
            driver.semantic = Some(lane);
            driver.joint_finish = JointFinishDriver::Polling;
            let outcome = super::tests::retain_with_cause(
                &mut driver,
                crate::inventory_capture::ZeroPassCause::OperatorStop,
                None,
            );
            let (mut run, error) = retained_run_of(outcome);
            run.block = Some(RetainedBlock::Publication);
            let outcome = ClassicOutcome {
                stopped: None,
                error,
                zero_pass: None,
                retained: Some(run),
            };
            let stop = Cell::new(false);
            let stop_now = || stop.get();
            let clock = consume_clock(&stop_now);
            let (_, error, _) = driver.consume_outcome(outcome, &clock, &mut |_, _| Ok(()));
            assert!(
                error.is_some(),
                "the exit carries the first error without the gate"
            );
            assert_eq!(
                driver.joint_finish,
                JointFinishDriver::Abandoned,
                "the gated lane still abandons"
            );
            assert_eq!(detach_polls.get(), 0, "a gated detach is never polled");
            drop(gate);
        }

        // The Published wound-down error path skips the abandon: the
        // finish already published, so the hold is direct.
        {
            let mut coordinator3 = coordinator();
            let headless = headless_display();
            let mut driver = driver_with_display(&mut coordinator3, headless.display);
            let mut io = WindDownIo::completing();
            io.fail_poll = true;
            driver.semantic = Some(joint_lane(io, true));
            driver.joint_finish = JointFinishDriver::Polling;
            let outcome = super::tests::retain_with_cause(
                &mut driver,
                crate::inventory_capture::ZeroPassCause::OperatorStop,
                None,
            );
            driver.joint_finish = JointFinishDriver::Published;
            let (mut run, error) = retained_run_of(outcome);
            run.block = Some(RetainedBlock::Publication);
            let outcome = ClassicOutcome {
                stopped: None,
                error,
                zero_pass: None,
                retained: Some(run),
            };
            let stop = Cell::new(false);
            let stop_now = || stop.get();
            let clock = consume_clock(&stop_now);
            let (_, error, _) = driver.consume_outcome(outcome, &clock, &mut |_, _| Ok(()));
            assert!(
                error.is_some(),
                "the wound-down refusal exits with its error"
            );
            assert_eq!(
                driver.joint_finish,
                JointFinishDriver::Abandoned,
                "the failed wound-down abandons"
            );
            assert!(
                gaps(&mut driver)
                    .iter()
                    .all(|(subject, _)| subject != "joint finish abandoned for exit"),
                "a published finish skips the abandon: {:?}",
                gaps(&mut driver)
            );
            let failures: Vec<(String, String)> = gaps(&mut driver)
                .into_iter()
                .filter(|(subject, _)| subject == "joint wound-down failed")
                .collect();
            assert_eq!(
                failures.len(),
                1,
                "exactly one wound-down gap: {:?}",
                gaps(&mut driver)
            );
        }

        // A latch on an already-finished lane (the missing-receipt
        // case) skips the abandon too.
        {
            let mut coordinator4 = coordinator();
            let headless = headless_display();
            let mut driver = driver_with_display(&mut coordinator4, headless.display);
            let mut lane = joint_lane(WindDownIo::completing(), true);
            lane.note_joint_finish_failure(SemanticRefusal::Unavailable);
            driver.semantic = Some(lane);
            driver.joint_finish = JointFinishDriver::Polling;
            let outcome = super::tests::retain_with_cause(
                &mut driver,
                crate::inventory_capture::ZeroPassCause::OperatorStop,
                None,
            );
            let (mut run, error) = retained_run_of(outcome);
            run.block = Some(RetainedBlock::Publication);
            let outcome = ClassicOutcome {
                stopped: None,
                error,
                zero_pass: None,
                retained: Some(run),
            };
            let stop = Cell::new(false);
            let stop_now = || stop.get();
            let clock = consume_clock(&stop_now);
            let (_, error, _) = driver.consume_outcome(outcome, &clock, &mut |_, _| Ok(()));
            assert!(error.is_some(), "the latched error exits");
            assert_eq!(
                driver.joint_finish,
                JointFinishDriver::Abandoned,
                "the latched finish abandons"
            );
            assert!(
                gaps(&mut driver)
                    .iter()
                    .all(|(subject, _)| subject != "joint finish abandoned for exit"),
                "a finished lane skips the abandon: {:?}",
                gaps(&mut driver)
            );
        }
    }

    #[test]
    fn untouched_graph_refusal_exits_finitely_with_its_reason() {
        use crate::inventory_semantics::SemanticRefusal;
        use std::cell::Cell;
        use std::sync::atomic::Ordering;

        let mut coord = coordinator();
        // The G6 one-short refusal, seeded where the engine leaves it.
        coord
            .seed_collected_graph_refusal_for_test("terminal graph refused before native mutation");
        let headless = headless_display();
        let mut driver = driver_with_display(&mut coord, headless.display);
        let mut lane = joint_lane(WindDownIo::completing(), false);
        lane.note_joint_finish_failure(SemanticRefusal::ProviderStorage);
        driver.semantic = Some(lane);
        driver.joint_finish = JointFinishDriver::Polling;
        let (source, mint_polls, _) = CountingSource::scripted(None);
        driver.completion_source = Some(Box::new(source));
        let outcome = super::tests::retain_with_cause(
            &mut driver,
            crate::inventory_capture::ZeroPassCause::OperatorStop,
            None,
        );
        let (mut run, error) = retained_run_of(outcome);
        // The G6 one-short owes its publication: the drain's first
        // hook steps the Joint driver, which sees the latch.
        run.block = Some(RetainedBlock::Publication);
        let outcome = ClassicOutcome {
            stopped: None,
            error,
            zero_pass: None,
            retained: Some(run),
        };
        let stop = Cell::new(false);
        let stop_now = || stop.get();
        let clock = consume_clock(&stop_now);
        let (_, error, _) = driver.consume_outcome(outcome, &clock, &mut |_, _| Ok(()));
        assert_eq!(
            driver.joint_finish,
            JointFinishDriver::Abandoned,
            "the refused graph takes the finite stop"
        );
        assert!(driver.semantic.is_none(), "the lane is held");
        let error = error.expect("the refusal reason exits");
        assert!(
            format!("{error:#}").contains("terminal graph refused before native mutation"),
            "the exit carries the refusal reason: {error:#}"
        );
        assert_eq!(mint_polls.load(Ordering::SeqCst), 0, "no mint on abandon");
        let abandons: Vec<(String, String)> = gaps(&mut driver)
            .into_iter()
            .filter(|(subject, _)| subject == "joint finish abandoned for exit")
            .collect();
        assert_eq!(
            abandons.len(),
            1,
            "exactly one abandon gap: {:?}",
            gaps(&mut driver)
        );
        assert_eq!(
            abandons[0].1, "terminal graph refused before native mutation",
            "the abandon records the refusal reason"
        );
    }

    #[test]
    fn zero_pass_stop_cause_reaches_presentation_once() {
        use std::cell::Cell;
        use std::time::{Duration, Instant};

        // A deadline-retained run reports its cause once: the sampled
        // cause survives a later stop signal unchanged.
        let mut coord = coordinator();
        let headless = headless_display();
        let mut driver = driver_with_display(&mut coord, headless.display);
        driver.semantic = Some(joint_lane(WindDownIo::completing(), true));
        driver.joint_finish = JointFinishDriver::Polling;
        let outcome = retain_with_cause(&mut driver, ZeroPassCause::Deadline, None);
        let (run, error) = retained_run_of(outcome);
        assert_eq!(run.stop_cause, Some(ZeroPassCause::Deadline));
        // A later operator stop never overwrites the recorded cause.
        let stop = Cell::new(true);
        let stop_now = || stop.get();
        let clock = LoopClock {
            deadline: None,
            stop: &stop_now,
            now: &std::time::Instant::now,
            interval: super::inventory_test_poll_interval(),
            tick: crate::inventory_capture::SERVICE_TICK,
            collection_tick: crate::inventory_capture::SERVICE_TICK,
        };
        let mut budget = RetainedWorkBudget {
            remaining_actions: 1024,
            deadline: Instant::now() + Duration::from_millis(10),
        };
        let outcome = crate::inventory_capture::poll_retained_classic(
            &mut driver,
            run,
            error,
            &clock,
            &mut budget,
            &mut |_, _| Ok(()),
        );
        let stop = Cell::new(false);
        let stop_now = || stop.get();
        let clock = consume_clock(&stop_now);
        let (stopped, error, zero_pass) =
            driver.consume_outcome(outcome, &clock, &mut |_, _| Ok(()));
        assert!(stopped.is_none(), "a scan run stops no native lane");
        assert!(error.is_none(), "no error on the stop path");
        let zero = zero_pass.expect("zero passes by deadline report once");
        assert_eq!(zero.cause, ZeroPassCause::Deadline, "cause kept");
        assert_eq!(zero.discarded, 0, "nothing collected past the stop");
        let reason = zero.gap_reason();
        assert!(
            reason.contains("deadline"),
            "the gap reason names the cause: {reason}"
        );
        let line = zero.stderr_line();
        assert!(
            line.contains("deadline"),
            "the stderr line names the cause: {line}"
        );
        let zeros: Vec<(String, String)> = gaps(&mut driver)
            .into_iter()
            .filter(|(subject, _)| subject == ZERO_PASS_GAP_SUBJECT)
            .collect();
        assert_eq!(zeros.len(), 1, "one zero-pass gap: {:?}", gaps(&mut driver));

        // Twin: a retained first error is never overwritten by the
        // zero-pass staging, which stays suppressed under error.
        {
            let mut coordinator2 = coordinator();
            let headless = headless_display();
            let mut driver = driver_with_display(&mut coordinator2, headless.display);
            driver.semantic = Some(joint_lane(WindDownIo::completing(), true));
            driver.joint_finish = JointFinishDriver::Polling;
            let outcome = retain_with_cause(
                &mut driver,
                ZeroPassCause::OperatorStop,
                Some(anyhow::anyhow!("the retained failure")),
            );
            let stop = Cell::new(false);
            let stop_now = || stop.get();
            let clock = consume_clock(&stop_now);
            let (_, error, zero_pass) = driver.consume_outcome(outcome, &clock, &mut |_, _| Ok(()));
            let error = error.expect("the first error is kept");
            assert!(
                format!("{error:#}").contains("the retained failure"),
                "the first error is never overwritten: {error:#}"
            );
            assert!(
                zero_pass.is_none(),
                "no zero-pass report beside a first error"
            );
            let failures: Vec<(String, String)> = gaps(&mut driver)
                .into_iter()
                .filter(|(subject, _)| subject == "inventory capture failed")
                .collect();
            assert_eq!(
                failures.len(),
                1,
                "one failure gap: {:?}",
                gaps(&mut driver)
            );
        }
    }

    #[test]
    fn consumer_keeps_mixed_outcome_and_reports() {
        // Defensive: a retained run beside stopped evidence holds
        // its owners and reports instead of completing either.
        let mut coord = coordinator();
        let headless = headless_display();
        let mut driver = driver_with_display(&mut coord, headless.display);
        driver.semantic = Some(joint_lane(WindDownIo::completing(), true));
        driver.joint_finish = JointFinishDriver::Polling;
        let outcome = super::tests::retain_with_cause(
            &mut driver,
            crate::inventory_capture::ZeroPassCause::OperatorStop,
            None,
        );
        let (run, _) = retained_run_of(outcome);
        let mixed = ClassicOutcome {
            stopped: None::<Stopped<FacadeLane>>,
            error: None,
            zero_pass: Some(ZeroPassStop {
                cause: ZeroPassCause::Deadline,
                discarded: 0,
                elapsed: std::time::Duration::from_secs(0),
            }),
            retained: Some(run),
        };
        let stop = std::cell::Cell::new(false);
        let stop_now = || stop.get();
        let clock = consume_clock(&stop_now);
        let (stopped, error, zero_pass) = driver.consume_outcome(mixed, &clock, &mut |_, _| Ok(()));
        assert!(stopped.is_none(), "no stopped owner is minted");
        let error = error.expect("the malformed outcome reports");
        assert!(
            format!("{error:#}").contains("mixed"),
            "the report names the mixture: {error:#}"
        );
        assert_eq!(
            zero_pass.map(|zero| zero.cause),
            Some(ZeroPassCause::Deadline),
            "the zero-pass evidence passes through"
        );
        assert_eq!(driver.joint_step_calls, 0, "nothing polls a mixed outcome");
        assert_eq!(driver.commit_calls, 0, "nothing commits a mixed outcome");
        assert!(
            driver.semantic.is_some(),
            "the mixed arm keeps the driver's lane"
        );
    }

    #[test]
    fn dispose_retained_native_waits_in_table_without_stop() {
        use crate::inventory_capture::{RetainedPass, RetainedTerminalPhase};
        use std::time::{Duration, Instant};

        // A planted Native block beside no stop: the driver resolves
        // (it owns no native step) and the table holds the uncovered
        // pairing across polls — finite, inventing nothing. The live
        // N1 wait is the capture loop's (T16a).
        let mut coord = coordinator();
        let headless = headless_display();
        let mut driver = driver_with_display(&mut coord, headless.display);
        driver.semantic = Some(joint_lane(WindDownIo::completing(), true));
        driver.joint_finish = JointFinishDriver::Polling;
        let outcome = retain_with_error_no_stop(&mut driver, "the retained failure");
        let (mut run, error) = retained_run_of(outcome);
        assert_eq!(run.stop_cause, None, "no stop was sampled");
        run.block = Some(RetainedBlock::Native);
        let mut run = Some(run);
        let mut error = error;
        for hook in 1..=3 {
            let stop = std::cell::Cell::new(false);
            let stop_now = || stop.get();
            let clock = consume_clock(&stop_now);
            let mut budget = RetainedWorkBudget {
                remaining_actions: 1024,
                deadline: Instant::now() + Duration::from_millis(10),
            };
            let outcome = crate::inventory_capture::poll_retained_classic(
                &mut driver,
                run.take().expect("held across hooks"),
                error,
                &clock,
                &mut budget,
                &mut |_, _| Ok(()),
            );
            let held = retained_run_of(outcome);
            run = Some(held.0);
            error = held.1;
            assert_eq!(
                run.as_ref().expect("held").block,
                Some(RetainedBlock::Native),
                "hook {hook} holds the uncovered pairing"
            );
        }
        let error = error.expect("the retained failure is kept");
        assert!(
            format!("{error:#}").contains("the retained failure"),
            "no error is invented while waiting: {error:#}"
        );
        assert!(driver.semantic.is_some(), "the waiting lane is kept");

        // The N1 arm shape without a live lane resolves through as
        // a no-op: nothing waits, nothing errors.
        {
            let mut coordinator2 = coordinator();
            let headless = headless_display();
            let mut driver = driver_with_display(&mut coordinator2, headless.display);
            driver.semantic = Some(joint_lane(WindDownIo::completing(), true));
            driver.joint_finish = JointFinishDriver::Polling;
            let outcome = retain_with_error_no_stop(&mut driver, "the retained failure");
            let (mut run, error) = retained_run_of(outcome);
            run.block = Some(RetainedBlock::Native);
            run.pass = RetainedPass::Terminal {
                phase: RetainedTerminalPhase::NativeStop,
            };
            let stop = std::cell::Cell::new(false);
            let stop_now = || stop.get();
            let clock = consume_clock(&stop_now);
            let mut budget = RetainedWorkBudget {
                remaining_actions: 1024,
                deadline: Instant::now() + Duration::from_millis(10),
            };
            let outcome = crate::inventory_capture::poll_retained_classic(
                &mut driver,
                run,
                error,
                &clock,
                &mut budget,
                &mut |_, _| Ok(()),
            );
            // The no-op arm clears the block and the planted terminal
            // phase drains to its outcome: nothing waits, nothing errors.
            match outcome.into_completion() {
                Ok(ClassicCompletion::Finalized { error, .. }) => {
                    let error = error.expect("the retained failure is kept");
                    assert!(
                        format!("{error:#}").contains("the retained failure"),
                        "no error is invented: {error:#}"
                    );
                }
                _ => panic!("the no-op arm drains"),
            }
        }
    }

    #[test]
    fn take_joined_session_without_recorded_wound_down_refuses() {
        // The §8.3 order enforced in-API: no recorded wound-down,
        // no take — even finished and frameless.
        let coord = coordinator();
        let mut lane = joint_lane(WindDownIo::completing(), true);
        lane.set_test_joint_frame(false);
        assert!(
            matches!(
                lane.take_joined_session(),
                Err(crate::inventory_semantics::SemanticRefusal::Unavailable)
            ),
            "a take without a recorded wound-down refuses"
        );
        // The earlier gates keep their answers: unfinished and
        // framed lanes stay not-ready, not refused.
        let mut lane = joint_lane(WindDownIo::completing(), false);
        lane.set_test_joint_frame(false);
        assert!(
            lane.take_joined_session().unwrap().is_none(),
            "an unfinished lane stays not-ready"
        );
        let mut lane = joint_lane(WindDownIo::completing(), true);
        assert!(
            lane.take_joined_session().unwrap().is_none(),
            "a framed lane stays not-ready"
        );
        drop(coord);
    }

    #[test]
    fn take_joined_session_after_recorded_wound_down_proceeds() {
        // Control: once the wound-down poll records its success,
        // the take proceeds (a substituted lane hands no session).
        let mut coord = coordinator();
        let mut lane = joint_lane(WindDownIo::completing(), true);
        lane.set_test_joint_frame(false);
        assert!(
            matches!(
                lane.poll_wound_down(&mut coord, &mut std::io::sink()),
                Ok(true)
            ),
            "the completing detach joins"
        );
        assert!(
            lane.take_joined_session().unwrap().is_none(),
            "the recorded wound-down admits the take"
        );
    }

    #[test]
    fn abandon_finish_for_exit_refuses_second_call() {
        use crate::inventory_semantics::SemanticRefusal;

        let mut coord = coordinator();
        let mut lane = joint_lane(WindDownIo::completing(), false);
        lane.note_joint_finish_failure(SemanticRefusal::ProviderStorage);
        lane.abandon_finish_for_exit(&mut coord, "native ownership uncertain")
            .expect("the first abandon is admitted");
        coord.commit_batch(false).expect("a fresh coord commits");
        assert_eq!(coord.registry().gaps().len(), 1, "one abandon, one gap");
        assert!(
            matches!(
                lane.abandon_finish_for_exit(&mut coord, "native ownership uncertain"),
                Err(SemanticRefusal::Unavailable)
            ),
            "a second abandon refuses"
        );
        coord.commit_batch(false).expect("a fresh coord commits");
        assert_eq!(
            coord.registry().gaps().len(),
            1,
            "the refused abandon records nothing more"
        );
        assert!(lane.is_finished(), "the lane stays finished");
        assert!(
            matches!(
                lane.take_joined_session(),
                Err(SemanticRefusal::Unavailable)
            ),
            "the lane stays retained"
        );
    }

    #[test]
    fn abandon_finish_for_exit_first_call_abandons() {
        use crate::inventory_semantics::SemanticRefusal;

        // Control: the first abandon still builds its terminal batch
        // and retains the lane.
        let mut coord = coordinator();
        let mut lane = joint_lane(WindDownIo::completing(), false);
        lane.note_joint_finish_failure(SemanticRefusal::ProviderStorage);
        let domain = lane.domain();
        let batch = lane
            .abandon_finish_for_exit(&mut coord, "native ownership uncertain")
            .expect("disposition-required admits the abandon");
        assert!(lane.is_finished(), "the abandon finishes the lane");
        assert_eq!(batch.domain(), domain, "the batch names the lane");
        assert!(batch.is_empty(), "an empty finish abandons empty");
        assert!(
            matches!(
                lane.poll_wound_down(&mut coord, &mut std::io::sink()),
                Err(SemanticRefusal::Unavailable)
            ),
            "the retained lane refuses the wound-down"
        );
    }

    /// The inventory harness's real pending verdict for the
    /// presentation-guard tests: a seated Joint driver with an owed
    /// commit reads pending; an idle driver does not.
    fn harness_pending_verdict(pending: bool) -> bool {
        let mut coordinator = coordinator();
        let headless = headless_display();
        let mut driver = driver_with_display(&mut coordinator, headless.display);
        if pending {
            driver.semantic = Some(joint_lane(WindDownIo::completing(), false));
            driver.joint_commit_pending = true;
        }
        driver.publication_pending()
    }

    fn empty_pass_report() -> PassReport {
        PassReport {
            pass: 0,
            scanned: 1,
            maps_matched: 1,
            native_callers: 0,
            scan_callers: 0,
            engine_changed: false,
            pending_refresh: Vec::new(),
            events: Vec::new(),
            timings: crate::timing::StageTimings::new(),
        }
    }

    #[test]
    fn presentation_guard_startup_keeps_prior_view() {
        // While a publication pends, the startup prologue writes
        // nothing: the stream keeps its prior bytes (here, the first
        // prologue) instead of a second live-read prologue.
        let pending = harness_pending_verdict(true);
        assert!(pending, "the harness driver pends");
        let mut coordinator = coordinator();
        coordinator.commit_batch(false).unwrap();
        let (writer, mut reader) = stream_identity_sink();
        let mut stream = EventLogState::new(Some(writer));
        assert!(start_event_log(&mut stream, &coordinator, "system", 1).is_none());
        let baseline = stream_sink_records(&mut reader);
        assert_eq!(baseline.len(), 1, "one prologue before the pending drive");
        // The registry advances behind the pending publication...
        coordinator.note_scope_gap("staged behind pending".into(), "x".into());
        coordinator.commit_batch(false).unwrap();
        // ...but the guarded prologue neither reads nor emits.
        assert!(start_event_log_guarded(&mut stream, &coordinator, "system", 1, pending).is_none());
        assert_eq!(
            stream_sink_records(&mut reader),
            baseline,
            "no second prologue while pending"
        );
    }

    #[test]
    fn presentation_guard_startup_advances_without_pending() {
        // Twin: with no publication pending, the guarded prologue
        // writes the `started` record from a fresh read.
        let pending = harness_pending_verdict(false);
        assert!(!pending, "the idle driver does not pend");
        let mut coordinator = coordinator();
        coordinator.commit_batch(false).unwrap();
        let (writer, mut reader) = stream_identity_sink();
        let mut stream = EventLogState::new(Some(writer));
        assert!(start_event_log_guarded(&mut stream, &coordinator, "system", 1, pending).is_none());
        let records = stream_sink_records(&mut reader);
        assert_eq!(records.len(), 1, "one prologue: {records:?}");
        assert_eq!(records[0]["kind"], "started");
    }

    #[test]
    fn presentation_guard_stream_keeps_prior_view() {
        // While a publication pends, the stream view is None: the
        // caller emits nothing, so the emitted bytes and the emitter
        // baselines equal the pre-pending snapshot.
        let mut coordinator = coordinator();
        coordinator.note_scope_gap("baseline gap".into(), "x".into());
        coordinator.commit_batch(false).unwrap();
        let headless = headless_display();
        let mut driver = driver_with_display(&mut coordinator, headless.display);
        let (writer, mut reader) = stream_identity_sink();
        let mut stream = EventLogState::new(Some(writer));
        let mut state = StreamState::new();
        let report = empty_pass_report();
        // Baseline: the unpending pass publishes and retains.
        let view = stream_view_guarded(&driver, &mut state, "system", 1, 2)
            .expect("the unpending pass publishes");
        assert_eq!(
            stream.attempt("pass publication", |writer| {
                emit_pass_events(writer, &mut state, &report, &view, 2)
            }),
            None
        );
        let baseline = stream_sink_records(&mut reader);
        assert!(
            baseline
                .iter()
                .any(|record| record["kind"] == "pass_committed"),
            "the baseline publishes: {baseline:?}"
        );
        // The registry advances behind the pending publication...
        driver
            .coordinator
            .note_scope_gap("staged behind pending".into(), "y".into());
        driver.coordinator.commit_batch(false).unwrap();
        driver.semantic = Some(joint_lane(WindDownIo::completing(), false));
        driver.joint_commit_pending = true;
        assert!(driver.publication_pending(), "the harness driver pends");
        // ...but the guarded view is None, so nothing emits.
        assert!(
            stream_view_guarded(&driver, &mut state, "system", 1, 3).is_none(),
            "no live view while pending"
        );
        assert_eq!(
            stream_sink_records(&mut reader),
            baseline,
            "no emit while pending"
        );
        // The skip left emitter baselines untouched: resolving the
        // publication streams the staged gap fresh.
        driver.joint_commit_pending = false;
        assert!(!driver.publication_pending(), "the commit resolved");
        let view = stream_view_guarded(&driver, &mut state, "system", 1, 3)
            .expect("the resolved pass publishes");
        assert_eq!(
            stream.attempt("pass publication", |writer| {
                emit_pass_events(writer, &mut state, &report, &view, 3)
            }),
            None
        );
        let records = stream_sink_records(&mut reader);
        assert!(
            records.iter().any(|record| record["kind"] == "gap_recorded"
                && record["event"]["subject"] == "staged behind pending"),
            "the staged gap still streams fresh: {records:?}"
        );
    }

    #[test]
    fn presentation_guard_stream_advances_without_pending() {
        // Twin: with no publication pending, successive views see
        // staged content and the bytes grow.
        let mut coordinator = coordinator();
        coordinator.note_scope_gap("baseline gap".into(), "x".into());
        coordinator.commit_batch(false).unwrap();
        let headless = headless_display();
        let driver = driver_with_display(&mut coordinator, headless.display);
        assert!(
            !driver.publication_pending(),
            "the idle driver does not pend"
        );
        let (writer, mut reader) = stream_identity_sink();
        let mut stream = EventLogState::new(Some(writer));
        let mut state = StreamState::new();
        let report = empty_pass_report();
        let view = stream_view_guarded(&driver, &mut state, "system", 1, 2)
            .expect("the first pass publishes");
        assert_eq!(
            stream.attempt("pass publication", |writer| {
                emit_pass_events(writer, &mut state, &report, &view, 2)
            }),
            None
        );
        let baseline = stream_sink_records(&mut reader);
        driver
            .coordinator
            .note_scope_gap("second gap".into(), "y".into());
        driver.coordinator.commit_batch(false).unwrap();
        let view = stream_view_guarded(&driver, &mut state, "system", 1, 3)
            .expect("the second pass publishes");
        assert_eq!(
            stream.attempt("pass publication", |writer| {
                emit_pass_events(writer, &mut state, &report, &view, 3)
            }),
            None
        );
        let records = stream_sink_records(&mut reader);
        assert!(
            records.len() > baseline.len(),
            "the second view advances the bytes"
        );
        assert!(
            records.iter().any(|record| record["kind"] == "gap_recorded"
                && record["event"]["subject"] == "second gap"),
            "the staged gap streams: {records:?}"
        );
    }

    #[test]
    fn presentation_guard_dashboard_helper_keeps_prior_view() {
        // While a publication pends, the dashboard pass helper
        // yields no views: the caller skips both the stream emit and
        // the display offer, so both keep their prior view.
        let mut coordinator = coordinator();
        coordinator.note_scope_gap("baseline gap".into(), "x".into());
        coordinator.commit_batch(false).unwrap();
        let headless = headless_display();
        let mut driver = driver_with_display(&mut coordinator, headless.display);
        let (writer, mut reader) = stream_identity_sink();
        let mut stream = EventLogState::new(Some(writer));
        let mut state = StreamState::new();
        let report = empty_pass_report();
        // Baseline: the unpending pass publishes and retains.
        let (display, error) =
            dashboard_pass_guarded(&driver, &mut stream, &mut state, &report, "system", 1, 2)
                .expect("the unpending pass publishes");
        assert!(error.is_none(), "no stream error on the baseline");
        assert!(
            display.gaps.iter().any(|gap| gap.subject == "baseline gap"),
            "the display view sees the baseline"
        );
        let baseline = stream_sink_records(&mut reader);
        assert!(
            baseline
                .iter()
                .any(|record| record["kind"] == "pass_committed"),
            "the baseline publishes: {baseline:?}"
        );
        // The registry advances behind the pending publication...
        driver
            .coordinator
            .note_scope_gap("staged behind pending".into(), "y".into());
        driver.coordinator.commit_batch(false).unwrap();
        driver.semantic = Some(joint_lane(WindDownIo::completing(), false));
        driver.joint_commit_pending = true;
        assert!(driver.publication_pending(), "the harness driver pends");
        // ...but the guarded helper yields no views: no emit, and no
        // display view for the caller to offer.
        assert!(
            dashboard_pass_guarded(&driver, &mut stream, &mut state, &report, "system", 1, 3)
                .is_none(),
            "no live views while pending"
        );
        assert_eq!(
            stream_sink_records(&mut reader),
            baseline,
            "no emit while pending"
        );
        // The skip left emitter baselines untouched: resolving the
        // publication streams the staged gap fresh.
        driver.joint_commit_pending = false;
        assert!(!driver.publication_pending(), "the commit resolved");
        let (display, error) =
            dashboard_pass_guarded(&driver, &mut stream, &mut state, &report, "system", 1, 3)
                .expect("the resolved pass publishes");
        assert!(error.is_none(), "no stream error on resolve");
        assert!(
            display
                .gaps
                .iter()
                .any(|gap| gap.subject == "staged behind pending"),
            "the resolved display view advances"
        );
        let records = stream_sink_records(&mut reader);
        assert!(
            records.iter().any(|record| record["kind"] == "gap_recorded"
                && record["event"]["subject"] == "staged behind pending"),
            "the staged gap still streams fresh: {records:?}"
        );
    }

    #[test]
    fn presentation_guard_dashboard_helper_advances_without_pending() {
        // Twin: with no publication pending, the helper yields both
        // views from fresh reads and the bytes grow.
        let mut coordinator = coordinator();
        coordinator.note_scope_gap("baseline gap".into(), "x".into());
        coordinator.commit_batch(false).unwrap();
        let headless = headless_display();
        let driver = driver_with_display(&mut coordinator, headless.display);
        assert!(
            !driver.publication_pending(),
            "the idle driver does not pend"
        );
        let (writer, mut reader) = stream_identity_sink();
        let mut stream = EventLogState::new(Some(writer));
        let mut state = StreamState::new();
        let report = empty_pass_report();
        let (_, error) =
            dashboard_pass_guarded(&driver, &mut stream, &mut state, &report, "system", 1, 2)
                .expect("the first pass publishes");
        assert!(error.is_none());
        let baseline = stream_sink_records(&mut reader);
        driver
            .coordinator
            .note_scope_gap("second gap".into(), "y".into());
        driver.coordinator.commit_batch(false).unwrap();
        let (display, error) =
            dashboard_pass_guarded(&driver, &mut stream, &mut state, &report, "system", 1, 3)
                .expect("the second pass publishes");
        assert!(error.is_none());
        assert!(
            display.gaps.iter().any(|gap| gap.subject == "second gap"),
            "the display view advances"
        );
        let records = stream_sink_records(&mut reader);
        assert!(
            records.len() > baseline.len(),
            "the second view advances the bytes"
        );
    }

    #[test]
    fn presentation_guard_classic_final_keeps_prior_view() {
        // While a publication pends, the classic final reuses the
        // prior stream view instead of a fresh live read.
        let mut coordinator = coordinator();
        coordinator.note_scope_gap("baseline gap".into(), "x".into());
        coordinator.commit_batch(false).unwrap();
        let headless = headless_display();
        let mut driver = driver_with_display(&mut coordinator, headless.display);
        driver.semantic = Some(joint_lane(WindDownIo::completing(), false));
        let mut state = StreamState::new();
        // The last completed pass retains the prior (with the seated
        // lane's summary, which the reuse keeps).
        let prior = stream_view_guarded(&driver, &mut state, "system", 1, 2)
            .expect("the unpending pass publishes");
        // The registry advances behind the pending publication...
        driver
            .coordinator
            .note_scope_gap("staged behind pending".into(), "y".into());
        driver.coordinator.commit_batch(false).unwrap();
        driver.joint_commit_pending = true;
        assert!(driver.publication_pending(), "the harness driver pends");
        // ...but the final reuses the prior view.
        let final_view = final_view_guarded(&driver, &state, "system", 1, 9);
        assert_eq!(
            render_json_from_presentation(&final_view),
            render_json_from_presentation(&prior),
            "the final reuses the prior view"
        );
        assert!(
            final_view
                .gaps
                .iter()
                .all(|gap| gap.subject != "staged behind pending"),
            "no live read while pending"
        );
    }

    #[test]
    fn presentation_guard_classic_final_advances_without_pending() {
        // Twin: with no publication pending, the classic final reads
        // fresh, including staged content the prior predates.
        let mut coordinator = coordinator();
        coordinator.note_scope_gap("baseline gap".into(), "x".into());
        coordinator.commit_batch(false).unwrap();
        let headless = headless_display();
        let driver = driver_with_display(&mut coordinator, headless.display);
        assert!(
            !driver.publication_pending(),
            "the idle driver does not pend"
        );
        let mut state = StreamState::new();
        let prior = stream_view_guarded(&driver, &mut state, "system", 1, 2)
            .expect("the unpending pass publishes");
        driver
            .coordinator
            .note_scope_gap("staged late gap".into(), "y".into());
        driver.coordinator.commit_batch(false).unwrap();
        let final_view = final_view_guarded(&driver, &state, "system", 1, 9);
        assert!(
            final_view
                .gaps
                .iter()
                .any(|gap| gap.subject == "staged late gap"),
            "the fresh final sees staged content"
        );
        assert!(
            prior
                .gaps
                .iter()
                .all(|gap| gap.subject != "staged late gap"),
            "the prior predates it"
        );
    }

    #[test]
    fn presentation_guard_dashboard_final_keeps_prior_view() {
        // While a publication pends, the dashboard final reuses the
        // prior stream view instead of a fresh live read. It shares
        // the final-view core with the classic final; this test pins
        // it from the dashboard-final call shape.
        let mut coordinator = coordinator();
        coordinator.note_scope_gap("baseline gap".into(), "x".into());
        coordinator.commit_batch(false).unwrap();
        let headless = headless_display();
        let mut driver = driver_with_display(&mut coordinator, headless.display);
        driver.semantic = Some(joint_lane(WindDownIo::completing(), false));
        let mut state = StreamState::new();
        let prior = stream_view_guarded(&driver, &mut state, "system", 1, 2)
            .expect("the unpending pass publishes");
        driver
            .coordinator
            .note_scope_gap("staged behind pending".into(), "y".into());
        driver.coordinator.commit_batch(false).unwrap();
        driver.joint_commit_pending = true;
        assert!(driver.publication_pending(), "the harness driver pends");
        let final_view = final_view_guarded(&driver, &state, "system", 1, 99);
        assert_eq!(
            render_json_from_presentation(&final_view),
            render_json_from_presentation(&prior),
            "the final reuses the prior view"
        );
        assert!(
            final_view
                .gaps
                .iter()
                .all(|gap| gap.subject != "staged behind pending"),
            "no live read while pending"
        );
    }

    #[test]
    fn presentation_guard_dashboard_final_advances_without_pending() {
        // Twin: with no publication pending, the dashboard final
        // reads fresh, including staged content.
        let mut coordinator = coordinator();
        coordinator.note_scope_gap("baseline gap".into(), "x".into());
        coordinator.commit_batch(false).unwrap();
        let headless = headless_display();
        let driver = driver_with_display(&mut coordinator, headless.display);
        assert!(
            !driver.publication_pending(),
            "the idle driver does not pend"
        );
        let mut state = StreamState::new();
        stream_view_guarded(&driver, &mut state, "system", 1, 2)
            .expect("the unpending pass publishes");
        driver
            .coordinator
            .note_scope_gap("staged late gap".into(), "y".into());
        driver.coordinator.commit_batch(false).unwrap();
        let final_view = final_view_guarded(&driver, &state, "system", 1, 99);
        assert!(
            final_view
                .gaps
                .iter()
                .any(|gap| gap.subject == "staged late gap"),
            "the fresh final sees staged content"
        );
    }

    #[test]
    fn presentation_guard_failed_startup_final_keeps_prior_view() {
        // While a publication pends, the failed-startup final
        // renders the prior view; the failure bookkeeping (the
        // retired stream, the committed failure gap) still runs.
        let pending = harness_pending_verdict(true);
        assert!(pending, "the harness driver pends");
        let mut coordinator = coordinator();
        coordinator.note_scope_gap("baseline gap".into(), "x".into());
        coordinator.commit_batch(false).unwrap();
        let prior = Presentation::capture(&coordinator, "system", 1, 2, 1);
        let dir = private_tempdir();
        let report_path = dir.path().join("report.json");
        let events_path = dir.path().join("events.jsonl");
        let writer = EventWriter::anonymous_test_sink(std::fs::File::create(&events_path).unwrap());
        let mut stream = EventLogState::new(Some(writer));
        let mut stdout: Vec<u8> = Vec::new();
        let error = anyhow::anyhow!("scripted native failure");
        let finalized = std::cell::Cell::new(false);
        finish_failed_startup_guarded(
            pending,
            Some(&prior),
            &mut coordinator,
            "system",
            1,
            Some(crate::output::atomic_file_test_fixture(&report_path)),
            &mut stream,
            None,
            true,
            &mut crate::inventory_output::WriterStdout(&mut stdout),
            &error,
            &|| false,
            &|| finalized.set(true),
            None,
        );
        assert!(finalized.get(), "outputs were attempted");
        assert_eq!(
            std::fs::read(&report_path).unwrap(),
            stdout,
            "the report and stdout render the same document"
        );
        assert!(
            std::fs::read(&events_path).unwrap().is_empty(),
            "no event observation started"
        );
        let document: serde_json::Value = serde_json::from_slice(&stdout).unwrap();
        assert_eq!(
            document["observation"]["passes"], 1,
            "the prior view renders: {document:?}"
        );
        let gaps = document["gaps"].as_array().unwrap();
        assert!(
            gaps.iter()
                .all(|gap| gap["subject"] != "inventory capture failed"),
            "no live read while pending: {gaps:?}"
        );
    }

    #[test]
    fn presentation_guard_failed_startup_final_advances_without_pending() {
        // Twin: with no publication pending, the failed-startup
        // final reads fresh (ignoring any prior) and reports the
        // failure gap it just committed.
        let pending = harness_pending_verdict(false);
        assert!(!pending, "the idle driver does not pend");
        let mut coordinator = coordinator();
        coordinator.note_scope_gap("baseline gap".into(), "x".into());
        coordinator.commit_batch(false).unwrap();
        let prior = Presentation::capture(&coordinator, "system", 1, 2, 1);
        let dir = private_tempdir();
        let report_path = dir.path().join("report.json");
        let events_path = dir.path().join("events.jsonl");
        let writer = EventWriter::anonymous_test_sink(std::fs::File::create(&events_path).unwrap());
        let mut stream = EventLogState::new(Some(writer));
        let mut stdout: Vec<u8> = Vec::new();
        let error = anyhow::anyhow!("scripted native failure");
        let finalized = std::cell::Cell::new(false);
        finish_failed_startup_guarded(
            pending,
            Some(&prior),
            &mut coordinator,
            "system",
            1,
            Some(crate::output::atomic_file_test_fixture(&report_path)),
            &mut stream,
            None,
            true,
            &mut crate::inventory_output::WriterStdout(&mut stdout),
            &error,
            &|| false,
            &|| finalized.set(true),
            None,
        );
        assert!(finalized.get(), "outputs were attempted");
        let document: serde_json::Value = serde_json::from_slice(&stdout).unwrap();
        assert_eq!(
            document["observation"]["passes"],
            coordinator.passes(),
            "the fresh view renders"
        );
        let gaps = document["gaps"].as_array().unwrap();
        assert!(
            gaps.iter()
                .any(|gap| gap["subject"] == "inventory capture failed"),
            "the fresh final reports the failure gap: {gaps:?}"
        );
    }

    #[test]
    fn presentation_guard_final_without_prior_falls_back_to_fresh_capture() {
        // Pending without a prior (only before the opening seed)
        // falls back to a fresh capture: the stop must still write
        // its report. Lock-in: the fallback is the specified
        // behavior, so it holds with and without the guard.
        let mut coordinator = coordinator();
        coordinator.note_scope_gap("staged late gap".into(), "y".into());
        coordinator.commit_batch(false).unwrap();
        let headless = headless_display();
        let mut driver = driver_with_display(&mut coordinator, headless.display);
        driver.semantic = Some(joint_lane(WindDownIo::completing(), false));
        driver.joint_commit_pending = true;
        assert!(driver.publication_pending(), "the harness driver pends");
        let state = StreamState::new();
        let final_view = final_view_guarded(&driver, &state, "system", 1, 9);
        let fresh = Presentation::capture(
            driver.coordinator,
            "system",
            1,
            9,
            driver.coordinator.passes(),
        );
        assert_eq!(final_view.passes, fresh.passes);
        assert_eq!(final_view.ended_ns, fresh.ended_ns);
        assert_eq!(final_view.gaps.len(), fresh.gaps.len());
        assert!(
            final_view
                .gaps
                .iter()
                .any(|gap| gap.subject == "staged late gap"),
            "the fallback reads fresh"
        );
    }

    #[test]
    fn presentation_guard_failed_startup_without_prior_falls_back_to_fresh_capture() {
        // Pending without a prior falls back to a fresh capture:
        // the failure must still be reported. Lock-in like the
        // final-view fallback above.
        let pending = harness_pending_verdict(true);
        assert!(pending, "the harness driver pends");
        let mut coordinator = coordinator();
        coordinator.commit_batch(false).unwrap();
        let dir = private_tempdir();
        let report_path = dir.path().join("report.json");
        let events_path = dir.path().join("events.jsonl");
        let writer = EventWriter::anonymous_test_sink(std::fs::File::create(&events_path).unwrap());
        let mut stream = EventLogState::new(Some(writer));
        let mut stdout: Vec<u8> = Vec::new();
        let error = anyhow::anyhow!("scripted native failure");
        let finalized = std::cell::Cell::new(false);
        finish_failed_startup_guarded(
            pending,
            None,
            &mut coordinator,
            "system",
            1,
            Some(crate::output::atomic_file_test_fixture(&report_path)),
            &mut stream,
            None,
            true,
            &mut crate::inventory_output::WriterStdout(&mut stdout),
            &error,
            &|| false,
            &|| finalized.set(true),
            None,
        );
        assert!(finalized.get(), "outputs were attempted");
        let document: serde_json::Value = serde_json::from_slice(&stdout).unwrap();
        let gaps = document["gaps"].as_array().unwrap();
        assert!(
            gaps.iter()
                .any(|gap| gap["subject"] == "inventory capture failed"),
            "the fallback reports the failure gap: {gaps:?}"
        );
    }

    /// The D5 scene: a fresh substituted lane (no Joint seams) with a
    /// legacy-tick spy, seated on the driver. Returns the tick spy.
    fn seat_fresh_joint_candidate(
        driver: &mut ClassicDriver<'_>,
    ) -> std::rc::Rc<std::cell::Cell<usize>> {
        use std::cell::Cell;
        use std::rc::Rc;
        let ticks = Rc::new(Cell::new(0));
        let mut io = WindDownIo::completing();
        io.ticks = Rc::clone(&ticks);
        driver.semantic = Some(wind_down_lane(io));
        ticks
    }

    #[test]
    fn joint_lane_initializes_before_first_tick_pid() {
        let mut coordinator = coordinator();
        let headless = headless_display();
        let mut driver = driver_with_display(&mut coordinator, headless.display);
        let ticks = seat_fresh_joint_candidate(&mut driver);
        driver
            .semantic
            .as_mut()
            .expect("lane stays seated")
            .set_scripted_joint_init_for_test(Some(Ok(())));
        driver.initialize_joint_lane();
        {
            let lane = driver.semantic.as_ref().expect("lane stays seated");
            assert_eq!(
                lane.joint_init_calls_for_test(),
                1,
                "D5 initializes the lane before its first tick"
            );
            assert!(
                lane.has_joint_machine(),
                "a successful init marks the lane Joint"
            );
        }
        assert_eq!(ticks.get(), 0, "initialization ticks no legacy quantum");
        // Exactly once: a second call is a no-op on a Joint lane.
        driver.initialize_joint_lane();
        assert_eq!(
            driver
                .semantic
                .as_ref()
                .expect("lane stays seated")
                .joint_init_calls_for_test(),
            1,
            "D5 initializes exactly once per lane"
        );
        assert_eq!(ticks.get(), 0, "still no legacy tick");
    }

    #[test]
    fn joint_lane_initializes_before_first_tick_cgroup() {
        let mut coordinator = coordinator();
        let headless = headless_display();
        let mut driver = driver_with_display(&mut coordinator, headless.display);
        // The D5 wiring is scope-blind: only the run scope differs.
        driver.scope = InventoryRunScope::Cgroup;
        let ticks = seat_fresh_joint_candidate(&mut driver);
        driver
            .semantic
            .as_mut()
            .expect("lane stays seated")
            .set_scripted_joint_init_for_test(Some(Ok(())));
        driver.initialize_joint_lane();
        {
            let lane = driver.semantic.as_ref().expect("lane stays seated");
            assert_eq!(
                lane.joint_init_calls_for_test(),
                1,
                "D5 initializes the lane before its first tick"
            );
            assert!(
                lane.has_joint_machine(),
                "a successful init marks the lane Joint"
            );
        }
        assert_eq!(ticks.get(), 0, "initialization ticks no legacy quantum");
        driver.initialize_joint_lane();
        assert_eq!(
            driver
                .semantic
                .as_ref()
                .expect("lane stays seated")
                .joint_init_calls_for_test(),
            1,
            "D5 initializes exactly once per lane"
        );
        assert_eq!(ticks.get(), 0, "still no legacy tick");
    }

    #[test]
    fn joint_lane_initializes_before_first_tick_system() {
        let mut coordinator = coordinator();
        let headless = headless_display();
        let mut driver = driver_with_display(&mut coordinator, headless.display);
        // The D5 wiring is scope-blind: only the run scope differs.
        driver.scope = InventoryRunScope::System;
        driver.inventory_scope = Some(InventoryScope::System);
        let ticks = seat_fresh_joint_candidate(&mut driver);
        driver
            .semantic
            .as_mut()
            .expect("lane stays seated")
            .set_scripted_joint_init_for_test(Some(Ok(())));
        driver.initialize_joint_lane();
        {
            let lane = driver.semantic.as_ref().expect("lane stays seated");
            assert_eq!(
                lane.joint_init_calls_for_test(),
                1,
                "D5 initializes the lane before its first tick"
            );
            assert!(
                lane.has_joint_machine(),
                "a successful init marks the lane Joint"
            );
        }
        assert_eq!(ticks.get(), 0, "initialization ticks no legacy quantum");
        driver.initialize_joint_lane();
        assert_eq!(
            driver
                .semantic
                .as_ref()
                .expect("lane stays seated")
                .joint_init_calls_for_test(),
            1,
            "D5 initializes exactly once per lane"
        );
        assert_eq!(ticks.get(), 0, "still no legacy tick");
    }

    #[test]
    fn joint_lane_after_legacy_tick_stays_legacy_and_disclosed() {
        let mut coordinator = coordinator();
        let headless = headless_display();
        let mut driver = driver_with_display(&mut coordinator, headless.display);
        let ticks = seat_fresh_joint_candidate(&mut driver);
        // No scripted init: the natural path on a substituted lane.
        driver.on_tick();
        assert_eq!(ticks.get(), 1, "the first hook ticks the legacy lane");
        driver.initialize_joint_lane();
        {
            let lane = driver.semantic.as_ref().expect("lane stays seated");
            assert_eq!(
                lane.joint_init_calls_for_test(),
                1,
                "D5 attempts the init once"
            );
            assert!(
                !lane.has_joint_machine(),
                "a refused init stays off the Joint path"
            );
        }
        let joint_gaps: Vec<(String, String)> = gaps(&mut driver)
            .into_iter()
            .filter(|gap| gap.0 == "joint machine unavailable")
            .collect();
        assert_eq!(joint_gaps.len(), 1, "the refusal is disclosed once");
        assert!(
            joint_gaps[0].1.contains("semantic_unavailable"),
            "the gap names the refusal: {:?}",
            joint_gaps[0].1
        );
        // The legacy path continues: the staged gate held the second
        // hook, so clear it (the test's own driver) and tick again.
        driver.semantic_staged = false;
        driver.on_tick();
        assert_eq!(ticks.get(), 2, "a refused lane keeps legacy service");
    }

    #[test]
    fn joint_poll_commit_refused_poll_holds_lane_and_publishes() {
        // Structural contract (controller ruling E1: the semantic lane
        // must never end the broad inventory): a refused Joint commit
        // poll holds the lane for exit, discloses it once, commits the
        // pass's native evidence, and publishes, so later passes
        // continue on the legacy path. Replaces the old fail-the-call
        // pin, which is superseded by the ruling.
        let mut coordinator = coordinator();
        let headless = headless_display();
        let mut driver = driver_with_display(&mut coordinator, headless.display);
        let mut lane = joint_lane(WindDownIo::completing(), false);
        lane.set_scripted_joint_begin_for_test(Some(Ok(())));
        driver.semantic = Some(lane);
        // The first call carries the engine change and begins; the
        // poll refuses without a live machine, and the refusal holds
        // the lane instead of failing the call.
        let first = driver.poll_commit(true);
        assert!(
            matches!(
                first,
                Ok(crate::inventory_capture::PassCommitProgress::Published)
            ),
            "a refused poll publishes the pass past the held lane"
        );
        assert!(
            driver.semantic.is_none(),
            "the refused lane is held for exit"
        );
        assert!(
            !driver.joint_commit_pending,
            "the held commit pends nothing"
        );
        assert_eq!(driver.joint_commit_polls, 1, "the first call polls once");
        assert_eq!(
            driver.commit_calls, 1,
            "the pass commits past the held lane"
        );
        let stops: Vec<(String, String)> = gaps(&mut driver)
            .into_iter()
            .filter(|gap| gap.0 == "semantic lane stopped")
            .collect();
        assert_eq!(stops.len(), 1, "the hold is disclosed once");
        assert_eq!(
            stops[0].1,
            "semantic_unavailable; broad inventory continues; semantic probes stay attached until exit",
            "the gap names the poll refusal"
        );
        // Later passes continue on the legacy path: no begin, no poll.
        let second = driver.poll_commit(false);
        assert!(
            matches!(
                second,
                Ok(crate::inventory_capture::PassCommitProgress::Published)
            ),
            "later passes publish without the lane"
        );
        assert_eq!(
            driver.commit_calls, 2,
            "every pass commits its native evidence"
        );
        assert_eq!(driver.joint_commit_polls, 1, "no further joint poll runs");
    }

    #[test]
    fn joint_poll_commit_absent_machine_falls_back_to_legacy() {
        // No live machine (the natural NotInitialized): a Joint-marked
        // lane with nothing to begin on commits the legacy way, like
        // D5's Err path, so the retained pump keeps progress-or-pend.
        let mut coordinator = coordinator();
        let headless = headless_display();
        let mut driver = driver_with_display(&mut coordinator, headless.display);
        let lane = joint_lane(WindDownIo::completing(), false);
        driver.semantic = Some(lane);
        let outcome = driver.poll_commit(true);
        assert!(
            matches!(
                outcome,
                Ok(crate::inventory_capture::PassCommitProgress::Published)
            ),
            "the fallback publishes at once"
        );
        assert_eq!(driver.commit_calls, 1, "one legacy commit runs");
        assert!(!driver.joint_commit_pending, "the fallback pends nothing");
        assert_eq!(
            driver
                .semantic
                .as_ref()
                .expect("lane stays seated")
                .joint_commit_begin_calls_for_test(),
            1,
            "the begin is attempted once"
        );
        assert_eq!(driver.joint_commit_polls, 0, "the fallback never polls");
    }

    #[test]
    fn joint_poll_commit_begin_refusal_holds_lane_and_publishes() {
        // Structural contract (controller ruling E1: the semantic lane
        // must never end the broad inventory): a refused Joint begin
        // (DispositionRequired from any machine latch) holds the lane
        // for exit, discloses it once, commits the pass, and publishes,
        // with no poll. The tick that latched names the stop: the
        // driver keeps the first tick-service refusal instead of
        // dropping it, and the gap carries it. Replaces the old
        // fail-the-call pin, which is superseded by the ruling.
        let mut coordinator = coordinator();
        let headless = headless_display();
        let mut driver = driver_with_display(&mut coordinator, headless.display);
        let mut lane = joint_lane(WindDownIo::completing(), false);
        lane.set_scripted_joint_begin_for_test(Some(Err(
            crate::inventory_semantics::JointCommitRefusal::DispositionRequired,
        )));
        driver.semantic = Some(lane);
        // The latch lands on the tick first (production shape: the tick
        // service latches, the next begin refuses); the driver keeps
        // the reason instead of dropping it.
        driver.on_tick();
        let outcome = driver.poll_commit(true);
        assert!(
            matches!(
                outcome,
                Ok(crate::inventory_capture::PassCommitProgress::Published)
            ),
            "a refused begin publishes the pass past the held lane"
        );
        assert!(
            driver.semantic.is_none(),
            "the refused lane is held for exit"
        );
        assert!(
            !driver.joint_commit_pending,
            "a refused begin pends nothing"
        );
        assert_eq!(driver.joint_commit_polls, 0, "a refused begin never polls");
        assert_eq!(
            driver.commit_calls, 1,
            "the pass commits past the held lane"
        );
        let stops: Vec<(String, String)> = gaps(&mut driver)
            .into_iter()
            .filter(|gap| gap.0 == "semantic lane stopped")
            .collect();
        assert_eq!(stops.len(), 1, "the hold is disclosed once");
        assert_eq!(
            stops[0].1,
            "semantic_unavailable; broad inventory continues; semantic probes stay attached until exit",
            "the gap names the latched tick refusal"
        );
    }

    #[test]
    fn joint_poll_commit_latched_lane_abandons_for_lane_stop_and_continues() {
        // Production-shape conversion: a latched lane (latched via
        // note_joint_finish_failure, as a machine latch leaves it)
        // whose begin refuses DispositionRequired converts mid-run.
        // The abandon runs (H0 stops) with a lane-stop subject, never
        // "for exit": the run continues. The pass commits and
        // publishes, and later passes continue on the legacy path.
        let mut coordinator = coordinator();
        let headless = headless_display();
        let mut driver = driver_with_display(&mut coordinator, headless.display);
        let mut lane = joint_lane(WindDownIo::completing(), false);
        lane.note_joint_finish_failure(crate::inventory_semantics::SemanticRefusal::Unavailable);
        lane.set_scripted_joint_begin_for_test(Some(Err(
            crate::inventory_semantics::JointCommitRefusal::DispositionRequired,
        )));
        driver.semantic = Some(lane);
        let outcome = driver.poll_commit(true);
        assert!(
            matches!(
                outcome,
                Ok(crate::inventory_capture::PassCommitProgress::Published)
            ),
            "a refused begin publishes the pass past the held lane"
        );
        assert!(
            driver.semantic.is_none(),
            "the refused lane is held for exit"
        );
        assert!(
            !driver.joint_commit_pending,
            "a refused begin pends nothing"
        );
        assert_eq!(
            driver.commit_calls, 1,
            "the pass commits past the held lane"
        );
        let abandons: Vec<(String, String)> = gaps(&mut driver)
            .into_iter()
            .filter(|gap| gap.0 == "joint finish abandoned for lane stop")
            .collect();
        assert_eq!(abandons.len(), 1, "the mid-run abandon is disclosed once");
        assert!(
            gaps(&mut driver)
                .iter()
                .all(|gap| gap.0 != "joint finish abandoned for exit"),
            "a mid-run abandon never says for exit"
        );
        let stops: Vec<(String, String)> = gaps(&mut driver)
            .into_iter()
            .filter(|gap| gap.0 == "semantic lane stopped")
            .collect();
        assert_eq!(stops.len(), 1, "the hold is disclosed once");
        // Later passes continue on the legacy path: no panic, no
        // re-hold, every pass commits its native evidence.
        let second = driver.poll_commit(false);
        assert!(
            matches!(
                second,
                Ok(crate::inventory_capture::PassCommitProgress::Published)
            ),
            "later passes publish without the lane"
        );
        assert_eq!(driver.commit_calls, 2, "every pass commits");
    }

    #[test]
    fn converted_commit_hold_reports_partial_summary() {
        // A mid-run hold marks the seated summary Partial: the lane
        // stopped with declared loss for the rest of the run, so the
        // report must never read "active" past the hold.
        let mut coordinator = coordinator();
        let headless = headless_display();
        let mut driver = driver_with_display(&mut coordinator, headless.display);
        let mut lane = joint_lane(WindDownIo::completing(), false);
        lane.set_scripted_joint_begin_for_test(Some(Err(
            crate::inventory_semantics::JointCommitRefusal::DispositionRequired,
        )));
        driver.semantic = Some(lane);
        driver.on_tick();
        let outcome = driver.poll_commit(true);
        assert!(
            matches!(
                outcome,
                Ok(crate::inventory_capture::PassCommitProgress::Published)
            ),
            "a refused begin publishes the pass past the held lane"
        );
        assert_eq!(
            driver.semantic_summary().status,
            crate::inventory_semantics::SemanticCaptureStatus::Partial,
            "a held lane reads partial, never active"
        );
    }

    #[test]
    fn retained_tick_conversion_reports_partial_summary() {
        // Stop-time parity: a Tick-cursor conversion marks the seated
        // summary Partial, exactly like the Poll path.
        let mut coordinator = coordinator();
        let headless = headless_display();
        let mut driver = driver_with_display(&mut coordinator, headless.display);
        driver.semantic = Some(joint_lane(WindDownIo::completing(), false));
        driver.suspended = true;
        driver.joint_commit_pending = true;
        driver.on_tick();
        assert!(
            driver.semantic.is_none(),
            "the refused lane is held for exit"
        );
        assert_eq!(
            driver.semantic_summary().status,
            crate::inventory_semantics::SemanticCaptureStatus::Partial,
            "a held lane reads partial, never active"
        );
    }

    #[test]
    fn joint_poll_commit_outstanding_begin_holds_lane_on_poll_refusal() {
        // Structural contract (controller ruling E1: the semantic lane
        // must never end the broad inventory): an outstanding demand
        // without the flag repairs the flag and resumes polling its
        // original ownership, and the resumed poll's refusal holds the
        // lane and publishes instead of failing the call. Replaces the
        // old fail-the-call pin, which is superseded by the ruling.
        let mut coordinator = coordinator();
        let headless = headless_display();
        let mut driver = driver_with_display(&mut coordinator, headless.display);
        let mut lane = joint_lane(WindDownIo::completing(), false);
        lane.set_scripted_joint_begin_for_test(Some(Err(
            crate::inventory_semantics::JointCommitRefusal::OutstandingRequest,
        )));
        driver.semantic = Some(lane);
        // An outstanding demand without the flag repairs the flag and
        // resumes polling; the resumed poll refuses without a live
        // machine, and the refusal holds the lane.
        let outcome = driver.poll_commit(false);
        assert!(
            matches!(
                outcome,
                Ok(crate::inventory_capture::PassCommitProgress::Published)
            ),
            "a refused resumed poll publishes past the held lane"
        );
        assert!(
            driver.semantic.is_none(),
            "the refused lane is held for exit"
        );
        assert!(
            !driver.joint_commit_pending,
            "the held commit pends nothing"
        );
        assert_eq!(driver.joint_commit_polls, 1, "the call polls once");
        assert_eq!(
            driver.commit_calls, 1,
            "the pass commits past the held lane"
        );
        let stops: Vec<(String, String)> = gaps(&mut driver)
            .into_iter()
            .filter(|gap| gap.0 == "semantic lane stopped")
            .collect();
        assert_eq!(stops.len(), 1, "the hold is disclosed once");
        assert_eq!(
            stops[0].1,
            "semantic_unavailable; broad inventory continues; semantic probes stay attached until exit",
            "the gap names the poll refusal"
        );
    }

    #[test]
    fn joint_poll_commit_partway_latch_publishes_and_continues() {
        // Partway twin (controller ruling E1): pass 1 publishes
        // healthy, the lane latches mid-run (the tick refuses, then
        // the next begin refuses DispositionRequired), the latched pass
        // still publishes with the named gap, and later passes continue
        // on the legacy path: the run reaches its deadline with every
        // pass's native evidence committed.
        let mut coordinator = coordinator();
        let headless = headless_display();
        let mut driver = driver_with_display(&mut coordinator, headless.display);
        driver.semantic = Some(joint_lane(WindDownIo::completing(), false));
        // Pass 1: a Joint lane with no live machine commits the legacy
        // way and publishes, with no stop gap.
        let first = driver.poll_commit(true);
        assert!(
            matches!(
                first,
                Ok(crate::inventory_capture::PassCommitProgress::Published)
            ),
            "the healthy pass publishes"
        );
        assert_eq!(driver.commit_calls, 1, "the healthy pass commits");
        assert!(
            gaps(&mut driver)
                .iter()
                .all(|gap| gap.0 != "semantic lane stopped"),
            "a healthy pass discloses no lane stop"
        );
        // The latch lands mid-run: the tick refuses, then the next
        // pass's begin refuses DispositionRequired.
        driver
            .semantic
            .as_mut()
            .expect("lane stays seated until the latch")
            .set_scripted_joint_begin_for_test(Some(Err(
                crate::inventory_semantics::JointCommitRefusal::DispositionRequired,
            )));
        driver.on_tick();
        let second = driver.poll_commit(true);
        assert!(
            matches!(
                second,
                Ok(crate::inventory_capture::PassCommitProgress::Published)
            ),
            "the latched pass still publishes"
        );
        assert!(
            driver.semantic.is_none(),
            "the latched lane is held for exit"
        );
        assert!(!driver.publication_pending(), "nothing pends past the hold");
        assert_eq!(
            driver.commit_calls, 2,
            "the latched pass commits its native evidence"
        );
        let stops: Vec<(String, String)> = gaps(&mut driver)
            .into_iter()
            .filter(|gap| gap.0 == "semantic lane stopped")
            .collect();
        assert_eq!(stops.len(), 1, "the hold is disclosed once");
        assert_eq!(
            stops[0].1,
            "semantic_unavailable; broad inventory continues; semantic probes stay attached until exit",
            "the gap names the latched tick refusal"
        );
        // Pass 3: broad inventory continues without the lane.
        let third = driver.poll_commit(false);
        assert!(
            matches!(
                third,
                Ok(crate::inventory_capture::PassCommitProgress::Published)
            ),
            "later passes publish without the lane"
        );
        assert_eq!(driver.commit_calls, 3, "every pass commits");
    }

    #[test]
    fn retained_tick_commit_refusal_converts_like_poll() {
        // Stop-time twin (Tick sees the refusal first): the deadline
        // lands while a Joint commit is pending, the suspended tick's
        // retained step polls the same commit and it refuses. The
        // outcome must match the Poll path for the same event
        // (controller ruling E1): hold, name the stop, publish past
        // it, no run error — never exit 1 with a bare disposition.
        let mut coordinator = coordinator();
        let headless = headless_display();
        let mut driver = driver_with_display(&mut coordinator, headless.display);
        driver.semantic = Some(joint_lane(WindDownIo::completing(), false));
        driver.suspended = true;
        driver.joint_commit_pending = true;
        // The Tick cursor polls the pending commit first and refuses.
        driver.on_tick();
        assert!(
            driver.semantic.is_none(),
            "the refused lane is held for exit"
        );
        assert_eq!(
            driver.joint_finish,
            JointFinishDriver::Abandoned,
            "the commit refusal abandons the unbegun finish"
        );
        assert!(
            !driver.joint_commit_pending,
            "the held commit pends nothing"
        );
        assert!(
            driver.joint_first_error.is_none(),
            "a converted commit refusal keeps no run error"
        );
        // The Poll cursor then commits the legacy way past the held
        // lane and publishes the staged stop gap.
        let polled = driver.poll_commit(false);
        assert!(
            matches!(
                polled,
                Ok(crate::inventory_capture::PassCommitProgress::Published)
            ),
            "the pass publishes past the held lane"
        );
        let stops: Vec<(String, String)> = gaps(&mut driver)
            .into_iter()
            .filter(|gap| gap.0 == "semantic lane stopped")
            .collect();
        assert_eq!(stops.len(), 1, "the hold is disclosed once");
        assert_eq!(
            stops[0].1,
            "semantic_unavailable; broad inventory continues; semantic probes stay attached until exit",
            "the gap names the commit refusal"
        );
        assert!(
            driver.fold_retained_joint_error(None).is_none(),
            "the retained run folds no error from the conversion"
        );
    }

    #[test]
    fn retained_poll_commit_refusal_converts_before_tick() {
        // Stop-time twin (Poll sees the refusal first): the same
        // deadline-during-pending-commit shape, but the Poll cursor
        // polls before the suspended tick. The outcome must equal the
        // Tick-first twin above: hold, one named stop gap, published
        // pass, no retained error.
        let mut coordinator = coordinator();
        let headless = headless_display();
        let mut driver = driver_with_display(&mut coordinator, headless.display);
        driver.semantic = Some(joint_lane(WindDownIo::completing(), false));
        driver.suspended = true;
        driver.joint_commit_pending = true;
        // The Poll cursor polls the pending commit first and refuses.
        let polled = driver.poll_commit(false);
        assert!(
            matches!(
                polled,
                Ok(crate::inventory_capture::PassCommitProgress::Published)
            ),
            "a refused poll publishes the pass past the held lane"
        );
        assert!(
            driver.semantic.is_none(),
            "the refused lane is held for exit"
        );
        assert!(
            !driver.joint_commit_pending,
            "the held commit pends nothing"
        );
        // The suspended tick past the hold is a no-op.
        driver.on_tick();
        assert!(
            driver.joint_first_error.is_none(),
            "a converted commit refusal keeps no run error"
        );
        let stops: Vec<(String, String)> = gaps(&mut driver)
            .into_iter()
            .filter(|gap| gap.0 == "semantic lane stopped")
            .collect();
        assert_eq!(stops.len(), 1, "the hold is disclosed once");
        assert_eq!(
            stops[0].1,
            "semantic_unavailable; broad inventory continues; semantic probes stay attached until exit",
            "the gap names the commit refusal"
        );
        assert!(
            driver.fold_retained_joint_error(None).is_none(),
            "the retained run folds no error from the conversion"
        );
    }

    #[test]
    fn retained_deadline_with_pending_publication_names_the_retained_run() {
        // When the deadline retains the run while a Joint publication
        // pends, the consumer names the retained drain on stderr, so a
        // slow drain is visible instead of a silent hang. The
        // conversion still finalizes the run without an error.
        let mut coordinator = coordinator();
        let headless = headless_display();
        let mut driver = driver_with_display(&mut coordinator, headless.display);
        driver.semantic = Some(joint_lane(WindDownIo::completing(), false));
        driver.joint_commit_pending = true;
        let outcome = retain_with_cause(&mut driver, ZeroPassCause::Deadline, None);
        assert!(outcome.retained.is_some(), "the deadline retains the run");
        assert!(driver.suspended, "the run suspends beside the driver");
        super::take_warned_for_test();
        let stop_now = || false;
        let clock = consume_clock(&stop_now);
        let (stopped, error, _zero_pass) =
            driver.consume_outcome(outcome, &clock, &mut |_, _| Ok(()));
        assert!(
            stopped.is_some() || error.is_none(),
            "the retained run finalizes"
        );
        assert!(error.is_none(), "the conversion folds no run error");
        let warned = super::take_warned_for_test();
        assert!(
            warned.iter().any(|line| line.contains("deadline")
                && line.contains("joint publication")
                && line.contains("retained run")),
            "the retained drain is named on stderr: {warned:?}"
        );
    }

    #[test]
    fn retained_stuck_joint_publication_holds_for_report_within_bound() {
        // A Joint commit stuck Pending past the retained wall bound is
        // held so the report still writes: the hold names its own gap,
        // marks the summary Partial, drops the hold error (exit 0),
        // and the pump finalizes past the held lane. The sticky
        // Pending stands in for the unbounded production wedge;
        // without the bound this test never ends.
        let mut coordinator = coordinator();
        let headless = headless_display();
        let mut driver = driver_with_display(&mut coordinator, headless.display);
        let mut lane = joint_lane(WindDownIo::completing(), false);
        lane.set_scripted_joint_begin_for_test(Some(Ok(())));
        lane.set_scripted_commit_poll_for_test(Some(Ok(JointCommitProgress::Pending)));
        driver.semantic = Some(lane);
        driver.joint_commit_pending = true;
        let outcome = retain_with_cause(&mut driver, ZeroPassCause::Deadline, None);
        assert!(outcome.retained.is_some(), "the deadline retains the run");
        let (run, error) = retained_run_of(outcome);
        let stop_now = || false;
        let clock = consume_clock(&stop_now);
        let started = std::time::Instant::now();
        let (stopped, error, _zero_pass) = driver.consume_retained_run_with_bound(
            run,
            error,
            &clock,
            &mut |_, _| Ok(()),
            std::time::Duration::from_millis(200),
        );
        assert!(
            started.elapsed() < std::time::Duration::from_secs(20),
            "the bound ends a stuck publication finitely"
        );
        assert!(
            stopped.is_some() || error.is_none(),
            "the retained run finalizes"
        );
        assert!(error.is_none(), "the bound hold folds no run error");
        assert!(driver.semantic.is_none(), "the stuck lane is held for exit");
        assert!(
            !driver.joint_commit_pending,
            "the held commit pends nothing"
        );
        assert!(
            driver.joint_first_error.is_none(),
            "the bound hold keeps no run error"
        );
        assert_eq!(
            driver.semantic_summary().status,
            crate::inventory_semantics::SemanticCaptureStatus::Partial,
            "a bound-held lane reads partial"
        );
        let timeouts: Vec<(String, String)> = gaps(&mut driver)
            .into_iter()
            .filter(|gap| gap.0 == "retained joint publication timed out")
            .collect();
        assert_eq!(timeouts.len(), 1, "the bound hold is disclosed once");
        assert!(
            timeouts[0].1.contains("still pending") && timeouts[0].1.contains("report written"),
            "the gap words the hold in plain words: {:?}",
            timeouts[0].1
        );
    }

    #[test]
    fn joint_poll_commit_healthy_run_carries_no_semantic_stop_gap() {
        // Healthy twin: legacy commits and unbegun-Joint fallbacks
        // publish with no "semantic lane stopped" gap; the gap fires
        // only on a real hold.
        let mut coordinator = coordinator();
        let headless = headless_display();
        let mut driver = driver_with_display(&mut coordinator, headless.display);
        driver.semantic = Some(wind_down_lane(WindDownIo::completing()));
        let legacy = driver.poll_commit(true);
        assert!(
            matches!(
                legacy,
                Ok(crate::inventory_capture::PassCommitProgress::Published)
            ),
            "a legacy commit publishes at once"
        );
        driver.semantic = Some(joint_lane(WindDownIo::completing(), false));
        let fallback = driver.poll_commit(true);
        assert!(
            matches!(
                fallback,
                Ok(crate::inventory_capture::PassCommitProgress::Published)
            ),
            "an unbegun Joint lane falls back and publishes"
        );
        assert!(
            gaps(&mut driver)
                .iter()
                .all(|gap| gap.0 != "semantic lane stopped"),
            "a healthy run discloses no lane stop"
        );
    }

    #[test]
    fn joint_poll_commit_conversion_commit_failure_still_fails() {
        // Negative twin: the conversion commits the pass through the
        // coordinator, and a broad (non-semantic) commit failure still
        // fails the call: only semantic-lane refusals convert.
        let mut coordinator = coordinator();
        let headless = headless_display();
        let mut driver = driver_with_display(&mut coordinator, headless.display);
        let mut lane = joint_lane(WindDownIo::completing(), false);
        lane.set_scripted_joint_begin_for_test(Some(Err(
            crate::inventory_semantics::JointCommitRefusal::DispositionRequired,
        )));
        driver.semantic = Some(lane);
        fail_next_classic_commit_for_test("broad commit exploded");
        let outcome = driver.poll_commit(true);
        let error = outcome.expect_err("a broad commit failure still fails the call");
        assert!(
            error.to_string().contains("broad commit exploded"),
            "the broad failure surfaces, not the converted refusal: {error:#}"
        );
        assert!(
            driver.semantic.is_none(),
            "the lane is already held past the failure"
        );
        let stops: Vec<(String, String)> = gaps(&mut driver)
            .into_iter()
            .filter(|gap| gap.0 == "semantic lane stopped")
            .collect();
        assert_eq!(stops.len(), 1, "the stop stages before the failed commit");
    }

    #[test]
    fn joint_poll_commit_wedged_publication_names_semantic_cause() {
        // Wedged-publication mitigation: the machine latched after
        // physically preparing the commit, so the coordinator still
        // holds the unfinished Joint publication and the conversion's
        // plain commit refuses. The driver names the semantic cause
        // on stderr and in the error — never the internal
        // resume-original-frame message. A full hold-and-publish past
        // this wedge needs a coordinator abandon API (reported
        // residual); this twin pins the honest failure.
        let mut coordinator = coordinator();
        let headless = headless_display();
        let mut driver = driver_with_display(&mut coordinator, headless.display);
        let mut lane = joint_lane(WindDownIo::completing(), false);
        lane.set_scripted_joint_begin_for_test(Some(Err(
            crate::inventory_semantics::JointCommitRefusal::DispositionRequired,
        )));
        driver.semantic = Some(lane);
        driver.on_tick();
        fail_next_classic_commit_for_test(
            "an unfinished Joint publication must resume its original frame",
        );
        super::take_warned_for_test();
        let outcome = driver.poll_commit(true);
        let error = outcome.expect_err("a wedged publication still fails the call");
        assert!(
            error.to_string().contains("semantic lane stopped"),
            "the error names the semantic cause: {error:#}"
        );
        assert!(
            !error.to_string().contains("must resume its original frame"),
            "never the internal message: {error:#}"
        );
        assert!(
            driver.semantic.is_none(),
            "the lane is already held past the failure"
        );
        let warned = super::take_warned_for_test();
        assert!(
            warned
                .iter()
                .any(|line| line.contains("unfinished joint publication")),
            "stderr names the wedge: {warned:?}"
        );
        let stops: Vec<(String, String)> = gaps(&mut driver)
            .into_iter()
            .filter(|gap| gap.0 == "semantic lane stopped")
            .collect();
        assert_eq!(stops.len(), 1, "the stop stages before the failed commit");
    }

    #[test]
    fn joint_poll_commit_held_lane_wedge_names_cause() {
        // Terminal-commit twin (soak shape): the lane is already held
        // but the coordinator still holds its unfinished Joint
        // publication, so the plain commit refuses. The driver names
        // the semantic cause on stderr and in the error — never the
        // internal resume-original-frame message.
        let mut coordinator = coordinator();
        let headless = headless_display();
        let mut driver = driver_with_display(&mut coordinator, headless.display);
        assert!(driver.semantic.is_none(), "the lane is already held");
        fail_next_classic_commit_for_test(
            "an unfinished Joint publication must resume its original frame",
        );
        super::take_warned_for_test();
        let outcome = driver.poll_commit(true);
        let error = outcome.expect_err("a wedged publication still fails the call");
        assert!(
            error.to_string().contains("semantic lane held"),
            "the error names the held lane: {error:#}"
        );
        assert!(
            !error.to_string().contains("must resume its original frame"),
            "never the internal message: {error:#}"
        );
        let warned = super::take_warned_for_test();
        assert!(
            warned
                .iter()
                .any(|line| line.contains("unfinished joint publication")),
            "stderr names the wedge: {warned:?}"
        );
    }

    #[test]
    fn joint_poll_commit_live_legacy_wedge_propagates_raw() {
        // No-lie guard: a live legacy lane that hits the wedge shape
        // is NOT stopped, so its commit failure propagates unchanged.
        // Only the already-held lane renames.
        let mut coordinator = coordinator();
        let headless = headless_display();
        let mut driver = driver_with_display(&mut coordinator, headless.display);
        driver.semantic = Some(wind_down_lane(WindDownIo::completing()));
        fail_next_classic_commit_for_test(
            "an unfinished Joint publication must resume its original frame",
        );
        let outcome = driver.poll_commit(true);
        let error = outcome.expect_err("the failure still fails the call");
        assert!(
            error.to_string().contains("must resume its original frame"),
            "a live lane keeps the raw failure: {error:#}"
        );
    }

    #[test]
    fn abandon_unfinished_joint_publication_without_pending_work_is_a_quiet_noop() {
        // Healthy twin: with no unfinished publication the abandon is
        // a quiet no-op (no gap, nothing cleared), and the later plain
        // commit succeeds.
        let mut coordinator = coordinator();
        let mut lane = joint_lane(WindDownIo::completing(), false);
        assert!(
            lane.take_joint_frame_for_abandon().is_none(),
            "a substituted lane holds no frame to abandon"
        );
        assert!(
            !coordinator.publication_pending(),
            "the bare coordinator pends nothing"
        );
        coordinator.abandon_unfinished_joint_publication(&mut lane, None, "test noop".to_string());
        assert!(
            !coordinator.publication_pending(),
            "the no-op clears nothing"
        );
        assert!(
            coordinator
                .registry()
                .staged_scope_gaps_for_test()
                .iter()
                .all(|(subject, _)| subject != "unfinished joint publication abandoned"),
            "the no-op stages no abandon gap"
        );
        coordinator
            .commit_batch(false)
            .expect("a later plain commit succeeds");
    }

    #[test]
    fn hold_joint_lane_for_exit_abandons_a_pending_publication_before_its_abandon_commit() {
        // The exit hold abandons the coordinator's unfinished Joint
        // publication before its abandon commit: the prepared physical
        // work publishes, the abandon stages its named gap, and the
        // later plain commit succeeds instead of refusing past the wedge.
        let mut coordinator = coordinator();
        coordinator.pose_pending_joint_publication_for_test();
        assert!(
            coordinator.publication_pending(),
            "the pose stands in for the wedge"
        );
        let lane = joint_lane(WindDownIo::completing(), false);
        let mut display = None;
        let mut warn = WarnSink {
            display: &mut display,
        };
        let _ = ClassicDriver::hold_joint_lane_for_exit(
            lane,
            &mut coordinator,
            "test wedge",
            "joint work abandoned for exit",
            &mut warn,
            None,
        );
        assert!(
            !coordinator.publication_pending(),
            "the hold abandons the unfinished publication"
        );
        assert!(
            coordinator
                .registry()
                .staged_scope_gaps_for_test()
                .iter()
                .any(|(subject, _)| subject == "unfinished joint publication abandoned"),
            "the abandon stages its named gap"
        );
        coordinator
            .commit_batch(false)
            .expect("a later plain commit succeeds past the abandoned publication");
    }

    #[test]
    fn joint_poll_commit_legacy_lane_keeps_sync_commit() {
        // Lock-in: a legacy lane's poll_commit is today's sync commit
        // plus Published, with no Joint flag, begin or poll.
        let mut coordinator = coordinator();
        let headless = headless_display();
        let mut driver = driver_with_display(&mut coordinator, headless.display);
        driver.semantic = Some(wind_down_lane(WindDownIo::completing()));
        let outcome = driver.poll_commit(true);
        assert!(
            matches!(
                outcome,
                Ok(crate::inventory_capture::PassCommitProgress::Published)
            ),
            "a legacy commit publishes at once"
        );
        assert_eq!(driver.commit_calls, 1, "one sync commit runs");
        assert!(
            !driver.joint_commit_pending,
            "a legacy commit pends nothing"
        );
        assert_eq!(
            driver
                .semantic
                .as_ref()
                .expect("lane stays seated")
                .joint_commit_begin_calls_for_test(),
            0,
            "a legacy commit never begins"
        );
        assert_eq!(driver.joint_commit_polls, 0, "a legacy commit never polls");
    }

    #[test]
    fn joint_poll_commit_pending_repolls_without_rebeginning() {
        // Begin-once lock-in (the E1 rewrites kept the fail-the-call
        // parts superseded but must keep this): a commit still Pending
        // is re-polled without a new begin. Only the first call
        // carries engine_changed; every call polls.
        use crate::discovery::engine::inventory_coordinator::BatchReceipt;
        let mut coordinator = coordinator();
        let headless = headless_display();
        let mut driver = driver_with_display(&mut coordinator, headless.display);
        let mut lane = joint_lane(WindDownIo::completing(), false);
        lane.set_scripted_joint_begin_for_test(Some(Ok(())));
        lane.set_scripted_commit_poll_queue_for_test(vec![
            Ok(JointCommitProgress::Pending),
            Ok(JointCommitProgress::Pending),
            Ok(JointCommitProgress::Published(BatchReceipt {
                engine_facts: 0,
                engine_published: 0,
                registry_facts: 0,
                registry_published: 0,
                registry_applied: 0,
            })),
        ]);
        driver.semantic = Some(lane);
        // The first call carries the engine change, begins once, and
        // polls Pending; the commit pends across the call.
        let first = driver.poll_commit(true);
        assert!(
            matches!(
                first,
                Ok(crate::inventory_capture::PassCommitProgress::Pending)
            ),
            "a pending poll stays pending"
        );
        assert!(
            driver.joint_commit_pending,
            "a begun commit pends across hooks"
        );
        assert_eq!(
            driver
                .semantic
                .as_ref()
                .expect("lane stays seated")
                .joint_commit_begin_calls_for_test(),
            1,
            "begin runs once per publication"
        );
        assert_eq!(driver.joint_commit_polls, 1, "the first call polls once");
        // Retries pass false and resume polling without re-beginning.
        let second = driver.poll_commit(false);
        assert!(
            matches!(
                second,
                Ok(crate::inventory_capture::PassCommitProgress::Pending)
            ),
            "the resumed poll still pends"
        );
        assert!(
            driver.joint_commit_pending,
            "the commit still pends between calls"
        );
        assert_eq!(
            driver
                .semantic
                .as_ref()
                .expect("lane stays seated")
                .joint_commit_begin_calls_for_test(),
            1,
            "retries never re-begin"
        );
        assert_eq!(driver.joint_commit_polls, 2, "every call polls");
        let third = driver.poll_commit(false);
        assert!(
            matches!(
                third,
                Ok(crate::inventory_capture::PassCommitProgress::Published)
            ),
            "the final poll publishes"
        );
        assert!(
            !driver.joint_commit_pending,
            "a published commit pends nothing"
        );
        assert_eq!(
            driver
                .semantic
                .as_ref()
                .expect("lane stays seated")
                .joint_commit_begin_calls_for_test(),
            1,
            "one publication begins exactly once"
        );
        assert_eq!(driver.joint_commit_polls, 3, "all three calls polled");
        assert_eq!(driver.commit_calls, 0, "no legacy commit on the Joint path");
        assert!(
            gaps(&mut driver)
                .iter()
                .all(|gap| gap.0 != "semantic lane stopped"),
            "a healthy commit discloses no lane stop"
        );
    }

    #[test]
    fn joint_service_runs_during_slow_scan_and_staged_retry() {
        use std::cell::Cell;
        use std::rc::Rc;
        let mut coordinator = coordinator();
        let headless = headless_display();
        let mut driver = driver_with_display(&mut coordinator, headless.display);
        // A Joint lane with a freshly staged quantum: the legacy path
        // would hold hooks behind the staged gate and retry the commit
        // at the 1 s staleness deadline; the Joint path services every
        // hook instead, without waiting out the staged age.
        let ticks = Rc::new(Cell::new(0));
        let mut io = WindDownIo::completing();
        io.ticks = Rc::clone(&ticks);
        let mut lane = joint_lane(io, false);
        lane.note_semantic_staged();
        driver.semantic = Some(lane);
        driver.semantic_staged = true;
        // Thirty hooks is about 300 ms at the 10 ms service cadence:
        // the same hook body the loop runs while a collection blocks.
        for _ in 0..30 {
            driver.on_tick();
        }
        let lane = driver.semantic.as_ref().expect("lane stays seated");
        assert_eq!(
            lane.joint_service_calls_for_test(),
            30,
            "every hook services the Joint lane (contract: at least 20)"
        );
        assert_eq!(
            driver.commit_calls, 0,
            "no staged-commit retry on the Joint path"
        );
        assert_eq!(ticks.get(), 0, "no legacy lane tick on the Joint path");
        assert!(
            driver.semantic_staged,
            "Joint service leaves the staged flag alone"
        );
        assert!(
            lane.staged_semantic_age()
                .is_some_and(|age| age < STAGED_SEMANTIC_MAX_AGE),
            "the staged age stays under 1 s: never waited out"
        );
    }
}

#[cfg(test)]
#[path = "inventory_privileged_tests.rs"]
mod privileged_tests;

#[cfg(test)]
#[path = "inventory_manifest_e2e_tests.rs"]
mod manifest_e2e_tests;

#[cfg(test)]
#[path = "inventory_edge_stream_tests.rs"]
mod edge_stream_tests;

#[cfg(test)]
#[path = "inventory_diagnostics_runtime_tests.rs"]
mod diagnostics_runtime_tests;

#[cfg(test)]
#[path = "inventory_cgroup_runtime_tests.rs"]
mod cgroup_runtime_tests;

#[cfg(test)]
mod promotion_driver_tests {
    //! DR37 driver wiring: takes refuse honestly behind the resolver
    //! seam, service statuses apply to the mailbox with gap records,
    //! operator cancel winds work down to a confirmed end, retiring
    //! domains poll the completion minter, and the stop path drains
    //! bounded without installing.
    use super::*;
    use crate::attach::capture::{
        CaptureScopeCoverage, CaptureTargets, CleanupSummary, CookieQuery, DiscoveryBatch,
        ExtendReceipt, ExtendWindow, NativeDomainId, ReadWindow, WitnessBatch,
    };
    use crate::attach::selected_detailed::baseline::{BaselineTarget, PromotionBaselineBatch};
    use crate::discovery::caller_registry::{
        CallerId, ImageAuthority, ModuleId, ModuleKey, OsProcessSource, RegistryLimits,
    };
    use crate::discovery::hooks::HookRegistry;
    use crate::discovery::inventory_attach_set::TargetDelta;
    use crate::inventory_capture::CaptureLane;
    use crate::inventory_dashboard::{DashboardIo, StderrRoute};
    use crate::inventory_promotion::lifecycle::{
        NativeActivationRefusal, NativeActivationSource, NativeCasReceipt, NativeCompletionSource,
        PreparationOutcome, SelectedActivationBinding, SessionNativeCompletion,
    };
    use crate::inventory_promotion::{CaptureId, PromotionEnd, PromotionRefusal, PromotionState};
    use std::cell::{Cell, RefCell};
    use std::collections::BTreeSet;
    use std::os::fd::AsRawFd as _;
    use std::rc::Rc;
    use std::sync::atomic::{AtomicUsize, Ordering};
    use std::sync::{Arc, Condvar, Mutex};
    use std::time::{Duration, Instant};

    fn coordinator() -> InventoryCoordinator<OsProcessSource> {
        InventoryCoordinator::new(
            Scope::Pid(std::process::id()),
            HookRegistry::builtin(),
            Vec::new(),
            OsProcessSource,
            RegistryLimits::default_limits(),
        )
        .expect("test coordinator builds")
    }

    /// A headless display: frames go to /dev/null, no keys, stderr
    /// left alone. The file stays alive with the display.
    pub(crate) struct HeadlessDisplay {
        _null: std::fs::File,
        pub(crate) display: Display,
    }

    pub(crate) fn headless_display() -> HeadlessDisplay {
        let null = std::fs::File::open("/dev/null").expect("/dev/null opens");
        let io = DashboardIo {
            output: null.as_raw_fd(),
            input: None,
            account: None,
            stderr_fd: 2,
            stderr: StderrRoute::Leave,
        };
        let display = Display::open(&io, "test").expect("headless display opens");
        HeadlessDisplay {
            _null: null,
            display,
        }
    }

    pub(crate) fn driver_with_display<'a>(
        coordinator: &'a mut InventoryCoordinator<OsProcessSource>,
        display: Display,
    ) -> ClassicDriver<'a> {
        ClassicDriver {
            coordinator,
            inventory_scope: None,
            scope: InventoryRunScope::Pid(std::process::id()),
            cgroup: None,
            max_scan_pids: None,
            guard: UnavailableImageGuard,
            deadline: None,
            attach_backend: crate::attach::BackendSelection::Auto,
            identity: None,
            display: Some(display),
            semantic: None,
            semantic_staged: false,
            seated_summary: None,
            second_signal: None,
            lifecycle: crate::inventory_promotion::lifecycle::SelectedLifecycleService::new(),
            completion_source: None,
            pending_install: None,
            installed_promotion: None,
            retiring: None,
            joint_finish: JointFinishDriver::NotBegun,
            stop_requested: false,
            joint_first_error: None,
            suspended: false,
            joint_commit_pending: false,
            joint_tick_refusal: None,
            joint_commit_retries: 0,
            #[cfg(test)]
            terminal_seq_calls: 0,
            #[cfg(test)]
            reclaim_calls: Vec::new(),
            #[cfg(test)]
            joint_begin_calls: 0,
            #[cfg(test)]
            joint_step_calls: 0,
            #[cfg(test)]
            joint_commit_polls: 0,
            #[cfg(test)]
            take_promotion_work_calls: 0,
            #[cfg(test)]
            drive_pending_install_calls: 0,
            #[cfg(test)]
            service_caller_metadata_calls: 0,
            #[cfg(test)]
            commit_calls: 0,
        }
    }

    pub(crate) fn queue_request(display: &mut Display) {
        use crate::inventory_promotion::lifecycle::scripted_promotion_view_for_test;
        assert!(display.promotion_enable(CaptureId::new(11)));
        display
            .queue_promotion_request_for_test(
                scripted_promotion_view_for_test(),
                CallerId(3),
                ModuleId(5),
            )
            .expect("exact pair queues");
    }

    struct StubActivationSource;

    impl NativeActivationSource for StubActivationSource {
        fn activate(
            &mut self,
            _session: &crate::attach::Session,
            expected: &SelectedActivationBinding,
        ) -> Result<NativeCasReceipt, NativeActivationRefusal> {
            Ok(NativeCasReceipt::scripted(*expected))
        }
    }

    struct StubCompletionSource(Option<SessionNativeCompletion>);

    impl NativeCompletionSource for StubCompletionSource {
        fn poll_completion(
            &mut self,
            _domain: crate::attach::capture::NativeDomainId,
        ) -> Option<SessionNativeCompletion> {
            self.0.take()
        }

        fn note_wound_down(
            &mut self,
            _domain: crate::attach::capture::NativeDomainId,
            _session: crate::attach::Session,
        ) {
            // Driver twins deliver scripted completions directly and
            // never wind down a live Session.
        }
    }

    /// A completion source whose mint failed: polls pending like the
    /// production minter after a failed mint, with the preserved
    /// first failure available once for the gap path.
    struct FailingCompletionSource {
        failure: Option<String>,
    }

    impl NativeCompletionSource for FailingCompletionSource {
        fn poll_completion(
            &mut self,
            _domain: crate::attach::capture::NativeDomainId,
        ) -> Option<SessionNativeCompletion> {
            None
        }

        fn note_wound_down(
            &mut self,
            _domain: crate::attach::capture::NativeDomainId,
            _session: crate::attach::Session,
        ) {
        }

        fn take_first_failure(&mut self) -> Option<String> {
            self.failure.take()
        }
    }

    /// Scripted terminal cleanup beneath the wind-down stub: the
    /// predicate observes interruption.
    type WindDownCleanup = Box<dyn FnMut(&dyn Fn() -> bool) -> anyhow::Result<()>>;

    /// Minimal substituted lane I/O for wind-down tests: quiescent,
    /// quiet ticks, an empty Finish unless `nonempty_finish` scripts a
    /// Stopped position. Cleanup behavior is scripted per test; receipt
    /// validation honestly refuses (no batch here carries receipts).
    /// The detach reaps beneath the wound-down poll: completing
    /// variants join at once, a gated one stays Pending until its
    /// gate releases. Shared counters observe submits, polls, joins
    /// and drops without disturbing the substituted verdicts.
    pub(crate) struct WindDownIo {
        cleanup: WindDownCleanup,
        nonempty_finish: bool,
        gate: Option<Arc<(Mutex<bool>, Condvar)>>,
        release_after_polls: Option<usize>,
        pub(crate) fail_poll: bool,
        quiescent: bool,
        submits: Rc<Cell<usize>>,
        pub(crate) polls: Rc<Cell<usize>>,
        completes: Rc<Cell<usize>>,
        pub(crate) ticks: Rc<Cell<usize>>,
        threads: Rc<RefCell<Vec<std::thread::ThreadId>>>,
        pub(crate) drop_spy: Option<Rc<Cell<usize>>>,
        submitted: bool,
    }

    impl Drop for WindDownIo {
        fn drop(&mut self) {
            if let Some(spy) = &self.drop_spy {
                spy.set(spy.get() + 1);
            }
        }
    }

    impl WindDownIo {
        pub(crate) fn completing() -> Self {
            Self {
                cleanup: Box::new(|_| Ok(())),
                nonempty_finish: false,
                gate: None,
                release_after_polls: None,
                fail_poll: false,
                quiescent: true,
                submits: Rc::new(Cell::new(0)),
                polls: Rc::new(Cell::new(0)),
                completes: Rc::new(Cell::new(0)),
                ticks: Rc::new(Cell::new(0)),
                threads: Rc::new(RefCell::new(Vec::new())),
                drop_spy: None,
                submitted: false,
            }
        }

        /// A completing cleanup beneath a nonempty Finish (Stopped at
        /// 7): the uncertainty twin's terminal loss, which must stay
        /// disposable without restoring positives.
        pub(crate) fn nonempty_completing() -> Self {
            Self {
                cleanup: Box::new(|_| Ok(())),
                nonempty_finish: true,
                gate: None,
                release_after_polls: None,
                fail_poll: false,
                quiescent: true,
                submits: Rc::new(Cell::new(0)),
                polls: Rc::new(Cell::new(0)),
                completes: Rc::new(Cell::new(0)),
                ticks: Rc::new(Cell::new(0)),
                threads: Rc::new(RefCell::new(Vec::new())),
                drop_spy: None,
                submitted: false,
            }
        }

        /// A gated cleanup: the detach stays Pending until the test
        /// releases the gate, then joins. The synchronous consume
        /// boundary refuses while held, so only the poll path retires.
        pub(crate) fn gated() -> (Self, Arc<(Mutex<bool>, Condvar)>) {
            let gate = Arc::new((Mutex::new(false), Condvar::new()));
            let mut io = Self::completing();
            io.gate = Some(Arc::clone(&gate));
            (io, gate)
        }
    }

    /// Release a gated cleanup: later polls join.
    fn release_gate(gate: &Arc<(Mutex<bool>, Condvar)>) {
        let (lock, waker) = &**gate;
        *lock.lock().unwrap_or_else(|poison| poison.into_inner()) = true;
        waker.notify_all();
    }

    /// Whether a gated cleanup is released.
    fn gate_released(gate: &Arc<(Mutex<bool>, Condvar)>) -> bool {
        let (lock, _) = &**gate;
        *lock.lock().unwrap_or_else(|poison| poison.into_inner())
    }

    impl crate::inventory_semantics::LaneTestIo for WindDownIo {
        fn begin_terminal_cleanup(&mut self) -> anyhow::Result<()> {
            // The production begin submits once and idles after: only
            // the first call counts as a submit.
            if !self.submitted {
                self.submitted = true;
                self.submits.set(self.submits.get() + 1);
            }
            Ok(())
        }

        fn finish_terminal_cleanup(
            &mut self,
            second_signal: &dyn Fn() -> bool,
            _out: &mut dyn std::io::Write,
        ) -> anyhow::Result<()> {
            if let Some(gate) = &self.gate
                && !gate_released(gate)
            {
                anyhow::bail!("scripted cleanup still gated");
            }
            (self.cleanup)(second_signal)
        }

        fn poll_terminal_detach(
            &mut self,
            _out: &mut dyn std::io::Write,
        ) -> anyhow::Result<crate::attach::ProducerDetachProgress> {
            use crate::attach::ProducerDetachProgress;
            self.polls.set(self.polls.get() + 1);
            self.threads.borrow_mut().push(std::thread::current().id());
            if self.fail_poll {
                anyhow::bail!("scripted genuine Unproved detach");
            }
            // A detach that joins mid-wait: release the gate once the
            // poll count reaches the scripted step, so the same poll
            // observes the join deterministically, with no thread.
            if self
                .release_after_polls
                .is_some_and(|at| self.polls.get() >= at)
                && let Some(gate) = &self.gate
            {
                release_gate(gate);
            }
            match &self.gate {
                None => {
                    self.completes.set(self.completes.get() + 1);
                    Ok(ProducerDetachProgress::Complete)
                }
                Some(gate) if gate_released(gate) => {
                    self.completes.set(self.completes.get() + 1);
                    Ok(ProducerDetachProgress::Complete)
                }
                Some(_) => Ok(ProducerDetachProgress::Pending),
            }
        }

        fn validate_current(
            &mut self,
            _receipt: &crate::semantic_capture::CurrentPartitionReceipt,
            _report: &mut crate::semantic_capture::TickReport,
        ) -> Result<(), crate::semantic_capture::CurrentReceiptRefusal> {
            Err(crate::semantic_capture::CurrentReceiptRefusal::Attachment)
        }

        fn tick(
            &mut self,
            domain: crate::attach::capture::NativeDomainId,
        ) -> Result<
            crate::inventory_semantics::SemanticBatch,
            crate::inventory_semantics::SemanticRefusal,
        > {
            self.ticks.set(self.ticks.get() + 1);
            Ok(crate::inventory_semantics::SemanticBatch::scripted(
                domain,
                Vec::new(),
                0,
            ))
        }

        fn refresh(
            &mut self,
            pin: std::sync::Arc<PidPin>,
            _slot: u32,
        ) -> Result<
            (
                Vec<p11scope_ebpf_common::ImageIdentity>,
                std::sync::Arc<PidPin>,
            ),
            crate::inventory_semantics::SemanticRefusal,
        > {
            Ok((Vec::new(), pin))
        }

        fn has_pending_evidence(&self) -> bool {
            false
        }

        fn finish(
            &mut self,
            domain: crate::attach::capture::NativeDomainId,
        ) -> crate::inventory_semantics::SemanticBatch {
            if self.nonempty_finish {
                use crate::semantic_capture::{
                    Invalidation, InvalidationScope, TickOutcome, TickReport,
                };
                let outcome = TickOutcome::Invalidation(Invalidation::scripted(
                    domain,
                    InvalidationScope::Stopped,
                    Some(7),
                ));
                let report = TickReport::scripted(vec![outcome], Vec::new());
                crate::inventory_semantics::SemanticBatch::from_tick_report(
                    domain,
                    report,
                    Vec::new(),
                    0,
                )
                .expect("scripted nonempty Finish respects lane bounds")
            } else {
                crate::inventory_semantics::SemanticBatch::scripted(domain, Vec::new(), 0)
            }
        }

        fn quiescent(&mut self) -> bool {
            // A blocked H0 drain never settles: any terminal
            // sequence that runs this lane burns its time budget.
            self.quiescent
        }

        fn positions(&mut self) -> Option<[(usize, usize); 2]> {
            Some([(0, 0), (0, 0)])
        }

        fn drain_events_to(
            &mut self,
            _stop: usize,
            _quantum: usize,
        ) -> crate::inventory_semantics::LaneDrainOutcome {
            crate::inventory_semantics::LaneDrainOutcome::default()
        }

        fn drain_discovery_to(
            &mut self,
            _stop: usize,
            _quantum: usize,
        ) -> crate::inventory_semantics::LaneDrainOutcome {
            crate::inventory_semantics::LaneDrainOutcome::default()
        }
    }

    /// A shell lane carrying the wind-down stub: the subset is only
    /// ever carried (empty batches stage nothing provable), so a
    /// single-slot envelope suffices. Shared with the D5 init tests,
    /// which need a fresh lane without the Joint seams.
    pub(crate) fn wind_down_lane(
        io: WindDownIo,
    ) -> crate::inventory_semantics::AttestedSemanticLane {
        use crate::discovery::identity::PinnedObjectId;
        let slot = crate::plan::Slot {
            index: 0,
            descriptor_index: crate::kinds::function_id("C_SignInit").unwrap() + 1,
            object: PinnedObjectId(0),
            object_path: "/stub-provider.so".into(),
            file_offset: 0x1200,
            names: vec!["C_SignInit".into()],
            aliased: false,
            semantics: crate::kinds::descriptor("C_SignInit").unwrap(),
            semantic_authorized: true,
            semantic_ambiguous: false,
            fork_safe: true,
            module_ids: vec![crate::plan::ModuleId(0)],
        };
        let subset =
            crate::discovery::engine::inventory_coordinator::semantics::AttestedSubset::scripted(
                crate::plan::AttachPlan::from_slots(vec![slot]),
                crate::discovery::identity::PinnedObjects::empty(),
                std::collections::BTreeMap::from([(
                    PinnedObjectId(0),
                    std::collections::BTreeSet::from([0]),
                )]),
            );
        let mut lane = crate::inventory_semantics::AttestedSemanticLane::start(
            subset,
            &Scope::Pid(std::process::id()),
            crate::attach::BackendSelection::Auto,
        )
        .expect("shell lane starts");
        lane.install_test_io(Box::new(io));
        lane
    }

    /// Record a promotion-installed lane on the driver: queue and
    /// cancel a request (the display observes `Stopping`), then note
    /// the install the wind-down confirms. Returns the lane domain.
    fn install_promotion_for_wind_down(
        driver: &mut ClassicDriver<'_>,
    ) -> crate::attach::capture::NativeDomainId {
        use crate::inventory_promotion::lifecycle::scripted_promotion_view_for_test;
        let display = driver.display.as_mut().expect("display");
        assert!(display.promotion_enable(CaptureId::new(11)));
        display
            .queue_promotion_request_for_test(
                scripted_promotion_view_for_test(),
                CallerId(3),
                ModuleId(5),
            )
            .expect("exact pair queues");
        let taken = display.take_promotion_request().expect("mailbox holds it");
        display.cancel_promotion_for_test();
        assert_eq!(
            display.promotion_state(),
            PromotionState::Stopping,
            "cancel parks the control in Stopping"
        );
        let domain = driver.semantic.as_ref().expect("lane").domain();
        driver.installed_promotion = Some(InstalledPromotion {
            capture: CaptureId::new(11),
            request: taken.id(),
            pair: crate::inventory_promotion::PromotionPair::new(3, 5),
        });
        domain
    }

    /// Publish staged mutations, then read the committed gaps:
    /// gap records stage and apply at publication, like production.
    pub(crate) fn gaps(driver: &mut ClassicDriver<'_>) -> Vec<(String, String)> {
        driver.coordinator.registry_mut().publish();
        driver
            .coordinator
            .registry()
            .gaps()
            .iter()
            .map(|gap| (gap.subject.clone(), gap.reason.clone()))
            .collect()
    }

    fn tick_until_idle(driver: &mut ClassicDriver<'_>) {
        let deadline = Instant::now() + Duration::from_secs(5);
        loop {
            driver.on_tick();
            if driver.lifecycle.is_idle() {
                return;
            }
            assert!(
                Instant::now() < deadline,
                "driver did not settle the service within the bound"
            );
            std::thread::sleep(Duration::from_millis(1));
        }
    }

    /// A completion source that counts polls and wound-down notes:
    /// "no mint" is zero polls, a handed session is one note.
    pub(crate) struct CountingSource {
        inner: StubCompletionSource,
        polls: Arc<AtomicUsize>,
        notes: Arc<AtomicUsize>,
    }

    impl CountingSource {
        pub(crate) fn scripted(
            completion: Option<SessionNativeCompletion>,
        ) -> (Self, Arc<AtomicUsize>, Arc<AtomicUsize>) {
            let polls = Arc::new(AtomicUsize::new(0));
            let notes = Arc::new(AtomicUsize::new(0));
            (
                Self {
                    inner: StubCompletionSource(completion),
                    polls: Arc::clone(&polls),
                    notes: Arc::clone(&notes),
                },
                polls,
                notes,
            )
        }
    }

    impl NativeCompletionSource for CountingSource {
        fn poll_completion(
            &mut self,
            domain: crate::attach::capture::NativeDomainId,
        ) -> Option<SessionNativeCompletion> {
            self.polls.fetch_add(1, Ordering::SeqCst);
            self.inner.poll_completion(domain)
        }

        fn note_wound_down(
            &mut self,
            domain: crate::attach::capture::NativeDomainId,
            session: crate::attach::Session,
        ) {
            self.notes.fetch_add(1, Ordering::SeqCst);
            self.inner.note_wound_down(domain, session);
        }
    }

    /// A Joint lane for the driver tests: a substituted lane with the
    /// retained-frame seam set (production jointness is the live
    /// machine, which unit tests cannot build; the seam drives the
    /// same driver branch). Finished when asked through the real H0
    /// stop; the scaffolding Finish batch is dropped unstaged.
    pub(crate) fn joint_lane(
        io: WindDownIo,
        finished: bool,
    ) -> crate::inventory_semantics::AttestedSemanticLane {
        let mut lane = wind_down_lane(io);
        if finished {
            let _ = lane.finish_semantic_stop();
            assert!(lane.is_finished(), "the H0 stop finishes the lane");
        }
        lane.set_test_joint_frame(true);
        lane.set_test_joint_machine(true);
        assert!(lane.has_joint_frame(), "the seam marks a Joint lane");
        lane
    }

    /// Live, quiescent finalizer state for `domain` through the real
    /// stage/finalize path, with the seal evidence drained: a
    /// retire-Ok scene. Returns nothing; the coordinator holds it.
    fn quiesce_domain_for_retire(
        coordinator: &mut InventoryCoordinator<OsProcessSource>,
        domain: crate::attach::capture::NativeDomainId,
    ) {
        use crate::inventory_semantics::SemanticBatch;
        coordinator.stage_semantic_batch(SemanticBatch::scripted(domain, Vec::new(), 1));
        coordinator.finalize_semantic_batches(None);
        let _ = coordinator.take_h3_disposition();
        assert!(
            !coordinator.joint_domain_has_pending_work(domain),
            "the quiesced domain holds no pending work"
        );
    }

    #[test]
    fn run_promotion_enable_binds_a_fresh_dashboard() {
        let mut coordinator = coordinator();
        let headless = headless_display();
        let mut driver = driver_with_display(&mut coordinator, headless.display);
        assert!(
            !driver
                .display
                .as_ref()
                .expect("display")
                .promotion_enabled(),
            "a fresh dashboard starts unbound"
        );
        assert!(driver.enable_run_promotion(CaptureId::new(7)));
        assert!(
            driver
                .display
                .as_ref()
                .expect("display")
                .promotion_enabled(),
            "the ordinary enable binds the run capture"
        );
    }

    #[test]
    fn run_promotion_enable_twins() {
        // Headless runs have no display and stay unbound; a bound
        // display keeps its capture (a foreign run never rebinds it).
        let mut bare = coordinator();
        let headless = headless_display();
        let mut driver = driver_with_display(&mut bare, headless.display);
        driver.display = None;
        assert!(!driver.enable_run_promotion(CaptureId::new(7)));

        let mut rebound = coordinator();
        let headless = headless_display();
        let mut driver = driver_with_display(&mut rebound, headless.display);
        assert!(driver.enable_run_promotion(CaptureId::new(7)));
        assert!(!driver.enable_run_promotion(CaptureId::new(9)));
        assert!(
            driver
                .display
                .as_ref()
                .expect("display")
                .promotion_enabled(),
            "the refused rebind keeps the first capture"
        );
    }

    /// Scripted baseline lane: delegates every pass-service method to
    /// an inner scripted lane and answers baseline acquisition from
    /// the pairing-only test batch, recording calls and the demanded
    /// (capture, caller).
    type BaselineCallCount = Rc<Cell<usize>>;
    type BaselineSeenPairs = Rc<RefCell<Vec<(CaptureId, CallerId)>>>;

    struct BaselineStub<L> {
        inner: L,
        calls: BaselineCallCount,
        fail: bool,
        seen: BaselineSeenPairs,
    }

    impl<L: NativeIdentity<PidPin>> NativeIdentity<PidPin> for BaselineStub<L> {
        fn owner_image(&mut self, pid: u32) -> Option<ImageIdentity> {
            self.inner.owner_image(pid)
        }

        fn query_cookie(&mut self, domain: NativeDomainId, pin: &PidPin) -> CookieQuery {
            self.inner.query_cookie(domain, pin)
        }
    }

    impl<L: CaptureLane<PidPin>> CaptureLane<PidPin> for BaselineStub<L> {
        fn domain(&self) -> NativeDomainId {
            self.inner.domain()
        }

        fn scope_coverage(&self) -> CaptureScopeCoverage {
            self.inner.scope_coverage()
        }

        fn extend(
            &mut self,
            delta: TargetDelta,
            targets: &dyn CaptureTargets,
            window: ExtendWindow,
        ) -> ExtendReceipt {
            self.inner.extend(delta, targets, window)
        }

        fn service_discovery(&mut self, window: ReadWindow) -> DiscoveryBatch {
            self.inner.service_discovery(window)
        }

        fn read_witnesses(&mut self, window: ReadWindow) -> WitnessBatch {
            self.inner.read_witnesses(window)
        }

        fn begin_stop(&mut self) {
            self.inner.begin_stop()
        }

        fn poll_retirement(&mut self, deadline: Instant) -> Result<bool> {
            self.inner.poll_retirement(deadline)
        }

        fn cleanup(&self) -> Option<CleanupSummary> {
            self.inner.cleanup()
        }

        fn query_promotion_baselines(
            &mut self,
            capture: CaptureId,
            presentation: std::sync::Arc<Presentation>,
            targets: &[BaselineTarget],
            window: ReadWindow,
            _reserve: &mut dyn FnMut(
                usize,
            ) -> std::result::Result<
                crate::semantics_edge::resources::ResourceLease,
                crate::semantics_edge::resources::SemanticResourceRefusal,
            >,
        ) -> Result<PromotionBaselineBatch> {
            self.calls.set(self.calls.get() + 1);
            assert_eq!(
                targets.len(),
                1,
                "the scheduler acquires one pair at a time"
            );
            assert_eq!(
                window.max_rows(),
                1,
                "the scheduler bounds its read to one row"
            );
            self.seen.borrow_mut().push((capture, targets[0].caller));
            if self.fail {
                return Err(anyhow::anyhow!("scripted baseline failure"));
            }
            Ok(PromotionBaselineBatch::scripted_for_test(
                capture,
                presentation,
            ))
        }
    }

    fn baseline_stub<L>(
        inner: L,
        fail: bool,
    ) -> (BaselineStub<L>, BaselineCallCount, BaselineSeenPairs) {
        let calls = Rc::new(Cell::new(0));
        let seen = Rc::new(RefCell::new(Vec::new()));
        (
            BaselineStub {
                inner,
                calls: Rc::clone(&calls),
                fail,
                seen: Rc::clone(&seen),
            },
            calls,
            seen,
        )
    }

    /// A coordinator that admitted this process through the real
    /// reconcile path, with a scripted provider edge for its caller:
    /// custody is genuine, only the edge is scripted.
    fn admitted_self_with_edge() -> (InventoryCoordinator<OsProcessSource>, CallerId) {
        let mut coordinator = coordinator();
        let pid = std::process::id();
        let started_ns = crate::attach::monotonic_ns().expect("monotonic clock");
        let observed = BTreeSet::from([pid]);
        let events = coordinator.adapter_mut().reconcile(
            &observed,
            &mut |_| ImageAuthority::ScanPinned,
            started_ns,
        );
        coordinator.apply_reconcile_events(&events, started_ns);
        let caller = coordinator.adapter().live_id(pid).expect("self admits");
        let key = ModuleKey::physical(
            8,
            1,
            975_001,
            Some("dr37sched".to_string()),
            "/sched/provider.so",
        );
        coordinator.registry_mut().scripted_module_edge(key, caller);
        (coordinator, caller)
    }

    /// A demanded frame: the coordinator admitted self with an edge,
    /// so the captured presentation carries a cursor pair.
    fn demanded_frame() -> (
        InventoryCoordinator<OsProcessSource>,
        Presentation,
        CallerId,
    ) {
        let (coordinator, caller) = admitted_self_with_edge();
        let started_ns = crate::attach::monotonic_ns().expect("monotonic clock");
        let ended_ns = crate::attach::monotonic_ns().expect("monotonic clock");
        let frame = Presentation::capture(&coordinator, "pid", started_ns, ended_ns, 1);
        assert!(!frame.edges.is_empty(), "the edge scripts the cursor pair");
        (coordinator, frame, caller)
    }

    /// Offer a frame and repaint past it: the headless terminal
    /// takes every frame whole, so the repaint commits a viewed frame
    /// with demand.
    fn offer_and_tick(display: &mut Display, frame: Presentation) {
        display.offer(frame);
        display.repaint_for_test();
        assert!(
            display.baseline_demand().is_some(),
            "the repaint commits a viewed frame with demand"
        );
    }

    #[test]
    fn native_service_schedules_baseline_for_viewed_pair() {
        let (mut coordinator, frame, caller) = demanded_frame();
        let headless = headless_display();
        let mut driver = driver_with_display(&mut coordinator, headless.display);
        assert!(driver.enable_run_promotion(CaptureId::new(7)));
        offer_and_tick(driver.display.as_mut().expect("display"), frame);
        let (inner, _) = crate::inventory_capture::tests::cgroup_runtime_lane();
        let (mut stub, calls, seen) = baseline_stub(inner, false);
        driver.on_native_service(Some(&mut stub));
        assert_eq!(calls.get(), 1, "one demand schedules one acquisition");
        assert_eq!(*seen.borrow(), vec![(CaptureId::new(7), caller)]);
        assert!(
            driver
                .display
                .as_ref()
                .expect("display")
                .baseline_demand()
                .is_none(),
            "the staged batch suppresses its own demand"
        );
        // A staged frame schedules nothing more, and only the repaint
        // commits the staged batch with the draw's revision.
        driver.on_native_service(Some(&mut stub));
        assert_eq!(calls.get(), 1);
        driver.display.as_mut().expect("display").repaint_for_test();
        assert!(
            driver
                .display
                .as_ref()
                .expect("display")
                .baseline_demand()
                .is_none(),
            "the committed batch satisfies demand"
        );
        driver.on_native_service(Some(&mut stub));
        assert_eq!(calls.get(), 1);
    }

    #[test]
    fn baseline_schedule_skips_while_disabled() {
        let (mut coordinator, frame, _) = demanded_frame();
        let headless = headless_display();
        let mut driver = driver_with_display(&mut coordinator, headless.display);
        driver.display.as_mut().expect("display").offer(frame);
        driver.display.as_mut().expect("display").tick();
        let (inner, _) = crate::inventory_capture::tests::cgroup_runtime_lane();
        let (mut stub, calls, _) = baseline_stub(inner, false);
        driver.on_native_service(Some(&mut stub));
        assert_eq!(calls.get(), 0, "disabled schedules nothing");
    }

    #[test]
    fn baseline_schedule_skips_without_capture() {
        let (mut coordinator, frame, _) = demanded_frame();
        let headless = headless_display();
        let mut driver = driver_with_display(&mut coordinator, headless.display);
        assert!(driver.enable_run_promotion(CaptureId::new(7)));
        offer_and_tick(driver.display.as_mut().expect("display"), frame);
        driver.on_native_service(None);
        assert!(
            driver
                .display
                .as_ref()
                .expect("display")
                .baseline_demand()
                .is_some(),
            "a skipped demand persists for the next tick"
        );
    }

    #[test]
    fn baseline_schedule_skips_cgroup_scope() {
        let (mut coordinator, frame, _) = demanded_frame();
        let headless = headless_display();
        let mut driver = driver_with_display(&mut coordinator, headless.display);
        driver.scope = InventoryRunScope::Cgroup;
        assert!(driver.enable_run_promotion(CaptureId::new(7)));
        offer_and_tick(driver.display.as_mut().expect("display"), frame);
        let (inner, _) = crate::inventory_capture::tests::cgroup_runtime_lane();
        let (mut stub, calls, _) = baseline_stub(inner, false);
        driver.on_native_service(Some(&mut stub));
        assert_eq!(calls.get(), 0, "cgroup schedules nothing");
    }

    #[test]
    fn baseline_schedule_skips_headless() {
        let (mut coordinator, _, _) = demanded_frame();
        let headless = headless_display();
        let mut driver = driver_with_display(&mut coordinator, headless.display);
        driver.display = None;
        let (inner, _) = crate::inventory_capture::tests::cgroup_runtime_lane();
        let (mut stub, calls, _) = baseline_stub(inner, false);
        driver.on_native_service(Some(&mut stub));
        assert_eq!(calls.get(), 0, "headless schedules nothing");
    }

    #[test]
    fn baseline_schedule_skips_unknown_custody() {
        let (other, frame, _) = demanded_frame();
        drop(other);
        let mut fresh = coordinator();
        let headless = headless_display();
        let mut driver = driver_with_display(&mut fresh, headless.display);
        assert!(driver.enable_run_promotion(CaptureId::new(7)));
        offer_and_tick(driver.display.as_mut().expect("display"), frame);
        let (inner, _) = crate::inventory_capture::tests::cgroup_runtime_lane();
        let (mut stub, calls, _) = baseline_stub(inner, false);
        driver.on_native_service(Some(&mut stub));
        assert_eq!(calls.get(), 0, "missing custody acquires nothing");
        assert!(
            driver
                .display
                .as_ref()
                .expect("display")
                .baseline_demand()
                .is_some(),
            "a skipped demand persists for the next tick"
        );
    }

    #[test]
    fn baseline_schedule_failure_retries_on_new_frame_only() {
        let (mut coordinator, frame, _) = demanded_frame();
        let second = Presentation::capture(
            &coordinator,
            "pid",
            crate::attach::monotonic_ns().expect("monotonic clock"),
            crate::attach::monotonic_ns().expect("monotonic clock"),
            2,
        );
        let headless = headless_display();
        let mut driver = driver_with_display(&mut coordinator, headless.display);
        assert!(driver.enable_run_promotion(CaptureId::new(7)));
        offer_and_tick(driver.display.as_mut().expect("display"), frame);
        let (inner, _) = crate::inventory_capture::tests::cgroup_runtime_lane();
        let (mut stub, calls, _) = baseline_stub(inner, true);
        driver.on_native_service(Some(&mut stub));
        assert_eq!(calls.get(), 1, "the first attempt runs");
        assert!(
            driver
                .display
                .as_ref()
                .expect("display")
                .baseline_demand()
                .is_none(),
            "a failed attempt stays quiet for its frame"
        );
        driver.on_native_service(Some(&mut stub));
        assert_eq!(calls.get(), 1, "no retry for the same frame");
        offer_and_tick(driver.display.as_mut().expect("display"), second);
        driver.on_native_service(Some(&mut stub));
        assert_eq!(calls.get(), 2, "a new frame retries");
    }

    #[test]
    fn take_refuses_unloaded_provider_and_records_gap() {
        // The scripted pair names module 5, which a fresh coordinator
        // never saw: the resolver reports the provider axis, not a
        // blanket manifest refusal.
        let mut coordinator = coordinator();
        let headless = headless_display();
        let mut driver = driver_with_display(&mut coordinator, headless.display);
        queue_request(driver.display.as_mut().expect("display"));
        driver.on_tick();
        assert_eq!(
            driver.display.as_ref().expect("display").promotion_state(),
            PromotionState::Refused(PromotionRefusal::ProviderUnloaded),
            "takes refuse honestly behind the resolver seam"
        );
        assert!(
            gaps(&mut driver)
                .iter()
                .any(|(subject, reason)| subject == "selected promotion refused"
                    && reason == PromotionRefusal::ProviderUnloaded.label()),
            "terminal refusal records a gap: {:?}",
            gaps(&mut driver)
        );
        assert!(driver.lifecycle.is_idle());
        assert!(driver.pending_install.is_none());
    }

    #[test]
    fn take_refuses_without_manifest_permission_and_records_gap() {
        // Module 5 is live with a physical key, but no manifest was
        // ever retained: no permission covers the pair, and no worker
        // starts.
        use crate::discovery::caller_registry::ModuleKey;
        let mut coordinator = coordinator();
        for ino in 100..106 {
            coordinator.registry_mut().scripted_module_edge(
                ModuleKey::physical(8, 1, ino, Some(format!("sha-{ino}")), "/lib/x.so"),
                CallerId(3),
            );
        }
        assert!(
            coordinator.registry().module(ModuleId(5)).is_some(),
            "the scripted provider exists for the permission lookup"
        );
        let headless = headless_display();
        let mut driver = driver_with_display(&mut coordinator, headless.display);
        queue_request(driver.display.as_mut().expect("display"));
        driver.on_tick();
        assert_eq!(
            driver.display.as_ref().expect("display").promotion_state(),
            PromotionState::Refused(PromotionRefusal::ManifestUnavailable),
            "an uncovered pair refuses on the permission axis"
        );
        assert!(
            gaps(&mut driver)
                .iter()
                .any(|(subject, reason)| subject == "selected promotion refused"
                    && reason == PromotionRefusal::ManifestUnavailable.label()),
            "terminal refusal records a gap: {:?}",
            gaps(&mut driver)
        );
        assert!(driver.lifecycle.is_idle());
        assert!(driver.pending_install.is_none());
    }

    #[test]
    fn take_refuses_when_parent_scope_is_cgroup() {
        // Selected cgroup preparation is unqualified: the resolver
        // fails closed before loading any BPF, and names the live
        // scope unsupported instead of misreporting it ended.
        let mut coordinator = coordinator();
        let headless = headless_display();
        let mut driver = driver_with_display(&mut coordinator, headless.display);
        driver.scope = InventoryRunScope::Cgroup;
        queue_request(driver.display.as_mut().expect("display"));
        driver.on_tick();
        assert_eq!(
            driver.display.as_ref().expect("display").promotion_state(),
            PromotionState::Refused(PromotionRefusal::ScopeUnsupported),
            "an unqualified parent scope refuses"
        );
        assert!(driver.lifecycle.is_idle());
        assert!(driver.pending_install.is_none());
    }

    #[test]
    fn take_refuses_when_run_deadline_passed() {
        // Starting BPF preparation for a dead run can never install:
        // the resolver refuses instead of wasting the load.
        let mut coordinator = coordinator();
        let headless = headless_display();
        let mut driver = driver_with_display(&mut coordinator, headless.display);
        driver.deadline = Some(Instant::now() - Duration::from_secs(1));
        queue_request(driver.display.as_mut().expect("display"));
        driver.on_tick();
        assert_eq!(
            driver.display.as_ref().expect("display").promotion_state(),
            PromotionState::Refused(PromotionRefusal::ScopeEnded),
            "an expired run refuses new preparation"
        );
        assert!(driver.lifecycle.is_idle());
        assert!(driver.pending_install.is_none());
    }

    #[test]
    fn service_status_applies_to_display_and_gaps() {
        use crate::attach::selected_detailed::SelectedPreparationFailure;
        let mut coordinator = coordinator();
        let headless = headless_display();
        let mut driver = driver_with_display(&mut coordinator, headless.display);
        queue_request(driver.display.as_mut().expect("display"));
        let request = driver
            .display
            .as_mut()
            .expect("display")
            .take_promotion_request()
            .expect("mailbox holds it");
        let capacity = driver
            .coordinator
            .reserve_promotion_install()
            .expect("capacity reserves");
        driver
            .lifecycle
            .start(request, capacity, Box::new(StubActivationSource), || {
                PreparationOutcome::Failed(SelectedPreparationFailure::scripted_settled())
            })
            .expect("service starts");
        tick_until_idle(&mut driver);
        assert_eq!(
            driver.display.as_ref().expect("display").promotion_state(),
            PromotionState::Refused(PromotionRefusal::PreparationFailed)
        );
        assert!(
            gaps(&mut driver)
                .iter()
                .any(|(subject, _)| subject == "selected promotion refused"),
            "terminal status records a gap: {:?}",
            gaps(&mut driver)
        );
    }

    #[test]
    fn stopping_cancels_service_work_and_confirms_cancelled() {
        use crate::attach::selected_detailed::SelectedPreparationFailure;
        let mut coordinator = coordinator();
        let headless = headless_display();
        let mut driver = driver_with_display(&mut coordinator, headless.display);
        queue_request(driver.display.as_mut().expect("display"));
        let request = driver
            .display
            .as_mut()
            .expect("display")
            .take_promotion_request()
            .expect("mailbox holds it");
        let capacity = driver
            .coordinator
            .reserve_promotion_install()
            .expect("capacity reserves");
        let (release, gate) = std::sync::mpsc::channel::<()>();
        driver
            .lifecycle
            .start(
                request,
                capacity,
                Box::new(StubActivationSource),
                move || {
                    gate.recv().expect("test releases the worker");
                    PreparationOutcome::Failed(SelectedPreparationFailure::scripted_settled())
                },
            )
            .expect("service starts");
        driver
            .display
            .as_mut()
            .expect("display")
            .cancel_promotion_for_test();
        assert_eq!(
            driver.display.as_ref().expect("display").promotion_state(),
            PromotionState::Stopping
        );
        release.send(()).expect("test releases the worker");
        tick_until_idle(&mut driver);
        assert_eq!(
            driver.display.as_ref().expect("display").promotion_state(),
            PromotionState::Ended(PromotionEnd::Cancelled)
        );
        assert!(
            gaps(&mut driver)
                .iter()
                .any(|(subject, reason)| subject == "selected promotion ended"
                    && reason == PromotionEnd::Cancelled.label()),
            "confirmed end records a gap: {:?}",
            gaps(&mut driver)
        );
    }

    #[test]
    fn eager_retire_polls_completion_source() {
        use crate::attach::capture::NativeDomainId;
        use crate::inventory_semantics::SemanticBatch;
        let mut coordinator = coordinator();
        let headless = headless_display();
        let mut driver = driver_with_display(&mut coordinator, headless.display);
        let domain = NativeDomainId::try_mint().expect("domain mints");
        // A live namespace, quiesced through the real drain path.
        driver
            .coordinator
            .stage_semantic_batch(SemanticBatch::scripted(domain, Vec::new(), 1));
        driver.coordinator.finalize_semantic_batches(None);
        driver.retiring = Some(RetiringDomain::wound_down(domain));
        // Without a minter the namespace holds, never forced.
        driver.on_tick();
        assert_eq!(driver.retiring_domain(), Some(domain));
        driver.completion_source = Some(Box::new(StubCompletionSource(Some(
            SessionNativeCompletion::scripted(domain),
        ))));
        driver.on_tick();
        assert_eq!(driver.retiring_domain(), None, "proven completion retires");
        // The domain stays refused: staging it again is audited.
        driver
            .coordinator
            .stage_semantic_batch(SemanticBatch::scripted(domain, Vec::new(), 2));
        assert!(
            gaps(&mut driver)
                .iter()
                .any(|(subject, _)| subject == "semantic batch refused for an ended domain"),
            "retired domain refuses through the audited path: {:?}",
            gaps(&mut driver)
        );
    }

    #[test]
    fn refused_retire_preserves_completion_across_attempts() {
        use crate::attach::capture::NativeDomainId;
        use crate::inventory_semantics::SemanticBatch;
        let mut coordinator = coordinator();
        let headless = headless_display();
        let mut driver = driver_with_display(&mut coordinator, headless.display);
        let domain = NativeDomainId::try_mint().expect("domain mints");
        // Pending work holds the first retire attempt; the minter
        // delivers its proof once, so the retry must reuse the
        // retained completion, never a second delivery.
        driver
            .coordinator
            .stage_semantic_batch(SemanticBatch::scripted(domain, Vec::new(), 1));
        driver.retiring = Some(RetiringDomain::wound_down(domain));
        driver.completion_source = Some(Box::new(StubCompletionSource(Some(
            SessionNativeCompletion::scripted(domain),
        ))));
        driver.on_tick();
        assert_eq!(
            driver.retiring_domain(),
            Some(domain),
            "pending work holds retirement"
        );
        // Drain the pending work through the audited path; the empty
        // batch leaves no drop shadow, so the namespace quiesces.
        driver.coordinator.finalize_semantic_batches(None);
        driver.on_tick();
        assert_eq!(
            driver.retiring_domain(),
            None,
            "the retained proof retires once the work drains"
        );
    }

    #[test]
    fn failed_completion_mint_reports_once_and_holds_retirement() {
        use crate::attach::capture::NativeDomainId;
        use crate::inventory_semantics::SemanticBatch;
        // A failed mint must surface its cause without retiring the
        // namespace: one gap, take-once, and the domain still held.
        let mut coordinator = coordinator();
        let headless = headless_display();
        let mut driver = driver_with_display(&mut coordinator, headless.display);
        let domain = NativeDomainId::try_mint().expect("domain mints");
        driver
            .coordinator
            .stage_semantic_batch(SemanticBatch::scripted(domain, Vec::new(), 1));
        driver.coordinator.finalize_semantic_batches(None);
        driver.retiring = Some(RetiringDomain::wound_down(domain));
        driver.completion_source = Some(Box::new(FailingCompletionSource {
            failure: Some("detach never joined".to_owned()),
        }));
        driver.on_tick();
        assert_eq!(
            driver.retiring_domain(),
            Some(domain),
            "a failed mint holds the namespace"
        );
        let failures: Vec<(String, String)> = gaps(&mut driver)
            .into_iter()
            .filter(|(subject, _)| subject == "selected promotion completion failed")
            .collect();
        assert_eq!(
            failures.len(),
            1,
            "the first failure reports exactly once: {:?}",
            gaps(&mut driver)
        );
        assert!(
            failures[0].1.contains("detach never joined"),
            "the gap carries the mint cause: {:?}",
            failures[0].1
        );
        // A second tick reports nothing further: take-once, never
        // gap-spam, and the namespace still held.
        driver.on_tick();
        assert_eq!(
            driver.retiring_domain(),
            Some(domain),
            "the namespace still holds after the report"
        );
        assert_eq!(
            gaps(&mut driver)
                .iter()
                .filter(|(subject, _)| subject == "selected promotion completion failed")
                .count(),
            1,
            "no duplicate gap on later ticks"
        );
    }

    #[test]
    fn failed_finish_publication_keeps_lane_until_published() {
        let mut coordinator = coordinator();
        let headless = headless_display();
        let mut driver = driver_with_display(&mut coordinator, headless.display);
        driver.semantic = Some(wind_down_lane(WindDownIo::completing()));
        let domain = install_promotion_for_wind_down(&mut driver);
        FAIL_TERMINAL_PUBLICATION.with(|fail| fail.set(true));
        driver.wind_down_installed_promotion(PromotionEnd::Cancelled);
        assert!(
            !FAIL_TERMINAL_PUBLICATION.with(|fail| fail.get()),
            "the refusal hit the real terminal commit boundary"
        );
        assert!(
            driver.semantic.is_some(),
            "the validating lane stays until terminal publication completes"
        );
        assert!(
            driver.installed_promotion.is_some(),
            "no end is confirmed before publication"
        );
        assert!(
            driver.semantic_staged,
            "the unpublished Finish stays staged"
        );
        assert_eq!(
            driver.retiring_domain(),
            None,
            "nothing retires before publication"
        );
        // The retry publishes through the kept lane and the wind-down
        // completes: lane released, domain retiring, end confirmed,
        // and no evidence orphaned without its validator.
        driver
            .semantic
            .as_mut()
            .expect("lane")
            .age_staged_for_test(Instant::now() - Duration::from_secs(5));
        driver.wind_down_installed_promotion(PromotionEnd::Cancelled);
        assert!(driver.semantic.is_none(), "publication releases the lane");
        assert!(driver.installed_promotion.is_none());
        assert_eq!(driver.retiring_domain(), Some(domain));
        assert_eq!(
            driver.display.as_ref().expect("display").promotion_state(),
            PromotionState::Ended(PromotionEnd::Cancelled)
        );
        assert!(
            gaps(&mut driver)
                .iter()
                .all(|(subject, _)| subject != "semantic batch dropped without lane authority"),
            "no evidence orphaned: {:?}",
            gaps(&mut driver)
        );
    }

    #[test]
    fn failed_nonempty_finish_with_uncertainty_still_winds_down() {
        // The nonempty-uncertainty twin: after a failed Finish (H0
        // finished), physical uncertainty refuses its cut, ends the
        // domain, and turns the nonempty Finish into a drop shadow.
        // Terminal loss must stay disposable without restoring
        // positives: the wind-down completes and the retire disposes.
        // Fails pre-fix stranded in Stopping with the lane kept.
        use crate::discovery::engine::inventory_coordinator::semantics::SemanticCallerBinding;
        let mut coordinator = coordinator();
        let headless = headless_display();
        let mut driver = driver_with_display(&mut coordinator, headless.display);
        driver.semantic = Some(wind_down_lane(WindDownIo::nonempty_completing()));
        let domain = install_promotion_for_wind_down(&mut driver);
        FAIL_TERMINAL_PUBLICATION.with(|fail| fail.set(true));
        driver.wind_down_installed_promotion(PromotionEnd::Cancelled);
        assert!(
            driver.semantic.is_some() && driver.semantic_staged,
            "the failed Finish stays staged behind its lane"
        );
        assert!(
            driver.semantic.as_ref().expect("lane").is_finished(),
            "H0 finished before the retry"
        );
        // Physical uncertainty arrives before the retry: a bound,
        // proven caller turns tail-uncertain, and the finished H0
        // refuses its cut.
        let caller = CallerId(9);
        let image = ImageIdentity {
            task_cookie: 41,
            exec_id: 42,
        };
        let pin = std::sync::Arc::new(PidPin::test_proc_only(std::process::id()));
        let module = crate::discovery::caller_registry::ModuleKey::physical(
            8,
            1,
            100,
            Some("sha-100".into()),
            "/lib/x.so",
        );
        driver
            .coordinator
            .semantic_bindings_mut()
            .insert_for_test(SemanticCallerBinding::scripted(
                caller, module, domain, image, pin,
            ))
            .expect("uncertain caller binds");
        driver.coordinator.reference_prove_image(domain, image);
        driver.coordinator.reference_mark_tail(caller);
        driver.semantic.as_mut().expect("lane").fail_cut_once();
        driver
            .semantic
            .as_mut()
            .expect("lane")
            .age_staged_for_test(Instant::now() - Duration::from_secs(5));
        driver.wind_down_installed_promotion(PromotionEnd::Cancelled);
        assert!(
            driver.semantic.is_none(),
            "terminal loss disposes: the lane releases despite the refused cut"
        );
        assert!(driver.installed_promotion.is_none());
        assert_eq!(driver.retiring_domain(), Some(domain));
        assert_eq!(
            driver.display.as_ref().expect("display").promotion_state(),
            PromotionState::Ended(PromotionEnd::Cancelled)
        );
        let subjects: Vec<String> = gaps(&mut driver)
            .iter()
            .map(|(subject, _)| subject.clone())
            .collect();
        assert!(
            subjects
                .iter()
                .any(|subject| subject == "semantic authority ended for domain"),
            "the failed cut ends the domain loudly: {subjects:?}"
        );
        assert!(
            subjects
                .iter()
                .any(|subject| subject == "semantic batch refused for an ended domain"),
            "the nonempty Finish refuses through the audited path: {subjects:?}"
        );
        // The retire disposes the refused shadow without restoring
        // positives: the proof retires, and the domain still refuses.
        driver.completion_source = Some(Box::new(StubCompletionSource(Some(
            SessionNativeCompletion::scripted(domain),
        ))));
        driver.on_tick();
        assert_eq!(
            driver.retiring_domain(),
            None,
            "the refused shadow retires instead of stranding"
        );
        driver.coordinator.stage_semantic_batch(
            crate::inventory_semantics::SemanticBatch::scripted(domain, Vec::new(), 3),
        );
        assert!(
            gaps(&mut driver)
                .iter()
                .any(|(subject, _)| subject == "semantic batch refused for an ended domain"),
            "no positive authority returns: {subjects:?}"
        );
    }

    #[test]
    fn refused_finish_terminates_open_operations_before_shadow_disposal() {
        // The open-operation twin of the nonempty-uncertainty flow: an
        // admitted instance holds an open operation when its Finish
        // fails and the cut refuses the domain. Refusing future
        // positives must not strand existing claims: the refused
        // Finish still publishes its Stopped negative, ending the
        // open operation unknown before the shadow/namespace dispose.
        // Fails pre-fix with the namespace disposed while claims stay
        // clean.
        use crate::discovery::caller_registry::instance_input::{
            InstanceLifecycle, InstanceReason, call as instance_call, key as instance_key,
            position as instance_position, registration as instance_registration,
        };
        use crate::discovery::caller_registry::{AdmissionState, ModuleInfo, ModuleKey};
        use crate::discovery::engine::inventory_coordinator::semantics::SemanticCallerBinding;
        use crate::discovery::instances::InstanceId;
        let mut coordinator = coordinator();
        let headless = headless_display();
        let mut driver = driver_with_display(&mut coordinator, headless.display);
        driver.semantic = Some(wind_down_lane(WindDownIo::nonempty_completing()));
        let domain = install_promotion_for_wind_down(&mut driver);
        // Admit one instance with an open operation before the
        // terminal sequence: mapping, binding, registration, then a
        // current Init call.
        let caller = CallerId(9);
        let image = ImageIdentity {
            task_cookie: 41,
            exec_id: 42,
        };
        let pid = std::process::id();
        let module = ModuleKey::physical(8, 1, 100, Some("sha-100".into()), "/lib/x.so");
        driver.coordinator.registry_mut().note_mapping(
            caller,
            pid,
            ModuleInfo {
                path: "/lib/x.so".into(),
                key: module.clone(),
                double_loaded: false,
                build_id: None,
                identity_source: Some("twin".into()),
                admission: AdmissionState::Admitted,
                admission_class: Some("exact".into()),
                admission_endpoints: Some(1),
                admission_reasons: Vec::new(),
            },
            60,
        );
        driver.coordinator.registry_mut().publish();
        let pin = std::sync::Arc::new(PidPin::test_proc_only(pid));
        driver
            .coordinator
            .semantic_bindings_mut()
            .insert_for_test(SemanticCallerBinding::scripted(
                caller,
                module.clone(),
                domain,
                image,
                pin,
            ))
            .expect("open-operation caller binds");
        let key = instance_key(domain, image, InstanceId::from_raw(1), module);
        driver
            .coordinator
            .registry_mut()
            .note_instance(instance_registration(key.clone(), caller, 100, None));
        driver.coordinator.registry_mut().publish();
        let facts = crate::semantics_edge::SemanticCall {
            function: "C_SignInit".into(),
            session: 7,
            mechanism: 0x000d,
            capture: p11scope_ebpf_common::capture::MECHANISM_VALUE
                | p11scope_ebpf_common::capture::OUTPUT_NON_NULL,
            ts_ns: 110,
            ..Default::default()
        };
        driver
            .coordinator
            .registry_mut()
            .observe_instance_semantic(instance_call(
                key,
                caller,
                instance_position(domain, 1),
                facts,
                None,
            ));
        driver.coordinator.registry_mut().publish();
        let (lossy, started, completed, unknown, state) = {
            let registry = driver.coordinator.registry();
            let edge = registry
                .instance_semantic_edges()
                .next()
                .expect("one admitted edge");
            let semantics = edge.semantics.as_ref().expect("open operation reduces");
            (
                edge.lossy,
                semantics.started(),
                semantics.completed(),
                semantics.unknown(),
                registry.instances().next().expect("one instance").state,
            )
        };
        assert!(
            !lossy && started == 1 && completed == 0 && unknown == 0,
            "the operation opens clean: lossy={lossy} started={started} completed={completed} unknown={unknown}"
        );
        assert_eq!(state, InstanceLifecycle::Observed);
        // The terminal sequence: the Finish fails, then physical
        // uncertainty refuses its cut and ends the domain.
        FAIL_TERMINAL_PUBLICATION.with(|fail| fail.set(true));
        driver.wind_down_installed_promotion(PromotionEnd::Cancelled);
        assert!(
            driver.semantic.is_some() && driver.semantic_staged,
            "the failed Finish stays staged behind its lane"
        );
        driver.coordinator.reference_prove_image(domain, image);
        driver.coordinator.reference_mark_tail(caller);
        driver.semantic.as_mut().expect("lane").fail_cut_once();
        driver
            .semantic
            .as_mut()
            .expect("lane")
            .age_staged_for_test(Instant::now() - Duration::from_secs(5));
        driver.wind_down_installed_promotion(PromotionEnd::Cancelled);
        assert!(
            driver.semantic.is_none(),
            "terminal loss disposes: the lane releases despite the refused cut"
        );
        // The refused Stopped still terminates existing claims: the
        // open operation ends unknown while the namespace still stands.
        // This state check runs BEFORE gaps(): that helper publishes
        // staged mutations, so the twin must observe the production
        // publication order — never perform the publication whose
        // ordering it verifies.
        let (lossy, stopped, started, completed, unknown, state) = {
            let registry = driver.coordinator.registry();
            let edge = registry
                .instance_semantic_edges()
                .next()
                .expect("one admitted edge");
            let semantics = edge.semantics.as_ref().expect("reduced operation stands");
            (
                edge.lossy,
                edge.reasons.contains(&InstanceReason::CaptureStopped),
                semantics.started(),
                semantics.completed(),
                semantics.unknown(),
                registry.instances().next().expect("one instance").state,
            )
        };
        assert!(
            lossy && stopped,
            "the refused Finish publishes its Stopped negative: lossy={lossy} stopped={stopped}"
        );
        assert!(
            started == 1 && completed == 0 && unknown == 1,
            "the open operation ends unknown, never silently completed: started={started} completed={completed} unknown={unknown}"
        );
        assert_eq!(
            state,
            InstanceLifecycle::Uncertain,
            "the claim is unknown before its namespace disposes"
        );
        let subjects: Vec<String> = gaps(&mut driver)
            .iter()
            .map(|(subject, _)| subject.clone())
            .collect();
        assert!(
            subjects
                .iter()
                .any(|subject| subject == "semantic batch refused for an ended domain"),
            "the nonempty Finish refuses through the audited path: {subjects:?}"
        );
        // The retire then disposes the refused shadow without
        // restoring positives — over claims already unknown.
        driver.completion_source = Some(Box::new(StubCompletionSource(Some(
            SessionNativeCompletion::scripted(domain),
        ))));
        driver.on_tick();
        assert_eq!(
            driver.retiring_domain(),
            None,
            "the refused shadow retires instead of stranding"
        );
        let (lossy, unknown, state) = {
            let registry = driver.coordinator.registry();
            let edge = registry
                .instance_semantic_edges()
                .next()
                .expect("one admitted edge");
            (
                edge.lossy,
                edge.semantics
                    .as_ref()
                    .expect("reduced operation stands")
                    .unknown(),
                registry.instances().next().expect("one instance").state,
            )
        };
        assert!(
            lossy && unknown == 1 && state == InstanceLifecycle::Uncertain,
            "disposal never revives terminated claims: lossy={lossy} unknown={unknown} state={}",
            state.label()
        );
    }

    #[test]
    fn reclaim_without_handoff_records_no_take() {
        // The reclaim spy sits after the take: a stop with no held
        // handoff records nothing (mutant B — reclaim does nothing —
        // must be indistinguishable from this only when no handoff
        // exists; with one, the take must record).
        let mut coordinator = coordinator();
        let headless = headless_display();
        let mut driver = driver_with_display(&mut coordinator, headless.display);
        assert!(driver.pending_install.is_none(), "no handoff held");
        driver.on_stop_requested();
        assert_eq!(
            driver.reclaim_calls,
            Vec::<PromotionEnd>::new(),
            "no handoff means no take recorded"
        );
    }

    #[test]
    fn wind_down_io_threads_spy_records_the_polling_thread() {
        // The OQ-2 "same worker thread" check is only as good as
        // its spy: poll a gated cleanup twice on a worker thread
        // (the I/O is built inside, so nothing !Send crosses) and
        // prove the recorded ids are the worker's, not the test
        // thread's.
        use crate::inventory_semantics::LaneTestIo;
        let test_thread = std::thread::current().id();
        let (recorded, worker) = std::thread::scope(|scope| {
            scope
                .spawn(|| {
                    let (mut io, _gate) = WindDownIo::gated();
                    let mut sink = std::io::sink();
                    for _ in 0..2 {
                        let _ = io.poll_terminal_detach(&mut sink);
                    }
                    (io.threads.borrow().clone(), std::thread::current().id())
                })
                .join()
                .expect("the worker polls twice")
        });
        assert_ne!(worker, test_thread, "the worker is not the test thread");
        assert_eq!(
            recorded,
            vec![worker, worker],
            "the spy records the polling thread"
        );
    }

    #[test]
    fn wind_down_cancel_returns_promptly_and_retains_pending_cleanup() {
        let mut coordinator = coordinator();
        let headless = headless_display();
        let mut driver = driver_with_display(&mut coordinator, headless.display);
        let (io, gate) = WindDownIo::gated();
        let submits = Rc::clone(&io.submits);
        let polls = Rc::clone(&io.polls);
        let completes = Rc::clone(&io.completes);
        let threads = Rc::clone(&io.threads);
        driver.semantic = Some(wind_down_lane(io));
        let domain = install_promotion_for_wind_down(&mut driver);
        quiesce_domain_for_retire(&mut *driver.coordinator, domain);
        let start = Instant::now();
        driver.wind_down_installed_promotion(PromotionEnd::Cancelled);
        assert!(
            start.elapsed() < Duration::from_secs(1),
            "cancel returns within its tick budget: {:?}",
            start.elapsed()
        );
        assert_eq!(
            driver.display.as_ref().expect("display").promotion_state(),
            PromotionState::Ended(PromotionEnd::Cancelled)
        );
        assert_eq!(driver.retiring_domain(), Some(domain));
        {
            let winding = driver
                .retiring
                .as_ref()
                .expect("retiring")
                .winding
                .as_ref()
                .expect("the pending lane winds down in place");
            assert!(!winding.joint, "a legacy wind-down carries no finish");
            assert_eq!(
                winding.lane.as_ref().expect("lane").domain(),
                domain,
                "the same lane winds down"
            );
        }
        // B queues while A winds down: preparation must wait for A.
        queue_request(driver.display.as_mut().expect("display"));
        let (source, mint_polls, _) =
            CountingSource::scripted(Some(SessionNativeCompletion::scripted(domain)));
        driver.completion_source = Some(Box::new(source));
        for _ in 0..3 {
            let start = Instant::now();
            driver.on_tick();
            assert!(
                start.elapsed() < Duration::from_secs(1),
                "every pending tick returns within budget: {:?}",
                start.elapsed()
            );
        }
        assert!(
            gaps(&mut driver)
                .iter()
                .all(|(subject, _)| subject != "selected lane native cleanup failed"),
            "no failure gap while the cleanup pends: {:?}",
            gaps(&mut driver)
        );
        assert_eq!(
            mint_polls.load(Ordering::SeqCst),
            0,
            "no mint while the detach pends"
        );
        assert_eq!(
            driver.retiring_domain(),
            Some(domain),
            "no retire while the detach pends"
        );
        assert_eq!(
            driver.display.as_ref().expect("display").promotion_state(),
            PromotionState::Queued,
            "B waits while A winds down"
        );
        assert!(
            driver.lifecycle.is_idle(),
            "B prepares nothing while A winds down"
        );
        assert!(
            driver.semantic.is_none(),
            "B installs nothing while A winds down"
        );
        assert_eq!(submits.get(), 1, "the cleanup submits once");
        assert!(polls.get() >= 3, "every tick reaps without joining");
        {
            // The reaps run on the tick thread with no hop; the
            // spy itself is proved faithful on a worker thread by
            // `wind_down_io_threads_spy_records_the_polling_thread`.
            // Running full ticks on a worker thread needs the
            // driver (Rc spies, `Box<dyn LaneTestIo>`) to turn
            // Send — refused as fixture churn for this minor
            // (R1.4 minor ruling).
            let threads = threads.borrow();
            assert!(
                threads.len() >= 3 && threads.iter().all(|id| *id == threads[0]),
                "the same worker thread reaps every poll"
            );
            assert_eq!(
                threads[0],
                std::thread::current().id(),
                "the reaps run on the tick thread"
            );
        }
        release_gate(&gate);
        driver.on_tick();
        assert_eq!(completes.get(), 1, "one joined receipt");
        assert_eq!(driver.retiring_domain(), None, "one retire after the join");
        // The retired domain refuses through the audited path.
        driver.coordinator.stage_semantic_batch(
            crate::inventory_semantics::SemanticBatch::scripted(domain, Vec::new(), 9),
        );
        assert!(
            gaps(&mut driver)
                .iter()
                .any(|(subject, _)| subject == "semantic batch refused for an ended domain"),
            "the retired domain stays refused: {:?}",
            gaps(&mut driver)
        );
        // B's request is processed only after A retires (refused: the
        // bare coordinator holds no manifest permission; installing B
        // needs native preparation, which the privileged loop covers).
        assert_eq!(
            driver.display.as_ref().expect("display").promotion_state(),
            PromotionState::Refused(PromotionRefusal::ProviderUnloaded),
            "B is taken once A retired"
        );
        assert!(
            gaps(&mut driver)
                .iter()
                .any(|(subject, _)| subject == "selected promotion refused"),
            "B's refusal records honestly: {:?}",
            gaps(&mut driver)
        );
    }

    #[test]
    fn wind_down_real_cleanup_stays_pending_without_failure_gap() {
        // Sustained pending cleanup: many ticks hold without a gap,
        // then the release joins and retires exactly once.
        {
            let mut coordinator = coordinator();
            let headless = headless_display();
            let mut driver = driver_with_display(&mut coordinator, headless.display);
            let (io, gate) = WindDownIo::gated();
            let submits = Rc::clone(&io.submits);
            let polls = Rc::clone(&io.polls);
            let completes = Rc::clone(&io.completes);
            driver.semantic = Some(wind_down_lane(io));
            let domain = install_promotion_for_wind_down(&mut driver);
            quiesce_domain_for_retire(&mut *driver.coordinator, domain);
            driver.wind_down_installed_promotion(PromotionEnd::Cancelled);
            let (source, mint_polls, _) =
                CountingSource::scripted(Some(SessionNativeCompletion::scripted(domain)));
            driver.completion_source = Some(Box::new(source));
            for _ in 0..10 {
                let start = Instant::now();
                driver.on_tick();
                assert!(
                    start.elapsed() < Duration::from_secs(1),
                    "every pending tick returns within budget: {:?}",
                    start.elapsed()
                );
            }
            assert_eq!(
                driver.retiring_domain(),
                Some(domain),
                "the cleanup stays pending"
            );
            assert_eq!(
                mint_polls.load(Ordering::SeqCst),
                0,
                "no mint while pending"
            );
            assert_eq!(submits.get(), 1, "one submit across sustained polls");
            assert_eq!(polls.get(), 10, "every tick reaps");
            assert!(
                gaps(&mut driver)
                    .iter()
                    .all(|(subject, _)| subject != "selected lane native cleanup failed"),
                "no failure gap across sustained pending: {:?}",
                gaps(&mut driver)
            );
            release_gate(&gate);
            driver.on_tick();
            assert_eq!(completes.get(), 1, "one joined receipt");
            assert_eq!(driver.retiring_domain(), None, "one retire after the join");
        }
        // Genuine-Err twin: a truly failed detach reports one gap,
        // stays Unproved with its owner kept, and still retires the
        // namespace through the legacy downstream.
        let mut coordinator = coordinator();
        let headless = headless_display();
        let mut driver = driver_with_display(&mut coordinator, headless.display);
        let mut io = WindDownIo::completing();
        io.fail_poll = true;
        let polls = Rc::clone(&io.polls);
        let drops = Rc::new(Cell::new(0));
        io.drop_spy = Some(Rc::clone(&drops));
        driver.semantic = Some(wind_down_lane(io));
        let domain = install_promotion_for_wind_down(&mut driver);
        quiesce_domain_for_retire(&mut *driver.coordinator, domain);
        driver.wind_down_installed_promotion(PromotionEnd::Cancelled);
        let (source, _, _) =
            CountingSource::scripted(Some(SessionNativeCompletion::scripted(domain)));
        driver.completion_source = Some(Box::new(source));
        driver.on_tick();
        let failures: Vec<(String, String)> = gaps(&mut driver)
            .into_iter()
            .filter(|(subject, _)| subject == "selected lane native cleanup failed")
            .collect();
        assert_eq!(
            failures.len(),
            1,
            "exactly one failure gap: {:?}",
            gaps(&mut driver)
        );
        assert!(
            failures[0].1.contains("Unproved"),
            "the gap carries the detach error text: {:?}",
            failures[0].1
        );
        assert_eq!(polls.get(), 1, "a failed detach is never re-polled");
        assert_eq!(drops.get(), 0, "the failed owner is kept, never dropped");
        assert_eq!(
            driver.retiring_domain(),
            None,
            "the namespace still retires through the legacy downstream"
        );
        driver.coordinator.stage_semantic_batch(
            crate::inventory_semantics::SemanticBatch::scripted(domain, Vec::new(), 9),
        );
        assert!(
            gaps(&mut driver)
                .iter()
                .any(|(subject, _)| subject == "semantic batch refused for an ended domain"),
            "the retired domain stays refused: {:?}",
            gaps(&mut driver)
        );
    }

    #[test]
    fn joint_stop_latches_without_blocking_terminal_sequence() {
        let mut coordinator = coordinator();
        let headless = headless_display();
        let mut driver = driver_with_display(&mut coordinator, headless.display);
        let mut io = WindDownIo::completing();
        io.quiescent = false;
        let drops = Rc::new(Cell::new(0));
        io.drop_spy = Some(Rc::clone(&drops));
        driver.semantic = Some(joint_lane(io, false));
        let (source, mint_polls, _) = CountingSource::scripted(None);
        driver.completion_source = Some(Box::new(source));
        let start = Instant::now();
        driver.on_stop_requested();
        let elapsed = start.elapsed();
        assert!(
            elapsed < Duration::from_millis(50),
            "the Joint stop latches without blocking: {elapsed:?}"
        );
        assert_eq!(
            driver.terminal_seq_calls, 0,
            "the blocking terminal sequence never runs for Joint lanes"
        );
        assert_eq!(driver.joint_begin_calls, 1, "the finish begins once");
        assert_eq!(
            driver.joint_finish,
            JointFinishDriver::Abandoned,
            "a begin refusal abandons through the finite stop"
        );
        assert!(driver.semantic.is_none(), "the abandoned lane is held");
        assert_eq!(drops.get(), 0, "held means never dropped");
        assert_eq!(
            driver.joint_first_error.as_deref(),
            Some("joint finish disposition required"),
            "the first error is kept"
        );
        assert!(
            gaps(&mut driver)
                .iter()
                .any(|(subject, _)| subject == "joint finish abandoned for exit"),
            "the abandon records honestly: {:?}",
            gaps(&mut driver)
        );
        assert_eq!(
            mint_polls.load(Ordering::SeqCst),
            0,
            "no mint on the finite stop"
        );
        // A second stop never re-begins.
        driver.on_stop_requested();
        assert_eq!(driver.joint_begin_calls, 1, "the finish begins once");
        assert_eq!(driver.joint_finish, JointFinishDriver::Abandoned);
    }

    #[test]
    fn joint_lane_stopped_polls_finish_then_wound_down() {
        // Begin-once through the post-retirement hook.
        {
            let mut coordinator = coordinator();
            let headless = headless_display();
            let mut driver = driver_with_display(&mut coordinator, headless.display);
            driver.semantic = Some(joint_lane(WindDownIo::completing(), true));
            driver.on_lane_stopped();
            assert_eq!(driver.joint_begin_calls, 1, "the hook begins once");
            assert_eq!(
                driver.joint_finish,
                JointFinishDriver::Published,
                "a finished lane resumes at the wound-down phase"
            );
            driver.on_lane_stopped();
            assert_eq!(driver.joint_begin_calls, 1, "a second hook never re-begins");
        }
        // Polling polls the finish: the attempt latches, the state stays.
        {
            let mut coordinator = coordinator();
            let headless = headless_display();
            let mut driver = driver_with_display(&mut coordinator, headless.display);
            driver.semantic = Some(joint_lane(WindDownIo::completing(), false));
            driver.joint_finish = JointFinishDriver::Polling;
            driver.on_lane_stopped();
            assert_eq!(
                driver.joint_finish,
                JointFinishDriver::Polling,
                "one poll stays polling"
            );
            assert!(
                driver
                    .semantic
                    .as_ref()
                    .expect("lane")
                    .joint_finish_disposition_required(),
                "the step polled the finish"
            );
        }
        // Published polls only the wound-down: the detach reaps.
        {
            let mut coordinator = coordinator();
            let headless = headless_display();
            let mut driver = driver_with_display(&mut coordinator, headless.display);
            let (io, gate) = WindDownIo::gated();
            let polls = Rc::clone(&io.polls);
            driver.semantic = Some(joint_lane(io, true));
            driver.joint_finish = JointFinishDriver::Published;
            driver.on_lane_stopped();
            assert_eq!(
                driver.joint_finish,
                JointFinishDriver::Published,
                "a pending detach stays published"
            );
            assert_eq!(polls.get(), 1, "the step reaped the detach");
            assert_eq!(driver.joint_step_calls, 1, "the hook stepped once");
            // The joined detach completes the final lane.
            release_gate(&gate);
            // The seal drains before the completion, as in production.
            driver
                .semantic
                .as_mut()
                .expect("lane")
                .set_test_joint_frame(false);
            driver.on_lane_stopped();
            assert!(driver.semantic.is_none(), "the wound-down lane completes");
        }
        // Published implies finished: an unfinished lane fails closed
        // through the wound-down poll (a finish poll would have
        // latched and stayed, so the divergence proves which poll ran).
        {
            let mut coordinator = coordinator();
            let headless = headless_display();
            let mut driver = driver_with_display(&mut coordinator, headless.display);
            let mut io = WindDownIo::completing();
            let drops = Rc::new(Cell::new(0));
            io.drop_spy = Some(Rc::clone(&drops));
            driver.semantic = Some(joint_lane(io, false));
            driver.joint_finish = JointFinishDriver::Published;
            driver.on_lane_stopped();
            assert_eq!(
                driver.joint_finish,
                JointFinishDriver::Abandoned,
                "an unfinished Published lane abandons through the wound-down poll"
            );
            assert!(driver.semantic.is_none(), "the lane is held");
            assert_eq!(drops.get(), 0, "held means never dropped");
            assert!(
                driver.joint_first_error.is_some(),
                "the first error is kept"
            );
        }
    }

    #[test]
    fn joint_driver_after_published_polls_only_wound_down() {
        let mut coordinator = coordinator();
        let headless = headless_display();
        let mut driver = driver_with_display(&mut coordinator, headless.display);
        let (io, gate) = WindDownIo::gated();
        let polls = Rc::clone(&io.polls);
        driver.semantic = Some(joint_lane(io, true));
        driver.joint_finish = JointFinishDriver::Published;
        queue_request(driver.display.as_mut().expect("display"));
        let ticks_before = driver.display.as_ref().expect("display").account().ticks;
        for _ in 0..8 {
            driver.on_tick();
        }
        assert_eq!(
            driver.joint_finish,
            JointFinishDriver::Published,
            "a pending detach never triggers the finite stop"
        );
        assert_eq!(polls.get(), 8, "every hook reaped the detach");
        assert_eq!(driver.joint_step_calls, 8, "every hook stepped once");
        assert_eq!(
            driver.display.as_ref().expect("display").account().ticks,
            ticks_before + 8,
            "every hook still ticked the display"
        );
        assert_eq!(
            driver.display.as_ref().expect("display").promotion_state(),
            PromotionState::Queued,
            "no hook took promotion work"
        );
        assert!(
            driver.lifecycle.is_idle(),
            "the finite stop never triggered"
        );
        assert_eq!(
            driver
                .semantic
                .as_ref()
                .expect("lane")
                .finish_poll_calls_for_test(),
            0,
            "5a: no hook polled the finish past Published"
        );
        release_gate(&gate);
        // The seal drains before the completion, as in production.
        driver
            .semantic
            .as_mut()
            .expect("lane")
            .set_test_joint_frame(false);
        driver.on_tick();
        assert!(
            driver.semantic.is_none(),
            "the joined detach completes the lane"
        );
    }

    #[test]
    fn joint_driver_disposition_required_triggers_finite_stop() {
        use crate::inventory_semantics::SemanticRefusal;
        for reason in [
            SemanticRefusal::Unavailable,
            SemanticRefusal::ProviderStorage,
        ] {
            // The Q-mismatch twin latches Unavailable, the
            // storage-bound twin ProviderStorage; both abandon.
            let mut coordinator = coordinator();
            let headless = headless_display();
            let mut driver = driver_with_display(&mut coordinator, headless.display);
            let mut io = WindDownIo::completing();
            let drops = Rc::new(Cell::new(0));
            io.drop_spy = Some(Rc::clone(&drops));
            let mut lane = joint_lane(io, false);
            lane.note_joint_finish_failure(reason);
            driver.semantic = Some(lane);
            driver.joint_finish = JointFinishDriver::Polling;
            let (source, mint_polls, _) = CountingSource::scripted(None);
            driver.completion_source = Some(Box::new(source));
            driver.on_tick();
            assert_eq!(
                driver.joint_finish,
                JointFinishDriver::Abandoned,
                "a dispositioned Polling abandons: {reason:?}"
            );
            assert!(driver.semantic.is_none(), "the lane is held: {reason:?}");
            assert_eq!(drops.get(), 0, "held means never dropped: {reason:?}");
            assert!(
                driver.joint_first_error.is_some(),
                "the first error is kept: {reason:?}"
            );
            assert_eq!(
                mint_polls.load(Ordering::SeqCst),
                0,
                "no mint on abandon: {reason:?}"
            );
            assert!(
                gaps(&mut driver)
                    .iter()
                    .any(|(subject, _)| subject == "joint finish abandoned for exit"),
                "the abandon records honestly ({reason:?}): {:?}",
                gaps(&mut driver)
            );
        }
    }

    #[test]
    fn joint_begin_ok_reaches_polling_without_latch() {
        // The begin-Ok arm runs unprivileged through the scripted
        // begin: a begun finish polls, latches nothing and keeps
        // its lane. A begin that never reaches Polling fails here.
        let mut coordinator = coordinator();
        let headless = headless_display();
        let mut driver = driver_with_display(&mut coordinator, headless.display);
        let mut lane = joint_lane(WindDownIo::completing(), false);
        lane.set_scripted_finish_begin_for_test(Some(Ok(())));
        driver.semantic = Some(lane);
        driver.on_stop_requested();
        assert_eq!(driver.joint_begin_calls, 1, "the finish begins once");
        assert_eq!(
            driver.joint_finish,
            JointFinishDriver::Polling,
            "begin Ok reaches Polling"
        );
        assert!(driver.semantic.is_some(), "the begun lane is kept");
        assert!(
            !driver
                .semantic
                .as_ref()
                .expect("lane")
                .joint_finish_disposition_required(),
            "begin Ok latches nothing"
        );
    }

    #[test]
    fn joint_poll_published_reaches_published_and_counts_once() {
        // The Polling-to-Published arm runs unprivileged through the
        // scripted poll: one poll publishes, and the lane counts
        // exactly that call. A poll that never publishes fails here.
        use crate::discovery::engine::inventory_coordinator::BatchReceipt;
        let mut coordinator = coordinator();
        let headless = headless_display();
        let mut driver = driver_with_display(&mut coordinator, headless.display);
        let mut lane = joint_lane(WindDownIo::completing(), false);
        lane.set_scripted_finish_poll_for_test(Some(Ok(JointCommitProgress::Published(
            BatchReceipt {
                engine_facts: 0,
                engine_published: 0,
                registry_facts: 0,
                registry_published: 0,
                registry_applied: 0,
            },
        ))));
        driver.semantic = Some(lane);
        driver.joint_finish = JointFinishDriver::Polling;
        driver.on_tick();
        assert_eq!(
            driver.joint_finish,
            JointFinishDriver::Published,
            "poll Published reaches Published"
        );
        assert_eq!(
            driver
                .semantic
                .as_ref()
                .expect("lane")
                .finish_poll_calls_for_test(),
            1,
            "the poll ran once through the lane"
        );
    }

    #[test]
    fn settle_joint_finish_completes_multi_poll_finish() {
        // man-1 Cause 2: a begun finish needing two polls (Pending
        // then Published, the live shape) must reach Published: the
        // classic stop path runs no post-loop hooks, so the
        // pre-retirement settle drives every step itself.
        use crate::discovery::engine::inventory_coordinator::BatchReceipt;
        let mut coordinator = coordinator();
        let headless = headless_display();
        let mut driver = driver_with_display(&mut coordinator, headless.display);
        let mut lane = joint_lane(WindDownIo::completing(), false);
        lane.set_scripted_finish_poll_queue_for_test(vec![
            Ok(JointCommitProgress::Pending),
            Ok(JointCommitProgress::Published(BatchReceipt {
                engine_facts: 0,
                engine_published: 0,
                registry_facts: 0,
                registry_published: 0,
                registry_applied: 0,
            })),
        ]);
        driver.semantic = Some(lane);
        driver.joint_finish = JointFinishDriver::Polling;
        driver.settle_joint_finish();
        assert_eq!(
            driver.joint_finish,
            JointFinishDriver::Published,
            "the settle drives every scripted poll to Published"
        );
        assert_eq!(
            driver
                .semantic
                .as_ref()
                .expect("lane")
                .finish_poll_calls_for_test(),
            2,
            "both polls ran through the lane"
        );
    }

    #[test]
    fn settle_joint_finish_single_poll_completes() {
        // Healthy twin: a finish that publishes on its first poll
        // settles in one step, like the post-retirement hook.
        use crate::discovery::engine::inventory_coordinator::BatchReceipt;
        let mut coordinator = coordinator();
        let headless = headless_display();
        let mut driver = driver_with_display(&mut coordinator, headless.display);
        let mut lane = joint_lane(WindDownIo::completing(), false);
        lane.set_scripted_finish_poll_for_test(Some(Ok(JointCommitProgress::Published(
            BatchReceipt {
                engine_facts: 0,
                engine_published: 0,
                registry_facts: 0,
                registry_published: 0,
                registry_applied: 0,
            },
        ))));
        driver.semantic = Some(lane);
        driver.joint_finish = JointFinishDriver::Polling;
        driver.settle_joint_finish();
        assert_eq!(
            driver.joint_finish,
            JointFinishDriver::Published,
            "one poll publishes"
        );
        assert_eq!(
            driver
                .semantic
                .as_ref()
                .expect("lane")
                .finish_poll_calls_for_test(),
            1,
            "the poll ran once through the lane"
        );
    }

    #[test]
    fn settle_joint_finish_escalates_on_second_signal() {
        // Healthy twin: a second operator signal holds the begun
        // finish for exit instead of stepping it: the run is leaving.
        let mut coordinator = coordinator();
        let headless = headless_display();
        let mut driver = driver_with_display(&mut coordinator, headless.display);
        let mut lane = joint_lane(WindDownIo::completing(), false);
        lane.set_scripted_finish_poll_for_test(Some(Ok(JointCommitProgress::Pending)));
        driver.semantic = Some(lane);
        driver.joint_finish = JointFinishDriver::Polling;
        driver.second_signal = Some(&|| true);
        driver.settle_joint_finish();
        assert_eq!(
            driver.joint_finish,
            JointFinishDriver::Abandoned,
            "the second signal holds the finish for exit"
        );
        assert!(driver.semantic.is_none(), "the held lane leaves the driver");
    }

    #[test]
    fn settle_joint_finish_ignores_unbegun_and_legacyless() {
        // Healthy twin: unbegun finishes and drivers without a Joint
        // lane are untouched; the post-retirement hook owns those.
        {
            let mut coordinator = coordinator();
            let headless = headless_display();
            let mut driver = driver_with_display(&mut coordinator, headless.display);
            driver.semantic = Some(joint_lane(WindDownIo::completing(), false));
            driver.joint_finish = JointFinishDriver::NotBegun;
            driver.settle_joint_finish();
            assert_eq!(
                driver.joint_finish,
                JointFinishDriver::NotBegun,
                "an unbegun finish stays unbegun"
            );
            assert_eq!(
                driver.joint_step_calls, 0,
                "nothing steps an unbegun finish"
            );
        }
        {
            let mut coordinator = coordinator();
            let headless = headless_display();
            let mut driver = driver_with_display(&mut coordinator, headless.display);
            driver.semantic = None;
            driver.joint_finish = JointFinishDriver::Polling;
            driver.settle_joint_finish();
            assert_eq!(
                driver.joint_finish,
                JointFinishDriver::Polling,
                "no lane means no finish to settle"
            );
            assert_eq!(driver.joint_step_calls, 0, "nothing steps without a lane");
        }
    }

    #[test]
    fn scan_stop_settles_begun_joint_finish() {
        // The scan-fallback (lane == None) post-loop path must drive a
        // begun Joint finish exactly like the native-lane path: the
        // stop begins it (Polling), the settle drains every poll, and
        // the terminal consume reaps a Published lane instead of
        // stranding a Polling one.
        use crate::discovery::engine::inventory_coordinator::BatchReceipt;
        let mut coordinator = coordinator();
        let headless = headless_display();
        let mut driver = driver_with_display(&mut coordinator, headless.display);
        let mut lane = joint_lane(WindDownIo::completing(), false);
        lane.set_scripted_finish_begin_for_test(Some(Ok(())));
        lane.set_scripted_finish_poll_queue_for_test(vec![
            Ok(JointCommitProgress::Pending),
            Ok(JointCommitProgress::Published(BatchReceipt {
                engine_facts: 0,
                engine_published: 0,
                registry_facts: 0,
                registry_published: 0,
                registry_applied: 0,
            })),
        ]);
        driver.semantic = Some(lane);
        let outcome = super::tests::retain_with_cause(
            &mut driver,
            crate::inventory_capture::ZeroPassCause::OperatorStop,
            None,
        );
        assert!(outcome.retained.is_none(), "the stopped scan run finalizes");
        assert!(outcome.error.is_none(), "the stop carries no error");
        assert!(outcome.zero_pass.is_some(), "a zero-pass stop is reported");
        assert_eq!(
            driver.joint_finish,
            JointFinishDriver::Published,
            "the scan path settles the begun finish"
        );
        assert_eq!(
            driver
                .semantic
                .as_ref()
                .expect("lane")
                .finish_poll_calls_for_test(),
            2,
            "both polls ran through the lane"
        );
    }

    #[test]
    fn scan_stop_settle_escalation_publishes_held_gap() {
        // Scan-path twin: a second operator signal during the settle
        // holds the begun finish for exit, and the held gap publishes
        // with the stop instead of stranding a Polling finish.
        let mut coordinator = coordinator();
        let headless = headless_display();
        let mut driver = driver_with_display(&mut coordinator, headless.display);
        let mut lane = joint_lane(WindDownIo::completing(), false);
        lane.set_scripted_finish_begin_for_test(Some(Ok(())));
        lane.set_scripted_finish_poll_for_test(Some(Ok(JointCommitProgress::Pending)));
        driver.semantic = Some(lane);
        driver.second_signal = Some(&|| true);
        let outcome = super::tests::retain_with_cause(
            &mut driver,
            crate::inventory_capture::ZeroPassCause::OperatorStop,
            None,
        );
        assert!(outcome.retained.is_none(), "the stopped scan run finalizes");
        assert_eq!(
            driver.joint_finish,
            JointFinishDriver::Abandoned,
            "the second signal holds the scan-path finish"
        );
        assert!(driver.semantic.is_none(), "the held lane leaves the driver");
        let held = committed_gaps_by_subject(&mut driver, "joint finish held for exit");
        assert_eq!(held.len(), 1, "the held gap publishes with the stop");
        assert_eq!(
            held[0].1, "second stop during joint finish",
            "the gap names the escalation"
        );
    }

    #[test]
    fn settle_joint_finish_bound_abandons_never_latching_finish() {
        // A begun finish whose polls never latch (sticky Pending, no
        // disposition) still ends within an explicit wall bound: at
        // the bound it abandons with its own settle-bound gap (total
        // time, never "without progress": the settle measures no
        // progress) and its own held cause (never "second stop": no
        // second signal happened). The short test bound stands in
        // for the production settle backstop.
        let mut coordinator = coordinator();
        let headless = headless_display();
        let mut driver = driver_with_display(&mut coordinator, headless.display);
        let mut lane = joint_lane(WindDownIo::completing(), false);
        lane.set_scripted_finish_poll_for_test(Some(Ok(JointCommitProgress::Pending)));
        driver.semantic = Some(lane);
        driver.joint_finish = JointFinishDriver::Polling;
        let started = Instant::now();
        driver.settle_joint_finish_with_bound(Duration::from_millis(120));
        assert!(
            started.elapsed() < Duration::from_secs(5),
            "the settle ends within the bound"
        );
        assert_eq!(
            driver.joint_finish,
            JointFinishDriver::Abandoned,
            "the bound abandons a never-latching finish"
        );
        assert!(driver.semantic.is_none(), "the held lane leaves the driver");
        assert_eq!(
            driver.joint_first_error.as_deref(),
            Some("joint finish settle bound reached"),
            "the bound keeps its own cause, not a second stop"
        );
        driver.commit(false).expect("the stop commit runs");
        let stalled = committed_gaps_by_subject(&mut driver, "joint finish settle bound reached");
        assert_eq!(stalled.len(), 1, "the bound discloses the wedge");
        assert!(
            stalled[0].1.contains("did not complete within")
                && stalled[0]
                    .1
                    .contains("settle polls; abandoning the finish for exit"),
            "the gap words total time, never progress it never measured: {:?}",
            stalled[0].1
        );
        let held = committed_gaps_by_subject(&mut driver, "joint finish held for exit");
        assert_eq!(held.len(), 1, "the escalation discloses the hold");
        assert_eq!(
            held[0].1, "joint finish settle bound reached",
            "the held gap names the bound cause, not a second stop"
        );
        let machine_trips = committed_gaps_by_subject(&mut driver, "joint finish made no progress");
        assert!(
            machine_trips.is_empty(),
            "the settle never borrows the machine trip's gap: {:?}",
            machine_trips
        );
    }

    #[test]
    fn settle_joint_finish_latch_mid_settle_abandons() {
        // A finish that latches mid-settle (Pending, then a refused
        // poll) ends Abandoned with the lane held and the first error
        // kept: the next step observes the latch and abandons.
        let mut coordinator = coordinator();
        let headless = headless_display();
        let mut driver = driver_with_display(&mut coordinator, headless.display);
        let mut lane = joint_lane(WindDownIo::completing(), false);
        lane.set_scripted_finish_poll_queue_for_test(vec![
            Ok(JointCommitProgress::Pending),
            Err(crate::inventory_semantics::SemanticRefusal::Unavailable),
        ]);
        driver.semantic = Some(lane);
        driver.joint_finish = JointFinishDriver::Polling;
        driver.settle_joint_finish();
        assert_eq!(
            driver.joint_finish,
            JointFinishDriver::Abandoned,
            "the mid-settle latch abandons the finish"
        );
        assert!(driver.semantic.is_none(), "the held lane leaves the driver");
        assert_eq!(
            driver.joint_first_error.as_deref(),
            Some("joint finish disposition required"),
            "the first error is kept"
        );
        assert_eq!(
            driver.joint_step_calls, 3,
            "Pending, refusal, then the latch-observing step"
        );
    }

    /// Nonzero live-derived stop counts for the disclosure twins: the
    /// live-run shape (a burst collected, refresh scans refused),
    /// scripted because substituted lanes carry no live Session.
    /// Shed stays real and is noted per test.
    fn scripted_nonzero_stop_counts() -> crate::inventory_semantics::ScriptedStopCounts {
        use crate::attach::image_query::ImageQueryRefusal;
        let mut refusal_counts = [0u64; 12];
        for _ in 0..10 {
            crate::inventory_semantics::count_scan_refusals(
                &mut refusal_counts,
                &[ImageQueryRefusal::Unknown],
            );
        }
        for _ in 0..2 {
            crate::inventory_semantics::count_scan_refusals(
                &mut refusal_counts,
                &[ImageQueryRefusal::Custody],
            );
        }
        crate::inventory_semantics::ScriptedStopCounts {
            refusal_counts,
            collected_calls: 68,
            joined_calls: 5,
            scan_refusals: 12,
        }
    }

    /// The stop line the disclosure twins expect: scripted
    /// collected/joined/refused, real shed, no bound callers in the
    /// scene.
    fn expected_stop_line() -> String {
        crate::inventory_semantics::semantic_stop_line(68, 5, 7, 0, 12)
    }

    /// Committed gaps for one subject, read without publishing:
    /// proves what a commit already published (order against it).
    fn committed_gaps_by_subject(
        driver: &mut ClassicDriver<'_>,
        subject: &str,
    ) -> Vec<(String, String)> {
        driver
            .coordinator
            .registry()
            .gaps()
            .iter()
            .map(|gap| (gap.subject.clone(), gap.reason.clone()))
            .filter(|(candidate, _)| candidate == subject)
            .collect()
    }

    #[test]
    fn joint_stop_publish_discloses_before_final_commit() {
        use crate::discovery::engine::inventory_coordinator::BatchReceipt;
        // Isolate from lines other tests on this thread warned: the
        // recorder is thread-local and every read drains.
        take_warned_for_test();
        // A Joint stop that publishes ends with the same honest stop
        // disclosure as the legacy path: exactly one scan-refusal gap
        // plus exactly one call-count line with the lane's lifetime
        // counts, both before the final commit.
        let mut coordinator = coordinator();
        let headless = headless_display();
        let mut driver = driver_with_display(&mut coordinator, headless.display);
        let mut lane = joint_lane(WindDownIo::completing(), false);
        let counts = scripted_nonzero_stop_counts();
        lane.set_scripted_stop_counts_for_test(Some(counts));
        lane.note_shed_calls(7);
        lane.set_scripted_finish_begin_for_test(Some(Ok(())));
        lane.set_scripted_finish_poll_for_test(Some(Ok(JointCommitProgress::Published(
            BatchReceipt {
                engine_facts: 0,
                engine_published: 0,
                registry_facts: 0,
                registry_published: 0,
                registry_applied: 0,
            },
        ))));
        driver.semantic = Some(lane);
        driver.on_stop_requested();
        assert_eq!(
            driver.joint_finish,
            JointFinishDriver::Polling,
            "begin Ok reaches Polling"
        );
        assert!(
            take_warned_for_test().is_empty(),
            "no disclosure before the finish publishes"
        );
        driver.on_lane_stopped();
        assert_eq!(
            driver.joint_finish,
            JointFinishDriver::Published,
            "the poll publishes"
        );
        // Production marks the lane finished at publication; the
        // scripted poll only answers progress, so the scaffolding H0
        // stop runs here (its batch drops unstaged, as in joint_lane).
        let _ = driver
            .semantic
            .as_mut()
            .expect("lane")
            .finish_semantic_stop();
        // The seal drains before the completion, as in production: a
        // framed take stays not-ready and the lane never completes.
        driver
            .semantic
            .as_mut()
            .expect("lane")
            .set_test_joint_frame(false);
        driver.on_lane_stopped();
        assert!(driver.semantic.is_none(), "the wound-down lane completes");
        assert_eq!(
            take_warned_for_test(),
            vec![expected_stop_line()],
            "exactly one stop line, before the final commit"
        );
        // The final commit publishes the staged scan-refusal gap.
        driver
            .coordinator
            .commit_batch(false)
            .expect("the final commit runs");
        let scans = committed_gaps_by_subject(&mut driver, "semantic scan refused");
        assert_eq!(scans.len(), 1, "exactly one scan-refusal gap");
        assert_eq!(
            scans[0].1,
            crate::inventory_semantics::scan_refusals_gap_reason(&counts.refusal_counts)
                .expect("nonzero refusals name a reason"),
            "the gap carries the lane's per-reason counts"
        );
    }

    #[test]
    fn legacy_stop_disclosure_is_unchanged() {
        // Isolate from lines other tests on this thread warned: the
        // recorder is thread-local and every read drains.
        take_warned_for_test();
        // Healthy twin: the legacy stop keeps its one gap plus one
        // line with the lane's lifetime counts. Passes before and
        // after the shared-helper refactor.
        let mut coordinator = coordinator();
        let headless = headless_display();
        let mut driver = driver_with_display(&mut coordinator, headless.display);
        let mut lane = wind_down_lane(WindDownIo::completing());
        let counts = scripted_nonzero_stop_counts();
        lane.set_scripted_stop_counts_for_test(Some(counts));
        lane.note_shed_calls(7);
        driver.semantic = Some(lane);
        driver.on_stop_requested();
        driver.on_lane_stopped();
        assert_eq!(
            driver.terminal_seq_calls, 1,
            "the terminal sequence runs once; the safety-net hook discloses nothing further"
        );
        assert_eq!(
            take_warned_for_test(),
            vec![expected_stop_line()],
            "exactly one legacy stop line"
        );
        driver
            .coordinator
            .commit_batch(false)
            .expect("the final commit runs");
        let scans = committed_gaps_by_subject(&mut driver, "semantic scan refused");
        assert_eq!(scans.len(), 1, "exactly one legacy scan-refusal gap");
        assert_eq!(
            scans[0].1,
            crate::inventory_semantics::scan_refusals_gap_reason(&counts.refusal_counts)
                .expect("nonzero refusals name a reason"),
            "the gap carries the lane's per-reason counts"
        );
    }

    #[test]
    fn joint_stop_disposition_abandon_discloses_once() {
        use crate::inventory_semantics::SemanticRefusal;
        // Isolate from lines other tests on this thread warned: the
        // recorder is thread-local and every read drains.
        take_warned_for_test();
        // A disposition-required hold discloses exactly once, before
        // the abandon commit: both gaps are already committed when
        // the hold returns, with no further publish.
        let mut coordinator = coordinator();
        let headless = headless_display();
        let mut driver = driver_with_display(&mut coordinator, headless.display);
        let mut lane = joint_lane(WindDownIo::completing(), false);
        let counts = scripted_nonzero_stop_counts();
        lane.set_scripted_stop_counts_for_test(Some(counts));
        lane.note_shed_calls(7);
        lane.set_scripted_finish_begin_for_test(Some(Ok(())));
        driver.semantic = Some(lane);
        driver.on_stop_requested();
        assert_eq!(
            driver.joint_finish,
            JointFinishDriver::Polling,
            "begin Ok reaches Polling"
        );
        driver
            .semantic
            .as_mut()
            .expect("lane")
            .note_joint_finish_failure(SemanticRefusal::ProviderStorage);
        driver.on_lane_stopped();
        assert_eq!(
            driver.joint_finish,
            JointFinishDriver::Abandoned,
            "disposition holds through the finite stop"
        );
        assert!(driver.semantic.is_none(), "the lane is held");
        assert_eq!(
            committed_gaps_by_subject(&mut driver, "joint finish abandoned for exit").len(),
            1,
            "the abandon recorded once"
        );
        let scans = committed_gaps_by_subject(&mut driver, "semantic scan refused");
        assert_eq!(
            scans.len(),
            1,
            "the disclosure ran before the abandon commit published it"
        );
        assert_eq!(
            scans[0].1,
            crate::inventory_semantics::scan_refusals_gap_reason(&counts.refusal_counts)
                .expect("nonzero refusals name a reason"),
            "the gap carries the lane's per-reason counts"
        );
        assert_eq!(
            take_warned_for_test(),
            vec![expected_stop_line()],
            "exactly one stop line"
        );
        // A further hook reaps nothing further.
        driver.on_lane_stopped();
        assert!(
            take_warned_for_test().is_empty(),
            "the line printed once: a further hook warns nothing more"
        );
        assert_eq!(
            committed_gaps_by_subject(&mut driver, "semantic scan refused").len(),
            1,
            "the gap records once"
        );
    }

    #[test]
    fn joint_stop_wound_down_failure_discloses_once() {
        use crate::discovery::engine::inventory_coordinator::BatchReceipt;
        // Isolate from lines other tests on this thread warned: the
        // recorder is thread-local and every read drains.
        take_warned_for_test();
        // A Published finish whose detach fails holds with the same
        // one disclosure. The lane is finished, so no abandon batch
        // is admitted — but the counts are still disclosed.
        let mut coordinator = coordinator();
        let headless = headless_display();
        let mut driver = driver_with_display(&mut coordinator, headless.display);
        let mut io = WindDownIo::completing();
        io.fail_poll = true;
        let mut lane = joint_lane(io, false);
        let counts = scripted_nonzero_stop_counts();
        lane.set_scripted_stop_counts_for_test(Some(counts));
        lane.note_shed_calls(7);
        lane.set_scripted_finish_begin_for_test(Some(Ok(())));
        lane.set_scripted_finish_poll_for_test(Some(Ok(JointCommitProgress::Published(
            BatchReceipt {
                engine_facts: 0,
                engine_published: 0,
                registry_facts: 0,
                registry_published: 0,
                registry_applied: 0,
            },
        ))));
        driver.semantic = Some(lane);
        driver.on_stop_requested();
        assert_eq!(
            driver.joint_finish,
            JointFinishDriver::Polling,
            "begin Ok reaches Polling"
        );
        driver.on_lane_stopped();
        assert_eq!(
            driver.joint_finish,
            JointFinishDriver::Published,
            "the poll publishes"
        );
        let _ = driver
            .semantic
            .as_mut()
            .expect("lane")
            .finish_semantic_stop();
        driver.on_lane_stopped();
        assert_eq!(
            driver.joint_finish,
            JointFinishDriver::Abandoned,
            "the failed detach abandons"
        );
        assert!(driver.semantic.is_none(), "the lane is held");
        // No abandon commit runs here (a finished lane admits no
        // abandon batch), so both gaps stage until the final publish
        // — while the line already printed, before that commit.
        assert_eq!(
            take_warned_for_test(),
            vec![expected_stop_line()],
            "exactly one stop line, before the final commit"
        );
        let published = gaps(&mut driver);
        assert_eq!(
            published
                .iter()
                .filter(|(subject, _)| subject == "joint wound-down failed")
                .count(),
            1,
            "the wound-down failure records once"
        );
        assert!(
            published
                .iter()
                .all(|(subject, _)| subject != "joint finish abandoned for exit"),
            "a finished lane admits no abandon batch"
        );
        let scans: Vec<(String, String)> = published
            .into_iter()
            .filter(|(subject, _)| subject == "semantic scan refused")
            .collect();
        assert_eq!(scans.len(), 1, "the counts are still disclosed once");
        assert_eq!(
            scans[0].1,
            crate::inventory_semantics::scan_refusals_gap_reason(&counts.refusal_counts)
                .expect("nonzero refusals name a reason"),
            "the gap carries the lane's per-reason counts"
        );
        assert!(
            take_warned_for_test().is_empty(),
            "the publish warns nothing further"
        );
    }

    #[test]
    fn joint_second_stop_while_polling_abandons_once_and_discloses() {
        use crate::inventory_semantics::SemanticRefusal;
        // Isolate from lines other tests on this thread warned: the
        // recorder is thread-local and every read drains.
        take_warned_for_test();
        // Exit while a finish is Polling: the second stop escalates
        // to the typed exit — the abandon runs once and the stop
        // disclosure still prints. A repeat escalation is a no-op
        // (the lane is held; a second abandon would refuse per the
        // abandon contract).
        let mut coordinator = coordinator();
        let headless = headless_display();
        let mut driver = driver_with_display(&mut coordinator, headless.display);
        let mut lane = joint_lane(WindDownIo::completing(), false);
        let counts = scripted_nonzero_stop_counts();
        lane.set_scripted_stop_counts_for_test(Some(counts));
        lane.note_shed_calls(7);
        lane.set_scripted_finish_begin_for_test(Some(Ok(())));
        driver.semantic = Some(lane);
        driver.on_stop_requested();
        assert_eq!(
            driver.joint_finish,
            JointFinishDriver::Polling,
            "begin Ok reaches Polling"
        );
        // The disposition admits the abandon at the hold.
        driver
            .semantic
            .as_mut()
            .expect("lane")
            .note_joint_finish_failure(SemanticRefusal::ProviderStorage);
        assert!(
            take_warned_for_test().is_empty(),
            "no disclosure before the exit"
        );
        driver.on_stop_requested();
        assert_eq!(
            driver.joint_finish,
            JointFinishDriver::Abandoned,
            "the second stop escalates"
        );
        assert!(driver.semantic.is_none(), "the lane is held");
        assert_eq!(
            driver.joint_first_error.as_deref(),
            Some("joint finish disposition required"),
            "the first error is kept"
        );
        let abandons = committed_gaps_by_subject(&mut driver, "joint finish abandoned for exit");
        assert_eq!(abandons.len(), 1, "the abandon ran once");
        assert_eq!(
            abandons[0].1, "joint finish disposition required",
            "the abandon records its reason"
        );
        let scans = committed_gaps_by_subject(&mut driver, "semantic scan refused");
        assert_eq!(
            scans.len(),
            1,
            "the disclosure ran before the abandon commit published it"
        );
        assert_eq!(
            scans[0].1,
            crate::inventory_semantics::scan_refusals_gap_reason(&counts.refusal_counts)
                .expect("nonzero refusals name a reason"),
            "the gap carries the lane's per-reason counts"
        );
        assert_eq!(
            take_warned_for_test(),
            vec![expected_stop_line()],
            "the stop disclosure still prints"
        );
        driver.on_stop_requested();
        assert!(
            take_warned_for_test().is_empty(),
            "a repeat escalation warns nothing more"
        );
        assert_eq!(
            committed_gaps_by_subject(&mut driver, "semantic scan refused").len(),
            1,
            "a repeat escalation records nothing more"
        );
    }

    #[test]
    fn joint_stop_without_refusals_prints_line_without_gap() {
        use crate::discovery::engine::inventory_coordinator::BatchReceipt;
        // Isolate from lines other tests on this thread warned: the
        // recorder is thread-local and every read drains.
        take_warned_for_test();
        // Zero refusals on the Joint path: no gap, the line still
        // prints (match legacy).
        let mut coordinator = coordinator();
        let headless = headless_display();
        let mut driver = driver_with_display(&mut coordinator, headless.display);
        let mut lane = joint_lane(WindDownIo::completing(), false);
        lane.set_scripted_finish_begin_for_test(Some(Ok(())));
        lane.set_scripted_finish_poll_for_test(Some(Ok(JointCommitProgress::Published(
            BatchReceipt {
                engine_facts: 0,
                engine_published: 0,
                registry_facts: 0,
                registry_published: 0,
                registry_applied: 0,
            },
        ))));
        driver.semantic = Some(lane);
        driver.on_stop_requested();
        driver.on_lane_stopped();
        let _ = driver
            .semantic
            .as_mut()
            .expect("lane")
            .finish_semantic_stop();
        // The seal drains before the completion, as in production: a
        // framed take stays not-ready and the lane never completes.
        driver
            .semantic
            .as_mut()
            .expect("lane")
            .set_test_joint_frame(false);
        driver.on_lane_stopped();
        assert!(driver.semantic.is_none(), "the wound-down lane completes");
        assert_eq!(
            take_warned_for_test(),
            vec![crate::inventory_semantics::semantic_stop_line(
                0, 0, 0, 0, 0
            )],
            "the line still prints with zero counts"
        );
        driver
            .coordinator
            .commit_batch(false)
            .expect("the final commit runs");
        assert!(
            committed_gaps_by_subject(&mut driver, "semantic scan refused").is_empty(),
            "zero refusals record no gap"
        );
    }

    #[test]
    fn legacy_stop_without_refusals_prints_line_without_gap() {
        // Isolate from lines other tests on this thread warned: the
        // recorder is thread-local and every read drains.
        take_warned_for_test();
        // Zero refusals on the legacy path: no gap, the line still
        // prints. Passes before and after the refactor.
        let mut coordinator = coordinator();
        let headless = headless_display();
        let mut driver = driver_with_display(&mut coordinator, headless.display);
        driver.semantic = Some(wind_down_lane(WindDownIo::completing()));
        driver.on_stop_requested();
        driver.on_lane_stopped();
        assert_eq!(
            take_warned_for_test(),
            vec![crate::inventory_semantics::semantic_stop_line(
                0, 0, 0, 0, 0
            )],
            "the line still prints with zero counts"
        );
        driver
            .coordinator
            .commit_batch(false)
            .expect("the final commit runs");
        assert!(
            committed_gaps_by_subject(&mut driver, "semantic scan refused").is_empty(),
            "zero refusals record no gap"
        );
    }

    #[test]
    fn joint_winding_complete_discloses_once() {
        // Isolate from lines other tests on this thread warned: the
        // recorder is thread-local and every read drains.
        take_warned_for_test();
        // A Joint promotion wind-down that completes discloses the
        // lane once, like its hold twin: the finished lane's counts
        // are read before the take hands the session away.
        let mut coordinator = coordinator();
        let headless = headless_display();
        let mut driver = driver_with_display(&mut coordinator, headless.display);
        let mut lane = joint_lane(WindDownIo::completing(), true);
        let counts = scripted_nonzero_stop_counts();
        lane.set_scripted_stop_counts_for_test(Some(counts));
        lane.note_shed_calls(7);
        driver.semantic = Some(lane);
        install_promotion_for_wind_down(&mut driver);
        driver.wind_down_installed_promotion(PromotionEnd::Cancelled);
        assert!(
            take_warned_for_test().is_empty(),
            "no disclosure at wind-down start"
        );
        // The seal drains before the completion, as in production.
        driver
            .retiring
            .as_mut()
            .expect("retiring")
            .winding
            .as_mut()
            .expect("winding")
            .lane
            .as_mut()
            .expect("lane")
            .set_test_joint_frame(false);
        driver.on_tick();
        assert_eq!(
            take_warned_for_test(),
            vec![expected_stop_line()],
            "the completed winding discloses once"
        );
        driver
            .coordinator
            .commit_batch(false)
            .expect("a commit publishes the staged gap");
        let scans = committed_gaps_by_subject(&mut driver, "semantic scan refused");
        assert_eq!(scans.len(), 1, "exactly one scan-refusal gap");
        assert_eq!(
            scans[0].1,
            crate::inventory_semantics::scan_refusals_gap_reason(&counts.refusal_counts)
                .expect("nonzero refusals name a reason"),
            "the gap carries the lane's per-reason counts"
        );
        driver.on_tick();
        assert!(
            take_warned_for_test().is_empty(),
            "a further tick discloses nothing more"
        );
    }

    /// A shell lane over a scripted subset, without substituted I/O:
    /// no live session, so its stop counts are unreadable.
    fn shell_lane_for_wind_down() -> crate::inventory_semantics::AttestedSemanticLane {
        use crate::discovery::identity::PinnedObjectId;
        let slot = crate::plan::Slot {
            index: 0,
            descriptor_index: crate::kinds::function_id("C_SignInit").unwrap() + 1,
            object: PinnedObjectId(0),
            object_path: "/stub-provider.so".into(),
            file_offset: 0x1200,
            names: vec!["C_SignInit".into()],
            aliased: false,
            semantics: crate::kinds::descriptor("C_SignInit").unwrap(),
            semantic_authorized: true,
            semantic_ambiguous: false,
            fork_safe: true,
            module_ids: vec![crate::plan::ModuleId(0)],
        };
        let subset =
            crate::discovery::engine::inventory_coordinator::semantics::AttestedSubset::scripted(
                crate::plan::AttachPlan::from_slots(vec![slot]),
                crate::discovery::identity::PinnedObjects::empty(),
                std::collections::BTreeMap::from([(
                    PinnedObjectId(0),
                    std::collections::BTreeSet::from([0]),
                )]),
            );
        crate::inventory_semantics::AttestedSemanticLane::start(
            subset,
            &Scope::Pid(std::process::id()),
            crate::attach::BackendSelection::Auto,
        )
        .expect("shell lane starts")
    }

    /// Stop counts for the final lane twin, distinct from the
    /// winding lane's in every field.
    fn distinct_final_stop_counts() -> crate::inventory_semantics::ScriptedStopCounts {
        use crate::attach::image_query::ImageQueryRefusal;
        let mut refusal_counts = [0u64; 12];
        for _ in 0..3 {
            crate::inventory_semantics::count_scan_refusals(
                &mut refusal_counts,
                &[ImageQueryRefusal::Unknown],
            );
        }
        crate::inventory_semantics::ScriptedStopCounts {
            refusal_counts,
            collected_calls: 11,
            joined_calls: 3,
            scan_refusals: 5,
        }
    }

    /// The stop line the final-lane twin expects: its own scripted
    /// collected/joined/refused, its own real shed, no bound callers.
    fn expected_final_stop_line() -> String {
        crate::inventory_semantics::semantic_stop_line(11, 3, 4, 0, 5)
    }

    #[test]
    fn joint_stop_during_winding_discloses_once() {
        // Isolate from lines other tests on this thread warned: the
        // recorder is thread-local and every read drains.
        take_warned_for_test();
        // A stop while A's promotion finish still winds discloses A's
        // stop counts before the final commit: the drop hold stays
        // silent, so the stop path is the winding lane's only honest
        // disclosure.
        let mut coordinator = coordinator();
        let headless = headless_display();
        {
            let mut driver = driver_with_display(&mut coordinator, headless.display);
            let mut lane = joint_lane(WindDownIo::completing(), true);
            let counts = scripted_nonzero_stop_counts();
            lane.set_scripted_stop_counts_for_test(Some(counts));
            lane.note_shed_calls(7);
            driver.semantic = Some(lane);
            install_promotion_for_wind_down(&mut driver);
            driver.wind_down_installed_promotion(PromotionEnd::Cancelled);
            assert!(
                take_warned_for_test().is_empty(),
                "no disclosure at wind-down start"
            );
            driver.on_stop_requested();
            assert_eq!(
                take_warned_for_test(),
                vec![expected_stop_line()],
                "the stop discloses the winding lane once"
            );
            driver
                .coordinator
                .commit_batch(false)
                .expect("the final commit runs");
            let scans = committed_gaps_by_subject(&mut driver, "semantic scan refused");
            assert_eq!(scans.len(), 1, "exactly one scan-refusal gap");
            assert_eq!(
                scans[0].1,
                crate::inventory_semantics::scan_refusals_gap_reason(&counts.refusal_counts)
                    .expect("nonzero refusals name a reason"),
                "the gap carries the winding lane's per-reason counts"
            );
            // A further stop and the lane-stop hook disclose nothing
            // more; the driver drops below with the winding held.
            driver.on_stop_requested();
            driver.on_lane_stopped();
            assert!(
                take_warned_for_test().is_empty(),
                "the winding lane discloses exactly once"
            );
        }
        assert!(
            take_warned_for_test().is_empty(),
            "the drop hold stays silent"
        );
    }

    #[test]
    fn joint_stop_during_winding_reversed_order_discloses_once() {
        // Isolate from lines other tests on this thread warned: the
        // recorder is thread-local and every read drains.
        take_warned_for_test();
        // A bare lane stop before the stop request discloses the
        // winding lane; the later stop request must not disclose it
        // again: the stop disclosure stays once-only from any stop
        // path, in any order.
        let mut coordinator = coordinator();
        let headless = headless_display();
        {
            let mut driver = driver_with_display(&mut coordinator, headless.display);
            let mut lane = joint_lane(WindDownIo::completing(), true);
            let counts = scripted_nonzero_stop_counts();
            lane.set_scripted_stop_counts_for_test(Some(counts));
            lane.note_shed_calls(7);
            driver.semantic = Some(lane);
            install_promotion_for_wind_down(&mut driver);
            driver.wind_down_installed_promotion(PromotionEnd::Cancelled);
            assert!(
                take_warned_for_test().is_empty(),
                "no disclosure at wind-down start"
            );
            driver.on_lane_stopped();
            assert_eq!(
                take_warned_for_test(),
                vec![expected_stop_line()],
                "the bare lane stop discloses the winding lane once"
            );
            driver.on_stop_requested();
            assert!(
                take_warned_for_test().is_empty(),
                "the stop request discloses nothing more"
            );
            driver
                .coordinator
                .commit_batch(false)
                .expect("the final commit runs");
            let scans = committed_gaps_by_subject(&mut driver, "semantic scan refused");
            assert_eq!(scans.len(), 1, "exactly one scan-refusal gap");
            assert_eq!(
                scans[0].1,
                crate::inventory_semantics::scan_refusals_gap_reason(&counts.refusal_counts)
                    .expect("nonzero refusals name a reason"),
                "the gap carries the winding lane's per-reason counts"
            );
            let held = committed_gaps_by_subject(&mut driver, "promotion wind-down held for exit");
            assert_eq!(held.len(), 1, "the held-for-exit gap records once");
            // A further lane stop discloses nothing more; the driver
            // drops below with the winding held.
            driver.on_lane_stopped();
            assert!(
                take_warned_for_test().is_empty(),
                "the winding lane discloses exactly once"
            );
        }
        assert!(
            take_warned_for_test().is_empty(),
            "the drop hold stays silent"
        );
    }

    #[test]
    fn joint_stop_during_winding_tick_after_stop_discloses_once() {
        // Isolate from lines other tests on this thread warned: the
        // recorder is thread-local and every read drains.
        take_warned_for_test();
        // A tick after the stop still reaps the winding join, but the
        // join must not disclose the lane again: the stop already
        // did. Production never ticks past the stop; the disclosed
        // flag keeps even a stray tick silent.
        let mut coordinator = coordinator();
        let headless = headless_display();
        let mut driver = driver_with_display(&mut coordinator, headless.display);
        let mut lane = joint_lane(WindDownIo::completing(), true);
        let counts = scripted_nonzero_stop_counts();
        lane.set_scripted_stop_counts_for_test(Some(counts));
        lane.note_shed_calls(7);
        driver.semantic = Some(lane);
        install_promotion_for_wind_down(&mut driver);
        driver.wind_down_installed_promotion(PromotionEnd::Cancelled);
        assert!(
            take_warned_for_test().is_empty(),
            "no disclosure at wind-down start"
        );
        driver.on_stop_requested();
        assert_eq!(
            take_warned_for_test(),
            vec![expected_stop_line()],
            "the stop discloses the winding lane once"
        );
        // The seal drains before the completion, as in production.
        driver
            .retiring
            .as_mut()
            .expect("retiring")
            .winding
            .as_mut()
            .expect("winding")
            .lane
            .as_mut()
            .expect("lane")
            .set_test_joint_frame(false);
        driver.on_tick();
        assert!(
            take_warned_for_test().is_empty(),
            "the stray tick discloses nothing more for the stopped winding"
        );
        driver
            .coordinator
            .commit_batch(false)
            .expect("the final commit runs");
        let scans = committed_gaps_by_subject(&mut driver, "semantic scan refused");
        assert_eq!(scans.len(), 1, "exactly one scan-refusal gap");
        assert_eq!(
            scans[0].1,
            crate::inventory_semantics::scan_refusals_gap_reason(&counts.refusal_counts)
                .expect("nonzero refusals name a reason"),
            "the gap carries the winding lane's per-reason counts"
        );
        let held = committed_gaps_by_subject(&mut driver, "promotion wind-down held for exit");
        assert_eq!(held.len(), 1, "the held-for-exit gap records once");
    }

    #[test]
    fn joint_stop_during_winding_disposition_tick_after_stop_discloses_once() {
        use crate::inventory_semantics::SemanticRefusal;
        // Isolate from lines other tests on this thread warned: the
        // recorder is thread-local and every read drains.
        take_warned_for_test();
        // A disposition latched on the winding lane before the stop, then
        // a stray tick past the stop: the tick's exit hold must not
        // disclose the lane's counts again — the stop already did.
        // Production never ticks past the stop; the disclosed flag keeps
        // even a stray tick silent on the hold path too.
        let mut coordinator = coordinator();
        let headless = headless_display();
        let mut driver = driver_with_display(&mut coordinator, headless.display);
        let mut lane = joint_lane(WindDownIo::completing(), true);
        let counts = scripted_nonzero_stop_counts();
        lane.set_scripted_stop_counts_for_test(Some(counts));
        lane.note_shed_calls(7);
        lane.set_scripted_finish_begin_for_test(Some(Ok(())));
        driver.semantic = Some(lane);
        install_promotion_for_wind_down(&mut driver);
        driver.wind_down_installed_promotion(PromotionEnd::Cancelled);
        assert!(
            take_warned_for_test().is_empty(),
            "no disclosure at wind-down start"
        );
        assert_eq!(
            driver
                .retiring
                .as_ref()
                .expect("retiring")
                .winding
                .as_ref()
                .expect("winding")
                .finish,
            JointFinishDriver::Polling,
            "the scripted begin leaves the winding finish polling"
        );
        driver
            .retiring
            .as_mut()
            .expect("retiring")
            .winding
            .as_mut()
            .expect("winding")
            .lane
            .as_mut()
            .expect("lane")
            .note_joint_finish_failure(SemanticRefusal::ProviderStorage);
        driver.on_stop_requested();
        assert_eq!(
            take_warned_for_test(),
            vec![expected_stop_line()],
            "the stop discloses the winding lane once"
        );
        driver.on_tick();
        assert!(
            take_warned_for_test().is_empty(),
            "the stray tick discloses nothing more for the stopped winding"
        );
        assert_eq!(
            driver
                .retiring
                .as_ref()
                .expect("retiring")
                .winding
                .as_ref()
                .expect("winding")
                .finish,
            JointFinishDriver::Abandoned,
            "the stray tick holds the winding lane for exit"
        );
        assert!(
            driver
                .retiring
                .as_ref()
                .expect("retiring")
                .winding
                .as_ref()
                .expect("winding")
                .lane
                .is_none(),
            "the hold takes the winding lane"
        );
        driver
            .coordinator
            .commit_batch(false)
            .expect("the final commit runs");
        let scans = committed_gaps_by_subject(&mut driver, "semantic scan refused");
        assert_eq!(scans.len(), 1, "exactly one scan-refusal gap");
        assert_eq!(
            scans[0].1,
            crate::inventory_semantics::scan_refusals_gap_reason(&counts.refusal_counts)
                .expect("nonzero refusals name a reason"),
            "the gap carries the winding lane's per-reason counts"
        );
        let held = committed_gaps_by_subject(&mut driver, "promotion wind-down held for exit");
        assert_eq!(held.len(), 1, "the held-for-exit gap records once");
    }

    #[test]
    fn joint_stop_during_winding_after_join_discloses_nothing_more() {
        // Isolate from lines other tests on this thread warned: the
        // recorder is thread-local and every read drains.
        take_warned_for_test();
        // A winding that already handed its session off disclosed at
        // the join; a later stop must not print its counts again.
        // After the take the lane reads zeros, so a second line would
        // invent them.
        let mut coordinator = coordinator();
        let headless = headless_display();
        let mut driver = driver_with_display(&mut coordinator, headless.display);
        let mut lane = joint_lane(WindDownIo::completing(), true);
        let counts = scripted_nonzero_stop_counts();
        lane.set_scripted_stop_counts_for_test(Some(counts));
        lane.note_shed_calls(7);
        driver.semantic = Some(lane);
        install_promotion_for_wind_down(&mut driver);
        driver.wind_down_installed_promotion(PromotionEnd::Cancelled);
        // The seal drains before the completion, as in production.
        driver
            .retiring
            .as_mut()
            .expect("retiring")
            .winding
            .as_mut()
            .expect("winding")
            .lane
            .as_mut()
            .expect("lane")
            .set_test_joint_frame(false);
        driver.on_tick();
        assert_eq!(
            take_warned_for_test(),
            vec![expected_stop_line()],
            "the join discloses once"
        );
        driver.on_stop_requested();
        assert!(
            take_warned_for_test().is_empty(),
            "the stop discloses nothing more for a joined winding"
        );
        driver
            .coordinator
            .commit_batch(false)
            .expect("the final commit runs");
        let scans = committed_gaps_by_subject(&mut driver, "semantic scan refused");
        assert_eq!(scans.len(), 1, "still exactly one scan-refusal gap");
        assert_eq!(
            scans[0].1,
            crate::inventory_semantics::scan_refusals_gap_reason(&counts.refusal_counts)
                .expect("nonzero refusals name a reason"),
            "the gap still carries the join's per-reason counts"
        );
    }

    #[test]
    fn joint_stop_winding_and_final_lane_both_disclose_once() {
        use crate::inventory_semantics::SemanticRefusal;
        // Isolate from lines other tests on this thread warned: the
        // recorder is thread-local and every read drains.
        take_warned_for_test();
        // A stop with A's finish winding and B seated discloses both
        // lanes, each once with its own counts: A at the stop, B at
        // its exit hold.
        let mut coordinator = coordinator();
        let headless = headless_display();
        let mut driver = driver_with_display(&mut coordinator, headless.display);
        let mut lane_a = joint_lane(WindDownIo::completing(), true);
        let counts_a = scripted_nonzero_stop_counts();
        lane_a.set_scripted_stop_counts_for_test(Some(counts_a));
        lane_a.note_shed_calls(7);
        driver.semantic = Some(lane_a);
        install_promotion_for_wind_down(&mut driver);
        driver.wind_down_installed_promotion(PromotionEnd::Cancelled);
        let mut lane_b = joint_lane(WindDownIo::completing(), false);
        let counts_b = distinct_final_stop_counts();
        lane_b.set_scripted_stop_counts_for_test(Some(counts_b));
        lane_b.note_shed_calls(4);
        lane_b.set_scripted_finish_begin_for_test(Some(Ok(())));
        driver.semantic = Some(lane_b);
        assert!(
            take_warned_for_test().is_empty(),
            "no disclosure before the stop"
        );
        driver.on_stop_requested();
        assert_eq!(
            driver.joint_finish,
            JointFinishDriver::Polling,
            "the final lane begins at the stop"
        );
        assert_eq!(
            take_warned_for_test(),
            vec![expected_stop_line()],
            "the stop discloses the winding lane once"
        );
        // The disposition admits B's abandon at the exit hold.
        driver
            .semantic
            .as_mut()
            .expect("final lane")
            .note_joint_finish_failure(SemanticRefusal::ProviderStorage);
        driver.on_stop_requested();
        assert_eq!(
            driver.joint_finish,
            JointFinishDriver::Abandoned,
            "the second stop escalates the final lane"
        );
        assert!(driver.semantic.is_none(), "the final lane is held");
        assert_eq!(
            take_warned_for_test(),
            vec![expected_final_stop_line()],
            "the exit hold discloses the final lane once, with its own counts"
        );
        // Neither lane discloses twice.
        driver.on_lane_stopped();
        driver.on_stop_requested();
        assert!(
            take_warned_for_test().is_empty(),
            "neither lane discloses twice"
        );
        driver
            .coordinator
            .commit_batch(false)
            .expect("the final commit runs");
        let scans = committed_gaps_by_subject(&mut driver, "semantic scan refused");
        assert_eq!(scans.len(), 2, "one scan-refusal gap per lane");
        let mut reasons: Vec<String> = scans.into_iter().map(|(_, reason)| reason).collect();
        reasons.sort();
        let mut expected = vec![
            crate::inventory_semantics::scan_refusals_gap_reason(&counts_a.refusal_counts)
                .expect("A refused"),
            crate::inventory_semantics::scan_refusals_gap_reason(&counts_b.refusal_counts)
                .expect("B refused"),
        ];
        expected.sort();
        assert_eq!(
            reasons, expected,
            "each gap carries its own lane's per-reason counts"
        );
    }

    #[test]
    fn joint_stop_counts_once_gate_agrees_across_callers() {
        // Isolate from lines other tests on this thread warned: the
        // recorder is thread-local and every read drains.
        take_warned_for_test();
        // The stop path and the exit hold consult the one shared
        // once-gate: both stay silent past a disclosure, both disclose
        // exactly once when it is still owed, and the hold arms the
        // flag it discloses through.
        let scripted_lane = || {
            let mut lane = joint_lane(WindDownIo::completing(), false);
            lane.set_scripted_stop_counts_for_test(Some(scripted_nonzero_stop_counts()));
            lane.note_shed_calls(7);
            lane
        };
        let mut coordinator = coordinator();
        let mut display = None;
        let mut warn = WarnSink {
            display: &mut display,
        };
        // Already disclosed: both callers stay silent.
        let probe = scripted_lane();
        let counts = SemanticStopCounts::read(&probe, &mut coordinator);
        let mut winding = WindingLane {
            lane: None,
            finish: JointFinishDriver::NotBegun,
            joint: true,
            joined: false,
            stop_disclosed: true,
        };
        disclose_stop_counts_once(&mut winding, &counts, &mut coordinator, &mut warn);
        let mut held = true;
        let _ = ClassicDriver::hold_joint_lane_for_exit(
            scripted_lane(),
            &mut coordinator,
            "already disclosed",
            "joint finish abandoned for exit",
            &mut warn,
            Some(&mut held),
        );
        assert!(
            take_warned_for_test().is_empty(),
            "both callers stay silent past a disclosure"
        );
        assert!(held, "a silent hold leaves the armed flag armed");
        // Still owed: both callers disclose exactly once, and the
        // hold arms the flag so the next hold stays silent.
        winding.stop_disclosed = false;
        disclose_stop_counts_once(&mut winding, &counts, &mut coordinator, &mut warn);
        assert_eq!(
            take_warned_for_test(),
            vec![expected_stop_line()],
            "the stop path discloses the owed counts once"
        );
        let mut held = false;
        let _ = ClassicDriver::hold_joint_lane_for_exit(
            scripted_lane(),
            &mut coordinator,
            "owed",
            "joint finish abandoned for exit",
            &mut warn,
            Some(&mut held),
        );
        assert_eq!(
            take_warned_for_test(),
            vec![expected_stop_line()],
            "the exit hold discloses the owed counts once"
        );
        assert!(held, "the disclosing hold arms the flag");
        let _ = ClassicDriver::hold_joint_lane_for_exit(
            scripted_lane(),
            &mut coordinator,
            "owed",
            "joint finish abandoned for exit",
            &mut warn,
            Some(&mut held),
        );
        assert!(
            take_warned_for_test().is_empty(),
            "the armed hold stays silent"
        );
    }

    #[test]
    fn held_tripped_finish_names_wedge_on_stderr() {
        // Isolate from lines other tests on this thread warned: the
        // recorder is thread-local and every read drains.
        take_warned_for_test();
        // A lane whose finish tripped the no-progress bound names the
        // wedge on stderr when the exit hold takes it: the wedged
        // publication stands in front of the commit, so the staged gap
        // cannot commit, and the hold's warning is the user-visible
        // name. The untripped control discloses only its stop line.
        let scripted_lane = || {
            let mut lane = joint_lane(WindDownIo::completing(), false);
            lane.set_scripted_stop_counts_for_test(Some(scripted_nonzero_stop_counts()));
            lane.note_shed_calls(7);
            lane
        };
        let mut coordinator = coordinator();
        let mut display = None;
        let mut warn = WarnSink {
            display: &mut display,
        };
        // Clear the posed trip even if an assertion panics: the
        // override is thread-local and must not leak into the next
        // test on this thread.
        struct ClearPosedTrip;
        impl Drop for ClearPosedTrip {
            fn drop(&mut self) {
                crate::inventory_semantics::AttestedSemanticLane::pose_no_progress_trip_for_test(
                    None,
                );
            }
        }
        let _clear = ClearPosedTrip;
        // Substituted lanes carry no live machine to trip, so the
        // trip is posed (like the lane's `scripted_*` seams stage
        // machine behavior); the hold still reads it through the
        // production accessor.
        crate::inventory_semantics::AttestedSemanticLane::pose_no_progress_trip_for_test(Some((
            612,
            std::time::Duration::from_secs(6),
        )));
        let staged = scripted_lane()
            .joint_finish_no_progress_trip()
            .expect("the posed trip is observable");
        assert_eq!(staged.polls, 612, "the posed poll count is observable");
        assert_eq!(
            staged.stalled,
            std::time::Duration::from_secs(6),
            "the posed stall duration is observable"
        );
        let _ = ClassicDriver::hold_joint_lane_for_exit(
            scripted_lane(),
            &mut coordinator,
            "tripped",
            "joint finish abandoned for exit",
            &mut warn,
            None,
        );
        assert_eq!(
            take_warned_for_test(),
            vec![
                "joint finish made no progress for 6s across 612 polls; \
                 the lane is held for exit"
                    .to_string(),
                expected_stop_line(),
            ],
            "the hold names the wedge before the stop line"
        );
        crate::inventory_semantics::AttestedSemanticLane::pose_no_progress_trip_for_test(None);
        assert_eq!(
            scripted_lane().joint_finish_no_progress_trip(),
            None,
            "clearing the pose records no trip"
        );
        let _ = ClassicDriver::hold_joint_lane_for_exit(
            scripted_lane(),
            &mut coordinator,
            "untripped",
            "joint finish abandoned for exit",
            &mut warn,
            None,
        );
        assert_eq!(
            take_warned_for_test(),
            vec![expected_stop_line()],
            "the untripped hold discloses only its stop line"
        );
    }

    #[test]
    fn held_wedged_live_publication_names_stall_and_abandon_on_stderr() {
        // Isolate from lines other tests on this thread warned: the
        // recorder is thread-local and every read drains.
        take_warned_for_test();
        // A lane whose live publication tripped the running
        // no-progress bound, or whose unfinished publication the hold
        // abandons, names it on stderr: the wedged publication stands
        // in front of the commit, so the staged gap cannot commit,
        // and the hold's warning is the user-visible name. One line
        // per trip: the hold runs once per lane and the trip latches
        // once in the machine, so the line never repeats per poll.
        // The expectations read the real formatter; the literals pin
        // its wording.
        assert_eq!(
            ClassicDriver::held_live_publication_line(Some(6), true).as_deref(),
            Some(
                "p11scope: live publication made no progress for 6 s; abandoned it, coverage is partial"
            ),
            "the formatter names the stall and the abandon"
        );
        assert_eq!(
            ClassicDriver::held_live_publication_line(Some(6), false).as_deref(),
            Some(
                "p11scope: live publication made no progress for 6 s; the lane is held for exit, coverage is partial"
            ),
            "the formatter claims no abandon it did not run"
        );
        assert_eq!(
            ClassicDriver::held_live_publication_line(None, true).as_deref(),
            Some("p11scope: abandoned the unfinished live publication, coverage is partial"),
            "the formatter names a bare abandon"
        );
        assert_eq!(
            ClassicDriver::held_live_publication_line(None, false),
            None,
            "a quiet hold owes no line"
        );
        let scripted_lane = || {
            let mut lane = joint_lane(WindDownIo::completing(), false);
            lane.set_scripted_stop_counts_for_test(Some(scripted_nonzero_stop_counts()));
            lane.note_shed_calls(7);
            lane
        };
        // Clear the posed trip even if an assertion panics: the
        // override is thread-local and must not leak into the next
        // test on this thread.
        struct ClearPosedAuditTrip;
        impl Drop for ClearPosedAuditTrip {
            fn drop(&mut self) {
                crate::inventory_semantics::AttestedSemanticLane::pose_audit_no_progress_trip_for_test(
                    None,
                );
            }
        }
        let _clear = ClearPosedAuditTrip;
        let mut display = None;
        let mut warn = WarnSink {
            display: &mut display,
        };
        // Substituted lanes carry no live machine to trip, so the
        // trip is posed (like the lane's `scripted_*` seams stage
        // machine behavior); the hold still reads it through the
        // production accessor. Posing the audit trip names nothing
        // through the finish accessor.
        crate::inventory_semantics::AttestedSemanticLane::pose_audit_no_progress_trip_for_test(
            Some((1163, std::time::Duration::from_secs(6))),
        );
        let staged = scripted_lane()
            .joint_audit_no_progress_trip()
            .expect("the posed trip is observable");
        assert_eq!(staged.polls, 1163, "the posed poll count is observable");
        assert_eq!(
            staged.stalled,
            std::time::Duration::from_secs(6),
            "the posed stall duration is observable"
        );
        assert_eq!(
            scripted_lane().joint_finish_no_progress_trip(),
            None,
            "the audit pose stays out of the finish accessor"
        );
        // Trip plus a standing publication: the hold abandons it and
        // names both exactly once, before the stop line.
        let mut coordinator = coordinator();
        coordinator.pose_pending_joint_publication_for_test();
        let _ = ClassicDriver::hold_joint_lane_for_exit(
            scripted_lane(),
            &mut coordinator,
            "tripped",
            "joint finish abandoned for exit",
            &mut warn,
            None,
        );
        assert!(
            !coordinator.publication_pending(),
            "the hold abandons the posed publication"
        );
        assert_eq!(
            take_warned_for_test(),
            vec![
                ClassicDriver::held_live_publication_line(Some(6), true).expect("a line is owed"),
                expected_stop_line(),
            ],
            "the hold names the wedge once, before the stop line"
        );
        // Trip with nothing standing: the hold names the stall
        // without claiming an abandon, exactly once. The coordinator
        // carries over: the first hold cleared its posed publication.
        let _ = ClassicDriver::hold_joint_lane_for_exit(
            scripted_lane(),
            &mut coordinator,
            "tripped",
            "joint finish abandoned for exit",
            &mut warn,
            None,
        );
        assert_eq!(
            take_warned_for_test(),
            vec![
                ClassicDriver::held_live_publication_line(Some(6), false).expect("a line is owed"),
                expected_stop_line(),
            ],
            "a tripped hold without an abandon names only the stall"
        );
        // A bare abandon (no trip): the hold names what it cleared,
        // exactly once.
        crate::inventory_semantics::AttestedSemanticLane::pose_audit_no_progress_trip_for_test(
            None,
        );
        assert_eq!(
            scripted_lane().joint_audit_no_progress_trip(),
            None,
            "clearing the pose records no trip"
        );
        coordinator.pose_pending_joint_publication_for_test();
        let _ = ClassicDriver::hold_joint_lane_for_exit(
            scripted_lane(),
            &mut coordinator,
            "wedged",
            "joint finish abandoned for exit",
            &mut warn,
            None,
        );
        assert!(
            !coordinator.publication_pending(),
            "the hold abandons the posed publication"
        );
        assert_eq!(
            take_warned_for_test(),
            vec![
                ClassicDriver::held_live_publication_line(None, true).expect("a line is owed"),
                expected_stop_line(),
            ],
            "an abandoned hold without a trip names the abandon"
        );
        // Neither: the hold discloses only its stop line. The
        // coordinator carries over: the third hold cleared its pose.
        let _ = ClassicDriver::hold_joint_lane_for_exit(
            scripted_lane(),
            &mut coordinator,
            "quiet",
            "joint finish abandoned for exit",
            &mut warn,
            None,
        );
        assert_eq!(
            take_warned_for_test(),
            vec![expected_stop_line()],
            "the quiet hold discloses only its stop line"
        );
    }

    #[test]
    fn joint_stop_winding_without_live_session_names_unknown_counts() {
        // Isolate from lines other tests on this thread warned: the
        // recorder is thread-local and every read drains.
        take_warned_for_test();
        // A winding whose counts are unreadable (no live session left
        // to read) still discloses: a named gap says its
        // key-operation counts after the promotion began are unknown.
        // Never a silent hold, never an invented zero line.
        let mut coordinator = coordinator();
        let headless = headless_display();
        let mut driver = driver_with_display(&mut coordinator, headless.display);
        let mut lane = shell_lane_for_wind_down();
        assert!(!lane.is_live(), "the shell lane owns no session");
        lane.set_test_joint_machine(true);
        lane.set_scripted_finish_begin_for_test(Some(Ok(())));
        driver.semantic = Some(lane);
        install_promotion_for_wind_down(&mut driver);
        driver.wind_down_installed_promotion(PromotionEnd::Cancelled);
        assert_eq!(
            driver
                .retiring
                .as_ref()
                .expect("retiring")
                .winding
                .as_ref()
                .expect("winding")
                .finish,
            JointFinishDriver::Polling,
            "the scripted begin keeps the winding lane"
        );
        driver.on_stop_requested();
        assert!(
            take_warned_for_test().is_empty(),
            "no invented zero line for unreadable counts"
        );
        let unknown: Vec<(String, String)> = gaps(&mut driver)
            .into_iter()
            .filter(|(subject, _)| subject == "winding lane key-operation counts unknown")
            .collect();
        assert_eq!(unknown.len(), 1, "exactly one unknown-counts gap");
        assert_eq!(
            unknown[0].1,
            "stop held the winding lane with its counts unreadable; \
             its key-operation counts after the promotion began are unknown",
            "the gap names the unknown post-promotion counts"
        );
    }

    #[test]
    fn legacy_stop_during_winding_warns_nothing_new() {
        // Isolate from lines other tests on this thread warned: the
        // recorder is thread-local and every read drains.
        take_warned_for_test();
        // A legacy winding disclosed at wind-down through the terminal
        // sequence; the stop holds it with its gap only and warns no
        // second stop line.
        let mut coordinator = coordinator();
        let headless = headless_display();
        let mut driver = driver_with_display(&mut coordinator, headless.display);
        driver.semantic = Some(wind_down_lane(WindDownIo::completing()));
        let domain = install_promotion_for_wind_down(&mut driver);
        quiesce_domain_for_retire(&mut *driver.coordinator, domain);
        let (source, _, _) =
            CountingSource::scripted(Some(SessionNativeCompletion::scripted(domain)));
        driver.completion_source = Some(Box::new(source));
        driver.wind_down_installed_promotion(PromotionEnd::Cancelled);
        assert_eq!(
            take_warned_for_test(),
            vec![crate::inventory_semantics::semantic_stop_line(
                0, 0, 0, 0, 0
            )],
            "the wind-down discloses the legacy lane once"
        );
        driver.on_stop_requested();
        assert!(
            take_warned_for_test().is_empty(),
            "the stop warns no second line for a legacy winding"
        );
    }

    #[test]
    fn joint_driver_wound_down_error_exits_retained() {
        let mut coordinator = coordinator();
        let headless = headless_display();
        let mut driver = driver_with_display(&mut coordinator, headless.display);
        let mut io = WindDownIo::completing();
        io.fail_poll = true;
        let polls = Rc::clone(&io.polls);
        let drops = Rc::new(Cell::new(0));
        io.drop_spy = Some(Rc::clone(&drops));
        driver.semantic = Some(joint_lane(io, true));
        driver.joint_finish = JointFinishDriver::Published;
        let (source, mint_polls, _) = CountingSource::scripted(None);
        driver.completion_source = Some(Box::new(source));
        driver.on_tick();
        assert_eq!(
            driver.joint_finish,
            JointFinishDriver::Abandoned,
            "an Unproved detach abandons"
        );
        assert!(driver.semantic.is_none(), "the lane is held");
        assert_eq!(drops.get(), 0, "held means never dropped");
        assert!(
            driver.joint_first_error.is_some(),
            "the first error is kept"
        );
        assert_eq!(mint_polls.load(Ordering::SeqCst), 0, "no mint on abandon");
        assert_eq!(polls.get(), 1, "a failed detach is never re-polled");
        let failures: Vec<(String, String)> = gaps(&mut driver)
            .into_iter()
            .filter(|(subject, _)| subject == "joint wound-down failed")
            .collect();
        assert_eq!(
            failures.len(),
            1,
            "exactly one wound-down gap: {:?}",
            gaps(&mut driver)
        );
        assert!(
            failures[0].1.contains("Unproved"),
            "the gap carries the detach text: {:?}",
            failures[0].1
        );
    }

    #[test]
    fn joint_driver_commit_refusal_converts_within_one_hook() {
        use crate::inventory_semantics::SemanticRefusal;
        // Item 7 runs on the retained final lane: the winding always
        // begins or transfers, so no winding polls a commit. A
        // non-retryable commit refusal in NotBegun converts within one
        // hook (controller ruling E1, like the Poll path): the step
        // holds the lane and names the stop, keeping no run error,
        // instead of beginning or failing.
        let mut coord = coordinator();
        let headless = headless_display();
        let mut driver = driver_with_display(&mut coord, headless.display);
        let mut io = WindDownIo::completing();
        let drops = Rc::new(Cell::new(0));
        io.drop_spy = Some(Rc::clone(&drops));
        driver.semantic = Some(joint_lane(io, false));
        driver.joint_commit_pending = true;
        driver.suspended = true;
        driver.on_tick();
        assert_eq!(driver.joint_begin_calls, 0, "a refused commit never begins");
        assert_eq!(
            driver.joint_finish,
            JointFinishDriver::Abandoned,
            "a non-retryable commit refusal abandons within one hook"
        );
        assert!(driver.semantic.is_none(), "the abandoned lane is held");
        assert_eq!(drops.get(), 0, "held means never dropped");
        assert!(
            driver.joint_first_error.is_none(),
            "a converted refusal keeps no run error"
        );
        assert_eq!(
            gaps(&mut driver)
                .into_iter()
                .filter(|gap| gap.0 == "semantic lane stopped")
                .count(),
            1,
            "the conversion discloses the stop once"
        );
        // B stays blocked behind an abandoned winding: a
        // dispositioned lane winds down into a held Abandoned finish
        // that gates B.
        {
            let mut coord = coordinator();
            let headless = headless_display();
            let mut driver = driver_with_display(&mut coord, headless.display);
            let mut lane = joint_lane(WindDownIo::completing(), false);
            lane.note_joint_finish_failure(SemanticRefusal::Unavailable);
            driver.semantic = Some(lane);
            install_promotion_for_wind_down(&mut driver);
            driver.wind_down_installed_promotion(PromotionEnd::Cancelled);
            let winding = driver
                .retiring
                .as_ref()
                .expect("retiring")
                .winding
                .as_ref()
                .expect("the abandoned finish stays winding");
            assert!(winding.joint, "A carries a promotion finish");
            assert_eq!(
                winding.finish,
                JointFinishDriver::Abandoned,
                "the dispositioned wind-down abandons"
            );
            queue_request(driver.display.as_mut().expect("display"));
            for _ in 0..2 {
                driver.on_tick();
            }
            assert_eq!(
                driver.display.as_ref().expect("display").promotion_state(),
                PromotionState::Queued,
                "B waits behind the abandoned finish"
            );
            assert!(
                driver.lifecycle.is_idle(),
                "B prepares nothing behind the abandoned finish"
            );
        }
        // The retryable counter: ProviderStorage stays through 100
        // hooks and fails on the 101st; anything else fails at once.
        let mut retries = 0u16;
        for _ in 0..100 {
            assert!(
                note_commit_refusal_once(&mut retries, SemanticRefusal::ProviderStorage),
                "storage refusals retry through 100 hooks"
            );
        }
        assert!(
            !note_commit_refusal_once(&mut retries, SemanticRefusal::ProviderStorage),
            "the 101st storage refusal fails"
        );
        let mut retries = 0u16;
        assert!(
            !note_commit_refusal_once(&mut retries, SemanticRefusal::Unavailable),
            "a non-retryable refusal fails at once"
        );
    }

    #[test]
    fn joint_polling_on_finished_lane_publishes_without_spinning() {
        // A finished lane in Polling has nothing left to poll: one
        // hook resumes at the wound-down phase instead of spinning
        // on a refusal the latch can never bound.
        let mut coordinator = coordinator();
        let headless = headless_display();
        let mut driver = driver_with_display(&mut coordinator, headless.display);
        driver.semantic = Some(joint_lane(WindDownIo::completing(), true));
        driver.joint_finish = JointFinishDriver::Polling;
        driver.on_tick();
        assert_eq!(
            driver.joint_finish,
            JointFinishDriver::Published,
            "a finished lane in Polling publishes at once"
        );
        assert_eq!(
            driver
                .semantic
                .as_ref()
                .expect("lane")
                .finish_poll_calls_for_test(),
            0,
            "no spin: the shortcut polls nothing"
        );
    }

    #[test]
    fn winding_fresh_begin_arms_promotion_finish_with_joint_finish_not_begun() {
        // The item-9 gate needs no promotion conjunct: a fresh
        // wind-down begin arms the promotion flag while the driver
        // finish stays NotBegun (the begun state lives on the
        // winding), and the flag disarms only when the winding
        // retires — before any new lane seats.
        let mut coordinator = coordinator();
        let headless = headless_display();
        let mut driver = driver_with_display(&mut coordinator, headless.display);
        driver.semantic = Some(joint_lane(WindDownIo::completing(), true));
        let _ = install_promotion_for_wind_down(&mut driver);
        driver.wind_down_installed_promotion(PromotionEnd::Cancelled);
        assert!(
            driver.coordinator.promotion_finish(),
            "A's promotion finish runs"
        );
        assert_eq!(
            driver.joint_finish,
            JointFinishDriver::NotBegun,
            "the begun state lives on the winding, not the driver"
        );
        assert!(
            driver.semantic.is_none(),
            "the winding carries the lane while the flag is armed"
        );
    }

    #[test]
    fn winding_transfer_keeps_promotion_finish_disarmed_and_resets_joint_finish() {
        // An in-flight seated finish transfers into the winding
        // without arming the promotion flag; the driver finish
        // resets to NotBegun.
        let mut coordinator = coordinator();
        let headless = headless_display();
        let mut driver = driver_with_display(&mut coordinator, headless.display);
        driver.semantic = Some(joint_lane(WindDownIo::completing(), false));
        let _ = install_promotion_for_wind_down(&mut driver);
        driver.joint_finish = JointFinishDriver::Polling;
        driver.wind_down_installed_promotion(PromotionEnd::Cancelled);
        assert!(
            !driver.coordinator.promotion_finish(),
            "a transferred finish is not A's promotion finish"
        );
        assert_eq!(
            driver.joint_finish,
            JointFinishDriver::NotBegun,
            "the transfer resets the driver finish"
        );
        assert_eq!(
            driver
                .retiring
                .as_ref()
                .expect("retiring")
                .winding
                .as_ref()
                .expect("winding")
                .finish,
            JointFinishDriver::Polling,
            "the winding keeps the in-flight state"
        );
    }

    #[test]
    fn joint_final_finish_tick_runs_only_driver() {
        let mut coordinator = coordinator();
        let headless = headless_display();
        let mut driver = driver_with_display(&mut coordinator, headless.display);
        let io = WindDownIo::completing();
        let lane_ticks = Rc::clone(&io.ticks);
        // In-flight through the scripted poll: the finish polls on
        // without latching while the item-9 gate holds.
        let mut lane = joint_lane(io, false);
        lane.set_scripted_finish_poll_for_test(Some(Ok(JointCommitProgress::Pending)));
        driver.semantic = Some(lane);
        driver.joint_finish = JointFinishDriver::Polling;
        assert!(
            !driver.coordinator.promotion_finish(),
            "the final finish runs outside any promotion"
        );
        queue_request(driver.display.as_mut().expect("display"));
        driver.semantic_staged = true;
        driver
            .semantic
            .as_mut()
            .expect("lane")
            .age_staged_for_test(Instant::now() - Duration::from_secs(5));
        let epoch = driver.coordinator.graph_inputs_epoch_for_test();
        let ticks_before = driver.display.as_ref().expect("display").account().ticks;
        for _ in 0..8 {
            driver.on_tick();
        }
        assert_eq!(
            driver.joint_finish,
            JointFinishDriver::Polling,
            "an in-flight lane polls without latching"
        );
        assert_eq!(driver.joint_step_calls, 8, "every hook stepped the driver");
        assert_eq!(
            driver.display.as_ref().expect("display").account().ticks,
            ticks_before + 8,
            "every hook still ticked the display"
        );
        // The epoch pins "driver ticks never dirty the graph
        // inputs" as a tripwire, not as the gate killer: no
        // on_tick-reachable path bumps it (a full-path probe moves
        // takes and commits but leaves the epoch at 0), and the
        // contract's due scan / pending exec transition are
        // serviced only by the collection loop, so planting them
        // here would sit unserviced in both paths (R1.4 minor
        // ruling: fixture theater refused). The take and commit
        // spies below are the gate killers (mutant A).
        assert_eq!(
            driver.coordinator.graph_inputs_epoch_for_test(),
            epoch,
            "no hook moved the graph inputs"
        );
        assert_eq!(
            driver.take_promotion_work_calls, 0,
            "no hook took promotion work"
        );
        assert_eq!(
            driver.commit_calls, 0,
            "no hook attempted the staged commit"
        );
        assert_eq!(
            driver.display.as_ref().expect("display").promotion_state(),
            PromotionState::Queued,
            "no hook took promotion work"
        );
        assert!(
            driver.lifecycle.is_idle(),
            "no hook ran the promotion service"
        );
        assert_eq!(lane_ticks.get(), 0, "no hook ticked the lane");
        assert!(
            driver.semantic_staged,
            "no hook committed the staged quantum"
        );
    }

    #[test]
    fn joint_winding_empty_mint_then_mint_retries_and_retires() {
        // The first retire attempt after the handoff does not mint;
        // the retry retires A instead of abandoning it. The joined
        // retry never re-polls the wound-down: the session is gone,
        // so reaping again would fail closed and strand B.
        let mut coordinator = coordinator();
        let headless = headless_display();
        let mut driver = driver_with_display(&mut coordinator, headless.display);
        let io = WindDownIo::completing();
        let polls = Rc::clone(&io.polls);
        driver.semantic = Some(joint_lane(io, true));
        let domain = install_promotion_for_wind_down(&mut driver);
        quiesce_domain_for_retire(&mut *driver.coordinator, domain);
        let (source, _, _) = CountingSource::scripted(None);
        driver.completion_source = Some(Box::new(source));
        driver.wind_down_installed_promotion(PromotionEnd::Cancelled);
        assert!(
            driver.coordinator.promotion_finish(),
            "A's promotion finish runs"
        );
        // The seal drains before the first retire poll, as in
        // production (a finished lane retains no frame past the take).
        driver
            .retiring
            .as_mut()
            .expect("retiring")
            .winding
            .as_mut()
            .expect("winding")
            .lane
            .as_mut()
            .expect("lane")
            .set_test_joint_frame(false);
        driver.on_tick();
        assert_eq!(
            driver.retiring_domain(),
            Some(domain),
            "an empty mint holds A without abandoning it"
        );
        assert_eq!(
            driver
                .retiring
                .as_ref()
                .expect("retiring")
                .winding
                .as_ref()
                .expect("winding")
                .finish,
            JointFinishDriver::Published,
            "the held retry never abandons"
        );
        assert_eq!(polls.get(), 1, "the wind-down reaped once");
        assert!(
            gaps(&mut driver)
                .iter()
                .all(|(subject, _)| subject != "joint wound-down failed"),
            "no wound-down failure on the held mint: {:?}",
            gaps(&mut driver)
        );
        let (source, mint_polls, _) =
            CountingSource::scripted(Some(SessionNativeCompletion::scripted(domain)));
        driver.completion_source = Some(Box::new(source));
        driver.on_tick();
        assert_eq!(driver.retiring_domain(), None, "the retry mint retires A");
        assert!(
            !driver.coordinator.promotion_finish(),
            "the flag clears only after A's retire"
        );
        assert_eq!(
            polls.get(),
            1,
            "the joined retry never re-polls the wound-down"
        );
        assert_eq!(mint_polls.load(Ordering::SeqCst), 1, "the retry mints once");
    }

    #[test]
    fn joint_winding_retire_refused_then_ok_retries_without_reaping() {
        // A refused retire retains its proof; the retry retires on
        // the drained seal without reaping the wound-down again. The
        // hold is staged h9 ledger work (the seal drain); the frame
        // is already gone, as in production past the take.
        let mut coordinator = coordinator();
        let headless = headless_display();
        let mut driver = driver_with_display(&mut coordinator, headless.display);
        let io = WindDownIo::completing();
        let polls = Rc::clone(&io.polls);
        driver.semantic = Some(joint_lane(io, true));
        let domain = install_promotion_for_wind_down(&mut driver);
        quiesce_domain_for_retire(&mut *driver.coordinator, domain);
        let (source, mint_polls, _) =
            CountingSource::scripted(Some(SessionNativeCompletion::scripted(domain)));
        driver.completion_source = Some(Box::new(source));
        driver.wind_down_installed_promotion(PromotionEnd::Cancelled);
        assert!(
            driver.coordinator.promotion_finish(),
            "A's promotion finish runs"
        );
        driver
            .retiring
            .as_mut()
            .expect("retiring")
            .winding
            .as_mut()
            .expect("winding")
            .lane
            .as_mut()
            .expect("lane")
            .set_test_joint_frame(false);
        driver
            .coordinator
            .joint_capture_mut()
            .ledger_mut()
            .charge(7, 64)
            .expect("one h9 entry stages");
        driver.on_tick();
        assert_eq!(
            driver.retiring_domain(),
            Some(domain),
            "a refused retire holds A with its proof retained"
        );
        assert_eq!(polls.get(), 1, "the wind-down reaped once");
        assert_eq!(
            mint_polls.load(Ordering::SeqCst),
            1,
            "the refused proof minted once"
        );
        // The seal drains; the retry retires on the retained proof.
        driver
            .coordinator
            .joint_capture_mut()
            .ledger_mut()
            .release(7, 64);
        driver.on_tick();
        assert_eq!(
            driver.retiring_domain(),
            None,
            "the drained retry retires A"
        );
        assert!(
            !driver.coordinator.promotion_finish(),
            "the flag clears only after A's retire"
        );
        assert_eq!(
            polls.get(),
            1,
            "the joined retry never re-polls the wound-down"
        );
        assert_eq!(
            mint_polls.load(Ordering::SeqCst),
            1,
            "the retained proof is reused, never re-polled"
        );
    }

    #[test]
    fn foreign_completion_for_another_domain_reports_without_debug_id() {
        use crate::attach::capture::NativeDomainId;
        // A completion for another domain with no live finalizer
        // state is genuinely foreign: one gap, worded without the
        // opaque domain id (NativeDomainId is equality-only; no
        // Display exists and numeric access is journal-only).
        let mut coordinator = coordinator();
        let headless = headless_display();
        let mut driver = driver_with_display(&mut coordinator, headless.display);
        driver.semantic = Some(joint_lane(WindDownIo::completing(), true));
        let domain = install_promotion_for_wind_down(&mut driver);
        quiesce_domain_for_retire(&mut *driver.coordinator, domain);
        let foreign = NativeDomainId::try_mint().expect("domain mints");
        let (source, _, _) =
            CountingSource::scripted(Some(SessionNativeCompletion::scripted(foreign)));
        driver.completion_source = Some(Box::new(source));
        driver.wind_down_installed_promotion(PromotionEnd::Cancelled);
        driver
            .retiring
            .as_mut()
            .expect("retiring")
            .winding
            .as_mut()
            .expect("winding")
            .lane
            .as_mut()
            .expect("lane")
            .set_test_joint_frame(false);
        driver.on_tick();
        assert_eq!(
            driver.retiring_domain(),
            Some(domain),
            "the foreign proof holds A"
        );
        let failures: Vec<(String, String)> = gaps(&mut driver)
            .into_iter()
            .filter(|(subject, _)| subject == "selected promotion completion failed")
            .collect();
        assert_eq!(
            failures.len(),
            1,
            "the foreign completion reports exactly once: {:?}",
            gaps(&mut driver)
        );
        assert_eq!(
            failures[0].1, "foreign completion for a domain with no live finalizer state",
            "the gap words the foreign domain without a Debug id"
        );
        assert!(
            !failures[0].1.contains("NativeDomainId"),
            "no Debug domain id leaks: {:?}",
            failures[0].1
        );
    }

    #[test]
    fn own_domain_completion_without_live_finalizer_stays_silent() {
        // A's own late completion with no live finalizer state is
        // not foreign: no gap fires, and the drained winding
        // clears like the lane-less tail instead of holding: no
        // production path can make a finalizer for A's domain
        // live again (the slot stays empty until B installs, B
        // waits behind the retire, and the joined winding stages
        // nothing), so holding would block B silently forever.
        let mut coordinator = coordinator();
        let headless = headless_display();
        let mut driver = driver_with_display(&mut coordinator, headless.display);
        driver.semantic = Some(joint_lane(WindDownIo::completing(), true));
        let domain = install_promotion_for_wind_down(&mut driver);
        let (source, _, _) =
            CountingSource::scripted(Some(SessionNativeCompletion::scripted(domain)));
        driver.completion_source = Some(Box::new(source));
        driver.wind_down_installed_promotion(PromotionEnd::Cancelled);
        driver
            .retiring
            .as_mut()
            .expect("retiring")
            .winding
            .as_mut()
            .expect("winding")
            .lane
            .as_mut()
            .expect("lane")
            .set_test_joint_frame(false);
        driver.on_tick();
        assert_eq!(
            driver.retiring_domain(),
            None,
            "A clears once drained with no live finalizer"
        );
        assert!(
            !driver.coordinator.promotion_finish(),
            "the clear releases B's gate"
        );
        assert!(
            gaps(&mut driver)
                .iter()
                .all(|(subject, _)| subject != "selected promotion completion failed"),
            "A's own domain never reports a foreign completion: {:?}",
            gaps(&mut driver)
        );
    }

    #[test]
    fn promotion_wind_down_scopes_promotion_finish_to_a() {
        for _ in 0..3 {
            let mut coordinator = coordinator();
            let headless = headless_display();
            let mut driver = driver_with_display(&mut coordinator, headless.display);
            driver.semantic = Some(joint_lane(WindDownIo::completing(), true));
            let domain = install_promotion_for_wind_down(&mut driver);
            quiesce_domain_for_retire(&mut *driver.coordinator, domain);
            assert!(
                !driver.coordinator.promotion_finish(),
                "the flag starts clear"
            );
            let (source, _, _) =
                CountingSource::scripted(Some(SessionNativeCompletion::scripted(domain)));
            driver.completion_source = Some(Box::new(source));
            driver.wind_down_installed_promotion(PromotionEnd::Cancelled);
            assert!(
                driver.coordinator.promotion_finish(),
                "the flag sets before A's begin"
            );
            // A's frame still held: the retire holds with the flag set.
            driver.on_tick();
            assert_eq!(
                driver.retiring_domain(),
                Some(domain),
                "A holds while its frame stays live"
            );
            assert!(
                driver.coordinator.promotion_finish(),
                "the flag stays set until A retires"
            );
            // The frame drains; A retires and clears the flag.
            driver
                .retiring
                .as_mut()
                .expect("retiring")
                .winding
                .as_mut()
                .expect("winding")
                .lane
                .as_mut()
                .expect("lane")
                .set_test_joint_frame(false);
            driver.on_tick();
            assert_eq!(driver.retiring_domain(), None, "A retires once drained");
            assert!(
                !driver.coordinator.promotion_finish(),
                "the flag clears only after A's retire"
            );
            assert_eq!(
                driver.coordinator.engine_collected_finish_calls(),
                0,
                "no promotion finish enters the Engine"
            );
            // B is seated after A retires (installing B needs native
            // preparation, which the privileged loop covers; the unit
            // test pins the flag discipline around B's finish).
            driver.semantic = Some(joint_lane(WindDownIo::completing(), true));
            driver.on_stop_requested();
            assert!(
                !driver.coordinator.promotion_finish(),
                "B's later final finish runs with the flag clear"
            );
            assert_eq!(driver.joint_finish, JointFinishDriver::Published);
            assert_eq!(
                driver.coordinator.engine_collected_finish_calls(),
                0,
                "no view ID is retained across the promotion"
            );
        }
    }

    #[test]
    fn stop_during_promotion_finish_discloses_once() {
        let mut coordinator = coordinator();
        let headless = headless_display();
        let mut driver = driver_with_display(&mut coordinator, headless.display);
        let (io, gate) = WindDownIo::gated();
        let polls = Rc::clone(&io.polls);
        driver.semantic = Some(joint_lane(io, true));
        let domain = install_promotion_for_wind_down(&mut driver);
        quiesce_domain_for_retire(&mut *driver.coordinator, domain);
        let (source, _, _) =
            CountingSource::scripted(Some(SessionNativeCompletion::scripted(domain)));
        driver.completion_source = Some(Box::new(source));
        driver.wind_down_installed_promotion(PromotionEnd::Cancelled);
        assert!(
            driver.coordinator.promotion_finish(),
            "A's promotion finish runs"
        );
        // A stop during the finish keeps it and discloses once.
        driver.on_stop_requested();
        {
            let winding = driver
                .retiring
                .as_ref()
                .expect("retiring")
                .winding
                .as_ref()
                .expect("A's finish is kept");
            assert!(winding.joint, "A keeps its promotion finish");
            assert_eq!(winding.finish, JointFinishDriver::Published);
            assert!(winding.lane.is_some(), "A's lane is kept");
        }
        let stops: Vec<(String, String)> = gaps(&mut driver)
            .into_iter()
            .filter(|(subject, _)| subject == "terminal stop during promotion")
            .collect();
        assert_eq!(
            stops.len(),
            1,
            "exactly one terminal-stop gap: {:?}",
            gaps(&mut driver)
        );
        assert_eq!(
            stops[0].1, "process exits after the last inventory scan were not retired at the stop",
            "the gap carries the exact reason"
        );
        // The kept finish still completes: polls continue, the join
        // retires, and no second gap appears.
        driver.on_tick();
        assert!(polls.get() >= 1, "the kept finish still polls");
        driver
            .retiring
            .as_mut()
            .expect("retiring")
            .winding
            .as_mut()
            .expect("winding")
            .lane
            .as_mut()
            .expect("lane")
            .set_test_joint_frame(false);
        release_gate(&gate);
        driver.on_tick();
        assert_eq!(
            driver.retiring_domain(),
            None,
            "the kept finish still retires"
        );
        driver.on_stop_requested();
        assert_eq!(
            gaps(&mut driver)
                .iter()
                .filter(|(subject, _)| subject == "terminal stop during promotion")
                .count(),
            1,
            "a second stop discloses nothing further"
        );
    }

    #[test]
    fn stop_during_legacy_winding_holds_lane_and_records_one_gap() {
        // A stop during a legacy wind-down never reaps it (no ticks
        // follow the stop): the driver holds the lane for exit
        // instead of dropping it, and the stop path records exactly
        // one gap before the final commit publishes it.
        let mut coordinator = coordinator();
        let headless = headless_display();
        let drops = Rc::new(Cell::new(0));
        {
            let mut driver = driver_with_display(&mut coordinator, headless.display);
            let (io, _gate) = WindDownIo::gated();
            let mut io = io;
            io.drop_spy = Some(Rc::clone(&drops));
            driver.semantic = Some(wind_down_lane(io));
            let domain = install_promotion_for_wind_down(&mut driver);
            quiesce_domain_for_retire(&mut *driver.coordinator, domain);
            let (source, _, _) =
                CountingSource::scripted(Some(SessionNativeCompletion::scripted(domain)));
            driver.completion_source = Some(Box::new(source));
            driver.wind_down_installed_promotion(PromotionEnd::Cancelled);
            driver.on_tick();
            assert_eq!(
                driver.retiring_domain(),
                Some(domain),
                "the gated detach holds the winding"
            );
            driver.on_stop_requested();
            let holds: Vec<(String, String)> = gaps(&mut driver)
                .into_iter()
                .filter(|(subject, _)| subject == "promotion wind-down held for exit")
                .collect();
            assert_eq!(
                holds.len(),
                1,
                "exactly one unjoined-winding gap: {:?}",
                gaps(&mut driver)
            );
            assert_eq!(
                holds[0].1, "stop during a legacy wind-down; the lane is held for exit",
                "the gap names the unjoined legacy winding"
            );
            // The driver drops here with the winding still held.
        }
        assert_eq!(drops.get(), 0, "a hold, not a drop");
    }

    #[test]
    fn stop_during_joint_winding_holds_lane_and_records_one_gap() {
        // The Joint twin: a stop during A's promotion finish holds
        // the winding lane for exit with exactly one gap (beside the
        // pre-existing terminal-stop-during-promotion disclosure).
        let mut coordinator = coordinator();
        let headless = headless_display();
        let drops = Rc::new(Cell::new(0));
        {
            let mut driver = driver_with_display(&mut coordinator, headless.display);
            let (io, _gate) = WindDownIo::gated();
            let mut io = io;
            io.drop_spy = Some(Rc::clone(&drops));
            driver.semantic = Some(joint_lane(io, true));
            let domain = install_promotion_for_wind_down(&mut driver);
            quiesce_domain_for_retire(&mut *driver.coordinator, domain);
            let (source, _, _) =
                CountingSource::scripted(Some(SessionNativeCompletion::scripted(domain)));
            driver.completion_source = Some(Box::new(source));
            driver.wind_down_installed_promotion(PromotionEnd::Cancelled);
            driver.on_tick();
            assert_eq!(
                driver.retiring_domain(),
                Some(domain),
                "the gated finish holds the winding"
            );
            driver.on_stop_requested();
            let holds: Vec<(String, String)> = gaps(&mut driver)
                .into_iter()
                .filter(|(subject, _)| subject == "promotion wind-down held for exit")
                .collect();
            assert_eq!(
                holds.len(),
                1,
                "exactly one unjoined-winding gap: {:?}",
                gaps(&mut driver)
            );
            assert_eq!(
                holds[0].1, "stop during a Joint promotion finish; the lane is held for exit",
                "the gap names the unjoined Joint winding"
            );
            // The driver drops here with the winding still held.
        }
        assert_eq!(drops.get(), 0, "a hold, not a drop");
    }

    #[test]
    fn legacy_h3_staged_lane_winds_down_and_retires_on_cancel() {
        use crate::discovery::engine::inventory_coordinator::semantics::JointRetireRefusal;
        // A legacy lane (no Joint seam) whose finalized batch staged
        // seal evidence still winds down and retires on cancel: the
        // shared gate does not hold h3, and the legacy retire drops
        // it with the namespace.
        let mut coordinator = coordinator();
        let headless = headless_display();
        let mut driver = driver_with_display(&mut coordinator, headless.display);
        driver.semantic = Some(wind_down_lane(WindDownIo::completing()));
        let domain = install_promotion_for_wind_down(&mut driver);
        quiesce_domain_for_retire(&mut *driver.coordinator, domain);
        driver.wind_down_installed_promotion(PromotionEnd::Cancelled);
        assert_eq!(driver.retiring_domain(), Some(domain));
        // The terminal commit staged h3: the seal-drained retire
        // holds on it while the shared gate does not.
        assert!(
            !driver.coordinator.joint_domain_has_pending_work(domain),
            "h3 does not hold the shared wind-down gate"
        );
        let lane = driver
            .retiring
            .as_ref()
            .expect("retiring")
            .winding
            .as_ref()
            .expect("winding")
            .lane
            .as_ref()
            .expect("lane");
        assert!(!lane.has_joint_frame(), "a legacy lane stays frameless");
        let (completion, refusal) = driver
            .coordinator
            .retire_joint_domain_with_lane(lane, SessionNativeCompletion::scripted(domain))
            .expect_err("h3 is staged");
        assert_eq!(refusal, JointRetireRefusal::PendingWork);
        assert_eq!(completion.domain(), domain);
        let (source, _, _) =
            CountingSource::scripted(Some(SessionNativeCompletion::scripted(domain)));
        driver.completion_source = Some(Box::new(source));
        driver.on_tick();
        assert_eq!(
            driver.retiring_domain(),
            None,
            "the legacy lane retires with its h3 dropped"
        );
        driver.coordinator.stage_semantic_batch(
            crate::inventory_semantics::SemanticBatch::scripted(domain, Vec::new(), 9),
        );
        assert!(
            gaps(&mut driver)
                .iter()
                .any(|(subject, _)| subject == "semantic batch refused for an ended domain"),
            "the retired domain stays refused: {:?}",
            gaps(&mut driver)
        );
    }

    #[test]
    fn held_joint_lane_keeps_its_summary() {
        // A held final lane leaves no seat, but its summary stays:
        // the hold snapshots the seated lane and the run serves it.
        // A later hold overwrites with its own lane.
        let mut coordinator = coordinator();
        let headless = headless_display();
        let mut driver = driver_with_display(&mut coordinator, headless.display);
        let mut io = WindDownIo::completing();
        io.fail_poll = true;
        let mut lane = joint_lane(io, false);
        lane.mark_startup_failed();
        let seated = lane.semantic_summary();
        driver.semantic = Some(lane);
        driver.joint_finish = JointFinishDriver::Published;
        driver.on_lane_stopped();
        assert_eq!(
            driver.joint_finish,
            JointFinishDriver::Abandoned,
            "the failed detach holds"
        );
        assert!(driver.semantic.is_none(), "the hold takes the seat");
        assert_eq!(
            driver.semantic_summary(),
            seated,
            "the hold serves the seated summary, not the default"
        );
        let mut io = WindDownIo::completing();
        io.fail_poll = true;
        let lane = joint_lane(io, false);
        let reseated = lane.semantic_summary();
        assert_ne!(reseated, seated, "the second lane reads distinctly");
        driver.semantic = Some(lane);
        driver.joint_finish = JointFinishDriver::Published;
        driver.on_lane_stopped();
        assert_eq!(
            driver.semantic_summary(),
            reseated,
            "the later hold overwrites with its own lane"
        );
    }

    #[test]
    fn completed_joint_lane_keeps_its_summary() {
        // A completed final lane releases its seat, but the run
        // still serves the seated summary past the handoff.
        let mut coordinator = coordinator();
        let headless = headless_display();
        let mut driver = driver_with_display(&mut coordinator, headless.display);
        let mut lane = joint_lane(WindDownIo::completing(), true);
        lane.mark_startup_failed();
        let seated = lane.semantic_summary();
        driver.semantic = Some(lane);
        driver.joint_finish = JointFinishDriver::Published;
        // The seal drains before the completion, as in production.
        driver
            .semantic
            .as_mut()
            .expect("lane")
            .set_test_joint_frame(false);
        driver.on_lane_stopped();
        assert!(
            driver.semantic.is_none(),
            "the joined detach completes the lane"
        );
        assert_eq!(
            driver.semantic_summary(),
            seated,
            "the completion serves the seated summary, not the default"
        );
    }

    #[test]
    fn joint_wind_down_skips_staged_gate_and_begins() {
        // A Joint lane with staged evidence winds down and begins
        // its finish at once; the retire gate handles pending work,
        // so staged work never wedges the wind-down behind B.
        let mut coordinator = coordinator();
        let headless = headless_display();
        let mut driver = driver_with_display(&mut coordinator, headless.display);
        driver.semantic = Some(joint_lane(WindDownIo::completing(), true));
        let domain = install_promotion_for_wind_down(&mut driver);
        quiesce_domain_for_retire(&mut *driver.coordinator, domain);
        driver.semantic_staged = true;
        driver.wind_down_installed_promotion(PromotionEnd::Cancelled);
        assert_eq!(
            driver.joint_begin_calls, 1,
            "the Joint finish begins despite staged work"
        );
        assert!(
            driver.coordinator.promotion_finish(),
            "A's promotion finish runs"
        );
        assert_eq!(
            driver.retiring_domain(),
            Some(domain),
            "the Joint lane winds down"
        );
    }

    #[test]
    fn legacy_wind_down_holds_while_staged() {
        // The legacy gate is untouched: staged work keeps the
        // validating lane until the normal staged path commits it.
        let mut coordinator = coordinator();
        let headless = headless_display();
        let mut driver = driver_with_display(&mut coordinator, headless.display);
        let mut lane = wind_down_lane(WindDownIo::completing());
        lane.finish_semantic_stop();
        driver.semantic = Some(lane);
        install_promotion_for_wind_down(&mut driver);
        driver.semantic_staged = true;
        driver.wind_down_installed_promotion(PromotionEnd::Cancelled);
        assert_eq!(
            driver.retiring_domain(),
            None,
            "the legacy lane holds its staged work"
        );
        assert!(driver.semantic.is_some(), "the validating lane is kept");
        assert!(
            !driver.coordinator.promotion_finish(),
            "no promotion finish runs"
        );
        assert_eq!(driver.joint_begin_calls, 0, "nothing begins");
    }

    #[test]
    fn second_signal_at_lane_stop_escalates_the_begun_finish() {
        // The second operator signal reaches the driver at the lane
        // stop: a begun-but-unfinished Joint finish escalates to the
        // typed exit instead of stepping on.
        let mut coordinator = coordinator();
        let headless = headless_display();
        let mut driver = driver_with_display(&mut coordinator, headless.display);
        let mut lane = joint_lane(WindDownIo::completing(), false);
        lane.set_scripted_finish_poll_for_test(Some(Ok(JointCommitProgress::Pending)));
        driver.semantic = Some(lane);
        driver.joint_finish = JointFinishDriver::Polling;
        driver.second_signal = Some(&|| true);
        driver.on_lane_stopped();
        assert_eq!(
            driver.joint_finish,
            JointFinishDriver::Abandoned,
            "the second signal escalates the begun finish"
        );
        assert!(driver.semantic.is_none(), "the escalation holds its lane");
        assert_eq!(
            driver.joint_first_error.as_deref(),
            Some("second stop during joint finish"),
            "the escalation keeps its cause"
        );
        assert_eq!(
            gaps(&mut driver)
                .iter()
                .filter(|(subject, _)| subject == "joint finish held for exit")
                .count(),
            1,
            "the escalation discloses its hold: {:?}",
            gaps(&mut driver)
        );
    }

    #[test]
    fn lane_stop_without_second_signal_steps_the_begun_finish() {
        // Control: without a second signal the lane stop steps the
        // begun finish normally instead of escalating.
        let mut coordinator = coordinator();
        let headless = headless_display();
        let mut driver = driver_with_display(&mut coordinator, headless.display);
        let mut lane = joint_lane(WindDownIo::completing(), false);
        lane.set_scripted_finish_poll_for_test(Some(Ok(JointCommitProgress::Pending)));
        driver.semantic = Some(lane);
        driver.joint_finish = JointFinishDriver::Polling;
        driver.second_signal = Some(&|| false);
        driver.on_lane_stopped();
        assert_eq!(
            driver.joint_finish,
            JointFinishDriver::Polling,
            "no signal means no escalation"
        );
        assert!(driver.semantic.is_some(), "the polling lane is kept");
        assert!(
            driver.joint_first_error.is_none(),
            "no error without escalation"
        );
    }

    #[test]
    fn completed_framed_lane_waits_for_the_seal() {
        // A Published final lane whose seal has not drained keeps
        // its seat through the wound-down: the not-ready take
        // holds, and the drained retry completes it.
        let mut coordinator = coordinator();
        let headless = headless_display();
        let mut driver = driver_with_display(&mut coordinator, headless.display);
        let mut io = WindDownIo::completing();
        let drops = Rc::new(Cell::new(0));
        io.drop_spy = Some(Rc::clone(&drops));
        driver.semantic = Some(joint_lane(io, true));
        driver.joint_finish = JointFinishDriver::Published;
        driver.on_lane_stopped();
        assert_eq!(
            driver.joint_finish,
            JointFinishDriver::Published,
            "the framed lane never abandons"
        );
        assert!(
            driver.semantic.is_some(),
            "the not-ready take keeps the lane"
        );
        assert!(driver.joint_first_error.is_none(), "no error while waiting");
        assert_eq!(drops.get(), 0, "kept means never dropped");
        // The seal drains; the retry completes it.
        driver
            .semantic
            .as_mut()
            .expect("lane")
            .set_test_joint_frame(false);
        driver.on_lane_stopped();
        assert!(
            driver.semantic.is_none(),
            "the drained retry completes the lane"
        );
        assert_eq!(drops.get(), 1, "completion drops the shell");
    }

    #[test]
    fn joint_first_error_keeps_first_across_holds() {
        // Two sequential holds keep the first error, never the
        // latest: the second hold's reason must not overwrite it.
        use crate::inventory_semantics::SemanticRefusal;
        let mut coordinator = coordinator();
        let headless = headless_display();
        let mut driver = driver_with_display(&mut coordinator, headless.display);
        let mut lane = joint_lane(WindDownIo::completing(), false);
        lane.note_joint_finish_failure(SemanticRefusal::Unavailable);
        driver.semantic = Some(lane);
        driver.on_stop_requested();
        assert_eq!(
            driver.joint_first_error.as_deref(),
            Some("joint finish disposition required"),
            "the first hold keeps the default reason"
        );
        // A later hold carries a graph refusal; the first error stays.
        driver
            .coordinator
            .seed_collected_graph_refusal_for_test("terminal graph refused before native mutation");
        let mut lane = joint_lane(WindDownIo::completing(), false);
        lane.note_joint_finish_failure(SemanticRefusal::Unavailable);
        driver.semantic = Some(lane);
        driver.joint_finish = JointFinishDriver::NotBegun;
        driver.on_stop_requested();
        assert_eq!(
            driver.joint_finish,
            JointFinishDriver::Abandoned,
            "the second hold abandons again"
        );
        assert_eq!(
            driver.joint_first_error.as_deref(),
            Some("joint finish disposition required"),
            "the first error wins across holds"
        );
    }

    #[test]
    fn joint_published_wound_down_failure_keeps_preset_first_error() {
        // A pre-set first error survives a Published lane whose
        // wound-down fails: the later cause must not overwrite it,
        // and the failure gap still records.
        let mut coordinator = coordinator();
        let headless = headless_display();
        let mut driver = driver_with_display(&mut coordinator, headless.display);
        let mut io = WindDownIo::completing();
        io.fail_poll = true;
        driver.semantic = Some(joint_lane(io, true));
        driver.joint_finish = JointFinishDriver::Published;
        driver.joint_first_error = Some("the earlier disposition".to_string());
        driver.on_tick();
        assert_eq!(
            driver.joint_finish,
            JointFinishDriver::Abandoned,
            "a failed wound-down abandons"
        );
        assert!(driver.semantic.is_none(), "the lane is held");
        assert_eq!(
            driver.joint_first_error.as_deref(),
            Some("the earlier disposition"),
            "the pre-set first error survives the wound-down failure"
        );
        assert_eq!(
            gaps(&mut driver)
                .iter()
                .filter(|(subject, _)| subject == "joint wound-down failed")
                .count(),
            1,
            "the failure gap still records: {:?}",
            gaps(&mut driver)
        );
    }

    #[test]
    fn consume_gated_published_lane_escalates_on_second_signal() {
        // The terminal consume waits for the Published detach, but
        // a second operator signal escalates at once instead of
        // hanging: Abandoned, held, one gap, first error kept.
        let mut coordinator = coordinator();
        let headless = headless_display();
        let mut driver = driver_with_display(&mut coordinator, headless.display);
        let (io, _gate) = WindDownIo::gated();
        let polls = Rc::clone(&io.polls);
        let mut lane = joint_lane(io, true);
        lane.set_test_joint_frame(false);
        driver.semantic = Some(lane);
        driver.joint_finish = JointFinishDriver::Published;
        driver.second_signal = Some(&|| true);
        let stop = std::cell::Cell::new(false);
        let stop_now = || stop.get();
        let clock = super::tests::consume_clock(&stop_now);
        let outcome = ClassicOutcome {
            stopped: None,
            error: None,
            zero_pass: None,
            retained: None,
        };
        let start = Instant::now();
        let (_stopped, _error, _zero) = driver.consume_outcome(outcome, &clock, &mut |_, _| Ok(()));
        assert!(
            start.elapsed() < Duration::from_secs(1),
            "the second signal returns the consume promptly"
        );
        assert_eq!(
            driver.joint_finish,
            JointFinishDriver::Abandoned,
            "the signal escalates the Published wait"
        );
        assert!(driver.semantic.is_none(), "the escalation holds its lane");
        assert_eq!(polls.get(), 1, "one poll, then the escalation");
        assert_eq!(
            driver.joint_first_error.as_deref(),
            Some("second stop during joint finish"),
            "the escalation keeps its cause"
        );
        assert_eq!(
            gaps(&mut driver)
                .iter()
                .filter(|(subject, _)| subject == "joint finish held for exit")
                .count(),
            1,
            "the escalation discloses its hold: {:?}",
            gaps(&mut driver)
        );
    }

    #[test]
    fn consume_published_lane_past_run_deadline_completes_without_gap() {
        // The run deadline (--duration end) is not a stop budget: a
        // Published detach that needs several 10 ms steps still joins
        // past the deadline with no hold, no gap and no first error.
        // Only the second operator signal interrupts the wait, like
        // the legacy owned-detach wait.
        let mut coordinator = coordinator();
        let headless = headless_display();
        let mut driver = driver_with_display(&mut coordinator, headless.display);
        let (mut io, _gate) = WindDownIo::gated();
        io.release_after_polls = Some(3);
        let polls = Rc::clone(&io.polls);
        let mut lane = joint_lane(io, true);
        lane.set_test_joint_frame(false);
        driver.semantic = Some(lane);
        driver.joint_finish = JointFinishDriver::Published;
        driver.deadline = Some(Instant::now() - Duration::from_secs(1));
        let stop = std::cell::Cell::new(false);
        let stop_now = || stop.get();
        let clock = super::tests::consume_clock(&stop_now);
        let outcome = ClassicOutcome {
            stopped: None,
            error: None,
            zero_pass: None,
            retained: None,
        };
        let start = Instant::now();
        let (_stopped, _error, _zero) = driver.consume_outcome(outcome, &clock, &mut |_, _| Ok(()));
        assert!(
            start.elapsed() < Duration::from_secs(1),
            "the past-deadline wait joins promptly"
        );
        assert_eq!(
            polls.get(),
            3,
            "three steps run past the deadline without a hold"
        );
        assert!(
            driver.semantic.is_none(),
            "the joined lane releases at the consume"
        );
        assert_eq!(
            driver.joint_finish,
            JointFinishDriver::Published,
            "no hold abandons the joined finish"
        );
        assert!(
            driver.joint_first_error.is_none(),
            "no error on a clean join past the deadline"
        );
        assert!(
            gaps(&mut driver).iter().all(|(subject, _)| {
                subject != "joint finish held for exit" && subject != "joint wound-down failed"
            }),
            "a normal stop past the deadline gains no gap: {:?}",
            gaps(&mut driver)
        );
    }

    #[test]
    fn consume_released_published_lane_completes_without_gap() {
        // Control: a Published detach that joins completes through
        // the terminal consume with no hold and no gap.
        let mut coordinator = coordinator();
        let headless = headless_display();
        let mut driver = driver_with_display(&mut coordinator, headless.display);
        let (io, gate) = WindDownIo::gated();
        let polls = Rc::clone(&io.polls);
        let mut lane = joint_lane(io, true);
        lane.set_test_joint_frame(false);
        driver.semantic = Some(lane);
        driver.joint_finish = JointFinishDriver::Published;
        release_gate(&gate);
        let stop = std::cell::Cell::new(false);
        let stop_now = || stop.get();
        let clock = super::tests::consume_clock(&stop_now);
        let outcome = ClassicOutcome {
            stopped: None,
            error: None,
            zero_pass: None,
            retained: None,
        };
        let (_stopped, _error, _zero) = driver.consume_outcome(outcome, &clock, &mut |_, _| Ok(()));
        assert!(
            driver.semantic.is_none(),
            "the joined lane releases at the consume"
        );
        assert_eq!(polls.get(), 1, "one poll joins the detach");
        assert!(
            driver.joint_first_error.is_none(),
            "no error on a clean join"
        );
        assert!(
            gaps(&mut driver).iter().all(|(subject, _)| {
                subject != "joint finish held for exit" && subject != "joint wound-down failed"
            }),
            "a quick stop gains no gap: {:?}",
            gaps(&mut driver)
        );
    }

    #[test]
    fn repeated_stop_request_escalates_polling_finish() {
        // A second stop request escalates a begun-but-unfinished
        // Joint finish to the typed exit instead of re-running
        // the stop path.
        let mut coordinator = coordinator();
        let headless = headless_display();
        let mut driver = driver_with_display(&mut coordinator, headless.display);
        driver.semantic = Some(joint_lane(WindDownIo::completing(), false));
        driver.joint_finish = JointFinishDriver::Polling;
        driver.on_stop_requested();
        assert_eq!(
            driver.joint_finish,
            JointFinishDriver::Polling,
            "the first stop keeps a begun finish"
        );
        assert!(driver.semantic.is_some(), "the first stop keeps the lane");
        driver.on_stop_requested();
        assert_eq!(
            driver.joint_finish,
            JointFinishDriver::Abandoned,
            "the second stop escalates the begun finish"
        );
        assert!(driver.semantic.is_none(), "the escalation holds its lane");
        assert_eq!(
            driver.joint_first_error.as_deref(),
            Some("second stop during joint finish"),
            "the escalation keeps its cause"
        );
        assert_eq!(
            gaps(&mut driver)
                .iter()
                .filter(|(subject, _)| subject == "joint finish held for exit")
                .count(),
            1,
            "the escalation discloses its hold: {:?}",
            gaps(&mut driver)
        );
    }

    #[test]
    fn joint_abandon_commit_failure_is_kept_as_a_gap() {
        // The abandon's best-effort terminal commit fails: the
        // abandon reason stays the first error, and the commit
        // failure is kept as its own gap instead of dropped.
        use crate::inventory_semantics::SemanticRefusal;
        let mut coordinator = coordinator();
        let headless = headless_display();
        let mut driver = driver_with_display(&mut coordinator, headless.display);
        let mut lane = joint_lane(WindDownIo::completing(), false);
        lane.note_joint_finish_failure(SemanticRefusal::Unavailable);
        driver.semantic = Some(lane);
        FAIL_TERMINAL_PUBLICATION.with(|fail| fail.set(true));
        driver.on_stop_requested();
        assert_eq!(
            driver.joint_finish,
            JointFinishDriver::Abandoned,
            "the abandon proceeds past the commit failure"
        );
        assert_eq!(
            driver.joint_first_error.as_deref(),
            Some("joint finish disposition required"),
            "the abandon reason stays the first error"
        );
        let commits: Vec<(String, String)> = gaps(&mut driver)
            .into_iter()
            .filter(|(subject, _)| subject == "joint abandon commit failed")
            .collect();
        assert_eq!(
            commits.len(),
            1,
            "the commit failure is kept: {:?}",
            gaps(&mut driver)
        );
        assert!(
            commits[0]
                .1
                .contains("injected terminal publication refusal"),
            "the gap carries the commit error text: {:?}",
            commits[0].1
        );
    }

    #[test]
    fn stop_drains_service_without_installing() {
        use crate::attach::selected_detailed::SelectedPreparationFailure;
        let mut coordinator = coordinator();
        let headless = headless_display();
        let mut driver = driver_with_display(&mut coordinator, headless.display);
        queue_request(driver.display.as_mut().expect("display"));
        let request = driver
            .display
            .as_mut()
            .expect("display")
            .take_promotion_request()
            .expect("mailbox holds it");
        let capacity = driver
            .coordinator
            .reserve_promotion_install()
            .expect("capacity reserves");
        driver
            .lifecycle
            .start(request, capacity, Box::new(StubActivationSource), || {
                PreparationOutcome::Failed(SelectedPreparationFailure::scripted_settled())
            })
            .expect("service starts");
        driver.on_stop_requested();
        // The stop polls once; later hooks drain the service.
        tick_until_idle(&mut driver);
        assert!(driver.lifecycle.is_idle());
        assert!(driver.pending_install.is_none());
        assert!(driver.semantic.is_none(), "teardown never installs");
        assert_eq!(
            driver.display.as_ref().expect("display").promotion_state(),
            PromotionState::Ended(PromotionEnd::RunStopped)
        );
    }

    #[test]
    fn quiet_tick_without_display_is_noop() {
        let mut coordinator = coordinator();
        let mut driver = ClassicDriver {
            coordinator: &mut coordinator,
            inventory_scope: None,
            scope: InventoryRunScope::Pid(std::process::id()),
            cgroup: None,
            max_scan_pids: None,
            guard: UnavailableImageGuard,
            deadline: None,
            attach_backend: crate::attach::BackendSelection::Auto,
            identity: None,
            display: None,
            semantic: None,
            semantic_staged: false,
            seated_summary: None,
            second_signal: None,
            lifecycle: crate::inventory_promotion::lifecycle::SelectedLifecycleService::new(),
            completion_source: None,
            pending_install: None,
            installed_promotion: None,
            retiring: None,
            joint_finish: JointFinishDriver::NotBegun,
            stop_requested: false,
            joint_first_error: None,
            suspended: false,
            joint_commit_pending: false,
            joint_tick_refusal: None,
            joint_commit_retries: 0,
            #[cfg(test)]
            terminal_seq_calls: 0,
            #[cfg(test)]
            reclaim_calls: Vec::new(),
            #[cfg(test)]
            joint_begin_calls: 0,
            #[cfg(test)]
            joint_step_calls: 0,
            #[cfg(test)]
            joint_commit_polls: 0,
            #[cfg(test)]
            take_promotion_work_calls: 0,
            #[cfg(test)]
            drive_pending_install_calls: 0,
            #[cfg(test)]
            service_caller_metadata_calls: 0,
            #[cfg(test)]
            commit_calls: 0,
        };
        driver.on_tick();
        assert!(driver.lifecycle.is_idle());
        assert!(gaps(&mut driver).is_empty(), "quiet tick records nothing");
    }

    // `#[path]` cannot escape an inline module's virtual directory,
    // so the Driver home file joins through `include!` under the
    // contract's `joint_cells` module (§8.7).
    mod joint_cells {
        include!("inventory_joint_cells_tests.rs");
    }
}

#[cfg(test)]
mod seal_readiness_tests {
    //! The seal-readiness line (T6): the startup notes one stderr
    //! line when the semantic lane seals, so users and scripts know
    //! from when newly started programs are covered. The scripted
    //! startups drive the real match arms without manifests or BPF.
    use super::promotion_driver_tests::{WindDownIo, joint_lane};
    use super::*;
    use crate::discovery::engine::inventory_coordinator::semantics::{
        AttestedSubset, SubsetPreparation,
    };
    use crate::inventory_semantics::SemanticRefusal;

    /// The exact seal line, pinned as a literal: the wording is the
    /// contract with users and scripts, independent of the builder.
    const SEAL_LINE: &str = "p11scope: semantic lane ready; mechanisms and API results are recorded from now on (key operations: planned for 0.5.1)";

    fn coordinator() -> InventoryCoordinator<OsProcessSource> {
        InventoryCoordinator::new(
            Scope::Pid(std::process::id()),
            crate::discovery::hooks::HookRegistry::builtin(),
            Vec::new(),
            OsProcessSource,
            crate::discovery::caller_registry::RegistryLimits::default_limits(),
        )
        .expect("test coordinator builds")
    }

    /// A scripted subset, like the wind-down lane's: the preparations
    /// carry real subset values without attesting manifests.
    fn scripted_subset() -> AttestedSubset {
        use crate::discovery::identity::PinnedObjectId;
        let slot = crate::plan::Slot {
            index: 0,
            descriptor_index: crate::kinds::function_id("C_SignInit").unwrap() + 1,
            object: PinnedObjectId(0),
            object_path: "/stub-provider.so".into(),
            file_offset: 0x1200,
            names: vec!["C_SignInit".into()],
            aliased: false,
            semantics: crate::kinds::descriptor("C_SignInit").unwrap(),
            semantic_authorized: true,
            semantic_ambiguous: false,
            fork_safe: true,
            module_ids: vec![crate::plan::ModuleId(0)],
        };
        AttestedSubset::scripted(
            crate::plan::AttachPlan::from_slots(vec![slot]),
            crate::discovery::identity::PinnedObjects::empty(),
            std::collections::BTreeMap::from([(
                PinnedObjectId(0),
                std::collections::BTreeSet::from([0]),
            )]),
        )
    }

    fn some_preparation() -> SubsetPreparation {
        SubsetPreparation {
            subset: Some(scripted_subset()),
            refusals: Vec::new(),
        }
    }

    fn gaps_for_subject(
        coordinator: &mut InventoryCoordinator<OsProcessSource>,
        subject: &str,
    ) -> Vec<(String, String)> {
        coordinator.registry_mut().publish();
        coordinator
            .registry()
            .gaps()
            .iter()
            .map(|gap| (gap.subject.clone(), gap.reason.clone()))
            .filter(|(candidate, _)| candidate == subject)
            .collect()
    }

    #[test]
    fn seal_line_present_once_on_sealed_path() {
        // Isolate from lines other tests on this thread noted: the
        // recorder is thread-local and every read drains.
        take_sealed_for_test();
        // A live start that seals notes exactly one line with the
        // exact wording.
        let mut coordinator = coordinator();
        let scope = Scope::Pid(std::process::id());
        let lane = seal_startup_test::with(
            vec![some_preparation(), some_preparation()],
            Some(Ok(joint_lane(WindDownIo::completing(), false))),
            || {
                start_semantic_lane(
                    &mut coordinator,
                    &scope,
                    crate::attach::BackendSelection::Auto,
                )
            },
        );
        assert!(lane.is_some(), "the scripted seal seats a lane");
        assert_eq!(
            take_sealed_for_test(),
            vec![SEAL_LINE.to_string()],
            "exactly one seal line with the exact wording"
        );
    }

    #[test]
    fn seal_line_absent_without_manifest_subset() {
        // Isolate from lines other tests on this thread noted: the
        // recorder is thread-local and every read drains.
        take_sealed_for_test();
        // No manifests: the real mint yields no subset, no lane seats,
        // and no seal line prints. (The run also short-circuits empty
        // manifests before the startup; this pins the function arm a
        // line at the top would break.)
        let mut coordinator = coordinator();
        let scope = Scope::Pid(std::process::id());
        let lane = start_semantic_lane(
            &mut coordinator,
            &scope,
            crate::attach::BackendSelection::Auto,
        );
        assert!(lane.is_none(), "no subset seats no lane");
        assert!(
            take_sealed_for_test().is_empty(),
            "no seal without a subset"
        );
    }

    #[test]
    fn seal_line_absent_when_attach_subset_refused() {
        // Isolate from lines other tests on this thread noted: the
        // recorder is thread-local and every read drains.
        take_sealed_for_test();
        // The attach mint refuses: no lane seats, the refusal's own
        // gap stays, and no seal line prints.
        let mut coordinator = coordinator();
        let scope = Scope::Pid(std::process::id());
        let lane = seal_startup_test::with(
            vec![SubsetPreparation {
                subset: None,
                refusals: vec![SemanticRefusal::Unattested],
            }],
            None,
            || {
                start_semantic_lane(
                    &mut coordinator,
                    &scope,
                    crate::attach::BackendSelection::Auto,
                )
            },
        );
        assert!(lane.is_none(), "a refused mint seats no lane");
        assert!(
            take_sealed_for_test().is_empty(),
            "no seal line on a refused mint"
        );
        assert_eq!(
            gaps_for_subject(&mut coordinator, "semantic subset refused").len(),
            1,
            "the refusal's own disclosure stays"
        );
    }

    #[test]
    fn seal_line_absent_when_conversion_subset_refused() {
        // Isolate from lines other tests on this thread noted: the
        // recorder is thread-local and every read drains.
        take_sealed_for_test();
        // The attach mint succeeds but the conversion envelope
        // refuses: no lane seats and no seal line prints.
        let mut coordinator = coordinator();
        let scope = Scope::Pid(std::process::id());
        let lane = seal_startup_test::with(
            vec![
                some_preparation(),
                SubsetPreparation {
                    subset: None,
                    refusals: vec![SemanticRefusal::Unattested],
                },
            ],
            None,
            || {
                start_semantic_lane(
                    &mut coordinator,
                    &scope,
                    crate::attach::BackendSelection::Auto,
                )
            },
        );
        assert!(lane.is_none(), "a refused envelope seats no lane");
        assert!(
            take_sealed_for_test().is_empty(),
            "no seal line on a refused envelope"
        );
        assert_eq!(
            gaps_for_subject(&mut coordinator, "semantic subset refused").len(),
            1,
            "the refusal's own disclosure stays"
        );
    }

    #[test]
    fn seal_line_absent_when_start_refuses() {
        // Isolate from lines other tests on this thread noted: the
        // recorder is thread-local and every read drains.
        take_sealed_for_test();
        // The live start is attempted and refused: the shell fallback
        // seats with the refusal's own disclosure, and no seal line
        // prints. (A line before the seal would fail this twin.)
        let mut coordinator = coordinator();
        let scope = Scope::Pid(std::process::id());
        let lane = seal_startup_test::with(
            vec![some_preparation(), some_preparation(), some_preparation()],
            Some(Err(SemanticRefusal::Unavailable)),
            || {
                start_semantic_lane(
                    &mut coordinator,
                    &scope,
                    crate::attach::BackendSelection::Auto,
                )
            },
        );
        let lane = lane.expect("the shell fallback seats");
        assert!(!lane.is_live(), "the fallback owns no session");
        assert!(
            take_sealed_for_test().is_empty(),
            "no seal line on a refused start"
        );
        assert_eq!(
            gaps_for_subject(&mut coordinator, "semantic lane unavailable").len(),
            1,
            "the refusal's own disclosure stays"
        );
    }
}
