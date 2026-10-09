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
use crate::discovery::engine::inventory::UnavailableImageGuard;
use crate::discovery::engine::inventory_coordinator::{
    InventoryCoordinator, InventoryScope, PassReport,
};
use crate::discovery::hooks::HookRegistry;
use crate::discovery::native_binding::NativeIdentity;
#[cfg(test)]
use crate::inventory_capture::run_classic;
use crate::inventory_capture::{
    CgroupJobFailure, CollectJob, CollectedPass, FacadeLane, LaneSummary, LaneWindows, LoopClock,
    NativeLane, PassDriver, Publish, SERVICE_TICK, run_classic_finalizing,
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
    EdgeEmitter, EventWriter, GapEmitter, caller_event_payload, ended_payload, pass_payload,
    started_payload,
};
#[cfg(test)]
use crate::inventory_output::WriterStdout;
use crate::inventory_output::{FdStdout, FinalStdout, StdoutFailureReason, StdoutResult};
use crate::inventory_present::{DASHBOARD_ACTIVITY_WINDOW_NS, Presentation, render_snapshot};
use crate::output::AtomicFile;
use crate::process::PidPin;
use anyhow::{Context as _, Result};
use std::collections::BTreeMap;
use std::io::Write as _;
use std::path::{Path, PathBuf};
use std::time::{Duration, Instant};

const DOC_ID: &str = "p11scope/inventory/v1";

/// Rescan interval inside a `--duration` observation window.
const POLL_INTERVAL: Duration = Duration::from_secs(1);

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

/// The event prologue shared by classic and dashboard startup.
fn start_event_log<Source: ProcessSource>(
    stream: &mut EventLogState,
    coordinator: &InventoryCoordinator<Source>,
    scope_label: &str,
    started_ns: u64,
) -> Option<anyhow::Error> {
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
) -> Result<i32> {
    if !manifests.is_empty() && capture == CaptureMode::Scan {
        anyhow::bail!("--manifest requires --capture auto or native");
    }
    let scope: crate::cli::ScopeArg = scope.into();
    let endpoint_budget = inventory_endpoint_budget(max_endpoints).map_err(anyhow::Error::msg)?;
    let stdout_tty = crate::inventory_dashboard::fd_is_tty(1);
    // SIGINT/SIGTERM/SIGHUP end the loop, classic or dashboard, through
    // its stop path (the final sinks are still written).
    let stop = StopFlag::install();
    let signals = || stop.signal_count();
    let mut stdout = FdStdout::new(1, &signals);
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
        stop,
        outputs_attempted,
        stdout_tty,
        stdout,
        terminal,
        request,
        None,
        event_fault,
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
    stop: &dyn Fn() -> bool,
    outputs_attempted: &dyn Fn(),
    stdout_tty: bool,
    stdout: &mut dyn FinalStdout,
    terminal: &DashboardIo,
    request: DiagnosticRequest<'_>,
    operator_stop_source: Option<std::sync::Arc<std::sync::atomic::AtomicUsize>>,
    #[cfg(test)] event_fault: Option<crate::inventory_events::EventFault>,
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
        .then(|| CgroupDriverState::new(deadline_for_duration(duration), operator_stop_source));
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
        display: None,
    };
    let clock = LoopClock {
        deadline,
        stop,
        interval: POLL_INTERVAL,
        tick: SERVICE_TICK,
        collection_tick: SERVICE_TICK,
    };
    let running = run_classic_finalizing(
        &mut driver,
        lane,
        &clock,
        initial_error,
        &mut |driver: &mut ClassicDriver<'_>, point| {
            let coordinator = &*driver.coordinator;
            match point {
                Publish::Pass { report, now_ns } => {
                    for line in progress_lines(coordinator, report) {
                        inventory_diagnostic(&line);
                    }
                    if let Some(error) = stream.attempt("pass publication", |writer| {
                        let presentation =
                            stream_presentation(coordinator, &scope_label, started_ns, now_ns);
                        emit_pass_events(writer, &mut stream_state, report, &presentation, now_ns)
                    }) {
                        let _ =
                            crate::sink::try_stderr_line(&crate::render::escape_controls(&error));
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
                    if let Some(error) = stream.attempt("stop publication", |writer| {
                        let presentation =
                            stream_presentation(coordinator, &scope_label, started_ns, now_ns);
                        emit_stop_events(
                            writer,
                            &mut stream_state,
                            events,
                            coordinator.passes(),
                            &presentation,
                            now_ns,
                        )
                    }) {
                        let _ =
                            crate::sink::try_stderr_line(&crate::render::escape_controls(&error));
                    }
                }
            }
            Ok(())
        },
    );
    let stopped = running.stopped;
    let capture_error = running.error;
    drop(driver);
    begin_scan_stdout(stdout, stopped.is_some());
    if let Some(stopped) = &stopped {
        inventory_diagnostic(&stop_line(&stopped.summary));
    }
    let ended_ns = now_ns();
    let passes = coordinator.passes();
    let presentation =
        Presentation::capture(&coordinator, &scope_label, started_ns, ended_ns, passes);
    // Output attempts first; only then may an unsettled retirement's drop
    // block (invariant 5), and a further signal then exits at once
    // (R-C51-4).
    let previously_reported = stream.first_error().map(str::to_string);
    let diagnostic_outcome = diagnostic_outcome(
        native_available,
        capture_error.is_some(),
        diagnostics.is_some() && stop(),
    );
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
    );
    outcome.notices(previously_reported.as_deref(), &mut |line| {
        let _ = crate::sink::try_stderr_line(line);
    });
    if let Some(error) = capture_error {
        return Err(error);
    }
    Ok(outcome.exit_code())
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
    let presentation = Presentation::capture(
        coordinator,
        scope_label,
        started_ns,
        now_ns(),
        coordinator.passes(),
    );
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
}

impl CgroupDriverState {
    fn new(
        deadline: Option<Instant>,
        source: Option<std::sync::Arc<std::sync::atomic::AtomicUsize>>,
    ) -> Self {
        let control = crate::scope::inventory_cgroup::CollectionControl::new(deadline);
        let control = match source {
            Some(source) => control.with_operator_stop_source(source),
            None => control,
        };
        Self {
            continuation: Some(crate::scope::inventory_cgroup::CgroupWalkState::default()),
            limits: crate::scope::inventory_cgroup::CgroupWalkLimits::default(),
            control,
            deadline,
        }
    }
}

/// The classic loop's pass side over the production coordinator.
struct ClassicDriver<'a> {
    coordinator: &'a mut InventoryCoordinator<OsProcessSource>,
    inventory_scope: Option<InventoryScope>,
    scope: InventoryRunScope,
    cgroup: Option<CgroupDriverState>,
    max_scan_pids: Option<usize>,
    guard: UnavailableImageGuard,
    deadline: Option<Instant>,
    /// The interactive dashboard's display (C5.3): it draws on the loop's
    /// service ticks and takes the pass warnings into its log tail.
    display: Option<Display>,
}

impl ClassicDriver<'_> {
    /// A pass warning: stderr on the classic path; under the dashboard
    /// (which must never scribble beside its screen) the log tail, kept
    /// for stderr past the screen.
    fn warn(&mut self, warning: &str) {
        match self.display.as_mut() {
            Some(display) => display.warn(warning),
            None => inventory_diagnostic(warning),
        }
    }
}

impl PassDriver<PidPin> for ClassicDriver<'_> {
    type Host = InventoryCoordinator<OsProcessSource>;

    fn host(&mut self) -> &mut Self::Host {
        self.coordinator
    }

    fn collector(&mut self) -> crate::inventory_capture::CollectJob {
        if let Some(cgroup) = &mut self.cgroup {
            let task = cgroup
                .continuation
                .take()
                .ok_or(CgroupJobFailure::Preparation)
                .and_then(|state| {
                    self.coordinator
                        .cgroup_collector(
                            state,
                            cgroup.limits.clone(),
                            cgroup.control.clone(),
                            self.max_scan_pids,
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
            Some(scope) => CollectJob::Legacy(Box::new(
                self.coordinator.collector(scope, self.max_scan_pids),
            )),
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
        Ok(report)
    }

    fn commit(&mut self, engine_changed: bool) -> Result<()> {
        self.coordinator.commit_batch(engine_changed).map(|_| ())
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
        Err(error) => return unavailable(coordinator, format!("{error:#}")),
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
) -> FinalOutputOutcome {
    let mut document = render_json_from_presentation(presentation);
    if let Some(summary) = native {
        note_native_observation(&mut document, summary);
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
        // Exact repeat counts, then the final edge sweep, then ended:
        // preserve healthy ordering and the sweep's retention reservation.
        stream_state
            .gaps
            .emit(writer, &presentation.gaps, true, presentation.ended_ns)?;
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
        let (_, payload) = stream_state.edges.settle_ended(
            writer,
            &presentation.edges,
            swept.unretained,
            presentation.ended_ns,
            |unretained| {
                let mut payload = ended_payload(presentation, presentation.ended_ns, writer);
                payload["edge_events"] = swept.emitted.into();
                payload["edges_unretained"] = unretained.into();
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
    );
    if let Some(diagnostics) = diagnostics {
        outcome.diagnostics_failed =
            diagnostics.finish(coordinator, diagnostic_outcome, second_signal, notice);
    }
    outcome
}

/// Bytes the `ended` line may take: its payload as measured now plus
/// [`ENDED_TAIL_SLACK`] (the envelope and counters that may still grow).
fn ended_tail(presentation: &Presentation, writer: &EventWriter) -> u64 {
    let mut payload = ended_payload(presentation, presentation.ended_ns, writer);
    payload["edge_events"] = u64::MAX.into();
    payload["edges_unretained"] = u64::MAX.into();
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
/// limit) so only changes are streamed (DR-C5-EDGE).
pub(crate) struct StreamState {
    gaps: GapEmitter,
    edges: EdgeEmitter,
    emitted_suppressed: u64,
    /// Unbound witness rows per (module, reason) already counted on a
    /// pass marker.
    emitted_unbound: BTreeMap<(ModuleId, &'static str), u64>,
}

impl StreamState {
    pub(crate) fn new() -> Self {
        Self {
            gaps: GapEmitter::new(),
            edges: EdgeEmitter::new(),
            emitted_suppressed: 0,
            emitted_unbound: BTreeMap::new(),
        }
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
/// meaning to snapshot gaps (same subject/reason/budget).
fn emit_pass_events(
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
    let fresh = state.gaps.emit(writer, &presentation.gaps, false, now_ns)?;
    let edges = state.edges.emit(
        writer,
        &presentation.edges,
        &identities,
        presentation.budgets.edges_limit,
        now_ns,
    )?;
    let suppressed_delta = presentation
        .gaps_suppressed
        .saturating_sub(state.emitted_suppressed);
    state.emitted_suppressed = presentation.gaps_suppressed;
    let mut payload = pass_payload(report, presentation, fresh, suppressed_delta);
    payload["edge_events"] = edges.emitted.into();
    payload["edge_events_deferred"] = edges.deferred.into();
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
) -> (Presentation, Presentation) {
    let display = Presentation::capture_dashboard(
        coordinator,
        scope_label,
        started_ns,
        now_ns,
        coordinator.passes(),
        now_ns,
        DASHBOARD_ACTIVITY_WINDOW_NS,
    );
    (
        stream_presentation(coordinator, scope_label, started_ns, now_ns),
        display,
    )
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
) -> (Presentation, Option<String>) {
    let (stream_view, display_view) =
        dashboard_pass_views(coordinator, scope_label, started_ns, now_ns);
    let error = stream.attempt("pass publication", |writer| {
        emit_pass_events(writer, state, report, &stream_view, now_ns)
    });
    (display_view, error)
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
    } = run;
    let quit = display.quit_flag();
    let mut stream_state = StreamState::new();
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
        display: Some(display),
    };
    let ending = || stop() || quit.get();
    let clock = LoopClock {
        deadline: Some(deadline.unwrap_or_else(unbounded_dashboard_deadline)),
        stop: &ending,
        interval: RESCAN_INTERVAL,
        tick: SERVICE_TICK,
        collection_tick: SERVICE_TICK,
    };
    let running = run_classic_finalizing(
        &mut driver,
        lane,
        &clock,
        initial_error,
        &mut |driver: &mut ClassicDriver<'_>, point| {
            match point {
                Publish::Pass { report, now_ns } => {
                    let coordinator = &*driver.coordinator;
                    let (display_view, event_error) = dashboard_stream_pass(
                        &mut stream,
                        &mut stream_state,
                        report,
                        coordinator,
                        &scope_label,
                        started_ns,
                        now_ns,
                    );
                    if let Some(display) = driver.display.as_mut() {
                        if let Some(error) = event_error {
                            display.notice(&crate::render::escape_controls(&error));
                        }
                        // The pass line is progress; its events and gaps
                        // must outlive the screen.
                        for (index, line) in progress_lines(coordinator, report).iter().enumerate()
                        {
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
                    if let Some(error) = stream.attempt("stop publication", |writer| {
                        let presentation =
                            stream_presentation(coordinator, &scope_label, started_ns, now_ns);
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
        },
    );
    let stopped = running.stopped;
    let capture_error = running.error;
    begin_scan_stdout(stdout, stopped.is_some());
    let mut display = driver
        .display
        .take()
        .expect("the dashboard driver keeps its display");
    drop(driver);
    display.restore();
    let failure = display.take_failure();
    if let Some(stopped) = &stopped {
        display.notice(&stop_line(&stopped.summary));
    }
    let passes = coordinator.passes();
    let ended_ns = now_ns();
    let presentation =
        Presentation::capture(&coordinator, &scope_label, started_ns, ended_ns, passes);
    // Output attempts first (R-C51-4), silent text: the live view showed it.
    let previously_reported = stream.first_error().map(str::to_string);
    let diagnostic_outcome = diagnostic_outcome(
        native_available,
        capture_error.is_some(),
        diagnostics.is_some() && ending(),
    );
    let display_notices = std::cell::RefCell::new(&mut display);
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
                &mut coordinator,
                diagnostics,
                diagnostic_outcome,
                second_signal,
                &mut |line| display_notices.borrow_mut().notice(line),
            )
        },
        outputs_attempted,
        &mut |line| display_notices.borrow_mut().notice(&line),
    );
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
    for line in dashboard_account_lines(passes, &display.account()) {
        display.notice(&line);
    }
    if let Some(slot) = &terminal.account {
        slot.set(Some(display.account()));
    }
    if let Some(error) = capture_error {
        return Err(error);
    }
    // Sink errors use the bounded notices above, including a simultaneous
    // display error. Preserve the existing display-only error policy.
    if outcome.exit_code() == 0
        && let Some(error) = failure
    {
        return Err(anyhow::anyhow!(error)).context("writing the dashboard terminal");
    }
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

fn caller_json(caller: &crate::inventory_present::CallerView) -> serde_json::Value {
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
    serde_json::json!({
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
    })
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
        },
        "budgets": budgets_json(&presentation.budgets),
        "callers": presentation.callers.iter().map(caller_json).collect::<Vec<_>>(),
        "modules": presentation.modules.iter().map(module_json).collect::<Vec<_>>(),
        "edges": presentation.edges.iter().map(edge_json).collect::<Vec<_>>(),
        "instances": presentation.instances.iter().map(instance_json).collect::<Vec<_>>(),
        "semantic_edges": presentation.semantic_edges.iter().map(instance_semantic_json).collect::<Vec<_>>(),
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
        let (stream_view, display_view) =
            dashboard_pass_views(coordinator, "pid:83000", started, now);
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
}

#[cfg(test)]
#[path = "inventory_privileged_tests.rs"]
mod privileged_tests;

#[cfg(test)]
#[path = "inventory_edge_stream_tests.rs"]
mod edge_stream_tests;

#[cfg(test)]
#[path = "inventory_diagnostics_runtime_tests.rs"]
mod diagnostics_runtime_tests;

#[cfg(test)]
#[path = "inventory_cgroup_runtime_tests.rs"]
mod cgroup_runtime_tests;
