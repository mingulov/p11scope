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
use crate::inventory_capture::{
    FacadeLane, LaneSummary, LaneWindows, LoopClock, NativeLane, PassDriver, Publish, SERVICE_TICK,
    run_classic,
};
use crate::inventory_dashboard::{
    DashboardIo, Display, DisplayAccount, RESCAN_INTERVAL, RESTORE_RETRY_BUDGET, StderrRoute,
    StopFlag,
};
use crate::inventory_events::{
    EdgeEmitter, EventWriter, GapEmitter, caller_event_payload, ended_payload, pass_payload,
    started_payload,
};
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
) -> Result<i32> {
    let stdout_tty = crate::inventory_dashboard::fd_is_tty(1);
    // SIGINT/SIGTERM/SIGHUP end the loop, classic or dashboard, through
    // its stop path (the final sinks are still written).
    let stop = StopFlag::install();
    run_with_writer(
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
        &|| stop.stopped(),
        &|| stop.exit_on_next_signal(),
        stdout_tty,
        &mut std::io::stdout().lock(),
    )
}

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
    report_written: &dyn Fn(),
    stdout_tty: bool,
    stdout: &mut dyn std::io::Write,
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
        report_written,
        stdout_tty,
        stdout,
        &DashboardIo::stdio(),
    )
}

/// `run_with_writer` with the interactive dashboard's terminal named
/// (production: stdout and stdin; the privileged slow-terminal cell: a
/// pty).
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
    report_written: &dyn Fn(),
    stdout_tty: bool,
    stdout: &mut dyn std::io::Write,
    terminal: &DashboardIo,
) -> Result<i32> {
    // DR-K8S-1: the kernel-side PID filter numbers tasks in the initial PID
    // namespace; a mismatched observer's --pid would match nothing, so it
    // is refused by name before anything is opened or scanned.
    let numbering = crate::pidns::numbering();
    match scope {
        InspectScope::Pid(pid) => {
            crate::pidns::require_numbering_agrees(numbering, &format!("inventory --pid {pid}"))?;
        }
        InspectScope::System => {
            if let Some(warning) = crate::pidns::nested_warning(numbering) {
                let _ = writeln!(std::io::stderr(), "{warning}");
            }
        }
    }
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
    let mut stream = match event_log {
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
    let (inventory_scope, engine_scope, scope_label) = match scope {
        InspectScope::Pid(pid) => (
            InventoryScope::Pid(pid),
            Scope::Pid(pid),
            format!("pid:{pid}"),
        ),
        InspectScope::System => (InventoryScope::System, Scope::System, "system".to_string()),
    };
    let started_ns = now_ns();
    let mut coordinator = InventoryCoordinator::new(
        engine_scope,
        hooks.clone(),
        modules.to_vec(),
        OsProcessSource,
        registry_limits(max_gaps),
    )?;
    // F4 (review): a document with no `exact` flag still says, as a
    // scope-level gap, that /proc PIDs are not the kernel's here.
    stage_numbering_gap(&mut coordinator, numbering);
    // The scan lane stages no usage coverage: every edge reads
    // `unknown (scan only)`. The native lane stages per-edge coverage
    // notes and witnesses; `auto` falls back to scan with a named gap.
    let lane = open_native_lane(capture, attach_backend, scope, &mut coordinator)?;
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
                    report_written,
                    stdout,
                    terminal,
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
        eprintln!(
            "p11scope: --dashboard {why}; degraded to {} (no ANSI emitted)",
            if json {
                "the JSON document"
            } else {
                "pager snapshots"
            }
        );
    }
    if let Some(writer) = stream.as_mut() {
        let prologue = Presentation::capture(
            &coordinator,
            &scope_label,
            started_ns,
            started_ns,
            0,
            started_ns,
            0,
        );
        writer
            .append(
                "started",
                started_payload(&scope_label, started_ns, &prologue),
                started_ns,
            )
            .map_err(|error| anyhow::anyhow!("{error}"))?;
    }
    let mut stream_state = StreamState::new();
    let deadline = deadline_for_duration(duration);
    let mut driver = ClassicDriver {
        coordinator: &mut coordinator,
        inventory_scope: &inventory_scope,
        scope,
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
    let stopped = run_classic(
        &mut driver,
        lane,
        &clock,
        &mut |driver: &mut ClassicDriver<'_>, point| {
            let coordinator = &*driver.coordinator;
            match point {
                Publish::Pass { report, now_ns } => {
                    for line in progress_lines(coordinator, report) {
                        eprintln!("{line}");
                    }
                    if let Some(writer) = stream.as_mut() {
                        let presentation =
                            stream_presentation(coordinator, &scope_label, started_ns, now_ns);
                        emit_pass_events(writer, &mut stream_state, report, &presentation, now_ns)
                            .map_err(|error| anyhow::anyhow!("{error}"))?;
                    }
                }
                Publish::Retiring {
                    attached,
                    links,
                    budget,
                } => eprintln!(
                    "p11scope: stopping: detaching the native probes of {attached} endpoints \
                     in {links} links (up to {} s)",
                    budget.as_secs()
                ),
                Publish::Stop { events, now_ns } => {
                    if let Some(writer) = stream.as_mut() {
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
                        .map_err(|error| anyhow::anyhow!("{error}"))?;
                    }
                }
            }
            Ok(())
        },
    )?;
    if let Some(stopped) = &stopped {
        eprintln!("{}", stop_line(&stopped.summary));
    }
    let ended_ns = now_ns();
    let passes = coordinator.passes();
    let window_ns = ended_ns.saturating_sub(started_ns);
    let presentation = Presentation::capture(
        &coordinator,
        &scope_label,
        started_ns,
        ended_ns,
        passes,
        ended_ns,
        window_ns,
    );
    // The report first; only then may an unsettled retirement's drop
    // block (invariant 5), and a second signal then exits at once
    // (R-C51-4).
    crate::inventory_capture::finish_native(
        stopped,
        |summary| {
            finish_output(
                sink,
                stream.as_mut(),
                &mut stream_state,
                &presentation,
                json,
                false,
                stdout,
                summary,
            )
        },
        report_written,
        &mut |line| eprintln!("{line}"),
    )
}

/// The classic loop's pass side over the production coordinator.
struct ClassicDriver<'a> {
    coordinator: &'a mut InventoryCoordinator<OsProcessSource>,
    inventory_scope: &'a InventoryScope,
    scope: InspectScope,
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
            None => eprintln!("{warning}"),
        }
    }
}

impl PassDriver<PidPin> for ClassicDriver<'_> {
    type Host = InventoryCoordinator<OsProcessSource>;

    fn host(&mut self) -> &mut Self::Host {
        self.coordinator
    }

    fn collector(&mut self) -> crate::inventory_capture::CollectJob {
        Box::new(
            self.coordinator
                .collector(*self.inventory_scope, self.max_scan_pids),
        )
    }

    fn apply(
        &mut self,
        collected: Result<crate::inspect_system::Catalog>,
        identity: &mut dyn NativeIdentity<PidPin>,
        now_ns: u64,
    ) -> Result<PassReport> {
        let (report, warning) = apply_one_pass(
            self.coordinator,
            collected,
            self.scope,
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
    scope: InspectScope,
    coordinator: &mut InventoryCoordinator<OsProcessSource>,
) -> Result<Option<NativeLane<FacadeLane>>> {
    let unavailable =
        |coordinator: &mut InventoryCoordinator<OsProcessSource>, reason: String| match mode {
            CaptureMode::Native => Err(anyhow::anyhow!(
                "--capture native: the native usage lane cannot run: {reason}"
            )),
            _ => {
                eprintln!(
                    "p11scope: native usage feed unavailable, continuing with the scan lane: {}",
                    crate::render::escape_controls(&reason)
                );
                coordinator.note_scope_gap("native usage feed unavailable".into(), reason);
                Ok(None)
            }
        };
    if mode == CaptureMode::Scan {
        return Ok(None);
    }
    let capture_scope = match scope {
        InspectScope::Pid(pid) => match PidPin::open(pid) {
            Ok(pin) => crate::attach::capture::CaptureScope::Pid(pin),
            Err(reason) => return unavailable(coordinator, reason),
        },
        InspectScope::System => crate::attach::capture::CaptureScope::System,
    };
    let capture = match FacadeLane::prepare(
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
            eprintln!("{}", lane_active_line(&backend));
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

/// The stderr line a native run ends with: what it attached, how its
/// retirement ended, and its settlement.
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
    format!(
        "p11scope: native capture stopped after {} pass{}: {} endpoints attached ({} links), \
         {} failed; {retirement}; settlement {}",
        summary.passes,
        if summary.passes == 1 { "" } else { "es" },
        summary.attached,
        summary.backend.mechanism(),
        summary.failed,
        crate::inventory_capture::SETTLEMENT,
    )
}

/// Final sinks, shared by the classic and dashboard paths: the event
/// stream's `ended` marker, the atomic `-o` report, then stdout (the
/// JSON document under `--json`, the pager snapshot otherwise —
/// silent in dashboard mode, whose live view already showed it).
#[allow(clippy::too_many_arguments)]
fn finish_output(
    sink: Option<AtomicFile>,
    stream: Option<&mut EventWriter>,
    stream_state: &mut StreamState,
    presentation: &Presentation,
    json: bool,
    silent_text: bool,
    stdout: &mut dyn std::io::Write,
    native: Option<&LaneSummary>,
) -> Result<i32> {
    let mut document = render_json_from_presentation(presentation);
    if let Some(summary) = native {
        note_native_observation(&mut document, summary);
    }
    if let Some(writer) = stream {
        // The exact repeat counts and the final edge sweep before `ended`,
        // on every termination path, in the per-pass order (gaps, then
        // edges): the last `gap_repeated` per index and the last
        // `edge_observed` per edge then equal the snapshot. The sweep goes
        // last so nothing but `ended` follows it (its retention bound).
        stream_state
            .gaps
            .emit(writer, &presentation.gaps, true, presentation.ended_ns)
            .map_err(|error| anyhow::anyhow!("{error}"))?;
        // The sweep reserves room for `ended` before it counts, so the
        // `edges_unretained` it reports is final (review R-1).
        let tail = ended_tail(presentation, writer);
        let swept = stream_state
            .edges
            .sweep(
                writer,
                &presentation.edges,
                presentation.budgets.edges_limit,
                presentation.ended_ns,
                tail,
            )
            .map_err(|error| anyhow::anyhow!("{error}"))?;
        // Recounted for the real `ended` line (review R2-1): the sweep's
        // count was taken for the padded reservation.
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
        writer
            .finish(payload, presentation.ended_ns)
            .map_err(|error| anyhow::anyhow!("{error}"))?;
    }
    if let Some(mut sink) = sink {
        serde_json::to_writer_pretty(sink.file(), &document)?;
        // Same bytes stdout carries: the pretty document plus its
        // trailing newline, so the two sinks agree byte for byte.
        sink.file().write_all(b"\n")?;
        sink.file().flush()?;
        sink.commit().map_err(|error| anyhow::anyhow!("{error}"))?;
    }
    if json {
        let text = serde_json::to_string_pretty(&document)?;
        writeln!(stdout, "{text}")?;
    } else if !silent_text {
        write!(stdout, "{}", render_snapshot(presentation))?;
    }
    Ok(0)
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
struct StreamState {
    gaps: GapEmitter,
    edges: EdgeEmitter,
    emitted_suppressed: u64,
    /// Unbound witness rows per (module, reason) already counted on a
    /// pass marker.
    emitted_unbound: BTreeMap<(ModuleId, &'static str), u64>,
}

impl StreamState {
    fn new() -> Self {
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
    for event in &report.events {
        writer.append("caller_event", caller_event_payload(event), now_ns)?;
    }
    let fresh = state.gaps.emit(writer, &presentation.gaps, false, now_ns)?;
    let edges = state.edges.emit(
        writer,
        &presentation.edges,
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
fn emit_stop_events(
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
    scope: InspectScope,
    inventory_scope: InventoryScope,
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
        now_ns,
        now_ns.saturating_sub(started_ns),
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
    let display = Presentation::capture(
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
    stream: Option<&mut EventWriter>,
    state: &mut StreamState,
    report: &PassReport,
    coordinator: &InventoryCoordinator<S>,
    scope_label: &str,
    started_ns: u64,
    now_ns: u64,
) -> Result<Presentation> {
    let (stream_view, display_view) =
        dashboard_pass_views(coordinator, scope_label, started_ns, now_ns);
    if let Some(writer) = stream {
        emit_pass_events(writer, state, report, &stream_view, now_ns)
            .map_err(|error| anyhow::anyhow!("{error}"))?;
    }
    Ok(display_view)
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
    mut stream: Option<EventWriter>,
    stop: &dyn Fn() -> bool,
    report_written: &dyn Fn(),
    stdout: &mut dyn std::io::Write,
    terminal: &DashboardIo,
) -> Result<i32> {
    let DashboardRun {
        scope,
        inventory_scope,
        scope_label,
        started_ns,
        max_scan_pids,
        duration,
        json,
    } = run;
    let quit = display.quit_flag();
    let mut stream_state = StreamState::new();
    if let Some(writer) = stream.as_mut() {
        let prologue = Presentation::capture(
            &coordinator,
            &scope_label,
            started_ns,
            started_ns,
            0,
            started_ns,
            0,
        );
        writer
            .append(
                "started",
                started_payload(&scope_label, started_ns, &prologue),
                started_ns,
            )
            .map_err(|error| anyhow::anyhow!("{error}"))?;
    }
    let deadline = deadline_for_duration(duration);
    let mut driver = ClassicDriver {
        coordinator: &mut coordinator,
        inventory_scope: &inventory_scope,
        scope,
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
    let stopped = run_classic(
        &mut driver,
        lane,
        &clock,
        &mut |driver: &mut ClassicDriver<'_>, point| {
            match point {
                Publish::Pass { report, now_ns } => {
                    let coordinator = &*driver.coordinator;
                    let display_view = dashboard_stream_pass(
                        stream.as_mut(),
                        &mut stream_state,
                        report,
                        coordinator,
                        &scope_label,
                        started_ns,
                        now_ns,
                    )?;
                    if let Some(display) = driver.display.as_mut() {
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
                    // The terminal back first: the stop's notices (and a
                    // detach past the report) are then readable.
                    if let Some(display) = driver.display.as_mut() {
                        display.restore();
                        display.notice(&format!(
                            "p11scope: stopping: detaching the native probes of {attached} \
                             endpoints in {links} links (up to {} s)",
                            budget.as_secs()
                        ));
                    }
                }
                Publish::Stop { events, now_ns } => {
                    if let Some(writer) = stream.as_mut() {
                        let coordinator = &*driver.coordinator;
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
                        .map_err(|error| anyhow::anyhow!("{error}"))?;
                    }
                }
            }
            Ok(())
        },
    )?;
    let mut display = driver
        .display
        .take()
        .expect("the dashboard driver keeps its display");
    display.restore();
    let failure = display.take_failure();
    if let Some(stopped) = &stopped {
        display.notice(&stop_line(&stopped.summary));
    }
    let passes = coordinator.passes();
    for line in dashboard_account_lines(passes, &display.account()) {
        display.notice(&line);
    }
    let ended_ns = now_ns();
    let window_ns = ended_ns.saturating_sub(started_ns);
    let presentation = Presentation::capture(
        &coordinator,
        &scope_label,
        started_ns,
        ended_ns,
        passes,
        ended_ns,
        window_ns,
    );
    // The report first (R-C51-4), silent text: the live view showed it.
    let code = crate::inventory_capture::finish_native(
        stopped,
        |summary| {
            finish_output(
                sink,
                stream.as_mut(),
                &mut stream_state,
                &presentation,
                json,
                true,
                stdout,
                summary,
            )
        },
        report_written,
        &mut |line| display.notice(&line),
    )?;
    // A restore the terminal shed (Ctrl-S then `q`) leaves the shell in
    // the alternate screen: with the report written, it can wait longer.
    display.retry_restore(RESTORE_RETRY_BUDGET);
    if let Some(slot) = &terminal.account {
        slot.set(Some(display.account()));
    }
    if let Some(error) = failure {
        return Err(anyhow::anyhow!(error)).context("writing the dashboard terminal");
    }
    Ok(code)
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
        lines.push(format!(
            "p11scope: pass {}: stage timings: {}",
            report.pass,
            report.timings.ops_line()
        ));
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
                    .unwrap_or(0);
                format!("caller {} admitted (pid {pid})", id.label())
            }
            CallerEvent::Exited { id, reason } => {
                format!(
                    "caller {} exited: {}",
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
    let window_ns = ended_ns.saturating_sub(started_ns);
    let presentation = Presentation::capture(
        coordinator,
        scope_label,
        started_ns,
        ended_ns,
        passes,
        ended_ns,
        window_ns,
    );
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
    let window_ns = ended_ns.saturating_sub(started_ns);
    let presentation = Presentation::capture(
        coordinator,
        scope_label,
        started_ns,
        ended_ns,
        passes,
        ended_ns,
        window_ns,
    );
    render_snapshot(&presentation)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::discovery::caller_registry::{
        AdmissionState, ImageAuthority, ModuleInfo, ModuleKey,
    };

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
                out,
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
        let presentation = Presentation::capture(&coordinator, "system", 1, 2, 1, 2, 1);
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
            finish_output(
                None,
                None,
                &mut StreamState::new(),
                &presentation,
                true,
                false,
                &mut stdout,
                Some(&summary),
            )
            .unwrap();
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
        let presentation = Presentation::capture(&coordinator, "system", 1, 2, 1, 2, 1);
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
            let dir = tempfile::tempdir().unwrap();
            std::fs::set_permissions(
                dir.path(),
                std::os::unix::fs::PermissionsExt::from_mode(0o700),
            )
            .unwrap();
            let out = dir.path().join("doc.json");
            let sink = AtomicFile::create(&out).unwrap();
            let mut stdout = Vec::new();
            finish_output(
                Some(sink),
                None,
                &mut StreamState::new(),
                &presentation,
                true,
                false,
                &mut stdout,
                Some(&summary),
            )
            .unwrap();
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
        finish_output(
            None,
            None,
            &mut StreamState::new(),
            &presentation,
            true,
            false,
            &mut stdout,
            None,
        )
        .unwrap();
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
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("events.jsonl");
        let mut writer = EventWriter::create(&path, 1 << 20, 5).unwrap();
        let mut state = StreamState::new();
        let presentation = Presentation::capture(&coordinator, "system", 1, 2, 1, 2, 1);
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
        let presentation = Presentation::capture(&coordinator, "system", 1, 3, 1, 3, 2);
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
        let dir = tempfile::tempdir().unwrap();
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
            let presentation =
                Presentation::capture(&coordinator, "pid", 0, pass, pass, pass, pass);
            emit_pass_events(&mut writer, &mut state, &report, &presentation, pass).unwrap();
        }
        // The pre-`ended` flush makes the last value per index exact.
        let last = Presentation::capture(&coordinator, "pid", 0, 3, 3, 3, 3);
        // Through the real terminal path: flush, then `ended`.
        let mut sink = Vec::new();
        finish_output(
            None,
            Some(&mut writer),
            &mut state,
            &last,
            false,
            true,
            &mut sink,
            None,
        )
        .unwrap();
        drop(writer);
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
        let dir = tempfile::tempdir().unwrap();
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
            let presentation =
                Presentation::capture(&coordinator, "pid", 0, pass, pass, pass, pass);
            let before = writer.live_events();
            emit_pass_events(&mut writer, &mut state, &report, &presentation, pass).unwrap();
            per_pass.push(writer.live_events() - before);
        }
        let last = Presentation::capture(&coordinator, "pid", 0, passes, passes, passes, passes);
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
            &mut stdout,
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
        let dir = tempfile::tempdir().unwrap();
        let stream = |name: &str, view: &Presentation| {
            let path = dir.path().join(name);
            let mut writer = EventWriter::create(&path, 1 << 20, 2).unwrap();
            let mut state = StreamState::new();
            emit_pass_events(&mut writer, &mut state, &report, view, now).unwrap();
            let mut sink = Vec::new();
            finish_output(
                None,
                Some(&mut writer),
                &mut state,
                view,
                false,
                true,
                &mut sink,
                None,
            )
            .unwrap();
            drop(writer);
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
