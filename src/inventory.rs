//! SPDX-License-Identifier: GPL-3.0-or-later
//! `p11scope inventory`: which module is used by whom.
//!
//! One snapshot pass, or a `--duration` observation window of passes,
//! over `--pid` or `--system`: every pass collects the scope, reconciles
//! caller incarnations, and publishes caller/module/edge facts through
//! the coordinator batch. The JSON document (`p11scope/inventory/v1`)
//! carries stable capture-local IDs, timestamps on the capture clock,
//! lifecycle state, and explicit gaps. Scan-only like inspect: usage
//! columns read unknown unless an entry feed observed them, and mappings
//! are never reported as observed calls.

use crate::attach::Scope;
use crate::cli::InspectScope;
use crate::discovery::caller_registry::{
    CallerEvent, ImageAuthority, OsProcessSource, ProcessSource, RegistryLimits, now_ns,
};
use crate::discovery::engine::inventory::UnavailableImageGuard;
use crate::discovery::engine::inventory_coordinator::{
    InventoryCoordinator, InventoryScope, PassReport,
};
use crate::discovery::hooks::HookRegistry;
use crate::inventory_dashboard::{
    DashboardState, DetailPage, DisplayHandoff, Key, LogTail, REDRAW_INTERVAL, RESCAN_INTERVAL,
    RawModeGuard, StopFlag, TerminalGuard, Viewport, poll_key, render_frame, stdout_terminal,
};
use crate::inventory_events::{
    EventWriter, caller_event_payload, ended_payload, gap_payload, pass_payload, started_payload,
};
use crate::inventory_present::{DASHBOARD_ACTIVITY_WINDOW_NS, Presentation, render_snapshot};
use crate::output::AtomicFile;
use anyhow::{Context as _, Result};
use p11scope_ebpf_common::ImageIdentity;
use std::io::Write as _;
use std::os::fd::AsRawFd as _;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::{Duration, Instant};

const DOC_ID: &str = "p11scope/inventory/v1";

/// Rescan interval inside a `--duration` observation window.
const POLL_INTERVAL: Duration = Duration::from_secs(1);

fn no_native_images(_: u32) -> Option<ImageIdentity> {
    None
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
) -> Result<i32> {
    let stdout_tty = crate::inventory_dashboard::fd_is_tty(1);
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
    stdout_tty: bool,
    stdout: &mut dyn std::io::Write,
) -> Result<i32> {
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
    // The scan lane stages no entries: entry columns read unknown. Only a
    // BPF usage feed (the privileged lane) may flip this.
    coordinator.registry_mut().set_usage_feed(false);
    // Interactive dashboard takes over stdout's terminal; a pipe
    // degrades honestly to snapshots/JSON below (never ANSI).
    if dashboard && stdout_tty {
        return run_dashboard_loop(
            scope,
            inventory_scope,
            scope_label,
            started_ns,
            coordinator,
            max_scan_pids,
            duration.map(|window| Instant::now() + window),
            sink,
            stream,
            json,
            stdout,
        );
    }
    if dashboard {
        eprintln!(
            "p11scope: --dashboard needs a terminal on stdout; degraded to {} (no ANSI emitted)",
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
    let mut guard = UnavailableImageGuard;
    let deadline = duration.map(|window| Instant::now() + window);
    loop {
        let now = now_ns();
        let (report, warning) = scan_one_pass(
            &mut coordinator,
            &inventory_scope,
            scope,
            max_scan_pids,
            &mut guard,
            deadline,
            now,
        )?;
        coordinator.commit_batch(report.engine_changed)?;
        if let Some(warning) = warning {
            eprintln!("{warning}");
        }
        for line in progress_lines(&coordinator, &report) {
            eprintln!("{line}");
        }
        if let Some(writer) = stream.as_mut() {
            let window_ns = now.saturating_sub(started_ns);
            let presentation = Presentation::capture(
                &coordinator,
                &scope_label,
                started_ns,
                now,
                coordinator.passes(),
                now,
                window_ns,
            );
            emit_pass_events(writer, &mut stream_state, &report, &presentation, now)
                .map_err(|error| anyhow::anyhow!("{error}"))?;
        }
        match deadline {
            None => break,
            Some(end) => {
                let now_instant = Instant::now();
                if now_instant >= end {
                    break;
                }
                std::thread::sleep(POLL_INTERVAL.min(end - now_instant));
            }
        }
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
    finish_output(sink, stream.as_mut(), &presentation, json, false, stdout)
}

/// Final sinks, shared by the classic and dashboard paths: the event
/// stream's `ended` marker, the atomic `-o` report, then stdout (the
/// JSON document under `--json`, the pager snapshot otherwise —
/// silent in dashboard mode, whose live view already showed it).
fn finish_output(
    sink: Option<AtomicFile>,
    stream: Option<&mut EventWriter>,
    presentation: &Presentation,
    json: bool,
    silent_text: bool,
    stdout: &mut dyn std::io::Write,
) -> Result<i32> {
    let document = render_json_from_presentation(presentation);
    if let Some(writer) = stream {
        let payload = ended_payload(presentation, presentation.ended_ns, writer);
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

/// One scan pass with the shared failure policy: a failed FIRST pass
/// is a hard error (nothing was ever observed); a later failure is an
/// empty pass plus a warning line the caller routes (stderr on the
/// classic path, the log tail on the dashboard) — lifecycle still
/// reconciles, and the observation survives its target's death.
fn scan_one_pass(
    coordinator: &mut InventoryCoordinator<OsProcessSource>,
    inventory_scope: &InventoryScope,
    scope: InspectScope,
    max_scan_pids: Option<usize>,
    guard: &mut UnavailableImageGuard,
    deadline: Option<Instant>,
    now: u64,
) -> Result<(PassReport, Option<String>)> {
    let pass_deadline = match deadline {
        Some(end) => {
            let remaining = end.saturating_duration_since(Instant::now());
            now.saturating_add(remaining.as_nanos().min(u128::from(u64::MAX)) as u64)
        }
        None => u64::MAX,
    };
    let scope_context = match scope {
        InspectScope::Pid(pid) => format!("inventory --pid {pid}"),
        InspectScope::System => "inventory --system".to_string(),
    };
    match coordinator.scan_pass(
        inventory_scope,
        max_scan_pids,
        guard,
        no_native_images,
        pass_deadline,
        now,
    ) {
        Ok(report) => Ok((report, None)),
        Err(error) if coordinator.passes() == 0 => Err(error).with_context(|| scope_context),
        Err(error) => {
            let warning = format!("p11scope: pass failed, continuing without its scan: {error:#}");
            let report =
                coordinator.observe_empty_pass(guard, no_native_images, &format!("{error:#}"), now);
            Ok((report, Some(warning)))
        }
    }
}

/// Incremental stream position: gaps are push-only until the bound,
/// so an index plus the suppressed counter replays exactly the new
/// loss on every pass.
struct StreamState {
    emitted_gaps: usize,
    emitted_suppressed: u64,
}

impl StreamState {
    fn new() -> Self {
        Self {
            emitted_gaps: 0,
            emitted_suppressed: 0,
        }
    }
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
    for event in &report.events {
        writer.append("caller_event", caller_event_payload(event), now_ns)?;
    }
    let fresh = presentation.gaps.len().saturating_sub(state.emitted_gaps);
    for gap in presentation.gaps.iter().skip(state.emitted_gaps) {
        writer.append("gap_recorded", gap_payload(gap), now_ns)?;
    }
    state.emitted_gaps = presentation.gaps.len();
    let suppressed_delta = presentation
        .gaps_suppressed
        .saturating_sub(state.emitted_suppressed);
    state.emitted_suppressed = presentation.gaps_suppressed;
    writer.append(
        "pass_committed",
        pass_payload(report, presentation, fresh, suppressed_delta),
        now_ns,
    )
}

/// The interactive dashboard loop: rescan at 1 Hz, offer immutable
/// snapshots through the bounded handoff, redraw coalesced at ~3 Hz.
/// Keys scroll (stdin TTY only — a pipe never blocks the loop);
/// `--duration`, `q`/Ctrl-C/ESC, or SIGINT/SIGTERM/SIGHUP ends it.
/// Every exit path drops the guards first (terminal restored) and
/// only then touches the final sinks.
#[allow(clippy::too_many_arguments)]
fn run_dashboard_loop(
    scope: InspectScope,
    inventory_scope: InventoryScope,
    scope_label: String,
    started_ns: u64,
    mut coordinator: InventoryCoordinator<OsProcessSource>,
    max_scan_pids: Option<usize>,
    deadline: Option<Instant>,
    sink: Option<AtomicFile>,
    mut stream: Option<EventWriter>,
    json: bool,
    stdout: &mut dyn std::io::Write,
) -> Result<i32> {
    let mut term = stdout_terminal().with_context(|| "opening the dashboard terminal")?;
    let _term_guard =
        TerminalGuard::enter(&term).with_context(|| "entering the dashboard screen")?;
    let raw_guard = RawModeGuard::enter_stdin().with_context(|| "entering dashboard input mode")?;
    let keys_live = raw_guard.is_some();
    let stop = StopFlag::install();
    let handoff = DisplayHandoff::new();
    let mut tail = LogTail::bounded();
    let mut state = DashboardState::new();
    let mut last_viewport = Viewport {
        width: 80,
        height: 24,
    };
    let mut last_frame: Option<crate::inventory_dashboard::DisplayFrame> = None;
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
    tail.push(&format!(
        "p11scope inventory {scope_label}: dashboard started (rescan 1 Hz, redraw ~3 Hz{})",
        if keys_live {
            ""
        } else {
            "; stdin is not a terminal, keys unavailable"
        }
    ));
    let mut guard = UnavailableImageGuard;
    let mut next_rescan = Instant::now();
    let mut next_redraw = Instant::now();
    loop {
        if keys_live {
            while let Some(key) = poll_key() {
                match key {
                    Key::Quit => {
                        tail.push("p11scope: quit requested");
                        return finish_dashboard(
                            scope_label.clone(),
                            started_ns,
                            coordinator,
                            &handoff,
                            sink,
                            stream,
                            json,
                            stdout,
                            _term_guard,
                            raw_guard,
                        );
                    }
                    Key::Up => {
                        if state.detail == DetailPage::Gaps {
                            state.scroll_gaps_up();
                        } else {
                            state.scroll_up();
                        }
                    }
                    Key::Down => {
                        if state.detail == DetailPage::Gaps {
                            // Within-record paging (F6d) wraps at the
                            // live viewport width, exactly like the
                            // renderer — tall records page line by
                            // line before records advance.
                            if let Some(frame) = last_frame.as_ref() {
                                state.scroll_gaps_down(&frame.presentation, last_viewport.width);
                            }
                        } else {
                            let total = last_frame
                                .as_ref()
                                .map(|frame| state.items_total(&frame.presentation))
                                .unwrap_or(0);
                            state.scroll_down(total);
                        }
                    }
                    Key::Detail => {
                        state.next_detail();
                        if let Some(frame) = last_frame.as_ref() {
                            state.clamp_to_presentation(&frame.presentation);
                        }
                    }
                }
                // Keys redraw immediately (scrolling stays responsive
                // inside the coalesced cadence).
                next_redraw = Instant::now();
            }
        }
        if stop.stopped() {
            tail.push("p11scope: stop signal received");
            return finish_dashboard(
                scope_label.clone(),
                started_ns,
                coordinator,
                &handoff,
                sink,
                stream,
                json,
                stdout,
                _term_guard,
                raw_guard,
            );
        }
        if let Some(end) = deadline
            && Instant::now() >= end
        {
            return finish_dashboard(
                scope_label.clone(),
                started_ns,
                coordinator,
                &handoff,
                sink,
                stream,
                json,
                stdout,
                _term_guard,
                raw_guard,
            );
        }
        let tick = Instant::now();
        if tick >= next_rescan {
            next_rescan = tick + RESCAN_INTERVAL;
            let now = now_ns();
            let (report, warning) = scan_one_pass(
                &mut coordinator,
                &inventory_scope,
                scope,
                max_scan_pids,
                &mut guard,
                deadline,
                now,
            )?;
            coordinator.commit_batch(report.engine_changed)?;
            if let Some(warning) = warning {
                tail.push(&warning);
            }
            for line in progress_lines(&coordinator, &report) {
                tail.push(&line);
            }
            // Dashboard frames read activity through the trailing
            // window (a growing observation window would pin every
            // historical entry as "recent" forever); the stream ignores
            // activity, so sharing this capture is exact for both.
            let presentation = Presentation::capture(
                &coordinator,
                &scope_label,
                started_ns,
                now,
                coordinator.passes(),
                now,
                DASHBOARD_ACTIVITY_WINDOW_NS,
            );
            if let Some(writer) = stream.as_mut() {
                emit_pass_events(writer, &mut stream_state, &report, &presentation, now)
                    .map_err(|error| anyhow::anyhow!("{error}"))?;
            }
            handoff.offer(Arc::new(presentation), tail.snapshot());
        }
        if tick >= next_redraw {
            next_redraw = tick + REDRAW_INTERVAL;
            if let Some(frame) = handoff.take() {
                last_frame = Some(frame);
            }
            if let Some(frame) = last_frame.as_ref() {
                state.clamp_to_presentation(&frame.presentation);
                let viewport = Viewport::from_fd(term.as_raw_fd()).unwrap_or(Viewport {
                    width: 80,
                    height: 24,
                });
                last_viewport = viewport;
                let bytes = render_frame(frame, viewport, &state);
                term.write_all(&bytes)
                    .with_context(|| "writing the dashboard frame")?;
                term.flush()
                    .with_context(|| "flushing the dashboard frame")?;
            }
        }
        std::thread::sleep(Duration::from_millis(20));
    }
}

/// Dashboard exit: drop the terminal guards FIRST (restoring cursor,
/// screen, and input mode on every path), then write the final sinks
/// exactly like the classic path — silent text, since the live view
/// already showed it.
#[allow(clippy::too_many_arguments)]
fn finish_dashboard(
    scope_label: String,
    started_ns: u64,
    coordinator: InventoryCoordinator<OsProcessSource>,
    handoff: &DisplayHandoff,
    sink: Option<AtomicFile>,
    mut stream: Option<EventWriter>,
    json: bool,
    stdout: &mut dyn std::io::Write,
    _term_guard: TerminalGuard,
    _raw_guard: Option<RawModeGuard>,
) -> Result<i32> {
    drop(_raw_guard);
    drop(_term_guard);
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
    eprintln!(
        "p11scope: dashboard exited after {passes} pass{}",
        if passes == 1 { "" } else { "es" }
    );
    eprintln!(
        "p11scope: dashboard frames: {} offered, {} consumed, {} shed (shed frames are obsolete display work; capture is unaffected)",
        handoff.offered(),
        handoff.consumed(),
        handoff.dropped_frames(),
    );
    finish_output(sink, stream.as_mut(), &presentation, json, true, stdout)
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
        "p11scope: pass {}: {} scanned ({} native, {} scan-pinned){}",
        report.pass,
        report.scanned,
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
    for event in &report.events {
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
                format!("caller {} exited: {reason}", id.label())
            }
            CallerEvent::ExecRetired { old, new } => {
                format!("caller {} exec-retired, now {}", old.label(), new.label())
            }
            CallerEvent::Reused { old, new } => {
                format!("caller {} reused, now {}", old.label(), new.label())
            }
            CallerEvent::AdmitFailed { pid, reason, .. } => {
                format!("caller admission failed for pid {pid}: {reason}")
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
        },
        "lifecycle": record.lifecycle.label(),
        "unloaded_observed": record.unloaded_observed,
    })
}

fn edge_json(edge: &crate::inventory_present::EdgeView) -> serde_json::Value {
    serde_json::json!({
        "caller": edge.caller.label(),
        "module": edge.module.label(),
        "mapping": {
            "state": edge.mapping.label(),
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
        },
        "budgets": budgets_json(&presentation.budgets),
        "callers": presentation.callers.iter().map(caller_json).collect::<Vec<_>>(),
        "modules": presentation.modules.iter().map(module_json).collect::<Vec<_>>(),
        "edges": presentation.edges.iter().map(edge_json).collect::<Vec<_>>(),
        "gaps": gaps,
        "gaps_suppressed": presentation.gaps_suppressed,
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
}
