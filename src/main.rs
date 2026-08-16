//! p11scope — non-interposing PKCS#11 observer (eBPF uprobes). CLI entry
//! point; the modules themselves live in the `p11scope` library crate
//! (`src/lib.rs`) so integration tests can exercise them directly.

use anyhow::{Context as _, Result, anyhow, bail};
use p11scope::attach::{CapturePolicy, Scope, Session};
use p11scope::cli::{self, CliError, Kind, ScopeArg};
use p11scope::discovery::identity::{PinnedObjects, pin_manifest_objects};
use p11scope::manifest_input::read_manifest;
use p11scope::output::AtomicFile;
use p11scope::{events, metrics, plan, process, render, scope, semantics, trace};
use p11scope_manifest::manifest::{Manifest, SCHEMA};
use std::io::{Seek as _, SeekFrom, Write};
use std::path::Path;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

/// Both operator stop signals end a capture the same clean way. SIGTERM is
/// what a supervisor (systemd, a container runtime, `timeout`) sends, and
/// its default disposition would kill the process mid-write.
const STOP_SIGNALS: [libc::c_int; 2] = [libc::SIGINT, libc::SIGTERM];

/// Installs handlers that only ever set an `AtomicBool` —
/// `signal_hook::flag::register` is itself the signal-safe minimum a raw
/// handler may do (no allocation, no I/O, no locks). Every capture loop
/// polls this flag cooperatively, the same way it already polls
/// `--duration` elapsing, so Ctrl-C (or SIGTERM) ends a capture the same
/// clean way: stop polling, print the final frame, write `-o` if given —
/// never torn down mid-write.
///
/// Chose `signal-hook` over a hand-rolled `libc::signal` handler: this
/// is exactly the "self-pipe/flag" pattern signal-hook exists for, its
/// `flag` module is a few lines of audited, already-idiomatic code doing
/// precisely this, and it costs one small, already-`libc`-based
/// dependency (the project already pulls `libc` transitively via `aya`).
/// Hand-rolling it correctly means getting async-signal-safety right
/// with no compiler help; reusing it means getting it right by
/// construction.
fn install_stop_flag() -> Result<Arc<AtomicBool>> {
    let flag = Arc::new(AtomicBool::new(false));
    for signal in STOP_SIGNALS {
        signal_hook::flag::register(signal, Arc::clone(&flag))
            .with_context(|| format!("installing handler for signal {signal}"))?;
    }
    Ok(flag)
}

/// Whether a capture loop should stop this tick: interrupted (Ctrl-C or
/// SIGTERM) or `--duration` elapsed. A pure function so the stop path is
/// directly testable without sending a real signal — set the flag,
/// confirm this returns `true` regardless of `elapsed`/`duration`.
fn should_stop(interrupted: &AtomicBool, elapsed: Duration, duration: Option<Duration>) -> bool {
    interrupted.load(Ordering::Relaxed) || duration.is_some_and(|d| elapsed >= d)
}

fn main() {
    if let Err(e) = run() {
        eprintln!("p11scope: {e:#}");
        std::process::exit(1);
    }
}

fn run() -> Result<()> {
    let mut args = std::env::args().skip(1);
    match args.next().as_deref() {
        Some("profile") => cmd_capture(Kind::Profile, args),
        Some("trace") => cmd_capture(Kind::Trace, args),
        Some("discover") => {
            eprintln!(
                "`p11scope discover` was removed: run `p11scope-discover --module <provider.so> \
                 -o <manifest.json>` (offline helper; executes provider code)\n{}",
                cli::USAGE
            );
            std::process::exit(2);
        }
        Some("--help") | Some("-h") => {
            eprintln!("{}", cli::USAGE);
            Ok(())
        }
        other => {
            eprintln!(
                "unknown or missing subcommand: {}\n{}",
                other.unwrap_or("(none)"),
                cli::USAGE
            );
            std::process::exit(2);
        }
    }
}

/// Both capture subcommands: parse, decide the policy, pin the manifest's
/// objects, install the stop flag, then run the loop `kind` selects.
fn cmd_capture(kind: Kind, args: impl Iterator<Item = String>) -> Result<()> {
    let a = match cli::parse_capture(kind, args) {
        Ok(a) => a,
        Err(CliError::Help) => {
            eprintln!("{}", cli::USAGE);
            return Ok(());
        }
        Err(CliError::Usage(msg)) => {
            eprintln!("{msg}");
            std::process::exit(2);
        }
    };
    let mode = match (kind, a.metrics) {
        (Kind::Trace, _) => "trace",
        (Kind::Profile, true) => "metrics",
        (Kind::Profile, false) => "profile",
    };
    let policy = CapturePolicy::from_cli(
        mode,
        a.unsafe_requested,
        cfg!(feature = "unsafe-unvalidated-metadata"),
    )?;
    let scope = match &a.scope {
        ScopeArg::Pid(p) => {
            if !std::path::Path::new(&format!("/proc/{p}")).exists() {
                bail!("--pid {p}: no such process");
            }
            Scope::Pid(*p)
        }
        ScopeArg::Cgroup(c) => Scope::Cgroup {
            id: scope::cgroup_id(c)?,
            path: c.clone(),
        },
    };
    if kind == Kind::Trace && a.duration.is_none() {
        eprintln!(
            "p11scope: no --duration given; trace streams until interrupted (Ctrl-C) or the \
             process exits"
        );
    }
    warn_unsafe_policy(policy);
    let (manifest, plan, pinned) = load_plan(&a.manifest)?;
    let stop = install_stop_flag()?;
    match kind {
        Kind::Profile => capture_profile(
            manifest,
            plan,
            scope,
            policy,
            a.duration,
            a.out.as_deref(),
            &pinned,
            &stop,
        ),
        Kind::Trace => capture_trace(
            plan,
            scope,
            policy,
            a.duration,
            a.out.as_deref(),
            &pinned,
            &stop,
        ),
    }
}

/// Reads and pins the manifest, then builds the attach plan — shared by
/// both capture subcommands.
fn load_plan(manifest_path: &Path) -> Result<(Manifest, plan::AttachPlan, PinnedObjects)> {
    let text = read_manifest(manifest_path)
        .map_err(|error| anyhow!("reading manifest {}: {error}", manifest_path.display()))?;
    let manifest: Manifest = serde_json::from_str(&text)
        .with_context(|| format!("parsing manifest {}", manifest_path.display()))?;
    if manifest.schema != SCHEMA {
        bail!(
            "manifest schema mismatch: got {:?}, this build expects {SCHEMA:?}; \
             rerun `p11scope-discover` to rediscover the module",
            manifest.schema
        );
    }
    let pinned = pin_manifest_objects(&manifest).map_err(|problems| {
        for problem in &problems {
            eprintln!("p11scope: {problem}");
        }
        anyhow!("manifest does not match the current files; refusing to attach")
    })?;
    let plan = plan::build(&manifest);
    // The merge refuses an over-capacity module whole rather than attaching a
    // prefix, so the ceiling is reported here instead of as an empty plan.
    if let Some(refused) = plan.modules_skipped.first() {
        bail!("{}: {}", refused.subject, refused.reason);
    }
    if plan.slots.is_empty() {
        bail!(
            "attach plan is empty: manifest {} has no attachable slots",
            manifest_path.display()
        );
    }
    plan::ensure_capacity(&plan).map_err(|error| anyhow!(error))?;
    Ok((manifest, plan, pinned))
}

/// Prints every attach failure — shared by `profile` and `trace`, which
/// each attach the same way. A capture that attached at least one probe
/// still gets each per-slot failure printed (it is real evidence of a
/// PARTIAL capture, kept as-is). But when literally nothing attached,
/// N copies of the same generic per-slot line leave the operator to
/// work out on their own that this means "the environment can't do BPF
/// attach at all" — so that case also gets one synthesized, actionable
/// summary line naming the likely causes, not just a wall of identical
/// failures. This is in addition to `Session::start`'s own hint (fired
/// only when the *earlier* map-creation/program-load stage fails
/// outright); this one covers the case where that stage succeeds but
/// every individual uprobe attach is refused (e.g. `perf_event_open`
/// blocked by `perf_event_paranoid`).
fn report_attach_failures(session: &Session) {
    for (idx, msg) in session.attach_failures() {
        eprintln!("attach failed (slot {idx}): {msg}");
    }
    if session.attached_probes() == 0 {
        if let Some((_, first)) = session.attach_failures().first() {
            eprintln!(
                "p11scope: {}/{} attach attempts failed, every one the same way — this almost \
                 always means the environment cannot attach BPF uprobes at all: missing \
                 CAP_BPF/CAP_SYS_ADMIN (or root), a kernel lockdown mode, or a restrictive \
                 kernel.perf_event_paranoid sysctl. First underlying error: {first}",
                session.attach_failures().len(),
                session.attached_probes() + session.attach_failures().len()
            );
        }
    }
}

/// Gives unsafe rendering the same diagnostic shape expectations that
/// `Session::start` published to `MECH_SHAPE`.
fn load_mech_shapes(state: &mut semantics::State) -> Result<()> {
    let registry = pkcs11_proxy_ng_types::mechanism_registry::MechanismRegistry::load(None)
        .map_err(|e| anyhow!("loading mechanism registry: {e}"))?;
    state.set_mech_shapes(p11scope::shapes::expected_shapes(&registry));
    Ok(())
}

fn warn_unsafe_policy(policy: CapturePolicy) {
    if policy.uses_unsafe_decoders() {
        eprintln!(
            "p11scope: WARNING: unsafe-unvalidated-metadata follows caller-supplied pointer \
             topology and is only for trusted, ABI-valid workloads"
        );
    }
}

fn identify_tracked(
    tracker: &mut process::Tracker,
    state: &mut semantics::State,
    ev: &p11scope_ebpf_common::Event,
) -> semantics::ProcessKey {
    let pid = (ev.pid_tgid >> 32) as u32;
    let identified = tracker.identify(pid);
    if let Some(retired) = identified.retired {
        state.retire_process(retired);
    }
    identified.key
}

fn retire_exited(tracker: &mut process::Tracker, state: &mut semantics::State) {
    for process in tracker.poll_exited() {
        state.retire_process(process);
    }
}

fn observe_fork(
    tracker: &mut process::Tracker,
    state: &mut semantics::State,
    ev: &p11scope_ebpf_common::Event,
) -> bool {
    if ev.event_type != p11scope_ebpf_common::event_type::FORK {
        return false;
    }
    let parent_pid = (ev.pid_tgid >> 32) as u32;
    if !state.pid_has_process_state(parent_pid) {
        return true;
    }
    let parent = tracker.identify(parent_pid);
    if let Some(retired) = parent.retired {
        state.retire_process(retired);
    }
    if !state.has_process_state(parent.key) {
        tracker.retire(parent.key);
        return true;
    }
    let child = tracker.identify(ev.session as u32);
    if let Some(retired) = child.retired {
        state.retire_process(retired);
    }
    state.fork_process(parent.key, child.key);
    if !state.has_process_state(child.key) {
        state.retire_process(child.key);
        tracker.retire(child.key);
    }
    true
}

#[allow(clippy::too_many_arguments)]
fn capture_profile(
    manifest: Manifest,
    plan: plan::AttachPlan,
    scope: Scope,
    policy: CapturePolicy,
    duration: Option<Duration>,
    out: Option<&Path>,
    pinned: &PinnedObjects,
    interrupted: &AtomicBool,
) -> Result<()> {
    // Created before the attach so a bad `-o` path fails early, published
    // by `commit()` only once the final report is written.
    let output = out
        .map(AtomicFile::create)
        .transpose()
        .map_err(anyhow::Error::msg)?;
    let has_output = output.is_some();
    let mut stdout_sink = std::io::stdout().lock();
    let stdout: &mut dyn Write = &mut stdout_sink;
    let mut session =
        Session::start(&plan, &scope, pinned, policy).context("starting attach session")?;
    report_attach_failures(&session);
    let profile = policy.uses_events();
    let mode = if profile { "profile" } else { "metrics" };

    // Only `--mode profile` decodes the event stream; `--mode metrics` never
    // drains the ring buffer, so it stays the lighter, maps-only level.
    let mut state = semantics::State::with_policy(&plan, policy);
    let mut process_tracker = process::Tracker::new();
    if policy.uses_unsafe_decoders() {
        load_mech_shapes(&mut state)?;
    }
    let mut malformed_records: u64 = 0;
    let drain_events = |session: &mut Session,
                        state: &mut semantics::State,
                        tracker: &mut process::Tracker|
     -> Result<u64> {
        let mut drain = events::Drain::new(&mut session.ebpf)?;
        drain.poll(|ev| {
            if observe_fork(tracker, state, &ev) {
                return;
            }
            let process = identify_tracked(tracker, state, &ev);
            state.observe_process(process, &ev);
            if !state.has_process_state(process) {
                state.retire_process(process);
                tracker.retire(process);
            }
        });
        Ok(drain.malformed())
    };

    let mut stdout_open = true;
    let wall_start = SystemTime::now();
    let clock = Instant::now();
    loop {
        pinned.check_unchanged().map_err(anyhow::Error::msg)?;
        let elapsed = clock.elapsed();
        retire_exited(&mut process_tracker, &mut state);
        if should_stop(interrupted, elapsed, duration) {
            break;
        }
        if profile {
            malformed_records += drain_events(&mut session, &mut state, &mut process_tracker)?;
        }
        let mut kernel_evidence = metrics::kernel_evidence(&session)?;
        if !profile {
            kernel_evidence.ring_loss = 0;
        }
        let reports = metrics::read(&session, &plan)?;
        let ev = evidence_for(
            &plan,
            &session,
            &reports,
            kernel_evidence,
            process_tracker.evidence(),
            malformed_records,
            &state,
            pinned.provider_changed(),
        );
        let frame = render::live(&reports, &ev, elapsed, &manifest.module_path, mode, policy);
        pinned.check_unchanged().map_err(anyhow::Error::msg)?;
        write_stdout(
            stdout,
            &mut stdout_open,
            format!("\x1b[2J\x1b[H{frame}").as_bytes(),
        )?;
        flush_stdout(stdout, &mut stdout_open)?;
        if !stdout_open && !has_output {
            break;
        }
        std::thread::sleep(Duration::from_secs(1));
    }

    session.detach_producers()?;
    pinned.check_unchanged().map_err(anyhow::Error::msg)?;
    if profile {
        malformed_records += drain_events(&mut session, &mut state, &mut process_tracker)?;
    }
    retire_exited(&mut process_tracker, &mut state);
    let reports = metrics::read(&session, &plan)?;
    let mut kernel_evidence = metrics::kernel_evidence(&session)?;
    if !profile {
        kernel_evidence.ring_loss = 0;
    }
    // Last look before the evidence that the final frame and the `-o` report
    // are built from, so an in-place provider change is reflected in both.
    pinned.check_unchanged().map_err(anyhow::Error::msg)?;
    let mut ev = evidence_for(
        &plan,
        &session,
        &reports,
        kernel_evidence,
        process_tracker.evidence(),
        malformed_records,
        &state,
        pinned.provider_changed(),
    );
    ev.mark_terminal_drain_unproven();
    let frame = render::live(
        &reports,
        &ev,
        clock.elapsed(),
        &manifest.module_path,
        mode,
        policy,
    );
    write_stdout(
        stdout,
        &mut stdout_open,
        format!("\x1b[2J\x1b[H{frame}").as_bytes(),
    )?;
    flush_stdout(stdout, &mut stdout_open)?;

    if let Some(mut out_file) = output {
        let kernel = std::fs::read_to_string("/proc/sys/kernel/osrelease")
            .unwrap_or_default()
            .trim()
            .to_string();
        let started = fmt_rfc3339(wall_start);
        let ended = fmt_rfc3339(SystemTime::now());
        let build_id = manifest
            .objects
            .iter()
            .find(|o| o.path == manifest.module_path)
            .and_then(|o| o.identity.value.as_deref());
        let capture = render::CaptureMeta {
            module: &manifest.module_path,
            build_id,
            started: &started,
            ended: &ended,
            kernel: &kernel,
            policy,
        };
        let j = if profile {
            render::profile_json(&reports, &ev, &state, &capture)
        } else {
            render::json(&reports, &ev, &capture)
        };
        write_json_report(out_file.file(), &j)?;
        out_file.commit().map_err(anyhow::Error::msg)?;
    }

    drop(session);
    Ok(())
}

/// Writes the `-o` report — the same call whether the loop above it
/// exited because `--duration` elapsed or because SIGINT set
/// `interrupted`: finalization does not know or care which. Factored out
/// so that fact is directly testable without standing up a real attach session.
fn write_json_report(file: &mut std::fs::File, j: &serde_json::Value) -> Result<()> {
    file.set_len(0).context("truncating profile output")?;
    file.seek(SeekFrom::Start(0))
        .context("seeking profile output")?;
    serde_json::to_writer_pretty(&mut *file, j).context("writing profile output")?;
    file.flush().context("flushing profile output")?;
    file.sync_all().context("syncing profile output")
}

/// `p11scope trace`: one line per completed call, printed as it arrives,
/// instead of `profile`'s periodic aggregate frame. A separate
/// subcommand rather than a `--mode` — its transport (drain-and-print
/// every tick, no periodic full-screen redraw) and time-bounding differ
/// enough that folding it into `profile`'s loop would tangle both.
fn capture_trace(
    plan: plan::AttachPlan,
    scope: Scope,
    policy: CapturePolicy,
    duration: Option<Duration>,
    out: Option<&Path>,
    pinned: &PinnedObjects,
    interrupted: &AtomicBool,
) -> Result<()> {
    // A line stream, not a published artifact: created before the attach so a
    // bad `-o` path fails early, then appended to as lines arrive.
    let mut out_sink = match out {
        Some(path) => Some(
            p11scope::output::create_private_stream(path)
                .map_err(anyhow::Error::msg)
                .context("creating trace output")?,
        ),
        None => None,
    };
    let out_file = &mut out_sink;
    let mut stdout_sink = std::io::stdout().lock();
    let stdout: &mut dyn Write = &mut stdout_sink;
    let mut session =
        Session::start(&plan, &scope, pinned, policy).context("starting attach session")?;
    report_attach_failures(&session);

    let mut state = semantics::State::with_policy(&plan, policy);
    let mut process_tracker = process::Tracker::new();
    if policy.uses_unsafe_decoders() {
        load_mech_shapes(&mut state)?;
    }
    let mut tracer = trace::Tracer::new(&plan);

    let mut stdout_open = true;
    let mut malformed_records: u64 = 0;
    let mut last_reported_loss: u64 = 0;
    let clock = Instant::now();
    emit_trace_line(
        &trace::capture_line(policy),
        stdout,
        &mut stdout_open,
        out_file,
    )?;
    loop {
        pinned.check_unchanged().map_err(anyhow::Error::msg)?;
        let elapsed = clock.elapsed();
        if should_stop(interrupted, elapsed, duration) {
            break;
        }
        malformed_records += drain_trace_events(
            &mut session,
            &mut state,
            &mut process_tracker,
            &mut tracer,
            stdout,
            &mut stdout_open,
            out_file,
        )?;
        retire_exited(&mut process_tracker, &mut state);
        pinned.check_unchanged().map_err(anyhow::Error::msg)?;
        report_trace_loss(
            &session,
            &mut last_reported_loss,
            stdout,
            &mut stdout_open,
            out_file,
        )?;
        flush_stdout(stdout, &mut stdout_open)?;
        if let Some(f) = out_file.as_mut() {
            f.flush().context("flushing trace output file")?;
        }
        if !stdout_open && out_file.is_none() {
            break;
        }
        std::thread::sleep(Duration::from_millis(200));
    }

    session.detach_producers()?;
    // Drain everything currently visible after detach, then report the closing
    // loss line. Kernel detach does not wait for callbacks already executing
    // on another CPU, so terminal evidence below remains explicitly PARTIAL.
    malformed_records += drain_trace_events(
        &mut session,
        &mut state,
        &mut process_tracker,
        &mut tracer,
        stdout,
        &mut stdout_open,
        out_file,
    )?;
    retire_exited(&mut process_tracker, &mut state);
    pinned.check_unchanged().map_err(anyhow::Error::msg)?;
    report_trace_loss(
        &session,
        &mut last_reported_loss,
        stdout,
        &mut stdout_open,
        out_file,
    )?;
    let reports = metrics::read(&session, &plan)?;
    // Last look before the evidence line the trace ends with, so an in-place
    // provider change is reflected in it.
    pinned.check_unchanged().map_err(anyhow::Error::msg)?;
    let mut evidence = evidence_for(
        &plan,
        &session,
        &reports,
        metrics::kernel_evidence(&session)?,
        process_tracker.evidence(),
        malformed_records,
        &state,
        pinned.provider_changed(),
    );
    evidence.mark_terminal_drain_unproven();
    emit_trace_line(
        &trace::evidence_line(&evidence, policy),
        stdout,
        &mut stdout_open,
        out_file,
    )?;
    if malformed_records > 0 {
        eprintln!(
            "p11scope: {malformed_records} malformed ring-buffer records discarded this capture"
        );
    }
    if let Some(f) = out_file.as_mut() {
        f.flush().context("flushing trace output file")?;
    }

    drop(session);
    Ok(())
}

/// Prints (and, if given, appends to the `-o` file) every rendered line.
fn emit_trace_line<W: Write>(
    line: &str,
    stdout: &mut dyn Write,
    stdout_open: &mut bool,
    out_file: &mut Option<W>,
) -> Result<()> {
    write_stdout(stdout, stdout_open, format!("{line}\n").as_bytes())?;
    if let Some(f) = out_file {
        writeln!(f, "{line}").context("writing trace output file")?;
    }
    Ok(())
}

fn write_stdout(writer: &mut dyn Write, open: &mut bool, bytes: &[u8]) -> Result<()> {
    if !*open {
        return Ok(());
    }
    match writer.write_all(bytes) {
        Ok(()) => Ok(()),
        Err(error) if error.kind() == std::io::ErrorKind::BrokenPipe => {
            *open = false;
            Ok(())
        }
        Err(error) => Err(error).context("writing stdout"),
    }
}

fn flush_stdout(writer: &mut dyn Write, open: &mut bool) -> Result<()> {
    if !*open {
        return Ok(());
    }
    match writer.flush() {
        Ok(()) => Ok(()),
        Err(error) if error.kind() == std::io::ErrorKind::BrokenPipe => {
            *open = false;
            Ok(())
        }
        Err(error) => Err(error).context("flushing stdout"),
    }
}

/// Drains whatever the ring buffer currently holds, rendering and
/// emitting one line per completed call. Returns the malformed-record
/// count from this drain, to accumulate at the call site.
fn drain_trace_events<W: Write>(
    session: &mut Session,
    state: &mut semantics::State,
    tracker: &mut process::Tracker,
    tracer: &mut trace::Tracer<'_>,
    stdout: &mut dyn Write,
    stdout_open: &mut bool,
    out_file: &mut Option<W>,
) -> Result<u64> {
    let mut drain = events::Drain::new(&mut session.ebpf)?;
    let mut write_error = None;
    drain.poll(|ev| {
        if observe_fork(tracker, state, &ev) {
            return;
        }
        let process = identify_tracked(tracker, state, &ev);
        if write_error.is_none() {
            write_error = emit_trace_line(
                &tracer.on_event_process(&ev, process, state),
                stdout,
                stdout_open,
                out_file,
            )
            .err();
        } else {
            state.observe_process(process, &ev);
        }
        if !state.has_process_state(process) {
            state.retire_process(process);
            tracker.retire(process);
        }
    });
    if let Some(error) = write_error {
        return Err(error);
    }
    Ok(drain.malformed())
}

/// Emits `LOST n events` when the ring buffer's loss counter has grown
/// since the last report — mandatory whenever it is nonzero, so a trace
/// that dropped events never ends silently.
fn report_trace_loss<W: Write>(
    session: &Session,
    last_reported_loss: &mut u64,
    stdout: &mut dyn Write,
    stdout_open: &mut bool,
    out_file: &mut Option<W>,
) -> Result<()> {
    let lost = metrics::lost_events(session)?;
    if lost > *last_reported_loss {
        if let Some(line) = trace::lost_line(lost) {
            emit_trace_line(&line, stdout, stdout_open, out_file)?;
        }
        *last_reported_loss = lost;
    }
    Ok(())
}

/// Evidence built from the plan (skips, aliases, surface/vendor gaps), the
/// session (attach failures), the current reports (in-flight count), and
/// (profile mode only — always 0 in metrics mode) the ring-buffer/semantic
/// gap counters. Calls `.verdict()` itself before returning, so callers
/// must not call it again.
#[allow(clippy::too_many_arguments)]
fn evidence_for(
    plan: &plan::AttachPlan,
    session: &Session,
    reports: &[metrics::SlotReport],
    kernel_evidence: metrics::KernelEvidence,
    tracking_evidence: process::TrackingEvidence,
    malformed_records: u64,
    state: &semantics::State,
    provider_changed: bool,
) -> render::Evidence {
    let semantic = state.semantic_evidence();
    let mut ev = render::Evidence {
        table_entries: plan.entries_seen,
        slots: plan.slots.len(),
        attached_probes: session.attached_probes(),
        attach_failures: session
            .attach_failures()
            .iter()
            .map(|(_, msg)| msg.clone())
            .collect(),
        aliased: plan
            .slots
            .iter()
            .filter(|s| s.aliased)
            .map(|s| s.names.clone())
            .collect(),
        skipped: plan
            .skipped
            .iter()
            .map(|s| render::SkippedOut {
                name: s.subject.clone(),
                reason: s.reason.clone(),
            })
            .collect(),
        in_flight_at_end: reports.iter().map(|r| r.in_flight).sum(),
        surfaces: plan.surfaces.clone(),
        vendor_interfaces: plan.vendor_interfaces,
        interface_list: plan.interface_list.clone(),
        event_loss: kernel_evidence.ring_loss,
        start_insert_failures: kernel_evidence.start_insert_failures,
        unmatched_returns: kernel_evidence.unmatched_returns,
        rv_update_failures: kernel_evidence.rv_update_failures,
        cgroup_scope_failures: kernel_evidence.cgroup_scope_failures,
        semantic_capture_failures: kernel_evidence.semantic_capture_failures
            + semantic.semantic_capture_failures,
        unregistered_mechanisms: kernel_evidence.unregistered_mechanisms,
        template_tail_failures: kernel_evidence.template_tail_failures,
        process_tracking_fallbacks: tracking_evidence.fallbacks,
        process_tracking_failures: tracking_evidence.failures,
        process_tracking_evictions: tracking_evidence.evictions,
        state_reconciliations: semantic.state_reconciliations,
        session_cancel_ambiguities: semantic.session_cancel_ambiguities,
        session_cancel_unknown_flags: semantic.session_cancel_unknown_flags,
        operation_state_imports: semantic.operation_state_imports,
        auth_state_ambiguities: semantic.auth_state_ambiguities,
        async_target_failures: semantic.async_target_failures,
        async_orphans: semantic.async_orphans,
        async_duplicates: semantic.async_duplicates,
        async_evictions: semantic.async_evictions,
        fork_state_ambiguities: semantic.fork_state_ambiguities,
        semantic_state_drops: semantic.semantic_state_drops,
        pending_at_end: state.pending_at_end(),
        malformed_records,
        orphan_ops: state.orphan_ops(),
        unmatched_closes: state.unmatched_closes(),
        shape_decode_failures: state.shape_decode_failures(),
        shape_decode_total_failures: state.total_shape_decode_failures(),
        templates_truncated: state.templates_truncated(),
        provider_changed,
        completeness: "UNKNOWN",
    };
    ev.verdict();
    ev
}

/// `SystemTime` → an RFC3339-ish UTC timestamp, no `chrono` dependency.
/// Civil-from-days conversion per Howard Hinnant's `civil_from_days`.
fn fmt_rfc3339(t: SystemTime) -> String {
    let secs = t.duration_since(UNIX_EPOCH).unwrap_or_default().as_secs();
    let days = (secs / 86_400) as i64;
    let rem = secs % 86_400;
    let (hour, min, sec) = (rem / 3600, (rem % 3600) / 60, rem % 60);

    let z = days + 719_468;
    let era = if z >= 0 { z } else { z - 146_096 } / 146_097;
    let doe = (z - era * 146_097) as u64; // [0, 146096]
    let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365; // [0, 399]
    let y = yoe as i64 + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100); // [0, 365]
    let mp = (5 * doy + 2) / 153; // [0, 11]
    let day = doy - (153 * mp + 2) / 5 + 1; // [1, 31]
    let month = if mp < 10 { mp + 3 } else { mp - 9 }; // [1, 12]
    let year = if month <= 2 { y + 1 } else { y };

    format!("{year:04}-{month:02}-{day:02}T{hour:02}:{min:02}:{sec:02}Z")
}

#[cfg(test)]
mod tests {
    use super::*;

    struct FailingWriter {
        kind: std::io::ErrorKind,
        fail_flush: bool,
    }

    impl Write for FailingWriter {
        fn write(&mut self, _buf: &[u8]) -> std::io::Result<usize> {
            if self.fail_flush {
                Ok(0)
            } else {
                Err(std::io::Error::from(self.kind))
            }
        }

        fn flush(&mut self) -> std::io::Result<()> {
            if self.fail_flush {
                Err(std::io::Error::from(self.kind))
            } else {
                Ok(())
            }
        }
    }

    /// build.rs must embed the real cross-compiled BPF object, never a
    /// placeholder byte array — a stub would silently break every attach.
    #[test]
    fn ebpf_object_is_a_real_bpf_elf() {
        let obj = p11scope::EBPF_OBJECT;
        assert!(obj.len() > 1000, "expected a real BPF object, not a stub");
        assert_eq!(&obj[..4], b"\x7fELF", "embedded object is not an ELF file");
    }

    #[test]
    fn fmt_rfc3339_matches_a_known_instant() {
        // 2024-01-01T00:00:00Z == 1704067200.
        assert_eq!(
            fmt_rfc3339(UNIX_EPOCH + Duration::from_secs(1_704_067_200)),
            "2024-01-01T00:00:00Z"
        );
        assert_eq!(fmt_rfc3339(UNIX_EPOCH), "1970-01-01T00:00:00Z");
    }

    /// Exercises the interrupt path directly, with no real signal sent:
    /// once the flag `signal_hook::flag::register` would set is set, a
    /// capture loop must stop on the very next tick regardless of
    /// `--duration` — the same "stop, then finalize" branch a real
    /// SIGINT drives.
    #[test]
    fn should_stop_on_interrupt_regardless_of_duration() {
        let interrupted = AtomicBool::new(false);
        assert!(!should_stop(&interrupted, Duration::from_secs(0), None));
        assert!(!should_stop(
            &interrupted,
            Duration::from_secs(0),
            Some(Duration::from_secs(3600))
        ));

        interrupted.store(true, Ordering::Relaxed);
        assert!(
            should_stop(&interrupted, Duration::from_secs(0), None),
            "no --duration set at all"
        );
        assert!(
            should_stop(
                &interrupted,
                Duration::from_secs(0),
                Some(Duration::from_secs(3600))
            ),
            "must stop immediately even mid-way through a long --duration"
        );
    }

    #[test]
    fn should_stop_still_honors_duration_elapsing_without_an_interrupt() {
        let interrupted = AtomicBool::new(false);
        assert!(should_stop(
            &interrupted,
            Duration::from_secs(10),
            Some(Duration::from_secs(5))
        ));
        assert!(!should_stop(
            &interrupted,
            Duration::from_secs(4),
            Some(Duration::from_secs(5))
        ));
    }

    /// A real SIGTERM (raised in-process after the handler is installed) sets
    /// the same stop flag Ctrl-C sets, so `should_stop` returns true on the
    /// next tick instead of the default disposition killing the capture
    /// mid-write.
    #[test]
    fn sigterm_sets_the_stop_flag() {
        let stop = install_stop_flag().unwrap();
        assert!(!should_stop(&stop, Duration::ZERO, None));
        // SAFETY: raise() with a handled signal; the handler only sets an AtomicBool.
        assert_eq!(unsafe { libc::raise(libc::SIGTERM) }, 0);
        assert!(should_stop(&stop, Duration::ZERO, None));
    }

    #[test]
    fn fork_only_traffic_does_not_consume_process_tracking_budget() {
        let plan = plan::AttachPlan {
            slots: vec![],
            modules: vec![],
            skipped: vec![],
            modules_skipped: vec![],
            entries_seen: 0,
            surfaces: vec![],
            vendor_interfaces: 0,
            interface_list: "absent".into(),
            module_ambiguous: 0,
        };
        let mut state = semantics::State::new(&plan);
        let mut tracker = process::Tracker::with_limits(0, 1);
        for parent in 100_000..100_100u32 {
            let event = p11scope_ebpf_common::Event {
                event_type: p11scope_ebpf_common::event_type::FORK,
                pid_tgid: u64::from(parent) << 32,
                session: u64::from(parent + 1),
                ..Default::default()
            };
            assert!(observe_fork(&mut tracker, &mut state, &event));
        }
        assert_eq!(tracker.evidence(), process::TrackingEvidence::default());
    }

    #[test]
    fn manifest_v1_and_v2_are_rejected_with_rediscovery_instruction() {
        for schema in ["p11scope-manifest/1", "p11scope-manifest/2"] {
            let dir = tempfile::tempdir().unwrap();
            let path = dir.path().join("m.json");
            std::fs::write(
                &path,
                format!(
                    r#"{{"schema":"{schema}","module_path":"/opt/p.so","objects":[],"interface_list":{{"status":"absent"}},"surfaces":[],"vendor_interfaces":[],"alias_groups":[]}}"#
                ),
            )
            .unwrap();
            let err = load_plan(&path).unwrap_err().to_string();
            assert!(err.contains("rediscover"), "{err}");
        }
    }

    /// The finalization a stopped loop runs into: `-o` publication produces
    /// valid JSON and replaces stale content atomically (adapted from the
    /// previous shutdown-path test).
    #[test]
    fn shutdown_path_publishes_valid_json_over_a_stale_file() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("observed.json");
        std::fs::write(&path, b"stale trailing bytes that must disappear").unwrap();
        let j = serde_json::json!({"schema": "pkcs11-scope/observed-profile/v1.4", "evidence": {}});
        let mut out = AtomicFile::create(&path).unwrap();
        write_json_report(out.file(), &j).expect("shutdown finalization must write the report");
        out.commit().unwrap();
        let parsed: serde_json::Value =
            serde_json::from_str(&std::fs::read_to_string(&path).unwrap()).unwrap();
        assert_eq!(parsed["schema"], "pkcs11-scope/observed-profile/v1.4");
    }

    /// The unsafe policy is refused by `CapturePolicy::from_cli` on the parsed
    /// arguments alone — before the manifest path is ever opened.
    #[cfg(not(feature = "unsafe-unvalidated-metadata"))]
    #[test]
    fn policy_output_unsafe_flag_is_refused_before_manifest_loading() {
        let a = cli::parse_capture(
            Kind::Profile,
            [
                "--unsafe-unvalidated-metadata",
                "--manifest",
                "/definitely/not/a/manifest.json",
                "--pid",
                "1",
            ]
            .into_iter()
            .map(str::to_string),
        )
        .unwrap();
        let error = CapturePolicy::from_cli(
            "profile",
            a.unsafe_requested,
            cfg!(feature = "unsafe-unvalidated-metadata"),
        )
        .unwrap_err();
        let rendered = format!("{error:#}");
        assert!(rendered.contains("Cargo feature"), "{rendered}");
        assert!(!rendered.contains("reading manifest"), "{rendered}");
    }

    #[test]
    fn broken_stdout_closes_only_that_sink_and_file_continues() {
        let mut stdout = FailingWriter {
            kind: std::io::ErrorKind::BrokenPipe,
            fail_flush: false,
        };
        let mut stdout_open = true;
        let mut file = Some(Vec::new());
        emit_trace_line("final", &mut stdout, &mut stdout_open, &mut file).unwrap();
        assert!(!stdout_open);
        assert_eq!(file.unwrap(), b"final\n");
    }

    #[test]
    fn trace_file_write_and_flush_errors_propagate() {
        let mut stdout = Vec::new();
        let mut stdout_open = true;
        let mut file = Some(FailingWriter {
            kind: std::io::ErrorKind::Other,
            fail_flush: false,
        });
        assert!(emit_trace_line("x", &mut stdout, &mut stdout_open, &mut file).is_err());

        let mut flush = FailingWriter {
            kind: std::io::ErrorKind::Other,
            fail_flush: true,
        };
        let mut open = true;
        assert!(flush_stdout(&mut flush, &mut open).is_err());
    }
}
