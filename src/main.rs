//! p11scope — non-interposing PKCS#11 observer (eBPF uprobes). CLI entry
//! point; the modules themselves live in the `p11scope` library crate
//! (`src/lib.rs`) so integration tests can exercise them directly.

use anyhow::{Context as _, Result, anyhow, bail};
use p11scope::attach::{CapturePolicy, Scope, Session};
use p11scope::{
    discover_cmd, events, metrics, plan, process, render, scope, semantics, trace, verify,
};
use p11scope_manifest::manifest::{Manifest, SCHEMA};
use std::io::{Seek as _, SeekFrom, Write};
use std::path::PathBuf;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

const USAGE: &str = "usage:\n  \
p11scope profile --manifest <m.json> --provenance-module <provider.so> (--pid <n> | --cgroup <path>) [--mode profile|metrics] [--unsafe-unvalidated-metadata] [--duration <secs>] [-o <out.json>]\n  \
p11scope trace --manifest <m.json> --provenance-module <provider.so> (--pid <n> | --cgroup <path>) [--unsafe-unvalidated-metadata] [--duration <secs>] [-o <out.file>]\n  \
p11scope discover --module <provider.so> [-o <manifest.json>]\n\n\
note: --mode defaults to profile (metrics + mechanisms/sessions/logins from\n\
the event stream); --mode metrics is the lighter, maps-only level.\n\
note: trace prints one line per completed call as it happens, in arrival\n\
order, instead of aggregating; --duration bounds it, same as profile. If\n\
omitted, trace streams until interrupted (Ctrl-C) or the process exits.\n\
note: Ctrl-C (SIGINT) ends either subcommand's capture cleanly: polling\n\
stops, the final frame prints, and (with -o) the report is written —\n\
same as --duration elapsing. --duration remains the only way to bound a\n\
capture that runs unattended.\n\
note: --cgroup matches that cgroup and every descendant cgroup beneath it\n\
(kernel >= 5.15 due to attach cookies), so a container or pod directory works\n\
even though its processes live in a nested child cgroup. Sibling cgroups\n\
(anything not under the given path) are never matched. The path must be\n\
under /sys/fs/cgroup.";

/// Installs a SIGINT handler that only ever sets an `AtomicBool` —
/// `signal_hook::flag::register` is itself the signal-safe minimum a raw
/// handler may do (no allocation, no I/O, no locks). Every capture loop
/// polls this flag cooperatively, the same way it already polls
/// `--duration` elapsing, so Ctrl-C ends a capture the same clean way:
/// stop polling, print the final frame, write `-o` if given — never
/// torn down mid-write.
///
/// Chose `signal-hook` over a hand-rolled `libc::signal` handler: this
/// is exactly the "self-pipe/flag" pattern signal-hook exists for, its
/// `flag` module is a few lines of audited, already-idiomatic code doing
/// precisely this, and it costs one small, already-`libc`-based
/// dependency (the project already pulls `libc` transitively via `aya`).
/// Hand-rolling it correctly means getting async-signal-safety right
/// with no compiler help; reusing it means getting it right by
/// construction.
fn install_sigint_flag() -> Result<Arc<AtomicBool>> {
    let flag = Arc::new(AtomicBool::new(false));
    signal_hook::flag::register(signal_hook::consts::SIGINT, Arc::clone(&flag))
        .context("installing SIGINT handler")?;
    Ok(flag)
}

/// Whether a capture loop should stop this tick: interrupted (Ctrl-C) or
/// `--duration` elapsed. A pure function so the interrupt path is
/// directly testable without sending a real signal — set the flag,
/// confirm this returns `true` regardless of `elapsed`/`duration`.
fn should_stop(interrupted: &AtomicBool, elapsed: Duration, duration: Option<u64>) -> bool {
    interrupted.load(Ordering::Relaxed)
        || duration.is_some_and(|d| elapsed >= Duration::from_secs(d))
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
        Some("profile") => cmd_profile(args),
        Some("trace") => cmd_trace(args),
        Some("discover") => cmd_discover(args),
        Some("--help") | Some("-h") => {
            eprintln!("{USAGE}");
            Ok(())
        }
        other => {
            eprintln!(
                "unknown or missing subcommand: {}\n{USAGE}",
                other.unwrap_or("(none)")
            );
            std::process::exit(2);
        }
    }
}

fn cmd_discover(args: impl Iterator<Item = String>) -> Result<()> {
    let args: Vec<_> = args.collect();
    if args
        .iter()
        .any(|arg| arg == "--unsafe-unvalidated-metadata")
    {
        CapturePolicy::from_cli(
            "discover",
            true,
            cfg!(feature = "unsafe-unvalidated-metadata"),
        )?;
    }
    discover_cmd::run(args.into_iter())
}

/// Pulls the value for a flag out of the argument stream, or exits 2 with
/// the Phase 1a convention (`<flag> requires a value`) when it is missing.
fn require_value(args: &mut impl Iterator<Item = String>, flag: &str) -> String {
    match args.next() {
        Some(v) => v,
        None => {
            eprintln!("{flag} requires a value\n{USAGE}");
            std::process::exit(2);
        }
    }
}

/// Pulls `(pid, cgroup)` apart into the one `Scope` the CLI contract
/// allows — shared by every subcommand that attaches. Exits 2 with the
/// usual usage message on zero or both being set.
fn resolve_scope(pid: Option<u32>, cgroup: Option<PathBuf>) -> Result<Scope> {
    match (pid, cgroup) {
        (Some(p), None) => Ok(Scope::Pid(p)),
        (None, Some(c)) => Ok(Scope::Cgroup {
            id: scope::cgroup_id(&c)?,
            path: c,
        }),
        (None, None) => {
            eprintln!("exactly one of --pid or --cgroup is required\n{USAGE}");
            std::process::exit(2);
        }
        (Some(_), Some(_)) => {
            eprintln!("--pid and --cgroup are mutually exclusive\n{USAGE}");
            std::process::exit(2);
        }
    }
}

/// Loads and verifies the manifest, then builds the attach plan — shared
/// by every subcommand that attaches (`profile`, `trace`).
fn load_plan(
    manifest_path: &std::path::Path,
    provenance_module: &std::path::Path,
) -> Result<(Manifest, plan::AttachPlan, verify::VerifiedObjects)> {
    let text = verify::read_manifest(manifest_path)
        .map_err(|error| anyhow!("reading manifest {}: {error}", manifest_path.display()))?;
    let manifest: Manifest = serde_json::from_str(&text)
        .with_context(|| format!("parsing manifest {}", manifest_path.display()))?;
    if manifest.schema != SCHEMA {
        bail!(
            "manifest schema mismatch: got {:?}, this build expects {SCHEMA:?}; \
             rerun `p11scope discover` to rediscover the module",
            manifest.schema
        );
    }
    let objects = verify::check_reuse(&manifest).map_err(|problems| {
        for problem in &problems {
            eprintln!("p11scope: {problem}");
        }
        anyhow!("manifest does not match the current files; refusing to attach")
    })?;
    let discovered = discover_cmd::rediscover_stable(provenance_module).with_context(|| {
        format!(
            "verifying manifest against fresh discovery of {}",
            provenance_module.display()
        )
    })?;
    verify::check_provenance(&manifest, discovered.manifest()).map_err(|problems| {
        for problem in &problems {
            eprintln!("p11scope: {problem}");
        }
        anyhow!("manifest provenance was not reproduced; refusing to attach")
    })?;
    discovered
        .ensure_stable()
        .context("checking provenance closure after manifest comparison")?;
    objects
        .ensure_stable()
        .map_err(anyhow::Error::msg)
        .context("checking authorized provider objects after provenance discovery")?;

    let plan = plan::build(&manifest);
    if plan.slots.is_empty() {
        bail!(
            "attach plan is empty: manifest {} has no attachable slots",
            manifest_path.display()
        );
    }
    plan::ensure_capacity(&plan).map_err(|error| anyhow!(error))?;
    Ok((manifest, plan, objects))
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

fn cmd_profile(mut args: impl Iterator<Item = String>) -> Result<()> {
    let mut manifest_path: Option<PathBuf> = None;
    let mut provenance_module: Option<PathBuf> = None;
    let mut pid: Option<u32> = None;
    let mut cgroup: Option<PathBuf> = None;
    let mut mode = "profile".to_string();
    let mut duration: Option<u64> = None;
    let mut out: Option<PathBuf> = None;
    let mut unsafe_requested = false;

    while let Some(a) = args.next() {
        match a.as_str() {
            "--manifest" => manifest_path = Some(require_value(&mut args, "--manifest").into()),
            "--provenance-module" => {
                provenance_module = Some(require_value(&mut args, "--provenance-module").into())
            }
            "--pid" => {
                let v = require_value(&mut args, "--pid");
                pid = Some(
                    v.parse()
                        .with_context(|| format!("--pid: invalid number {v:?}"))?,
                );
            }
            "--cgroup" => cgroup = Some(require_value(&mut args, "--cgroup").into()),
            "--mode" => mode = require_value(&mut args, "--mode"),
            "--duration" => {
                let v = require_value(&mut args, "--duration");
                duration = Some(
                    v.parse()
                        .with_context(|| format!("--duration: invalid number {v:?}"))?,
                );
            }
            "-o" => out = Some(require_value(&mut args, "-o").into()),
            "--unsafe-unvalidated-metadata" => unsafe_requested = true,
            "--help" | "-h" => {
                eprintln!("{USAGE}");
                return Ok(());
            }
            other => {
                eprintln!("unknown argument: {other}\n{USAGE}");
                std::process::exit(2);
            }
        }
    }

    if mode != "profile" && mode != "metrics" {
        bail!("mode {mode} not implemented in this phase");
    }
    let policy = CapturePolicy::from_cli(
        &mode,
        unsafe_requested,
        cfg!(feature = "unsafe-unvalidated-metadata"),
    )?;

    let Some(manifest_path) = manifest_path else {
        eprintln!("--manifest is required\n{USAGE}");
        std::process::exit(2);
    };
    let Some(provenance_module) = provenance_module else {
        eprintln!("--provenance-module is required\n{USAGE}");
        std::process::exit(2);
    };
    let scope = resolve_scope(pid, cgroup)?;
    warn_unsafe_policy(policy);
    let signals = verify::CaptureSignals::block().map_err(anyhow::Error::msg)?;
    let (manifest, plan, objects) = load_plan(&manifest_path, &provenance_module)?;
    let output = verify::SupervisorOutput::profile(out).map_err(anyhow::Error::msg)?;
    let outcome = verify::supervise_capture(signals, objects, output, move |worker| {
        capture_profile(manifest, plan, scope, mode, policy, duration, worker)
            .map_err(|error| format!("{error:#}"))
    })
    .map_err(anyhow::Error::msg)?;
    finish_supervised_capture(outcome)
}

fn capture_profile(
    manifest: Manifest,
    plan: plan::AttachPlan,
    scope: Scope,
    mode: String,
    policy: CapturePolicy,
    duration: Option<u64>,
    worker: &mut verify::WorkerContext,
) -> Result<()> {
    let interrupted = install_sigint_flag()?;
    worker
        .unblock_operator_signals()
        .map_err(anyhow::Error::msg)?;
    let (stdout, output, objects) = worker.output_parts();
    let has_output = output.is_some();
    let mut session =
        Session::start(&plan, &scope, objects, policy).context("starting attach session")?;
    objects
        .verify_stable()
        .map_err(anyhow::Error::msg)
        .context("rechecking authorized provider objects after attach")?;
    report_attach_failures(&session);

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
        objects
            .ensure_stable()
            .map_err(anyhow::Error::msg)
            .context("authorized provider object changed during capture")?;
        let elapsed = clock.elapsed();
        retire_exited(&mut process_tracker, &mut state);
        if should_stop(&interrupted, elapsed, duration) {
            break;
        }
        if mode == "profile" {
            malformed_records += drain_events(&mut session, &mut state, &mut process_tracker)?;
        }
        let mut kernel_evidence = metrics::kernel_evidence(&session)?;
        if mode != "profile" {
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
        );
        let frame = render::live(&reports, &ev, elapsed, &manifest.module_path, &mode, policy);
        objects
            .ensure_stable()
            .map_err(anyhow::Error::msg)
            .context("authorized provider object changed during capture")?;
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
    objects
        .ensure_stable()
        .map_err(anyhow::Error::msg)
        .context("authorized provider object changed during capture")?;
    if mode == "profile" {
        malformed_records += drain_events(&mut session, &mut state, &mut process_tracker)?;
    }
    retire_exited(&mut process_tracker, &mut state);
    let reports = metrics::read(&session, &plan)?;
    let mut kernel_evidence = metrics::kernel_evidence(&session)?;
    if mode != "profile" {
        kernel_evidence.ring_loss = 0;
    }
    let ev = evidence_for(
        &plan,
        &session,
        &reports,
        kernel_evidence,
        process_tracker.evidence(),
        malformed_records,
        &state,
    );
    let frame = render::live(
        &reports,
        &ev,
        clock.elapsed(),
        &manifest.module_path,
        &mode,
        policy,
    );
    objects
        .ensure_stable()
        .map_err(anyhow::Error::msg)
        .context("authorized provider object changed during capture")?;
    write_stdout(
        stdout,
        &mut stdout_open,
        format!("\x1b[2J\x1b[H{frame}").as_bytes(),
    )?;
    flush_stdout(stdout, &mut stdout_open)?;

    if let Some(out_file) = output.as_mut() {
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
        let j = if mode == "profile" {
            render::profile_json(&reports, &ev, &state, &capture)
        } else {
            render::json(&reports, &ev, &capture)
        };
        objects
            .ensure_stable()
            .map_err(anyhow::Error::msg)
            .context("authorized provider object changed during capture")?;
        write_json_report(out_file, &j)?;
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
fn cmd_trace(mut args: impl Iterator<Item = String>) -> Result<()> {
    let mut manifest_path: Option<PathBuf> = None;
    let mut provenance_module: Option<PathBuf> = None;
    let mut pid: Option<u32> = None;
    let mut cgroup: Option<PathBuf> = None;
    let mut duration: Option<u64> = None;
    let mut out: Option<PathBuf> = None;
    let mut unsafe_requested = false;

    while let Some(a) = args.next() {
        match a.as_str() {
            "--manifest" => manifest_path = Some(require_value(&mut args, "--manifest").into()),
            "--provenance-module" => {
                provenance_module = Some(require_value(&mut args, "--provenance-module").into())
            }
            "--pid" => {
                let v = require_value(&mut args, "--pid");
                pid = Some(
                    v.parse()
                        .with_context(|| format!("--pid: invalid number {v:?}"))?,
                );
            }
            "--cgroup" => cgroup = Some(require_value(&mut args, "--cgroup").into()),
            "--duration" => {
                let v = require_value(&mut args, "--duration");
                duration = Some(
                    v.parse()
                        .with_context(|| format!("--duration: invalid number {v:?}"))?,
                );
            }
            "-o" => out = Some(require_value(&mut args, "-o").into()),
            "--unsafe-unvalidated-metadata" => unsafe_requested = true,
            "--help" | "-h" => {
                eprintln!("{USAGE}");
                return Ok(());
            }
            other => {
                eprintln!("unknown argument: {other}\n{USAGE}");
                std::process::exit(2);
            }
        }
    }

    let policy = CapturePolicy::from_cli(
        "trace",
        unsafe_requested,
        cfg!(feature = "unsafe-unvalidated-metadata"),
    )?;

    let Some(manifest_path) = manifest_path else {
        eprintln!("--manifest is required\n{USAGE}");
        std::process::exit(2);
    };
    let Some(provenance_module) = provenance_module else {
        eprintln!("--provenance-module is required\n{USAGE}");
        std::process::exit(2);
    };
    if duration.is_none() {
        eprintln!(
            "p11scope: no --duration given; trace streams until interrupted (Ctrl-C) or the \
             process exits"
        );
    }
    let scope = resolve_scope(pid, cgroup)?;
    warn_unsafe_policy(policy);
    let signals = verify::CaptureSignals::block().map_err(anyhow::Error::msg)?;
    let (_manifest, plan, objects) = load_plan(&manifest_path, &provenance_module)?;
    let output = verify::SupervisorOutput::trace(out, policy).map_err(anyhow::Error::msg)?;
    let outcome = verify::supervise_capture(signals, objects, output, move |worker| {
        capture_trace(plan, scope, policy, duration, worker).map_err(|error| format!("{error:#}"))
    })
    .map_err(anyhow::Error::msg)?;
    finish_supervised_capture(outcome)
}

fn capture_trace(
    plan: plan::AttachPlan,
    scope: Scope,
    policy: CapturePolicy,
    duration: Option<u64>,
    worker: &mut verify::WorkerContext,
) -> Result<()> {
    let interrupted = install_sigint_flag()?;
    worker
        .unblock_operator_signals()
        .map_err(anyhow::Error::msg)?;
    let (stdout, out_file, objects) = worker.output_parts();
    let mut session =
        Session::start(&plan, &scope, objects, policy).context("starting attach session")?;
    objects
        .verify_stable()
        .map_err(anyhow::Error::msg)
        .context("rechecking authorized provider objects after attach")?;
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
        objects
            .ensure_stable()
            .map_err(anyhow::Error::msg)
            .context("authorized provider object changed during capture")?;
        let elapsed = clock.elapsed();
        if should_stop(&interrupted, elapsed, duration) {
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
        objects
            .ensure_stable()
            .map_err(anyhow::Error::msg)
            .context("authorized provider object changed during capture")?;
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
    // Final drain after detaching every producer: empty the remaining ring,
    // then report the closing loss line. Calls that had entered but did not
    // return before detach remain explicit in `in_flight_at_end`.
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
    objects
        .ensure_stable()
        .map_err(anyhow::Error::msg)
        .context("authorized provider object changed during capture")?;
    report_trace_loss(
        &session,
        &mut last_reported_loss,
        stdout,
        &mut stdout_open,
        out_file,
    )?;
    let reports = metrics::read(&session, &plan)?;
    let evidence = evidence_for(
        &plan,
        &session,
        &reports,
        metrics::kernel_evidence(&session)?,
        process_tracker.evidence(),
        malformed_records,
        &state,
    );
    objects
        .ensure_stable()
        .map_err(anyhow::Error::msg)
        .context("authorized provider object changed during capture")?;
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

fn finish_supervised_capture(outcome: verify::SupervisorOutcome) -> Result<()> {
    match outcome {
        verify::SupervisorOutcome::Exited(0) => Ok(()),
        verify::SupervisorOutcome::Exited(code) => std::process::exit(code),
        verify::SupervisorOutcome::LeaseBroken => std::process::exit(verify::OBJECT_CHANGED_EXIT),
        verify::SupervisorOutcome::Signaled(signal) => verify::mirror_worker_signal(signal),
    }
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
fn evidence_for(
    plan: &plan::AttachPlan,
    session: &Session,
    reports: &[metrics::SlotReport],
    kernel_evidence: metrics::KernelEvidence,
    tracking_evidence: process::TrackingEvidence,
    malformed_records: u64,
    state: &semantics::State,
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
                name: s.name.clone(),
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

    #[test]
    fn terminal_quiesce_precedes_final_drain_maps_and_evidence() {
        let source = include_str!("main.rs");
        let profile = source
            .split_once("fn capture_profile(")
            .unwrap()
            .1
            .split_once("fn write_json_report(")
            .unwrap()
            .0;
        let profile_detach = profile.rfind("session.detach_producers()?").unwrap();
        let profile_drain = profile.rfind("drain_events(").unwrap();
        let profile_maps = profile.rfind("metrics::read(").unwrap();
        let profile_output = profile.rfind("write_json_report(").unwrap();
        assert!(profile_detach < profile_drain);
        assert!(profile_detach < profile_maps);
        assert!(profile_maps < profile_output);

        let trace = source
            .split_once("fn capture_trace(")
            .unwrap()
            .1
            .split_once("fn finish_supervised_capture(")
            .unwrap()
            .0;
        let trace_detach = trace.rfind("session.detach_producers()?").unwrap();
        let trace_drain = trace.rfind("drain_trace_events(").unwrap();
        let trace_maps = trace.rfind("metrics::read(").unwrap();
        let trace_evidence = trace.rfind("trace::evidence_line(").unwrap();
        assert!(trace_detach < trace_drain);
        assert!(trace_drain < trace_maps);
        assert!(trace_maps < trace_evidence);
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
            Some(3600)
        ));

        interrupted.store(true, Ordering::Relaxed);
        assert!(
            should_stop(&interrupted, Duration::from_secs(0), None),
            "no --duration set at all"
        );
        assert!(
            should_stop(&interrupted, Duration::from_secs(0), Some(3600)),
            "must stop immediately even mid-way through a long --duration"
        );
    }

    #[test]
    fn should_stop_still_honors_duration_elapsing_without_an_interrupt() {
        let interrupted = AtomicBool::new(false);
        assert!(should_stop(&interrupted, Duration::from_secs(10), Some(5)));
        assert!(!should_stop(&interrupted, Duration::from_secs(4), Some(5)));
    }

    #[test]
    fn fork_only_traffic_does_not_consume_process_tracking_budget() {
        let plan = plan::AttachPlan {
            slots: vec![],
            skipped: vec![],
            entries_seen: 0,
            surfaces: vec![],
            vendor_interfaces: 0,
            interface_list: "absent".into(),
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
    fn manifest_v1_is_rejected_with_rediscovery_instruction() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("manifest-v1.json");
        std::fs::write(
            &path,
            r#"{
                "schema":"p11scope-manifest/1",
                "module_path":"/opt/provider.so",
                "objects":[],
                "interface_list":{"status":"absent"},
                "surfaces":[],
                "vendor_interfaces":[],
                "alias_groups":[]
            }"#,
        )
        .unwrap();

        let err = load_plan(&path, std::path::Path::new("/unused"))
            .unwrap_err()
            .to_string();
        assert!(err.contains("rediscover"), "{err}");
    }

    #[test]
    fn manifest_v2_is_rejected_with_rediscovery_instruction() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("manifest-v2.json");
        std::fs::write(
            &path,
            r#"{
                "schema":"p11scope-manifest/2",
                "module_path":"/opt/provider.so",
                "objects":[{"id":0,"path":"/opt/provider.so","identity":{"kind":"gnu_build_id","value":"aa","reusable":true,"note":null}}],
                "interface_list":{"status":"absent"},
                "surfaces":[],
                "vendor_interfaces":[],
                "alias_groups":[]
            }"#,
        )
        .unwrap();

        let err = load_plan(&path, std::path::Path::new("/unused"))
            .unwrap_err()
            .to_string();
        assert!(err.contains("rediscover"), "{err}");
    }

    /// The finalization a stopped loop runs into (profile's `-o` write)
    /// succeeds and produces valid JSON — exercised directly, standing in
    /// for "Ctrl-C a capture, confirm -o has valid JSON" without a real
    /// attach session (that part needs root + a real kernel; see the
    /// manual check documented in the phase report).
    #[test]
    fn policy_output_shutdown_path_replaces_a_file_with_valid_json() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("observed.json");
        let j = serde_json::json!({"schema": "pkcs11-scope/observed-profile/v1.4", "evidence": {}});

        let mut file = std::fs::File::create(&path).unwrap();
        file.write_all(b"stale trailing bytes that must disappear")
            .unwrap();
        write_json_report(&mut file, &j).expect("shutdown finalization must write the report");

        let written = std::fs::read_to_string(&path).unwrap();
        let parsed: serde_json::Value = serde_json::from_str(&written).expect("valid JSON");
        assert_eq!(parsed["schema"], "pkcs11-scope/observed-profile/v1.4");
    }

    #[cfg(not(feature = "unsafe-unvalidated-metadata"))]
    #[test]
    fn policy_output_unsafe_flag_is_refused_before_manifest_loading() {
        let error = cmd_profile(
            [
                "--unsafe-unvalidated-metadata",
                "--manifest",
                "/definitely/not/a/manifest.json",
                "--provenance-module",
                "/definitely/not/a/provider.so",
                "--pid",
                "1",
            ]
            .into_iter()
            .map(str::to_string),
        )
        .unwrap_err();
        let rendered = format!("{error:#}");
        assert!(rendered.contains("Cargo feature"), "{rendered}");
        assert!(!rendered.contains("reading manifest"), "{rendered}");
    }

    #[test]
    fn policy_output_profile_rejects_trace_mode_before_manifest_loading() {
        let error = cmd_profile(
            [
                "--mode",
                "trace",
                "--manifest",
                "/definitely/not/a/manifest.json",
                "--provenance-module",
                "/definitely/not/a/provider.so",
                "--pid",
                "1",
            ]
            .into_iter()
            .map(str::to_string),
        )
        .unwrap_err();
        let rendered = format!("{error:#}");
        assert!(rendered.contains("mode trace"), "{rendered}");
        assert!(!rendered.contains("reading manifest"), "{rendered}");
    }

    #[test]
    fn policy_output_discover_rejects_unsafe_flag_before_helper_lookup() {
        let error = cmd_discover(
            [
                "--unsafe-unvalidated-metadata",
                "--module",
                "/definitely/not/a/provider.so",
                "--helper",
                "/definitely/not/a/helper",
            ]
            .into_iter()
            .map(str::to_string),
        )
        .unwrap_err();
        let rendered = format!("{error:#}");
        assert!(rendered.contains("discover does not accept"), "{rendered}");
        assert!(!rendered.contains("helper"), "{rendered}");
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
