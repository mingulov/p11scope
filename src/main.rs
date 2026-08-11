//! p11scope — non-interposing PKCS#11 observer (eBPF uprobes). CLI entry
//! point; the modules themselves live in the `p11scope` library crate
//! (`src/lib.rs`) so integration tests can exercise them directly.

use anyhow::{Context as _, Result, anyhow, bail};
use p11scope::attach::{Scope, Session};
use p11scope::{discover_cmd, events, metrics, plan, render, scope, semantics, trace, verify};
use p11scope_manifest::manifest::{Manifest, SCHEMA};
use std::io::Write as _;
use std::path::PathBuf;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

const USAGE: &str = "usage:\n  \
p11scope profile --manifest <m.json> (--pid <n> | --cgroup <path>) [--mode profile|metrics] [--duration <secs>] [-o <out.json>]\n  \
p11scope trace --manifest <m.json> (--pid <n> | --cgroup <path>) [--duration <secs>] [-o <out.file>]\n  \
p11scope discover --module <provider.so> [-o <manifest.json>]\n\n\
note: --mode defaults to profile (metrics + mechanisms/sessions/logins from\n\
the event stream); --mode metrics is the lighter, maps-only level.\n\
note: trace prints one line per completed call as it happens, in arrival\n\
order, instead of aggregating; --duration bounds it, same as profile. If\n\
omitted, trace streams until interrupted (Ctrl-C) or the process exits.\n\
note: no SIGINT handler is installed in this build (no signal-handling\n\
dependency); Ctrl-C aborts without writing output. Use --duration for a\n\
clean exit that prints the final frame and (with -o) writes the JSON report.\n\
note: --cgroup matches that cgroup and every descendant cgroup beneath it\n\
(kernel >= 5.15 ancestor matching), so a container or pod directory works\n\
even though its processes live in a nested child cgroup. Sibling cgroups\n\
(anything not under the given path) are never matched. The path must be\n\
under /sys/fs/cgroup.";

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
        Some("discover") => discover_cmd::run(args),
        Some("--help") | Some("-h") => {
            eprintln!("{USAGE}");
            Ok(())
        }
        other => {
            eprintln!("unknown or missing subcommand: {}\n{USAGE}", other.unwrap_or("(none)"));
            std::process::exit(2);
        }
    }
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
        (None, Some(c)) => Ok(Scope::Cgroup { id: scope::cgroup_id(&c)?, level: scope::cgroup_level(&c)? }),
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
fn load_plan(manifest_path: &std::path::Path) -> Result<(Manifest, plan::AttachPlan)> {
    let text = std::fs::read_to_string(manifest_path)
        .with_context(|| format!("reading manifest {}", manifest_path.display()))?;
    let manifest: Manifest = serde_json::from_str(&text)
        .with_context(|| format!("parsing manifest {}", manifest_path.display()))?;
    if manifest.schema != SCHEMA {
        bail!(
            "manifest schema mismatch: got {:?}, this build expects {SCHEMA:?}",
            manifest.schema
        );
    }
    if let Err(problems) = verify::check_reuse(&manifest) {
        for p in &problems {
            eprintln!("p11scope: {p}");
        }
        bail!("manifest does not match the current files; refusing to attach");
    }

    let plan = plan::build(&manifest);
    if plan.slots.is_empty() {
        bail!(
            "attach plan is empty: manifest {} has no attachable slots",
            manifest_path.display()
        );
    }
    if plan.slots.len() > p11scope_ebpf_common::MAX_SLOTS as usize {
        bail!(
            "attach plan has {} slots, exceeding MAX_SLOTS ({}): BPF would silently drop slots \
             beyond that limit",
            plan.slots.len(),
            p11scope_ebpf_common::MAX_SLOTS
        );
    }
    Ok((manifest, plan))
}

/// Loads the embedded-default mechanism registry and publishes its
/// shapes into `state` — the same load `Session::start` already did to
/// publish `MECH_SHAPE` (attach.rs), reloaded here (cheap: no I/O, no
/// dlopen) so `state` can tell "no allowlisted shape for this
/// mechanism" apart from "an allowlisted shape whose decode failed on
/// every call" when rendering.
fn load_mech_shapes(state: &mut semantics::State) -> Result<()> {
    let registry = pkcs11_proxy_ng_types::mechanism_registry::MechanismRegistry::load(None)
        .map_err(|e| anyhow!("loading mechanism registry: {e}"))?;
    state.set_mech_shapes(p11scope::shapes::expected_shapes(&registry));
    Ok(())
}

fn cmd_profile(mut args: impl Iterator<Item = String>) -> Result<()> {
    let mut manifest_path: Option<PathBuf> = None;
    let mut pid: Option<u32> = None;
    let mut cgroup: Option<PathBuf> = None;
    let mut mode = "profile".to_string();
    let mut duration: Option<u64> = None;
    let mut out: Option<PathBuf> = None;

    while let Some(a) = args.next() {
        match a.as_str() {
            "--manifest" => manifest_path = Some(require_value(&mut args, "--manifest").into()),
            "--pid" => {
                let v = require_value(&mut args, "--pid");
                pid = Some(v.parse().with_context(|| format!("--pid: invalid number {v:?}"))?);
            }
            "--cgroup" => cgroup = Some(require_value(&mut args, "--cgroup").into()),
            "--mode" => mode = require_value(&mut args, "--mode"),
            "--duration" => {
                let v = require_value(&mut args, "--duration");
                duration =
                    Some(v.parse().with_context(|| format!("--duration: invalid number {v:?}"))?);
            }
            "-o" => out = Some(require_value(&mut args, "-o").into()),
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

    let Some(manifest_path) = manifest_path else {
        eprintln!("--manifest is required\n{USAGE}");
        std::process::exit(2);
    };
    let scope = resolve_scope(pid, cgroup)?;
    if mode != "metrics" && mode != "profile" {
        eprintln!("mode {mode} not implemented in this phase\n{USAGE}");
        std::process::exit(2);
    }

    let (manifest, plan) = load_plan(&manifest_path)?;

    let mut session = Session::start(&plan, &scope).context("starting attach session")?;
    for (idx, msg) in session.attach_failures() {
        eprintln!("attach failed (slot {idx}): {msg}");
    }

    // Only `--mode profile` decodes the event stream; `--mode metrics` never
    // drains the ring buffer, so it stays the lighter, maps-only level.
    let mut state = semantics::State::new(&plan);
    load_mech_shapes(&mut state)?;
    let mut malformed_records: u64 = 0;
    let drain_events = |session: &mut Session, state: &mut semantics::State| -> Result<u64> {
        let mut drain = events::Drain::new(&mut session.ebpf)?;
        drain.poll(|ev| state.observe(&ev));
        Ok(drain.malformed())
    };

    let wall_start = SystemTime::now();
    let clock = Instant::now();
    loop {
        let elapsed = clock.elapsed();
        if duration.is_some_and(|d| elapsed >= Duration::from_secs(d)) {
            break;
        }
        let event_loss = if mode == "profile" {
            malformed_records += drain_events(&mut session, &mut state)?;
            metrics::lost_events(&session)?
        } else {
            0
        };
        let reports = metrics::read(&session, &plan)?;
        let ev = evidence_for(&plan, &session, &reports, event_loss, malformed_records, &state);
        let frame = render::live(&reports, &ev, elapsed, &manifest.module_path, &mode);
        print!("\x1b[2J\x1b[H{frame}");
        std::io::stdout().flush().ok();
        std::thread::sleep(Duration::from_secs(1));
    }

    if mode == "profile" {
        malformed_records += drain_events(&mut session, &mut state)?;
    }
    let reports = metrics::read(&session, &plan)?;
    let event_loss = if mode == "profile" { metrics::lost_events(&session)? } else { 0 };
    let ev = evidence_for(&plan, &session, &reports, event_loss, malformed_records, &state);
    let frame = render::live(&reports, &ev, clock.elapsed(), &manifest.module_path, &mode);
    print!("\x1b[2J\x1b[H{frame}");
    std::io::stdout().flush().ok();

    if let Some(out_path) = out {
        let kernel = std::fs::read_to_string("/proc/sys/kernel/osrelease")
            .unwrap_or_default()
            .trim()
            .to_string();
        let started = fmt_rfc3339(wall_start);
        let ended = fmt_rfc3339(SystemTime::now());
        let j = if mode == "profile" {
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
            };
            render::profile_json(&reports, &ev, &state, &capture)
        } else {
            render::json(&reports, &ev, &manifest.module_path, &started, &ended, &kernel)
        };
        std::fs::write(&out_path, serde_json::to_vec_pretty(&j)?)
            .with_context(|| format!("writing {}", out_path.display()))?;
    }

    Ok(())
}

/// `p11scope trace`: one line per completed call, printed as it arrives,
/// instead of `profile`'s periodic aggregate frame. A separate
/// subcommand rather than a `--mode` — its transport (drain-and-print
/// every tick, no periodic full-screen redraw) and time-bounding differ
/// enough that folding it into `profile`'s loop would tangle both.
fn cmd_trace(mut args: impl Iterator<Item = String>) -> Result<()> {
    let mut manifest_path: Option<PathBuf> = None;
    let mut pid: Option<u32> = None;
    let mut cgroup: Option<PathBuf> = None;
    let mut duration: Option<u64> = None;
    let mut out: Option<PathBuf> = None;

    while let Some(a) = args.next() {
        match a.as_str() {
            "--manifest" => manifest_path = Some(require_value(&mut args, "--manifest").into()),
            "--pid" => {
                let v = require_value(&mut args, "--pid");
                pid = Some(v.parse().with_context(|| format!("--pid: invalid number {v:?}"))?);
            }
            "--cgroup" => cgroup = Some(require_value(&mut args, "--cgroup").into()),
            "--duration" => {
                let v = require_value(&mut args, "--duration");
                duration =
                    Some(v.parse().with_context(|| format!("--duration: invalid number {v:?}"))?);
            }
            "-o" => out = Some(require_value(&mut args, "-o").into()),
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

    let Some(manifest_path) = manifest_path else {
        eprintln!("--manifest is required\n{USAGE}");
        std::process::exit(2);
    };
    if duration.is_none() {
        eprintln!(
            "p11scope: no --duration given; trace streams until interrupted (Ctrl-C) or the \
             process exits"
        );
    }
    let scope = resolve_scope(pid, cgroup)?;
    let (_manifest, plan) = load_plan(&manifest_path)?;

    let mut session = Session::start(&plan, &scope).context("starting attach session")?;
    for (idx, msg) in session.attach_failures() {
        eprintln!("attach failed (slot {idx}): {msg}");
    }

    let mut state = semantics::State::new(&plan);
    load_mech_shapes(&mut state)?;
    let mut tracer = trace::Tracer::new(&plan);

    let mut out_file: Option<std::io::BufWriter<std::fs::File>> = match &out {
        Some(p) => Some(std::io::BufWriter::new(
            std::fs::File::create(p).with_context(|| format!("creating {}", p.display()))?,
        )),
        None => None,
    };

    let mut malformed_records: u64 = 0;
    let mut last_reported_loss: u64 = 0;
    let clock = Instant::now();
    loop {
        let elapsed = clock.elapsed();
        if duration.is_some_and(|d| elapsed >= Duration::from_secs(d)) {
            break;
        }
        malformed_records +=
            drain_trace_events(&mut session, &mut state, &mut tracer, &mut out_file)?;
        report_trace_loss(&session, &mut last_reported_loss, &mut out_file)?;
        std::io::stdout().flush().ok();
        if let Some(f) = out_file.as_mut() {
            f.flush().ok();
        }
        std::thread::sleep(Duration::from_millis(200));
    }

    // Final drain: catch whatever arrived since the last poll, then report
    // the closing loss line — a trace that lost events must never end
    // silently.
    malformed_records += drain_trace_events(&mut session, &mut state, &mut tracer, &mut out_file)?;
    report_trace_loss(&session, &mut last_reported_loss, &mut out_file)?;
    if malformed_records > 0 {
        eprintln!(
            "p11scope: {malformed_records} malformed ring-buffer records discarded this capture"
        );
    }
    if let Some(f) = out_file.as_mut() {
        f.flush().ok();
    }

    Ok(())
}

/// Prints (and, if given, appends to the `-o` file) every rendered line.
fn emit_trace_line(line: &str, out_file: &mut Option<std::io::BufWriter<std::fs::File>>) {
    println!("{line}");
    if let Some(f) = out_file {
        let _ = writeln!(f, "{line}");
    }
}

/// Drains whatever the ring buffer currently holds, rendering and
/// emitting one line per completed call. Returns the malformed-record
/// count from this drain, to accumulate at the call site.
fn drain_trace_events(
    session: &mut Session,
    state: &mut semantics::State,
    tracer: &mut trace::Tracer<'_>,
    out_file: &mut Option<std::io::BufWriter<std::fs::File>>,
) -> Result<u64> {
    let mut drain = events::Drain::new(&mut session.ebpf)?;
    drain.poll(|ev| emit_trace_line(&tracer.on_event(&ev, state), out_file));
    Ok(drain.malformed())
}

/// Emits `LOST n events` when the ring buffer's loss counter has grown
/// since the last report — mandatory whenever it is nonzero, so a trace
/// that dropped events never ends silently.
fn report_trace_loss(
    session: &Session,
    last_reported_loss: &mut u64,
    out_file: &mut Option<std::io::BufWriter<std::fs::File>>,
) -> Result<()> {
    let lost = metrics::lost_events(session)?;
    if lost > *last_reported_loss {
        if let Some(line) = trace::lost_line(lost) {
            emit_trace_line(&line, out_file);
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
    event_loss: u64,
    malformed_records: u64,
    state: &semantics::State,
) -> render::Evidence {
    let mut ev = render::Evidence {
        table_entries: plan.entries_seen,
        slots: plan.slots.len(),
        attached_probes: session.attached_probes(),
        attach_failures: session.attach_failures().iter().map(|(_, msg)| msg.clone()).collect(),
        aliased: plan.slots.iter().filter(|s| s.aliased).map(|s| s.names.clone()).collect(),
        skipped: plan
            .skipped
            .iter()
            .map(|s| render::SkippedOut { name: s.name.clone(), reason: s.reason.clone() })
            .collect(),
        in_flight_at_end: reports.iter().map(|r| r.in_flight).sum(),
        surfaces: plan.surfaces.clone(),
        vendor_interfaces: plan.vendor_interfaces,
        interface_list: plan.interface_list.clone(),
        event_loss,
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
}
