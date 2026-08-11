//! p11scope — non-interposing PKCS#11 observer (eBPF uprobes). CLI entry
//! point; the modules themselves live in the `p11scope` library crate
//! (`src/lib.rs`) so integration tests can exercise them directly.

use anyhow::{Context as _, Result, bail};
use p11scope::attach::{Scope, Session};
use p11scope::{discover_cmd, metrics, plan, render, scope, verify};
use p11scope_manifest::manifest::{Manifest, SCHEMA};
use std::io::Write as _;
use std::path::PathBuf;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

const USAGE: &str = "usage:\n  \
p11scope profile --manifest <m.json> (--pid <n> | --cgroup <path>) [--mode metrics] [--duration <secs>] [-o <out.json>]\n  \
p11scope discover --module <provider.so> [-o <manifest.json>]\n\n\
note: no SIGINT handler is installed in this build (no signal-handling\n\
dependency); Ctrl-C aborts without writing output. Use --duration for a\n\
clean exit that prints the final frame and (with -o) writes the JSON report.\n\
note: --cgroup matches that exact cgroup only, not descendant cgroups; a\n\
service whose processes live in child cgroups will show zero counts.";

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

fn cmd_profile(mut args: impl Iterator<Item = String>) -> Result<()> {
    let mut manifest_path: Option<PathBuf> = None;
    let mut pid: Option<u32> = None;
    let mut cgroup: Option<PathBuf> = None;
    let mut mode = "metrics".to_string();
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
    let scope = match (pid, cgroup) {
        (Some(p), None) => Scope::Pid(p),
        (None, Some(c)) => Scope::Cgroup(scope::cgroup_id(&c)?),
        (None, None) => {
            eprintln!("exactly one of --pid or --cgroup is required\n{USAGE}");
            std::process::exit(2);
        }
        (Some(_), Some(_)) => {
            eprintln!("--pid and --cgroup are mutually exclusive\n{USAGE}");
            std::process::exit(2);
        }
    };
    if mode != "metrics" {
        eprintln!("mode {mode} not implemented in this phase\n{USAGE}");
        std::process::exit(2);
    }

    let text = std::fs::read_to_string(&manifest_path)
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

    let session = Session::start(&plan, &scope).context("starting attach session")?;
    for (idx, msg) in session.attach_failures() {
        eprintln!("attach failed (slot {idx}): {msg}");
    }

    let wall_start = SystemTime::now();
    let clock = Instant::now();
    loop {
        let elapsed = clock.elapsed();
        if duration.is_some_and(|d| elapsed >= Duration::from_secs(d)) {
            break;
        }
        let reports = metrics::read(&session, &plan)?;
        let ev = evidence_for(&plan, &session, &reports);
        let frame = render::live(&reports, &ev, elapsed, &manifest.module_path);
        print!("\x1b[2J\x1b[H{frame}");
        std::io::stdout().flush().ok();
        std::thread::sleep(Duration::from_secs(1));
    }

    let reports = metrics::read(&session, &plan)?;
    let ev = evidence_for(&plan, &session, &reports);
    let frame = render::live(&reports, &ev, clock.elapsed(), &manifest.module_path);
    print!("\x1b[2J\x1b[H{frame}");
    std::io::stdout().flush().ok();

    if let Some(out_path) = out {
        let kernel = std::fs::read_to_string("/proc/sys/kernel/osrelease")
            .unwrap_or_default()
            .trim()
            .to_string();
        let started = fmt_rfc3339(wall_start);
        let ended = fmt_rfc3339(SystemTime::now());
        let j = render::json(&reports, &ev, &manifest.module_path, &started, &ended, &kernel);
        std::fs::write(&out_path, serde_json::to_vec_pretty(&j)?)
            .with_context(|| format!("writing {}", out_path.display()))?;
    }

    Ok(())
}

/// Evidence built from the plan (skips, aliases, surface/vendor gaps), the
/// session (attach failures), and the current reports (in-flight count).
/// Calls `.verdict()` itself before returning, so callers must not call it
/// again.
fn evidence_for(
    plan: &plan::AttachPlan,
    session: &Session,
    reports: &[metrics::SlotReport],
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
