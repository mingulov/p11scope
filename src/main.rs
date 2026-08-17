//! p11scope — non-interposing PKCS#11 observer (eBPF uprobes). CLI entry
//! point; the modules themselves live in the `p11scope` library crate
//! (`src/lib.rs`) so integration tests can exercise them directly.

use anyhow::{Context as _, Result, anyhow, bail};
use p11scope::attach::{CapturePolicy, Scope, Session};
use p11scope::cli::{self, CaptureArgs, CliError, Command, Kind, ScopeArg};
use p11scope::discovery::identity::{
    PinnedObjects, collapse_overlay_mappings, pin_manifest_objects, pin_scanned_objects,
};
use p11scope::discovery::scan::{
    ScanLimits, ScanOutcome, ScanRequest, ScannedModule, Skipped, scan_pid,
};
use p11scope::manifest_input::read_manifest;
use p11scope::output::AtomicFile;
use p11scope::{doctor, events, inspect, metrics, plan, process, render, scope, semantics, trace};
use p11scope_manifest::manifest::{Manifest, Resolution, SCHEMA};
use p11scope_manifest::maps::ObjectKey;
use std::collections::BTreeSet;
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
    match run() {
        Ok(0) => {}
        Ok(code) => std::process::exit(code),
        Err(e) => {
            // Every failure the observer can name arrives here as one line: an
            // unreadable target, a stale manifest, an environment without BPF.
            eprintln!("p11scope: {e:#}");
            std::process::exit(1);
        }
    }
}

fn run() -> Result<i32> {
    match cli::parse(std::env::args().skip(1)) {
        // `kind` travels inside the arguments, so both capture subcommands share
        // one arm as well as one parser.
        Ok(Command::Profile(a) | Command::Trace(a)) => cmd_capture(a).map(|()| 0),
        // Both of `inspect`'s hard failures — a pid that names nothing, and a target
        // that exited while its objects were being pinned — mean "the target could
        // not be read at all": one line here, exit 1, never a panic.
        Ok(Command::Inspect(a)) => inspect::run(a.pid, &a.modules, &a.hooks, a.json)
            .with_context(|| format!("inspect --pid {}", a.pid)),
        Ok(Command::Doctor(a)) => {
            if let Some(module) = &a.module {
                eprintln!(
                    "p11scope: doctor has no module lane yet; ignoring --module {}",
                    module.display()
                );
            }
            doctor::run(a.pid, a.cgroup.as_deref())
        }
        Err(CliError::Help) => {
            eprintln!("{}", cli::USAGE);
            Ok(0)
        }
        Err(CliError::Usage(msg)) => {
            eprintln!("{msg}");
            Ok(2)
        }
    }
}

/// Both capture subcommands: decide the policy, discover and pin what is in
/// scope, install the stop flag, then run the loop `kind` selects.
fn cmd_capture(a: CaptureArgs) -> Result<()> {
    let kind = a.kind;
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
            // Refuses a pid that names nothing before anything is opened, and gives
            // discovery a pin it can recheck: a recycled pid must not be scanned.
            process::PidPin::open(*p).map_err(|error| anyhow!("--pid {p}: {error}"))?;
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
    let discovered = discover_plan(&a, &scope)?;
    // Zero modules is not an error (spec §4.10): the capture still runs, still
    // writes its report, and says here how to find out why it found nothing.
    if discovered.plan.modules.is_empty() {
        eprintln!("{}", no_modules_hint(&a.scope));
    }
    let stop = install_stop_flag()?;
    match kind {
        Kind::Profile => capture_profile(
            discovered,
            scope,
            policy,
            a.duration,
            a.out.as_deref(),
            &stop,
        ),
        Kind::Trace => capture_trace(
            discovered,
            scope,
            policy,
            a.duration,
            a.out.as_deref(),
            &stop,
        ),
    }
}

/// Everything discovery produced: the plan, the objects it pinned, and the
/// record of how it found them. One value because every capture needs all
/// three and none of them means anything without the others.
struct Discovered {
    plan: plan::AttachPlan,
    pinned: PinnedObjects,
    discovery: render::DiscoveryEvidence,
}

/// How many processes of a `--cgroup` discovery scans.
///
/// ponytail: a flat cap, not a byte budget. A pod is a handful of processes; a
/// cgroup with thousands would otherwise pay the per-pid scan budget thousands of
/// times. Upgrade path if that ever bites: carry `ScanLimits::total_bytes` across
/// pids instead of counting them.
const MAX_SCAN_PIDS: usize = 256;

/// What the discovery pass learned besides the plan itself — everything
/// `discovery_evidence` needs that the plan does not already carry.
#[derive(Debug, Default)]
struct DiscoveryCounters {
    /// Manifest modules the scan contradicted; the union is attached (spec §4.12).
    conflicts: u64,
    /// Manifest modules nothing corroborated by the time the plan was built.
    uncorroborated: u64,
    /// `Some("ptrace")` when the memory scan could not read a target's memory.
    scan_unavailable: Option<&'static str>,
    scan_ms: u64,
    /// Manifest objects ignored, and why — evidence, never silence.
    notes: Vec<String>,
    /// Objects discovery saw but could not use at all: a mapping with no usable
    /// pathname, exports it could not read, one over the byte caps, a snapshot
    /// that ended early. Whole modules, not entries — the module they belong to
    /// publishes no table, so nothing else in the plan records the loss.
    object_skips: Vec<Skipped>,
    /// Which §4.12 outcome each corroborated module got, so `discovery[]` can
    /// tell an agreement from a conflict instead of publishing a counter with
    /// nothing to explain it.
    corroboration: Vec<(ObjectKey, &'static str)>,
}

impl DiscoveryCounters {
    /// The notes, on stderr. Called as soon as they are complete rather than from
    /// `report`, because every bail between the two would otherwise swallow them —
    /// and a note is most useful exactly when discovery is about to fail. The same
    /// facts reach the report as `evidence.discovery[].corroboration`.
    fn report_notes(&self) {
        for note in &self.notes {
            eprintln!("p11scope: {note}");
        }
    }

    /// What discovery ended up with, on stderr, before the capture starts.
    fn report(&self, plan: &plan::AttachPlan) {
        if let Some(reason) = self.scan_unavailable {
            eprintln!(
                "p11scope: the memory scan could not read the target ({reason}); any \
                 --manifest offsets are attached uncorroborated"
            );
        }
        eprintln!(
            "p11scope: discovery: {} module(s), {} attach slot(s), scan {}ms, \
             conflicts {}, uncorroborated {}",
            plan.modules.len(),
            plan.slots.len(),
            self.scan_ms,
            self.conflicts,
            self.uncorroborated,
        );
    }
}

/// Which of spec §4.12's outcomes one `--manifest` gets.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Corroboration {
    /// Not mapped in scope, or the scan could not run: its offsets stand alone.
    Uncorroborated,
    /// Mapped, and the scan found exactly the same {object, offset} set.
    Agreed,
    /// Mapped, but the two sets differ: attach the union and count a conflict.
    Conflict,
    /// Mapped and identity-matched, but the scan decoded no table in it at all —
    /// the documented primary use of `--manifest` (offsets for a provider the
    /// scan cannot read), not two sources contradicting each other. Attached
    /// exactly like `Conflict`, reported as uncorroborated rather than as a
    /// disagreement: there is no rival set to disagree with.
    ScanEmpty,
    /// Mapped with bytes the manifest did not record: ignore this manifest.
    IdentityMismatch,
}

/// Pure so all four cases are testable without a live target. `identity` is `None`
/// when the object is not mapped in scope (or was not pinnable), `Some(false)` when
/// the object is mapped but its SHA-256 is not the one the manifest recorded.
fn corroborate(
    scan_unavailable: bool,
    identity: Option<bool>,
    manifest_targets: &BTreeSet<(String, u64)>,
    scanned_targets: &BTreeSet<(String, u64)>,
) -> Corroboration {
    match identity {
        // A scan that could not read memory found no tables to compare against;
        // that is not evidence against the manifest.
        _ if scan_unavailable => Corroboration::Uncorroborated,
        None => Corroboration::Uncorroborated,
        Some(false) => Corroboration::IdentityMismatch,
        Some(true) if manifest_targets == scanned_targets => Corroboration::Agreed,
        // Nothing decoded is not a contradiction: the manifest is the only
        // source that ever had offsets here.
        Some(true) if scanned_targets.is_empty() => Corroboration::ScanEmpty,
        Some(true) => Corroboration::Conflict,
    }
}

/// The scan's view of the object a manifest describes, and whether the two agree on
/// its bytes. Matched by SHA-256 first — a manifest records the device and inode of
/// the host it was made on, which a container or a remount spells differently — and
/// by the recorded path second: a path match whose hash differs is exactly §4.12's
/// "manifest `sha256` ≠ the pinned object's".
fn scan_view<'a>(
    m: &Manifest,
    modules: &'a [ScannedModule],
    pinned: &PinnedObjects,
) -> Option<(&'a ScannedModule, bool)> {
    let sha_of = |module: &ScannedModule| {
        pinned
            .pinned()
            .find(|p| p.key == module.key)
            .map(|p| p.sha256.to_string())
    };
    let sha = m
        .objects
        .iter()
        .find(|o| o.path == m.module_path)
        .and_then(|o| o.identity.sha256.clone());
    if let Some(sha) = sha
        && let Some(module) = modules.iter().find(|m| sha_of(m).as_deref() == Some(&sha))
    {
        return Some((module, true));
    }
    let module = modules.iter().find(|module| module.path == m.module_path)?;
    // A module the scan saw but could not pin has no hash to disagree with: that is
    // "nothing corroborated it", never "the manifest is wrong".
    sha_of(module).map(|_| (module, false))
}

/// {object SHA-256, file offset} for every entry the scan decoded — the comparison
/// a manifest can be held against without depending on device and inode numbers.
fn scanned_targets(module: &ScannedModule, pinned: &PinnedObjects) -> BTreeSet<(String, u64)> {
    module
        .tables
        .iter()
        .flat_map(|table| &table.entries)
        .filter_map(|entry| {
            let sha = pinned.pinned().find(|p| p.key == entry.object)?.sha256;
            Some((sha.to_string(), entry.file_offset))
        })
        .collect()
}

/// The same set as a manifest records it.
fn manifest_targets(m: &Manifest) -> BTreeSet<(String, u64)> {
    m.surfaces
        .iter()
        .flat_map(|surface| &surface.functions)
        .filter_map(|function| match function.resolution {
            Resolution::Resolved {
                object,
                file_offset,
            } => {
                let record = m.objects.iter().find(|o| o.id == object)?;
                Some((record.identity.sha256.clone()?, file_offset))
            }
            _ => None,
        })
        .collect()
}

/// Replaces every `{device, inode}` a manifest *recorded* with the identity of the
/// object this capture actually *pinned* for it: the scan's pin of the module it
/// corroborated when there is one, this manifest's own pin otherwise.
///
/// A recorded pair is an identity from another host, another mount or another boot —
/// it is not an identity in this capture's namespace, and it must never be used as
/// one. Two things break if it is:
///
///  - `Session::start` resolves a slot by key first, so a recorded pair that happens
///    to equal a live pin of an *unrelated* file (inode reuse after a rebuild is
///    enough) attaches the manifest's offsets into that file;
///  - the union of §4.12 lands in two slots on one address, double-counting every
///    call, whenever the scan and the manifest name one object differently.
///
/// After this pass every key in the plan is one this capture pinned — the invariant
/// `attach.rs` resolves against, with no by-path fallback to paper over a miss.
fn retarget_to_pins(
    m: &mut Manifest,
    scanned: Option<&ScannedModule>,
    scan_pins: &PinnedObjects,
    own_pins: &PinnedObjects,
) {
    // Only the objects the matched scan saw. Any pin with the same bytes could
    // otherwise be adopted — including an earlier manifest's copy of a file this
    // target does not map, which is a probe that never fires.
    let seen: BTreeSet<ObjectKey> = scanned
        .into_iter()
        .flat_map(|module| {
            std::iter::once(module.key).chain(
                module
                    .tables
                    .iter()
                    .flat_map(|table| &table.entries)
                    .map(|entry| entry.object),
            )
        })
        .collect();
    // Driven from `objects[]`, because that is what was pinned: `pin_manifest_objects`
    // opens `ObjectRecord.path` and files the pin under it, so the own-pin lookup below
    // is an exact match rather than a second guess at which record describes which
    // file. `plan::provenance_of` then says which provenance record the plan will read
    // that object's identity from — the same relation, so the record rewritten here is
    // always the record read there.
    let updates: Vec<(usize, ObjectKey)> = m
        .objects
        .iter()
        .filter_map(|object| {
            let sha = object.identity.sha256.as_deref();
            let summary = scan_pins
                .pinned()
                .find(|p| seen.contains(&p.key) && Some(p.sha256) == sha)
                .or_else(|| own_pins.pinned().find(|p| p.path == object.path))?;
            Some((plan::provenance_of(m, object)?, summary.key))
        })
        .collect();
    for (index, key) in updates {
        let provenance = &mut m.provenance_objects[index];
        provenance.device_major = key.device.major;
        provenance.device_minor = key.device.minor;
        provenance.inode = key.inode;
    }
}

/// Every pid discovery must look at. `--cgroup` matches the named cgroup and every
/// descendant during capture, so discovery walks the same tree: a pod's processes
/// live in its container cgroups, never in `cgroup.procs` of the pod directory.
/// A subtree the observer cannot read is a set of processes that were never even
/// listed, let alone scanned: the losses are returned, not swallowed, so they end
/// up in `evidence.skipped` like every other thing discovery could not do.
fn scope_pids(scope: &Scope) -> (Vec<u32>, Vec<Skipped>) {
    let path = match scope {
        Scope::Pid(pid) => return (vec![*pid], Vec::new()),
        Scope::Cgroup { path, .. } => path,
    };
    let mut pids = Vec::new();
    let mut lost = Vec::new();
    let mut stack = vec![path.clone()];
    while let Some(dir) = stack.pop() {
        match std::fs::read_to_string(dir.join("cgroup.procs")) {
            Ok(text) => pids.extend(
                text.lines()
                    .filter_map(|line| line.trim().parse::<u32>().ok()),
            ),
            // Absent is not unreadable: a directory in the tree that is not a
            // cgroup has no `cgroup.procs` and hides nothing. Anything else —
            // permission, I/O — means processes exist here that were never listed.
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
            Err(error) => lost.push(Skipped {
                subject: dir.display().to_string(),
                reason: format!(
                    "cgroup.procs could not be read ({error}); no process of this cgroup \
                     was scanned"
                ),
            }),
        }
        match std::fs::read_dir(&dir) {
            Ok(entries) => {
                for entry in entries.flatten() {
                    if entry.file_type().is_ok_and(|kind| kind.is_dir()) {
                        stack.push(entry.path());
                    }
                }
            }
            // Gone, not hidden — the same rule as above, and the container
            // cgroups this walks churn constantly. A cgroup is only removable
            // once it is empty, so a directory that vanished between its
            // parent's listing and this read held no process to lose.
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
            Err(error) => lost.push(Skipped {
                subject: dir.display().to_string(),
                reason: format!(
                    "the cgroup directory could not be listed ({error}); any process \
                     below it was never discovered"
                ),
            }),
        }
    }
    pids.sort_unstable();
    pids.dedup();
    (pids, lost)
}

/// What a scope-wide loss is filed under: the cgroup path, or the pid.
fn scope_label(scope: &Scope) -> String {
    match scope {
        Scope::Pid(pid) => format!("pid {pid}"),
        Scope::Cgroup { path, .. } => path.display().to_string(),
    }
}

/// Zero modules is not an error (spec §4.10) — but an operator whose provider was
/// not found is owed the two commands that say why.
fn no_modules_hint(scope: &ScopeArg) -> String {
    match scope {
        ScopeArg::Pid(pid) => format!(
            "p11scope: no PKCS#11 modules discovered in pid {pid}; run \
             `p11scope inspect --pid {pid}` or `p11scope doctor --pid {pid}` to see why"
        ),
        ScopeArg::Cgroup(path) => format!(
            "p11scope: no PKCS#11 modules discovered in cgroup {0}; run \
             `p11scope inspect --pid <n>` for a process in it or \
             `p11scope doctor --cgroup {0}` to see why",
            path.display()
        ),
    }
}

/// Reads, parses and schema-checks one `--manifest`.
fn read_manifest_file(path: &Path) -> Result<Manifest> {
    let text = read_manifest(path)
        .map_err(|error| anyhow!("reading manifest {}: {error}", path.display()))?;
    let manifest: Manifest = serde_json::from_str(&text)
        .with_context(|| format!("parsing manifest {}", path.display()))?;
    if manifest.schema != SCHEMA {
        bail!(
            "manifest schema mismatch: got {:?}, this build expects {SCHEMA:?}; \
             rerun `p11scope-discover` to rediscover the module",
            manifest.schema
        );
    }
    Ok(manifest)
}

/// Scans one process and pins every object the scan named. The scan's own skips and
/// the pinning skips are printed rather than dropped: a module the observer could
/// see but not read is exactly the gap an operator needs to know about.
fn scan_and_pin(
    pid: u32,
    a: &CaptureArgs,
    limits: ScanLimits,
    counters: &mut DiscoveryCounters,
) -> Result<(Vec<ScannedModule>, PinnedObjects)> {
    let outcome = scan_pid(&ScanRequest {
        pid,
        hints: &a.modules,
        hooks: &a.hooks,
        limits,
    })
    .map_err(|error| anyhow!("scanning pid {pid}: {error}"))?;
    counters.scan_unavailable = counters.scan_unavailable.or(outcome.unavailable_reason());
    let (pinned, pin_skips) = pin_scanned_objects(pid, outcome.modules(), limits)
        .map_err(|error| anyhow!("pinning the objects of pid {pid}: {error}"))?;
    // Printed *and* kept: an object discovery could not read is a provider that
    // may never have been observed, and a report that only prints it leaves the
    // document claiming a clean capture.
    for skipped in outcome.skipped().iter().chain(&pin_skips) {
        eprintln!(
            "p11scope: discovery skipped {} — {}",
            skipped.subject, skipped.reason
        );
        counters.object_skips.push(skipped.clone());
    }
    let modules = match outcome {
        ScanOutcome::Scanned {
            modules, scan_ms, ..
        } => {
            counters.scan_ms += scan_ms;
            modules
        }
        ScanOutcome::Unavailable { modules, .. } => modules,
    };
    Ok((modules, pinned))
}

/// Drops every table entry whose object was not pinned, returning one `Skipped` per
/// drop. `pin_scanned_objects` skips an object it cannot open, identify or afford to
/// hash rather than failing the capture (spec §4.10) — so an entry pointing into one
/// has no attach path of its own, and `Session::start` resolves slots by key with no
/// fallback. Keeping such an entry would fail the whole attach, which is the opposite
/// of what that per-object skip exists for: this is the scanned half of "every key in
/// a plan is one this capture pinned".
fn drop_unpinned_entries(modules: &mut [ScannedModule], pinned: &PinnedObjects) -> Vec<Skipped> {
    let mut dropped = Vec::new();
    for module in modules {
        for table in &mut module.tables {
            let mut lost = Vec::new();
            table.entries.retain(|entry| {
                if pinned.pinned().any(|p| p.key == entry.object) {
                    return true;
                }
                lost.push(Skipped {
                    subject: entry.name.to_string(),
                    reason: format!(
                        "{} was not pinned; nothing to attach into",
                        entry.object_path
                    ),
                });
                false
            });
            dropped.extend(lost.iter().cloned());
            // Left on the table it came from, so the plan still counts it as a
            // record the scan saw and attributes the skip to this module.
            table.unpinned.extend(lost);
        }
    }
    dropped
}

/// Discovery for one capture: scan the scope, read and corroborate any manifests,
/// merge into one plan, pin every object, and record how all of it was found.
fn discover_plan(a: &CaptureArgs, scope: &Scope) -> Result<Discovered> {
    let limits = ScanLimits::default();
    let mut counters = DiscoveryCounters::default();
    let (pids, unlisted) = scope_pids(scope);
    counters.object_skips.extend(unlisted);
    // The pid the operator named is the capture; a cgroup's processes are many,
    // however few happen to be in it right now.
    let named = matches!(scope, Scope::Pid(_));
    let mut modules: Vec<ScannedModule> = Vec::new();
    let mut pinned = PinnedObjects::empty();
    if pids.len() > MAX_SCAN_PIDS {
        // Published, not just noted: a provider mapped only by a process past the
        // cap is undiscovered, unprobed, and has nothing else to show for it.
        counters.object_skips.push(Skipped {
            subject: scope_label(scope),
            reason: format!(
                "{} processes in scope; discovery scanned the first {MAX_SCAN_PIDS} — a \
                 provider mapped only by one of the rest was never discovered",
                pids.len()
            ),
        });
    }
    for pid in pids.iter().take(MAX_SCAN_PIDS) {
        match scan_and_pin(*pid, a, limits, &mut counters) {
            Ok((found, pins)) => {
                pinned.absorb(pins);
                // Ten processes of one container map one object under one key; ten
                // containers of one image map it under ten (each mount has its own
                // anonymous device). Only the first case is a key match, so this
                // dedupe cannot see the second — `collapse_overlay_mappings` below
                // handles the measured shared-layer case with explicit uncertainty.
                for module in found {
                    if !modules.iter().any(|known| known.key == module.key) {
                        modules.push(module);
                    }
                }
            }
            // The pid the operator named *is* the capture; any other is one of many
            // in a cgroup, and may legitimately exit between listing and scanning —
            // legitimate, but still a process whose providers went unexamined.
            Err(error) if named => return Err(error),
            Err(error) => {
                eprintln!("p11scope: discovery skipped pid {pid}: {error:#}");
                counters.object_skips.push(Skipped {
                    subject: format!("pid {pid}"),
                    reason: format!("the process could not be scanned: {error:#}"),
                });
            }
        }
    }

    // Before corroboration: an entry nothing pinned is not a target either source
    // can be held to, and must never reach the plan.
    let unpinned = drop_unpinned_entries(&mut modules, &pinned);
    for skipped in &unpinned {
        eprintln!(
            "p11scope: discovery skipped {} — {}",
            skipped.subject, skipped.reason
        );
    }

    // Then, and only then: collapse the common shared-overlay-layer shape so one kernel
    // uprobe point is not registered once per container mount. Overlay classification
    // and matching bytes cannot prove physical identity, so every rewrite below also
    // publishes uncertainty and forces PARTIAL. Run after the drop so election counts
    // only targets that can actually be attached.
    let (collapsed, differed) = collapse_overlay_mappings(&mut modules, &pinned);
    if collapsed > 0 {
        eprintln!(
            "p11scope: discovery: {collapsed} matching overlay mapping(s) were collapsed \
             onto one attach target; physical identity is not provable, so published \
             uncertainty makes this capture PARTIAL"
        );
    }
    for skipped in &differed {
        eprintln!(
            "p11scope: discovery skipped {} — {}",
            skipped.subject, skipped.reason
        );
    }
    counters.object_skips.extend(differed);

    let mut accepted: Vec<Manifest> = Vec::new();
    let mut corroborated: Vec<ObjectKey> = Vec::new();
    // Only §4.12's identity mismatch: a manifest whose bytes are not the mapped
    // object's. Distinct from `counters.uncorroborated`, which counts manifests that
    // were *accepted* with nothing to corroborate them.
    let mut identity_mismatches = 0usize;
    for path in &a.manifests {
        // Both `?`s below leave discovery: the notes accumulated so far are most
        // useful exactly here, so they are printed before either returns.
        let mut manifest = read_manifest_file(path).inspect_err(|_| counters.report_notes())?;
        let manifest_pins = pin_manifest_objects(&manifest).map_err(|problems| {
            counters.report_notes();
            for problem in &problems {
                eprintln!("p11scope: {problem}");
            }
            anyhow!(
                "manifest {} does not match the current files; refusing to attach",
                path.display()
            )
        })?;
        let view = scan_view(&manifest, &modules, &pinned);
        let mapped = view.map(|(module, _)| module.key);
        let outcome = corroborate(
            counters.scan_unavailable.is_some(),
            view.map(|(_, agrees)| agrees),
            &manifest_targets(&manifest),
            &view
                .map(|(module, _)| scanned_targets(module, &pinned))
                .unwrap_or_default(),
        );
        counters
            .corroboration
            .extend(mapped.map(|key| (key, corroboration_label(outcome))));
        match outcome {
            // Every offset it carries is already in the plan; nothing to add but the
            // fact that a second source said the same thing.
            Corroboration::Agreed => corroborated.extend(mapped),
            Corroboration::ScanEmpty => {
                // Not marked corroborated: nothing confirmed these offsets, so the
                // module is counted as uncorroborated and the capture is PARTIAL.
                counters.notes.push(format!(
                    "the memory scan decoded no function table in {}; attaching the \
                     offsets manifest {} records, uncorroborated",
                    manifest.module_path,
                    path.display(),
                ));
                retarget_to_pins(
                    &mut manifest,
                    view.map(|(module, _)| module),
                    &pinned,
                    &manifest_pins,
                );
                accepted.push(manifest);
                pinned.absorb(manifest_pins);
            }
            Corroboration::Conflict => {
                counters.conflicts += 1;
                counters.notes.push(format!(
                    "manifest {} and the memory scan decoded different targets in {}; \
                     attaching the union of both",
                    path.display(),
                    manifest.module_path
                ));
                corroborated.extend(mapped);
                retarget_to_pins(
                    &mut manifest,
                    view.map(|(module, _)| module),
                    &pinned,
                    &manifest_pins,
                );
                accepted.push(manifest);
                pinned.absorb(manifest_pins);
            }
            Corroboration::Uncorroborated => {
                // No scan pin to prefer, but the recorded identity is still not one of
                // this capture's: it becomes the manifest's own pin.
                retarget_to_pins(&mut manifest, None, &pinned, &manifest_pins);
                accepted.push(manifest);
                pinned.absorb(manifest_pins);
            }
            Corroboration::IdentityMismatch => {
                identity_mismatches += 1;
                counters.notes.push(format!(
                    "ignoring manifest {}: the {} mapped in the target does not hash to \
                     the sha256 it records",
                    path.display(),
                    manifest.module_path
                ));
            }
        }
    }

    counters.report_notes();

    // Each dropped record stayed on the table it came from, so the plan counts
    // it as seen and files its skip under its own module. The scan's object-level
    // losses have no module to be filed under and are added here.
    let mut plan = plan::build_from_sources(&modules, &accepted);
    record_object_skips(&mut plan, &counters.object_skips);
    for key in &corroborated {
        if let Some(summary) = plan.modules.iter_mut().find(|m| m.key == *key) {
            summary.corroborated = true;
            if summary.source == "scan" {
                summary.source = "scan+manifest";
            }
        }
    }
    counters.uncorroborated = uncorroborated_count(&plan, identity_mismatches);
    // Ignoring a manifest is only fatal when it was the sole discovery source and
    // nothing else found a table (spec §4.12).
    if identity_mismatches > 0 && plan.slots.is_empty() {
        bail!(
            "{identity_mismatches} --manifest input(s) were ignored as stale — their \
             recorded sha256 is not the mapped object's (see the lines above) — and no \
             discovery source found a function table"
        );
    }
    for refused in &plan.modules_skipped {
        eprintln!(
            "p11scope: module refused: {} — {}",
            refused.subject, refused.reason
        );
    }
    if let Some(error) = refusal_error(&plan) {
        bail!(error);
    }
    plan::ensure_capacity(&plan).map_err(|error| anyhow!(error))?;
    counters.report(&plan);
    let discovery = discovery_evidence(&plan, &pinned, &counters);
    Ok(Discovered {
        plan,
        pinned,
        discovery,
    })
}

/// Modules whose offsets nothing corroborated, plus every `--manifest` ignored
/// as stale (§4.12 case 4). An ignored manifest never becomes a plan module, so
/// the filter cannot see it — and a stale manifest supplied for exactly the
/// provider the scan cannot read leaves that provider unobserved with nothing
/// else in the document to notice. Counted here, it forces `PARTIAL`.
fn uncorroborated_count(plan: &plan::AttachPlan, identity_mismatches: usize) -> u64 {
    let uncorroborated = plan
        .modules
        .iter()
        .filter(|m| m.source.contains("manifest") && !m.corroborated)
        .count();
    (uncorroborated + identity_mismatches) as u64
}

/// Folds the scan's own object-level losses into the plan's skip list, where
/// `Evidence::verdict` already turns any skip into `PARTIAL`. Deduplicated:
/// a `--cgroup` scans every process in the tree, and one provider ten of them
/// map is one loss, not ten lines of the same one.
fn record_object_skips(plan: &mut plan::AttachPlan, skips: &[Skipped]) {
    for skip in skips {
        if !plan.skipped.contains(skip) {
            plan.skipped.push(skip.clone());
        }
    }
}

/// The merge refuses an over-capacity module whole rather than attaching a
/// prefix (`plan::merge`). One provider over the ceiling must not cost the
/// capture the other providers could still have shared, so a refusal is
/// reported — it reaches `evidence.modules_skipped` and forces PARTIAL — rather
/// than aborting. It stays an error only when it leaves nothing to attach: an
/// empty capture whose emptiness was caused by a refusal is not the "no modules
/// discovered" case (spec §4.10) and must not read like it.
fn refusal_error(plan: &plan::AttachPlan) -> Option<String> {
    let refused = plan.modules_skipped.first()?;
    plan.slots.is_empty().then(|| {
        format!(
            "every module discovery found was refused at the {} attach-slot ceiling, \
             leaving nothing to attach — first refusal: {} — {}",
            p11scope_ebpf_common::MAX_SLOTS,
            refused.subject,
            refused.reason
        )
    })
}

/// The `discovery[]` record: what was found, where it was found, and how well
/// the two sources agreed. Identity is `{dev, ino, sha256}` — a path here is
/// only the label the source that saw it used, and for anything the scan found
/// that label lives in the *target's* mount namespace.
fn discovery_evidence(
    plan: &plan::AttachPlan,
    pinned: &PinnedObjects,
    counters: &DiscoveryCounters,
) -> render::DiscoveryEvidence {
    let summary_of = |key: ObjectKey, path: &str| {
        let pin = pinned.pinned().find(|p| p.key == key);
        render::ObjectSummary {
            dev: (key.device.major, key.device.minor),
            ino: key.inode,
            // Absent, not empty: nothing hashed it, so there is no digest to
            // report — an empty string would read as one.
            sha256: pin.map(|p| p.sha256.to_string()),
            path: pin.map_or_else(|| path.to_string(), |p| p.path.to_string()),
            build_id: pin.and_then(|p| p.build_id.map(str::to_string)),
            identity_source: pin.map_or("unpinned", |p| p.identity_source),
            note: pin.and_then(|p| p.note.map(str::to_string)),
        }
    };
    let modules = plan
        .modules
        .iter()
        .map(|m| {
            let mut seen: BTreeSet<ObjectKey> = BTreeSet::new();
            let objects: Vec<render::ObjectSummary> = plan
                .slots
                .iter()
                .filter(|s| s.module_ids.contains(&m.id) && seen.insert(s.object))
                .map(|s| summary_of(s.object, &s.object_path))
                .collect();
            let identity = summary_of(m.key, &m.path);
            render::DiscoveredModule {
                dev: identity.dev,
                ino: identity.ino,
                sha256: identity.sha256,
                path: m.path.clone(),
                build_id: identity.build_id,
                objects,
                sources: m.source.split('+').collect(),
                corroborated: m.corroborated,
                // Every outcome recorded against this object, not the first:
                // `--manifest` is repeatable, and two manifests naming one
                // object would otherwise render one outcome beside a
                // `corroborated` the other produced.
                corroboration: corroboration_of(counters, m),
                tables: m.tables.clone(),
                interfaces: m.interfaces,
                skipped: m.skipped.iter().map(skipped_out).collect(),
            }
        })
        .collect();
    render::DiscoveryEvidence {
        modules,
        conflicts: counters.conflicts,
        uncorroborated: counters.uncorroborated,
        module_ambiguous: plan.module_ambiguous as u64,
        modules_skipped: plan.modules_skipped.iter().map(skipped_out).collect(),
        scan_unavailable: counters.scan_unavailable.map(str::to_string),
        scan_ms: counters.scan_ms,
        ..render::DiscoveryEvidence::default()
    }
}

/// Every §4.12 outcome recorded against this module's object — one per
/// `--manifest` that named it. Empty only when no manifest did, which the
/// record states as `single_source` rather than as silence.
fn corroboration_of(counters: &DiscoveryCounters, m: &plan::ModuleSummary) -> Vec<&'static str> {
    let recorded: Vec<&'static str> = counters
        .corroboration
        .iter()
        .filter(|(key, _)| *key == m.key)
        .map(|(_, label)| *label)
        .collect();
    if !recorded.is_empty() {
        return recorded;
    }
    vec![if !m.source.contains("manifest") {
        "single_source"
    } else if m.corroborated {
        "agreed"
    } else {
        "uncorroborated"
    }]
}

fn skipped_out(s: &Skipped) -> render::SkippedOut {
    render::SkippedOut {
        name: s.subject.clone(),
        reason: s.reason.clone(),
    }
}

fn corroboration_label(outcome: Corroboration) -> &'static str {
    match outcome {
        Corroboration::Uncorroborated => "uncorroborated",
        Corroboration::Agreed => "agreed",
        Corroboration::Conflict => "conflict",
        Corroboration::ScanEmpty => "scan_empty",
        Corroboration::IdentityMismatch => "identity_mismatch",
    }
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

/// The provider line the live frame shows. One line for a screen header, where
/// `capture.modules[]` is the report's answer: a capture that observed two
/// providers says so rather than picking one and calling it "the" module.
fn module_label(plan: &plan::AttachPlan) -> String {
    match plan.modules.as_slice() {
        [] => "no modules discovered".to_string(),
        [only] => only.path.clone(),
        [first, rest @ ..] => format!("{} (+{} more)", first.path, rest.len()),
    }
}

fn capture_profile(
    discovered: Discovered,
    scope: Scope,
    policy: CapturePolicy,
    duration: Option<Duration>,
    out: Option<&Path>,
    interrupted: &AtomicBool,
) -> Result<()> {
    let Discovered {
        plan,
        pinned,
        discovery,
    } = discovered;
    let pinned = &pinned;
    let module_label = module_label(&plan);
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
            &discovery,
        );
        let frame = render::live(&reports, &ev, elapsed, &module_label, mode, policy);
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
        &discovery,
    );
    ev.mark_terminal_drain_unproven();
    let frame = render::live(&reports, &ev, clock.elapsed(), &module_label, mode, policy);
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
        // `capture.modules[]` comes from the evidence, not from here: one list,
        // rendered twice, so the two sections cannot disagree.
        let capture = render::CaptureMeta {
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
    discovered: Discovered,
    scope: Scope,
    policy: CapturePolicy,
    duration: Option<Duration>,
    out: Option<&Path>,
    interrupted: &AtomicBool,
) -> Result<()> {
    let Discovered {
        plan,
        pinned,
        discovery,
    } = discovered;
    let pinned = &pinned;
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
        &discovery,
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
    discovery: &render::DiscoveryEvidence,
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
            .map(render::capture_skipped_out)
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
        discovery: discovery.clone(),
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
    use p11scope::discovery::scan::ScannedEntry;
    use std::os::unix::fs::MetadataExt as _;

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
            let err = read_manifest_file(&path).unwrap_err().to_string();
            assert!(err.contains("rediscover"), "{err}");
        }
    }

    fn targets(offsets: &[u64]) -> BTreeSet<(String, u64)> {
        offsets
            .iter()
            .map(|offset| ("11".repeat(32), *offset))
            .collect()
    }

    /// Our own executable, scanned and pinned the way a capture pins a provider:
    /// a real `PinnedObjects` with one key in it, with no privileges needed.
    fn pinned_self() -> (Vec<ScannedModule>, PinnedObjects) {
        let hooks = p11scope::discovery::hooks::HookRegistry::builtin();
        let exe = std::env::current_exe().unwrap();
        // Unbounded on purpose: `pin_scanned_object` caps on the whole file size, and
        // this test binary is already at 96% of the 64 MiB default. The byte caps are
        // not what these tests are about, and a silent skip would fail them with
        // "the hinted executable is pinned", which names the symptom, not the cause.
        let limits = ScanLimits {
            per_object_bytes: u64::MAX,
            total_bytes: u64::MAX,
        };
        let outcome = scan_pid(&ScanRequest {
            pid: std::process::id(),
            hints: &[exe],
            hooks: &hooks,
            limits,
        })
        .unwrap();
        let modules = outcome.modules().to_vec();
        let (pinned, _) = pin_scanned_objects(std::process::id(), &modules, limits).unwrap();
        assert_eq!(
            pinned.pinned().count(),
            1,
            "the hinted executable is pinned"
        );
        (modules, pinned)
    }

    /// The pin `pin_manifest_objects` produces for one manifest object: filed under
    /// the path the manifest names (`ObjectRecord.path`, which it opens), keyed by the
    /// identity that path resolves to right now. Built through `pin_scanned_objects`
    /// only because reaching `pin_manifest_objects` needs a canonical full function
    /// list; the `Entry` — the only thing a retarget reads — is the same one.
    fn pin_as_manifest_object(object_path: &str) -> PinnedObjects {
        let file = p11scope_manifest::identity::open_object(Path::new(object_path)).unwrap();
        let found = p11scope_manifest::identity::mapping_file_key(&file).unwrap();
        let (pins, skipped) = pin_scanned_objects(
            std::process::id(),
            &[ScannedModule {
                key: ObjectKey {
                    device: p11scope_manifest::maps::Device {
                        major: found.device_major,
                        minor: found.device_minor,
                    },
                    inode: found.inode,
                },
                path: object_path.to_string(),
                exports: vec![],
                tables: vec![],
                interfaces: vec![],
            }],
            ScanLimits::default(),
        )
        .unwrap();
        assert!(skipped.is_empty(), "{skipped:?}");
        pins
    }

    fn entry(name: &'static str, object: ObjectKey, file_offset: u64) -> ScannedEntry {
        ScannedEntry {
            name,
            object,
            object_path: format!("/opt/{}.so", object.inode),
            file_offset,
        }
    }

    /// An entry whose object could not be pinned has no attach path of its own. Left
    /// in the plan it either kills the whole capture (§4.10 says one unusable
    /// dependency must not) or, once a manifest is in the same plan, falls back to
    /// the *observer's* file at the target's pathname — a different file, silently
    /// probed at scan-derived offsets.
    #[test]
    fn a_table_entry_whose_object_was_not_pinned_never_becomes_a_slot() {
        let (mut modules, pinned) = pinned_self();
        let pinned_key = pinned.pinned().next().unwrap().key;
        let unpinned_key = ObjectKey {
            device: p11scope_manifest::maps::Device {
                major: 0xffff,
                minor: 0xffff,
            },
            inode: u64::MAX,
        };
        modules[0]
            .tables
            .push(p11scope::discovery::scan::ScannedTable {
                version: (2, 40),
                walk: "full",
                entries: vec![
                    entry("C_Sign", pinned_key, 0x10),
                    entry("C_Verify", unpinned_key, 0x20),
                ],
                null_entries: vec![],
                unpinned: vec![],
                address: 0x7000,
            });

        let dropped = drop_unpinned_entries(&mut modules, &pinned);
        assert_eq!(dropped.len(), 1, "{dropped:?}");
        assert_eq!(dropped[0].subject, "C_Verify");
        assert!(dropped[0].reason.contains("not pinned"), "{dropped:?}");

        let plan = plan::build_from_modules(&modules);
        assert_eq!(plan.slots.len(), 1, "only the pinned target attaches");
        for slot in &plan.slots {
            assert!(
                pinned.attach_path_for(slot.object).is_ok(),
                "every scanned slot must have a pinned object of its own: {slot:?}"
            );
        }
        // A record the scan decoded and could not use is still a record it saw:
        // dropping it from `entries_seen` would make `slots` vs `table_entries`
        // read as "everything seen was attached". It is reported as a skip too,
        // the same way a NULL entry is, and attributed to its own module.
        assert_eq!(plan.entries_seen, 2, "the dropped entry stays counted");
        assert_eq!(plan.skipped.len(), 1, "{:?}", plan.skipped);
        assert_eq!(plan.skipped[0].subject, "C_Verify");
        assert_eq!(plan.modules[0].skipped, plan.skipped);
        // The reason the drop is recorded on the table rather than added to the
        // total afterwards: per-surface counts and the total stay one number.
        assert_eq!(
            plan.surfaces.iter().map(|s| s.functions).sum::<usize>(),
            plan.entries_seen,
            "every record counted in table_entries belongs to a surface"
        );
    }

    /// An object the scan could not read at all is the loss `discovery[]` cannot
    /// show: the module it belonged to contributes no table, so it produces no
    /// entry to skip, no attach to fail and no counter to raise. Printed and
    /// dropped, it leaves a document whose every field says the capture was
    /// clean while a provider went unobserved.
    #[test]
    fn an_object_the_scan_could_not_read_is_published_not_only_printed() {
        let (modules, _) = pinned_self();
        // The same objects, pinned under a cap they cannot fit: every one is
        // skipped, exactly as a memfd, a deleted file or an unreadable mapping
        // would be — without needing one.
        let tiny = ScanLimits {
            per_object_bytes: 1024,
            total_bytes: 1024,
        };
        let (pinned, skips) = pin_scanned_objects(std::process::id(), &modules, tiny).unwrap();
        assert_eq!(pinned.pinned().count(), 0, "nothing could be pinned");
        assert!(!skips.is_empty(), "the scan reported the loss");

        let mut modules = modules;
        drop_unpinned_entries(&mut modules, &pinned);
        let mut plan = plan::build_from_modules(&modules);
        assert!(
            plan.skipped.is_empty(),
            "the module published no table, so nothing else records the loss: {:?}",
            plan.skipped
        );

        record_object_skips(&mut plan, &skips);
        assert_eq!(plan.skipped.len(), skips.len(), "{:?}", plan.skipped);
        assert!(
            plan.skipped.iter().any(|s| s.reason.contains("too_large")),
            "{:?}",
            plan.skipped
        );

        // A cgroup scans many processes mapping the same provider; one loss is
        // one line however many processes hit it — and two *different* losses
        // are still two, which a dedupe that collapsed by subject would lose.
        let other = Skipped {
            subject: skips[0].subject.clone(),
            reason: "a second, different loss of the same object".into(),
        };
        let mixed: Vec<Skipped> = skips
            .iter()
            .chain(skips.iter())
            .cloned()
            .chain([other.clone()])
            .collect();
        let mut plan = plan::build_from_modules(&modules);
        record_object_skips(&mut plan, &mixed);
        assert_eq!(plan.skipped.len(), skips.len() + 1, "{:?}", plan.skipped);
        assert!(plan.skipped.contains(&other), "{:?}", plan.skipped);
    }

    fn plan_with(slots: usize, refused: usize) -> plan::AttachPlan {
        plan::AttachPlan {
            slots: (0..slots)
                .map(|index| plan::Slot {
                    index: index as u32,
                    object: ObjectKey {
                        device: p11scope_manifest::maps::Device { major: 8, minor: 1 },
                        inode: 42,
                    },
                    object_path: "/opt/p11.so".into(),
                    file_offset: index as u64 * 8,
                    names: vec!["C_Sign".into()],
                    aliased: false,
                    semantics: p11scope_ebpf_common::SlotSemantics::COUNT_ONLY,
                    semantic_ambiguous: false,
                    fork_safe: false,
                    module_ids: vec![plan::ModuleId(0)],
                })
                .collect(),
            modules: vec![plan::ModuleSummary {
                id: plan::ModuleId(0),
                key: ObjectKey {
                    device: p11scope_manifest::maps::Device { major: 8, minor: 1 },
                    inode: 42,
                },
                path: "/opt/p11.so".into(),
                tables: vec![],
                interfaces: 0,
                source: "scan",
                corroborated: false,
                skipped: vec![],
            }],
            skipped: vec![],
            modules_skipped: (0..refused)
                .map(|i| Skipped {
                    subject: format!("/opt/big{i}.so"),
                    reason: "module needs 600 more of the 512 attach slots".into(),
                })
                .collect(),
            entries_seen: slots,
            surfaces: vec![],
            vendor_interfaces: 0,
            interface_list: "absent".into(),
            module_ambiguous: 0,
        }
    }

    /// One provider over the slot ceiling must not cost the capture the other
    /// providers could still have shared: the refusal is evidence (and forces
    /// PARTIAL), not an abort. It stays an error only when nothing is left.
    #[test]
    fn a_partial_capacity_refusal_is_reported_and_only_an_empty_one_is_fatal() {
        assert_eq!(refusal_error(&plan_with(4, 0)), None, "nothing refused");
        assert_eq!(
            refusal_error(&plan_with(4, 1)),
            None,
            "one refused module must not lose the four slots that fit"
        );
        assert_eq!(refusal_error(&plan_with(0, 0)), None, "§4.10: not an error");
        let error = refusal_error(&plan_with(0, 1)).expect("a refusal with nothing left is fatal");
        assert!(error.contains("nothing to attach"), "{error}");
        assert!(error.contains("/opt/big0.so"), "{error}");

        // …and the refusal reaches evidence, which is what makes reporting it
        // instead of aborting honest: `render::Evidence::verdict` turns a
        // non-empty `modules_skipped` into PARTIAL (see `render`'s own tests).
        let evidence = discovery_evidence(
            &plan_with(4, 1),
            &PinnedObjects::empty(),
            &DiscoveryCounters::default(),
        );
        assert_eq!(evidence.modules_skipped.len(), 1);
        assert_eq!(evidence.modules_skipped[0].name, "/opt/big0.so");
        assert!(
            evidence.modules_skipped[0].reason.contains("attach slots"),
            "{:?}",
            evidence.modules_skipped[0]
        );
    }

    /// A manifest ignored as stale is the one §4.12 outcome with no module of
    /// its own in the plan — and the one most likely to be covering a provider
    /// the scan cannot read, which is then observed by nobody.
    #[test]
    fn an_ignored_stale_manifest_is_counted_as_uncorroborated() {
        let mut plan = plan_with(1, 0);
        assert_eq!(uncorroborated_count(&plan, 0), 0, "a scanned module is not");
        assert_eq!(
            uncorroborated_count(&plan, 1),
            1,
            "an ignored manifest must reach a counter, or it reaches none"
        );
        plan.modules[0].source = "manifest";
        assert_eq!(uncorroborated_count(&plan, 1), 2, "both are counted");
        plan.modules[0].corroborated = true;
        assert_eq!(uncorroborated_count(&plan, 0), 0);
    }

    /// Both §4.12 outcomes that attach a union mark the module corroborated, so
    /// without the outcome itself an agreement and a conflict are the same
    /// record — and `discovery_conflicts` would have nothing explaining it.
    #[test]
    fn the_module_record_says_which_corroboration_outcome_it_got() {
        let plan = plan_with(1, 0);
        let key = plan.modules[0].key;
        for (outcome, label) in [
            (Corroboration::Agreed, "agreed"),
            (Corroboration::Conflict, "conflict"),
            (Corroboration::ScanEmpty, "scan_empty"),
            (Corroboration::IdentityMismatch, "identity_mismatch"),
        ] {
            let counters = DiscoveryCounters {
                corroboration: vec![(key, corroboration_label(outcome))],
                ..DiscoveryCounters::default()
            };
            let evidence = discovery_evidence(&plan, &PinnedObjects::empty(), &counters);
            assert_eq!(evidence.modules[0].corroboration, vec![label]);
        }
        // Nothing recorded: one source described it, and the record says so
        // rather than implying a second source failed to.
        let evidence = discovery_evidence(
            &plan,
            &PinnedObjects::empty(),
            &DiscoveryCounters::default(),
        );
        assert_eq!(evidence.modules[0].corroboration, vec!["single_source"]);
        assert_eq!(evidence.modules[0].sources, vec!["scan"]);
    }

    /// A manifest records the `{device, inode}` its provider had on the host it was
    /// made on. Inode reuse after a rebuild is enough for that pair to collide with a
    /// *live* pin of an unrelated file — and the by-key lookup in `Session::start` is
    /// consulted first, so the collision wins and the manifest's offsets are applied
    /// to the wrong file. The mirror of the unpinned-entry hazard above.
    #[test]
    fn a_stale_recorded_identity_never_resolves_to_another_objects_pin() {
        let (_, mut pins) = pinned_self();
        let collision = pins.pinned().next().unwrap().key;

        // A second, unrelated file.
        let dir = tempfile::tempdir().unwrap();
        let provider = dir.path().join("provider.so");
        std::fs::copy("/bin/sh", &provider).unwrap();
        let path = provider.display().to_string();
        let own = pin_as_manifest_object(&path);

        let mut m = manifest_naming(&path, Some("11".repeat(32)));
        // The stale pair, here colliding with the live pin of a different file.
        m.provenance_objects[0].device_major = collision.device.major;
        m.provenance_objects[0].device_minor = collision.device.minor;
        m.provenance_objects[0].inode = collision.inode;

        retarget_to_pins(&mut m, None, &pins, &own);
        pins.absorb(own);

        let plan = plan::build_from_sources(&[], std::slice::from_ref(&m));
        let attach = pins.attach_path_for(plan.slots[0].object).unwrap();
        assert_eq!(
            std::fs::metadata(&attach).unwrap().ino(),
            std::fs::metadata(&provider).unwrap().ino(),
            "a manifest slot must attach into its own object, never into whatever \
             live pin happens to share the identity it recorded"
        );
    }

    /// `p11scope-discover` writes `objects[].path` as the `--module` argument was
    /// spelled and `provenance_objects[].path` as `/proc/self/maps` renders it — the
    /// resolved target. Any provider named through a symlink (`libykcs11.so` →
    /// `.so.2.x`, usrmerge `/lib` → `/usr/lib`) therefore has two different pathnames
    /// in one manifest, and a retarget that looked the pin up by the provenance path
    /// would find none: the recorded pair would survive into the plan, which either
    /// resolves to an unrelated file that shares it or fails to resolve at all.
    #[test]
    fn a_manifest_naming_its_object_and_its_provenance_differently_is_still_retargeted() {
        let (_, mut pins) = pinned_self();
        let collision = pins.pinned().next().unwrap().key;

        let dir = tempfile::tempdir().unwrap();
        let real = dir.path().join("provider.so.2.4");
        std::fs::copy("/bin/sh", &real).unwrap();
        let link = dir.path().join("provider.so");
        std::os::unix::fs::symlink(&real, &link).unwrap();
        let (link_path, real_path) = (link.display().to_string(), real.display().to_string());

        let own = pin_as_manifest_object(&link_path);
        pins.absorb(pin_as_manifest_object(&link_path));

        // A pair nothing pins (a manifest reused after a rebuild — the case pinning
        // exists to support), then one colliding with a live pin of another file.
        for recorded in [
            ObjectKey {
                device: p11scope_manifest::maps::Device {
                    major: 0xffff,
                    minor: 0xffff,
                },
                inode: u64::MAX,
            },
            collision,
        ] {
            let mut m = manifest_naming(&link_path, Some("11".repeat(32)));
            m.provenance_objects[0].path = real_path.clone();
            m.provenance_objects[0].device_major = recorded.device.major;
            m.provenance_objects[0].device_minor = recorded.device.minor;
            m.provenance_objects[0].inode = recorded.inode;

            retarget_to_pins(&mut m, None, &pins, &own);

            let plan = plan::build_from_sources(&[], std::slice::from_ref(&m));
            let attach = pins.attach_path_for(plan.slots[0].object).expect(
                "a manifest whose recorded identity is not the live one must still \
                 resolve — that reuse is what pinning by build-id and sha256 is for",
            );
            assert_eq!(
                std::fs::metadata(&attach).unwrap().ino(),
                std::fs::metadata(&real).unwrap().ino(),
                "recorded {recorded:?} must not decide what gets attached"
            );
        }
    }

    /// The glue that picks among the four §4.12 outcomes: which scanned module a
    /// manifest is talking about, and whether the bytes agree.
    #[test]
    fn scan_view_matches_by_hash_then_path_and_needs_a_pin() {
        let (modules, pinned) = pinned_self();
        let summary = pinned.pinned().next().unwrap();
        let (path, sha) = (summary.path.to_string(), summary.sha256.to_string());

        let m = manifest_naming(&path, Some(sha.clone()));
        let (module, agrees) = scan_view(&m, &modules, &pinned).expect("mapped and pinned");
        assert_eq!(module.key, summary.key);
        assert!(agrees, "the recorded sha256 is the pinned one");
        assert_eq!(
            manifest_targets(&m),
            BTreeSet::from([(sha.clone(), 0x40)]),
            "manifest targets are keyed by object hash, not by device/inode"
        );
        assert_eq!(
            scanned_targets(module, &pinned),
            BTreeSet::new(),
            "our own executable publishes no PKCS#11 table"
        );

        // Same path, different bytes: §4.12's identity mismatch.
        let stale = manifest_naming(&path, Some("22".repeat(32)));
        assert_eq!(
            scan_view(&stale, &modules, &pinned).map(|(_, a)| a),
            Some(false)
        );

        // Mapped but never pinned: nothing to compare against, so nothing corroborates
        // it — the trigger condition for the unpinned-slot bug above.
        let unpinned = manifest_naming(&path, Some(sha));
        assert!(
            scan_view(&unpinned, &modules, &PinnedObjects::empty()).is_none(),
            "a module with no pin has no hash to agree or disagree with"
        );

        // A manifest for something the target does not map at all.
        let elsewhere = manifest_naming("/opt/not-mapped.so", Some("33".repeat(32)));
        assert!(scan_view(&elsewhere, &modules, &pinned).is_none());
    }

    /// Retargeting adopts the identity of the object the scan matched — never some
    /// other pin that happens to hash the same (an earlier manifest's copy of the
    /// same bytes, which the target may not map at all).
    #[test]
    fn retargeting_only_adopts_the_matched_scanned_object() {
        let (modules, pinned) = pinned_self();
        let summary = pinned.pinned().next().unwrap();
        let (path, sha) = (summary.path.to_string(), summary.sha256.to_string());
        let mut m = manifest_naming(&path, Some(sha.clone()));
        m.provenance_objects[0].inode = 1;
        m.provenance_objects[0].device_major = 99;

        retarget_to_pins(&mut m, Some(&modules[0]), &pinned, &PinnedObjects::empty());
        assert_eq!(m.provenance_objects[0].inode, summary.key.inode);
        assert_eq!(
            m.provenance_objects[0].device_major,
            summary.key.device.major
        );

        // The same bytes pinned under an identity the scan did not see must not be
        // adopted: a decoy module the matched scan never named.
        let decoy = ScannedModule {
            key: ObjectKey {
                device: p11scope_manifest::maps::Device { major: 0, minor: 0 },
                inode: 7,
            },
            path: "/opt/decoy.so".into(),
            exports: vec![],
            tables: vec![],
            interfaces: vec![],
        };
        let mut m = manifest_naming(&path, Some(sha));
        m.provenance_objects[0].inode = 1;
        retarget_to_pins(&mut m, Some(&decoy), &pinned, &PinnedObjects::empty());
        assert_eq!(
            m.provenance_objects[0].inode, 1,
            "no pin of the decoy exists"
        );
    }

    /// A minimal schema-current manifest naming one object with one resolved function.
    fn manifest_naming(path: &str, sha256: Option<String>) -> Manifest {
        use p11scope_manifest::identity::{IdentityKind, ObjectIdentity};
        use p11scope_manifest::manifest::*;
        let identity = ObjectIdentity {
            kind: IdentityKind::GnuBuildId,
            value: Some("aa".into()),
            sha256,
            reusable: true,
            note: None,
        };
        Manifest {
            schema: SCHEMA.to_string(),
            module_path: path.to_string(),
            objects: vec![ObjectRecord {
                id: 0,
                path: path.to_string(),
                identity: identity.clone(),
            }],
            provenance_objects: vec![ProvenanceObject {
                path: path.to_string(),
                device_major: 8,
                device_minor: 1,
                inode: 42,
                identity,
            }],
            interface_list: Acquisition::Absent,
            surfaces: vec![SurfaceRecord {
                source: SurfaceSource::LegacyFunctionList,
                acquisition: Acquisition::Ok,
                version: None,
                walk: WalkOutcome::Full,
                functions: vec![FunctionRecord {
                    name: "C_Sign".into(),
                    resolution: Resolution::Resolved {
                        object: 0,
                        file_offset: 0x40,
                    },
                }],
            }],
            vendor_interfaces: vec![],
            alias_groups: vec![],
        }
    }

    /// The outcomes of spec §4.12, which decide whether `--manifest` is a safe
    /// fallback or a trapdoor. Each one changes what is attached and what the
    /// capture claims about it.
    #[test]
    fn the_corroboration_outcomes() {
        let recorded = targets(&[0x10, 0x20]);
        // 1. Not mapped in scope: the manifest stands on its own.
        assert_eq!(
            corroborate(false, None, &recorded, &BTreeSet::new()),
            Corroboration::Uncorroborated
        );
        // 2. Mapped, same {object, offset} set: corroborated.
        assert_eq!(
            corroborate(false, Some(true), &recorded, &targets(&[0x10, 0x20])),
            Corroboration::Agreed
        );
        // 3. Mapped, the sets differ: a conflict (the caller attaches the union).
        assert_eq!(
            corroborate(false, Some(true), &recorded, &targets(&[0x10, 0x30])),
            Corroboration::Conflict
        );
        // 3b. Mapped and identity-matched, but the scan decoded no table at all:
        // the documented use of `--manifest`, not two sources contradicting each
        // other. Reported as uncorroborated, never as a disagreement.
        assert_eq!(
            corroborate(false, Some(true), &recorded, &BTreeSet::new()),
            Corroboration::ScanEmpty
        );
        // Two empty sets are not a scan-empty case: nothing was recorded either.
        assert_eq!(
            corroborate(false, Some(true), &BTreeSet::new(), &BTreeSet::new()),
            Corroboration::Agreed
        );
        // 4. Mapped, but the bytes are not the ones the manifest recorded.
        assert_eq!(
            corroborate(false, Some(false), &recorded, &recorded),
            Corroboration::IdentityMismatch
        );
        // A scan that could not read memory found no tables to disagree with, so it
        // never turns a usable manifest into a conflict or a mismatch.
        for identity in [None, Some(true), Some(false)] {
            assert_eq!(
                corroborate(true, identity, &recorded, &BTreeSet::new()),
                Corroboration::Uncorroborated,
                "{identity:?}"
            );
        }
    }

    /// A pod's processes live in the container cgroups below the pod directory;
    /// capture scope already includes every descendant, so discovery must too.
    #[test]
    fn cgroup_scope_collects_pids_from_every_descendant() {
        let root = tempfile::tempdir().unwrap();
        let leaf = root.path().join("kubepods.slice").join("container.scope");
        std::fs::create_dir_all(&leaf).unwrap();
        std::fs::write(root.path().join("cgroup.procs"), "11\n").unwrap();
        std::fs::write(leaf.join("cgroup.procs"), "22\n33\n\n22\n").unwrap();
        let (pids, lost) = scope_pids(&Scope::Cgroup {
            id: 0,
            path: root.path().to_path_buf(),
        });
        assert_eq!(pids, vec![11, 22, 33], "deduplicated, descendants included");
        assert_eq!(lost, vec![], "every directory was readable");
        assert_eq!(scope_pids(&Scope::Pid(7)).0, vec![7]);

        // A cgroup that is gone by the time the walk reaches it — container
        // cgroups churn constantly, and one is removable only when empty — held
        // no process to lose, on either read. Claiming otherwise would publish a
        // false loss and force PARTIAL on ordinary pod turnover.
        let (pids, lost) = scope_pids(&Scope::Cgroup {
            id: 0,
            path: root.path().join("vanished.scope"),
        });
        assert_eq!(pids, Vec::<u32>::new());
        assert_eq!(lost, vec![], "a cgroup that no longer exists is not a loss");

        // A subtree the observer cannot read is not an empty subtree: the
        // processes in it were never listed, so their providers were never
        // discovered, and nothing else in the document would say so. An *absent*
        // cgroup.procs (the intermediate directory above) is not a loss — it is
        // not a cgroup — which is why the first assertion above sees none.
        //
        // Root reads a mode-000 directory, so the denial is not reproducible
        // there. Both configurations assert — a test that steps aside under the
        // very privilege level the gates run at is a green that proves nothing.
        // Which claim applies is decided by what this process can actually do
        // rather than by its uid: root with CAP_DAC_OVERRIDE dropped is denied
        // like anyone else, and would fail a uid-based branch for the wrong
        // reason.
        use std::os::unix::fs::PermissionsExt as _;
        let mut permissions = std::fs::metadata(&leaf).unwrap().permissions();
        permissions.set_mode(0o000);
        std::fs::set_permissions(&leaf, permissions).unwrap();
        let denied = std::fs::read_dir(&leaf).is_err();
        let (pids, lost) = scope_pids(&Scope::Cgroup {
            id: 0,
            path: root.path().to_path_buf(),
        });
        std::fs::set_permissions(&leaf, std::fs::Permissions::from_mode(0o755)).unwrap();
        if !denied {
            assert_eq!(
                pids,
                vec![11, 22, 33],
                "the mode change denied this observer nothing, so nothing is missed"
            );
            assert_eq!(lost, vec![], "nothing was denied, so nothing is a loss");
            return;
        }
        assert_eq!(pids, vec![11], "only the readable cgroup's process");
        assert_eq!(
            lost.len(),
            2,
            "the file and the listing both failed: {lost:?}"
        );
        assert!(
            lost.iter().all(|s| s.subject.ends_with("container.scope")),
            "{lost:?}"
        );
        assert!(
            lost.iter().any(|s| s.reason.contains("cgroup.procs"))
                && lost.iter().any(|s| s.reason.contains("never discovered")),
            "{lost:?}"
        );
    }

    /// Finding nothing is not an error, so the only thing that keeps the operator
    /// from a silent empty report is this line naming the two commands that explain.
    #[test]
    fn zero_modules_points_at_inspect_and_doctor() {
        let hint = no_modules_hint(&ScopeArg::Pid(42));
        assert!(
            hint.contains("no PKCS#11 modules discovered in pid 42"),
            "{hint}"
        );
        assert!(hint.contains("p11scope inspect --pid 42"), "{hint}");
        assert!(hint.contains("p11scope doctor --pid 42"), "{hint}");
        let hint = no_modules_hint(&ScopeArg::Cgroup("/sys/fs/cgroup/x".into()));
        assert!(hint.contains("cgroup /sys/fs/cgroup/x"), "{hint}");
        assert!(hint.contains("p11scope inspect --pid"), "{hint}");
        assert!(
            hint.contains("p11scope doctor --cgroup /sys/fs/cgroup/x"),
            "{hint}"
        );
    }

    /// `inspect` propagates a hard error for a pid that names nothing; it must reach
    /// the operator as one line and exit 1, never as a panic or a backtrace dump.
    #[test]
    fn inspect_on_a_nonexistent_pid_is_one_line_and_not_a_panic() {
        // Above /proc/sys/kernel/pid_max on every supported kernel.
        let error = inspect::run(
            0x7fff_fff0,
            &[],
            &p11scope::discovery::hooks::HookRegistry::builtin(),
            false,
        )
        .expect_err("a pid that names nothing cannot be inspected");
        let rendered = format!("{error:#}");
        assert_eq!(rendered.lines().count(), 1, "{rendered}");
        assert!(rendered.contains("2147483632"), "{rendered}");
    }

    /// The finalization a stopped loop runs into: `-o` publication produces
    /// valid JSON and replaces stale content atomically (adapted from the
    /// previous shutdown-path test).
    #[test]
    fn shutdown_path_publishes_valid_json_over_a_stale_file() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("observed.json");
        std::fs::write(&path, b"stale trailing bytes that must disappear").unwrap();
        let j = serde_json::json!({"schema": "pkcs11-scope/observed-profile/v2", "evidence": {}});
        let mut out = AtomicFile::create(&path).unwrap();
        write_json_report(out.file(), &j).expect("shutdown finalization must write the report");
        out.commit().unwrap();
        let parsed: serde_json::Value =
            serde_json::from_str(&std::fs::read_to_string(&path).unwrap()).unwrap();
        assert_eq!(parsed["schema"], "pkcs11-scope/observed-profile/v2");
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
