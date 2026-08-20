//! p11scope — non-interposing PKCS#11 observer (eBPF uprobes). CLI entry
//! point; the modules themselves live in the `p11scope` library crate
//! (`src/lib.rs`) so integration tests can exercise them directly.

use anyhow::{Context as _, Result, anyhow, bail};
use p11scope::attach::{CapturePolicy, Scope, Session};
use p11scope::cli::{self, CaptureArgs, CliError, Command, Kind, ScopeArg};
#[cfg(test)]
use p11scope::discovery::identity::pin_manifest_objects;
use p11scope::discovery::identity::{
    ManifestStaleReason, PinnedObjectId, PinnedObjects, ReconciledModule, StaleManifestObject,
    bind_scanned_modules, canonicalize_scanned_overlays, pin_manifest_objects_deferred_in_views,
    pin_scanned_view_objects, target_paths_equal,
};
#[cfg(test)]
use p11scope::discovery::scan::ScanLimits;
use p11scope::discovery::scan::{
    CaptureWorkBudget, ScanOutcome, ScanRequest, ScannedModule, ScannedTable, Skipped,
    scan_process_view,
};
use p11scope::manifest_input::{read_manifest, validate_structure};
use p11scope::output::AtomicFile;
use p11scope::process::{ProcessView, ProcessViewId};
use p11scope::{doctor, inspect, metrics, plan, process, render, scope, semantics, trace};
use p11scope_manifest::manifest::{Manifest, Resolution, SCHEMA};
use p11scope_manifest::maps::ObjectKey;
use std::collections::{BTreeMap, BTreeSet};
use std::io::{Seek as _, SeekFrom, Write};
use std::path::{Path, PathBuf};
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
        Ok(Command::Doctor(a)) => doctor::run(a.pid, a.cgroup.as_deref()),
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
    let (scope, named_view) = match &a.scope {
        ScopeArg::Pid(p) => {
            let view = ProcessView::open(ProcessViewId(0), *p)
                .map_err(|error| anyhow!("--pid {p}: {error}"))?;
            (Scope::Pid(*p), Some(view))
        }
        ScopeArg::Cgroup(c) => (
            Scope::Cgroup {
                id: scope::cgroup_id(c)?,
                path: c.clone(),
            },
            None,
        ),
    };
    if kind == Kind::Trace && a.duration.is_none() {
        eprintln!(
            "p11scope: no --duration given; trace streams until interrupted (Ctrl-C) or the \
             process exits"
        );
    }
    warn_unsafe_policy(policy);
    let discovered = discover_plan(&a, &scope, named_view)?;
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
    views: Vec<ProcessView>,
    modules: Vec<ReconciledModule>,
    manifests: Vec<Manifest>,
    counters: DiscoveryCounters,
    identity_mismatches: usize,
    scan_inputs: BTreeMap<ProcessViewId, ScanInput>,
    manifest_inputs: Vec<ManifestInput>,
    base_counters: DiscoveryCounters,
}

struct ScanInput {
    modules: Vec<ScannedModule>,
    pins: PinnedObjects,
    counters: DiscoveryCounters,
}

struct ManifestInput {
    path: PathBuf,
    manifest: Manifest,
    pins: PinnedObjects,
    stale: Vec<StaleManifestObject>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct ManifestFallback {
    manifest: u32,
    object: u32,
    reason: ManifestStaleReason,
    replacement: PinnedObjectId,
    proof: BoundFallbackProof,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct PendingManifestFallback {
    manifest: u32,
    object: u32,
    reason: ManifestStaleReason,
    candidate: CandidateFallbackProof,
}

/// Private raw scan instance that can be resolved only against the final
/// reconciled module set. It deliberately includes a process view and pathname:
/// a raw map key alone cannot select a peer.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
struct ScanOutcomeLocator {
    view: ProcessViewId,
    key: ObjectKey,
    path: String,
}

impl ScanOutcomeLocator {
    fn module(module: &ScannedModule) -> Self {
        Self {
            view: module.view,
            key: module.key,
            path: module.path.clone(),
        }
    }
}

/// Private raw manifest instance captured from the opened manifest pin before
/// recorded provenance is retargeted. It is never a public key/path relation.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
struct ManifestOutcomeLocator {
    key: ObjectKey,
    path: String,
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
enum OutcomeOwner {
    Scan(ScanOutcomeLocator),
    Manifest(ManifestOutcomeLocator),
}

/// One rendered corroboration item. `Vec` preserves the repeatable
/// `--manifest` input order; its owners become final pinned IDs only after every
/// accepted manifest has been absorbed and scans have been reconciled.
#[derive(Debug, Clone, PartialEq, Eq)]
struct PendingCorroboration {
    owners: Vec<OutcomeOwner>,
    label: &'static str,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct SurfaceRequirement {
    version: (u8, u8),
    all_names: BTreeMap<String, usize>,
    resolved_names: BTreeMap<String, usize>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct TableClaims {
    all_names: BTreeMap<String, usize>,
    resolved_names: BTreeMap<String, usize>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct CandidateTableProof {
    address: u64,
    requirement: SurfaceRequirement,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct CandidateFallbackProof {
    module_view: ProcessViewId,
    module_key: ObjectKey,
    module_path: String,
    recorded_key: ObjectKey,
    object_path: String,
    provenance_path: String,
    is_module: bool,
    replacement: PinnedObjectId,
    tables: Vec<CandidateTableProof>,
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
struct RequiredTarget {
    object: PinnedObjectId,
    file_offset: u64,
    name: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct BoundTableProof {
    address: u64,
    version: (u8, u8),
    entries: usize,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct BoundFallbackProof {
    module: PinnedObjectId,
    tables: Vec<BoundTableProof>,
    required_targets: BTreeMap<RequiredTarget, usize>,
}

/// How many processes of a `--cgroup` discovery scans.
///
/// ponytail: the capture byte budget already bounds work; this flat cap also bounds
/// `/proc` inventory overhead for cgroups containing thousands of processes.
const MAX_SCAN_PIDS: usize = 256;

/// What the discovery pass learned besides the plan itself — everything
/// `discovery_evidence` needs that the plan does not already carry.
#[derive(Debug, Clone, Default)]
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
    corroboration: Vec<(BTreeSet<PinnedObjectId>, &'static str)>,
    /// Stale manifest objects replaced only by exact scan-opened objects.
    manifest_fallbacks: Vec<ManifestFallback>,
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
    targets_agree: bool,
    scan_empty: bool,
) -> Corroboration {
    match identity {
        // A scan that could not read memory found no tables to compare against;
        // that is not evidence against the manifest.
        _ if scan_unavailable => Corroboration::Uncorroborated,
        None => Corroboration::Uncorroborated,
        Some(false) => Corroboration::IdentityMismatch,
        Some(true) if targets_agree => Corroboration::Agreed,
        // Nothing decoded is not a contradiction: the manifest is the only
        // source that ever had offsets here.
        Some(true) if scan_empty => Corroboration::ScanEmpty,
        Some(true) => Corroboration::Conflict,
    }
}

struct ScanView<'a> {
    modules: Vec<&'a ScannedModule>,
    agrees: bool,
}

/// The scan views of the exact opened object a manifest describes. A digest is a
/// comparison conjunct, never authority to choose among byte-identical ordinary
/// files. Every process view of the same exact object is retained for target union.
fn scan_view<'a>(
    m: &Manifest,
    modules: &'a [ScannedModule],
    scan_pins: &PinnedObjects,
    manifest_pins: &PinnedObjects,
) -> Option<ScanView<'a>> {
    let sha = m
        .objects
        .iter()
        .find(|object| object.path == m.module_path)
        .and_then(|object| object.identity.sha256.as_deref());
    let own = manifest_pins.id_for_path(&m.module_path);
    let exact: Vec<&ScannedModule> = modules
        .iter()
        .filter(|module| {
            let Some(scan) = scan_pins.id_for_scanned(module, module.key, &module.path) else {
                return false;
            };
            let Some(own) = own else { return false };
            scan_pins.exactly_matches(scan, manifest_pins, own)
                && scan_pins.summary(scan).map(|pin| pin.sha256) == sha
        })
        .collect();
    if !exact.is_empty() {
        return Some(ScanView {
            modules: exact,
            agrees: true,
        });
    }
    let path_matches: Vec<&ScannedModule> = modules
        .iter()
        .filter(|module| {
            module.path == m.module_path
                && scan_pins
                    .id_for_scanned(module, module.key, &module.path)
                    .is_some()
        })
        .collect();
    // A module the scan saw but could not pin has no hash to disagree with: that is
    // "nothing corroborated it", never "the manifest is wrong".
    (!path_matches.is_empty()).then_some(ScanView {
        modules: path_matches,
        agrees: false,
    })
}

/// Capture-local opened object and file offset for every entry the scan decoded.
#[cfg(test)]
fn scanned_targets(
    modules: &[&ScannedModule],
    pinned: &PinnedObjects,
) -> Option<BTreeSet<(PinnedObjectId, u64)>> {
    scanned_targets_without(modules, pinned, &BTreeSet::new())
}

fn scanned_targets_without(
    modules: &[&ScannedModule],
    pinned: &PinnedObjects,
    ignored: &BTreeSet<PinnedObjectId>,
) -> Option<BTreeSet<(PinnedObjectId, u64)>> {
    modules
        .iter()
        .flat_map(|module| {
            module.tables.iter().flat_map(move |table| {
                table.entries.iter().map(move |entry| {
                    let id = pinned.id_for_scanned(module, entry.object, &entry.object_path)?;
                    Some((!ignored.contains(&id)).then_some((id, entry.file_offset)))
                })
            })
        })
        .collect::<Option<Vec<_>>>()
        .map(|targets| targets.into_iter().flatten().collect())
}

/// The same set resolved through the manifest's exact opened pins in this capture.
fn manifest_targets(
    m: &Manifest,
    pinned: &PinnedObjects,
) -> Option<BTreeSet<(PinnedObjectId, u64)>> {
    m.surfaces
        .iter()
        .flat_map(|surface| &surface.functions)
        .filter_map(|function| match function.resolution {
            Resolution::Resolved {
                object,
                file_offset,
            } => {
                let record = m.objects.iter().find(|o| o.id == object)?;
                Some((record, file_offset))
            }
            _ => None,
        })
        .map(|(record, file_offset)| Some((pinned.id_for_path(&record.path)?, file_offset)))
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
///  - plan lowering resolves a recorded pair to a capture-local pin, so a pair that
///    happens to equal an *unrelated* live pin (inode reuse after a rebuild is enough)
///    would select that file's ID;
///  - the union of §4.12 lands in two slots on one address, double-counting every
///    call, whenever the scan and the manifest name one object differently.
///
/// After this pass every manifest key lowers to the intended capture-local pin ID;
/// `attach.rs` resolves only that ID, with no key or path fallback.
fn retarget_to_pins(
    m: &mut Manifest,
    scanned: &[&ScannedModule],
    scan_pins: &PinnedObjects,
    own_pins: &PinnedObjects,
) {
    // Only exact opened objects named by the matched scan views. Digest equality
    // cannot choose among two ordinary byte-identical files.
    let seen: BTreeSet<PinnedObjectId> = scanned
        .iter()
        .flat_map(|module| {
            std::iter::once((module.key, module.path.as_str()))
                .chain(
                    module
                        .tables
                        .iter()
                        .flat_map(|table| &table.entries)
                        .map(|entry| (entry.object, entry.object_path.as_str())),
                )
                .filter_map(|(key, path)| scan_pins.id_for_scanned(module, key, path))
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
            let own = own_pins.id_for_path(&object.path)?;
            let summary = seen
                .iter()
                .copied()
                .find(|scan| scan_pins.exactly_matches(*scan, own_pins, own))
                .and_then(|scan| scan_pins.summary(scan))
                .or_else(|| own_pins.summary(own))?;
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
    view: &ProcessView,
    a: &CaptureArgs,
    budget: &mut CaptureWorkBudget,
    counters: &mut DiscoveryCounters,
) -> Result<(Vec<ScannedModule>, PinnedObjects)> {
    let outcome = scan_process_view(
        &ScanRequest {
            pid: view.pid(),
            hints: &a.modules,
            hooks: &a.hooks,
        },
        view,
        budget,
    )
    .map_err(|error| anyhow!("scanning process view {:?}: {error}", view.id()))?;
    counters.scan_unavailable = counters.scan_unavailable.or(outcome.unavailable_reason());
    let (pinned, pin_skips) = pin_scanned_view_objects(view, outcome.modules(), budget)
        .map_err(|error| anyhow!("pinning process view {:?}: {error}", view.id()))?;
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

/// Discovery for one capture: scan the scope, read and corroborate any manifests,
/// merge into one plan, pin every object, and record how all of it was found.
fn discover_plan(
    a: &CaptureArgs,
    scope: &Scope,
    mut named_view: Option<ProcessView>,
) -> Result<Discovered> {
    let mut budget = CaptureWorkBudget::default();
    let mut base_counters = DiscoveryCounters::default();
    let (pids, unlisted) = scope_pids(scope);
    base_counters.object_skips.extend(unlisted);
    // The pid the operator named is the capture; a cgroup's processes are many,
    // however few happen to be in it right now.
    let named = matches!(scope, Scope::Pid(_));
    let mut scan_inputs = BTreeMap::new();
    let mut views = Vec::new();
    if pids.len() > MAX_SCAN_PIDS {
        // Published, not just noted: a provider mapped only by a process past the
        // cap is undiscovered, unprobed, and has nothing else to show for it.
        base_counters.object_skips.push(Skipped {
            subject: scope_label(scope),
            reason: format!(
                "{} processes in scope; discovery scanned the first {MAX_SCAN_PIDS} — a \
                 provider mapped only by one of the rest was never discovered",
                pids.len()
            ),
        });
    }
    for (view_index, pid) in pids.iter().take(MAX_SCAN_PIDS).enumerate() {
        let opened = if named {
            named_view
                .take()
                .filter(|view| view.pid() == *pid)
                .ok_or_else(|| "named process view was not retained from scope resolution".into())
        } else {
            ProcessView::open(ProcessViewId(view_index as u32), *pid)
        };
        let view = match opened {
            Ok(view) => view,
            Err(error) if named => return Err(anyhow!(error)),
            Err(error) => {
                base_counters.object_skips.push(Skipped {
                    subject: "process view".into(),
                    reason: format!("the process generation could not be pinned: {error}"),
                });
                continue;
            }
        };
        let mut counters = DiscoveryCounters::default();
        match scan_and_pin(&view, a, &mut budget, &mut counters) {
            Ok((found, pins)) => {
                scan_inputs.insert(
                    view.id(),
                    ScanInput {
                        modules: found,
                        pins,
                        counters,
                    },
                );
                views.push(view);
            }
            // The pid the operator named *is* the capture; any other is one of many
            // in a cgroup, and may legitimately exit between listing and scanning —
            // legitimate, but still a process whose providers went unexamined.
            Err(error) if named => return Err(error),
            Err(error) => {
                eprintln!("p11scope: discovery skipped pid {pid}: {error:#}");
                base_counters.scan_unavailable =
                    base_counters.scan_unavailable.or(counters.scan_unavailable);
                base_counters.scan_ms += counters.scan_ms;
                base_counters.object_skips.extend(counters.object_skips);
                base_counters.object_skips.push(Skipped {
                    subject: format!("pid {pid}"),
                    reason: format!("the process could not be scanned: {error:#}"),
                });
            }
        }
    }

    let mut manifest_inputs = Vec::new();
    for path in &a.manifests {
        let manifest = read_manifest_file(path).inspect_err(|_| base_counters.report_notes())?;
        let pinning =
            pin_manifest_objects_deferred_in_views(&manifest, &views).map_err(|error| {
                base_counters.report_notes();
                for problem in error.problems() {
                    eprintln!("p11scope: {problem}");
                }
                anyhow!(
                    "manifest {} is not a usable trusted input; refusing to attach",
                    path.display()
                )
            })?;
        manifest_inputs.push(ManifestInput {
            path: path.clone(),
            manifest,
            pins: pinning.pins,
            stale: pinning.stale,
        });
    }

    let mut discovered = Discovered {
        plan: plan::build_from_reconciled_modules(&[]),
        pinned: PinnedObjects::empty(),
        discovery: render::DiscoveryEvidence::default(),
        views,
        modules: Vec::new(),
        manifests: Vec::new(),
        counters: DiscoveryCounters::default(),
        identity_mismatches: 0,
        scan_inputs,
        manifest_inputs,
        base_counters,
    };
    rebuild_discovered(&mut discovered)?;
    discovered.counters.report_notes();
    for refused in &discovered.plan.modules_skipped {
        eprintln!(
            "p11scope: module refused: {} — {}",
            refused.subject, refused.reason
        );
    }
    discovered.counters.report(&discovered.plan);
    Ok(discovered)
}

fn build_current_plan(
    modules: &[ReconciledModule],
    manifests: &[Manifest],
    pinned: &PinnedObjects,
    counters: &mut DiscoveryCounters,
    corroborated: &BTreeSet<PinnedObjectId>,
    identity_mismatches: usize,
    manifest_fallbacks: usize,
) -> Result<plan::AttachPlan> {
    // Every plan reference is a capture-local pinned ID. Raw mapping keys remain
    // evidence only and cannot select an attach fd.
    let mut plan = plan::build_from_sources(modules, manifests, pinned);
    record_object_skips(&mut plan, &counters.object_skips);
    for object in corroborated {
        if let Some(summary) = plan
            .modules
            .iter_mut()
            .find(|module| module.object == *object)
        {
            summary.corroborated = true;
            if summary.source == "scan" {
                summary.source = "scan+manifest";
            }
        }
    }
    counters.uncorroborated = uncorroborated_count(&plan, identity_mismatches, manifest_fallbacks);
    if identity_mismatches + manifest_fallbacks > 0 && plan.slots.is_empty() {
        bail!(
            "{} stale --manifest input object(s) had no usable planned replacement, and no discovery source found a function table",
            identity_mismatches + manifest_fallbacks
        );
    }
    if let Some(error) = refusal_error(&plan) {
        bail!(error);
    }
    plan::ensure_capacity(&plan).map_err(|error| anyhow!(error))?;
    Ok(plan)
}

/// Modules whose offsets nothing corroborated, plus every `--manifest` ignored
/// as stale (§4.12 case 4). An ignored manifest never becomes a plan module, so
/// the filter cannot see it — and a stale manifest supplied for exactly the
/// provider the scan cannot read leaves that provider unobserved with nothing
/// else in the document to notice. Counted here, it forces `PARTIAL`.
fn uncorroborated_count(
    plan: &plan::AttachPlan,
    identity_mismatches: usize,
    manifest_fallbacks: usize,
) -> u64 {
    let uncorroborated = plan
        .modules
        .iter()
        .filter(|m| m.source.contains("manifest") && !m.corroborated)
        .count();
    (uncorroborated + identity_mismatches + manifest_fallbacks) as u64
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
    let summary_of = |id, path: &str| {
        let pin = pinned
            .summary(id)
            .expect("every planned object has a comparable pin");
        render::ObjectSummary {
            dev: (pin.key.device.major, pin.key.device.minor),
            ino: pin.key.inode,
            // Absent, not empty: nothing hashed it, so there is no digest to
            // report — an empty string would read as one.
            sha256: Some(pin.sha256.to_string()),
            path: if pin.path.is_empty() {
                path.to_string()
            } else {
                pin.path.to_string()
            },
            build_id: pin.build_id.map(str::to_string),
            identity_source: pin.identity_source,
            note: pin.note.map(str::to_string),
            sources: pinned.sources(id),
        }
    };
    let modules = plan
        .modules
        .iter()
        .map(|m| {
            let mut seen = BTreeSet::new();
            let objects: Vec<render::ObjectSummary> = plan
                .slots
                .iter()
                .filter(|s| s.module_ids.contains(&m.id) && seen.insert(s.object))
                .map(|s| summary_of(s.object, &s.object_path))
                .collect();
            let identity = summary_of(m.object, &m.path);
            render::DiscoveredModule {
                id: m.id,
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
                skipped: m.skipped.iter().map(render::capture_skipped_out).collect(),
            }
        })
        .collect();
    let manifest_object_fallbacks = counters
        .manifest_fallbacks
        .iter()
        .map(|fallback| {
            let replacement = pinned
                .summary(fallback.replacement)
                .expect("every fallback replacement remains pinned in the final plan");
            render::ManifestObjectFallback {
                manifest: fallback.manifest,
                object: fallback.object,
                reason: fallback.reason.label(),
                replacement: render::ManifestReplacement {
                    dev: (replacement.key.device.major, replacement.key.device.minor),
                    ino: replacement.key.inode,
                    sha256: replacement.sha256.to_string(),
                },
            }
        })
        .collect();
    render::DiscoveryEvidence {
        modules,
        conflicts: counters.conflicts,
        uncorroborated: counters.uncorroborated,
        module_ambiguous: plan.module_ambiguous as u64,
        modules_skipped: plan.modules_skipped.iter().map(skipped_out).collect(),
        manifest_object_fallbacks,
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
        .filter(|(objects, _)| objects.contains(&m.object))
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

fn manifest_outcome_locator(
    manifest: &Manifest,
    pins: &PinnedObjects,
) -> Option<ManifestOutcomeLocator> {
    let mut modules = manifest
        .objects
        .iter()
        .filter(|object| object.path == manifest.module_path);
    let object = modules.next()?;
    if modules.next().is_some() {
        return None;
    }
    let id = pins.id_for_path(&object.path)?;
    let summary = pins.summary(id)?;
    Some(ManifestOutcomeLocator {
        key: summary.key,
        path: object.path.clone(),
    })
}

fn pending_corroboration(
    view: Option<&ScanView<'_>>,
    manifest: &Manifest,
    manifest_pins: &PinnedObjects,
    label: &'static str,
) -> Result<PendingCorroboration> {
    let owners: Vec<_> = view
        .map(|view| {
            view.modules
                .iter()
                .map(|module| OutcomeOwner::Scan(ScanOutcomeLocator::module(module)))
                .collect()
        })
        .unwrap_or_else(|| {
            manifest_outcome_locator(manifest, manifest_pins)
                .map(OutcomeOwner::Manifest)
                .into_iter()
                .collect()
        });
    if owners.is_empty() {
        bail!(
            "an accepted manifest outcome had no exact opened object instance to bind after reconciliation"
        );
    }
    Ok(PendingCorroboration { owners, label })
}

fn resolve_outcome_owner(
    owner: &OutcomeOwner,
    modules: &[ReconciledModule],
    pinned: &PinnedObjects,
) -> Option<PinnedObjectId> {
    match owner {
        OutcomeOwner::Scan(locator) => {
            let mut matching = modules.iter().filter(|module| {
                module.scanned.view == locator.view
                    && module.scanned.key == locator.key
                    && target_paths_equal(&module.scanned.path, &locator.path)
            });
            let module = matching.next()?;
            matching.next().is_none().then_some(module.object)
        }
        OutcomeOwner::Manifest(locator) => pinned.id_for_manifest(locator.key, &locator.path),
    }
}

fn bind_pending_corroboration(
    pending: Vec<PendingCorroboration>,
    modules: &[ReconciledModule],
    pinned: &PinnedObjects,
    counters: &mut DiscoveryCounters,
) -> Result<BTreeSet<PinnedObjectId>> {
    let mut corroborated = BTreeSet::new();
    for outcome in pending {
        let objects: Option<BTreeSet<_>> = outcome
            .owners
            .iter()
            .map(|owner| resolve_outcome_owner(owner, modules, pinned))
            .collect();
        let Some(objects) = objects.filter(|objects| !objects.is_empty()) else {
            bail!(
                "an accepted manifest outcome lost its exact final object during identity reconciliation"
            );
        };
        if matches!(outcome.label, "agreed" | "conflict") {
            corroborated.extend(&objects);
        }
        counters.corroboration.push((objects, outcome.label));
    }
    Ok(corroborated)
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

const STALE_VIEW_REASON: &str = "accepted process generation changed during attach preparation; its discovery claims were removed";

fn manifest_object_key(manifest: &Manifest, object: u32) -> Option<(ObjectKey, &str)> {
    let object = manifest.objects.iter().find(|record| record.id == object)?;
    let provenance = &manifest.provenance_objects[plan::provenance_of(manifest, object)?];
    Some((
        ObjectKey {
            device: p11scope_manifest::maps::Device {
                major: provenance.device_major,
                minor: provenance.device_minor,
            },
            inode: provenance.inode,
        },
        provenance.path.as_str(),
    ))
}

fn claims_covered(needed: &BTreeMap<String, usize>, available: &BTreeMap<String, usize>) -> bool {
    needed
        .iter()
        .all(|(claim, count)| available.get(claim).is_some_and(|seen| seen >= count))
}

fn fallback_requirements(
    manifest: &Manifest,
    stale: u32,
    is_module: bool,
) -> Option<Vec<SurfaceRequirement>> {
    let mut requirements = Vec::new();
    for surface in &manifest.surfaces {
        let mut all_names = BTreeMap::new();
        let mut resolved_names = BTreeMap::new();
        for function in &surface.functions {
            let affected = is_module
                || matches!(
                    function.resolution,
                    Resolution::Resolved { object, .. } if object == stale
                );
            if !affected {
                continue;
            }
            *all_names.entry(function.name.clone()).or_insert(0) += 1;
            if matches!(function.resolution, Resolution::Resolved { .. }) {
                *resolved_names.entry(function.name.clone()).or_insert(0) += 1;
            }
        }
        if all_names.is_empty() {
            continue;
        }
        let version = surface
            .version
            .map(|version| (version.major, version.minor))?;
        requirements.push(SurfaceRequirement {
            version,
            all_names,
            resolved_names,
        });
    }
    (!requirements.is_empty()).then_some(requirements)
}

fn relation_matches(proof: &CandidateFallbackProof, key: ObjectKey, path: &str) -> bool {
    key == proof.recorded_key
        && (target_paths_equal(path, &proof.object_path)
            || target_paths_equal(path, &proof.provenance_path))
}

fn raw_table_claims(
    module: &ScannedModule,
    table: &ScannedTable,
    pinned: &PinnedObjects,
    proof: &CandidateFallbackProof,
) -> TableClaims {
    let mut all_names = BTreeMap::new();
    let mut resolved_names = BTreeMap::new();
    for entry in &table.entries {
        *all_names.entry(entry.name.to_string()).or_insert(0) += 1;
        let relevant = proof.is_module
            || relation_matches(proof, entry.object, &entry.object_path)
                && pinned
                    .id_for_scanned(module, entry.object, &entry.object_path)
                    .and_then(|id| pinned.summary(id))
                    .is_some_and(|summary| summary.key == proof.recorded_key);
        if relevant
            && pinned
                .id_for_scanned(module, entry.object, &entry.object_path)
                .is_some()
        {
            *resolved_names.entry(entry.name.to_string()).or_insert(0) += 1;
        }
    }
    for name in &table.null_entries {
        *all_names.entry((*name).to_string()).or_insert(0) += 1;
    }
    for skipped in &table.unpinned {
        *all_names.entry(skipped.subject.clone()).or_insert(0) += 1;
    }
    TableClaims {
        all_names,
        resolved_names,
    }
}

fn requirement_covered(
    requirement: &SurfaceRequirement,
    table: &ScannedTable,
    claims: &TableClaims,
) -> bool {
    table.version == requirement.version
        && claims_covered(&requirement.all_names, &claims.all_names)
        && claims_covered(&requirement.resolved_names, &claims.resolved_names)
}

fn assign_table(
    surface: usize,
    candidates: &[Vec<usize>],
    seen: &mut [bool],
    owners: &mut [Option<usize>],
) -> bool {
    for &table in &candidates[surface] {
        if seen[table] {
            continue;
        }
        seen[table] = true;
        if owners[table].is_none() || assign_table(owners[table].unwrap(), candidates, seen, owners)
        {
            owners[table] = Some(surface);
            return true;
        }
    }
    false
}

fn injective_table_assignment(
    requirements: &[SurfaceRequirement],
    tables: &[ScannedTable],
    claims: &[TableClaims],
) -> Option<Vec<usize>> {
    let candidates: Vec<Vec<usize>> = requirements
        .iter()
        .map(|requirement| {
            tables
                .iter()
                .zip(claims)
                .enumerate()
                .filter_map(|(index, (table, claims))| {
                    requirement_covered(requirement, table, claims).then_some(index)
                })
                .collect()
        })
        .collect();
    if candidates.iter().any(Vec::is_empty) {
        return None;
    }
    let mut owners = vec![None; tables.len()];
    for surface in 0..requirements.len() {
        if !assign_table(
            surface,
            &candidates,
            &mut vec![false; tables.len()],
            &mut owners,
        ) {
            return None;
        }
    }
    let mut selected = vec![usize::MAX; requirements.len()];
    for (table, surface) in owners.into_iter().enumerate() {
        if let Some(surface) = surface {
            selected[surface] = table;
        }
    }
    selected
        .iter()
        .all(|table| *table != usize::MAX)
        .then_some(selected)
}

/// Locates one exact scan module and an injective table proof for every manifest
/// surface this stale object would remove. Raw paths and mapping keys only locate
/// this pending candidate; reconciliation binds it to canonical opened identities.
fn scanned_replacement(
    manifest: &Manifest,
    stale: &StaleManifestObject,
    modules: &[ScannedModule],
    pinned: &PinnedObjects,
    manifest_pins: &PinnedObjects,
) -> Option<CandidateFallbackProof> {
    let object = manifest
        .objects
        .iter()
        .find(|object| object.id == stale.object)?;
    let (recorded_key, provenance_path) = manifest_object_key(manifest, stale.object)?;
    let is_module = object.path == manifest.module_path;
    let requirements = fallback_requirements(manifest, stale.object, is_module)?;
    let module_owners: BTreeSet<_> = if is_module {
        BTreeSet::new()
    } else {
        let view = scan_view(manifest, modules, pinned, manifest_pins)?;
        if !view.agrees {
            return None;
        }
        view.modules
            .iter()
            .map(|module| (module.view, module.key))
            .collect()
    };
    let mut selected: Option<CandidateFallbackProof> = None;
    for module in modules {
        if !is_module && !module_owners.contains(&(module.view, module.key)) {
            continue;
        }
        let module_id = pinned.id_for_scanned(module, module.key, &module.path);
        let locator = CandidateFallbackProof {
            module_view: module.view,
            module_key: module.key,
            module_path: module.path.clone(),
            recorded_key,
            object_path: object.path.clone(),
            provenance_path: provenance_path.to_string(),
            is_module,
            replacement: PinnedObjectId(u32::MAX),
            tables: Vec::new(),
        };
        if is_module
            && !module_id.is_some_and(|id| {
                relation_matches(&locator, module.key, &module.path)
                    && pinned
                        .summary(id)
                        .is_some_and(|summary| summary.key == recorded_key)
            })
        {
            continue;
        }
        let claims: Vec<_> = module
            .tables
            .iter()
            .map(|table| raw_table_claims(module, table, pinned, &locator))
            .collect();
        let Some(assignment) = injective_table_assignment(&requirements, &module.tables, &claims)
        else {
            continue;
        };
        let replacement = if is_module {
            module_id?
        } else {
            let target_ids: BTreeSet<_> = assignment
                .iter()
                .flat_map(|table| &module.tables[*table].entries)
                .filter(|entry| relation_matches(&locator, entry.object, &entry.object_path))
                .filter_map(|entry| pinned.id_for_scanned(module, entry.object, &entry.object_path))
                .collect();
            if target_ids.len() != 1 {
                continue;
            }
            *target_ids.first()?
        };
        let candidate = CandidateFallbackProof {
            replacement,
            tables: assignment
                .into_iter()
                .zip(requirements.iter().cloned())
                .map(|(table, requirement)| CandidateTableProof {
                    address: module.tables[table].address,
                    requirement,
                })
                .collect(),
            ..locator
        };
        match &selected {
            Some(existing) if existing.replacement != candidate.replacement => return None,
            Some(_) => {}
            None => selected = Some(candidate),
        }
    }
    selected
}

fn bound_table_claims(
    module: &ReconciledModule,
    table: usize,
    proof: &CandidateFallbackProof,
) -> TableClaims {
    let table_record = &module.scanned.tables[table];
    let mut all_names = BTreeMap::new();
    let mut resolved_names = BTreeMap::new();
    for entry in &table_record.entries {
        *all_names.entry(entry.name.to_string()).or_insert(0) += 1;
        if proof.is_module || relation_matches(proof, entry.object, &entry.object_path) {
            *resolved_names.entry(entry.name.to_string()).or_insert(0) += 1;
        }
    }
    for name in &table_record.null_entries {
        *all_names.entry((*name).to_string()).or_insert(0) += 1;
    }
    for skipped in &table_record.unpinned {
        *all_names.entry(skipped.subject.clone()).or_insert(0) += 1;
    }
    TableClaims {
        all_names,
        resolved_names,
    }
}

fn bind_fallback_proof(
    candidate: &CandidateFallbackProof,
    modules: &[ReconciledModule],
) -> Option<(PinnedObjectId, BoundFallbackProof)> {
    let mut matching = modules.iter().filter(|module| {
        module.scanned.view == candidate.module_view
            && module.scanned.key == candidate.module_key
            && module.scanned.path == candidate.module_path
    });
    let module = matching.next()?;
    if matching.next().is_some() {
        return None;
    }
    let mut bound_tables = Vec::with_capacity(candidate.tables.len());
    let mut required_targets = BTreeMap::new();
    let mut replacement_ids = BTreeSet::new();
    for table_proof in &candidate.tables {
        let mut matching = module
            .scanned
            .tables
            .iter()
            .enumerate()
            .filter(|(_, table)| table.address == table_proof.address);
        let (table_index, table) = matching.next()?;
        if matching.next().is_some() {
            return None;
        }
        let claims = bound_table_claims(module, table_index, candidate);
        if !requirement_covered(&table_proof.requirement, table, &claims) {
            return None;
        }
        for (name, count) in &table_proof.requirement.resolved_names {
            let mut remaining = *count;
            for (entry, object) in table.entries.iter().zip(&module.entry_objects[table_index]) {
                if entry.name != name
                    || !candidate.is_module
                        && !relation_matches(candidate, entry.object, &entry.object_path)
                {
                    continue;
                }
                replacement_ids.insert(*object);
                *required_targets
                    .entry(RequiredTarget {
                        object: *object,
                        file_offset: entry.file_offset,
                        name: name.clone(),
                    })
                    .or_insert(0) += 1;
                remaining -= 1;
                if remaining == 0 {
                    break;
                }
            }
            if remaining != 0 {
                return None;
            }
        }
        bound_tables.push(BoundTableProof {
            address: table.address,
            version: table.version,
            entries: table.entries.len(),
        });
    }
    let replacement = if candidate.is_module {
        module.object
    } else {
        if replacement_ids.len() != 1 {
            return None;
        }
        *replacement_ids.first()?
    };
    Some((
        replacement,
        BoundFallbackProof {
            module: module.object,
            tables: bound_tables,
            required_targets,
        },
    ))
}

const FALLBACK_UNUSABLE_REASON: &str = "superseded by exact scan fallback";

fn filter_manifest_fallbacks(manifest: &mut Manifest, stale: &BTreeSet<u32>) -> Result<()> {
    for surface in &mut manifest.surfaces {
        for function in &mut surface.functions {
            if matches!(
                function.resolution,
                Resolution::Resolved { object, .. } if stale.contains(&object)
            ) {
                function.resolution = Resolution::UnusableFile {
                    reason: FALLBACK_UNUSABLE_REASON.into(),
                    path_hex: String::new(),
                };
            }
        }
    }

    let provenance: Vec<Option<usize>> = manifest
        .objects
        .iter()
        .map(|object| plan::provenance_of(manifest, object))
        .collect();
    let mut ids = BTreeMap::new();
    let mut objects = Vec::new();
    let mut kept_provenance = BTreeSet::new();
    for (index, object) in manifest.objects.iter().enumerate() {
        if stale.contains(&object.id) {
            continue;
        }
        let new_id = u32::try_from(objects.len()).expect("manifest object cap fits u32");
        ids.insert(object.id, new_id);
        let mut object = object.clone();
        object.id = new_id;
        objects.push(object);
        if let Some(provenance) = provenance[index] {
            kept_provenance.insert(provenance);
        }
    }
    manifest.objects = objects;
    manifest.provenance_objects = std::mem::take(&mut manifest.provenance_objects)
        .into_iter()
        .enumerate()
        .filter_map(|(index, object)| kept_provenance.contains(&index).then_some(object))
        .collect();
    for surface in &mut manifest.surfaces {
        for function in &mut surface.functions {
            if let Resolution::Resolved { object, .. } = &mut function.resolution {
                *object = ids[object];
            }
        }
    }
    manifest.alias_groups.retain_mut(|group| {
        let Some(object) = ids.get(&group.object).copied() else {
            return false;
        };
        group.object = object;
        true
    });
    let problems = validate_structure(manifest);
    if !problems.is_empty() {
        bail!(
            "manifest became structurally invalid after stale-object fallback: {}",
            problems.join("; ")
        );
    }
    Ok(())
}

fn fallback_proof_in_plan(proof: &BoundFallbackProof, plan: &plan::AttachPlan) -> bool {
    let mut table_addresses = BTreeSet::new();
    if proof
        .tables
        .iter()
        .any(|table| !table_addresses.insert(table.address))
    {
        return false;
    }
    let mut modules = plan
        .modules
        .iter()
        .filter(|module| module.object == proof.module);
    let Some(module) = modules.next() else {
        return false;
    };
    if modules.next().is_some() {
        return false;
    }
    let mut available_tables = BTreeMap::new();
    for table in module.tables.iter().filter(|table| table.source == "scan") {
        *available_tables
            .entry((table.version, table.entries))
            .or_insert(0usize) += 1;
    }
    let mut required_tables = BTreeMap::new();
    for table in &proof.tables {
        *required_tables
            .entry((table.version, table.entries))
            .or_insert(0usize) += 1;
    }
    if required_tables.iter().any(|(table, count)| {
        available_tables
            .get(table)
            .is_none_or(|available| available < count)
    }) {
        return false;
    }
    proof.required_targets.keys().all(|required| {
        plan.slots.iter().any(|slot| {
            slot.object == required.object
                && slot.file_offset == required.file_offset
                && slot.names.iter().any(|name| name == &required.name)
                && slot.module_ids.contains(&module.id)
        })
    })
}

fn rebuild_discovered(discovered: &mut Discovered) -> Result<()> {
    let mut counters = discovered.base_counters.clone();
    let mut scan_modules = Vec::new();
    for input in discovered.scan_inputs.values() {
        counters.scan_unavailable = counters
            .scan_unavailable
            .or(input.counters.scan_unavailable);
        counters.scan_ms += input.counters.scan_ms;
        counters
            .object_skips
            .extend(input.counters.object_skips.clone());
        scan_modules.extend(input.modules.clone());
    }
    let (mut pinned, aggregation_skips) =
        PinnedObjects::aggregate_views(discovered.scan_inputs.values().map(|input| &input.pins));
    counters.object_skips.extend(aggregation_skips);
    let (collapsed, overlay_skips) = canonicalize_scanned_overlays(&mut pinned);
    if collapsed > 0 {
        eprintln!(
            "p11scope: discovery: {collapsed} matching overlay mapping(s) were collapsed \
             onto one attach target; physical identity is not provable, so published \
             uncertainty makes this capture PARTIAL"
        );
    }
    counters.object_skips.extend(overlay_skips);
    let mut accepted = Vec::new();
    let mut pending_fallbacks = Vec::new();
    let mut pending_outcomes = Vec::new();
    let mut identity_mismatches = 0usize;
    for (manifest_index, input) in discovered.manifest_inputs.iter().enumerate() {
        let mut manifest = input.manifest.clone();
        let manifest_pins = &input.pins;
        let mut stale_ids = BTreeSet::new();
        let mut stale_replacements = BTreeSet::new();
        let mut stale_candidates = Vec::new();
        let manifest_number = u32::try_from(manifest_index)
            .map_err(|_| anyhow!("too many --manifest inputs to identify fallback evidence"))?;
        for stale in &input.stale {
            let Some(candidate) =
                scanned_replacement(&manifest, stale, &scan_modules, &pinned, manifest_pins)
            else {
                counters.report_notes();
                bail!(
                    "stale manifest object {} from {} ({}) has no exact, complete scanned replacement table",
                    stale.object,
                    input.path.display(),
                    stale.reason.label(),
                );
            };
            if pending_fallbacks.len() >= p11scope_ebpf_common::MAX_SLOTS as usize {
                bail!(
                    "more than {} stale manifest objects require fallback",
                    p11scope_ebpf_common::MAX_SLOTS
                );
            }
            stale_ids.insert(stale.object);
            if !stale_replacements.insert(candidate.replacement) {
                bail!(
                    "manifest {} maps more than one stale object to the same scanned replacement",
                    input.path.display()
                );
            }
            stale_candidates.push(candidate.clone());
            pending_fallbacks.push(PendingManifestFallback {
                manifest: manifest_number,
                object: stale.object,
                reason: stale.reason,
                candidate,
            });
            counters.notes.push(format!(
                "ignoring stale object {} from manifest {} ({}) because the memory scan pinned an exact replacement and covered every dropped function claim",
                stale.object,
                input.path.display(),
                stale.reason.label(),
            ));
        }
        let stale_module = manifest
            .objects
            .iter()
            .find(|object| object.path == manifest.module_path)
            .is_some_and(|object| stale_ids.contains(&object.id));
        if stale_module {
            let matched: Vec<_> = scan_modules
                .iter()
                .filter(|module| {
                    stale_candidates.iter().any(|candidate| {
                        module.view == candidate.module_view
                            && module.key == candidate.module_key
                            && module.path == candidate.module_path
                    })
                })
                .collect();
            let owners: Vec<_> = matched
                .iter()
                .map(|module| OutcomeOwner::Scan(ScanOutcomeLocator::module(module)))
                .collect();
            if owners.is_empty() {
                bail!(
                    "stale manifest module had no exact scanned object instance to bind after reconciliation"
                );
            }
            pending_outcomes.push(PendingCorroboration {
                owners,
                label: "object_fallback",
            });
            continue;
        }
        if !stale_ids.is_empty() {
            filter_manifest_fallbacks(&mut manifest, &stale_ids)?;
        }
        let view = scan_view(&manifest, &scan_modules, &pinned, manifest_pins);
        let scan_targets = view
            .as_ref()
            .and_then(|view| scanned_targets_without(&view.modules, &pinned, &stale_replacements));
        let own_targets = manifest_targets(&manifest, manifest_pins);
        let scan_empty = view.as_ref().is_some_and(|view| {
            view.modules
                .iter()
                .flat_map(|module| &module.tables)
                .all(|table| table.entries.is_empty())
        });
        let outcome = corroborate(
            counters.scan_unavailable.is_some(),
            view.as_ref().map(|view| view.agrees),
            scan_targets
                .as_ref()
                .zip(own_targets.as_ref())
                .is_some_and(|(scan, own)| pinned.exactly_same_targets(scan, manifest_pins, own)),
            scan_empty,
        );
        if outcome != Corroboration::IdentityMismatch {
            pending_outcomes.push(pending_corroboration(
                view.as_ref(),
                &manifest,
                manifest_pins,
                corroboration_label(outcome),
            )?);
        }
        match outcome {
            Corroboration::Agreed => {
                retarget_to_pins(
                    &mut manifest,
                    view.as_ref().map_or(&[], |view| view.modules.as_slice()),
                    &pinned,
                    manifest_pins,
                );
                accepted.push(manifest);
                counters
                    .object_skips
                    .extend(pinned.absorb(manifest_pins.clone()));
            }
            Corroboration::ScanEmpty => {
                counters.notes.push(format!(
                    "the memory scan decoded no function table in {}; attaching the \
                     offsets manifest {} records, uncorroborated",
                    manifest.module_path,
                    input.path.display(),
                ));
                retarget_to_pins(
                    &mut manifest,
                    view.as_ref().map_or(&[], |view| view.modules.as_slice()),
                    &pinned,
                    manifest_pins,
                );
                accepted.push(manifest);
                counters
                    .object_skips
                    .extend(pinned.absorb(manifest_pins.clone()));
            }
            Corroboration::Conflict => {
                counters.conflicts += 1;
                counters.notes.push(format!(
                    "manifest {} and the memory scan decoded different targets in {}; \
                     attaching the union of both",
                    input.path.display(),
                    manifest.module_path
                ));
                retarget_to_pins(
                    &mut manifest,
                    view.as_ref().map_or(&[], |view| view.modules.as_slice()),
                    &pinned,
                    manifest_pins,
                );
                accepted.push(manifest);
                counters
                    .object_skips
                    .extend(pinned.absorb(manifest_pins.clone()));
            }
            Corroboration::Uncorroborated => {
                retarget_to_pins(&mut manifest, &[], &pinned, manifest_pins);
                accepted.push(manifest);
                counters
                    .object_skips
                    .extend(pinned.absorb(manifest_pins.clone()));
            }
            Corroboration::IdentityMismatch => {
                identity_mismatches += 1;
                counters.notes.push(format!(
                    "ignoring manifest {}: the {} mapped in the target does not hash to \
                     the sha256 it records",
                    input.path.display(),
                    manifest.module_path
                ));
            }
        }
    }

    let (modules, differed) = bind_scanned_modules(&scan_modules, &mut pinned);
    counters.object_skips.extend(differed);
    let corroborated =
        bind_pending_corroboration(pending_outcomes, &modules, &pinned, &mut counters)?;

    let mut replacements = BTreeSet::new();
    for pending in pending_fallbacks {
        let Some((replacement, proof)) = bind_fallback_proof(&pending.candidate, &modules) else {
            bail!(
                "manifest {} object {} lost its exact scanned fallback proof during identity reconciliation",
                pending.manifest,
                pending.object
            );
        };
        if !replacements.insert(replacement) {
            bail!(
                "more than one stale manifest object maps to the same canonical scanned replacement"
            );
        }
        counters.manifest_fallbacks.push(ManifestFallback {
            manifest: pending.manifest,
            object: pending.object,
            reason: pending.reason,
            replacement,
            proof,
        });
    }
    let manifest_fallbacks = counters.manifest_fallbacks.len();
    let plan = build_current_plan(
        &modules,
        &accepted,
        &pinned,
        &mut counters,
        &corroborated,
        identity_mismatches,
        manifest_fallbacks,
    )
    .inspect_err(|_| counters.report_notes())?;
    if let Some(fallback) = counters
        .manifest_fallbacks
        .iter()
        .find(|fallback| !fallback_proof_in_plan(&fallback.proof, &plan))
    {
        bail!(
            "manifest {} object {} has no complete scanned fallback proof in the final attach plan",
            fallback.manifest,
            fallback.object
        );
    }
    let discovery = discovery_evidence(&plan, &pinned, &counters);
    discovered.plan = plan;
    discovered.pinned = pinned;
    discovered.discovery = discovery;
    discovered.modules = modules;
    discovered.manifests = accepted;
    discovered.counters = counters;
    discovered.identity_mismatches = identity_mismatches;
    Ok(())
}

fn remove_stale_views(discovered: &mut Discovered, stale: &[ProcessViewId]) -> Result<usize> {
    let accepted: BTreeSet<_> = discovered.views.iter().map(ProcessView::id).collect();
    let stale: BTreeSet<_> = stale
        .iter()
        .copied()
        .filter(|view| accepted.contains(view))
        .collect();
    let before = discovered.views.len();
    discovered.views.retain(|view| !stale.contains(&view.id()));
    let removed = before - discovered.views.len();
    if removed == 0 {
        bail!("lifecycle check did not identify an accepted process view");
    }
    for view in stale {
        discovered.scan_inputs.remove(&view);
        discovered.base_counters.object_skips.push(Skipped {
            subject: "process view".into(),
            reason: STALE_VIEW_REASON.into(),
        });
        eprintln!("p11scope: discovery skipped process view — {STALE_VIEW_REASON}");
    }
    rebuild_discovered(discovered)?;
    Ok(removed)
}

fn start_retained_with<S>(
    discovered: &mut Discovered,
    named: bool,
    mut stale_views: impl FnMut(&[ProcessView]) -> Vec<ProcessViewId>,
    mut start: impl FnMut(&plan::AttachPlan, &PinnedObjects) -> Result<S>,
) -> Result<S> {
    if named && discovered.views.len() != 1 {
        bail!("the named process generation was not retained through discovery");
    }
    loop {
        let stale = stale_views(&discovered.views);
        if !stale.is_empty() {
            if named {
                bail!("the named process generation changed before attach");
            }
            remove_stale_views(discovered, &stale)?;
            continue;
        }

        let session = start(&discovered.plan, &discovered.pinned)?;
        let stale = stale_views(&discovered.views);
        if stale.is_empty() {
            return Ok(session);
        }
        // No event/map consumer can see this session. Dropping it first tears down
        // every just-created link before stale ownership changes or a retry begins.
        drop(session);
        if named {
            bail!("the named process generation changed while attaching");
        }
        remove_stale_views(discovered, &stale)?;
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
    let mut discovered = discovered;
    // Created before the attach so a bad `-o` path fails early, published
    // by `commit()` only once the final report is written.
    let output = out
        .map(AtomicFile::create)
        .transpose()
        .map_err(anyhow::Error::msg)?;
    let has_output = output.is_some();
    let mut stdout_sink = std::io::stdout().lock();
    let stdout: &mut dyn Write = &mut stdout_sink;
    let named = matches!(scope, Scope::Pid(_));
    let mut session = start_retained_with(
        &mut discovered,
        named,
        process::stale_view_ids,
        |plan, pinned| Session::start(plan, &scope, pinned, policy, None),
    )
    .context("starting attach session")?;
    let Discovered {
        plan,
        pinned,
        discovery,
        ..
    } = discovered;
    let pinned = &pinned;
    let module_label = module_label(&plan);
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
        let mut drain = session.event_drain()?;
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

    let detach = session.detach_producers();
    // A detach error is retained until after this terminal drain. Do not put a
    // fallible provider check between those two operations.
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

    detach?;
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
    let mut discovered = discovered;
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
    let named = matches!(scope, Scope::Pid(_));
    let mut session = start_retained_with(
        &mut discovered,
        named,
        process::stale_view_ids,
        |plan, pinned| Session::start(plan, &scope, pinned, policy, None),
    )
    .context("starting attach session")?;
    let Discovered {
        plan,
        pinned,
        discovery,
        ..
    } = discovered;
    let pinned = &pinned;
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

    let detach = session.detach_producers();
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

    detach?;
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
    tracer: &mut trace::Tracer,
    stdout: &mut dyn Write,
    stdout_open: &mut bool,
    out_file: &mut Option<W>,
) -> Result<u64> {
    let mut drain = session.event_drain()?;
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
        semantic_unverified_slots: plan
            .slots
            .iter()
            .filter(|slot| !slot.semantic_authorized)
            .count(),
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
    use p11scope::discovery::identity::{
        ManifestPinError, ManifestStaleReason, PinnedObjectId, ReconciledModule,
        pin_manifest_objects_deferred, pin_scanned_objects, reconcile_scanned_modules,
    };
    use p11scope::discovery::scan::{ScannedEntry, ScannedTable, scan_pid};
    use p11scope_manifest::manifest::{
        Acquisition, AliasEntry, AliasGroup, FunctionRecord, InterfaceClassification,
        SurfaceRecord, SurfaceSource, Version, WalkOutcome,
    };
    use std::cell::Cell;
    use std::collections::BTreeMap;
    use std::os::unix::fs::MetadataExt as _;
    use std::path::PathBuf;

    fn current_mount_namespace() -> p11scope::process::MountNamespaceId {
        let metadata = std::fs::metadata("/proc/self/ns/mnt").unwrap();
        p11scope::process::MountNamespaceId {
            device: metadata.dev(),
            inode: metadata.ino(),
        }
    }

    fn reconcile_for_test(
        modules: &[ScannedModule],
        pinned: &mut PinnedObjects,
    ) -> Vec<ReconciledModule> {
        let (modules, _, skipped) = reconcile_scanned_modules(modules, pinned);
        assert!(skipped.is_empty(), "{skipped:?}");
        modules
    }

    fn lifecycle_discovered(views: Vec<ProcessView>) -> Discovered {
        let plan = plan::build_from_reconciled_modules(&[]);
        Discovered {
            discovery: render::DiscoveryEvidence::default(),
            plan,
            pinned: PinnedObjects::empty(),
            views,
            modules: Vec::new(),
            manifests: Vec::new(),
            counters: DiscoveryCounters::default(),
            identity_mismatches: 0,
            scan_inputs: BTreeMap::new(),
            manifest_inputs: Vec::new(),
            base_counters: DiscoveryCounters::default(),
        }
    }

    fn discovered_from_inputs(
        views: Vec<ProcessView>,
        scan_modules: Vec<ScannedModule>,
        scan_pins: PinnedObjects,
        manifest_inputs: Vec<ManifestInput>,
    ) -> Discovered {
        let mut discovered = lifecycle_discovered(views);
        let view = scan_modules
            .first()
            .expect("test scan input has one process view")
            .view;
        discovered.scan_inputs.insert(
            view,
            ScanInput {
                modules: scan_modules,
                pins: scan_pins,
                counters: DiscoveryCounters::default(),
            },
        );
        discovered.manifest_inputs = manifest_inputs;
        rebuild_discovered(&mut discovered).unwrap();
        discovered
    }

    fn same_object_scan_and_manifest(
        scan_offset: u64,
    ) -> (
        ProcessView,
        Vec<ScannedModule>,
        PinnedObjects,
        ManifestInput,
    ) {
        let (mut modules, pins) = pinned_self();
        assert_eq!(modules.len(), 1);
        let summary = pins.pinned().next().unwrap();
        let (path, key, sha256) = (
            summary.path.to_string(),
            summary.key,
            summary.sha256.to_string(),
        );
        modules[0].tables.push(ScannedTable {
            version: (2, 40),
            walk: "full",
            entries: vec![ScannedEntry {
                name: "C_Sign",
                object: key,
                object_path: path.clone(),
                file_offset: scan_offset,
            }],
            null_entries: vec![],
            unpinned: vec![],
            address: 0x7000,
        });
        let manifest = manifest_naming(&path, Some(sha256));
        let input = ManifestInput {
            path: PathBuf::from("manifest.json"),
            pins: pin_as_manifest_object(&path),
            manifest,
            stale: Vec::new(),
        };
        (
            ProcessView::open(ProcessViewId(0), std::process::id()).unwrap(),
            modules,
            pins,
            input,
        )
    }

    fn object_facts(path: &Path) -> (ObjectKey, p11scope_manifest::identity::ObjectIdentity, u64) {
        let file = p11scope_manifest::identity::open_object(path).unwrap();
        let mapping = p11scope_manifest::identity::mapping_file_key(&file).unwrap();
        let inspected = p11scope_manifest::identity::inspect_file(&file).unwrap();
        (
            ObjectKey {
                device: p11scope_manifest::maps::Device {
                    major: mapping.device_major,
                    minor: mapping.device_minor,
                },
                inode: mapping.inode,
            },
            inspected.identity,
            inspected.executable_ranges[0].0,
        )
    }

    fn valid_manifest_for(paths: &[PathBuf], targets: &[u32]) -> Manifest {
        use p11scope_manifest::manifest::*;

        assert_eq!(targets.len(), 67);
        let facts: Vec<_> = paths.iter().map(|path| object_facts(path)).collect();
        Manifest {
            schema: SCHEMA.to_string(),
            module_path: paths[0].display().to_string(),
            objects: paths
                .iter()
                .zip(&facts)
                .enumerate()
                .map(|(id, (path, (_, identity, _)))| ObjectRecord {
                    id: id as u32,
                    path: path.display().to_string(),
                    identity: identity.clone(),
                })
                .collect(),
            provenance_objects: paths
                .iter()
                .zip(&facts)
                .map(|(path, (key, identity, _))| ProvenanceObject {
                    path: path.display().to_string(),
                    device_major: key.device.major,
                    device_minor: key.device.minor,
                    inode: key.inode,
                    identity: identity.clone(),
                })
                .collect(),
            interface_list: Acquisition::Absent,
            surfaces: vec![SurfaceRecord {
                source: SurfaceSource::LegacyFunctionList,
                acquisition: Acquisition::Ok,
                version: Some(Version { major: 2, minor: 0 }),
                walk: WalkOutcome::Full,
                functions: pkcs11_module::FUNCTION_LIST_FIELDS[..67]
                    .iter()
                    .zip(targets)
                    .map(|(field, object)| FunctionRecord {
                        name: field.name.into(),
                        resolution: Resolution::Resolved {
                            object: *object,
                            file_offset: facts[*object as usize].2,
                        },
                    })
                    .collect(),
            }],
            vendor_interfaces: vec![],
            alias_groups: vec![],
        }
    }

    fn scanned_manifest_replacement(paths: &[PathBuf], targets: &[u32]) -> ScannedModule {
        let facts: Vec<_> = paths.iter().map(|path| object_facts(path)).collect();
        ScannedModule {
            view: ProcessViewId(0),
            mount_namespace: current_mount_namespace(),
            key: facts[0].0,
            path: paths[0].display().to_string(),
            exports: vec!["C_GetFunctionList".into()],
            tables: vec![ScannedTable {
                version: (2, 0),
                walk: "full",
                entries: pkcs11_module::FUNCTION_LIST_FIELDS[..67]
                    .iter()
                    .zip(targets)
                    .map(|(field, object)| ScannedEntry {
                        name: field.name,
                        object: facts[*object as usize].0,
                        object_path: paths[*object as usize].display().to_string(),
                        file_offset: facts[*object as usize].2,
                    })
                    .collect(),
                null_entries: vec![],
                unpinned: vec![],
                address: 0x7000,
            }],
            interfaces: vec![],
        }
    }

    fn manifest_input_from_pinning(path: &str, manifest: Manifest) -> ManifestInput {
        let pinning = pin_manifest_objects_deferred(&manifest).unwrap();
        ManifestInput {
            path: PathBuf::from(path),
            manifest,
            pins: pinning.pins,
            stale: pinning.stale,
        }
    }

    fn pin_scan(module: &ScannedModule) -> PinnedObjects {
        let (pins, skipped) = pin_scanned_objects(
            std::process::id(),
            std::slice::from_ref(module),
            &mut CaptureWorkBudget::default(),
        )
        .unwrap();
        assert!(skipped.is_empty(), "{skipped:?}");
        pins
    }

    #[test]
    fn discovery_open_stale_manifest_object_uses_only_the_exact_scanned_replacement() {
        let dir = tempfile::tempdir().unwrap();
        let provider = dir.path().join("provider.so");
        std::fs::copy("/bin/sh", &provider).unwrap();
        let paths = vec![provider.clone()];
        let targets = vec![0; 67];
        let manifest = valid_manifest_for(&paths, &targets);
        let scan = scanned_manifest_replacement(&paths, &targets);
        let scan_offset = scan.tables[0].entries[0].file_offset;
        let scan_pins = pin_scan(&scan);
        std::fs::remove_file(&provider).unwrap();
        let input = manifest_input_from_pinning("open-stale.json", manifest);
        assert_eq!(input.stale[0].reason, ManifestStaleReason::OpenStale);

        let view = ProcessView::open(ProcessViewId(0), std::process::id()).unwrap();
        let stale_view = view.id();
        let mut discovered = discovered_from_inputs(vec![view], vec![scan], scan_pins, vec![input]);

        assert_eq!(discovered.plan.modules[0].source, "scan");
        assert_eq!(discovered.plan.slots.len(), 1);
        assert_eq!(discovered.plan.slots[0].file_offset, scan_offset);
        assert!(!discovered.plan.slots[0].semantic_authorized);
        assert_eq!(
            discovered.plan.slots[0].semantics,
            p11scope_ebpf_common::SlotSemantics::COUNT_ONLY
        );
        assert_eq!(discovered.counters.manifest_fallbacks.len(), 1);
        assert_eq!(discovered.counters.uncorroborated, 1);
        assert_eq!(discovered.discovery.manifest_object_fallbacks.len(), 1);

        let error = remove_stale_views(&mut discovered, &[stale_view])
            .expect_err("fallback must be recomputed from the surviving pristine views");
        assert!(
            error.to_string().contains("stale manifest object"),
            "{error:#}"
        );
    }

    #[test]
    fn discovery_identity_stale_object_with_invalid_offset_is_fatal_before_fallback() {
        let dir = tempfile::tempdir().unwrap();
        let provider = dir.path().join("provider.so");
        std::fs::copy("/bin/sh", &provider).unwrap();
        let paths = vec![provider.clone()];
        let targets = vec![0; 67];
        let mut manifest = valid_manifest_for(&paths, &targets);
        for function in &mut manifest.surfaces[0].functions {
            let Resolution::Resolved { file_offset, .. } = &mut function.resolution else {
                unreachable!()
            };
            *file_offset = 0xdead_beef;
        }
        std::fs::copy("/bin/true", &provider).unwrap();
        let error = pin_manifest_objects_deferred(&manifest)
            .expect_err("invalid executable offsets stay fatal before stale fallback");
        assert!(
            matches!(
                &error,
                ManifestPinError::Fatal(problems)
                    if problems.iter().any(|problem| problem.contains("outside every executable"))
            ),
            "{error:?}"
        );
    }

    #[test]
    fn discovery_complementary_partial_tables_do_not_cover_one_stale_surface() {
        let dir = tempfile::tempdir().unwrap();
        let provider = dir.path().join("provider.so");
        std::fs::copy("/bin/sh", &provider).unwrap();
        let paths = vec![provider.clone()];
        let targets = vec![0; 67];
        let manifest = valid_manifest_for(&paths, &targets);
        std::fs::copy("/bin/ls", &provider).unwrap();
        let mut scan = scanned_manifest_replacement(&paths, &targets);
        let mut second = scan.tables[0].clone();
        let midpoint = scan.tables[0].entries.len() / 2;
        second.entries = scan.tables[0].entries.split_off(midpoint);
        second.address += 0x1000;
        scan.tables.push(second);
        let pins = pin_scan(&scan);
        let input = manifest_input_from_pinning("partial-tables.json", manifest);
        let mut discovered = lifecycle_discovered(vec![
            ProcessView::open(ProcessViewId(0), std::process::id()).unwrap(),
        ]);
        discovered.scan_inputs.insert(
            ProcessViewId(0),
            ScanInput {
                modules: vec![scan],
                pins,
                counters: DiscoveryCounters::default(),
            },
        );
        discovered.manifest_inputs.push(input);

        let error = rebuild_discovered(&mut discovered)
            .expect_err("two partial tables cannot manufacture one complete proof");
        assert!(error.to_string().contains("object 0"), "{error:#}");
    }

    #[test]
    fn discovery_one_duplicate_table_cannot_prove_two_manifest_surfaces() {
        let dir = tempfile::tempdir().unwrap();
        let provider = dir.path().join("provider.so");
        std::fs::copy("/bin/sh", &provider).unwrap();
        let paths = vec![provider.clone()];
        let targets = vec![0; 67];
        let mut manifest = valid_manifest_for(&paths, &targets);
        manifest.interface_list = Acquisition::Ok;
        manifest.surfaces[0] = SurfaceRecord {
            source: SurfaceSource::LegacyFunctionList,
            acquisition: Acquisition::Absent,
            version: None,
            walk: WalkOutcome::NotWalked,
            functions: vec![],
        };
        let functions: Vec<_> = pkcs11_module::FUNCTION_LIST_FIELDS
            .iter()
            .chain(pkcs11_module::FUNCTION_LIST_3_0_EXTRA_FIELDS)
            .map(|field| FunctionRecord {
                name: field.name.into(),
                resolution: Resolution::Resolved {
                    object: 0,
                    file_offset: object_facts(&provider).2,
                },
            })
            .collect();
        let interface = |index| SurfaceRecord {
            source: SurfaceSource::Interface {
                index,
                raw_name_hex: Some("504b4353203131".into()),
                name_lossy: Some("PKCS 11".into()),
                name_error: None,
                flags: 0,
                classification: InterfaceClassification::ExactStandard,
            },
            acquisition: Acquisition::Ok,
            version: Some(Version { major: 3, minor: 0 }),
            walk: WalkOutcome::Full,
            functions: functions.clone(),
        };
        manifest.surfaces.extend([interface(0), interface(1)]);
        std::fs::copy("/bin/ls", &provider).unwrap();
        let mut scan = scanned_manifest_replacement(&paths, &targets);
        let (key, _, offset) = object_facts(&provider);
        scan.tables[0].version = (3, 0);
        scan.tables[0].entries = pkcs11_module::FUNCTION_LIST_FIELDS
            .iter()
            .chain(pkcs11_module::FUNCTION_LIST_3_0_EXTRA_FIELDS)
            .flat_map(|field| {
                std::iter::repeat_n(
                    ScannedEntry {
                        name: field.name,
                        object: key,
                        object_path: provider.display().to_string(),
                        file_offset: offset,
                    },
                    2,
                )
            })
            .collect();
        let pins = pin_scan(&scan);
        let input = manifest_input_from_pinning("duplicate-table.json", manifest);
        let mut discovered = lifecycle_discovered(vec![
            ProcessView::open(ProcessViewId(0), std::process::id()).unwrap(),
        ]);
        discovered.scan_inputs.insert(
            ProcessViewId(0),
            ScanInput {
                modules: vec![scan],
                pins,
                counters: DiscoveryCounters::default(),
            },
        );
        discovered.manifest_inputs.push(input);

        let error = rebuild_discovered(&mut discovered)
            .expect_err("one table cannot be reused for two manifest surfaces");
        assert!(error.to_string().contains("object 0"), "{error:#}");
    }

    #[test]
    fn discovery_stale_module_requires_coverage_for_unresolved_claims() {
        let dir = tempfile::tempdir().unwrap();
        let provider = dir.path().join("provider.so");
        std::fs::copy("/bin/sh", &provider).unwrap();
        let paths = vec![provider.clone()];
        let targets = vec![0; 67];
        let mut manifest = valid_manifest_for(&paths, &targets);
        manifest.surfaces[0].functions[66].resolution = Resolution::NullPointer;
        std::fs::copy("/bin/ls", &provider).unwrap();
        let mut scan = scanned_manifest_replacement(&paths, &targets);
        scan.tables[0].entries.pop();
        let pins = pin_scan(&scan);
        let input = manifest_input_from_pinning("unresolved-claim.json", manifest);
        let mut discovered = lifecycle_discovered(vec![
            ProcessView::open(ProcessViewId(0), std::process::id()).unwrap(),
        ]);
        discovered.scan_inputs.insert(
            ProcessViewId(0),
            ScanInput {
                modules: vec![scan],
                pins,
                counters: DiscoveryCounters::default(),
            },
        );
        discovered.manifest_inputs.push(input);

        let error = rebuild_discovered(&mut discovered)
            .expect_err("discarded unresolved records still require table coverage");
        assert!(error.to_string().contains("object 0"), "{error:#}");
    }

    #[test]
    fn discovery_mixed_manifest_drops_only_the_stale_dependency_claims() {
        let dir = tempfile::tempdir().unwrap();
        let provider = dir.path().join("provider.so");
        let replaced = dir.path().join("replaced.so");
        let fresh = dir.path().join("fresh.so");
        for path in [&provider, &replaced, &fresh] {
            std::fs::copy("/bin/sh", path).unwrap();
        }
        let paths = vec![provider.clone(), replaced.clone(), fresh.clone()];
        let mut targets = vec![0; 67];
        targets[0] = 1;
        targets[1] = 2;
        targets[2] = 2;
        targets[3] = 1;
        let mut manifest = valid_manifest_for(&paths, &targets);
        let stale_offset = object_facts(&replaced).2;
        let fresh_offset = object_facts(&fresh).2;
        manifest.alias_groups = vec![
            AliasGroup {
                object: 1,
                file_offset: stale_offset,
                entries: vec![
                    AliasEntry {
                        surface: 0,
                        name: manifest.surfaces[0].functions[0].name.clone(),
                    },
                    AliasEntry {
                        surface: 0,
                        name: manifest.surfaces[0].functions[3].name.clone(),
                    },
                ],
            },
            AliasGroup {
                object: 2,
                file_offset: fresh_offset,
                entries: vec![
                    AliasEntry {
                        surface: 0,
                        name: manifest.surfaces[0].functions[1].name.clone(),
                    },
                    AliasEntry {
                        surface: 0,
                        name: manifest.surfaces[0].functions[2].name.clone(),
                    },
                ],
            },
        ];

        std::fs::copy("/bin/ls", &replaced).unwrap();
        let mut scan_targets = targets.clone();
        scan_targets[1] = 0;
        scan_targets[2] = 0;
        let mut scan = scanned_manifest_replacement(&paths, &scan_targets);
        scan.tables[0].entries[4].file_offset += 1;
        let scan_pins = pin_scan(&scan);
        let input = manifest_input_from_pinning("mixed-valid.json", manifest);
        assert_eq!(input.stale.len(), 1);
        assert_eq!(input.stale[0].object, 1);

        let view = ProcessView::open(ProcessViewId(0), std::process::id()).unwrap();
        let discovered = discovered_from_inputs(vec![view], vec![scan], scan_pins, vec![input]);

        assert_eq!(discovered.counters.manifest_fallbacks.len(), 1);
        assert_eq!(discovered.discovery.manifest_object_fallbacks.len(), 1);
        assert_eq!(discovered.manifests.len(), 1);
        let filtered = &discovered.manifests[0];
        assert_eq!(filtered.surfaces.len(), 1);
        assert_eq!(filtered.surfaces[0].walk, WalkOutcome::Full);
        assert_eq!(filtered.surfaces[0].functions.len(), 67);
        for index in [0, 3] {
            assert!(matches!(
                &filtered.surfaces[0].functions[index].resolution,
                Resolution::UnusableFile { reason, path_hex }
                    if reason == "superseded by exact scan fallback" && path_hex.is_empty()
            ));
        }
        for index in [1, 2] {
            assert!(matches!(
                filtered.surfaces[0].functions[index].resolution,
                Resolution::Resolved { object: 1, file_offset } if file_offset == fresh_offset
            ));
        }
        assert_eq!(
            filtered
                .objects
                .iter()
                .map(|object| (object.id, object.path.as_str()))
                .collect::<Vec<_>>(),
            vec![
                (0, provider.to_str().unwrap()),
                (1, fresh.to_str().unwrap())
            ]
        );
        assert_eq!(
            filtered
                .provenance_objects
                .iter()
                .map(|object| object.path.as_str())
                .collect::<Vec<_>>(),
            vec![provider.to_str().unwrap(), fresh.to_str().unwrap()]
        );
        assert_eq!(filtered.alias_groups.len(), 1);
        assert_eq!(filtered.alias_groups[0].object, 1);
        assert_eq!(filtered.alias_groups[0].entries.len(), 2);
        let module_objects = &discovered.discovery.modules[0].objects;
        let sources_for = |path: &Path| {
            let key = object_facts(path).0;
            module_objects
                .iter()
                .find(|object| {
                    object.dev == (key.device.major, key.device.minor) && object.ino == key.inode
                })
                .map(|object| object.sources.as_slice())
        };
        assert_eq!(
            sources_for(&provider),
            Some(["scan", "manifest"].as_slice())
        );
        assert_eq!(sources_for(&replaced), Some(["scan"].as_slice()));
        assert_eq!(sources_for(&fresh), Some(["manifest"].as_slice()));
        assert_eq!(
            discovered.plan.entries_seen, 72,
            "62 exact scan/manifest claims count once; distinct claims remain"
        );
        assert_eq!(discovered.plan.surfaces.len(), 2);
        assert_eq!(
            discovered.plan.modules[0]
                .tables
                .iter()
                .map(|table| (table.source, table.entries))
                .collect::<Vec<_>>(),
            vec![("scan", 67), ("manifest", 67)]
        );
        assert_eq!(
            discovered
                .plan
                .skipped
                .iter()
                .filter(|skip| skip.reason == "superseded by exact scan fallback")
                .count(),
            2
        );
    }

    #[test]
    fn discovery_dependency_fallback_rejects_an_unrelated_modules_table() {
        let dir = tempfile::tempdir().unwrap();
        let provider = dir.path().join("provider.so");
        let replaced = dir.path().join("replaced.so");
        let unrelated = dir.path().join("unrelated.so");
        for path in [&provider, &replaced, &unrelated] {
            std::fs::copy("/bin/sh", path).unwrap();
        }
        let paths = vec![provider.clone(), replaced.clone()];
        let mut manifest_targets = vec![0; 67];
        manifest_targets[0] = 1;
        let manifest = valid_manifest_for(&paths, &manifest_targets);

        std::fs::copy("/bin/ls", &replaced).unwrap();
        let owner_scan = scanned_manifest_replacement(&paths, &vec![0; 67]);
        let unrelated_scan =
            scanned_manifest_replacement(&[unrelated, replaced], &manifest_targets);
        let modules = vec![owner_scan, unrelated_scan];
        let (pins, skipped) = pin_scanned_objects(
            std::process::id(),
            &modules,
            &mut CaptureWorkBudget::default(),
        )
        .unwrap();
        assert!(skipped.is_empty(), "{skipped:?}");
        let input = manifest_input_from_pinning("unrelated.json", manifest);
        assert_eq!(input.stale.len(), 1);

        let mut discovered = lifecycle_discovered(vec![
            ProcessView::open(ProcessViewId(0), std::process::id()).unwrap(),
        ]);
        discovered.scan_inputs.insert(
            ProcessViewId(0),
            ScanInput {
                modules,
                pins,
                counters: DiscoveryCounters::default(),
            },
        );
        discovered.manifest_inputs.push(input);

        let error = rebuild_discovered(&mut discovered)
            .expect_err("only the exact manifest module's scan view may replace its dependency");
        assert!(error.to_string().contains("object 1"), "{error:#}");
    }

    #[test]
    fn discovery_fallback_fails_when_the_proof_module_is_refused_at_capacity() {
        let dir = tempfile::tempdir().unwrap();
        let provider = dir.path().join("provider.so");
        let replaced = dir.path().join("replaced.so");
        let unrelated = dir.path().join("unrelated.so");
        for path in [&provider, &replaced, &unrelated] {
            std::fs::copy("/bin/sh", path).unwrap();
        }
        let paths = vec![provider.clone(), replaced.clone()];
        let mut targets = vec![0; 67];
        targets[0] = 1;
        let manifest = valid_manifest_for(&paths, &targets);
        std::fs::copy("/bin/ls", &replaced).unwrap();

        let mut proof_module = scanned_manifest_replacement(&paths, &targets);
        let (provider_key, _, _) = object_facts(&provider);
        proof_module.tables[0]
            .entries
            .extend(
                (0..p11scope_ebpf_common::MAX_SLOTS).map(|index| ScannedEntry {
                    name: "C_Initialize",
                    object: provider_key,
                    object_path: provider.display().to_string(),
                    file_offset: 0x1000_0000 + u64::from(index),
                }),
            );
        let unrelated_module = scanned_manifest_replacement(&[unrelated, replaced], &targets);
        let modules = vec![proof_module, unrelated_module];
        let (pins, skipped) = pin_scanned_objects(
            std::process::id(),
            &modules,
            &mut CaptureWorkBudget::default(),
        )
        .unwrap();
        assert!(skipped.is_empty(), "{skipped:?}");
        let input = manifest_input_from_pinning("capacity-proof.json", manifest);
        let mut discovered = lifecycle_discovered(vec![
            ProcessView::open(ProcessViewId(0), std::process::id()).unwrap(),
        ]);
        discovered.scan_inputs.insert(
            ProcessViewId(0),
            ScanInput {
                modules,
                pins,
                counters: DiscoveryCounters::default(),
            },
        );
        discovered.manifest_inputs.push(input);

        let error = rebuild_discovered(&mut discovered).expect_err(
            "an unrelated admitted module using the dependency cannot preserve the proof",
        );
        assert!(error.to_string().contains("proof"), "{error:#}");
    }

    #[test]
    fn discovery_fallback_binding_rejects_a_proof_table_lost_during_reconciliation() {
        let dir = tempfile::tempdir().unwrap();
        let provider = dir.path().join("provider.so");
        std::fs::copy("/bin/sh", &provider).unwrap();
        let paths = vec![provider.clone()];
        let targets = vec![0; 67];
        let manifest = valid_manifest_for(&paths, &targets);
        std::fs::copy("/bin/ls", &provider).unwrap();
        let scan = scanned_manifest_replacement(&paths, &targets);
        let mut pins = pin_scan(&scan);
        let input = manifest_input_from_pinning("reconciliation-loss.json", manifest);
        let proof = scanned_replacement(
            &input.manifest,
            &input.stale[0],
            std::slice::from_ref(&scan),
            &pins,
            &input.pins,
        )
        .expect("the pristine scan table proves the pending fallback");
        let (mut reconciled, _, _) =
            reconcile_scanned_modules(std::slice::from_ref(&scan), &mut pins);
        reconciled[0].scanned.tables.clear();
        reconciled[0].entry_objects.clear();

        assert!(
            bind_fallback_proof(&proof, &reconciled).is_none(),
            "a candidate locator is not proof after its exact table is gone"
        );
    }

    #[test]
    fn discovery_open_stale_sole_source_is_fatal_after_scan_availability_is_known() {
        let dir = tempfile::tempdir().unwrap();
        let provider = dir.path().join("provider.so");
        std::fs::copy("/bin/sh", &provider).unwrap();
        let manifest = valid_manifest_for(&[provider.clone()], &vec![0; 67]);
        std::fs::remove_file(&provider).unwrap();
        let input = manifest_input_from_pinning("sole-source.json", manifest);
        let mut discovered = lifecycle_discovered(Vec::new());
        discovered.manifest_inputs.push(input);

        let error = rebuild_discovered(&mut discovered).expect_err("no scan replacement is fatal");
        assert!(
            error.to_string().contains("stale manifest object"),
            "{error:#}"
        );
    }

    #[test]
    fn discovery_mixed_manifest_cannot_hide_a_stale_sole_source_object() {
        let dir = tempfile::tempdir().unwrap();
        let provider = dir.path().join("provider.so");
        let replaced = dir.path().join("replaced.so");
        let sole = dir.path().join("sole.so");
        for path in [&provider, &replaced, &sole] {
            std::fs::copy("/bin/sh", path).unwrap();
        }
        let mut targets = vec![0; 67];
        targets[0] = 1;
        targets[1] = 2;
        let manifest = valid_manifest_for(
            &[provider.clone(), replaced.clone(), sole.clone()],
            &targets,
        );
        std::fs::copy("/bin/ls", &replaced).unwrap();
        std::fs::remove_file(&sole).unwrap();

        let mut scan_targets = targets.clone();
        scan_targets[1] = 0;
        let scan = scanned_manifest_replacement(&[provider, replaced], &scan_targets);
        let scan_pins = pin_scan(&scan);
        let input = manifest_input_from_pinning("mixed.json", manifest);
        assert_eq!(input.stale.len(), 2);
        let mut discovered = lifecycle_discovered(vec![
            ProcessView::open(ProcessViewId(0), std::process::id()).unwrap(),
        ]);
        discovered.scan_inputs.insert(
            ProcessViewId(0),
            ScanInput {
                modules: vec![scan],
                pins: scan_pins,
                counters: DiscoveryCounters::default(),
            },
        );
        discovered.manifest_inputs.push(input);

        let error = rebuild_discovered(&mut discovered)
            .expect_err("the second stale object has no scanned replacement");
        assert!(error.to_string().contains("object 2"), "{error:#}");
    }

    #[derive(Debug)]
    struct FakeSession(std::rc::Rc<std::cell::RefCell<Vec<&'static str>>>);

    impl Drop for FakeSession {
        fn drop(&mut self) {
            self.0.borrow_mut().push("drop");
        }
    }

    /// Mutation caught: starting before the precheck would attach against a raw,
    /// potentially recycled named PID.
    #[test]
    fn named_generation_change_before_attach_never_starts_a_session() {
        let view = ProcessView::open(ProcessViewId(0), std::process::id()).unwrap();
        let stale = view.id();
        let mut discovered = lifecycle_discovered(vec![view]);
        let starts = Cell::new(0);
        let error = start_retained_with(
            &mut discovered,
            true,
            |_| vec![stale],
            |_, _| {
                starts.set(starts.get() + 1);
                Ok(FakeSession(Default::default()))
            },
        )
        .expect_err("a named generation change is fatal");

        assert!(error.to_string().contains("before attach"), "{error:#}");
        assert_eq!(starts.get(), 0, "no attach action may follow the mismatch");
    }

    /// Mutation caught: returning the new session before the postcheck would make its
    /// ring/maps consumable; failing without dropping it would leave its links live.
    #[test]
    fn named_generation_change_during_attach_drops_before_event_consumption() {
        let view = ProcessView::open(ProcessViewId(0), std::process::id()).unwrap();
        let stale = view.id();
        let mut discovered = lifecycle_discovered(vec![view]);
        let checks = Cell::new(0);
        let log = std::rc::Rc::new(std::cell::RefCell::new(Vec::new()));
        let error = start_retained_with(
            &mut discovered,
            true,
            |_| {
                checks.set(checks.get() + 1);
                (checks.get() == 2).then_some(stale).into_iter().collect()
            },
            |_, _| {
                log.borrow_mut().push("start");
                Ok(FakeSession(std::rc::Rc::clone(&log)))
            },
        )
        .expect_err("a named generation change is fatal");

        assert!(error.to_string().contains("while attaching"), "{error:#}");
        assert_eq!(*log.borrow(), ["start", "drop"]);
        assert!(!log.borrow().contains(&"consume"));
    }

    /// Mutation caught: retrying without subtracting an originally accepted stale
    /// view can spin forever under cgroup churn. Three accepted views permit only
    /// three stale-session retries, followed by the final stable start.
    #[test]
    fn cgroup_retries_retire_one_original_view_each_time_and_publish_partial() {
        let views: Vec<_> = (0..3)
            .map(|id| ProcessView::open(ProcessViewId(id), std::process::id()).unwrap())
            .collect();
        let original: Vec<_> = views.iter().map(ProcessView::id).collect();
        let mut discovered = lifecycle_discovered(views);
        let checks = Cell::new(0usize);
        let starts = Cell::new(0usize);
        let log = std::rc::Rc::new(std::cell::RefCell::new(Vec::new()));
        let session = start_retained_with(
            &mut discovered,
            false,
            |_| {
                checks.set(checks.get() + 1);
                if checks.get() % 2 == 0 {
                    original
                        .get(checks.get() / 2 - 1)
                        .copied()
                        .into_iter()
                        .collect()
                } else {
                    Vec::new()
                }
            },
            |_, _| {
                starts.set(starts.get() + 1);
                log.borrow_mut().push("start");
                Ok(FakeSession(std::rc::Rc::clone(&log)))
            },
        )
        .unwrap();

        assert_eq!(starts.get(), original.len() + 1);
        assert!(discovered.views.is_empty());
        assert_eq!(
            discovered
                .counters
                .object_skips
                .iter()
                .filter(|skip| skip.reason == STALE_VIEW_REASON)
                .count(),
            original.len(),
            "each retired accepted view remains accounted internally"
        );
        assert_eq!(
            discovered.plan.skipped.len(),
            1,
            "identical public cgroup losses use the existing bounded deduplication"
        );
        assert!(
            discovered
                .plan
                .skipped
                .iter()
                .map(render::capture_skipped_out)
                .all(|skip| skip.name == "discovery subject"
                    && skip.reason == "discovery unavailable")
        );
        assert_eq!(
            log.borrow()
                .iter()
                .filter(|event| **event == "drop")
                .count(),
            original.len(),
            "every stale post-start pass tears down its whole session"
        );
        drop(session);
    }

    /// Mutation caught: retaining only the initial `Agreed` outcome drops the
    /// manifest's valid offsets when its sole agreeing scan owner is retired.
    #[test]
    fn stale_sole_owner_agreement_falls_back_to_the_retained_manifest() {
        let (view, modules, pins, input) = same_object_scan_and_manifest(0x40);
        let stale = view.id();
        let mut discovered = discovered_from_inputs(vec![view], modules, pins, vec![input]);
        assert_eq!(discovered.plan.slots.len(), 1);
        assert_eq!(discovered.plan.modules[0].source, "scan+manifest");
        assert!(
            discovered.plan.slots[0].semantic_authorized,
            "an agreed explicit manifest remains an exact plan claim"
        );
        assert_eq!(
            discovered.plan.slots[0].semantics,
            p11scope::kinds::descriptor("C_Sign").unwrap()
        );
        assert_eq!(discovered.plan.entries_seen, 1);

        remove_stale_views(&mut discovered, &[stale]).unwrap();

        assert_eq!(discovered.plan.slots.len(), 1);
        assert_eq!(discovered.plan.slots[0].names, ["C_Sign"]);
        assert_eq!(discovered.plan.slots[0].file_offset, 0x40);
        assert!(discovered.plan.slots[0].semantic_authorized);
        assert_eq!(discovered.plan.modules[0].source, "manifest");
        assert_eq!(discovered.counters.uncorroborated, 1);
        assert_eq!(discovered.identity_mismatches, 0);
    }

    /// Mutation caught: a stale path-matching view's mismatch must not remain
    /// latched and abort the rebuild after that view's scan slot is subtracted.
    #[test]
    fn stale_only_identity_mismatch_becomes_manifest_fallback_for_stable_scope() {
        let dir = tempfile::tempdir().unwrap();
        let provider = dir.path().join("provider.so");
        std::fs::copy("/bin/sh", &provider).unwrap();
        let path = provider.display().to_string();
        let own = pin_as_manifest_object(&path);
        let old_sha = own.pinned().next().unwrap().sha256.to_string();
        let manifest = manifest_naming(&path, Some(old_sha));

        let replacement = dir.path().join("replacement.so");
        std::fs::copy("/bin/true", &replacement).unwrap();
        std::fs::rename(&replacement, &provider).unwrap();
        let file = p11scope_manifest::identity::open_object(&provider).unwrap();
        let mapping = p11scope_manifest::identity::mapping_file_key(&file).unwrap();
        let key = ObjectKey {
            device: p11scope_manifest::maps::Device {
                major: mapping.device_major,
                minor: mapping.device_minor,
            },
            inode: mapping.inode,
        };
        let module = ScannedModule {
            view: ProcessViewId(0),
            mount_namespace: current_mount_namespace(),
            key,
            path: path.clone(),
            exports: vec!["C_GetFunctionList".into()],
            tables: vec![ScannedTable {
                version: (2, 40),
                walk: "full",
                entries: vec![ScannedEntry {
                    name: "C_Sign",
                    object: key,
                    object_path: path.clone(),
                    file_offset: 0x80,
                }],
                null_entries: vec![],
                unpinned: vec![],
                address: 0x7000,
            }],
            interfaces: vec![],
        };
        let (scan_pins, skipped) = pin_scanned_objects(
            std::process::id(),
            std::slice::from_ref(&module),
            &mut CaptureWorkBudget::default(),
        )
        .unwrap();
        assert!(skipped.is_empty(), "{skipped:?}");
        let stale = ProcessView::open(ProcessViewId(0), std::process::id()).unwrap();
        let stable = ProcessView::open(ProcessViewId(1), std::process::id()).unwrap();
        let stale_id = stale.id();
        let input = ManifestInput {
            path: PathBuf::from("stale-manifest.json"),
            manifest,
            pins: own,
            stale: Vec::new(),
        };
        let mut discovered =
            discovered_from_inputs(vec![stale, stable], vec![module], scan_pins, vec![input]);
        assert_eq!(discovered.identity_mismatches, 1);
        assert_eq!(
            discovered.plan.slots.len(),
            1,
            "the scan initially keeps capture viable"
        );

        remove_stale_views(&mut discovered, &[stale_id]).unwrap();

        assert_eq!(
            discovered.views.len(),
            1,
            "the unrelated stable view remains"
        );
        assert_eq!(discovered.identity_mismatches, 0);
        assert_eq!(discovered.plan.modules[0].source, "manifest");
        assert_eq!(discovered.plan.slots[0].names, ["C_Sign"]);
    }

    /// Mutation caught: subtracting the only conflicting scan owner must recompute
    /// the manifest as uncorroborated instead of preserving stale conflict evidence.
    #[test]
    fn stale_conflict_owner_is_removed_from_final_counter_and_corroboration() {
        let (view, modules, pins, input) = same_object_scan_and_manifest(0x80);
        let stale = view.id();
        let mut discovered = discovered_from_inputs(vec![view], modules, pins, vec![input]);
        assert_eq!(discovered.counters.conflicts, 1);
        assert_eq!(discovered.plan.slots.len(), 2);

        remove_stale_views(&mut discovered, &[stale]).unwrap();

        assert_eq!(discovered.counters.conflicts, 0);
        assert_eq!(discovered.plan.slots.len(), 1);
        assert_eq!(discovered.plan.modules[0].source, "manifest");
        assert_eq!(
            discovered.discovery.modules[0].corroboration,
            ["uncorroborated"]
        );
    }

    #[test]
    fn repeated_manifest_only_outcomes_preserve_order_and_multiplicity() {
        let (_, pins) = pinned_self();
        let summary = pins.pinned().next().unwrap();
        let path = summary.path.to_string();
        let sha256 = summary.sha256.to_string();
        let input = |name| ManifestInput {
            path: PathBuf::from(name),
            manifest: manifest_naming(&path, Some(sha256.clone())),
            pins: pin_as_manifest_object(&path),
            stale: Vec::new(),
        };
        let mut discovered = lifecycle_discovered(Vec::new());
        discovered.manifest_inputs = vec![input("first.json"), input("second.json")];

        rebuild_discovered(&mut discovered).unwrap();

        assert_eq!(discovered.plan.modules.len(), 1);
        assert_eq!(
            discovered.discovery.modules[0].corroboration,
            ["uncorroborated", "uncorroborated"],
            "one accepted outcome must remain visible for each repeated --manifest input"
        );
    }

    #[test]
    fn repeated_manifest_outcomes_recompute_after_the_scan_owner_is_removed() {
        let (view, modules, pins, input) = same_object_scan_and_manifest(0x40);
        let stale = view.id();
        let mut duplicate = ManifestInput {
            path: PathBuf::from("duplicate-manifest.json"),
            manifest: input.manifest.clone(),
            pins: pin_as_manifest_object(&input.manifest.module_path),
            stale: Vec::new(),
        };
        let Resolution::Resolved { file_offset, .. } =
            &mut duplicate.manifest.surfaces[0].functions[0].resolution
        else {
            unreachable!()
        };
        *file_offset = 0x80;
        let mut discovered =
            discovered_from_inputs(vec![view], modules, pins, vec![input, duplicate]);

        assert_eq!(
            discovered.discovery.modules[0].corroboration,
            ["agreed", "conflict"],
            "outcomes retain repeated manifest input order"
        );

        remove_stale_views(&mut discovered, &[stale]).unwrap();

        assert_eq!(discovered.plan.modules.len(), 1);
        assert_eq!(
            discovered.discovery.modules[0].corroboration,
            ["uncorroborated", "uncorroborated"],
            "rebuilds must retain each accepted manifest outcome, not synthesize one"
        );
    }

    #[test]
    fn later_manifest_identity_collision_drops_stale_scan_ids_before_planning() {
        let dir = tempfile::tempdir().unwrap();
        let provider = dir.path().join("provider.so");
        let dependency = dir.path().join("dependency.so");
        std::fs::copy("/bin/sh", &provider).unwrap();
        std::fs::copy("/bin/sh", &dependency).unwrap();
        let paths = vec![provider.clone(), dependency.clone()];
        let targets = vec![1; 67];
        let scan = scanned_manifest_replacement(&paths, &targets);
        let dependency_key = scan.tables[0].entries[0].object;
        let scan_pins = pin_scan(&scan);

        // `copy` truncates the existing file: its raw map key remains the same,
        // while its opened pin and hash become incomparable to the scan's pin.
        std::fs::copy("/bin/true", &dependency).unwrap();
        let input = manifest_input_from_pinning(
            "later-collision.json",
            valid_manifest_for(&paths, &targets),
        );
        let view = ProcessView::open(ProcessViewId(0), std::process::id()).unwrap();
        let stale = view.id();
        let mut discovered = lifecycle_discovered(vec![view]);
        discovered.scan_inputs.insert(
            stale,
            ScanInput {
                modules: vec![scan],
                pins: scan_pins,
                counters: DiscoveryCounters::default(),
            },
        );
        discovered.manifest_inputs.push(input);

        rebuild_discovered(&mut discovered).unwrap();

        assert!(
            discovered
                .plan
                .modules
                .iter()
                .all(|module| discovered.pinned.summary(module.object).is_some()),
            "no pre-absorption module ID may reach the final plan"
        );
        assert!(
            discovered
                .plan
                .slots
                .iter()
                .all(|slot| discovered.pinned.summary(slot.object).is_some()),
            "no pre-absorption dependency ID may reach the final plan"
        );
        assert!(
            discovered.plan.slots.iter().all(|slot| {
                discovered
                    .pinned
                    .summary(slot.object)
                    .is_none_or(|summary| summary.key != dependency_key)
            }),
            "the rejected collision group cannot lend its old dependency offsets"
        );
        assert_eq!(
            discovered.discovery.modules[0].corroboration,
            ["conflict"],
            "the surviving exact provider owns the conflict outcome"
        );

        remove_stale_views(&mut discovered, &[stale]).unwrap();
        assert!(
            discovered
                .plan
                .slots
                .iter()
                .all(|slot| discovered.pinned.summary(slot.object).is_some()),
            "a stable-view rebuild resolves fresh final IDs from pristine inputs"
        );
    }

    #[test]
    fn corroboration_marks_the_exact_reconciled_object_not_the_raw_key_peer() {
        let key = ObjectKey {
            device: p11scope_manifest::maps::Device { major: 8, minor: 1 },
            inode: 42,
        };
        let module = |view, object, path: &str, offset| ReconciledModule {
            object,
            entry_objects: vec![vec![object]],
            scanned: ScannedModule {
                view,
                mount_namespace: current_mount_namespace(),
                key,
                path: path.into(),
                exports: vec!["C_GetFunctionList".into()],
                tables: vec![ScannedTable {
                    version: (2, 40),
                    walk: "full",
                    entries: vec![ScannedEntry {
                        name: "C_Sign",
                        object: key,
                        object_path: path.into(),
                        file_offset: offset,
                    }],
                    null_entries: vec![],
                    unpinned: vec![],
                    address: 0x7000 + offset,
                }],
                interfaces: vec![],
            },
        };
        let first = module(ProcessViewId(0), PinnedObjectId(100), "/first.so", 0x10);
        let second = module(ProcessViewId(0), PinnedObjectId(200), "/second.so", 0x20);
        let mut counters = DiscoveryCounters::default();
        let plan = build_current_plan(
            &[first, second],
            &[],
            &PinnedObjects::empty(),
            &mut counters,
            // The exact final object, not its equal-key peer, owns the outcome.
            &[PinnedObjectId(200)].into_iter().collect(),
            0,
            0,
        )
        .unwrap();

        let first = plan
            .modules
            .iter()
            .find(|module| module.object == PinnedObjectId(100))
            .unwrap();
        let second = plan
            .modules
            .iter()
            .find(|module| module.object == PinnedObjectId(200))
            .unwrap();
        assert!(!first.corroborated);
        assert_eq!(first.source, "scan");
        assert!(second.corroborated);
        assert_eq!(second.source, "scan+manifest");

        counters
            .corroboration
            .push(([PinnedObjectId(200)].into_iter().collect(), "conflict"));
        assert_eq!(
            corroboration_of(&counters, first),
            ["single_source"],
            "a raw-key peer must not contribute public outcome evidence"
        );
        assert_eq!(
            corroboration_of(&counters, second),
            ["conflict"],
            "the exact reconciled module retains its outcome array"
        );
    }

    #[test]
    fn pending_fallback_outcome_follows_the_final_overlay_canonical_id_without_authority() {
        let key = ObjectKey {
            device: p11scope_manifest::maps::Device {
                major: 0,
                minor: 102,
            },
            inode: 42,
        };
        let module = |view: ProcessViewId, path: &str| ReconciledModule {
            object: PinnedObjectId(200),
            entry_objects: vec![vec![PinnedObjectId(200)]],
            scanned: ScannedModule {
                view,
                mount_namespace: current_mount_namespace(),
                key,
                path: path.into(),
                exports: vec!["C_GetFunctionList".into()],
                tables: vec![ScannedTable {
                    version: (2, 40),
                    walk: "full",
                    entries: vec![ScannedEntry {
                        name: "C_Sign",
                        object: key,
                        object_path: path.into(),
                        file_offset: 0x10,
                    }],
                    null_entries: vec![],
                    unpinned: vec![],
                    address: 0x7000,
                }],
                interfaces: vec![],
            },
        };
        let first = module(ProcessViewId(0), "/overlay/first.so");
        let second = module(ProcessViewId(1), "/overlay/second.so");
        let mut counters = DiscoveryCounters::default();
        let corroborated = bind_pending_corroboration(
            vec![PendingCorroboration {
                owners: vec![OutcomeOwner::Scan(ScanOutcomeLocator::module(
                    &second.scanned,
                ))],
                label: "object_fallback",
            }],
            &[first, second],
            &PinnedObjects::empty(),
            &mut counters,
        )
        .unwrap();

        assert!(
            corroborated.is_empty(),
            "a scan-only overlay collapse can bind fallback evidence but never semantic authority"
        );
        assert_eq!(
            counters.corroboration,
            vec![(
                [PinnedObjectId(200)].into_iter().collect(),
                "object_fallback"
            )],
            "the overlay peer's fallback locator binds to its final canonical ID, never a stale pre-remap ID"
        );
    }

    #[test]
    fn pending_corroboration_rebuild_resolves_the_current_final_id() {
        let key = ObjectKey {
            device: p11scope_manifest::maps::Device { major: 8, minor: 1 },
            inode: 42,
        };
        let module = |object| ReconciledModule {
            object,
            entry_objects: vec![vec![object]],
            scanned: ScannedModule {
                view: ProcessViewId(0),
                mount_namespace: current_mount_namespace(),
                key,
                path: "/stable-view.so".into(),
                exports: vec!["C_GetFunctionList".into()],
                tables: vec![ScannedTable {
                    version: (2, 40),
                    walk: "full",
                    entries: vec![ScannedEntry {
                        name: "C_Sign",
                        object: key,
                        object_path: "/stable-view.so".into(),
                        file_offset: 0x10,
                    }],
                    null_entries: vec![],
                    unpinned: vec![],
                    address: 0x7000,
                }],
                interfaces: vec![],
            },
        };
        let first = module(PinnedObjectId(10));
        let owner = OutcomeOwner::Scan(ScanOutcomeLocator::module(&first.scanned));
        let second = module(PinnedObjectId(20));
        let mut counters = DiscoveryCounters::default();
        let corroborated = bind_pending_corroboration(
            vec![PendingCorroboration {
                owners: vec![owner],
                label: "conflict",
            }],
            &[second],
            &PinnedObjects::empty(),
            &mut counters,
        )
        .unwrap();

        assert_eq!(corroborated, [PinnedObjectId(20)].into_iter().collect());
        assert_eq!(
            counters.corroboration,
            vec![([PinnedObjectId(20)].into_iter().collect(), "conflict")],
            "a rebuild cannot retain an earlier capture-local numeric ID"
        );
    }

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
        let plan = plan::AttachPlan::from_slots(vec![]);
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
        let mut budget = CaptureWorkBudget::new(limits);
        let outcome = scan_pid(
            &ScanRequest {
                pid: std::process::id(),
                hints: &[exe],
                hooks: &hooks,
            },
            &mut budget,
        )
        .unwrap();
        let modules = outcome.modules().to_vec();
        let (pinned, _) = pin_scanned_objects(std::process::id(), &modules, &mut budget).unwrap();
        assert_eq!(
            pinned.pinned().count(),
            1,
            "the hinted executable is pinned"
        );
        (modules, pinned)
    }

    #[test]
    fn coordinator_reuses_one_budget_across_process_scans_and_hashes() {
        use std::os::unix::fs::MetadataExt as _;

        let exe = std::env::current_exe().unwrap();
        let inode = std::fs::metadata(&exe).unwrap().ino();
        let maps = p11scope_manifest::maps::parse_maps(&std::fs::read("/proc/self/maps").unwrap())
            .unwrap();
        let scan_bytes: u64 = maps
            .iter()
            .filter(|m| m.inode == inode && m.permissions[0] == b'r' && m.permissions[2] != b'x')
            .map(|m| m.end - m.start)
            .sum();
        let hash_bytes = std::fs::metadata(&exe).unwrap().len();
        let mut budget = CaptureWorkBudget::new(ScanLimits {
            per_object_bytes: scan_bytes.max(hash_bytes),
            total_bytes: scan_bytes + hash_bytes,
        });
        let args = CaptureArgs {
            kind: Kind::Profile,
            modules: vec![exe],
            manifests: vec![],
            hooks: p11scope::discovery::hooks::HookRegistry::builtin(),
            scope: ScopeArg::Pid(std::process::id()),
            metrics: false,
            duration: None,
            out: None,
            unsafe_requested: false,
        };
        let mut counters = DiscoveryCounters::default();
        let first_view = ProcessView::open(ProcessViewId(0), std::process::id()).unwrap();
        let (_, first) = scan_and_pin(&first_view, &args, &mut budget, &mut counters).unwrap();
        let second_view = ProcessView::open(ProcessViewId(1), std::process::id()).unwrap();
        let (_, second) = scan_and_pin(&second_view, &args, &mut budget, &mut counters).unwrap();
        assert_eq!(first.pinned().count(), 1);
        assert_eq!(
            second.pinned().count(),
            0,
            "the later scan cannot renew bytes"
        );
        assert!(
            counters
                .object_skips
                .iter()
                .any(|skip| skip.reason.contains("capture attempted-I/O ceiling")),
            "budget exhaustion must remain explicit: {:?}",
            counters.object_skips
        );
    }

    /// The pin `pin_manifest_objects` produces for one manifest object: filed under
    /// the path the manifest names (`ObjectRecord.path`, which it opens), keyed by the
    /// identity that path resolves to right now.
    fn pin_as_manifest_object(object_path: &str) -> PinnedObjects {
        let file = p11scope_manifest::identity::open_object(Path::new(object_path)).unwrap();
        let found = p11scope_manifest::identity::mapping_file_key(&file).unwrap();
        let identity = p11scope_manifest::identity::inspect_file(&file)
            .unwrap()
            .identity;
        let mut manifest = manifest_naming(object_path, identity.sha256.clone());
        manifest.objects[0].identity = identity.clone();
        manifest.provenance_objects[0] = p11scope_manifest::manifest::ProvenanceObject {
            path: object_path.to_string(),
            device_major: found.device_major,
            device_minor: found.device_minor,
            inode: found.inode,
            identity,
        };
        manifest.surfaces[0].acquisition = p11scope_manifest::manifest::Acquisition::Absent;
        manifest.surfaces[0].walk = p11scope_manifest::manifest::WalkOutcome::NotWalked;
        manifest.surfaces[0].functions.clear();
        pin_manifest_objects(&manifest).unwrap()
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
        let (mut modules, mut pinned) = pinned_self();
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
        modules[0].tables.last_mut().unwrap().entries[0].object_path = modules[0].path.clone();

        let (reconciled, _, dropped) = reconcile_scanned_modules(&modules, &mut pinned);
        assert_eq!(dropped.len(), 1, "{dropped:?}");
        assert_eq!(dropped[0].subject, "C_Verify");
        assert!(
            dropped[0]
                .reason
                .contains("could not be reconciled to a comparable pinned object"),
            "{dropped:?}"
        );

        let plan = plan::build_from_reconciled_modules(&reconciled);
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

    #[test]
    fn an_unpinned_entry_skip_is_bounded_in_every_capture_output() {
        let raw = Skipped {
            subject: "C_Sign".into(),
            reason: "/private/ROUND4_OBJECT_PATH_SENTINEL.so was not pinned: \
                     ROUND4_ERROR_CHAIN_SENTINEL"
                .into(),
        };
        let (mut modules, mut pinned) = pinned_self();
        modules[0]
            .tables
            .push(p11scope::discovery::scan::ScannedTable {
                version: (2, 40),
                walk: "full",
                entries: vec![],
                null_entries: vec![],
                unpinned: vec![raw.clone()],
                address: 0x7000,
            });
        let reconciled = reconcile_for_test(&modules, &mut pinned);
        let plan = plan::build_from_reconciled_modules(&reconciled);
        assert_eq!(plan.skipped, vec![raw.clone()]);
        assert_eq!(plan.modules[0].skipped, vec![raw]);

        let discovery = discovery_evidence(&plan, &pinned, &DiscoveryCounters::default());
        let mut evidence = render::Evidence {
            table_entries: plan.entries_seen,
            slots: plan.slots.len(),
            attached_probes: 0,
            attach_failures: vec![],
            aliased: vec![],
            skipped: plan
                .skipped
                .iter()
                .map(render::capture_skipped_out)
                .collect(),
            semantic_unverified_slots: 0,
            in_flight_at_end: 0,
            surfaces: plan.surfaces.clone(),
            vendor_interfaces: 0,
            interface_list: "absent".into(),
            event_loss: 0,
            start_insert_failures: 0,
            unmatched_returns: 0,
            rv_update_failures: 0,
            cgroup_scope_failures: 0,
            semantic_capture_failures: 0,
            unregistered_mechanisms: 0,
            template_tail_failures: 0,
            process_tracking_fallbacks: 0,
            process_tracking_failures: 0,
            process_tracking_evictions: 0,
            state_reconciliations: 0,
            session_cancel_ambiguities: 0,
            session_cancel_unknown_flags: 0,
            operation_state_imports: 0,
            auth_state_ambiguities: 0,
            async_target_failures: 0,
            async_orphans: 0,
            async_duplicates: 0,
            async_evictions: 0,
            fork_state_ambiguities: 0,
            semantic_state_drops: 0,
            pending_at_end: 0,
            malformed_records: 0,
            orphan_ops: 0,
            unmatched_closes: 0,
            shape_decode_failures: 0,
            shape_decode_total_failures: 0,
            templates_truncated: false,
            provider_changed: false,
            discovery,
            completeness: "UNKNOWN",
        };
        evidence.verdict();
        let profile_capture = render::CaptureMeta {
            started: "t0",
            ended: "t1",
            kernel: "test",
            policy: CapturePolicy::Allowlisted,
        };
        let state = semantics::State::with_policy(&plan, CapturePolicy::Allowlisted);
        let profile = render::profile_json(&[], &evidence, &state, &profile_capture);
        let metrics_capture = render::CaptureMeta {
            policy: CapturePolicy::AggregateOnly,
            ..profile_capture
        };
        let metrics = render::json(&[], &evidence, &metrics_capture);
        let trace = trace::evidence_line(&evidence, CapturePolicy::Allowlisted);

        for rendered in [
            serde_json::to_string(&profile).unwrap(),
            serde_json::to_string(&metrics).unwrap(),
            trace,
        ] {
            for sentinel in ["ROUND4_OBJECT_PATH_SENTINEL", "ROUND4_ERROR_CHAIN_SENTINEL"] {
                assert!(
                    !rendered.contains(sentinel),
                    "leaked {sentinel}: {rendered}"
                );
            }
        }
        for document in [profile, metrics] {
            assert_eq!(document["evidence"]["completeness"], "PARTIAL");
            assert_eq!(document["evidence"]["skipped"].as_array().unwrap().len(), 1);
            assert_eq!(
                document["evidence"]["discovery"][0]["skipped"],
                document["evidence"]["skipped"]
            );
            assert_eq!(
                document["evidence"]["skipped"][0],
                serde_json::json!({
                    "name": "C_Sign",
                    "reason": "function entry unavailable",
                })
            );
        }
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
        let (mut pinned, skips) = pin_scanned_objects(
            std::process::id(),
            &modules,
            &mut CaptureWorkBudget::new(tiny),
        )
        .unwrap();
        assert_eq!(pinned.pinned().count(), 0, "nothing could be pinned");
        assert!(!skips.is_empty(), "the scan reported the loss");

        let (reconciled, _, _) = reconcile_scanned_modules(&modules, &mut pinned);
        let mut plan = plan::build_from_reconciled_modules(&reconciled);
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
        let mut plan = plan::build_from_reconciled_modules(&reconciled);
        record_object_skips(&mut plan, &mixed);
        assert_eq!(plan.skipped.len(), skips.len() + 1, "{:?}", plan.skipped);
        assert!(plan.skipped.contains(&other), "{:?}", plan.skipped);
    }

    fn plan_with(slots: usize, refused: usize) -> plan::AttachPlan {
        let mut plan = plan::AttachPlan::from_slots(
            (0..slots)
                .map(|index| plan::Slot {
                    index: index as u32,
                    descriptor_index: 0,
                    object: PinnedObjectId(42),
                    object_path: "/opt/p11.so".into(),
                    file_offset: index as u64 * 8,
                    names: vec!["C_Sign".into()],
                    aliased: false,
                    semantics: p11scope_ebpf_common::SlotSemantics::COUNT_ONLY,
                    semantic_authorized: true,
                    semantic_ambiguous: false,
                    fork_safe: false,
                    module_ids: vec![plan::ModuleId(0)],
                })
                .collect(),
        );
        plan.modules = vec![plan::ModuleSummary {
            id: plan::ModuleId(0),
            object: PinnedObjectId(42),
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
        }];
        plan.modules_skipped = (0..refused)
            .map(|i| Skipped {
                subject: format!("/opt/big{i}.so"),
                reason: "module needs 600 more of the 512 attach slots".into(),
            })
            .collect();
        plan.entries_seen = slots;
        plan
    }

    fn plan_with_pins(slots: usize, refused: usize) -> (plan::AttachPlan, PinnedObjects) {
        let (_, pins) = pinned_self();
        let pin = pins.pinned().next().unwrap();
        let mut plan = plan_with(slots, refused);
        for slot in &mut plan.slots {
            slot.object = pin.id;
            slot.object_path = pin.path.to_string();
        }
        plan.modules[0].object = pin.id;
        plan.modules[0].key = pin.key;
        plan.modules[0].path = pin.path.to_string();
        (plan, pins)
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
        let (plan, pins) = plan_with_pins(4, 1);
        let evidence = discovery_evidence(&plan, &pins, &DiscoveryCounters::default());
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
        assert_eq!(
            uncorroborated_count(&plan, 0, 0),
            0,
            "a scanned module is not"
        );
        assert_eq!(
            uncorroborated_count(&plan, 1, 0),
            1,
            "an ignored manifest must reach a counter, or it reaches none"
        );
        plan.modules[0].source = "manifest";
        assert_eq!(uncorroborated_count(&plan, 1, 0), 2, "both are counted");
        plan.modules[0].corroborated = true;
        assert_eq!(uncorroborated_count(&plan, 0, 0), 0);
        assert_eq!(uncorroborated_count(&plan, 0, 1), 1);
    }

    /// Both §4.12 outcomes that attach a union mark the module corroborated, so
    /// without the outcome itself an agreement and a conflict are the same
    /// record — and `discovery_conflicts` would have nothing explaining it.
    #[test]
    fn the_module_record_says_which_corroboration_outcome_it_got() {
        let (plan, pins) = plan_with_pins(1, 0);
        let object = plan.modules[0].object;
        for (outcome, label) in [
            (Corroboration::Agreed, "agreed"),
            (Corroboration::Conflict, "conflict"),
            (Corroboration::ScanEmpty, "scan_empty"),
            (Corroboration::IdentityMismatch, "identity_mismatch"),
        ] {
            let counters = DiscoveryCounters {
                corroboration: vec![([object].into_iter().collect(), corroboration_label(outcome))],
                ..DiscoveryCounters::default()
            };
            let evidence = discovery_evidence(&plan, &pins, &counters);
            assert_eq!(evidence.modules[0].corroboration, vec![label]);
        }
        // Nothing recorded: one source described it, and the record says so
        // rather than implying a second source failed to.
        let evidence = discovery_evidence(&plan, &pins, &DiscoveryCounters::default());
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

        retarget_to_pins(&mut m, &[], &pins, &own);
        pins.absorb(own);

        let plan = plan::build_from_sources(&[], std::slice::from_ref(&m), &pins);
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

            retarget_to_pins(&mut m, &[], &pins, &own);

            let plan = plan::build_from_sources(&[], std::slice::from_ref(&m), &pins);
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
        let own = pin_as_manifest_object(&path);
        let view = scan_view(&m, &modules, &pinned, &own).expect("mapped and pinned");
        assert_eq!(view.modules[0].key, summary.key);
        assert!(view.agrees, "the recorded sha256 is the pinned one");
        let manifest_target = manifest_targets(&m, &own).unwrap();
        assert_eq!(manifest_target.len(), 1);
        let (manifest_target, manifest_offset) = manifest_target.iter().next().unwrap();
        assert_eq!(*manifest_offset, 0x40);
        assert_eq!(
            own.summary(*manifest_target).unwrap().path,
            path,
            "manifest targets resolve through their exact opened pin"
        );
        assert_eq!(
            scanned_targets(&view.modules, &pinned),
            Some(BTreeSet::new()),
            "our own executable publishes no PKCS#11 table"
        );

        // Same path, different bytes: §4.12's identity mismatch.
        let stale = manifest_naming(&path, Some("22".repeat(32)));
        assert_eq!(
            scan_view(&stale, &modules, &pinned, &own).map(|view| view.agrees),
            Some(false)
        );

        // Mapped but never pinned: nothing to compare against, so nothing corroborates
        // it — the trigger condition for the unpinned-slot bug above.
        let unpinned = manifest_naming(&path, Some(sha));
        assert!(
            scan_view(&unpinned, &modules, &PinnedObjects::empty(), &own).is_none(),
            "a module with no pin has no hash to agree or disagree with"
        );

        // A manifest for something the target does not map at all.
        let elsewhere = manifest_naming("/opt/not-mapped.so", Some("33".repeat(32)));
        assert!(scan_view(&elsewhere, &modules, &pinned, &PinnedObjects::empty()).is_none());
    }

    #[test]
    fn scan_view_does_not_choose_the_first_byte_identical_ordinary_file() {
        let dir = tempfile::tempdir().unwrap();
        let first = dir.path().join("first.so");
        let intended = dir.path().join("intended.so");
        std::fs::copy("/bin/sh", &first).unwrap();
        std::fs::copy("/bin/sh", &intended).unwrap();
        let as_module = |path: &Path| {
            let file = p11scope_manifest::identity::open_object(path).unwrap();
            let key = p11scope_manifest::identity::mapping_file_key(&file).unwrap();
            ScannedModule {
                view: ProcessViewId(0),
                mount_namespace: current_mount_namespace(),
                key: ObjectKey {
                    device: p11scope_manifest::maps::Device {
                        major: key.device_major,
                        minor: key.device_minor,
                    },
                    inode: key.inode,
                },
                path: path.display().to_string(),
                exports: vec![],
                tables: vec![],
                interfaces: vec![],
            }
        };
        let modules = vec![as_module(&first), as_module(&intended)];
        let (pinned, skipped) = pin_scanned_objects(
            std::process::id(),
            &modules,
            &mut CaptureWorkBudget::default(),
        )
        .unwrap();
        assert!(skipped.is_empty(), "{skipped:?}");
        let intended_sha = pinned
            .pinned()
            .find(|pin| pin.key == modules[1].key)
            .unwrap()
            .sha256
            .to_string();
        let intended_path = intended.display().to_string();
        let manifest = manifest_naming(&intended_path, Some(intended_sha));
        let own = pin_as_manifest_object(&intended_path);

        let view = scan_view(&manifest, &modules, &pinned, &own).expect("mapped object");
        assert!(view.agrees);
        assert_eq!(
            view.modules[0].path, modules[1].path,
            "digest equality selected the first distinct ordinary file"
        );
    }

    #[test]
    fn byte_identical_distinct_entry_objects_conflict_and_attach_the_union() {
        use p11scope::discovery::scan::ScannedTable;
        use p11scope_manifest::manifest::{
            Acquisition, FunctionRecord, ObjectRecord, ProvenanceObject, SurfaceRecord,
            SurfaceSource, Version, WalkOutcome,
        };

        let dir = tempfile::tempdir().unwrap();
        let module_path = dir.path().join("module.so");
        let scanned_target_path = dir.path().join("scanned-target.so");
        let manifest_target_path = dir.path().join("manifest-target.so");
        for path in [&module_path, &scanned_target_path, &manifest_target_path] {
            std::fs::copy("/bin/sh", path).unwrap();
        }

        let opened = |path: &Path| {
            let file = p11scope_manifest::identity::open_object(path).unwrap();
            let mapping = p11scope_manifest::identity::mapping_file_key(&file).unwrap();
            let inspected = p11scope_manifest::identity::inspect_file(&file).unwrap();
            (mapping, inspected)
        };
        let (module_mapping, module_inspected) = opened(&module_path);
        let (scanned_mapping, scanned_inspected) = opened(&scanned_target_path);
        let (manifest_mapping, manifest_inspected) = opened(&manifest_target_path);
        assert_eq!(
            scanned_inspected.identity.sha256, manifest_inspected.identity.sha256,
            "the witness requires equal bytes"
        );
        assert_ne!(
            scanned_mapping.inode, manifest_mapping.inode,
            "the witness requires distinct opened objects"
        );
        let offset = scanned_inspected.executable_ranges[0].0;
        let key = |mapping: p11scope_manifest::identity::MappingFileKey| ObjectKey {
            device: p11scope_manifest::maps::Device {
                major: mapping.device_major,
                minor: mapping.device_minor,
            },
            inode: mapping.inode,
        };
        let module = ScannedModule {
            view: ProcessViewId(0),
            mount_namespace: current_mount_namespace(),
            key: key(module_mapping),
            path: module_path.display().to_string(),
            exports: vec!["C_GetFunctionList".into()],
            tables: vec![ScannedTable {
                version: (2, 40),
                walk: "full",
                entries: vec![ScannedEntry {
                    name: "C_Initialize",
                    object: key(scanned_mapping),
                    object_path: scanned_target_path.display().to_string(),
                    file_offset: offset,
                }],
                null_entries: vec![],
                unpinned: vec![],
                address: 0x7000,
            }],
            interfaces: vec![],
        };
        let mut budget = CaptureWorkBudget::new(ScanLimits {
            per_object_bytes: u64::MAX,
            total_bytes: u64::MAX,
        });
        let (mut scan_pins, skipped) = pin_scanned_objects(
            std::process::id(),
            std::slice::from_ref(&module),
            &mut budget,
        )
        .unwrap();
        assert!(skipped.is_empty(), "{skipped:?}");

        let object = |id, path: &Path, identity| ObjectRecord {
            id,
            path: path.display().to_string(),
            identity,
        };
        let provenance = |path: &Path,
                          mapping: p11scope_manifest::identity::MappingFileKey,
                          identity| ProvenanceObject {
            path: path.display().to_string(),
            device_major: mapping.device_major,
            device_minor: mapping.device_minor,
            inode: mapping.inode,
            identity,
        };
        let mut manifest = Manifest {
            schema: SCHEMA.into(),
            module_path: module_path.display().to_string(),
            objects: vec![
                object(0, &module_path, module_inspected.identity.clone()),
                object(
                    1,
                    &manifest_target_path,
                    manifest_inspected.identity.clone(),
                ),
            ],
            provenance_objects: vec![
                provenance(&module_path, module_mapping, module_inspected.identity),
                provenance(
                    &manifest_target_path,
                    manifest_mapping,
                    manifest_inspected.identity,
                ),
            ],
            interface_list: Acquisition::Absent,
            surfaces: vec![SurfaceRecord {
                source: SurfaceSource::LegacyFunctionList,
                acquisition: Acquisition::Ok,
                version: Some(Version {
                    major: 2,
                    minor: 40,
                }),
                walk: WalkOutcome::Full,
                functions: pkcs11_module::FUNCTION_LIST_FIELDS
                    .iter()
                    .map(|field| FunctionRecord {
                        name: field.name.into(),
                        resolution: Resolution::Resolved {
                            object: 1,
                            file_offset: offset,
                        },
                    })
                    .collect(),
            }],
            vendor_interfaces: vec![],
            alias_groups: vec![],
        };
        let manifest_pins = pin_manifest_objects(&manifest).unwrap();
        let view = scan_view(
            &manifest,
            std::slice::from_ref(&module),
            &scan_pins,
            &manifest_pins,
        )
        .expect("the module itself exact-matches");
        let scanned_targets = scanned_targets(&view.modules, &scan_pins).unwrap();
        let manifest_targets = manifest_targets(&manifest, &manifest_pins).unwrap();
        let outcome = corroborate(
            false,
            Some(view.agrees),
            scan_pins.exactly_same_targets(&scanned_targets, &manifest_pins, &manifest_targets),
            scanned_targets.is_empty(),
        );
        assert_eq!(
            outcome,
            Corroboration::Conflict,
            "equal digest/offset must not suppress a distinct opened target"
        );

        retarget_to_pins(&mut manifest, &view.modules, &scan_pins, &manifest_pins);
        assert!(scan_pins.absorb(manifest_pins).is_empty());
        let (modules, _, uncertainty) =
            reconcile_scanned_modules(std::slice::from_ref(&module), &mut scan_pins);
        assert!(uncertainty.is_empty(), "{uncertainty:?}");
        let plan = plan::build_from_sources(&modules, &[manifest], &scan_pins);
        assert_eq!(plan.slots.len(), 2, "both exact opened targets must attach");
        assert_eq!(
            plan.slots
                .iter()
                .map(|slot| slot.object)
                .collect::<BTreeSet<_>>()
                .len(),
            2,
            "the union must retain two distinct capture-local identities"
        );
        let mut counters = DiscoveryCounters {
            conflicts: 1,
            ..DiscoveryCounters::default()
        };
        counters
            .corroboration
            .push(([modules[0].object].into_iter().collect(), "conflict"));
        assert_eq!(
            discovery_evidence(&plan, &scan_pins, &counters).conflicts,
            1,
            "the conflict is the bounded evidence that forces PARTIAL"
        );
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

        let own = pin_as_manifest_object(&path);
        retarget_to_pins(&mut m, &[&modules[0]], &pinned, &own);
        assert_eq!(m.provenance_objects[0].inode, summary.key.inode);
        assert_eq!(
            m.provenance_objects[0].device_major,
            summary.key.device.major
        );

        // The same bytes pinned under an identity the scan did not see must not be
        // adopted: a decoy module the matched scan never named.
        let decoy = ScannedModule {
            view: ProcessViewId(0),
            mount_namespace: current_mount_namespace(),
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
        retarget_to_pins(&mut m, &[&decoy], &pinned, &own);
        assert_eq!(
            m.provenance_objects[0].inode, summary.key.inode,
            "no pin of the decoy exists, so the manifest's own exact pin is retained"
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
        // 1. Not mapped in scope: the manifest stands on its own.
        assert_eq!(
            corroborate(false, None, false, true),
            Corroboration::Uncorroborated
        );
        // 2. Mapped, same {object, offset} set: corroborated.
        assert_eq!(
            corroborate(false, Some(true), true, false),
            Corroboration::Agreed
        );
        // 3. Mapped, the sets differ: a conflict (the caller attaches the union).
        assert_eq!(
            corroborate(false, Some(true), false, false),
            Corroboration::Conflict
        );
        // 3b. Mapped and identity-matched, but the scan decoded no table at all:
        // the documented use of `--manifest`, not two sources contradicting each
        // other. Reported as uncorroborated, never as a disagreement.
        assert_eq!(
            corroborate(false, Some(true), false, true),
            Corroboration::ScanEmpty
        );
        // Two empty sets are not a scan-empty case: nothing was recorded either.
        assert_eq!(
            corroborate(false, Some(true), true, true),
            Corroboration::Agreed
        );
        // 4. Mapped, but the bytes are not the ones the manifest recorded.
        assert_eq!(
            corroborate(false, Some(false), true, false),
            Corroboration::IdentityMismatch
        );
        // A scan that could not read memory found no tables to disagree with, so it
        // never turns a usable manifest into a conflict or a mismatch.
        for identity in [None, Some(true), Some(false)] {
            assert_eq!(
                corroborate(true, identity, false, true),
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
