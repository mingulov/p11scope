//! SPDX-License-Identifier: GPL-3.0-or-later
//! Caller incarnations and the module/caller usage registry (inventory).
//!
//! The adapter turns OS process identity into inventory-grade caller
//! records: a stable capture-local caller ID per incarnation, where an
//! incarnation is one (pid, start-time) generation running one executable
//! image. Identity is pidfd-pinned with a `/proc` start-time fallback
//! (the `PidPin` authority); PID reuse and exec retire the old incarnation
//! and mint a new ID, so two incarnations never merge. Usage evidence is
//! retained after caller exit or module unload: retirement freezes counts,
//! it never deletes them.
//!
//! The registry keys edges by (caller incarnation, module instance) with
//! bounded cumulative entry counts (saturating, with an explicit flag),
//! first/last-seen timestamps on the capture clock, and per-endpoint
//! lifecycle. Mapping evidence and observed entries are separate columns:
//! a mapped-but-quiet caller is never reported as active. Mutations stage
//! behind a publication revision and become visible only at `publish`, so
//! inventory facts cross the same batch boundary as discovery facts.

pub(crate) mod instance_input;
pub(crate) mod module_init;

use instance_input::{
    AdmittedInstance, AdmittedInstanceCall, InstanceRetirement, InstanceSemanticLoss,
};

use crate::attach::capture::{DomainCookie, NativeDomainId};
use crate::discovery::native_binding::{BindingCensus, BoundImage, UnboundReason};
use crate::discovery::retained_member::RetainedGroupMember;
use crate::discovery::scan::CaptureWorkBudget;
use crate::discovery::sweep_attribution::{ReservationOwner, SegmentPolicy};
use crate::process::CustodyCharge;
use crate::process::{
    PidPin, generation_gone, process_is_kthread, process_is_zombie, process_start_time,
    process_stat_pair,
};
pub(crate) mod metadata;

use crate::semantics_edge::resources::{SemanticResourceRefusal, SemanticResourceReserver};
use crate::semantics_edge::{EdgeSemantics, SemanticCall};
use crate::semantics_objects::journal::ConsumptionOrdinal;
use crate::semantics_objects::journal::joint_audit::{DisposedJointQuantum, IngestedJointQuantum};
use crate::semantics_objects::journal::joint_driver::{
    JointCaptureOwner, RawJointQuantum, RawQuantumIdentity,
};
use anyhow::{Result, anyhow, bail};
use std::collections::{BTreeMap, BTreeSet, HashMap, HashSet};
use std::hash::BuildHasher as _;
use std::os::unix::fs::MetadataExt as _;
use std::sync::Arc;
use std::time::{Duration, Instant};

/// Capture-clock basis for every `*_ns` timestamp in the registry.
pub(crate) const CLOCK_BASIS: &str = "CLOCK_MONOTONIC";
/// Unit of every `*_ns` timestamp in the registry.
pub(crate) const CLOCK_UNIT: &str = "ns";

/// Current capture-clock reading. `None` from the clock (a failed
/// `clock_gettime`, effectively unreachable on Linux) reads as zero; the
/// coordinator records a gap when the clock is unavailable.
pub(crate) fn now_ns() -> u64 {
    crate::attach::monotonic_ns().unwrap_or(0)
}

/// Diagnostic-only settlement-latency toggle:
/// `P11SCOPE_DIAGNOSTIC_SETTLEMENT_LATENCY` set to exactly `1`
/// records the per-applied-call ENTRY-to-application delay in 1 ms
/// buckets and prints the cumulative p50/p99/max line beside the
/// stop line. Anything else, including unset, records nothing;
/// default paths are behavior-identical.
pub(crate) const DIAGNOSTIC_SETTLEMENT_LATENCY_ENV: &str = "P11SCOPE_DIAGNOSTIC_SETTLEMENT_LATENCY";

/// Pure predicate over the toggle value: only exactly `1` enables.
pub(crate) fn diagnostic_settlement_latency_by_env_value(value: Option<&std::ffi::OsStr>) -> bool {
    value.is_some_and(|value| value == "1")
}

pub(crate) fn diagnostic_settlement_latency_by_env() -> bool {
    diagnostic_settlement_latency_by_env_value(
        std::env::var_os(DIAGNOSTIC_SETTLEMENT_LATENCY_ENV).as_deref(),
    )
}

/// Stable capture-local caller ID. Minted monotonically per incarnation,
/// never reused — not after exit, exec, or PID reuse.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub(crate) struct CallerId(pub u32);

impl CallerId {
    /// Public label: `c0`, `c1`, … — stable for the capture.
    pub(crate) fn label(self) -> String {
        format!("c{}", self.0)
    }
}

/// Stable capture-local module ID. Minted monotonically per distinct
/// physical module instance, never reused.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub(crate) struct ModuleId(pub u32);

impl ModuleId {
    /// Public label: `m0`, `m1`, … — stable for the capture.
    pub(crate) fn label(self) -> String {
        format!("m{}", self.0)
    }
}

/// Executable image identity for exec detection within one pinned
/// generation: the device, inode, and mtime of `/proc/<pid>/exe`. This is
/// a change detector only — generation identity is the pin plus
/// start-time. A mismatch retires the incarnation (a conservative split),
/// never merges two images.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct ExeIdentity {
    pub dev: u64,
    pub ino: u64,
    pub mtime_secs: i64,
    pub mtime_nanos: i64,
    pub path: Option<String>,
}

/// One launcher-chain ancestor: one (pid, start-time) generation and its
/// executable basename. Chains run nearest first. The `label` hook stays
/// `None` in this lane; the app-identity lane fills interpreter labels
/// without touching capture. `exe_gap` carries the named reason when the
/// exe link could not be pinned to the statted generation (`None` exactly
/// when `exe` is `Some`).
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct LauncherAncestor {
    pub pid: u32,
    pub start_time: Option<u64>,
    pub exe: Option<String>,
    pub label: Option<String>,
    pub exe_gap: Option<&'static str>,
}

/// Why a launcher chain stops before a root: a named gap, never a guess.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct LauncherGap {
    pub subject: &'static str,
    pub reason: String,
}

/// Where a launcher chain came from: a real ancestor chain, an
/// init-type immediate parent (init, user manager, container init —
/// neither "launched by a service manager" nor "reparented" is claimed),
/// or a read gap.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum LauncherOrigin {
    Chain,
    InitParent,
    Gap,
}

impl LauncherOrigin {
    pub(crate) const fn label(self) -> &'static str {
        match self {
            Self::Chain => "chain",
            Self::InitParent => "init_parent",
            Self::Gap => "gap",
        }
    }
}

/// One captured launcher chain: the raw ancestors (never init, the user
/// manager, a container init or a proven-reused generation), the stop
/// gap, and the origin/unit pair.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct CapturedLauncherChain {
    pub ancestors: Vec<LauncherAncestor>,
    pub gap: Option<LauncherGap>,
    pub origin: LauncherOrigin,
    pub unit: Option<String>,
}

/// How many ancestors the walk keeps (nearest first).
pub(crate) const LAUNCHER_CHAIN_DEPTH: usize = 4;
/// Gap subject for every launcher-chain stop.
pub(crate) const LAUNCHER_GAP_SUBJECT: &str = "caller parent chain";
/// The parent exited before the ancestor read, or the live generation is
/// provably not the original parent (it started after its child).
pub(crate) const LAUNCHER_GAP_EXITED: &str = "launcher exited before read";
/// A stat-readable ancestor's exe link could not be read (no ptrace read
/// access, or the generation turned over under the read).
pub(crate) const LAUNCHER_GAP_EXE_UNREADABLE: &str = "launcher exe unreadable";
/// The parent's `/proc` entry was unreadable though it looks alive.
pub(crate) const LAUNCHER_GAP_HIDEPID: &str = "launcher hidden by /proc hidepid";
/// The walk kept [`LAUNCHER_CHAIN_DEPTH`] ancestors with more above.
pub(crate) const LAUNCHER_GAP_TRUNCATED: &str = "parent chain truncated after 4 ancestors";
/// Cgroup-transaction commits sample no parentage (zero post-sample reads).
pub(crate) const LAUNCHER_GAP_CGROUP_DEFERRED: &str =
    "parent chain not sampled in cgroup transaction";

/// Which authority backs a caller incarnation's image reference.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum ImageAuthority {
    /// Opaque expected native image (the native lifecycle adapter),
    /// installed only after a successful guarded owner opening.
    NativeExact { image: BoundImage },
    /// pidfd/start-time pin with exe-identity exec detection. Exact for
    /// lifetime (reuse-proof); exec detection is a best-effort change
    /// detector, and any uncertainty retires rather than merges.
    ScanPinned,
}

impl ImageAuthority {
    pub(crate) const fn label(self) -> &'static str {
        match self {
            Self::NativeExact { .. } => "native_exact",
            Self::ScanPinned => "scan_pinned",
        }
    }
}

/// Lifecycle of one caller incarnation.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum CallerLifecycle {
    Mapped,
    Exited,
    ExecRetired,
    Unknown,
}

impl CallerLifecycle {
    pub(crate) const fn label(self) -> &'static str {
        match self {
            Self::Mapped => "mapped",
            Self::Exited => "exited",
            Self::ExecRetired => "exec_retired",
            Self::Unknown => "unknown",
        }
    }
}

/// One caller incarnation: one (pid, start-time) generation running one
/// image. Retired incarnations are retained with frozen evidence.
#[derive(Debug, Clone)]
pub(crate) struct CallerRecord {
    pub id: CallerId,
    pub pid: u32,
    /// `/proc` start-time in clock ticks since boot (`None` when the pin
    /// is pidfd-only and `/proc` was unreadable at admission).
    pub start_time: Option<u64>,
    /// Zero-based incarnation index for this pid (admission order).
    pub incarnation: u32,
    pub exe: Option<ExeIdentity>,
    /// Display-only app hint (interpreter script/unit/snap label), sampled
    /// at admission. Never identity, admission, or join input.
    pub app_hint: Option<crate::app_hint::AppHint>,
    /// The launcher chain (nearest first), captured at admission; frozen
    /// evidence like the exe identity above.
    pub launched_by: Vec<LauncherAncestor>,
    /// Why the chain stops before a root, if it does.
    pub launcher_gap: Option<LauncherGap>,
    /// Where the chain came from (real ancestors, an init-type parent,
    /// or a read gap).
    pub launched_by_origin: LauncherOrigin,
    /// The caller's systemd unit/scope, set only for `InitParent`.
    pub launched_by_unit: Option<String>,
    /// False when the exe identity was unreadable at admission: exec
    /// changes are then undetectable and the record says so.
    pub exec_observed: bool,
    pub authority: ImageAuthority,
    pub lifecycle: CallerLifecycle,
    pub lifecycle_reason: Option<String>,
    pub first_seen_ns: u64,
    /// When the incarnation was admitted, on the observer's
    /// `CLOCK_MONOTONIC`: the boundary stale native records order
    /// against. The scan path admits after its collection, so this is
    /// the admission detection time, never the pass-start `now` that
    /// `first_seen_ns` keeps for scan-window comparisons.
    pub admitted_ns: u64,
    pub last_seen_ns: u64,
    pub retired: bool,
}

/// OS process access behind the adapter. Production reads pidfds and
/// `/proc`; scripted sources pin the exit/reuse/exec sequences in tests.
pub(crate) trait ProcessSource {
    type Pin;
    fn open(&mut self, pid: u32) -> Result<Self::Pin, String>;
    fn still_the_same(&self, pin: &Self::Pin) -> bool;
    fn start_time(&self, pid: u32) -> Option<u64>;
    fn exe_identity(&self, pid: u32) -> Option<ExeIdentity>;
    /// The maps-domain exe identity of `pid`, for joining EXEC
    /// records (never a bare PID). The default reads the live
    /// process; scripted sources program their own split.
    fn exe_maps_identity(&self, pid: u32) -> Option<ExeIdentity> {
        read_exe_maps_identity(pid)
    }
    /// Display-only app hint beside the already-read `exe`, for the
    /// `admitted_start_time` generation only: sampled facts belong to
    /// that generation or the hint is dropped. The default samples
    /// nothing: scripted sources gain no process authority here.
    fn app_hint(
        &self,
        _pid: u32,
        _exe: Option<&ExeIdentity>,
        _admitted_start_time: Option<u64>,
    ) -> Option<crate::app_hint::AppHint> {
        None
    }
    /// ppid (stat field 4) of `pid`, or `None` when unknown. The default
    /// knows no parentage; production and scripted sources override it.
    fn parent_pid(&self, _pid: u32) -> Option<u32> {
        None
    }
    /// `(start_time, ppid)` for `pid`. Production reads ONE stat line so
    /// reuse between two reads cannot mix generations; the default
    /// composes the two separate reads.
    fn stat_pair(&self, pid: u32) -> (Option<u64>, Option<u32>) {
        (self.start_time(pid), self.parent_pid(pid))
    }
    /// Basename of `pid`'s `/proc/<pid>/exe` link, or `None` when
    /// unreadable. The default derives it from [`exe_identity`].
    fn ancestor_exe(&self, pid: u32) -> Option<String> {
        self.exe_identity(pid)
            .and_then(|exe| exe.path)
            .map(|path| exe_basename(&path))
    }
    /// Raw `/proc/<pid>/cgroup` text, or `None` when unreadable. The
    /// default knows no cgroup; production reads the file and scripted
    /// sources replay fixture contents.
    fn cgroup_text(&self, _pid: u32) -> Option<String> {
        None
    }
    /// Parsed `NSpid` values (outermost first) of `pid`'s
    /// `/proc/<pid>/status`, or `None` when unreadable or unparsable.
    /// The walk derives container-init and pid-namespace-boundary
    /// classification from this single read. The default knows none.
    fn status_nspid(&self, _pid: u32) -> Option<Vec<u32>> {
        None
    }
    /// True when `pid` is a kernel thread (`PF_KTHREAD` in its stat
    /// flags): no exe link can exist, so it bounds the walk like init.
    /// The default never claims it.
    fn is_kthread(&self, _pid: u32) -> bool {
        false
    }
    /// True when the mounted `/proc` hides processes (`hidepid` in its
    /// mount options): an unreadable entry is then hidden-alive until
    /// proven otherwise, never presumed exited.
    fn proc_hidepid(&self) -> bool {
        false
    }
    /// True when `pid` names no live process: reaped, never existed, or
    /// a zombie awaiting its parent's `wait`. Zombies count as gone —
    /// the generation is dead even though `/proc` still parses — so a
    /// dead-but-unreaped target retires instead of re-admitting.
    fn gone(&self, pid: u32) -> bool;
    /// A leader-exit hook plus a held process pin is not proof of a live
    /// worker. Sources without fresh original-custody task evidence defer.
    fn leader_exit_observation(
        &self,
        _pin: &Self::Pin,
        _work: &mut crate::process::leader_exit::LeaderExitReadBudget,
    ) -> crate::process::leader_exit::LeaderExitObservation {
        crate::process::leader_exit::LeaderExitObservation::Unresolved
    }
    /// Cold-admit an already-zombie leader: when `pin` names a zombie
    /// thread group with exactly one live survivor, mint the survivor
    /// from this same pin and return its exe identity for the record.
    /// `Ok(None)` means "not a cold-admittable zombie" (the ordinary
    /// gone refusal applies); `Err` is a NAMED refusal (ambiguity —
    /// never a pick — or a raced proof, which stays silent about
    /// whether the group is dead). The default never cold-admits:
    /// scripted sources gain no process authority from this hook.
    fn cold_zombie_exe(&self, _pin: &Arc<Self::Pin>) -> Result<Option<ExeIdentity>, String> {
        Ok(None)
    }
    /// Share original custody only when the source can prove its concrete type.
    /// Scripted sources do not gain process authority from an Arc wrapper.
    fn shared_semantic_custody(&self, _pin: &Arc<Self::Pin>) -> Option<Arc<PidPin>> {
        None
    }
    fn install_shared_custody_charge(&self, _pin: &mut Self::Pin, _charge: &Arc<CustodyCharge>) {}
    /// Inspect held process custody without duplicating its pidfd. A known
    /// Detailed Arc can be reused after this check without a pidfd duplicate.
    fn semantic_custody_ref<'pin>(&self, _pin: &'pin Self::Pin) -> Option<&'pin PidPin> {
        None
    }
}

/// The maps-domain exe identity of `pid`: the `/proc/<pid>/exe`
/// link text plus the link's own mapped `(dev, ino)` — the probe
/// opens `/proc/<pid>/exe` itself, never the readlink target, so a
/// path swapped in under a user-writable dir can neither redirect
/// the probe nor hang the root observer on a FIFO. `None` when
/// unreadable or unmappable. This is the device domain the kernel's
/// EXEC pair lives in; the stat-domain [`read_exe_identity`] feeds
/// the caller adapter and the C1b confirmation read instead, so the
/// two compare like for like there and this one compares like for
/// like with EXEC records here. Only the link and the executable's
/// metadata are read — no cwd, cmdline, or environ.
pub(crate) fn read_exe_maps_identity_with(
    pid: u32,
    maps: impl Fn(&str) -> Option<(u64, u64)>,
) -> Option<ExeIdentity> {
    let proc_exe = format!("/proc/{pid}/exe");
    let link = std::fs::read_link(&proc_exe).ok()?;
    let link_text = link.to_string_lossy().into_owned();
    let metadata = std::fs::metadata(&proc_exe).ok()?;
    let (dev, ino) = maps(&proc_exe)?;
    Some(ExeIdentity {
        dev,
        ino,
        mtime_secs: metadata.mtime(),
        mtime_nanos: metadata.mtime_nsec(),
        path: Some(link_text),
    })
}

/// The maps-domain exe identity of `pid` through the real mapping
/// probe, opening `/proc/<pid>/exe` itself.
pub(crate) fn read_exe_maps_identity(pid: u32) -> Option<ExeIdentity> {
    read_exe_maps_identity_with(
        pid,
        crate::discovery::unbound_exe::real_maps_identity_proc_exe_link,
    )
}

/// The exe identity of `pid` (`/proc/<pid>/exe` metadata plus its link
/// text), or `None` when unreadable. One reader for the caller adapter and
/// the C1b confirmation read, so the two compare like for like.
pub(crate) fn read_exe_identity(pid: u32) -> Option<ExeIdentity> {
    let path = format!("/proc/{pid}/exe");
    let metadata = std::fs::metadata(&path).ok()?;
    let link = std::fs::read_link(&path)
        .ok()
        .map(|path| path.to_string_lossy().into_owned());
    exe_identity_from_followed_metadata(&metadata, link)
}

/// Build the exe identity from already-followed `/proc/<pid>/exe`
/// metadata: `None` unless the metadata is a regular file. A magic
/// link that refused the follow must never become an exe identity —
/// its link inode is stable per pid, so it would compare equal
/// across execs and falsely claim an observed image.
fn exe_identity_from_followed_metadata(
    metadata: &std::fs::Metadata,
    link: Option<String>,
) -> Option<ExeIdentity> {
    // A magic link that refused the follow returns the link itself
    // (a symlink on the procfs device): never an exe identity.
    if !metadata.is_file() {
        return None;
    }
    Some(ExeIdentity {
        dev: metadata.dev(),
        ino: metadata.ino(),
        mtime_secs: metadata.mtime(),
        mtime_nanos: metadata.mtime_nsec(),
        path: link,
    })
}

/// Last path segment of an exe link, verbatim (a ` (deleted)` marker
/// survives as part of the name, as in presentation labels).
pub(crate) fn exe_basename(path: &str) -> String {
    path.rsplit('/').next().unwrap_or(path).to_string()
}

/// The gap for an ancestor whose stat line would not parse. Under a
/// `hidepid` `/proc` an unreadable entry is hidden-alive until proven
/// otherwise (its `ENOENT` is indistinguishable from an exit), so the
/// mount evidence overrides the gone proof; otherwise exited when the
/// generation is provably gone, hidden when it looks alive. Never a guess.
fn launcher_read_gap<Source: ProcessSource>(source: &Source, pid: u32) -> LauncherGap {
    let reason = if !source.proc_hidepid() && source.gone(pid) {
        LAUNCHER_GAP_EXITED
    } else {
        LAUNCHER_GAP_HIDEPID
    };
    LauncherGap {
        subject: LAUNCHER_GAP_SUBJECT,
        reason: reason.into(),
    }
}

/// Raw `/proc/<pid>/cgroup` text, or `None` when unreadable.
pub(crate) fn read_cgroup_text(pid: u32) -> Option<String> {
    std::fs::read_to_string(format!("/proc/{pid}/cgroup")).ok()
}

/// True when a `/proc/self/mountinfo` text mounts a procfs at `/proc`
/// with `hidepid` hiding processes: any `hidepid=` value but `0`/`off`.
/// Anything else (no procfs at `/proc`, malformed rows) answers false:
/// hidepid is claimed only on positive mount evidence. The last
/// matching row wins (a later mount shadows an earlier one).
pub(crate) fn proc_mount_hidepid_on(mountinfo: &str) -> bool {
    let mut hidden = false;
    for line in mountinfo.lines() {
        let fields: Vec<&str> = line.split_ascii_whitespace().collect();
        if fields.get(4) != Some(&"/proc") {
            continue;
        }
        let Some(separator) = fields.iter().position(|field| *field == "-") else {
            continue;
        };
        let after = &fields[separator + 1..];
        if after.len() != 3 || after[0] != "proc" {
            continue;
        }
        hidden = after[2].split(',').any(|option| {
            option
                .strip_prefix("hidepid=")
                .is_some_and(|value| !value.is_empty() && value != "0" && value != "off")
        });
    }
    hidden
}

/// Collapse runs of adjacent identical launcher wrappers (same exe and
/// label, with at least one name present) for `-v`/JSON: each run keeps
/// its nearest link with the count of additional folded ancestors (`0`
/// when nothing folded). Records keep the raw chain; both emitters share
/// this helper so they cannot drift.
pub(crate) fn collapse_launcher_chain(chain: &[LauncherAncestor]) -> Vec<(LauncherAncestor, u32)> {
    let mut collapsed: Vec<(LauncherAncestor, u32)> = Vec::with_capacity(chain.len());
    for ancestor in chain {
        let named = ancestor.exe.is_some() || ancestor.label.is_some();
        if named
            && let Some((last, folded)) = collapsed.last_mut()
            && last.exe == ancestor.exe
            && last.label == ancestor.label
        {
            *folded += 1;
            continue;
        }
        collapsed.push((ancestor.clone(), 0));
    }
    collapsed
}

/// Capture one caller incarnation's launcher chain: up to
/// [`LAUNCHER_CHAIN_DEPTH`] raw ancestors, nearest first, each as a
/// (pid, start-time) generation with its exe basename. Init (pid 1 of
/// the scope's pid namespace), the systemd user manager, container
/// inits, pid-namespace boundaries and kernel threads are never
/// recorded: an init-type immediate parent yields `InitParent` with the
/// caller's systemd unit (or nothing), while an init-type ancestor
/// above real links just ends the walk. A caller that is itself a
/// container init is an `InitParent` too: its observer-visible parent
/// did not launch it. A parent younger than its child cannot be the
/// original parent (pid reuse), so the walk stops there with the exited
/// gap. Stops cleanly (no gap) at ppid 0 (no parent in this pid
/// namespace); any other stop keeps the ancestors read so far plus a
/// named gap. Never fails, never guesses, and never touches argv,
/// environ or comm.
pub(crate) fn capture_launcher_chain<Source: ProcessSource>(
    source: &Source,
    caller_pid: u32,
    caller_start_time: Option<u64>,
    caller_ppid: Option<u32>,
) -> CapturedLauncherChain {
    let gap = |reason: &str| LauncherGap {
        subject: LAUNCHER_GAP_SUBJECT,
        reason: reason.into(),
    };
    // The caller's unit, read only when an init-type parent needs it.
    let caller_unit = || {
        source
            .cgroup_text(caller_pid)
            .and_then(|cgroup| crate::caller_metadata::systemd_unit_from_cgroup_text(&cgroup))
    };
    let init_parent = || CapturedLauncherChain {
        ancestors: Vec::new(),
        gap: None,
        origin: LauncherOrigin::InitParent,
        unit: caller_unit(),
    };
    let partial_origin = |ancestors: &[LauncherAncestor]| {
        if ancestors.is_empty() {
            LauncherOrigin::Gap
        } else {
            LauncherOrigin::Chain
        }
    };
    // A boundary above real ancestors ends the walk; the chain stands
    // on its own with no gap and no unit.
    let plain_stop = |ancestors| CapturedLauncherChain {
        ancestors,
        gap: None,
        origin: LauncherOrigin::Chain,
        unit: None,
    };
    let Some(mut ppid) = caller_ppid else {
        return CapturedLauncherChain {
            ancestors: Vec::new(),
            gap: Some(launcher_read_gap(source, caller_pid)),
            origin: LauncherOrigin::Gap,
            unit: None,
        };
    };
    if ppid == 0 {
        // No parent in this pid namespace: a boundary like init, never
        // an empty chain.
        return init_parent();
    }
    if ppid == 1 {
        return init_parent();
    }
    // A caller that is itself a container init sits behind a
    // pid-namespace boundary by definition: its observer-visible
    // parent (a shim or host process) did not launch it.
    let caller_nspid = source.status_nspid(caller_pid);
    if caller_nspid
        .as_deref()
        .is_some_and(crate::pidns::nspid_is_container_init)
    {
        return init_parent();
    }
    let mut ancestors = Vec::new();
    let mut child_start_time = caller_start_time;
    let mut child_nspid_len = caller_nspid.map(|nspid| nspid.len());
    loop {
        if ppid == 0 {
            return plain_stop(ancestors);
        }
        if ppid == 1 {
            return plain_stop(ancestors);
        }
        let (start_time, grand) = source.stat_pair(ppid);
        let (Some(start_time), Some(grand)) = (start_time, grand) else {
            return CapturedLauncherChain {
                gap: Some(launcher_read_gap(source, ppid)),
                origin: partial_origin(&ancestors),
                unit: None,
                ancestors,
            };
        };
        // A parent younger than its child cannot be the original parent:
        // the pid was recycled after the child started.
        if child_start_time.is_some_and(|child| start_time > child) {
            let origin = partial_origin(&ancestors);
            return CapturedLauncherChain {
                ancestors,
                gap: Some(gap(LAUNCHER_GAP_EXITED)),
                origin,
                unit: None,
            };
        }
        // User-manager, container-init and pid-namespace-boundary links
        // are never shown; an immediate one reports init_parent with
        // the caller's unit, while one above real links just ends the
        // walk. A parent with fewer NSpid levels than its child lives
        // outside the child's pid namespace (a shim or host parent
        // above a container process). One status read classifies both
        // NSpid shapes. An unreadable cgroup or status fails open to
        // an ordinary ancestor: stat already proved the generation,
        // and the boundary processes are long-lived, so a
        // classification race is negligible. Same-namespace child
        // subreapers expose no `/proc` flag and stay visible links: a
        // documented known limit, never a silent rename.
        let parent_nspid = source.status_nspid(ppid);
        let is_user_manager = source
            .cgroup_text(ppid)
            .is_some_and(|cgroup| crate::caller_metadata::is_user_manager_cgroup_text(&cgroup));
        let crosses_namespace = match (child_nspid_len, parent_nspid.as_ref().map(Vec::len)) {
            (Some(child), Some(parent)) => parent < child,
            _ => false,
        };
        if is_user_manager
            || parent_nspid
                .as_deref()
                .is_some_and(crate::pidns::nspid_is_container_init)
            || crosses_namespace
        {
            if ancestors.is_empty() {
                return init_parent();
            }
            return plain_stop(ancestors);
        }
        // The fifth link was statted, start-time checked and classified
        // as a real ancestor above: more above is read evidence, not a
        // guess, so keeping four truncates with the named gap.
        // Boundaries stop before this check, so they never truncate.
        if ancestors.len() >= LAUNCHER_CHAIN_DEPTH {
            return CapturedLauncherChain {
                ancestors,
                gap: Some(gap(LAUNCHER_GAP_TRUNCATED)),
                origin: LauncherOrigin::Chain,
                unit: None,
            };
        }
        // Pin the exe to the statted generation: a recycle between the
        // stat and the readlink must not attach the new image's name.
        // A proved recycle names the exit; so does a dead generation.
        // A live generation with no exe link at all is a kernel thread
        // (no user address space, hence no link): a boundary, never a
        // recorded link. Anything else is unreadable (no ptrace read
        // access). The walk continues from the statted parent.
        let exe = source.ancestor_exe(ppid);
        let (recheck, _) = source.stat_pair(ppid);
        let (exe, exe_gap) = match (exe, recheck) {
            (Some(name), Some(again)) if again == start_time => (Some(name), None),
            (_, Some(again)) if again != start_time => (None, Some(LAUNCHER_GAP_EXITED)),
            _ if source.gone(ppid) => (None, Some(LAUNCHER_GAP_EXITED)),
            (None, _) if source.is_kthread(ppid) => {
                if ancestors.is_empty() {
                    return init_parent();
                }
                return plain_stop(ancestors);
            }
            _ => (None, Some(LAUNCHER_GAP_EXE_UNREADABLE)),
        };
        ancestors.push(LauncherAncestor {
            pid: ppid,
            start_time: Some(start_time),
            exe,
            label: None,
            exe_gap,
        });
        if grand == 0 {
            return plain_stop(ancestors);
        }
        child_start_time = Some(start_time);
        child_nspid_len = parent_nspid.map(|nspid| nspid.len());
        ppid = grand;
    }
}

/// Production source: `PidPin` identity, `/proc` start-time and exe.
pub(crate) struct OsProcessSource;

impl ProcessSource for OsProcessSource {
    type Pin = PidPin;

    fn open(&mut self, pid: u32) -> Result<PidPin, String> {
        PidPin::open(pid)
    }

    fn still_the_same(&self, pin: &PidPin) -> bool {
        pin.still_the_same()
    }

    fn start_time(&self, pid: u32) -> Option<u64> {
        process_start_time(pid).ok()
    }

    fn stat_pair(&self, pid: u32) -> (Option<u64>, Option<u32>) {
        process_stat_pair(pid)
    }

    fn exe_identity(&self, pid: u32) -> Option<ExeIdentity> {
        read_exe_identity(pid)
    }

    fn app_hint(
        &self,
        pid: u32,
        exe: Option<&ExeIdentity>,
        admitted_start_time: Option<u64>,
    ) -> Option<crate::app_hint::AppHint> {
        crate::app_hint::sample_for_pid(pid, exe, admitted_start_time)
    }

    fn cgroup_text(&self, pid: u32) -> Option<String> {
        read_cgroup_text(pid)
    }

    fn status_nspid(&self, pid: u32) -> Option<Vec<u32>> {
        std::fs::read_to_string(format!("/proc/{pid}/status"))
            .ok()
            .and_then(|status| crate::pidns::parse_nspid(&status))
    }

    fn is_kthread(&self, pid: u32) -> bool {
        process_is_kthread(pid)
    }

    fn proc_hidepid(&self) -> bool {
        std::fs::read_to_string("/proc/self/mountinfo")
            .is_ok_and(|mountinfo| proc_mount_hidepid_on(&mountinfo))
    }

    fn gone(&self, pid: u32) -> bool {
        generation_gone(pid) || process_is_zombie(pid)
    }

    fn leader_exit_observation(
        &self,
        pin: &PidPin,
        work: &mut crate::process::leader_exit::LeaderExitReadBudget,
    ) -> crate::process::leader_exit::LeaderExitObservation {
        pin.leader_exit_observation(work)
    }

    fn cold_zombie_exe(&self, pin: &Arc<PidPin>) -> Result<Option<ExeIdentity>, String> {
        if !process_is_zombie(pin.pid()) {
            return Ok(None);
        }
        // A scratch budget bounds the mint's own charges; the mint is a
        // handful of local reads, never pass work.
        let mut work = CaptureWorkBudget::default();
        match cold_admit_member(pin, &mut work) {
            Ok(minted) => {
                let exe = minted.member.read_exe_identity();
                drop(minted);
                // A member whose exe is unreadable proves nothing: fail
                // closed to the ordinary gone refusal.
                Ok(exe)
            }
            Err(ColdRefusal::Ambiguous(reason)) => Err(reason),
            Err(ColdRefusal::Dead) => Ok(None),
            // A raced proof stays silent about whether the group is
            // dead, so it keeps its own reason instead of the generic
            // gone refusal (which would falsely claim an exit).
            Err(ColdRefusal::Raced) => {
                Err("admission raced a thread change; retries on the next observation".to_string())
            }
        }
    }

    fn shared_semantic_custody(&self, pin: &Arc<PidPin>) -> Option<Arc<PidPin>> {
        Some(Arc::clone(pin))
    }

    fn install_shared_custody_charge(&self, pin: &mut PidPin, charge: &Arc<CustodyCharge>) {
        pin.install_shared_custody_charge(Arc::clone(charge));
    }

    fn semantic_custody_ref<'pin>(&self, pin: &'pin PidPin) -> Option<&'pin PidPin> {
        Some(pin)
    }
}

/// A cold-minted survivor: the retained member plus the minter Arc that
/// keeps its borrow alive. The minter clones the admission pin's own
/// Arc — never a fresh numeric-PID reopen — so the original custody
/// stays authoritative across the handoff.
pub(crate) struct ColdMint {
    pub member: RetainedGroupMember,
    pub minter: Arc<PidPin>,
}

/// Why a cold mint refused: the group has no live survivor (the
/// ordinary gone path), the survivors are ambiguous (a NAMED refusal —
/// never a pick), or the proof raced and stayed unproven (fail closed
/// like a gone process, like the sweep mint's silent custody refusal).
#[derive(Debug)]
pub(crate) enum ColdRefusal {
    Dead,
    Ambiguous(String),
    Raced,
}

/// The private reservation owner for one cold mint: exactly the member
/// envelope (two retained slots — the member directory plus the dup'd
/// original pidfd — and one transient unit), mirroring the sweep
/// confirm's member owner. Private to the mint, invisible to any
/// shared census; its leases return when the mint drops.
pub(crate) fn cold_member_owner() -> ReservationOwner {
    ReservationOwner::new(SegmentPolicy {
        headroom: 7,
        workers: 1,
        retained: 2,
        max_ranges: 0,
    })
}

/// The local-syscall grace for a cold mint: a handful of nonblocking
/// reads, capped by the work budget's own deadline when it has one.
/// Mirrors the sweep confirm's mint deadline; expiry fails closed.
fn cold_mint_deadline(work: &CaptureWorkBudget) -> Instant {
    const GRACE: Duration = Duration::from_secs(1);
    let grace = Instant::now() + GRACE;
    let capped = work.effective_deadline_ns().and_then(|limit| {
        let clock = crate::attach::monotonic_ns()?;
        let left = limit.checked_sub(clock)?;
        Instant::now().checked_add(Duration::from_nanos(left))
    });
    capped.map(|deadline| deadline.min(grace)).unwrap_or(grace)
}

/// Live non-leader task IDs of `tgid`, sorted. `ColdRefusal::Dead`
/// when the listing itself fails (the group is gone or unreadable).
fn live_survivor_tids(tgid: u32) -> Result<Vec<u32>, ColdRefusal> {
    let mut tids: Vec<u32> = std::fs::read_dir(format!("/proc/{tgid}/task"))
        .map_err(|_| ColdRefusal::Dead)?
        .map(|entry| {
            entry
                .map_err(|_| ColdRefusal::Dead)?
                .file_name()
                .to_string_lossy()
                .parse::<u32>()
                .map_err(|_| ColdRefusal::Dead)
        })
        .collect::<Result<_, _>>()?;
    tids.retain(|tid| *tid != tgid);
    tids.sort();
    Ok(tids)
}

/// Mint the lone survivor of an already-zombie leader from the held
/// original: the TGID's own task listing selects exactly one non-leader
/// candidate, then the retained-member proof (tgkill liveness, group
/// anchor, birth brackets) admits it, then a post-mint task re-list
/// refuses by the ambiguity name when the live set grew or changed,
/// and the original pidfd re-proves the group alive before the mint
/// lands (a group dead under a passing re-list refuses raced).
/// No numeric-PID reopen anywhere: the listings and the mint all
/// derive from `original`, whose pidfd stays non-ready while threads
/// live. A bare TID never selects here — its own task listing holds no
/// non-leader entry — and no parentage is consulted.
pub(crate) fn cold_admit_member(
    original: &Arc<PidPin>,
    work: &mut CaptureWorkBudget,
) -> Result<ColdMint, ColdRefusal> {
    cold_admit_member_with_relist(original, work, &mut |tgid| live_survivor_tids(tgid))
}

/// `cold_admit_member` with the post-mint task re-list injected:
/// production passes the live listing; tests script the second
/// listing so a survivor appearing between the two lists is
/// deterministic, never timing.
pub(crate) fn cold_admit_member_with_relist(
    original: &Arc<PidPin>,
    work: &mut CaptureWorkBudget,
    relist: &mut impl FnMut(u32) -> Result<Vec<u32>, ColdRefusal>,
) -> Result<ColdMint, ColdRefusal> {
    let tgid = original.pid();
    work.spend(1).map_err(|_| ColdRefusal::Raced)?;
    let mut lone = None;
    let mut extra = false;
    let entries = std::fs::read_dir(format!("/proc/{tgid}/task")).map_err(|_| ColdRefusal::Dead)?;
    for entry in entries {
        let tid: u32 = entry
            .map_err(|_| ColdRefusal::Dead)?
            .file_name()
            .to_string_lossy()
            .parse()
            .map_err(|_| ColdRefusal::Dead)?;
        if tid == tgid {
            continue;
        }
        if lone.is_some() {
            extra = true;
            break;
        }
        lone = Some(tid);
    }
    if extra {
        return Err(ColdRefusal::Ambiguous(format!(
            "thread group {tgid} has more than one live survivor (ambiguous; refusing to pick one)"
        )));
    }
    let Some(tid) = lone else {
        return Err(ColdRefusal::Dead);
    };
    let owner = cold_member_owner();
    let deadline = cold_mint_deadline(work);
    let member = match RetainedGroupMember::acquire(original, tid, &owner, work, deadline) {
        Ok(member) => member,
        // A raced or refused proof carries no admission signal: fail
        // closed to the ordinary gone refusal.
        Err(_) => return Err(ColdRefusal::Raced),
    };
    // Post-mint re-list: the exactly-one decision above trusted one
    // `read_dir` pass, but getdents skips entries under concurrent
    // modification, so a survivor born (or missed) during the first
    // listing would admit a two-survivor group. Refuse by the existing
    // ambiguity name when the live set grew or changed; an empty
    // re-list is an ordinary dead group, and an unreadable one is a
    // raced proof (the mint just proved a survivor). The refused
    // member drops here, releasing its mint slot with the refusal.
    work.spend(1).map_err(|_| ColdRefusal::Raced)?;
    let mut fresh = relist(tgid).map_err(|_| ColdRefusal::Raced)?;
    fresh.sort();
    if fresh.is_empty() {
        return Err(ColdRefusal::Dead);
    }
    if fresh != [tid] {
        return Err(ColdRefusal::Ambiguous(format!(
            "thread group {tgid} has more than one live survivor (ambiguous; refusing to pick one)"
        )));
    }
    // The re-list passed, but the listing may be stale: an original
    // whose pidfd no longer reports the group alive means the group
    // died under the listing, so refuse raced instead of admitting a
    // dead group. pidfd readiness never flips back, so this closes the
    // gap; the refused member drops here with its mint slot.
    if !original.still_the_same() {
        return Err(ColdRefusal::Raced);
    }
    Ok(ColdMint {
        member,
        minter: Arc::clone(original),
    })
}

/// What one `reconcile` concluded about a caller.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum CallerEvent {
    Admitted {
        id: CallerId,
    },
    Exited {
        id: CallerId,
        reason: String,
    },
    /// The old incarnation ended; no successor was authorized.
    Retired {
        id: CallerId,
        reason: String,
    },
    ExecRetired {
        old: CallerId,
        new: CallerId,
    },
    Reused {
        old: CallerId,
        new: CallerId,
    },
    AdmitFailed {
        pid: u32,
        reason: String,
        /// `Some` exactly when admission refused on the caller budget.
        budget: Option<BudgetRefusal>,
    },
}

#[derive(Clone, Copy)]
enum SuccessorAdmission {
    Unrestricted,
    ScopedDenied,
}

/// Lifecycle reason for a natively proven exec retirement: the later image
/// of the same task was witnessed (its exec sequence advanced under its
/// task cookie, or its leader task changed under the held pidfd).
const NATIVE_EXEC_REASON: &str = "a later image of the same task was witnessed natively (its exec \
     sequence advanced under its task cookie, or its leader task changed under the held pidfd)";

/// Moves original custody and its accounting together through every handoff.
/// The OS pin embeds the same peer for bare H0/history Arc holders. Drop the
/// pin first, then its peer; neither source identity nor charge is retagged.
pub(crate) struct SharedCallerPin<Pin> {
    pin: Arc<Pin>,
    charge: Arc<CustodyCharge>,
}

impl<Pin> std::ops::Deref for SharedCallerPin<Pin> {
    type Target = Pin;
    fn deref(&self) -> &Pin {
        &self.pin
    }
}

impl<Pin> SharedCallerPin<Pin> {
    fn new<Source: ProcessSource<Pin = Pin>>(
        mut pin: Pin,
        source: &Source,
        reserve: &SemanticResourceReserver,
    ) -> Result<Self, SemanticResourceRefusal> {
        // Cover inline tracked/prepared overlap as well as both heap Arcs.
        let charge = CustodyCharge::reserve::<Pin>(reserve, 2 * std::mem::size_of::<Self>())?;
        source.install_shared_custody_charge(&mut pin, &charge);
        Ok(Self {
            pin: Arc::new(pin),
            charge,
        })
    }

    fn share(&self) -> Self {
        Self {
            pin: Arc::clone(&self.pin),
            charge: Arc::clone(&self.charge),
        }
    }
}

struct TrackedCaller<Pin> {
    record: CallerRecord,
    pin: Option<SharedCallerPin<Pin>>,
    leader_exit_pending: bool,
}

/// Tracks caller incarnations: admission, exit/exec/reuse retirement with
/// retained evidence. The live incarnation per pid is unique; history is
/// never rewritten and IDs are never reused.
pub(crate) struct CallerAdapter<Source: ProcessSource> {
    source: Source,
    custody_reserver: SemanticResourceReserver,
    next_id: u32,
    incarnations: BTreeMap<u32, u32>,
    callers: BTreeMap<CallerId, TrackedCaller<Source::Pin>>,
    live_by_pid: BTreeMap<u32, CallerId>,
    max_callers: usize,
    admit_refused: u64,
    scoped_retire_cursor: Option<u32>,
    /// A per-incarnation detection-clock read failed (F7a): the
    /// coordinator takes the gap fallback explicitly. Sticky until
    /// taken.
    detection_clock_failed: bool,
    /// (pid, at_ns) retired for PID reuse since the last take: the pin
    /// died while the pid named a live process. The coordinator
    /// forwards these to the binder, whose retained-identity fallback
    /// voids holders admitted at or before them.
    pid_reuses: Vec<(u32, u64)>,
}

/// Why one admission attempt failed: an honest pin failure, or a budget
/// refusal carrying the resource, limit, and requested occupancy.
pub(crate) struct AdmitFailure {
    pub(crate) reason: String,
    pub(crate) budget: Option<BudgetRefusal>,
}

impl AdmitFailure {
    fn custody_storage(refusal: SemanticResourceRefusal) -> Self {
        Self {
            reason: "original process custody storage refused before allocation".into(),
            budget: Some(BudgetRefusal {
                resource: "semantic_bytes",
                limit: refusal.limit_bytes,
                requested: refusal.requested_bytes,
            }),
        }
    }
}

/// A fresh source pin and identity reads, still without an admitted ID.
/// Only a borrowed cgroup transaction permit can commit it.
pub(crate) struct PreparedScopedCaller<Pin> {
    pid: u32,
    pin: SharedCallerPin<Pin>,
    generation: crate::inspect_system::MemberGeneration,
    existing: Option<CallerId>,
}

impl<Pin> PreparedScopedCaller<Pin> {
    pub(crate) fn existing(&self) -> Option<CallerId> {
        self.existing
    }
    pub(crate) fn generation(&self) -> &crate::inspect_system::MemberGeneration {
        &self.generation
    }
}

/// Permit-backed proof of current cgroup membership for one staged
/// owner candidate: the final-sampled member's pid and generation,
/// validated against the borrowed admission permit. Constructible
/// only through `validate`, lifetime-bound to the permit borrow so it
/// cannot span transactions, move-only (no `Clone`, `Default`, or
/// serialization). The permit check re-reads custody liveness —
/// refuses on mismatch, supplies no replacement identity. The job
/// fence rides the transaction outcome gate beside this proof, never
/// inside it: a permit proves its member, not the whole transaction.
pub(crate) struct ScopedOwnerProof<'a> {
    pid: u32,
    generation: crate::inspect_system::MemberGeneration,
    _permit: std::marker::PhantomData<&'a ()>,
}

impl<'a> ScopedOwnerProof<'a> {
    /// Validate staged (pid, generation) against the borrowed
    /// final-sample permit: pid and generation match, custody live,
    /// work finish polled. Anything else is `None`.
    pub(crate) fn validate(
        pid: u32,
        generation: &crate::inspect_system::MemberGeneration,
        permit: &'a crate::inspect_system::inventory_cgroup::CgroupAdmissionPermit<'_>,
    ) -> Option<Self> {
        if pid != permit.pid()
            || *generation != *permit.generation()
            || !permit.check()
            || !permit.finish_check()
        {
            return None;
        }
        Some(Self {
            pid,
            generation: generation.clone(),
            _permit: std::marker::PhantomData,
        })
    }

    pub(crate) fn pid(&self) -> u32 {
        self.pid
    }

    pub(crate) fn generation(&self) -> &crate::inspect_system::MemberGeneration {
        &self.generation
    }
}

/// Whether a scoped mint observes exec for this generation: true only
/// when the generation carries an exe identity. The `CallerRecord`
/// contract requires false when the exe was unreadable at admission;
/// production gates (the pin-insert `is_some` check, `original_matches`,
/// and the prepare/commit generation equality) currently admit only
/// `Some` here, so this reads true on every live path today. The seam
/// pins the counterfactual against future gate changes.
fn scoped_mint_exec_observed(generation: &crate::inspect_system::MemberGeneration) -> bool {
    generation.exe.is_some()
}

impl<Source: ProcessSource> CallerAdapter<Source> {
    /// Never reopen the PID: this is the source pin enclosed by the original
    /// scoped preparation, before the collection's final sample.
    pub(crate) fn scoped_shared_semantic_custody(
        &self,
        prepared: &PreparedScopedCaller<Source::Pin>,
    ) -> Option<Arc<PidPin>> {
        self.source.shared_semantic_custody(&prepared.pin.pin)
    }

    pub(crate) fn scoped_semantic_custody_ref<'pin>(
        &self,
        prepared: &'pin PreparedScopedCaller<Source::Pin>,
    ) -> Option<&'pin PidPin> {
        self.source.semantic_custody_ref(&prepared.pin)
    }

    pub(crate) fn shared_semantic_custody(&self, caller: CallerId) -> Option<Arc<PidPin>> {
        let tracked = self.callers.get(&caller)?;
        if tracked.record.retired || self.live_id(tracked.record.pid) != Some(caller) {
            return None;
        }
        self.source
            .shared_semantic_custody(&tracked.pin.as_ref()?.pin)
    }

    pub(crate) fn semantic_custody_ref(&self, caller: CallerId) -> Option<&PidPin> {
        let tracked = self.callers.get(&caller)?;
        if tracked.record.retired || self.live_id(tracked.record.pid) != Some(caller) {
            return None;
        }
        self.source.semantic_custody_ref(tracked.pin.as_ref()?)
    }
    pub(crate) fn new(source: Source, custody_reserver: SemanticResourceReserver) -> Self {
        Self {
            source,
            custody_reserver,
            next_id: 0,
            incarnations: BTreeMap::new(),
            callers: BTreeMap::new(),
            live_by_pid: BTreeMap::new(),
            max_callers: DEFAULT_MAX_CALLERS,
            admit_refused: 0,
            scoped_retire_cursor: None,
            detection_clock_failed: false,
            pid_reuses: Vec::new(),
        }
    }

    /// Take and clear the detection-clock failure flag (F7a): true
    /// when a per-incarnation stamp saw a clock-read failure since the
    /// last take. The coordinator disables the stale-exit guard on
    /// true, never a silent pass-start stamp.
    pub(crate) fn take_detection_clock_failed(&mut self) -> bool {
        std::mem::take(&mut self.detection_clock_failed)
    }

    /// Take and clear the PID reuses reconcile retired since the last
    /// take, as (pid, at_ns). The coordinator forwards them to the
    /// binder whether or not a successor admitted.
    pub(crate) fn take_pid_reuses(&mut self) -> Vec<(u32, u64)> {
        std::mem::take(&mut self.pid_reuses)
    }

    /// The caller budget this adapter enforces at admission. The
    /// coordinator sets it from the registry limits so the two agree.
    pub(crate) fn set_max_callers(&mut self, max_callers: usize) {
        self.max_callers = max_callers.max(1);
    }

    /// Retained incarnations (live plus retired-with-evidence).
    pub(crate) fn len(&self) -> usize {
        self.callers.len()
    }

    /// Admissions refused on the caller budget. Exact even when gap
    /// retention overflows — the loss counter is not a gap.
    pub(crate) fn admit_refused(&self) -> u64 {
        self.admit_refused
    }

    pub(crate) fn record(&self, id: CallerId) -> Option<&CallerRecord> {
        self.callers.get(&id).map(|tracked| &tracked.record)
    }

    /// The process source (liveness and start-time reads).
    pub(crate) fn source(&self) -> &Source {
        &self.source
    }

    pub(crate) fn records(&self) -> impl Iterator<Item = &CallerRecord> {
        self.callers.values().map(|tracked| &tracked.record)
    }

    pub(crate) fn live_id(&self, pid: u32) -> Option<CallerId> {
        self.live_by_pid.get(&pid).copied()
    }

    /// The exec-coverage revalidation (Task 6 C4, C1 ruling): live
    /// incarnations admitted before `cutoff_ns` that still prove the same
    /// process image now — the pin holds the same generation, the start
    /// time and the exe identity are readable now and at admission and
    /// unchanged. Anything unreadable fails: the incarnation is then never
    /// eligible for native binding. A re-exec of the same binary keeps all
    /// three and passes (the named boundary in the schema doc).
    pub(crate) fn revalidate_admitted_before(&self, cutoff_ns: u64) -> HashSet<CallerId> {
        self.live_by_pid
            .iter()
            .filter_map(|(&pid, id)| {
                let tracked = self.callers.get(id)?;
                let record = &tracked.record;
                // `live_by_pid` holds live incarnations only.
                let same = record.first_seen_ns < cutoff_ns
                    && tracked
                        .pin
                        .as_ref()
                        .is_some_and(|pin| self.source.still_the_same(pin))
                    && record
                        .start_time
                        .is_some_and(|was| self.source.start_time(pid) == Some(was))
                    && record
                        .exe
                        .as_ref()
                        .is_some_and(|was| self.source.exe_identity(pid).as_ref() == Some(was));
                same.then_some(*id)
            })
            .collect()
    }

    /// The live incarnation for `pid` and its retained pin: what the native
    /// binder queries a task cookie through (Task 6 C4).
    pub(crate) fn live_pin(&self, pid: u32) -> Option<(&CallerRecord, &Source::Pin)> {
        let tracked = self.callers.get(self.live_by_pid.get(&pid)?)?;
        Some((&tracked.record, &**tracked.pin.as_ref()?))
    }

    pub(crate) fn share_caller_pin(
        &self,
        caller: CallerId,
    ) -> Option<SharedCallerPin<Source::Pin>> {
        Some(self.callers.get(&caller)?.pin.as_ref()?.share())
    }

    pub(crate) fn mark_leader_exit_pending(&mut self, caller: CallerId, pending: bool) {
        if let Some(tracked) = self.callers.get_mut(&caller) {
            tracked.leader_exit_pending = pending;
        }
    }

    pub(crate) fn leader_exit_pending(&self, caller: CallerId) -> bool {
        self.callers
            .get(&caller)
            .is_some_and(|tracked| tracked.leader_exit_pending)
    }

    fn mint(&mut self) -> Result<CallerId> {
        let id = CallerId(self.next_id);
        self.next_id = self
            .next_id
            .checked_add(1)
            .ok_or_else(|| anyhow!("caller ID space exhausted"))?;
        Ok(id)
    }

    /// Admit a pid as a new incarnation. Fails honestly when the process
    /// cannot be pinned, and refuses on the caller budget when the table
    /// is full — the refusal never erases a retained incarnation; the
    /// caller decides whether either is fatal.
    pub(crate) fn admit(
        &mut self,
        pid: u32,
        authority: ImageAuthority,
        now_ns: u64,
    ) -> Result<CallerId> {
        if let Some(live) = self.live_by_pid.get(&pid) {
            bail!("pid {pid} already has live caller {}", live.label());
        }
        if self.callers.len() >= self.max_callers {
            self.admit_refused = self.admit_refused.saturating_add(1);
            bail!(
                "caller budget exhausted: the registry retains at most {} callers (requested caller {}); the admission was refused",
                self.max_callers,
                self.callers.len() + 1,
            );
        }
        let mut pin = self
            .source
            .open(pid)
            .map_err(|error| anyhow!("cannot pin caller pid {pid}: {error}"))?;
        // A zombie pins successfully (its pidfd and `/proc` entries
        // survive until the parent reaps it), but admitting one mints a
        // caller for a dead generation that retires on the next pass —
        // one spurious incarnation per pass. Refuse up front instead,
        // unless it is an already-zombie leader with exactly one live
        // survivor, which cold-admits below with the survivor-served
        // image (the opened pin stays authoritative throughout).
        let mut cold_exe = None;
        if self.source.gone(pid) {
            let original = Arc::new(pin);
            match self.source.cold_zombie_exe(&original) {
                Ok(Some(exe)) => {
                    cold_exe = Some(exe);
                    pin = Arc::try_unwrap(original).map_err(|_| {
                        anyhow!("cannot pin caller pid {pid}: cold admission retained its original")
                    })?;
                }
                Ok(None) => {
                    bail!("cannot pin caller pid {pid}: no live process with that pid (it exited)")
                }
                Err(named) => bail!("cannot admit caller pid {pid}: {named}"),
            }
        }
        let (start_time, caller_ppid) = self.source.stat_pair(pid);
        let exe = cold_exe.or_else(|| self.source.exe_identity(pid));
        let app_hint = self.source.app_hint(pid, exe.as_ref(), start_time);
        let captured = capture_launcher_chain(&self.source, pid, start_time, caller_ppid);
        let pin = SharedCallerPin::new(pin, &self.source, &self.custody_reserver)
            .map_err(|_| anyhow!("original process custody storage refused before allocation"))?;
        let id = self.mint()?;
        let incarnation = self.incarnations.get(&pid).copied().unwrap_or(0);
        self.incarnations.insert(pid, incarnation.saturating_add(1));
        self.callers.insert(
            id,
            TrackedCaller {
                leader_exit_pending: false,
                record: CallerRecord {
                    id,
                    pid,
                    start_time,
                    incarnation,
                    exec_observed: exe.is_some(),
                    exe,
                    app_hint,
                    launched_by: captured.ancestors,
                    launcher_gap: captured.gap,
                    launched_by_origin: captured.origin,
                    launched_by_unit: captured.unit,
                    authority,
                    lifecycle: CallerLifecycle::Mapped,
                    lifecycle_reason: None,
                    first_seen_ns: now_ns,
                    admitted_ns: now_ns,
                    last_seen_ns: now_ns,
                    retired: false,
                },
                pin: Some(pin),
            },
        );
        self.live_by_pid.insert(pid, id);
        Ok(id)
    }

    pub(crate) fn prepare_scoped_caller(
        &mut self,
        preparation: &crate::inspect_system::inventory_cgroup::CgroupPreparation<'_>,
    ) -> Result<PreparedScopedCaller<Source::Pin>, AdmitFailure> {
        let failed = |reason: &str| AdmitFailure {
            reason: reason.into(),
            budget: None,
        };
        if !preparation.check() {
            return Err(failed(
                "original cgroup transaction custody could not be revalidated",
            ));
        }
        let pid = preparation.pid();
        let existing = self.live_id(pid);
        let pin = if let Some(id) = existing {
            self.callers
                .get(&id)
                .and_then(|tracked| tracked.pin.as_ref())
                .ok_or_else(|| failed("retained cgroup caller custody unavailable"))?
                .share()
        } else {
            let pin = self
                .source
                .open(pid)
                .map_err(|_| failed("cgroup caller source pin unavailable"))?;
            SharedCallerPin::new(pin, &self.source, &self.custody_reserver)
                .map_err(AdmitFailure::custody_storage)?
        };
        let generation = crate::inspect_system::MemberGeneration {
            start_time: self.source.start_time(pid),
            exe: self.source.exe_identity(pid),
        };
        if self.source.gone(pid)
            || !self.source.still_the_same(&pin)
            || generation != *preparation.generation()
        {
            return Err(failed(
                "cgroup caller source generation or image changed before final sampling",
            ));
        }
        if let Some(id) = existing {
            let record = self.record(id).expect("live caller retains its record");
            if record.start_time != generation.start_time || record.exe != generation.exe {
                return Err(failed(
                    "retained caller is a different image from the scoped transaction",
                ));
            }
        }
        Ok(PreparedScopedCaller {
            pid,
            pin,
            generation,
            existing,
        })
    }

    /// Commit one prepared scoped caller under its exact member permit.
    /// `now_ns` is the pass clock for scan-window stamps; `detected`
    /// samples the actual admission detection time per incarnation,
    /// after the permit/custody validation below — the boundary stale
    /// native records order against. On clock-read failure the stamp
    /// is zero (the guard never filters) and the failure flag is set
    /// for the coordinator's explicit gap fallback, never a silent
    /// pass-start stamp.
    pub(crate) fn commit_scoped_caller(
        &mut self,
        prepared: PreparedScopedCaller<Source::Pin>,
        permit: crate::inspect_system::inventory_cgroup::CgroupAdmissionPermit<'_>,
        now_ns: u64,
        detected: &mut dyn FnMut() -> Option<u64>,
    ) -> Result<(CallerId, bool), AdmitFailure> {
        let failed = |reason: &str| AdmitFailure {
            reason: reason.into(),
            budget: None,
        };
        if prepared.pid != permit.pid()
            || prepared.generation != *permit.generation()
            || !permit.check()
            || !self.source.still_the_same(&prepared.pin)
            || !permit.finish_check()
            || self.live_id(prepared.pid) != prepared.existing
        {
            return Err(failed(
                "cgroup transaction was interrupted or changed at admission commit",
            ));
        }
        if let Some(id) = prepared.existing {
            let record = self
                .record(id)
                .ok_or_else(|| failed("retained cgroup caller disappeared"))?;
            if record.retired
                || record.start_time != prepared.generation.start_time
                || record.exe != prepared.generation.exe
            {
                return Err(failed(
                    "retained cgroup caller changed before admission commit",
                ));
            }
            self.callers.get_mut(&id).unwrap().record.last_seen_ns = now_ns;
            return Ok((id, false));
        }
        if self.callers.len() >= self.max_callers {
            self.admit_refused = self.admit_refused.saturating_add(1);
            let budget = BudgetRefusal {
                resource: "callers",
                limit: self.max_callers,
                requested: self.callers.len().saturating_add(1),
            };
            return Err(AdmitFailure {
                reason: "cgroup caller admission refused on the retained caller budget".into(),
                budget: Some(budget),
            });
        }
        // Per-incarnation detection (F7a): after the validation above.
        let admitted_ns = match detected() {
            Some(stamp) => stamp.max(now_ns),
            None => {
                self.detection_clock_failed = true;
                0
            }
        };
        let id = self
            .mint()
            .map_err(|_| failed("caller ID space exhausted"))?;
        let incarnation = self.incarnations.get(&prepared.pid).copied().unwrap_or(0);
        self.incarnations
            .insert(prepared.pid, incarnation.saturating_add(1));
        // Derived, not literal: the mint reads `exec_observed` from
        // the carried exe identity via `scoped_mint_exec_observed`,
        // pinned by `scoped_mint_leaves_unreadable_exe_unobserved`.
        // Reverting this call orphans the seam, which the `-D warnings`
        // gate refuses as dead code on the non-test target.
        let exec_observed = scoped_mint_exec_observed(&prepared.generation);
        debug_assert!(
            prepared.generation.exe.is_some(),
            "scoped admission gates carry an exe identity to the mint"
        );
        let app_hint = self.source.app_hint(
            prepared.pid,
            prepared.generation.exe.as_ref(),
            prepared.generation.start_time,
        );
        self.callers.insert(
            id,
            TrackedCaller {
                leader_exit_pending: false,
                record: CallerRecord {
                    id,
                    pid: prepared.pid,
                    start_time: prepared.generation.start_time,
                    exe: prepared.generation.exe,
                    app_hint,
                    // No post-sample parentage read: the commit uses its
                    // verified generation only, and says so.
                    launched_by: Vec::new(),
                    launcher_gap: Some(LauncherGap {
                        subject: LAUNCHER_GAP_SUBJECT,
                        reason: LAUNCHER_GAP_CGROUP_DEFERRED.into(),
                    }),
                    launched_by_origin: LauncherOrigin::Gap,
                    launched_by_unit: None,
                    incarnation,
                    exec_observed,
                    authority: ImageAuthority::ScanPinned,
                    lifecycle: CallerLifecycle::Mapped,
                    lifecycle_reason: None,
                    first_seen_ns: now_ns,
                    admitted_ns,
                    last_seen_ns: now_ns,
                    retired: false,
                },
                pin: Some(prepared.pin),
            },
        );
        self.live_by_pid.insert(prepared.pid, id);
        Ok((id, true))
    }

    /// Commit one held exec handoff under its exact member permit (H6
    /// slice 2): the moved original pin proves the same process, and the
    /// borrowed permit proves current scope membership. The verified
    /// pre-sample generation arrives with the call, so commit performs
    /// no post-sample generation recapture; permit.check() custody
    /// liveness reread excepted (refuses on mismatch, supplies no
    /// replacement identity). Checks mirror
    /// `commit_scoped_caller` — pid/generation match, permit check,
    /// custody, finish — with no fallible tail after them. A live
    /// candidate for this pid joins only when it already holds the
    /// current incarnation; pid equality alone never adopts it.
    /// Returns the successor and whether it was freshly minted.
    /// `now_ns` is the pass clock for scan-window stamps; `detected`
    /// samples the actual admission detection time per incarnation,
    /// after the validation below. On clock-read failure the stamp is
    /// zero with the failure flag set, never a silent pass-start stamp.
    pub(crate) fn commit_handoff_caller(
        &mut self,
        pid: u32,
        pin: SharedCallerPin<Source::Pin>,
        permit: crate::inspect_system::inventory_cgroup::CgroupAdmissionPermit<'_>,
        generation: crate::inspect_system::MemberGeneration,
        now_ns: u64,
        detected: &mut dyn FnMut() -> Option<u64>,
    ) -> Result<(CallerId, bool), AdmitFailure> {
        let failed = |reason: &str| AdmitFailure {
            reason: reason.into(),
            budget: None,
        };
        if pid != permit.pid()
            || generation != *permit.generation()
            || !permit.check()
            || !self.source.still_the_same(&pin)
            || !permit.finish_check()
        {
            return Err(failed(
                "cgroup transaction was interrupted or changed at handoff commit",
            ));
        }
        if let Some(id) = self.live_by_pid.get(&pid).copied() {
            let record = self
                .record(id)
                .ok_or_else(|| failed("retained cgroup caller disappeared"))?;
            if record.retired
                || record.start_time != generation.start_time
                || record.exe != generation.exe
            {
                return Err(failed(
                    "the pid's live caller is not this handoff's current incarnation; \
                     pid equality alone never adopts it",
                ));
            }
            self.callers.get_mut(&id).unwrap().record.last_seen_ns = now_ns;
            return Ok((id, false));
        }
        if self.callers.len() >= self.max_callers {
            self.admit_refused = self.admit_refused.saturating_add(1);
            let budget = BudgetRefusal {
                resource: "callers",
                limit: self.max_callers,
                requested: self.callers.len().saturating_add(1),
            };
            return Err(AdmitFailure {
                reason: "cgroup successor admission refused on the retained caller budget".into(),
                budget: Some(budget),
            });
        }
        // Per-incarnation detection (F7a): after the validation above.
        let admitted_ns = match detected() {
            Some(stamp) => stamp.max(now_ns),
            None => {
                self.detection_clock_failed = true;
                0
            }
        };
        let id = self
            .mint()
            .map_err(|_| failed("caller ID space exhausted"))?;
        let incarnation = self.incarnations.get(&pid).copied().unwrap_or(0);
        self.incarnations.insert(pid, incarnation.saturating_add(1));
        let app_hint = self
            .source
            .app_hint(pid, generation.exe.as_ref(), generation.start_time);
        self.callers.insert(
            id,
            TrackedCaller {
                leader_exit_pending: false,
                record: CallerRecord {
                    id,
                    pid,
                    start_time: generation.start_time,
                    incarnation,
                    exec_observed: generation.exe.is_some(),
                    exe: generation.exe,
                    app_hint,
                    // No post-sample parentage read: the handoff commits
                    // its verified generation only, and says so.
                    launched_by: Vec::new(),
                    launcher_gap: Some(LauncherGap {
                        subject: LAUNCHER_GAP_SUBJECT,
                        reason: LAUNCHER_GAP_CGROUP_DEFERRED.into(),
                    }),
                    launched_by_origin: LauncherOrigin::Gap,
                    launched_by_unit: None,
                    authority: ImageAuthority::ScanPinned,
                    lifecycle: CallerLifecycle::Mapped,
                    lifecycle_reason: None,
                    first_seen_ns: now_ns,
                    admitted_ns,
                    last_seen_ns: now_ns,
                    retired: false,
                },
                pin: Some(pin),
            },
        );
        self.live_by_pid.insert(pid, id);
        Ok((id, true))
    }

    /// Install native-exact authority on an admitted caller after its
    /// staged owner proved under the permit-backed proof. The caller
    /// must be live, unretired, still scan-pinned, and name the
    /// proof's pid and generation, with its held pin still the same;
    /// anything else refuses without touching the record.
    pub(crate) fn install_scoped_native_authority(
        &mut self,
        caller: CallerId,
        image: BoundImage,
        proof: &ScopedOwnerProof<'_>,
    ) -> Result<(), AdmitFailure> {
        let failed = |reason: &str| AdmitFailure {
            reason: reason.into(),
            budget: None,
        };
        let record = self
            .record(caller)
            .ok_or_else(|| failed("scoped native activation names no retained caller"))?;
        if record.retired
            || record.authority != ImageAuthority::ScanPinned
            || record.pid != proof.pid()
            || self.live_id(record.pid) != Some(caller)
        {
            return Err(failed(
                "retained cgroup caller changed before native authority installation",
            ));
        }
        if record.start_time != proof.generation().start_time
            || record.exe != proof.generation().exe
        {
            return Err(failed(
                "retained caller is a different generation from the scoped proof",
            ));
        }
        let live = self
            .callers
            .get(&caller)
            .and_then(|tracked| tracked.pin.as_ref())
            .is_some_and(|pin| self.source.still_the_same(pin));
        if !live {
            return Err(failed(
                "retained caller custody lapsed before native authority installation",
            ));
        }
        self.callers
            .get_mut(&caller)
            .expect("validated retained caller")
            .record
            .authority = ImageAuthority::NativeExact { image };
        Ok(())
    }

    /// Restore scan-pinned authority after a failed activation commit
    /// that had already installed `image`. Only the exact installed
    /// image flips back; anything else is left untouched and reported.
    /// Caller IDs are never reused, so the flip cannot land on a
    /// newer incarnation.
    pub(crate) fn cancel_scoped_native_authority(
        &mut self,
        caller: CallerId,
        image: BoundImage,
    ) -> Result<(), String> {
        let tracked = self.callers.get_mut(&caller).ok_or_else(|| {
            format!(
                "scoped native activation rollback names no retained caller {}",
                caller.label()
            )
        })?;
        if tracked.record.authority == (ImageAuthority::NativeExact { image }) {
            tracked.record.authority = ImageAuthority::ScanPinned;
            Ok(())
        } else {
            Err(format!(
                "scoped native activation rollback missed its installed image for {}",
                caller.label()
            ))
        }
    }

    /// Retire a live caller whose installed native-exact authority
    /// survived a failed activation rollback with no activated owner:
    /// the record keeps its evidence and authority, leaves the live
    /// map, and drops its pin, so no live `NativeExact` caller lacks
    /// its owner. Returns false — changing nothing — when the caller
    /// is unknown, already retired, not live, or no longer
    /// native-exact (an already rolled-back caller is healthy and
    /// stays). Caller IDs are never reused, so the retirement cannot
    /// land on a newer incarnation.
    pub(crate) fn retire_native_caller_without_owner(
        &mut self,
        caller: CallerId,
        reason: String,
        now_ns: u64,
    ) -> bool {
        let stranded = self.callers.get(&caller).is_some_and(|tracked| {
            !tracked.record.retired
                && matches!(tracked.record.authority, ImageAuthority::NativeExact { .. })
                && self.live_by_pid.get(&tracked.record.pid) == Some(&caller)
        });
        if !stranded {
            return false;
        }
        self.retire(caller, CallerLifecycle::Unknown, reason, now_ns);
        true
    }

    /// Reconcile's admission: the budget refusal carries its
    /// resource/limit/requested structurally; pin failures stay bare.
    /// `detected` samples the admission detection time per incarnation,
    /// after the pin/liveness/generation validation inside `admit` —
    /// never a sweep-start sample shared across admissions. On
    /// clock-read failure the stamp is zero with the failure flag set,
    /// never a silent pass-start stamp.
    fn try_admit(
        &mut self,
        pid: u32,
        authority: ImageAuthority,
        now_ns: u64,
        detected: &mut dyn FnMut() -> Option<u64>,
    ) -> Result<CallerId, AdmitFailure> {
        if self.live_by_pid.contains_key(&pid) {
            return Err(AdmitFailure {
                reason: format!(
                    "pid {pid} already has live caller {}",
                    self.live_by_pid[&pid].label()
                ),
                budget: None,
            });
        }
        if self.callers.len() >= self.max_callers {
            self.admit_refused = self.admit_refused.saturating_add(1);
            let refusal = BudgetRefusal {
                resource: "callers",
                limit: self.max_callers,
                requested: self.callers.len() + 1,
            };
            return Err(AdmitFailure {
                reason: format!(
                    "caller budget exhausted: the registry retains at most {} callers (requested caller {}); the admission was refused",
                    refusal.limit, refusal.requested,
                ),
                budget: Some(refusal),
            });
        }
        let id = self
            .admit(pid, authority, now_ns)
            .map_err(|error| AdmitFailure {
                reason: format!("{error:#}"),
                budget: None,
            })?;
        let admitted_ns = match detected() {
            Some(stamp) => stamp.max(now_ns),
            None => {
                self.detection_clock_failed = true;
                0
            }
        };
        self.callers
            .get_mut(&id)
            .expect("the admitted caller retains its record")
            .record
            .admitted_ns = admitted_ns;
        Ok(id)
    }

    fn retire(&mut self, id: CallerId, lifecycle: CallerLifecycle, reason: String, now_ns: u64) {
        let Some(tracked) = self.callers.get_mut(&id) else {
            return;
        };
        tracked.record.lifecycle = lifecycle;
        tracked.record.lifecycle_reason = Some(reason);
        tracked.record.last_seen_ns = now_ns;
        tracked.record.retired = true;
        // The pin (and its fd) is released; the record and its usage
        // evidence are retained.
        tracked.pin = None;
        self.live_by_pid.remove(&tracked.record.pid);
    }

    /// A natively proven exec transition (Task 6 C4): the live incarnation
    /// `id`'s image ended while its pin held. It retires exec-retired with
    /// its evidence and the pid is admitted again as its successor. A
    /// retired or unknown `id` changes nothing.
    #[cfg_attr(not(test), allow(dead_code))] // Reached only by tests today.
    pub(crate) fn exec_transition(
        &mut self,
        id: CallerId,
        authority_for: &mut dyn FnMut(u32) -> ImageAuthority,
        now_ns: u64,
    ) -> Vec<CallerEvent> {
        self.exec_transition_inner(id, authority_for, now_ns, SuccessorAdmission::Unrestricted)
    }

    /// A scope-independent EXEC proof retires the old image. Membership of
    /// its successor is a separate transaction, never inherited from its PID.
    pub(crate) fn exec_transition_scoped(&mut self, id: CallerId, now_ns: u64) -> Vec<CallerEvent> {
        self.exec_transition_inner(
            id,
            &mut |_| ImageAuthority::ScanPinned,
            now_ns,
            SuccessorAdmission::ScopedDenied,
        )
    }

    fn exec_transition_inner(
        &mut self,
        id: CallerId,
        authority_for: &mut dyn FnMut(u32) -> ImageAuthority,
        now_ns: u64,
        admission: SuccessorAdmission,
    ) -> Vec<CallerEvent> {
        let Some(pid) = self
            .callers
            .get(&id)
            .filter(|tracked| !tracked.record.retired)
            .map(|tracked| tracked.record.pid)
        else {
            return Vec::new();
        };
        if matches!(admission, SuccessorAdmission::ScopedDenied) {
            self.retire(
                id,
                CallerLifecycle::ExecRetired,
                NATIVE_EXEC_REASON.into(),
                now_ns,
            );
            return vec![self.retired_event(id)];
        }
        // H6 slice 2: the original held pin moves to the successor first,
        // then the old incarnation retires. The successor is never reopened
        // by scalar PID. This rides the same two primitives as the
        // coordinator's pending handoff.
        let authority = authority_for(pid);
        let handoff = self.retire_for_exec_handoff(id, now_ns);
        let commit = match handoff {
            Some((pid, pin)) => self.admit_retained_successor(
                pid,
                pin,
                authority,
                now_ns,
                &mut crate::attach::monotonic_ns,
            ),
            None => self.commit_retained_successor(
                pid,
                None,
                authority,
                now_ns,
                &mut crate::attach::monotonic_ns,
            ),
        };
        vec![match commit {
            Ok(new) => CallerEvent::ExecRetired { old: id, new },
            Err(failure) => CallerEvent::AdmitFailed {
                pid,
                reason: format!("post-exec re-admission failed: {}", failure.reason),
                budget: failure.budget,
            },
        }]
    }

    /// Retire `id` for a coordinator exec handoff (H6 slice 2): the
    /// original held pin moves to the caller first, then the old
    /// incarnation retires exec-retired. `None` unless `id` is live with
    /// its pin. The coordinator mints the pending successor from this
    /// custody; the pin is never dropped here and never reopened by PID.
    pub(crate) fn retire_for_exec_handoff(
        &mut self,
        id: CallerId,
        now_ns: u64,
    ) -> Option<(u32, SharedCallerPin<Source::Pin>)> {
        let pid = self
            .callers
            .get(&id)
            .filter(|tracked| !tracked.record.retired)
            .map(|tracked| tracked.record.pid)?;
        let pin = self.callers.get_mut(&id)?.pin.take()?;
        self.retire(
            id,
            CallerLifecycle::ExecRetired,
            NATIVE_EXEC_REASON.into(),
            now_ns,
        );
        Some((pid, pin))
    }

    /// Admit one exec successor on retained custody (H6 slice 2): the moved
    /// original pin proves the same process. A dead pin, a live pid
    /// collision, a full caller budget, or a zombie refuses; nothing here
    /// reopens the successor by scalar PID. `detected` samples the
    /// admission detection time per incarnation, after validation
    /// (F7a): the supplied `now_ns` may be a stale pass-start stamp and
    /// must never stand in for detection.
    pub(crate) fn admit_retained_successor(
        &mut self,
        pid: u32,
        pin: SharedCallerPin<Source::Pin>,
        authority: ImageAuthority,
        now_ns: u64,
        detected: &mut dyn FnMut() -> Option<u64>,
    ) -> Result<CallerId, AdmitFailure> {
        self.commit_retained_successor(pid, Some(pin), authority, now_ns, detected)
    }

    /// The one retained-custody commit behind every exec handoff: the native
    /// transition path, the scan-proven path, and the coordinator's pending
    /// successor commit share these checks, in this order. `detected`
    /// samples the admission detection time per incarnation, after the
    /// custody/liveness validation above; on clock-read failure the
    /// stamp is zero with the failure flag set.
    fn commit_retained_successor(
        &mut self,
        pid: u32,
        pin: Option<SharedCallerPin<Source::Pin>>,
        authority: ImageAuthority,
        now_ns: u64,
        detected: &mut dyn FnMut() -> Option<u64>,
    ) -> Result<CallerId, AdmitFailure> {
        let Some(pin) = pin else {
            return Err(AdmitFailure {
                reason: "no retained process custody for the exec successor \
                     (the successor is never reopened by scalar PID)"
                    .into(),
                budget: None,
            });
        };
        if !self.source.still_the_same(&pin) {
            return Err(AdmitFailure {
                reason: "original process custody lost: the process exited or the pid was reused"
                    .into(),
                budget: None,
            });
        }
        if self.live_by_pid.contains_key(&pid) {
            return Err(AdmitFailure {
                reason: format!(
                    "pid {pid} already has live caller {}",
                    self.live_by_pid[&pid].label()
                ),
                budget: None,
            });
        }
        if self.callers.len() >= self.max_callers {
            self.admit_refused = self.admit_refused.saturating_add(1);
            let refusal = BudgetRefusal {
                resource: "callers",
                limit: self.max_callers,
                requested: self.callers.len() + 1,
            };
            return Err(AdmitFailure {
                reason: format!(
                    "caller budget exhausted: the registry retains at most {} callers (requested caller {}); the admission was refused",
                    refusal.limit, refusal.requested,
                ),
                budget: Some(refusal),
            });
        }
        // A zombie pins successfully but admits nothing: same refusal as a
        // fresh open, so a dead-but-unreaped target never mints a spurious
        // successor incarnation.
        if self.source.gone(pid) {
            return Err(AdmitFailure {
                reason: format!(
                    "cannot pin caller pid {pid}: no live process with that pid (it exited)"
                ),
                budget: None,
            });
        }
        let (start_time, caller_ppid) = self.source.stat_pair(pid);
        let exe = self.source.exe_identity(pid);
        let app_hint = self.source.app_hint(pid, exe.as_ref(), start_time);
        let captured = capture_launcher_chain(&self.source, pid, start_time, caller_ppid);
        // Per-incarnation detection (F7a): after the validation above.
        let admitted_ns = match detected() {
            Some(stamp) => stamp.max(now_ns),
            None => {
                self.detection_clock_failed = true;
                0
            }
        };
        let id = self.mint().map_err(|error| AdmitFailure {
            reason: format!("{error:#}"),
            budget: None,
        })?;
        let incarnation = self.incarnations.get(&pid).copied().unwrap_or(0);
        self.incarnations.insert(pid, incarnation.saturating_add(1));
        self.callers.insert(
            id,
            TrackedCaller {
                leader_exit_pending: false,
                record: CallerRecord {
                    id,
                    pid,
                    start_time,
                    incarnation,
                    exec_observed: exe.is_some(),
                    exe,
                    app_hint,
                    launched_by: captured.ancestors,
                    launcher_gap: captured.gap,
                    launched_by_origin: captured.origin,
                    launched_by_unit: captured.unit,
                    authority,
                    lifecycle: CallerLifecycle::Mapped,
                    lifecycle_reason: None,
                    first_seen_ns: now_ns,
                    admitted_ns,
                    last_seen_ns: now_ns,
                    retired: false,
                },
                pin: Some(pin),
            },
        );
        self.live_by_pid.insert(pid, id);
        Ok(id)
    }

    /// Reconcile tracked callers against one scan pass's observed pids:
    /// detect exit, exec (leader and nonleader — both change the exe
    /// identity while the pin holds), and PID reuse; admit newly observed
    /// pids. Every transition is an event; failures to admit are events,
    /// never silent. `authority_for` resolves the image authority per pid,
    /// so one pass can mix native-exact and scan-pinned incarnations.
    #[cfg_attr(not(test), allow(dead_code))] // Reached only by tests today.
    pub(crate) fn reconcile(
        &mut self,
        observed: &BTreeSet<u32>,
        authority_for: &mut dyn FnMut(u32) -> ImageAuthority,
        now_ns: u64,
    ) -> Vec<CallerEvent> {
        self.reconcile_detected(observed, authority_for, now_ns, &mut || Some(now_ns))
    }

    /// Reconcile with a per-incarnation admission detection clock:
    /// `now_ns` is the pass clock for scan-window stamps
    /// (`first_seen_ns` and retirement/last-seen), while `detected` is
    /// sampled once per admitted incarnation, after its
    /// generation/liveness/executable/reuse validation — the boundary
    /// stale native records order against (`admitted_ns`). The
    /// production scan path passes the monotonic clock; callers that
    /// admit at the pass clock use [`Self::reconcile`]. On clock-read
    /// failure the incarnation stamps zero with the failure flag set,
    /// never a silent pass-start stamp.
    pub(crate) fn reconcile_detected(
        &mut self,
        observed: &BTreeSet<u32>,
        authority_for: &mut dyn FnMut(u32) -> ImageAuthority,
        now_ns: u64,
        detected: &mut dyn FnMut() -> Option<u64>,
    ) -> Vec<CallerEvent> {
        self.reconcile_inner(
            observed,
            authority_for,
            now_ns,
            detected,
            SuccessorAdmission::Unrestricted,
            &mut || true,
        )
    }

    /// Retire independently proven old generations without authorizing any
    /// successor. The explicit work callback bounds these lifecycle checks.
    pub(crate) fn reconcile_scoped(
        &mut self,
        now_ns: u64,
        work: &mut dyn FnMut() -> bool,
    ) -> Vec<CallerEvent> {
        self.reconcile_inner(
            &BTreeSet::new(),
            &mut |_| ImageAuthority::ScanPinned,
            now_ns,
            &mut || Some(now_ns),
            SuccessorAdmission::ScopedDenied,
            work,
        )
    }

    /// The retirement event for an already-retired caller (H6 slice 2): the
    /// coordinator mints its pending handoff from the retired record and
    /// reports the retirement now while the successor commits later.
    pub(crate) fn retired_event(&self, id: CallerId) -> CallerEvent {
        CallerEvent::Retired {
            id,
            reason: self
                .record(id)
                .and_then(|record| record.lifecycle_reason.clone())
                .unwrap_or_else(|| "caller retired".into()),
        }
    }

    fn reconcile_inner(
        &mut self,
        observed: &BTreeSet<u32>,
        authority_for: &mut dyn FnMut(u32) -> ImageAuthority,
        now_ns: u64,
        detected: &mut dyn FnMut() -> Option<u64>,
        admission: SuccessorAdmission,
        work: &mut dyn FnMut() -> bool,
    ) -> Vec<CallerEvent> {
        let mut events = Vec::new();
        let live: Vec<(u32, CallerId)> = match admission {
            SuccessorAdmission::Unrestricted => self
                .live_by_pid
                .iter()
                .map(|(pid, id)| (*pid, *id))
                .collect(),
            SuccessorAdmission::ScopedDenied => {
                // Bounded lifecycle work leaves room for fresh final sampling.
                // Its cursor has no membership authority; it only schedules
                // later retained callers fairly across partial collections.
                use std::ops::Bound::{Excluded, Included, Unbounded};
                let start = self.scoped_retire_cursor.map_or(Unbounded, Excluded);
                let end = self.scoped_retire_cursor.map_or(Unbounded, Included);
                self.live_by_pid
                    .range((start, Unbounded))
                    .chain(
                        self.live_by_pid
                            .range((Unbounded, end))
                            .filter(|_| self.scoped_retire_cursor.is_some()),
                    )
                    .take(128)
                    .map(|(pid, id)| (*pid, *id))
                    .take_while(|_| work())
                    .collect()
            }
        };
        for (pid, id) in live {
            if !work() {
                break;
            }
            if matches!(admission, SuccessorAdmission::ScopedDenied) {
                self.scoped_retire_cursor = Some(pid);
            }
            let same = self
                .callers
                .get(&id)
                .and_then(|tracked| tracked.pin.as_ref())
                .is_some_and(|pin| self.source.still_the_same(pin));
            if same {
                let changed = self
                    .callers
                    .get(&id)
                    .and_then(|tracked| {
                        let current = self.source.exe_identity(pid)?;
                        let previous = tracked.record.exe.as_ref()?;
                        Some(current != *previous)
                    })
                    .unwrap_or(false);
                if changed {
                    // Same generation, new image: an exec (leader or
                    // nonleader). Retire the old incarnation with its
                    // evidence, admit the new one.
                    if matches!(admission, SuccessorAdmission::ScopedDenied) {
                        self.retire(
                            id,
                            CallerLifecycle::ExecRetired,
                            "executable image changed while the generation pin held (exec)".into(),
                            now_ns,
                        );
                        events.push(self.retired_event(id));
                        continue;
                    }
                    // H6 slice 2: the original held pin moves to the
                    // successor first, then the old incarnation retires.
                    // The successor is never reopened by scalar PID.
                    let authority = authority_for(pid);
                    let pin = self
                        .callers
                        .get_mut(&id)
                        .and_then(|tracked| tracked.pin.take());
                    self.retire(
                        id,
                        CallerLifecycle::ExecRetired,
                        "executable image changed while the generation pin held (exec)".into(),
                        now_ns,
                    );
                    let commit =
                        self.commit_retained_successor(pid, pin, authority, now_ns, detected);
                    match commit {
                        Ok(new) => events.push(CallerEvent::ExecRetired { old: id, new }),
                        Err(failure) => events.push(CallerEvent::AdmitFailed {
                            pid,
                            reason: format!("post-exec re-admission failed: {}", failure.reason),
                            budget: failure.budget,
                        }),
                    }
                } else if let Some(tracked) = self.callers.get_mut(&id) {
                    tracked.record.last_seen_ns = now_ns;
                }
                continue;
            }
            // The pin no longer holds this generation.
            if self.source.gone(pid) {
                self.retire(
                    id,
                    CallerLifecycle::Exited,
                    "process exited (pid names no live process)".into(),
                    now_ns,
                );
                events.push(CallerEvent::Exited {
                    id,
                    reason: "process exited (pid names no live process)".into(),
                });
            } else {
                // A live process answers, but it is not the tracked
                // generation: PID reuse. The old incarnation ended —
                // its generation is gone — and a new one begins. The
                // two never share an ID or evidence.
                let current = self.source.start_time(pid);
                let previous = self
                    .callers
                    .get(&id)
                    .and_then(|tracked| tracked.record.start_time);
                let (lifecycle, reason) = match (previous, current) {
                    (Some(was), Some(is)) if was != is => (
                        CallerLifecycle::Exited,
                        format!("pid reused: start-time changed from {was} to {is} clock ticks"),
                    ),
                    (_, Some(_)) => (
                        CallerLifecycle::Exited,
                        "pid reused: the tracked generation ended and the pid names a live process"
                            .into(),
                    ),
                    // The pin died but the pid's current state is
                    // unreadable (a race or a permission wall): the old
                    // incarnation ended, but the turnover is unproven,
                    // so it retires unknown rather than exited.
                    _ => (
                        CallerLifecycle::Unknown,
                        "the tracked generation ended but the pid's current state is unreadable"
                            .into(),
                    ),
                };
                self.retire(id, lifecycle, reason, now_ns);
                // A recorded turnover whatever the successor does (even
                // unproven, even denied): the binder voids retained
                // holders admitted at or before it.
                self.pid_reuses.push((pid, now_ns));
                if matches!(admission, SuccessorAdmission::ScopedDenied) {
                    events.push(self.retired_event(id));
                    continue;
                }
                match self.try_admit(pid, authority_for(pid), now_ns, detected) {
                    Ok(new) => events.push(CallerEvent::Reused { old: id, new }),
                    Err(failure) => events.push(CallerEvent::AdmitFailed {
                        pid,
                        reason: format!("post-reuse re-admission failed: {}", failure.reason),
                        budget: failure.budget,
                    }),
                }
            }
        }
        let mut observed: Vec<u32> = observed.iter().copied().collect();
        observed.sort_unstable();
        for pid in observed {
            if self.live_by_pid.contains_key(&pid) {
                continue;
            }
            match self.try_admit(pid, authority_for(pid), now_ns, detected) {
                Ok(id) => events.push(CallerEvent::Admitted { id }),
                Err(failure) => events.push(CallerEvent::AdmitFailed {
                    pid,
                    reason: failure.reason,
                    budget: failure.budget,
                }),
            }
        }
        events
    }
}

/// Physical module-instance identity, reusing the Phase 1 authority: the
/// (device, inode) file identity plus the whole-file SHA-256 that guards
/// against in-place replacement between passes. Two callers mapping
/// different objects at the same path are distinct instances; the path is
/// an attribute, never identity.
///
/// Boundary (F7b, S1): file identity is NOT load-instance authority.
/// A same-file double-load (two loader mappings of one file — notably
/// a `dlmopen` private-namespace double-load, whose objects own
/// distinct PKCS#11 session namespaces) carries one key and merges
/// into one module and one edge. The merge-by-construction stands:
/// same-key notes without scan evidence (a `dlopen` re-scan, a second
/// spelling) still merge, and for `dlopen` in one namespace the merge
/// is correct (same file → same loaded object → one session
/// namespace). What changed is the blind case: scan evidence now
/// carries the double-load verdict (`ScannedModule::double_loaded`,
/// from duplicate executable file-offset coverage), and a flagged
/// note fails the edge closed — live operations end unknown, later
/// calls void, and the `same-file double-load detected` gap names
/// the edge — instead of joining the instances' overlapping numeric
/// session handles. Per-call instance attribution (which instance a
/// call came from) still needs S2's entry-IP capture + mapping join.
/// Pinned by `d2_same_file_double_load_merges_boundary_for_s2`
/// (merge without evidence) and the owned-`dlmopen` detection
/// regression; S2's instance authority must replace both with
/// separation (see `docs/notes/s2-instance-authority.md`).
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub(crate) enum ModuleKey {
    Physical {
        dev_major: u64,
        dev_minor: u64,
        ino: u64,
        sha256: Option<String>,
    },
    /// No comparable file identity (zero device/inode): keyed by path
    /// with an explicit uncertainty gap. Distinct objects that share both
    /// a zero key and a path would merge here — the gap says so.
    Unidentified { path: String },
}

impl ModuleKey {
    pub(crate) fn physical(
        dev_major: u64,
        dev_minor: u64,
        ino: u64,
        sha256: Option<String>,
        path: &str,
    ) -> Self {
        if dev_major == 0 && dev_minor == 0 && ino == 0 {
            Self::Unidentified {
                path: path.to_string(),
            }
        } else {
            Self::Physical {
                dev_major,
                dev_minor,
                ino,
                sha256,
            }
        }
    }
}

impl ModuleKey {
    /// The key as a reason suffix for a gap that has no module id (the
    /// module is not in the registry): gaps for different keys must
    /// stay distinct, since gap identity is the published fields.
    fn gap_suffix(&self) -> String {
        match self {
            Self::Physical {
                dev_major,
                dev_minor,
                ino,
                ..
            } => format!(" [module key: dev {dev_major}:{dev_minor} inode {ino}]"),
            Self::Unidentified { path } => format!(" [module key: path {path}]"),
        }
    }
}

/// Scan-only admission verdict for one module instance (Phase 1 catalog
/// semantics, carried over verbatim).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum AdmissionState {
    Admitted,
    Refused,
    Unresolved,
}

impl AdmissionState {
    pub(crate) const fn label(self) -> &'static str {
        match self {
            Self::Admitted => "admitted",
            Self::Refused => "refused",
            Self::Unresolved => "unresolved",
        }
    }
}

/// Static facts about one module instance, from scan evidence.
#[derive(Debug, Clone)]
pub(crate) struct ModuleInfo {
    pub path: String,
    pub key: ModuleKey,
    /// Scan evidence (F7b): the mapping evidence behind this note
    /// shows this object loaded twice in the noting process
    /// (duplicate executable file-offset coverage — notably a
    /// `dlmopen` private-namespace double-load). Both projection
    /// paths (native and catalog) carry the scan's verdict, so the
    /// edge latch follows the latest note; synthetic notes without
    /// mapping evidence carry `false`.
    pub double_loaded: bool,
    pub build_id: Option<String>,
    pub identity_source: Option<String>,
    pub admission: AdmissionState,
    pub admission_class: Option<String>,
    pub admission_endpoints: Option<usize>,
    pub admission_reasons: Vec<String>,
}

/// How an edge's latest mapping observation was established.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum MappingEvidence {
    /// A deep scan of the caller (catalog member or native owner).
    DeepScan,
    /// C1b: the caller's confirmed maps show the pinned object by exact
    /// `(device, inode)`; the caller itself was not decoded.
    MapsMatch,
}

impl MappingEvidence {
    pub(crate) const fn label(self) -> &'static str {
        match self {
            Self::DeepScan => "deep_scan",
            Self::MapsMatch => "maps_match",
        }
    }
}

/// Lifecycle of one module instance across passes.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum ModuleLifecycle {
    Mapped,
    Unloaded,
    Unknown,
}

impl ModuleLifecycle {
    pub(crate) const fn label(self) -> &'static str {
        match self {
            Self::Mapped => "mapped",
            Self::Unloaded => "unloaded",
            Self::Unknown => "unknown",
        }
    }
}

/// Mapping state of one caller/module edge.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum MappingState {
    /// The mapping was observed and neither endpoint has ended.
    Mapped,
    /// Observation ended with proof: the caller exited or retired, or a
    /// complete rescan of the live caller no longer shows the module.
    Ended,
    /// Lifecycle evidence is missing (the member was not scanned this
    /// pass): the mapping is neither confirmed nor refuted.
    Uncertain,
}

impl MappingState {
    pub(crate) const fn label(self) -> &'static str {
        match self {
            Self::Mapped => "mapped",
            Self::Ended => "ended",
            Self::Uncertain => "uncertain",
        }
    }
}

/// What the edge's entry columns mean. Counts are cumulative observed
/// entries only; anything else reads as unknown, never zero-as-fact.
/// Derived from the edge's [`UseCoverage`]: a zero reads `observed`
/// only under `WatchedNoUse` or a loss-free `Counted` feed.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum EntryObservation {
    Observed,
    UnknownNotAdmitted,
    UnknownUnavailable,
    /// Use was witnessed, but no feed counts this edge's entries.
    UnknownCountUnavailable,
    /// A counting feed covers the edge, but it lost records: a zero is
    /// not a fact.
    UnknownLossy,
}

impl EntryObservation {
    pub(crate) const fn label(self) -> &'static str {
        match self {
            Self::Observed => "observed",
            Self::UnknownNotAdmitted => "unknown (not admitted)",
            Self::UnknownUnavailable => "unknown (usage observation unavailable)",
            Self::UnknownCountUnavailable => "unknown (count unavailable; use witnessed)",
            Self::UnknownLossy => "unknown (usage observation lossy)",
        }
    }
}

/// Why one edge's usage is unknown.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum UnknownReason {
    /// No native usage producer runs: the scan lane alone.
    ScanOnly,
    /// The module's admission verdict is not `admitted`.
    NotAdmitted,
    /// A producer runs, but this edge's module endpoints are not attached
    /// for this caller.
    #[cfg_attr(not(test), allow(dead_code))] // Task 6 C3/C5 producers stage it.
    NotAttached,
    /// Attaching one of the module's endpoints failed.
    #[cfg_attr(not(test), allow(dead_code))] // Task 6 C3 facade stages it.
    AttachFailed,
    /// The caller's identity cannot be bound to native evidence.
    #[allow(dead_code)] // Task 6 C4 binder stages it.
    IdentityUnavailable,
    /// A retained cgroup filter does not prove continuous caller residency.
    ScopeMembershipUnproven,
    /// A capture capacity (named resource) ran out.
    #[cfg_attr(not(test), allow(dead_code))] // Task 6 C3/C4 stage it.
    CapacityLimited(&'static str),
    /// Evidence was lost (a global health regression demoted the edge).
    /// Shared: one regression's text is not cloned per edge.
    Loss(Arc<str>),
    /// The caller retired before any coverage reached the edge.
    RetiredBeforeCoverage,
    /// A CALLER_USE row from this caller's pid was not bound to it (often
    /// a use before its admission): the pair's only row exists, so later
    /// use leaves no row and a watch could not see it (R-C51-1). Sticky.
    UseBeforeAdmission,
    /// A CALLER_USE row from this caller's pid, provably after its
    /// admission, stayed unbound because the caller exited before the
    /// row could be matched to a live incarnation and the retained
    /// identity was ambiguous: same sticky R-C51-1 downgrade as
    /// [`Self::UseBeforeAdmission`], with honest post-admission wording.
    CallerExitedBeforeMatch,
    /// A CALLER_USE row of this caller's pid on this module is read but
    /// undecided (its lifecycle and health horizons have not arrived):
    /// the edge may have been used. Transient, never staged: the
    /// presentation overlays it while the row is pending, and the staged
    /// watch resumes once the row binds elsewhere (DR-LIVE-LABEL-LAG).
    PendingFirstUse,
    /// A CALLER_USE pair insert failed (the map was full): some pair has
    /// use but no row, so absence proves nothing for every edge without
    /// positive history. Sticky for the capture; the detail names the
    /// `PairInsertFailure` evidence. Never a zero (C7 C4).
    Uncounted(Arc<str>),
}

impl UnknownReason {
    /// Stable machine code (`entries.coverage.reason`).
    pub(crate) const fn code(&self) -> &'static str {
        match self {
            Self::ScanOnly => "scan_only",
            Self::NotAdmitted => "not_admitted",
            Self::NotAttached => "not_attached",
            Self::AttachFailed => "attach_failed",
            Self::IdentityUnavailable => "identity_unavailable",
            Self::ScopeMembershipUnproven => "scope_membership_unproven",
            Self::CapacityLimited(_) => "capacity_limited",
            Self::Loss(_) => "loss",
            Self::RetiredBeforeCoverage => "retired_before_coverage",
            Self::UseBeforeAdmission => "use_before_admission",
            Self::CallerExitedBeforeMatch => "caller_exited_before_match",
            Self::PendingFirstUse => "pending_first_use",
            Self::Uncounted(_) => "uncounted",
        }
    }

    /// The reason's detail (`entries.coverage.detail`): the exhausted
    /// resource, or what was lost.
    pub(crate) fn detail(&self) -> Option<&str> {
        match self {
            Self::CapacityLimited(resource) => Some(resource),
            Self::Loss(reason) => Some(reason),
            Self::Uncounted(evidence) => Some(evidence),
            _ => None,
        }
    }

    /// Human wording for snapshots and the dashboard.
    pub(crate) fn text(&self) -> String {
        match self {
            Self::ScanOnly => "scan only".into(),
            Self::NotAdmitted => "not admitted".into(),
            Self::NotAttached => "not attached".into(),
            Self::AttachFailed => "attach failed".into(),
            Self::IdentityUnavailable => "caller identity unavailable".into(),
            Self::ScopeMembershipUnproven => "continuous cgroup membership unproven".into(),
            Self::CapacityLimited(resource) => format!("capacity limited: {resource}"),
            Self::Loss(reason) => format!("loss: {reason}"),
            Self::RetiredBeforeCoverage => "retired before coverage".into(),
            Self::UseBeforeAdmission => "use before admission".into(),
            Self::CallerExitedBeforeMatch => "the caller exited before it could be matched".into(),
            Self::PendingFirstUse => "first use undecided".into(),
            Self::Uncounted(evidence) => format!("uncounted: {evidence}"),
        }
    }
}

/// Per-edge usage coverage: what the edge's usage columns can claim.
/// Published at `publish` from staged producer notes; never inferred from
/// a global flag.
///
/// - `Counted`: a counting feed (actual call observations) covers the
///   edge since `since_ns`; the count and recency are meaningful, and
///   `lossy` says records were lost (a zero is then not a fact).
///   `pid_exit` refines a lossy feed whose sole loss cause is a clean
///   PID-target exit (no records dropped): the count ran until the
///   exit and is a lower bound. Any generic loss clears it.
/// - `Witnessed`: positive use was witnessed (first at `first_ns`); count
///   and recency are unavailable. Never rendered idle.
/// - `WatchedNoUse`: every endpoint of the module is attached for this
///   caller since `since_ns` with clean health, and no use was seen — the
///   zero is a fact; `until_ns` is the last proven-clean instant once the
///   producer stopped (`None` while it runs).
/// - `Unknown`: nothing can be claimed, with the reason.
///
/// Positives (`Counted` entries, `Witnessed`) are monotonic history:
/// they survive loss, retirement, and unload. A global health regression
/// demotes every ongoing `WatchedNoUse` interval to `Unknown`; a new
/// interval may start only from the detecting read on. When the producer
/// stops, each watch ends at the last proven-clean instant (`until_ns`)
/// and stays a frozen fact.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum UseCoverage {
    Counted {
        since_ns: u64,
        lossy: bool,
        /// The lossy feed's sole loss cause is a clean PID-target exit
        /// (implies `lossy`; cleared by any generic loss).
        pid_exit: bool,
    },
    Witnessed {
        first_ns: u64,
    },
    WatchedNoUse {
        since_ns: u64,
        until_ns: Option<u64>,
    },
    Unknown(UnknownReason),
}

impl UseCoverage {
    /// Stable state label (`entries.coverage.state`).
    pub(crate) const fn state(&self) -> &'static str {
        match self {
            Self::Counted { .. } => "counted",
            Self::Witnessed { .. } => "witnessed",
            Self::WatchedNoUse { .. } => "watched_no_use",
            Self::Unknown(_) => "unknown",
        }
    }

    pub(crate) const fn is_witnessed(&self) -> bool {
        matches!(self, Self::Witnessed { .. })
    }
}

/// One coverage note a producer stages for an edge.
#[derive(Debug, Clone, PartialEq, Eq)]
#[cfg_attr(not(test), allow(dead_code))] // Task 6 C3/C5/C6 producers construct it.
pub(crate) enum CoverageNote {
    /// A counting feed covers the edge from `since_ns`.
    Counted { since_ns: u64 },
    /// Every endpoint of the module is attached for this caller from
    /// `since_ns`, with clean health.
    Watched { since_ns: u64 },
    /// The edge's usage is unknown for this reason (an attach failure, a
    /// capacity refusal, …). Never overrides positive history.
    Unknown(UnknownReason),
}

/// The watch half of an edge's coverage (negative evidence).
#[derive(Debug, Clone, Default, PartialEq, Eq)]
enum Watch {
    #[default]
    Unset,
    Watching {
        since_ns: u64,
        /// The last proven-clean instant once the producer stopped; the
        /// interval is then a frozen fact.
        until_ns: Option<u64>,
    },
    Unknown(UnknownReason),
}

/// Staged coverage evidence for one edge: positive history plus the
/// current watch. The published [`UseCoverage`] derives from it.
#[derive(Debug, Clone, Default)]
pub(crate) struct EdgeCoverage {
    counted_since_ns: Option<u64>,
    lossy: bool,
    /// The edge's counted loss is (so far) a clean PID-target exit
    /// only: no generic loss touched it. Implies `lossy`; any generic
    /// loss clears it.
    clean_exit: bool,
    witnessed_first_ns: Option<u64>,
    watch: Watch,
    /// The current watch state is a demotion (a health regression or an
    /// unproven interval): later unknown notes keep its reason. A later
    /// watch note starts a new interval and clears it.
    demoted: bool,
    /// Sticky (R-C51-1): an unbound CALLER_USE row named this caller's
    /// pid, so no watch of this edge can be a fact; it reads
    /// `use_before_admission` and no watch starts again.
    use_before_admission: bool,
}

/// One admission-state change of a retained module (`from` → `to`).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct AdmissionChange {
    pub from: AdmissionState,
    pub to: AdmissionState,
    pub at_ns: u64,
}

/// One caller/module edge: mapping evidence plus cumulative usage.
#[derive(Debug)]
pub(crate) struct EdgeRecord {
    pub caller: CallerId,
    pub module: ModuleId,
    pub mapping: MappingState,
    pub mapping_reason: Option<String>,
    /// How the latest mapping note was established (`mapping.evidence`).
    pub mapping_evidence: MappingEvidence,
    pub mapping_first_seen_ns: u64,
    pub mapping_last_seen_ns: u64,
    /// Transitions from mapped to absent-while-live observed across
    /// passes (unload/reload evidence).
    pub mapping_interruptions: u64,
    pub entry_count: u64,
    pub entry_saturated: bool,
    pub entry_first_seen_ns: Option<u64>,
    pub entry_last_seen_ns: Option<u64>,
    pub entry_in_flight: bool,
    /// The entry count rose during the latest publication (Choice 3):
    /// the per-pass activity signal ("rose since previous pass").
    /// Cleared at each publication's start, set on every strict count
    /// advance; a saturated rest, an equal re-read, and a pass without
    /// counts all read quiet.
    pub entry_rose_since_previous_pass: bool,
    /// Per-edge semantic state (S1): `None` while semantic capture
    /// stays withheld (the scan lane never materializes it), `Some`
    /// once the semantic feed observes this edge. Materialization is
    /// budgeted by `max_semantic_states`; retirement never deletes
    /// the state (its claims are retained evidence).
    pub semantics: Option<EdgeSemantics>,
    /// Same-file double-load latch (F7b): the latest mapping note's
    /// scan evidence showed this object loaded twice in the caller's
    /// process. While set, observed calls establish no claim (they
    /// cannot attribute to one instance); the latch follows the
    /// latest note, so a resolved double-load unlatches.
    pub double_loaded: bool,
    /// Staged usage-coverage evidence (Task 6 C2); the published
    /// [`UseCoverage`] derives from it through
    /// [`CallerRegistry::coverage`].
    pub coverage: EdgeCoverage,
}

/// One module instance: static facts plus lifecycle.
#[derive(Debug, Clone)]
pub(crate) struct ModuleRecord {
    pub id: ModuleId,
    pub key: ModuleKey,
    pub paths: BTreeSet<String>,
    pub build_id: Option<String>,
    pub identity_source: Option<String>,
    pub admission: AdmissionState,
    pub admission_class: Option<String>,
    pub admission_endpoints: Option<usize>,
    pub admission_reasons: Vec<String>,
    /// Admission-state changes after the first verdict, in order. The
    /// state only rises (`unresolved` < `refused` < `admitted`), so this
    /// holds at most two entries.
    pub admission_history: Vec<AdmissionChange>,
    pub lifecycle: ModuleLifecycle,
    /// True once a complete rescan proved the module gone, even if it
    /// later reloaded: unload evidence is retained.
    pub unloaded_observed: bool,
    /// Natively witnessed use no caller edge carries (Task 6 C4): rows the
    /// binder could not bind to a caller incarnation, or bound to one with
    /// no mapping edge. Positive, monotonic, never attributed by pid.
    pub unbound_use: Option<UnboundUse>,
}

/// Module-level positive use from native witness rows that no caller edge
/// carries, with the count per reason code.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub(crate) struct UnboundUse {
    /// Earliest first-association instant among the rows.
    pub first_ns: u64,
    pub rows: u64,
    /// Rows per reason code ([`UnboundReason::code`] or
    /// [`NO_MAPPING_EDGE`]).
    ///
    /// [`UnboundReason::code`]: crate::discovery::native_binding::UnboundReason::code
    pub reasons: BTreeMap<&'static str, u64>,
    /// Folded entry-count lower bound over the single-module rows: each
    /// staged row's held count at drop, saturating. Lower bound — a
    /// refresh read after the drop never merges — and exactly-once per
    /// staged decision, like `rows`. Shared-endpoint and unresolved rows
    /// fold nothing: their counts name no single module.
    pub entries: u64,
    /// Distinct unidentified caller images (slice 1): one entry per
    /// (domain, task cookie) that reached this module's committed
    /// single-module path, each with its historical host pid (Part
    /// C). Cookies never publish: only the count ([`Self::images`]),
    /// the saturation flag, and the host-pid list reach output.
    /// `no_mapping_edge` rows never insert (their caller is known).
    pub(crate) images: HashMap<DomainCookie, UnboundPid>,
    /// The per-module image set hit its bound: [`Self::images`] is a
    /// lower bound. Sticky.
    pub images_saturated: bool,
    /// Distinct images (with their host pids) the per-module bound
    /// turned away, saturating. Sticky.
    pub pids_dropped: u64,
}

impl UnboundUse {
    /// Distinct unidentified caller images on this module (a lower
    /// bound while [`Self::images_saturated`]).
    pub(crate) fn images(&self) -> u64 {
        u64::try_from(self.images.len()).unwrap_or(u64::MAX)
    }

    /// Every collected host pid, oldest first call first (Part C):
    /// one entry per image, never deduplicated, complete while
    /// [`Self::pids_dropped`] is zero.
    pub(crate) fn pids_sorted(&self) -> Vec<UnboundPid> {
        let mut pids: Vec<UnboundPid> = self.images.values().cloned().collect();
        pids.sort_by_key(|pid| (pid.first_call_ns, pid.pid_host));
        pids
    }
}

/// One unidentified caller image's historical host pid (Part C):
/// the kernel tgid (host/init-namespace numbering) of the row that
/// named the image, with the earliest row's first-association
/// instant. Historical only: never the process now holding that
/// number. The pid is a label, never a join key and never re-read
/// through `/proc` for identity — except the executable resolution,
/// which names the image from its EXEC-joined `(dev, ino)` (see
/// [`ExeResolution`]).
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub(crate) struct UnboundPid {
    pub pid_host: u32,
    pub first_call_ns: u64,
    /// Folded entry-count lower bound over this image's rows on the
    /// owning scope (per module, or run-wide): each staged row's
    /// held count at drop, saturating.
    pub calls_at_least: u64,
    pub exe: UnboundExe,
}

/// How one unidentified caller image's executable was named (or why
/// it stays unknown). The join key is always the row's
/// domain-tagged task cookie against the EXEC record's ticket —
/// never a bare PID. JSON vocabulary: [`ExeResolution::json_label`].
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub(crate) enum ExeResolution {
    /// A live process at the image's pid whose start time predates
    /// the EXEC and whose `/proc/<pid>/exe`, opened and mapped
    /// itself, probes to the joined `(dev, ino)`.
    ProcAlive,
    /// An exe identity the scan already learned from an admitted
    /// caller, with the same `(dev, ino)` (re-verified by the
    /// mapping probe).
    ScanLearned,
    /// The lazy system-binary index matched the joined `(dev, ino)`.
    SystemIndex,
    /// A `(dev, ino)` joined but no source named a path for it
    /// (deleted file, container overlay, or a binary outside the
    /// system index).
    PathUnknown,
    /// The EXEC record arrived but its exe pair is `(0, 0)`: the
    /// kernel read failed.
    ExeUnavailable,
    /// No EXEC record joined this image and no lifecycle loss was
    /// observed: the exec predates the capture, the image is a fork
    /// child that never exec'd, or the ticket was unavailable (PID
    /// scope stamps none).
    NoExecRecord,
    /// No EXEC record joined this image while lifecycle evidence
    /// was lost in its domain: the record may be among the loss.
    ExecRecordLost,
}

impl ExeResolution {
    /// Finite JSON vocabulary for `unbound_use.executables[]`.
    pub(crate) const fn json_label(self) -> &'static str {
        match self {
            Self::ProcAlive => "proc_alive",
            Self::ScanLearned => "scan_learned",
            Self::SystemIndex => "system_index",
            Self::PathUnknown => "path_unknown",
            Self::ExeUnavailable => "exe_unavailable",
            Self::NoExecRecord => "no_exec_record",
            Self::ExecRecordLost => "exec_record_lost",
        }
    }

    /// True once a path names the image.
    pub(crate) const fn is_resolved(self) -> bool {
        matches!(
            self,
            Self::ProcAlive | Self::ScanLearned | Self::SystemIndex
        )
    }
}

/// One unidentified caller image's executable: the EXEC-joined
/// `(dev, ino)` pair with its userspace resolution. Invariants: a
/// resolved image carries `Some` path, a nonzero pair, and every
/// distinct canonical spelling that verified to the pair (sorted,
/// primary included, so exactly one entry when unambiguous); an
/// unknown image carries no path and no candidates.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub(crate) struct UnboundExe {
    pub dev: u64,
    pub ino: u64,
    pub path: Option<String>,
    pub resolution: ExeResolution,
    pub identity_candidates: Vec<String>,
}

impl UnboundExe {
    /// True when two or more distinct canonical paths verified to
    /// the same pair: the shown path is kept (never dropped to
    /// unknown) and the ambiguity is disclosed beside it.
    pub(crate) fn identity_ambiguous(&self) -> bool {
        self.identity_candidates.len() > 1
    }
}

/// The unidentified caller image one unbound row names (slice 1):
/// the row's domain-tagged task cookie, with the row's host tgid,
/// first-association instant, folded entries, and resolved
/// executable. Cookies are equality-only and never publish; only
/// counts, host pids, and executables reach output.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub(crate) struct UnboundImage {
    pub cookie: DomainCookie,
    pub pid_host: u32,
    pub first_call_ns: u64,
    pub calls: u64,
    pub exe: UnboundExe,
}

/// Slice-1 bounds for unidentified caller-image sets (LIM-1: never
/// lowered). The per-module bound mirrors the pending-exec-newcomer
/// bound (one entry per retainable caller); the run-wide bound
/// mirrors the kernel ticket budget (cookies never reuse
/// in-capture, so distinct images cannot outnumber minted tickets
/// within one domain). Saturation is a disclosed lower bound, never
/// a refusal.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct UnboundImageLimits {
    pub per_module: usize,
    pub global: usize,
}

/// Default per-module unidentified-image bound (LIM-1).
pub(crate) const DEFAULT_MAX_UNBOUND_IMAGES_PER_MODULE: usize = 4096;
/// Default run-wide unidentified-image bound (LIM-1).
pub(crate) const DEFAULT_MAX_UNBOUND_IMAGES_GLOBAL: usize = 16_384;

impl Default for UnboundImageLimits {
    fn default() -> Self {
        Self {
            per_module: DEFAULT_MAX_UNBOUND_IMAGES_PER_MODULE,
            global: DEFAULT_MAX_UNBOUND_IMAGES_GLOBAL,
        }
    }
}

/// Reason code for a witness bound to a caller incarnation whose edge to
/// the module is not known (no mapping note reached it).
pub(crate) const NO_MAPPING_EDGE: &str = "no_mapping_edge";

const UNBOUND_USE_SUBJECT: &str = "used by an unidentified caller image";
const WITNESS_WITHOUT_MAPPING: &str = "native witness without mapping evidence";
const WITNESS_UNKNOWN_MODULE: &str = "native witness for an unknown module";
pub(crate) const WITNESS_SHARED_ENDPOINT: &str = "ambiguous shared endpoint";
pub(crate) const DEMOTED_COUNT_REJECTED: &str = "rejected demoted count";
pub(crate) const DEMOTED_COUNT_PLACED: &str = "demoted count placed";

/// Where every decided native witness row went, each row exactly once
/// (C4 review M3): `edge` witnessed one caller edge, `module` became one
/// module's `unbound_use` row, `ambiguous` named an endpoint several
/// admitted modules share (no edge, no module-level use), `unresolved`
/// named no registered module. The sum equals the binder census's
/// `bound + unbound`, and `module` equals the sum of every module's
/// `unbound_use.rows`.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub(crate) struct WitnessPlacement {
    pub edge: u64,
    pub module: u64,
    pub ambiguous: u64,
    pub unresolved: u64,
}

/// One publication-time pending-count placement (P3): where the count
/// landed — decided together with its witness, from the same committed
/// state, so the two can never diverge.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct PendingCountDecision {
    /// The coordinator's handle from [`Mutation::NotePendingCount`].
    pub pending_id: u64,
    pub outcome: PendingCountOutcome,
}

/// A copy of one direct count mutation and its resulting published edge total.
/// This carries no pair identity or implication about native ownership.
#[derive(Clone, Copy)]
pub(crate) struct CountPublication {
    pub caller: CallerId,
    pub module: Option<ModuleId>,
    pub staged: u64,
    pub base: u64,
    pub edge_total: Option<u64>,
}

/// A pending count's publication-time outcome (P3).
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum PendingCountOutcome {
    /// Exactly one edged, admitted module took the count (and the
    /// witness): the pair binds there.
    Placed { module: ModuleKey },
    /// The count dropped with its witness (module-level or ambiguous):
    /// the pair finalizes, never to promote later.
    Rejected { reason: PendingRejection },
    /// Exactly one edged module, but it is not admitted: the witness
    /// sits on the edge while the count waits — the pair stays pending
    /// and re-resolves on the next advance (self-healing after
    /// admission, like the placed-count path).
    Unadmitted { module: ModuleKey },
}

/// Why a publication rejected a pending count (P3).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum PendingRejection {
    /// Two or more edged modules (or none of several candidates): the
    /// witness reads ambiguous.
    Ambiguous,
    /// No edged module: the witness went module-level or unresolved.
    NoEdge,
}

/// One bound row's publication-time placement (P3): the shared witness
/// and count verdict from [`CallerRegistry::place_bound_row`].
#[derive(Debug, Clone)]
enum RowPlacement {
    /// Exactly one edged module takes the witness and the count.
    Edge { key: ModuleKey, id: ModuleId },
    /// No edged module, one candidate: module-level use.
    NoMapping { key: ModuleKey },
    /// No candidate at all.
    Unresolved,
    /// Several candidates with no single edge: ambiguous.
    Shared,
}

impl WitnessPlacement {
    #[cfg(test)]
    pub(crate) fn total(&self) -> u64 {
        self.edge + self.module + self.ambiguous + self.unresolved
    }
}

/// One edge's demoted growth this publication (round 4, re-place): the
/// edge's count before this publication's demoted installs plus the
/// growth segments staged for it. Each segment is `(base, absolute)`
/// with the observing read's stamps: the install adds the covered
/// measure (overlaps merge, restages add nothing), so the install is
/// exact no matter how many reads staged before the commit — including
/// a mid-publish rebase, whose disjoint segments all accumulate.
#[derive(Debug, Clone, Default)]
struct DemotedGrowth {
    base_edge: u64,
    segments: Vec<(u64, u64, u64, u64)>,
}

impl DemotedGrowth {
    /// The covered growth: the union measure of `(base, absolute)`.
    fn total(&self) -> u64 {
        let mut spans: Vec<(u64, u64)> = self
            .segments
            .iter()
            .map(|&(base, abs, _, _)| (base, abs))
            .collect();
        spans.sort();
        let mut total = 0u64;
        let mut covered = 0u64;
        for (base, abs) in spans {
            if abs > covered {
                total = total.saturating_add(abs - base.max(covered));
                covered = covered.max(abs);
            }
        }
        total
    }

    /// The stamps of the furthest-reaching segment (ties: latest).
    fn stamps(&self) -> (u64, u64) {
        let mut best = (0u64, 0u64, 0u64);
        for &(_, abs, first_ns, last_ns) in &self.segments {
            if abs >= best.0 {
                best = (abs, first_ns, last_ns);
            }
        }
        (best.1, best.2)
    }
}

/// One budget refusal, carried structurally so the rendered gap names
/// the resource, its limit, and the requested occupancy — never a bare
/// sentence a reader must parse.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub(crate) struct BudgetRefusal {
    pub resource: &'static str,
    pub limit: usize,
    pub requested: usize,
}

/// One explicit coverage gap: what is unknown and why. Never silent
/// absence.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub(crate) struct RegistryGap {
    pub caller: Option<CallerId>,
    pub module: Option<ModuleId>,
    pub pid: Option<u32>,
    pub subject: String,
    pub reason: String,
    /// `Some` exactly when the gap records a budget refusal.
    pub budget: Option<BudgetRefusal>,
}

/// Named cap for cumulative per-edge entry counts. Addition saturates
/// and sets the edge's saturation flag — counts never wrap silently.
pub(crate) const MAX_EDGE_ENTRY_COUNT: u64 = u64::MAX;

/// What every edge's semantic column reads while capture stays
/// withheld (S-track): unknown, never an invented state.
pub(crate) const SEMANTIC_UNKNOWN: &str = "unknown (semantic capture withheld)";

fn with_key(mut reason: String, module: Option<ModuleId>, key: &ModuleKey) -> String {
    if module.is_none() {
        reason.push_str(&key.gap_suffix());
    }
    reason
}

/// Bound on remembered suppressed gaps (see `push_gap`).
pub(crate) const MAX_SUPPRESSED_GAP_MEMORY: usize = 4096;

const COVERAGE_WITHOUT_MAPPING: &str = "usage coverage without mapping evidence";
const PAIRS_UNCOUNTED_SUBJECT: &str = "usage coverage pair insert failure";
const COVERAGE_UNADMITTED: &str = "coverage for an unadmitted module";

/// Bound on one module's admission reasons: ignored lower verdicts append
/// here (deduplicated) until the bound, never growing per pass.
pub(crate) const MAX_ADMISSION_REASONS: usize = 8;

/// Default retained-table bounds. Exhaustion drops the association and
/// records a gap — never an eviction that rewrites published history.
pub(crate) const DEFAULT_MAX_CALLERS: usize = 4096;
pub(crate) const DEFAULT_MAX_MODULES: usize = 4096;
pub(crate) const DEFAULT_MAX_EDGES: usize = 32768;
pub(crate) const DEFAULT_MAX_GAPS: usize = 1024;
/// Stop-time gap headroom above the bound: in-run gaps keep the full
/// `max_gaps`, and terminal gaps (staged after
/// [`CallerRegistry::enter_terminal_phase`]) may use up to `max_gaps +
/// TERMINAL_GAP_RESERVE` rows, so terminal disclosures staged last are
/// never crowded out by a per-drain flood (a full-suite run retained
/// 746 per-drain unrouted rows and suppressed every terminal gap).
/// Measured terminal need is ~15 rows (post-pass newcomers, short-lived
/// count, pre-arm close, winding, terminal commits, joint finish); 64 is
/// 4x with headroom for future terminal disclosures. A bounded raise of
/// the stop-time retention ceiling (LIM-1 allows raises, never lowerings).
pub(crate) const TERMINAL_GAP_RESERVE: usize = 64;
/// Hard ceiling for the `--max-gaps` CLI knob (CLI input guard only;
/// [`RegistryLimits::new`] still accepts any non-zero bound). This caps
/// the retained RECORD COUNT, not bytes: subjects keep full /proc paths
/// and reasons are short templates, so worst-case bytes scale with path
/// length (low tens of megabytes at typical short paths). 65_536 exceeds
/// any plausible ambient flood (measured ~1.5K) by 40x.
pub(crate) const MAX_MAX_GAPS: usize = 65_536;
/// Default bound on the retained attach-endpoint census: the sum of
/// admitted per-module endpoint counts. A retained-census bound, not an
/// attach bound — 4096 modules at up to 256 endpoints each.
pub(crate) const DEFAULT_MAX_ENDPOINTS: usize = 1_048_576;
/// Default bound on retained semantic states (one per edge, the S-track
/// shape). The budget exists now; capture stays withheld, so occupancy
/// is always zero and every semantic column renders unknown.
pub(crate) const DEFAULT_MAX_SEMANTIC_STATES: usize = 32768;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct RegistryLimits {
    pub max_callers: usize,
    pub max_modules: usize,
    pub max_edges: usize,
    pub max_gaps: usize,
    pub max_endpoints: usize,
    pub max_semantic_states: usize,
}

impl RegistryLimits {
    pub(crate) fn new(
        max_callers: usize,
        max_modules: usize,
        max_edges: usize,
        max_gaps: usize,
        max_endpoints: usize,
        max_semantic_states: usize,
    ) -> Result<Self> {
        if max_callers == 0
            || max_modules == 0
            || max_edges == 0
            || max_gaps == 0
            || max_endpoints == 0
            || max_semantic_states == 0
        {
            bail!("caller registry limits must be non-zero");
        }
        Ok(Self {
            max_callers,
            max_modules,
            max_edges,
            max_gaps,
            max_endpoints,
            max_semantic_states,
        })
    }

    pub(crate) fn default_limits() -> Self {
        Self::new(
            DEFAULT_MAX_CALLERS,
            DEFAULT_MAX_MODULES,
            DEFAULT_MAX_EDGES,
            DEFAULT_MAX_GAPS,
            DEFAULT_MAX_ENDPOINTS,
            DEFAULT_MAX_SEMANTIC_STATES,
        )
        .expect("default registry limits are non-zero")
    }
}

/// Outcome of feeding one observed entry batch.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum EntryOutcome {
    /// Recorded (count, recency, or saturation flag advanced).
    Recorded,
    /// The caller retired: counts are frozen, the batch was dropped.
    FrozenRetired,
    /// No mapping edge exists for the pair: entries never invent
    /// mappings, so the batch was dropped and a gap staged.
    UnknownEdge,
}

#[derive(Debug)]
#[allow(clippy::large_enum_variant)] // H7 slice D: the semantic observation carries the 240 B validated object tail inline to its drop point; mutations stay allocation-free.
enum Mutation {
    NoteInstance(AdmittedInstance),
    ObserveInstanceSemantic(AdmittedInstanceCall),
    InstanceSemanticLoss(InstanceSemanticLoss),
    RetireInstance(InstanceRetirement),
    NoteMapping {
        caller: CallerId,
        pid: u32,
        info: ModuleInfo,
        evidence: MappingEvidence,
        at_ns: u64,
    },
    #[allow(dead_code)] // Privileged BPF usage-feed seam.
    ObserveEntries {
        caller: CallerId,
        module: ModuleKey,
        delta: u64,
        at_ns: u64,
    },
    #[allow(dead_code)] // Privileged BPF usage-feed seam.
    SetInFlight {
        caller: CallerId,
        module: ModuleKey,
        in_flight: bool,
    },
    ObserveSemantic {
        caller: CallerId,
        module: ModuleKey,
        call: SemanticCall,
    },
    NoteSemanticLoss {
        reason: String,
    },
    NoteRefreshLoss {
        reason: String,
    },
    /// The capture scope went unproven (lifecycle evidence or scope
    /// custody lost): bound-pair growth stages nothing more (pending
    /// first-sight installs still land, now `lossy`), so every counted
    /// column is a lower bound. The lifecycle/custody gap discloses
    /// the cause; this carries no second gap.
    NoteCountedLoss,
    /// The PID target exited cleanly: same staging as `NoteCountedLoss`,
    /// but the sole cause is the exit (no records dropped), so counted
    /// columns name it until a generic loss clears the claim.
    NoteCountedPidExit,
    NoteWitness {
        caller: CallerId,
        module: ModuleKey,
        first_ns: u64,
    },
    NoteBoundWitness {
        caller: CallerId,
        modules: Vec<ModuleKey>,
        first_ns: u64,
    },
    NoteUnboundWitness {
        modules: Vec<ModuleKey>,
        first_ns: u64,
        reason: UnboundReason,
        entries: u64,
        /// The row's unidentified image, when the stager knows it.
        /// `None` never inserts (test-direct staging, and the
        /// `no_mapping_edge` path whose caller is known).
        image: Option<UnboundImage>,
    },
    NoteUnresolvedWitness,
    NoteUseBeforeAdmission {
        caller: CallerId,
        /// `None`: every edge of the caller.
        module: Option<ModuleKey>,
        /// `UseBeforeAdmission`, or `Loss` for a row lifecycle loss left
        /// unbound.
        reason: UnknownReason,
    },
    NoteWitnessCensus {
        census: BindingCensus,
    },
    NoteCoverage {
        caller: CallerId,
        module: ModuleKey,
        note: CoverageNote,
    },
    NoteCountedUse {
        caller: CallerId,
        module: ModuleKey,
        /// The pair's absolute saturating lower bound (never a delta:
        /// several reads stage before one commit, so only the maximum
        /// is sound) — or, when `base` is nonzero, growth past that
        /// accounted base. Growth stagings accumulate by covered
        /// segment, so restages never double-count and disjoint
        /// segments (a mid-publish rebase) never lose.
        count: u64,
        /// The pair's first record (`recorded_at_ns`) — or, for
        /// growth, the observing read (growth never inherits the
        /// pair's backdated first sight).
        first_ns: u64,
        /// The read that observed `count` (`rows_read_ns`): pass
        /// resolution, never a BPF timestamp.
        last_ns: u64,
        /// The accounted absolute the count rebases past (round 4,
        /// re-place): nonzero growth accumulates onto the edge instead
        /// of installing absolute. 0 installs absolute (first sight).
        base: u64,
    },
    NotePendingCount {
        /// The coordinator's opaque handle, echoed in the decision.
        pending_id: u64,
        caller: CallerId,
        /// The candidate modules (the witness's): placement resolves at
        /// publication, alongside the witness, against the mappings this
        /// same publication commits.
        modules: Vec<ModuleKey>,
        count: u64,
        first_ns: u64,
        last_ns: u64,
        /// The read that observed `base` (round 4, window anchor): a
        /// placement windows its coverage from there.
        since_ns: u64,
        /// The accounted absolute the count rebases past (0 for a
        /// first-sight pair): a nonzero base marks a re-resolved pair,
        /// whose rejection the publication discloses (F3-02) and whose
        /// placement accumulates by segment.
        base: u64,
    },
    NotePairsUncounted {
        reason: Arc<str>,
        at_ns: u64,
    },
    NoteHealthRegression {
        subject: &'static str,
        reason: Arc<str>,
        at_ns: u64,
        detected_ns: u64,
        /// The producer may watch again from `detected_ns` on (a health
        /// rise); false when it never does (a sticky demotion, C5.2 D4).
        restartable: bool,
    },
    EndWatches {
        reason: Arc<str>,
        at_ns: u64,
    },
    RetireCaller {
        caller: CallerId,
        reason: String,
        at_ns: u64,
    },
    NoteModuleAbsent {
        caller: CallerId,
        module: ModuleId,
        complete_scan: bool,
        at_ns: u64,
    },
    NoteMemberUnscanned {
        caller: CallerId,
    },
    RecordGap {
        gap: RegistryGap,
        /// `terminal_phase` captured at stage time: a gap staged before
        /// the stop keeps the plain bound even when its publication lands
        /// after the phase flips, so a staged per-drain flood can never
        /// consume the stop-time headroom.
        terminal: bool,
    },
    RecordKeyedGap {
        /// The module key, resolved to an ID at apply time — after the
        /// publication's mappings commit (F3-04).
        key: ModuleKey,
        caller: Option<CallerId>,
        pid: Option<u32>,
        subject: String,
        reason: String,
        budget: Option<BudgetRefusal>,
        /// `terminal_phase` captured at stage time (see `RecordGap`).
        terminal: bool,
    },
    RecordAggregatedUnrouted {
        /// One drain's shed calls for an aggregated per-drain
        /// unrouted subject: summed into the (subject, bindings)
        /// row at apply time, never one row per drain.
        subject: String,
        total: u64,
        labels: Vec<(String, u64)>,
        bindings: usize,
        /// `terminal_phase` captured at stage time (see `RecordGap`).
        terminal: bool,
    },
}

/// A publication is applied but its original frame has not finished. This
/// refusal carries no evidence and permits neither replay nor acknowledgement.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct JointPublicationPending;

/// Diagnostic settlement-latency histogram buckets: 1 ms linear
/// buckets over [0, 10 s), plus overflow. The 1 ms resolution is the
/// measurement's stated resolution against the 250 ms budget.
pub(crate) const SETTLEMENT_LATENCY_BUCKETS: usize = 10_000;
/// Bucket width in nanoseconds.
const SETTLEMENT_LATENCY_BUCKET_NS: u64 = 1_000_000;

/// Diagnostic per-call settlement delay: ENTRY timestamp (the
/// record's `ts_ns` on the ktime/CLOCK_MONOTONIC basis) to registry
/// application, histogrammed in 1 ms buckets. ENTRY precedes END by
/// the call's own duration (microseconds for the throughput
/// providers), so ENTRY-based delays overstate END-based settlement
/// by that negligible amount; plumbing END would cost a field on
/// every admitted call for no verdict change at 250 ms. Counts
/// only, never identities: the histogram cannot name a call.
/// Allocated only while the diagnostic toggle enables it.
pub(crate) struct SettlementLatencyHist {
    buckets: Box<[u64; SETTLEMENT_LATENCY_BUCKETS]>,
    overflow: u64,
    unknown_ts: u64,
    samples: u64,
    max_ms: u64,
}

/// Cumulative settlement-latency summary for the stop line.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub(crate) struct SettlementLatencySummary {
    pub samples: u64,
    /// Smallest ms `m` with at least `ceil(q * samples)` samples at
    /// or below `m`, treating overflow as +infinity; when the rank
    /// falls in overflow the percentile is `max_ms` (a finite upper
    /// bound) with `overflow > 0` disclosing it. `None` without samples.
    pub p50_ms: Option<u64>,
    pub p99_ms: Option<u64>,
    pub max_ms: u64,
    pub overflow: u64,
    pub unknown_ts: u64,
}

impl SettlementLatencyHist {
    pub(crate) fn new() -> Self {
        Self {
            buckets: Box::new([0; SETTLEMENT_LATENCY_BUCKETS]),
            overflow: 0,
            unknown_ts: 0,
            samples: 0,
            max_ms: 0,
        }
    }

    /// Record one applied call's ENTRY-to-application delay. A zero
    /// timestamp (scripted calls, or a failed clock read on either
    /// side) carries no delay and counts unknown instead.
    pub(crate) fn record(&mut self, ts_ns: u64, now_ns: u64) {
        if ts_ns == 0 || now_ns == 0 {
            self.unknown_ts = self.unknown_ts.saturating_add(1);
            return;
        }
        let ms = now_ns.saturating_sub(ts_ns) / SETTLEMENT_LATENCY_BUCKET_NS;
        if let Some(bucket) = self.buckets.get_mut(ms as usize) {
            *bucket = bucket.saturating_add(1);
        } else {
            self.overflow = self.overflow.saturating_add(1);
        }
        self.samples = self.samples.saturating_add(1);
        self.max_ms = self.max_ms.max(ms);
    }

    fn percentile(&self, numerator: u64, denominator: u64) -> Option<u64> {
        if self.samples == 0 {
            return None;
        }
        // 1-based rank: ceil(q * n), saturating (n > 0 here).
        let rank = self
            .samples
            .saturating_mul(numerator)
            .saturating_add(denominator - 1)
            / denominator;
        let rank = rank.max(1);
        let mut cumulative = 0u64;
        for (ms, count) in self.buckets.iter().enumerate() {
            cumulative = cumulative.saturating_add(*count);
            if cumulative >= rank {
                return Some(ms as u64);
            }
        }
        // The rank falls in overflow: max_ms bounds it above, and
        // the disclosed overflow count says the bound is loose.
        Some(self.max_ms)
    }

    pub(crate) fn summary(&self) -> SettlementLatencySummary {
        SettlementLatencySummary {
            samples: self.samples,
            p50_ms: self.percentile(1, 2),
            p99_ms: self.percentile(99, 100),
            max_ms: self.max_ms,
            overflow: self.overflow,
            unknown_ts: self.unknown_ts,
        }
    }
}

struct AppliedJointPublication {
    identity: RawQuantumIdentity,
    frontier: Option<ConsumptionOrdinal>,
    base_revision: u64,
    // Borrow labels only from the physical inputs actually prepared for this
    // original. Semantic staging and later arrivals cannot widen the prefix.
    physical_prefix_end: Option<usize>,
    applied: Option<usize>,
    targets_bound: bool,
    _storage: crate::semantics_edge::resources::ResourceLease,
}

/// One aggregated per-drain unrouted subject: summed shed calls
/// and per-label counts across drains, with the retained row's
/// index once it lands. Keyed by (subject, bindings) so
/// pre-binding (`with 0 bindings`) sheds stay separable from
/// bound drains for the pre-binding forgiveness accounting.
struct UnroutedAggregate {
    total: u64,
    labels: BTreeMap<String, u64>,
    gap_index: Option<usize>,
}

/// Format an aggregated unrouted reason with the exact
/// single-drain template: `{total} calls shed without a route
/// ({label}={count} ...) with/from ...`. Labels sort by name
/// (BTreeMap order), matching the drain formatter. Unknown
/// subjects fall back to the `with {N} bindings` template; only
/// the two unrouted subjects aggregate.
fn aggregated_unrouted_reason(
    subject: &str,
    total: u64,
    labels: &BTreeMap<String, u64>,
    bindings: usize,
) -> String {
    let mut parts: Vec<String> = labels
        .iter()
        .map(|(label, count)| format!("{label}={count}"))
        .collect();
    parts.sort();
    let labels = parts.join(" ");
    if subject == "semantic calls unrouted from other callers" {
        format!(
            "{total} calls shed without a route ({labels}) from callers other than the {bindings} bound callers"
        )
    } else {
        format!("{total} calls shed without a route ({labels}) with {bindings} bindings")
    }
}

/// Staged physical and semantic inputs share one publication revision.
pub(crate) struct CallerRegistry {
    semantic_resources: crate::semantics_edge::resources::SemanticResourcePool,
    instance_state: instance_input::InstanceState,
    limits: RegistryLimits,
    next_module: u32,
    callers: BTreeSet<CallerId>,
    retired: BTreeMap<CallerId, String>,
    modules: BTreeMap<ModuleId, ModuleRecord>,
    modules_by_key: BTreeMap<ModuleKey, ModuleId>,
    edges: BTreeMap<(CallerId, ModuleId), EdgeRecord>,
    gaps: Vec<RegistryGap>,
    /// Parallel to `gaps`: how many times each retained gap was recorded
    /// this run (>= 1).
    gap_repeats: Vec<u64>,
    /// Retained gap -> its index in `gaps`: the run-wide dedupe key.
    gap_index: HashMap<RegistryGap, usize>,
    /// Distinct gaps already counted as suppressed (bounded by
    /// `MAX_SUPPRESSED_GAP_MEMORY`), so a suppressed gap that recurs every
    /// pass is counted once.
    suppressed_seen: HashSet<u64>,
    /// Randomly keyed, so a target cannot steer fingerprint collisions.
    suppressed_hasher: std::hash::RandomState,
    gaps_suppressed: u64,
    /// Aggregated per-drain unrouted sheds by (subject, bindings):
    /// repeated drains sum into one counted row instead of one row
    /// per distinct shed count. Bounded by distinct (subject,
    /// bindings) pairs (two subjects, few bindings counts).
    unrouted_aggregates: HashMap<(String, usize), UnroutedAggregate>,
    /// Aggregated subjects already counted as suppressed: a
    /// suppressed aggregate counts once, not once per merged drain.
    suppressed_aggregates: HashSet<(String, usize)>,
    /// Terminal/stop-time phase: set once the lane stops. Gaps staged
    /// from now on carry the terminal flag and may use the headroom
    /// above the bound; gaps staged before it keep the plain bound
    /// even when their publication lands after the flip.
    terminal_phase: bool,
    staged: Vec<Mutation>,
    /// One retained phase over the existing staging vector, never a second
    /// queue. New staged inputs belong to the next publication.
    joint_publication: Option<AppliedJointPublication>,
    /// Why an edge no producer covered reads unknown: `ScanOnly` until a
    /// native usage producer runs (Task 6 C5 sets `NotAttached`).
    uncovered_reason: UnknownReason,
    /// Detection instant of the last global health regression: a new
    /// watch interval never starts before it.
    last_health_regression_ns: Option<u64>,
    /// The producer stopped: every watch ended here and none starts.
    watches_ended_ns: Option<u64>,
    /// The capture scope went unproven (lifecycle evidence or scope
    /// custody lost): bound-pair growth stages nothing more (pending
    /// first-sight installs still land, now `lossy`), so every counted
    /// column is a lower bound — set by `NoteCountedLoss`, sticky for
    /// the capture, and honored by every later counted install and
    /// `Counted` note, including edges born after the loss.
    counted_loss: bool,
    /// The sticky counted loss is (so far) a clean PID-target exit
    /// only: set by `NoteCountedPidExit` when no loss of any kind came
    /// before, cleared by any generic loss (counted, refresh, or
    /// semantic). Honored alongside `counted_loss` for later installs.
    counted_clean_exit: bool,
    /// A generic counted loss (counted, refresh, or semantic) was ever
    /// staged. Refresh and semantic losses leave `counted_loss` alone
    /// (their scope is existing edges, not later installs), but they
    /// still void any exit-only claim, past and future.
    counted_generic_loss: bool,
    /// Coverage-note gaps already recorded, once per (caller, module,
    /// subject); bounded by the gap retention bound (past it the gap
    /// list is full and further gaps only count as suppressed).
    coverage_gap_memo: BTreeSet<(CallerId, ModuleKey, &'static str)>,
    /// Module-level witness gaps already recorded, once per (module,
    /// subject); bounded like `coverage_gap_memo`.
    witness_gap_memo: BTreeSet<(ModuleKey, &'static str)>,
    /// The native binder's latest census (published with the batch).
    witness_census: BindingCensus,
    /// Where decided witness rows went (published with the batch).
    witness_placement: WitnessPlacement,
    /// Bounds for unidentified caller-image sets (slice 1, LIM-1).
    /// `pub(crate)` so tests shrink them; production keeps defaults.
    pub(crate) unbound_image_limits: UnboundImageLimits,
    /// Run-wide distinct unidentified caller images (slice 1): the
    /// union of committed single-module inserts, each with its
    /// historical host pid (Part C). Cookies never publish: only
    /// the count, the saturation flag, and the host-pid list reach
    /// output.
    unidentified_images: HashMap<DomainCookie, UnboundPid>,
    /// The run-wide image set hit its bound: the published count is a
    /// lower bound. Sticky.
    unidentified_images_saturated: bool,
    /// Distinct images (with their host pids) the run-wide bound
    /// turned away, saturating. Sticky.
    unidentified_pids_dropped: u64,
    /// Pending-count placements the last publication decided, in apply
    /// order (P3): drained by the coordinator after each publish.
    pending_count_decisions: Vec<PendingCountDecision>,
    /// Demoted growth staged per edge this publication (round 4,
    /// re-place): cleared at every `publish`.
    demoted_place_growth: HashMap<(CallerId, ModuleId), DemotedGrowth>,
    facts_revision: u64,
    published_revision: u64,
    endpoints_total: usize,
    callers_refused: u64,
    modules_refused: u64,
    edges_refused: u64,
    endpoints_refused: u64,
    /// Edges with materialized semantic state (monotonic: edges are
    /// never deleted and state is never withdrawn).
    semantic_occupied: usize,
    /// Semantic keys refused: materializations past
    /// `max_semantic_states` plus per-edge keys past the S1 bounds.
    semantic_refused: u64,
    /// Installed Joint feed receipts by instance key (guarded H9
    /// path): consumed once at registration; empty in production
    /// (no live grants), so every feed stays S1Only. Bounded by the
    /// instance limit.
    joint_grants: HashMap<instance_input::InstanceKey, instance_input::PendingJointGrant>,
    joint_grant_allocation: instance_input::JointGrantTableAllocation,
    // The map and copied-key wrappers drop before retained bucket storage.
    joint_grant_storage: Option<crate::semantics_edge::resources::ResourceLease>,
    /// Capture-wide key-use reducer (guarded H9 path): once Joint
    /// accounting starts, S1Only siblings and later terminals keep
    /// contributing facts for the rest of the capture.
    joint_keyuse: crate::semantics_key_use::KeyUseReducer,
    /// Prospective-association fallback ledger (N1c): ledger-less
    /// publications charge their key-use opens here; ledger-bearing
    /// publications use the supplied shared owner. Each association
    /// returns its ticket to the owner which minted it.
    assoc_fallback: crate::semantics_objects::journal::StagingLedger,
    /// Current Joint-mode feeds; feeds may permanently fall back.
    joint_feeds: usize,
    /// Capture-lifetime accounting latch, set by a true Joint
    /// registration. Independent of object publication authority:
    /// ordered fallback can create opens before any seal arrives.
    joint_accounting: bool,
    /// Last H8 projection retained at seal/failure delivery: capture
    /// commits from it; `None` names `bootstrap_unavailable`.
    key_projection: Option<crate::semantics_objects::ObjectProjection>,
    /// Joint calls reduced S1Only-direct for lack of H8 staging
    /// (no ledger supplied, or the shared ledger refused): S1
    /// preserved, Joint evidence absent for those calls.
    joint_direct_fallback: u64,
    /// Calls shed unrouted after S1 proved a caller other than
    /// every bound one: counted as foreign not-attributed beside
    /// the bound callers' key-operation rows.
    foreign_unrouted_calls: u64,
    /// Diagnostic settlement-latency histogram (`None` unless the
    /// diagnostic toggle enables it): per-applied-call
    /// ENTRY-to-application delay. Boxed and absent by default, so
    /// the default registry pays one branch per applied call.
    settlement_latency: Option<Box<SettlementLatencyHist>>,
    /// Per-module observed `C_Initialize` returns since the semantic
    /// lane sealed, sparse: only modules with a tapped return hold an
    /// entry, so the table never exceeds the admitted module count.
    module_init: BTreeMap<ModuleId, module_init::ModuleInitRollup>,
    /// Latched when the run's semantic lane seals: taps and the
    /// honest absence wording exist only past the seal.
    semantic_sealed: bool,
}

impl CallerRegistry {
    pub(crate) fn semantic_storage_reserver(&self) -> SemanticResourceReserver {
        self.semantic_resources.reserver()
    }

    /// Provider copies and their retained containers share the reducers' one
    /// capture-wide pool. The move-only lease follows the actual allocation.
    pub(crate) fn reserve_semantic_storage(
        &self,
        bytes: usize,
    ) -> Result<
        crate::semantics_edge::resources::ResourceLease,
        crate::semantics_edge::resources::SemanticResourceRefusal,
    > {
        self.semantic_resources.reserve(bytes)
    }

    pub(crate) fn semantic_resource_snapshot(
        &self,
    ) -> crate::semantics_edge::resources::SemanticResourceSnapshot {
        self.semantic_resources.snapshot()
    }

    /// Shrink the pool to `room` bytes above its current charges, which
    /// stay owned by the capture itself (no outside lease).
    #[cfg(test)]
    pub(crate) fn clamp_semantic_resource_room_for_test(&self, room: usize) {
        let charged = self.semantic_resources.snapshot().charged_bytes;
        self.semantic_resources.reference_set_limit(charged + room);
    }

    #[cfg(test)]
    pub(crate) fn reference_semantic_resource_limit(&mut self, limit: usize) {
        assert_eq!(
            self.semantic_occupied + self.instance_semantic_occupied(),
            0
        );
        self.semantic_resources.reference_set_limit(limit);
    }

    pub(crate) fn new(limits: RegistryLimits) -> Self {
        let semantic_resources = crate::semantics_edge::resources::SemanticResourcePool::default();
        let assoc_fallback = crate::semantics_objects::journal::StagingLedger::with_resources(
            semantic_resources.reserver(),
        );
        Self {
            semantic_resources,
            instance_state: instance_input::InstanceState::default(),
            limits,
            next_module: 0,
            callers: BTreeSet::new(),
            retired: BTreeMap::new(),
            modules: BTreeMap::new(),
            modules_by_key: BTreeMap::new(),
            edges: BTreeMap::new(),
            gaps: Vec::new(),
            gap_repeats: Vec::new(),
            gap_index: HashMap::new(),
            suppressed_seen: HashSet::new(),
            suppressed_hasher: std::hash::RandomState::new(),
            gaps_suppressed: 0,
            unrouted_aggregates: HashMap::new(),
            suppressed_aggregates: HashSet::new(),
            terminal_phase: false,
            staged: Vec::new(),
            joint_publication: None,
            uncovered_reason: UnknownReason::ScanOnly,
            last_health_regression_ns: None,
            watches_ended_ns: None,
            counted_loss: false,
            counted_clean_exit: false,
            counted_generic_loss: false,
            coverage_gap_memo: BTreeSet::new(),
            witness_gap_memo: BTreeSet::new(),
            witness_placement: WitnessPlacement::default(),
            unbound_image_limits: UnboundImageLimits::default(),
            unidentified_images: HashMap::new(),
            unidentified_images_saturated: false,
            unidentified_pids_dropped: 0,
            pending_count_decisions: Vec::new(),
            demoted_place_growth: HashMap::new(),
            witness_census: BindingCensus::default(),
            facts_revision: 1,
            published_revision: 0,
            endpoints_total: 0,
            callers_refused: 0,
            modules_refused: 0,
            edges_refused: 0,
            endpoints_refused: 0,
            semantic_occupied: 0,
            semantic_refused: 0,
            joint_grants: HashMap::new(),
            joint_grant_allocation: instance_input::JointGrantTableAllocation::for_entries(0)
                .expect("empty grant table has no allocation"),
            joint_grant_storage: None,
            joint_keyuse: crate::semantics_key_use::KeyUseReducer::new(),
            assoc_fallback,
            joint_feeds: 0,
            joint_accounting: false,
            key_projection: None,
            joint_direct_fallback: 0,
            foreign_unrouted_calls: 0,
            settlement_latency: None,
            module_init: BTreeMap::new(),
            semantic_sealed: false,
        }
    }

    /// Count calls shed unrouted from a provably other caller.
    pub(crate) fn note_foreign_unrouted_calls(&mut self, count: u64) {
        self.foreign_unrouted_calls = self.foreign_unrouted_calls.saturating_add(count);
    }

    /// Calls shed unrouted from provably other callers, lifetime.
    #[cfg_attr(not(test), allow(dead_code))]
    pub(crate) fn foreign_unrouted_calls(&self) -> u64 {
        self.foreign_unrouted_calls
    }

    /// Fold one observed `C_Initialize` return into a module's
    /// roll-up. The finalizer taps joined (converted) and shed
    /// Events; both flow only past the lane seal.
    pub(crate) fn note_module_init(&mut self, module: ModuleId, rv: u64) {
        self.module_init.entry(module).or_default().note(rv);
    }

    /// One module's init roll-up: zeros when nothing tapped it.
    pub(crate) fn module_init_rollup(&self, module: ModuleId) -> module_init::ModuleInitRollup {
        self.module_init.get(&module).copied().unwrap_or_default()
    }

    /// Latch the run's semantic seal: from now on init returns are
    /// recorded, and a quiet module honestly reads unseen.
    pub(crate) fn set_semantic_sealed(&mut self) {
        self.semantic_sealed = true;
    }

    /// Whether the run's semantic lane sealed.
    pub(crate) fn semantic_sealed(&self) -> bool {
        self.semantic_sealed
    }

    /// Whether run-wide EVENTS loss (or an unreadable loss counter)
    /// may have hidden init evidence: init verdicts without observed
    /// proof read unknown then.
    pub(crate) fn semantic_events_lossy(&self) -> bool {
        self.gaps.iter().any(|gap| {
            gap.subject == module_init::NATIVE_EVENTS_LOST
                || gap.subject == module_init::NATIVE_EVENTS_LOSS_UNKNOWN
        })
    }

    /// Enable or disable the diagnostic settlement-latency
    /// histogram. Enabling allocates the buckets; disabling drops
    /// them with their samples. Default off.
    pub(crate) fn set_diagnostic_settlement_latency(&mut self, on: bool) {
        if on {
            if self.settlement_latency.is_none() {
                self.settlement_latency = Some(Box::new(SettlementLatencyHist::new()));
            }
        } else {
            self.settlement_latency = None;
        }
    }

    /// The cumulative settlement-latency summary, when enabled.
    pub(crate) fn settlement_latency_summary(&self) -> Option<SettlementLatencySummary> {
        self.settlement_latency
            .as_deref()
            .map(SettlementLatencyHist::summary)
    }

    /// Why edges no producer covered read unknown. The scan lane leaves
    /// `ScanOnly`; the native lane (Task 6 C5) sets `NotAttached`. This
    /// only names the reason — it never makes a zero read observed.
    #[cfg_attr(not(test), allow(dead_code))] // Task 6 C5 native lane.
    pub(crate) fn set_uncovered_reason(&mut self, reason: UnknownReason) {
        self.uncovered_reason = reason;
    }

    /// Tests-only reference wiring (N1): bind one module key to one
    /// caller edge, retained exactly as a mapped admission would
    /// leave it. Skips admission verdicts: the guarded-path tests
    /// prove feed selection, not admission.
    #[cfg(test)]
    pub(crate) fn scripted_module_edge(&mut self, key: ModuleKey, caller: CallerId) -> ModuleId {
        let module = self.modules_by_key.get(&key).copied().unwrap_or_else(|| {
            let id = ModuleId(self.next_module);
            self.next_module = self.next_module.saturating_add(1);
            let mut paths = BTreeSet::new();
            paths.insert("/scripted/driver.so".to_string());
            self.modules.insert(
                id,
                ModuleRecord {
                    id,
                    key: key.clone(),
                    paths,
                    build_id: None,
                    identity_source: None,
                    admission: AdmissionState::Admitted,
                    admission_class: None,
                    admission_endpoints: None,
                    admission_reasons: Vec::new(),
                    admission_history: Vec::new(),
                    lifecycle: ModuleLifecycle::Mapped,
                    unloaded_observed: false,
                    unbound_use: None,
                },
            );
            self.modules_by_key.insert(key, id);
            id
        });
        self.edges.insert(
            (caller, module),
            EdgeRecord {
                caller,
                module,
                mapping: MappingState::Mapped,
                mapping_reason: None,
                mapping_evidence: MappingEvidence::DeepScan,
                mapping_first_seen_ns: 0,
                mapping_last_seen_ns: 0,
                mapping_interruptions: 0,
                entry_count: 0,
                entry_saturated: false,
                entry_first_seen_ns: None,
                entry_last_seen_ns: None,
                entry_in_flight: false,
                entry_rose_since_previous_pass: false,
                semantics: None,
                double_loaded: false,
                coverage: EdgeCoverage::default(),
            },
        );
        module
    }

    /// Derived summary only: true when at least one edge holds usage
    /// coverage (counted, witnessed, or watched). Never an input to any
    /// edge's coverage.
    pub(crate) fn usage_feed(&self) -> bool {
        self.edges
            .values()
            .any(|edge| !matches!(self.coverage(edge), UseCoverage::Unknown(_)))
    }

    pub(crate) fn facts_revision(&self) -> u64 {
        self.facts_revision
    }

    pub(crate) fn published_revision(&self) -> u64 {
        self.published_revision
    }

    pub(crate) fn modules(&self) -> impl Iterator<Item = &ModuleRecord> {
        self.modules.values()
    }

    pub(crate) fn module(&self, id: ModuleId) -> Option<&ModuleRecord> {
        self.modules.get(&id)
    }

    #[allow(dead_code)] // Key lookup for the privileged entry feed; unit tests pin it.
    pub(crate) fn module_id_for(&self, key: &ModuleKey) -> Option<ModuleId> {
        self.modules_by_key.get(key).copied()
    }

    pub(crate) fn edges(&self) -> impl Iterator<Item = &EdgeRecord> {
        self.edges.values()
    }

    pub(crate) fn edge(&self, caller: CallerId, module: ModuleId) -> Option<&EdgeRecord> {
        self.edges.get(&(caller, module))
    }

    /// One caller's edges: a range query over the `(caller, module)` key,
    /// so per-caller projection is O(log E + edges of the caller), never a
    /// scan of every edge (C1b: callers grow to every provider user).
    pub(crate) fn edges_of(&self, caller: CallerId) -> impl Iterator<Item = &EdgeRecord> {
        self.edges
            .range((caller, ModuleId(0))..=(caller, ModuleId(u32::MAX)))
            .map(|(_, edge)| edge)
    }

    pub(crate) fn gaps(&self) -> &[RegistryGap] {
        &self.gaps
    }

    /// Per-gap record counts, parallel to [`Self::gaps`]; each is >= 1.
    pub(crate) fn gap_repeats(&self) -> &[u64] {
        &self.gap_repeats
    }

    pub(crate) fn gaps_suppressed(&self) -> u64 {
        self.gaps_suppressed
    }

    /// The enforced budgets (limits, occupancy, and loss counters render
    /// from these plus the table sizes).
    pub(crate) fn limits(&self) -> RegistryLimits {
        self.limits
    }

    // Registry-side caller occupancy; workload tests pin adapter/registry agreement.
    #[cfg(test)]
    pub(crate) fn caller_count(&self) -> usize {
        self.callers.len()
    }

    pub(crate) fn module_count(&self) -> usize {
        self.modules.len()
    }

    pub(crate) fn edge_count(&self) -> usize {
        self.edges.len()
    }

    /// Retained attach-endpoint census: the sum of admitted per-module
    /// endpoint counts. Only admitted modules with a count cost budget.
    pub(crate) fn endpoints_total(&self) -> usize {
        self.endpoints_total
    }

    /// Per-resource refusal counts. Exact even when gap retention
    /// overflows — loss counters are not gaps.
    pub(crate) fn callers_refused(&self) -> u64 {
        self.callers_refused
    }

    pub(crate) fn modules_refused(&self) -> u64 {
        self.modules_refused
    }

    pub(crate) fn edges_refused(&self) -> u64 {
        self.edges_refused
    }

    pub(crate) fn endpoints_refused(&self) -> u64 {
        self.endpoints_refused
    }

    /// Edges with materialized semantic state (the `semantic_state`
    /// budget occupancy). Zero while capture stays withheld.
    pub(crate) fn semantic_occupied(&self) -> usize {
        self.semantic_occupied
    }

    /// Edges whose semantic label reads unknown: withheld edges, tracked
    /// edges whose feed established no mechanism/operation claim, and
    /// latched same-file double-load edges (retained claims, unknown
    /// label). One predicate with the label, so census and label agree
    /// (DR-09).
    pub(crate) fn semantic_unknown_edges(&self) -> usize {
        self.edges
            .values()
            .filter(|edge| {
                edge.semantics
                    .as_ref()
                    .is_none_or(|state| state.label() != crate::semantics_edge::SEMANTIC_OBSERVED)
            })
            .count()
    }

    /// Semantic keys refused past budget (the `semantic_state` loss
    /// counter — exact even when gap retention overflows).
    pub(crate) fn semantic_refused(&self) -> u64 {
        self.semantic_refused
    }

    /// Counter budget census: edges with observed entries (count or
    /// in-flight), and edges whose counter saturated at the cap.
    pub(crate) fn counter_census(&self) -> (usize, usize) {
        let mut observed = 0;
        let mut saturated = 0;
        for edge in self.edges.values() {
            if edge.entry_count > 0 || edge.entry_in_flight {
                observed += 1;
            }
            if edge.entry_saturated {
                saturated += 1;
            }
        }
        (observed, saturated)
    }

    /// The edge's published usage coverage. Precedence: counted entries,
    /// then witnessed use, then a counting feed with no entries yet, then
    /// the watch (admitted modules only), then the uncovered reason.
    /// Positives come first, so loss or retirement never erases them.
    pub(crate) fn coverage(&self, edge: &EdgeRecord) -> UseCoverage {
        let coverage = &edge.coverage;
        if edge.entry_count > 0 {
            return UseCoverage::Counted {
                since_ns: coverage
                    .counted_since_ns
                    .or(edge.entry_first_seen_ns)
                    .unwrap_or(0),
                lossy: coverage.lossy,
                pid_exit: coverage.clean_exit,
            };
        }
        if let Some(first_ns) = coverage.witnessed_first_ns {
            return UseCoverage::Witnessed { first_ns };
        }
        if let Some(since_ns) = coverage.counted_since_ns {
            return UseCoverage::Counted {
                since_ns,
                lossy: coverage.lossy,
                pid_exit: coverage.clean_exit,
            };
        }
        let admitted = self
            .modules
            .get(&edge.module)
            .is_some_and(|module| module.admission == AdmissionState::Admitted);
        if !admitted {
            return UseCoverage::Unknown(UnknownReason::NotAdmitted);
        }
        match &coverage.watch {
            Watch::Watching { since_ns, until_ns } => UseCoverage::WatchedNoUse {
                since_ns: *since_ns,
                until_ns: *until_ns,
            },
            Watch::Unknown(reason) => UseCoverage::Unknown(reason.clone()),
            Watch::Unset => UseCoverage::Unknown(self.uncovered_reason.clone()),
        }
    }

    /// What the edge's entry columns mean, from its coverage. A positive
    /// count always reads as observed; a zero reads observed only under
    /// `WatchedNoUse` or a loss-free `Counted` feed.
    #[cfg_attr(not(test), allow(dead_code))] // Production presents through `entry_observation_for`.
    pub(crate) fn entry_observation(&self, edge: &EdgeRecord) -> EntryObservation {
        self.entry_observation_for(edge, &self.coverage(edge))
    }

    /// [`Self::entry_observation`] under an overlaid `coverage` (the
    /// pending-first-use presentation): the same rule, read from the
    /// presented coverage instead of the staged one.
    pub(crate) fn entry_observation_for(
        &self,
        edge: &EdgeRecord,
        coverage: &UseCoverage,
    ) -> EntryObservation {
        if edge.entry_count > 0 {
            return EntryObservation::Observed;
        }
        match coverage {
            UseCoverage::Counted { lossy: false, .. } | UseCoverage::WatchedNoUse { .. } => {
                EntryObservation::Observed
            }
            UseCoverage::Counted { lossy: true, .. } => EntryObservation::UnknownLossy,
            UseCoverage::Witnessed { .. } => EntryObservation::UnknownCountUnavailable,
            UseCoverage::Unknown(UnknownReason::NotAdmitted) => {
                EntryObservation::UnknownNotAdmitted
            }
            UseCoverage::Unknown(_) => EntryObservation::UnknownUnavailable,
        }
    }

    /// Recency answers "observed recently" from entry last-seen, not
    /// from any sticky bit: true when an entry was observed within
    /// `window_ns` of `now_ns`, or an entry is in flight. The dashboard
    /// display's predicate (the recorded signal is per-pass instead).
    /// Test-gated: unit tests pin the combined predicate; production
    /// splits it through [`Self::entry_recent_within`] plus the
    /// in-flight flag.
    #[cfg(test)]
    pub(crate) fn entry_active_within(
        &self,
        edge: &EdgeRecord,
        now_ns: u64,
        window_ns: u64,
    ) -> bool {
        edge.entry_in_flight || self.entry_recent_within(edge, now_ns, window_ns)
    }

    /// The last-seen half of [`Self::entry_active_within`]: true when an
    /// entry was observed within `window_ns` of `now_ns`, regardless of
    /// in-flight state. The presentation layer splits in-flight from
    /// recent for the dashboard activity column; both share this
    /// predicate, never two window implementations.
    pub(crate) fn entry_recent_within(
        &self,
        edge: &EdgeRecord,
        now_ns: u64,
        window_ns: u64,
    ) -> bool {
        edge.entry_last_seen_ns
            .is_some_and(|last| now_ns.saturating_sub(last) <= window_ns && last <= now_ns)
    }

    /// Stage one observed mapping. Unknown callers (never admitted) are
    /// refused outright — mappings never invent callers.
    pub(crate) fn note_mapping(
        &mut self,
        caller: CallerId,
        pid: u32,
        info: ModuleInfo,
        at_ns: u64,
    ) {
        self.staged.push(Mutation::NoteMapping {
            caller,
            pid,
            info,
            evidence: MappingEvidence::DeepScan,
            at_ns,
        });
    }

    /// Stage one mapping observed by exact maps identity (C1b): the same
    /// edge semantics as [`Self::note_mapping`], with the edge's evidence
    /// marked `maps_match`.
    pub(crate) fn note_maps_match(
        &mut self,
        caller: CallerId,
        pid: u32,
        info: ModuleInfo,
        at_ns: u64,
    ) {
        self.staged.push(Mutation::NoteMapping {
            caller,
            pid,
            info,
            evidence: MappingEvidence::MapsMatch,
            at_ns,
        });
    }

    /// Stage one observed entry batch. Counts come from observed entries
    /// only: BPF usage events or owned-harness scripted events. Fed by
    /// the privileged BPF lane; the scan lane stages no entries.
    #[allow(dead_code)] // Privileged BPF usage-feed seam; unit tests pin the semantics.
    pub(crate) fn observe_entries(
        &mut self,
        caller: CallerId,
        module: &ModuleKey,
        delta: u64,
        at_ns: u64,
    ) {
        self.staged.push(Mutation::ObserveEntries {
            caller,
            module: module.clone(),
            delta,
            at_ns,
        });
    }

    #[allow(dead_code)] // Privileged BPF usage-feed seam; unit tests pin the semantics.
    pub(crate) fn set_in_flight(&mut self, caller: CallerId, module: &ModuleKey, in_flight: bool) {
        self.staged.push(Mutation::SetInFlight {
            caller,
            module: module.clone(),
            in_flight,
        });
    }

    /// Stage one observed semantic call for an edge. The call's facts
    /// come from the existing trusted-slot mechanism path; the feed
    /// boundary copies them, never invents. Fed by the privileged
    /// semantic lane; the scan lane stages no semantic calls.
    ///
    /// D4-positive (an owned multi-mechanism workload through the real
    /// `p11scope inventory` binary showing observed mechanism/operation
    /// context) is EXPLICITLY OPEN: p11scope observes calls only via
    /// eBPF uprobes, which need privilege, so routing trusted events
    /// here belongs to the controller's privileged BPF capture lane
    /// (inventory uprobe activation under `attach::inventory`, decoded
    /// via `events::decode`) — not to this unprivileged scan lane.
    #[allow(dead_code)] // Privileged semantic-feed seam; unit tests pin the semantics.
    pub(crate) fn observe_semantic(
        &mut self,
        caller: CallerId,
        module: &ModuleKey,
        call: SemanticCall,
    ) {
        self.staged.push(Mutation::ObserveSemantic {
            caller,
            module: module.clone(),
            call,
        });
    }

    /// Stage one witnessed use of an edge (a native `CALLER_USE` row bound
    /// to this caller): positive, monotonic history with no count or
    /// recency. Accepted for retired callers — a row read after exit is
    /// still use — but never invents an edge.
    #[cfg_attr(not(test), allow(dead_code))] // Task 6 C4 binder.
    pub(crate) fn note_witness(&mut self, caller: CallerId, module: &ModuleKey, first_ns: u64) {
        self.staged.push(Mutation::NoteWitness {
            caller,
            module: module.clone(),
            first_ns,
        });
    }

    /// Stage one witness row the native binder bound to `caller`.
    /// `modules` are the admitted modules whose endpoint set holds the
    /// row's witness endpoint. The row witnesses `caller`'s edge only when
    /// exactly one of them has an edge to `caller`. With none and a single
    /// module, the use is that module's (`no_mapping_edge`, with a gap
    /// naming the caller: a witness never invents a mapping). Anything else
    /// is an `ambiguous shared endpoint` gap and witnesses nothing.
    pub(crate) fn note_bound_witness(
        &mut self,
        caller: CallerId,
        modules: Vec<ModuleKey>,
        first_ns: u64,
    ) {
        self.staged.push(Mutation::NoteBoundWitness {
            caller,
            modules,
            first_ns,
        });
    }

    /// Stage one witness row the native binder could not bind: positive
    /// module-level use, with the reason and a named gap, when `modules` is
    /// a single module; an `ambiguous shared endpoint` gap and no use when
    /// several modules share the endpoint. No tgid is recorded: the row's
    /// process is exactly what could not be identified. `entries` is the
    /// row's held entry count at drop; it folds into the single module's
    /// lower bound and is ignored for shared or unresolved rows.
    /// Test-direct staging (production always knows the image).
    #[cfg_attr(not(test), allow(dead_code))]
    pub(crate) fn note_unbound_witness(
        &mut self,
        modules: Vec<ModuleKey>,
        first_ns: u64,
        reason: UnboundReason,
        entries: u64,
    ) {
        self.note_unbound_witness_with_image(modules, first_ns, reason, entries, None);
    }

    /// Stage one unbound row with its unidentified image (slice 1):
    /// the image feeds the per-module and run-wide image sets on the
    /// committed single-module path, beside `rows`/`entries`.
    pub(crate) fn note_unbound_witness_with_image(
        &mut self,
        modules: Vec<ModuleKey>,
        first_ns: u64,
        reason: UnboundReason,
        entries: u64,
        image: Option<UnboundImage>,
    ) {
        self.staged.push(Mutation::NoteUnboundWitness {
            modules,
            first_ns,
            reason,
            entries,
            image,
        });
    }

    /// Stage one decided witness row whose endpoint resolved to no admitted
    /// module (the caller records the gap): counted, never shown.
    pub(crate) fn note_unresolved_witness(&mut self) {
        self.staged.push(Mutation::NoteUnresolvedWitness);
    }

    /// Stage R-C51-1 for `caller`'s edge on `module` (`None`: every edge
    /// of the caller): an unbound CALLER_USE row named its pid. The edge's
    /// watch (ongoing or frozen) reads unknown `use_before_admission`, and
    /// none starts again; positive history stays.
    pub(crate) fn note_use_before_admission(
        &mut self,
        caller: CallerId,
        module: Option<ModuleKey>,
    ) {
        self.staged.push(Mutation::NoteUseBeforeAdmission {
            caller,
            module,
            reason: UnknownReason::UseBeforeAdmission,
        });
    }

    /// The same sticky downgrade for a row that stayed unbound after
    /// the caller's admission because the caller exited before the row
    /// could be matched: the edge reads unknown
    /// `caller_exited_before_match`, never "before admission".
    pub(crate) fn note_caller_exited_before_match(
        &mut self,
        caller: CallerId,
        module: Option<ModuleKey>,
    ) {
        self.staged.push(Mutation::NoteUseBeforeAdmission {
            caller,
            module,
            reason: UnknownReason::CallerExitedBeforeMatch,
        });
    }

    /// The same sticky downgrade for a row lifecycle loss left unbound
    /// (R-C51-3): the edge reads unknown `loss` with `reason`.
    pub(crate) fn note_unbound_row_loss(
        &mut self,
        caller: CallerId,
        module: Option<ModuleKey>,
        reason: &str,
    ) {
        self.staged.push(Mutation::NoteUseBeforeAdmission {
            caller,
            module,
            reason: UnknownReason::Loss(reason.into()),
        });
    }

    /// Stage the native binder's census (the unbound-witness measurement).
    pub(crate) fn note_witness_census(&mut self, census: BindingCensus) {
        self.staged.push(Mutation::NoteWitnessCensus { census });
    }

    /// The published native binder census.
    pub(crate) fn witness_census(&self) -> &BindingCensus {
        &self.witness_census
    }

    /// Where the published decided witness rows went.
    pub(crate) fn witness_placement(&self) -> WitnessPlacement {
        self.witness_placement
    }

    /// Run-wide distinct unidentified caller images (slice 1): the
    /// published count — a lower bound while
    /// [`Self::unidentified_images_saturated`].
    pub(crate) fn unidentified_images(&self) -> u64 {
        u64::try_from(self.unidentified_images.len()).unwrap_or(u64::MAX)
    }

    /// The run-wide image set hit its bound. Sticky.
    pub(crate) fn unidentified_images_saturated(&self) -> bool {
        self.unidentified_images_saturated
    }

    /// Every collected run-wide host pid, oldest first call first
    /// (Part C): one entry per image, never deduplicated, complete
    /// while [`Self::unidentified_pids_dropped`] is zero.
    pub(crate) fn unidentified_pids(&self) -> Vec<UnboundPid> {
        let mut pids: Vec<UnboundPid> = self.unidentified_images.values().cloned().collect();
        pids.sort_by_key(|pid| (pid.first_call_ns, pid.pid_host));
        pids
    }

    /// Distinct images (with their host pids) the run-wide bound
    /// turned away, saturating. Sticky.
    pub(crate) fn unidentified_pids_dropped(&self) -> u64 {
        self.unidentified_pids_dropped
    }

    /// Stage one coverage note for an edge from its producer (the capture
    /// facade's attach receipts, the Detailed subset's counting feed).
    #[cfg_attr(not(test), allow(dead_code))] // Task 6 C3/C5/C6 producers.
    pub(crate) fn note_coverage(
        &mut self,
        caller: CallerId,
        module: &ModuleKey,
        note: CoverageNote,
    ) {
        self.staged.push(Mutation::NoteCoverage {
            caller,
            module: module.clone(),
            note,
        });
    }

    /// Stage one bound pair's absolute entry count: a saturating lower
    /// bound of entries on the module's attached endpoints since the
    /// pair's first record (`first_ns`), observed by the read at
    /// `last_ns` (pass resolution). Only a strict advance past the
    /// staged count moves the edge, so several reads per commit stay
    /// sound and recency never fakes activity. Like a witness, the
    /// count stages for retired callers (pre-exit history); unlike a
    /// witness it never invents an edge (one memoized gap). When
    /// `base` is nonzero, `count` is growth past that accounted base
    /// and accumulates onto the edge instead of installing absolute.
    pub(crate) fn note_counted_use(
        &mut self,
        caller: CallerId,
        module: &ModuleKey,
        count: u64,
        first_ns: u64,
        last_ns: u64,
        base: u64,
    ) {
        self.staged.push(Mutation::NoteCountedUse {
            caller,
            module: module.clone(),
            count,
            first_ns,
            last_ns,
            base,
        });
    }

    /// Stage one bound pair's entry count for publication-time
    /// placement (P3): the witness and the count resolve together at
    /// publication, against the mappings the publication commits —
    /// exactly one edged module takes both. A first-sight rejection
    /// (no edge, ambiguity) drops the count silently: the witness
    /// records the placement gaps, and a count never invents an edge.
    /// A re-resolved (`base` nonzero) rejection has no witness in this
    /// window, so the publication discloses under its own subject
    /// instead of dropping silently (F3-02); its placement accumulates
    /// by segment and windows its coverage from `since_ns` (the read
    /// that observed `base`). `pending_id` is the coordinator's opaque
    /// handle: the publication reports every pending count's placement
    /// through [`Self::take_pending_count_decisions`].
    #[allow(clippy::too_many_arguments)]
    pub(crate) fn note_pending_count(
        &mut self,
        pending_id: u64,
        caller: CallerId,
        modules: Vec<ModuleKey>,
        count: u64,
        first_ns: u64,
        last_ns: u64,
        since_ns: u64,
        base: u64,
    ) {
        self.staged.push(Mutation::NotePendingCount {
            pending_id,
            caller,
            modules,
            count,
            first_ns,
            last_ns,
            since_ns,
            base,
        });
    }

    /// Drains the last publication's pending-count placements, in apply
    /// order: one decision per staged pending count. The coordinator
    /// finalizes its pair targets from these (P3).
    pub(crate) fn take_pending_count_decisions(&mut self) -> Vec<PendingCountDecision> {
        std::mem::take(&mut self.pending_count_decisions)
    }

    /// Stage one global health regression (a native identity, pair, or
    /// usage evidence counter rose between `at_ns`, the last clean read,
    /// and `detected_ns`, the read that saw it). The failure cannot be
    /// localized, so every watch interval that reaches past `at_ns`
    /// demotes to `Unknown`; positives stand. A new interval may start
    /// only from `detected_ns` on. The regression itself is a gap.
    #[cfg_attr(not(test), allow(dead_code))] // Task 6 C5 health reads.
    pub(crate) fn note_health_regression(
        &mut self,
        reason: impl Into<Arc<str>>,
        at_ns: u64,
        detected_ns: u64,
    ) {
        self.staged.push(Mutation::NoteHealthRegression {
            subject: "usage coverage health regression",
            reason: reason.into(),
            at_ns,
            detected_ns,
            restartable: true,
        });
    }

    /// Stage the end of every watch: the producer stops. Each ongoing
    /// watch freezes as `since..at_ns` (`at_ns` is the last proven-clean
    /// instant); a watch with no clean instant after its start reads
    /// unknown; no watch starts afterwards.
    #[cfg_attr(not(test), allow(dead_code))] // Task 6 C5 stops native capture.
    pub(crate) fn note_watch_end(&mut self, reason: impl Into<Arc<str>>, at_ns: u64) {
        self.staged.push(Mutation::EndWatches {
            reason: reason.into(),
            at_ns,
        });
    }

    /// Stage one watch demotion that is not a health counter: the native
    /// capture lost system-scope lifecycle evidence (C5.2 D4).
    /// Same mechanics as `note_health_regression` (every watched edge,
    /// including one staged earlier in this batch, demotes sticky; later
    /// watches clamp to `at_ns`), under its own gap subject, whose text
    /// says no watch starts again: the producer stops watching for good.
    #[cfg_attr(not(test), allow(dead_code))] // Task 6 C5 forwards lifecycle loss.
    pub(crate) fn note_watch_demotion(
        &mut self,
        subject: &'static str,
        reason: impl Into<Arc<str>>,
        at_ns: u64,
    ) {
        self.staged.push(Mutation::NoteHealthRegression {
            subject,
            reason: reason.into(),
            at_ns,
            detected_ns: at_ns,
            restartable: false,
        });
    }

    /// Stage the pair-insert-failure demotion (C7 C4): some pair has use
    /// but no row, so every ongoing watch reads `uncounted` and no watch
    /// starts again in this capture (the coordinator withholds them).
    /// Positives and intervals frozen before `at_ns` stand. The caller
    /// stages this before the batch's health regression: demotions only
    /// touch ongoing watches, so the uncounted reason wins over the
    /// coincident loss demotion while both gaps stay recorded.
    pub(crate) fn note_pairs_uncounted(&mut self, reason: impl Into<Arc<str>>, at_ns: u64) {
        self.staged.push(Mutation::NotePairsUncounted {
            reason: reason.into(),
            at_ns,
        });
    }

    /// Stage one pass-wide semantic capture-loss boundary: every live
    /// operation on every semantically-tracked edge ends unknown with
    /// explicit accounting, and the loss itself is a gap — never
    /// silent completion, never silent loss.
    #[allow(dead_code)] // Privileged semantic-feed seam; unit tests pin the semantics.
    pub(crate) fn note_capture_loss(&mut self, reason: String) {
        self.staged.push(Mutation::NoteSemanticLoss { reason });
    }

    /// Stage one pass-wide count-refresh loss boundary: a refresh
    /// transport failure, or a refresh sweep that skipped a tracked row.
    /// Every counted column becomes a lower bound (`lossy`, never a
    /// quiet claim over the stale count), the observed counts stand, and
    /// the loss itself is a gap — never silent loss.
    pub(crate) fn note_refresh_loss(&mut self, reason: String) {
        self.staged.push(Mutation::NoteRefreshLoss { reason });
    }

    /// Stage one capture-unproven boundary: lifecycle evidence or scope
    /// custody was lost, so bound-pair growth stages nothing more
    /// (pending first-sight installs still land, now `lossy`) and every
    /// counted column is a lower bound (`lossy`). Observed counts
    /// stand; the lifecycle/custody gap discloses the cause, so this
    /// stages no second gap — never silent loss.
    pub(crate) fn note_counted_loss(&mut self) {
        self.staged.push(Mutation::NoteCountedLoss);
    }

    /// Stage one clean PID-target exit boundary: same staging as
    /// `note_counted_loss`, but the sole cause is the exit (no records
    /// dropped), so counted columns name it until a generic loss
    /// clears the claim.
    pub(crate) fn note_counted_pid_exit(&mut self) {
        self.staged.push(Mutation::NoteCountedPidExit);
    }

    /// Stage one caller retirement: the caller's edges end with the
    /// reason and its counts freeze. Evidence is retained.
    pub(crate) fn retire_caller(&mut self, caller: CallerId, reason: String, at_ns: u64) {
        self.staged.push(Mutation::RetireCaller {
            caller,
            reason,
            at_ns,
        });
    }

    /// Stage one module-absence observation: a pass over the live caller
    /// did not show the module. Only a complete scan ends the edge; an
    /// incomplete one marks it uncertain.
    pub(crate) fn note_module_absent(
        &mut self,
        caller: CallerId,
        module: ModuleId,
        complete_scan: bool,
        at_ns: u64,
    ) {
        self.staged.push(Mutation::NoteModuleAbsent {
            caller,
            module,
            complete_scan,
            at_ns,
        });
    }

    /// Stage one unscanned-member observation: the member was not scanned
    /// this pass (cap, loss), so its mapped edges become uncertain —
    /// neither confirmed nor refuted.
    pub(crate) fn note_member_unscanned(&mut self, caller: CallerId) {
        self.staged.push(Mutation::NoteMemberUnscanned { caller });
    }

    pub(crate) fn record_gap(&mut self, gap: RegistryGap) {
        let terminal = self.terminal_phase;
        self.staged.push(Mutation::RecordGap { gap, terminal });
    }

    /// Stage one drain's shed calls for an aggregated per-drain
    /// unrouted subject (`semantic calls unrouted` or `semantic
    /// calls unrouted from other callers`). Drains sharing
    /// (subject, bindings) sum into one counted row at apply time;
    /// the row is lane-wide (caller, module, pid and budget are
    /// always none for these subjects). Totals and per-label
    /// counts saturate; the formatted reason keeps the exact
    /// single-drain template so oracles parsing `{total} calls
    /// shed without a route ({labels}) ...` read the sum.
    pub(crate) fn record_aggregated_unrouted(
        &mut self,
        subject: String,
        total: u64,
        labels: Vec<(String, u64)>,
        bindings: usize,
    ) {
        let terminal = self.terminal_phase;
        self.staged.push(Mutation::RecordAggregatedUnrouted {
            subject,
            total,
            labels,
            bindings,
            terminal,
        });
    }

    /// Enter the terminal/stop-time phase: gaps staged from now on
    /// carry the terminal flag and may use the [`TERMINAL_GAP_RESERVE`]
    /// headroom above the bound. Idempotent; the lane enters it when
    /// stopping, before staging any terminal disclosure (stop request
    /// first; the lane stop re-enters for bare stops).
    pub(crate) fn enter_terminal_phase(&mut self) {
        self.terminal_phase = true;
    }

    /// Staged (subject, reason) gap pairs awaiting the next commit, in
    /// stage order. For twins whose disclosure cannot commit yet (an
    /// unfinished publication stands in front of it).
    #[cfg(test)]
    pub(crate) fn staged_scope_gaps_for_test(&self) -> Vec<(String, String)> {
        self.staged
            .iter()
            .filter_map(|staged| match staged {
                Mutation::RecordGap { gap, .. } => Some((gap.subject.clone(), gap.reason.clone())),
                _ => None,
            })
            .collect()
    }

    /// Staged gaps awaiting the next commit, in stage order, with their
    /// caller attribution: for twins that pin whom a disclosure names.
    #[cfg(test)]
    pub(crate) fn staged_gaps_for_test(&self) -> Vec<RegistryGap> {
        self.staged
            .iter()
            .filter_map(|staged| match staged {
                Mutation::RecordGap { gap, .. } => Some(gap.clone()),
                _ => None,
            })
            .collect()
    }

    /// Stage one gap for the module `key` names, resolving the ID at
    /// publication (F3-04): `record_gap` resolves eagerly against the
    /// committed snapshot, which misses a first-discovered module whose
    /// mapping stages in this same publication (receipts process
    /// pre-commit — scan → extend → commit) and would report its gap
    /// run-wide. This resolves at apply, after the publication's
    /// mappings commit; a module that never commits stays unattributed
    /// (genuinely unclaimable).
    pub(crate) fn record_gap_for_key(
        &mut self,
        caller: Option<CallerId>,
        key: ModuleKey,
        pid: Option<u32>,
        subject: String,
        reason: String,
        budget: Option<BudgetRefusal>,
    ) {
        let terminal = self.terminal_phase;
        self.staged.push(Mutation::RecordKeyedGap {
            key,
            caller,
            pid,
            subject,
            reason,
            budget,
            terminal,
        });
    }

    /// Apply every staged mutation in order and publish the snapshot.
    /// Returns the number of applied mutations. Ledger-less: Joint
    /// feeds reduce S1Only-direct and key-use opens charge the
    /// fallback; tests use this for the no-ledger twin. Production
    /// commits borrow the capture owner's ledger instead.
    #[cfg_attr(not(test), allow(dead_code))]
    pub(crate) fn publish(&mut self) -> usize {
        self.publish_inner(None, None)
    }

    /// Publish with the shared H8 staging ledger (guarded H9 path):
    /// Joint feeds stage against it; `None` (plain [`publish`]) keeps
    /// every feed S1Only-direct. Production commits borrow the
    /// capture owner's ledger here.
    pub(crate) fn publish_with_ledger(
        &mut self,
        ledger: &mut crate::semantics_objects::journal::StagingLedger,
    ) -> usize {
        self.publish_inner(None, Some(ledger))
    }

    /// Publish with a count observer plus the capture owner's ledger:
    /// the diagnostics commit path. Joint feeds stage against the
    /// owner's ledger exactly like [`publish_with_ledger`].
    pub(crate) fn publish_with_count_observer(
        &mut self,
        observer: Option<&mut dyn FnMut(CountPublication)>,
        ledger: &mut crate::semantics_objects::journal::StagingLedger,
    ) -> usize {
        self.publish_inner(observer, Some(ledger))
    }

    pub(crate) fn publication_pending(&self) -> bool {
        self.joint_publication.is_some()
    }

    /// Check the actual original before any preparation/apply. The stamp only
    /// protects phase custody; H3/H9 still validate the original frame itself.
    pub(crate) fn validate_joint_publication(
        &self,
        frame: &IngestedJointQuantum,
        owner: &JointCaptureOwner,
        producers: &crate::attach::SessionDrainProducers,
    ) -> Result<()> {
        frame
            .validate_owner(owner, producers)
            .map_err(|reason| anyhow!("Joint publication original refused: {reason:?}"))?;
        if let Some(phase) = &self.joint_publication
            && (phase.identity != frame.identity()
                || phase
                    .frontier
                    .is_some_and(|frontier| frontier != frame.frontier())
                || phase.base_revision != self.facts_revision)
        {
            bail!("Joint publication must resume its exact original frame and revision");
        }
        Ok(())
    }

    pub(crate) fn begin_joint_publication(
        &mut self,
        raw: &RawJointQuantum,
        owner: &JointCaptureOwner,
        producers: &crate::attach::SessionDrainProducers,
    ) -> Result<()> {
        raw.validate_preparation(owner.adapter(), producers)
            .map_err(|reason| anyhow!("Joint preparation original refused: {reason:?}"))?;
        if self.joint_publication.is_some() {
            bail!("Joint publication is already retained");
        }
        let storage = self
            .semantic_resources
            .reserve(std::mem::size_of::<AppliedJointPublication>())
            .map_err(|reason| anyhow!("Joint publication storage refused: {reason:?}"))?;
        self.joint_publication = Some(AppliedJointPublication {
            identity: raw.h0_identity(),
            frontier: None,
            base_revision: self.facts_revision,
            physical_prefix_end: None,
            applied: None,
            targets_bound: false,
            _storage: storage,
        });
        Ok(())
    }

    pub(crate) fn validate_joint_preparation(&self, raw: &RawJointQuantum) -> Result<()> {
        let phase = self
            .joint_publication
            .as_ref()
            .ok_or_else(|| anyhow!("no original Joint preparation"))?;
        if phase.identity != raw.h0_identity()
            || phase.frontier.is_some()
            || phase.applied.is_some()
            || phase.base_revision != self.facts_revision
        {
            bail!("Joint preparation must retain its original raw allocation and base revision");
        }
        Ok(())
    }

    /// Freeze only the actual successful physical preparation. Retrying the
    /// same original may validate this boundary, but never extends it.
    pub(crate) fn freeze_joint_physical_prefix(&mut self, raw: &RawJointQuantum) -> Result<()> {
        self.validate_joint_preparation(raw)?;
        let phase = self
            .joint_publication
            .as_mut()
            .ok_or_else(|| anyhow!("no original Joint preparation"))?;
        if phase.targets_bound
            || phase
                .physical_prefix_end
                .is_some_and(|end| end > self.staged.len())
        {
            bail!("Joint physical inputs no longer retain their original prefix");
        }
        phase.physical_prefix_end.get_or_insert(self.staged.len());
        Ok(())
    }

    pub(crate) fn bind_joint_publication_frame(
        &mut self,
        frame: &IngestedJointQuantum,
        owner: &JointCaptureOwner,
        producers: &crate::attach::SessionDrainProducers,
    ) -> Result<()> {
        self.validate_joint_publication(frame, owner, producers)?;
        let phase = self
            .joint_publication
            .as_mut()
            .ok_or_else(|| anyhow!("Joint physical preparation has not run"))?;
        if phase.frontier.is_none() {
            phase.frontier = Some(frame.frontier());
        }
        Ok(())
    }

    /// Only an engine-tail failure before preparation/application can unwind
    /// this new phase. An applied phase always retains its original frame.
    pub(crate) fn cancel_unapplied_joint_publication(&mut self) {
        assert!(
            self.joint_publication
                .as_ref()
                .is_some_and(|phase| phase.applied.is_none())
        );
        self.joint_publication = None;
    }

    pub(crate) fn apply_joint_publication(
        &mut self,
        owner: &mut JointCaptureOwner,
        frame: &IngestedJointQuantum,
        producers: &crate::attach::SessionDrainProducers,
        observer: Option<&mut dyn FnMut(CountPublication)>,
    ) -> Result<usize> {
        self.validate_joint_publication(frame, owner, producers)?;
        if !self
            .joint_publication
            .as_ref()
            .is_some_and(|phase| phase.frontier == Some(frame.frontier()))
        {
            bail!("Joint inputs require their original bound frame before apply");
        }
        assert!(
            self.joint_publication
                .as_ref()
                .is_some_and(|phase| phase.applied.is_none())
        );
        let applied = self.apply_staged(observer, Some(owner.ledger_mut()));
        self.joint_publication
            .as_mut()
            .expect("retained original phase")
            .applied = Some(applied);
        Ok(applied)
    }

    pub(crate) fn joint_publication_applied(&self) -> bool {
        self.joint_publication
            .as_ref()
            .is_some_and(|phase| phase.applied.is_some())
    }

    pub(crate) fn joint_publication_targets_bound(&self) -> bool {
        self.joint_publication
            .as_ref()
            .expect("retained phase")
            .targets_bound
    }

    pub(crate) fn mark_joint_publication_targets_bound(&mut self) {
        self.joint_publication
            .as_mut()
            .expect("retained phase")
            .targets_bound = true;
    }

    /// Completion is supplied only by the actual frame finish, never callback
    /// words, a progress enum, a cut scalar or a second H3 take.
    pub(crate) fn finish_joint_publication(
        &mut self,
        owner: &mut JointCaptureOwner,
        disposed: &DisposedJointQuantum,
    ) -> Result<usize> {
        let phase = self
            .joint_publication
            .as_ref()
            .ok_or_else(|| anyhow!("no retained Joint publication"))?;
        if phase.identity != disposed.identity()
            || phase.frontier != Some(disposed.frontier())
            || phase.base_revision != self.facts_revision
            || !phase.targets_bound
        {
            bail!("Joint completion does not name the retained original publication");
        }
        let applied = phase
            .applied
            .ok_or_else(|| anyhow!("Joint inputs have not applied"))?;
        self.complete_publication(Some(owner.ledger_mut()));
        self.joint_publication = None;
        Ok(applied)
    }

    fn publish_inner(
        &mut self,
        observer: Option<&mut dyn FnMut(CountPublication)>,
        mut ledger: Option<&mut crate::semantics_objects::journal::StagingLedger>,
    ) -> usize {
        assert!(
            !self.publication_pending(),
            "an unfinished Joint publication retains its original frame"
        );
        let applied = self.apply_staged(observer, ledger.as_deref_mut());
        self.complete_publication(ledger);
        applied
    }

    fn apply_staged(
        &mut self,
        mut observer: Option<&mut dyn FnMut(CountPublication)>,
        mut ledger: Option<&mut crate::semantics_objects::journal::StagingLedger>,
    ) -> usize {
        // Return eligible shared charges before staging new calls:
        // an association ended without its ledger must not cause a
        // false capacity refusal at the next ledger contact.
        if let Some(ledger) = ledger.as_deref_mut() {
            self.flush_joint_releases(ledger);
        }
        self.validate_joint_grants_staged();
        let staged = std::mem::take(&mut self.staged);
        let applied = staged.len();
        // Per-pass activity starts quiet: advances below set it.
        for edge in self.edges.values_mut() {
            edge.entry_rose_since_previous_pass = false;
        }
        self.demoted_place_growth.clear();
        for (position, mutation) in staged.into_iter().enumerate() {
            let count = if observer.is_some() {
                match &mutation {
                    Mutation::NoteCountedUse {
                        caller,
                        module,
                        count,
                        base,
                        ..
                    } => Some(CountPublication {
                        caller: *caller,
                        module: self.module_id_for(module),
                        staged: *count,
                        base: *base,
                        edge_total: None,
                    }),
                    _ => None,
                }
            } else {
                None
            };
            match mutation {
                Mutation::NoteInstance(input) => {
                    self.apply_instance(input, Some(position), ledger.as_deref_mut())
                }
                other => self.apply(other, ledger.as_deref_mut()),
            }
            if let Some(mut count) = count {
                count.edge_total = count
                    .module
                    .and_then(|module| self.edge(count.caller, module))
                    .map(|edge| edge.entry_count);
                observer.as_mut().expect("enabled count observer")(count);
            }
        }
        applied
    }

    fn complete_publication(
        &mut self,
        ledger: Option<&mut crate::semantics_objects::journal::StagingLedger>,
    ) {
        // Settle original payload/association releases only after all frame
        // consumers finish, even when this publication had no new effects.
        if let Some(ledger) = ledger {
            self.flush_joint_releases(ledger);
        }
        self.reconcile_initial_semantic_coverage();
        self.facts_revision = self.facts_revision.saturating_add(1);
        self.published_revision = self.facts_revision;
    }

    /// Disclose the initial observation interval after physical and semantic
    /// mutations join this publication, including a later physical reveal.
    /// Instance batch stamps are non-authority metadata: use before a stamp
    /// proves neither missing calls nor the actual start of semantic proof.
    /// Current receipts, reducers and physical counters remain untouched.
    fn reconcile_initial_semantic_coverage(&mut self) {
        let mut first_observed = BTreeMap::<(CallerId, ModuleId), u64>::new();
        for instance in self.instances() {
            first_observed
                .entry((instance.caller, instance.module))
                .and_modify(|first| *first = (*first).min(instance.first_seen_ns))
                .or_insert(instance.first_seen_ns);
        }
        // Retained instances bound this transient index; direct edge lookups
        // avoid scanning every edge for each registration or replacement.
        for ((caller, module), first_observed_ns) in first_observed {
            let Some(edge) = self.edge(caller, module) else {
                continue;
            };
            // Counted presentation can hide an earlier retained witness;
            // either positive history can precede this registration stamp.
            let physical_first_ns = edge
                .entry_first_seen_ns
                .filter(|_| edge.entry_count > 0)
                .into_iter()
                .chain(edge.coverage.witnessed_first_ns)
                .min();
            if !physical_first_ns.is_some_and(|first| first < first_observed_ns) {
                continue;
            }
            let gap = RegistryGap {
                caller: Some(caller),
                module: Some(module),
                pid: None,
                subject: "physical provider use preceded first observed semantic registration"
                    .into(),
                reason: instance_input::InstanceReason::BeforeSemanticBoundary
                    .label()
                    .into(),
                budget: None,
            };
            // Reconciliation is not a new occurrence each pass. Suppressed
            // identities retain the existing bounded fingerprint policy.
            if !self.gap_index.contains_key(&gap) {
                self.push_gap(gap);
            }
        }
    }

    /// Publish one gap generated while applying: it carries the live
    /// phase (staged gaps carry their flag captured at stage time).
    fn push_gap(&mut self, gap: RegistryGap) {
        let terminal = self.terminal_phase;
        self.push_gap_as(gap, terminal);
    }

    /// Publish one gap once per run. Identity is every published field
    /// (caller, module, pid, subject, reason, budget); gaps carry no
    /// time or pass-specific field, so none is excluded. A repeat of a
    /// retained gap bumps its `repeats` and consumes no `--max-gaps`
    /// budget; only a distinct gap past the bound is suppressed, and each
    /// distinct suppressed gap counts once. Suppressed gaps are
    /// remembered up to `MAX_SUPPRESSED_GAP_MEMORY` as 64-bit keyed-hash
    /// fingerprints of the identity fields (a collision, odds about
    /// 2^-40 at the bound, would under-count one gap); past that, a
    /// recurrence of an unremembered suppressed gap counts again (the
    /// counter then over-counts, never under-counts). In-run gaps keep
    /// the full `max_gaps` bound; terminal gaps (staged after
    /// `enter_terminal_phase`) may use [`TERMINAL_GAP_RESERVE`] headroom
    /// rows above it, so a per-drain flood can never crowd out the
    /// stop-time disclosures.
    fn push_gap_as(&mut self, gap: RegistryGap, terminal: bool) {
        if let Some(&index) = self.gap_index.get(&gap) {
            self.gap_repeats[index] = self.gap_repeats[index].saturating_add(1);
            return;
        }
        let cap = if terminal {
            self.limits.max_gaps.saturating_add(TERMINAL_GAP_RESERVE)
        } else {
            self.limits.max_gaps
        };
        if self.gaps.len() >= cap {
            let fingerprint = self.suppressed_hasher.hash_one(&gap);
            if self.suppressed_seen.contains(&fingerprint) {
                return;
            }
            self.gaps_suppressed = self.gaps_suppressed.saturating_add(1);
            if self.suppressed_seen.len() < MAX_SUPPRESSED_GAP_MEMORY {
                self.suppressed_seen.insert(fingerprint);
            }
            return;
        }
        self.gap_index.insert(gap.clone(), self.gaps.len());
        self.gaps.push(gap);
        self.gap_repeats.push(1);
    }

    /// Merge one drain's shed calls into the (subject, bindings)
    /// aggregated row: sums totals and per-label counts, then
    /// retains or rewrites the one lane-wide row in place. The row
    /// keeps `repeats` 1 (consumers multiply count by repeats, so
    /// a summed row must not count drains there). A suppressed
    /// aggregate counts once per (subject, bindings), never once
    /// per merged drain.
    fn push_aggregated_unrouted(
        &mut self,
        subject: String,
        total: u64,
        labels: Vec<(String, u64)>,
        bindings: usize,
        terminal: bool,
    ) {
        let key = (subject.clone(), bindings);
        let (reason, retained_index) = {
            let aggregate = self
                .unrouted_aggregates
                .entry(key.clone())
                .or_insert_with(|| UnroutedAggregate {
                    total: 0,
                    labels: BTreeMap::new(),
                    gap_index: None,
                });
            aggregate.total = aggregate.total.saturating_add(total);
            for (label, count) in labels {
                let entry = aggregate.labels.entry(label).or_insert(0);
                *entry = entry.saturating_add(count);
            }
            let reason =
                aggregated_unrouted_reason(&subject, aggregate.total, &aggregate.labels, bindings);
            (reason, aggregate.gap_index)
        };
        // A retained row rewrites in place (the dedupe key follows
        // the new reason); repeats stays 1.
        if let Some(index) = retained_index
            && let Some(retained) = self.gaps.get_mut(index)
            && retained.subject == subject
        {
            let old = std::mem::replace(&mut retained.reason, reason.clone());
            self.gap_index.remove(&RegistryGap {
                caller: None,
                module: None,
                pid: None,
                subject: subject.clone(),
                reason: old,
                budget: None,
            });
            self.gap_index.insert(
                RegistryGap {
                    caller: None,
                    module: None,
                    pid: None,
                    subject,
                    reason,
                    budget: None,
                },
                index,
            );
            return;
        }
        // First landing (or a lost index): retain one row through
        // the budgeted path. An aggregate suppressed once stays
        // suppressed without recounting per merged drain.
        if self.suppressed_aggregates.contains(&key) {
            return;
        }
        let gap = RegistryGap {
            caller: None,
            module: None,
            pid: None,
            subject: subject.clone(),
            reason,
            budget: None,
        };
        let before = self.gaps.len();
        self.push_gap_as(gap.clone(), terminal);
        if let Some(&index) = self.gap_index.get(&gap) {
            if let Some(aggregate) = self.unrouted_aggregates.get_mut(&key) {
                aggregate.gap_index = Some(index);
            }
            debug_assert!(self.gaps.len() == before + 1 || self.gap_repeats[index] > 1);
        } else {
            // `push_gap` counted this distinct suppression; later
            // merges of the same aggregate return early above.
            self.suppressed_aggregates.insert(key);
        }
    }

    fn apply(
        &mut self,
        mutation: Mutation,
        mut ledger: Option<&mut crate::semantics_objects::journal::StagingLedger>,
    ) {
        match mutation {
            Mutation::NoteInstance(input) => {
                self.apply_instance(input, None, ledger.as_deref_mut())
            }
            Mutation::ObserveInstanceSemantic(input) => {
                self.apply_instance_call(input, ledger.as_deref_mut())
            }
            Mutation::InstanceSemanticLoss(input) => {
                self.apply_instance_loss(input, ledger.as_deref_mut())
            }
            Mutation::RetireInstance(input) => {
                self.apply_instance_retirement(input, ledger.as_deref_mut())
            }
            Mutation::NoteMapping {
                caller,
                pid,
                info,
                evidence,
                at_ns,
            } => self.apply_mapping(caller, pid, info, evidence, at_ns),
            Mutation::ObserveEntries {
                caller,
                module,
                delta,
                at_ns,
            } => {
                let _ = self.apply_entries(caller, &module, delta, at_ns);
            }
            Mutation::SetInFlight {
                caller,
                module,
                in_flight,
            } => {
                if let Some(id) = self.modules_by_key.get(&module).copied()
                    && let Some(edge) = self.edges.get_mut(&(caller, id))
                {
                    edge.entry_in_flight = in_flight;
                }
            }
            Mutation::ObserveSemantic {
                caller,
                module,
                call,
            } => self.apply_semantic(caller, &module, &call),
            Mutation::NoteSemanticLoss { reason } => {
                // Generic loss: no counted column may claim an
                // exit-only cause, now or later.
                self.counted_generic_loss = true;
                self.counted_clean_exit = false;
                for edge in self.edges.values_mut() {
                    if let Some(state) = edge.semantics.as_mut() {
                        state.invalidate();
                    }
                    // Lost call records make every counted column a
                    // lower bound: a counted zero is no longer a fact.
                    if edge.coverage.counted_since_ns.is_some() || edge.entry_count > 0 {
                        edge.coverage.lossy = true;
                        edge.coverage.clean_exit = false;
                    }
                }
                self.push_gap(RegistryGap {
                    caller: None,
                    module: None,
                    pid: None,
                    subject: "semantic capture loss".into(),
                    reason,
                    budget: None,
                });
            }
            Mutation::NoteRefreshLoss { reason } => {
                // Generic loss: no counted column may claim an
                // exit-only cause, now or later.
                self.counted_generic_loss = true;
                self.counted_clean_exit = false;
                for edge in self.edges.values_mut() {
                    // A failed or skipped count re-read leaves every
                    // counted column a lower bound: observed counts
                    // stand, quiet claims do not.
                    if edge.coverage.counted_since_ns.is_some() || edge.entry_count > 0 {
                        edge.coverage.lossy = true;
                        edge.coverage.clean_exit = false;
                    }
                }
                self.push_gap(RegistryGap {
                    caller: None,
                    module: None,
                    pid: None,
                    subject: "native count refresh loss".into(),
                    reason,
                    budget: None,
                });
            }
            Mutation::NoteCountedLoss => {
                // Sticky for the capture: every later counted install
                // and `Counted` note honors it, including edges born
                // after the loss. Generic: no exit-only claim survives.
                self.counted_loss = true;
                self.counted_generic_loss = true;
                self.counted_clean_exit = false;
                for edge in self.edges.values_mut() {
                    // The capture scope went unproven: bound-pair growth
                    // stages nothing more (pending first-sight installs
                    // still land, now lossy), so every counted column
                    // is a lower bound. Observed counts stand; the
                    // lifecycle/custody gap discloses the cause.
                    if edge.coverage.counted_since_ns.is_some() || edge.entry_count > 0 {
                        edge.coverage.lossy = true;
                        edge.coverage.clean_exit = false;
                    }
                }
            }
            Mutation::NoteCountedPidExit => {
                // Sticky for the capture like `NoteCountedLoss`, with
                // the exit-only cause: honored only when no generic
                // loss of any kind came before (a later one still
                // clears it).
                if !self.counted_generic_loss && !self.counted_loss {
                    self.counted_clean_exit = true;
                }
                self.counted_loss = true;
                for edge in self.edges.values_mut() {
                    // The PID target exited cleanly: the count ran
                    // until the exit and is a lower bound. An edge
                    // already lossy keeps its earlier cause; a fresh
                    // edge names the exit.
                    if edge.coverage.counted_since_ns.is_some() || edge.entry_count > 0 {
                        if !edge.coverage.lossy {
                            edge.coverage.clean_exit = true;
                        }
                        edge.coverage.lossy = true;
                    }
                }
            }
            Mutation::NoteWitness {
                caller,
                module,
                first_ns,
            } => {
                if let Some(edge) = self.coverage_edge(caller, &module) {
                    let first = edge
                        .coverage
                        .witnessed_first_ns
                        .map_or(first_ns, |was| was.min(first_ns));
                    edge.coverage.witnessed_first_ns = Some(first);
                }
            }
            Mutation::NoteBoundWitness {
                caller,
                modules,
                first_ns,
            } => self.apply_bound_witness(caller, &modules, first_ns),
            Mutation::NoteUnboundWitness {
                modules,
                first_ns,
                reason,
                entries,
                image,
            } => match modules.as_slice() {
                [key] => {
                    self.apply_unbound_use(
                        key,
                        first_ns,
                        reason.code(),
                        reason.text(),
                        true,
                        entries,
                        image,
                    );
                }
                [] => self.witness_placement.unresolved += 1,
                shared => self.apply_shared_endpoint(shared, reason.text()),
            },
            Mutation::NoteUnresolvedWitness => self.witness_placement.unresolved += 1,
            Mutation::NoteUseBeforeAdmission {
                caller,
                module,
                reason,
            } => {
                // A key no module holds names no edge (`Some(None)`).
                let module = module.map(|key| self.modules_by_key.get(&key).copied());
                for ((_, id), edge) in self.edges.range_mut((caller, ModuleId(0))..) {
                    if edge.caller != caller {
                        break;
                    }
                    if module.is_some_and(|wanted| wanted != Some(*id)) {
                        continue;
                    }
                    edge.coverage.use_before_admission = true;
                    // A demotion's loss reason (a regression or lifecycle
                    // loss already made the watch unknown) stays: the
                    // flag alone keeps any watch from starting again.
                    if !(edge.coverage.demoted && matches!(edge.coverage.watch, Watch::Unknown(_)))
                    {
                        edge.coverage.demoted = true;
                        edge.coverage.watch = Watch::Unknown(reason.clone());
                    }
                }
            }
            Mutation::NoteWitnessCensus { census } => self.witness_census = census,
            Mutation::NoteCoverage {
                caller,
                module,
                note,
            } => self.apply_coverage(caller, &module, note),
            Mutation::NotePendingCount {
                pending_id,
                caller,
                modules,
                count,
                first_ns,
                last_ns,
                since_ns,
                base,
            } => self.apply_pending_count(
                pending_id, caller, &modules, count, first_ns, last_ns, since_ns, base,
            ),
            Mutation::NoteCountedUse {
                caller,
                module,
                count,
                first_ns,
                last_ns,
                base,
            } => {
                if base > 0 {
                    self.apply_demoted_use(caller, &module, count, first_ns, last_ns, base);
                } else {
                    self.apply_counted_install(caller, &module, count, first_ns, last_ns);
                }
            }
            Mutation::NotePairsUncounted { reason, at_ns } => {
                let mut demoted = 0usize;
                for edge in self.edges.values_mut() {
                    // An interval frozen before the evidence stands.
                    if matches!(edge.coverage.watch, Watch::Watching { until_ns, .. }
                        if until_ns.is_none_or(|until| until > at_ns))
                    {
                        edge.coverage.watch =
                            Watch::Unknown(UnknownReason::Uncounted(reason.clone()));
                        edge.coverage.demoted = true;
                        demoted += 1;
                    }
                }
                self.push_gap(RegistryGap {
                    caller: None,
                    module: None,
                    pid: None,
                    subject: PAIRS_UNCOUNTED_SUBJECT.into(),
                    reason: format!(
                        "{reason}; the failure cannot be localized to one pair, so {demoted} watched no-use {} read uncounted (no watch starts again in this capture)",
                        if demoted == 1 { "edge" } else { "edges" },
                    ),
                    budget: None,
                });
            }
            Mutation::EndWatches { reason, at_ns } => {
                if self.watches_ended_ns.is_none() {
                    self.watches_ended_ns = Some(at_ns);
                    for edge in self.edges.values_mut() {
                        if let Watch::Watching {
                            since_ns,
                            until_ns: None,
                        } = edge.coverage.watch
                        {
                            edge.coverage.watch = if at_ns > since_ns {
                                Watch::Watching {
                                    since_ns,
                                    until_ns: Some(at_ns),
                                }
                            } else {
                                // No clean instant proved any of it.
                                edge.coverage.demoted = true;
                                Watch::Unknown(UnknownReason::Loss(reason.clone()))
                            };
                        }
                    }
                }
            }
            Mutation::NoteHealthRegression {
                subject,
                reason,
                at_ns,
                detected_ns,
                restartable,
            } => {
                let restart = detected_ns.max(at_ns);
                self.last_health_regression_ns = Some(
                    self.last_health_regression_ns
                        .map_or(restart, |last| last.max(restart)),
                );
                let mut demoted = 0usize;
                for edge in self.edges.values_mut() {
                    // An interval frozen before the drop window stands.
                    if matches!(edge.coverage.watch, Watch::Watching { until_ns, .. }
                        if until_ns.is_none_or(|until| until > at_ns))
                    {
                        edge.coverage.watch = Watch::Unknown(UnknownReason::Loss(reason.clone()));
                        edge.coverage.demoted = true;
                        demoted += 1;
                    }
                }
                self.push_gap(RegistryGap {
                    caller: None,
                    module: None,
                    pid: None,
                    subject: subject.into(),
                    reason: format!(
                        "{reason}; the failure cannot be localized, so {demoted} watched no-use {} demoted to unknown ({})",
                        if demoted == 1 { "edge was" } else { "edges were" },
                        if restartable {
                            "a new watch may start only from the detecting read on"
                        } else {
                            "no watch starts again in this capture"
                        }
                    ),
                    budget: None,
                });
            }
            Mutation::RetireCaller {
                caller,
                reason,
                at_ns,
            } => self.apply_retire(caller, reason, at_ns, ledger.as_deref_mut()),
            Mutation::NoteModuleAbsent {
                caller,
                module,
                complete_scan,
                at_ns,
            } => self.apply_absent(caller, module, complete_scan, at_ns, ledger.as_deref_mut()),
            Mutation::NoteMemberUnscanned { caller } => {
                let mut modules = BTreeSet::new();
                for edge in self
                    .edges
                    .range_mut((caller, ModuleId(0))..=(caller, ModuleId(u32::MAX)))
                    .map(|(_, edge)| edge)
                    .filter(|edge| edge.mapping == MappingState::Mapped)
                {
                    edge.mapping = MappingState::Uncertain;
                    edge.mapping_reason = Some(
                        "member was not scanned this pass; the mapping is neither confirmed nor refuted"
                            .into(),
                    );
                    // Lifecycle evidence is missing: "right now"
                    // operation claims no longer have a proven edge
                    // beneath them, so they end unknown (C2).
                    if let Some(state) = edge.semantics.as_mut() {
                        state.invalidate();
                    }
                    modules.insert(edge.module);
                }
                for module in modules {
                    self.invalidate_physical_instances(
                        caller,
                        Some(module),
                        false,
                        ledger.as_deref_mut(),
                    );
                    self.recompute_module(module);
                }
            }
            Mutation::RecordGap { gap, terminal } => self.push_gap_as(gap, terminal),
            Mutation::RecordAggregatedUnrouted {
                subject,
                total,
                labels,
                bindings,
                terminal,
            } => self.push_aggregated_unrouted(subject, total, labels, bindings, terminal),
            Mutation::RecordKeyedGap {
                key,
                caller,
                pid,
                subject,
                reason,
                budget,
                terminal,
            } => {
                let module = self.modules_by_key.get(&key).copied();
                self.push_gap_as(
                    RegistryGap {
                        caller,
                        module,
                        pid,
                        subject,
                        reason,
                        budget,
                    },
                    terminal,
                );
            }
        }
    }

    fn apply_mapping(
        &mut self,
        caller: CallerId,
        pid: u32,
        info: ModuleInfo,
        evidence: MappingEvidence,
        at_ns: u64,
    ) {
        if self.retired.contains_key(&caller) {
            self.push_gap(RegistryGap {
                caller: Some(caller),
                module: None,
                pid: Some(pid),
                subject: "mapping for a retired caller".into(),
                reason:
                    "the caller incarnation retired; late mapping evidence was dropped, not merged"
                        .into(),
                budget: None,
            });
            return;
        }
        if !self.callers.contains(&caller) {
            if self.callers.len() >= self.limits.max_callers {
                self.callers_refused = self.callers_refused.saturating_add(1);
                let refusal = BudgetRefusal {
                    resource: "callers",
                    limit: self.limits.max_callers,
                    requested: self.callers.len() + 1,
                };
                self.push_gap(RegistryGap {
                    caller: Some(caller),
                    module: None,
                    pid: Some(pid),
                    subject: "caller capacity exhausted".into(),
                    reason: format!(
                        "the registry retains at most {} callers (requested caller {}); the mapping was dropped",
                        refusal.limit, refusal.requested,
                    ),
                    budget: Some(refusal),
                });
                return;
            }
            self.callers.insert(caller);
        }
        if matches!(info.key, ModuleKey::Unidentified { .. }) {
            self.push_gap(RegistryGap {
                caller: Some(caller),
                module: self.modules_by_key.get(&info.key).copied(),
                pid: Some(pid),
                subject: "module identity uncertain".into(),
                reason: format!(
                    "no comparable file identity for {}; the edge is keyed by path and distinct objects sharing it would merge",
                    info.path
                ),
                budget: None,
            });
        }
        let module = match self.modules_by_key.get(&info.key).copied() {
            Some(id) => {
                let record = self.modules.get_mut(&id).expect("indexed module");
                record.paths.insert(info.path.clone());
                // Admission follows the attach set's authoritative verdict
                // (I2): a module the run's attach set admits after a first
                // refusal reads admitted, with the change kept as history
                // and a gap — an instrumented module never reads refused.
                self.follow_admission(id, caller, pid, &info, at_ns);
                id
            }
            None => {
                if self.modules.len() >= self.limits.max_modules {
                    self.modules_refused = self.modules_refused.saturating_add(1);
                    let refusal = BudgetRefusal {
                        resource: "modules",
                        limit: self.limits.max_modules,
                        requested: self.modules.len() + 1,
                    };
                    self.push_gap(RegistryGap {
                        caller: Some(caller),
                        module: None,
                        pid: Some(pid),
                        subject: "module capacity exhausted".into(),
                        reason: format!(
                            "the registry retains at most {} modules (requested module {}); the mapping was dropped",
                            refusal.limit, refusal.requested,
                        ),
                        budget: Some(refusal),
                    });
                    return;
                }
                // The endpoint census charges only admitted modules with a
                // count. Over budget, the new module is refused with a
                // named gap; retained modules and their edges are untouched.
                let cost = match info.admission {
                    AdmissionState::Admitted => info.admission_endpoints.unwrap_or(0),
                    AdmissionState::Refused | AdmissionState::Unresolved => 0,
                };
                if self.endpoints_total.saturating_add(cost) > self.limits.max_endpoints {
                    self.endpoints_refused = self.endpoints_refused.saturating_add(1);
                    let refusal = BudgetRefusal {
                        resource: "endpoints",
                        limit: self.limits.max_endpoints,
                        requested: self.endpoints_total.saturating_add(cost),
                    };
                    self.push_gap(RegistryGap {
                        caller: Some(caller),
                        module: None,
                        pid: Some(pid),
                        subject: "endpoint budget exhausted".into(),
                        reason: format!(
                            "the registry retains at most {} attach endpoints (requested {}); the mapping was dropped",
                            refusal.limit, refusal.requested,
                        ),
                        budget: Some(refusal),
                    });
                    return;
                }
                let id = ModuleId(self.next_module);
                self.next_module = self.next_module.saturating_add(1);
                let mut paths = BTreeSet::new();
                paths.insert(info.path.clone());
                self.endpoints_total = self.endpoints_total.saturating_add(cost);
                self.modules.insert(
                    id,
                    ModuleRecord {
                        id,
                        key: info.key.clone(),
                        paths,
                        build_id: info.build_id.clone(),
                        identity_source: info.identity_source.clone(),
                        admission: info.admission,
                        admission_class: info.admission_class.clone(),
                        admission_endpoints: info.admission_endpoints,
                        admission_reasons: info.admission_reasons.clone(),
                        admission_history: Vec::new(),
                        lifecycle: ModuleLifecycle::Mapped,
                        unloaded_observed: false,
                        unbound_use: None,
                    },
                );
                self.modules_by_key.insert(info.key.clone(), id);
                id
            }
        };
        match self.edges.get_mut(&(caller, module)) {
            Some(edge) => {
                if edge.mapping != MappingState::Mapped {
                    edge.mapping = MappingState::Mapped;
                    edge.mapping_reason = None;
                }
                edge.mapping_evidence = evidence;
                edge.mapping_last_seen_ns = at_ns;
            }
            None => {
                if self.edges.len() >= self.limits.max_edges {
                    self.edges_refused = self.edges_refused.saturating_add(1);
                    let refusal = BudgetRefusal {
                        resource: "edges",
                        limit: self.limits.max_edges,
                        requested: self.edges.len() + 1,
                    };
                    self.push_gap(RegistryGap {
                        caller: Some(caller),
                        module: Some(module),
                        pid: Some(pid),
                        subject: "edge capacity exhausted".into(),
                        reason: format!(
                            "the registry retains at most {} edges (requested edge {}); the mapping was dropped",
                            refusal.limit, refusal.requested,
                        ),
                        budget: Some(refusal),
                    });
                    return;
                }
                self.edges.insert(
                    (caller, module),
                    EdgeRecord {
                        caller,
                        module,
                        mapping: MappingState::Mapped,
                        mapping_reason: None,
                        mapping_evidence: evidence,
                        mapping_first_seen_ns: at_ns,
                        mapping_last_seen_ns: at_ns,
                        mapping_interruptions: 0,
                        entry_count: 0,
                        entry_saturated: false,
                        entry_first_seen_ns: None,
                        entry_last_seen_ns: None,
                        entry_in_flight: false,
                        entry_rose_since_previous_pass: false,
                        semantics: None,
                        double_loaded: false,
                        coverage: EdgeCoverage::default(),
                    },
                );
            }
        }
        // A reload returns the module to mapped; the unload history stays.
        if let Some(record) = self.modules.get_mut(&module) {
            record.lifecycle = ModuleLifecycle::Mapped;
        }
        self.apply_double_load(caller, module, pid, info.double_loaded);
    }

    /// Same-file double-load evidence (F7b/F7c): the mapping note's
    /// scan evidence shows this object loaded twice in the caller's
    /// process. The merged edge stands (one key, one module — the
    /// `dlopen` shape stays correct), but its semantics fail closed:
    /// live operations end unknown, the latch forces the label
    /// unknown from detection on (retained counters stand as
    /// history), and every later call voids at the gate — until a
    /// later note shows one load again. The named gap fires on the
    /// false→true transition only, so a steady double-load never
    /// spams the gap retention.
    fn apply_double_load(
        &mut self,
        caller: CallerId,
        module: ModuleId,
        pid: u32,
        double_loaded: bool,
    ) {
        let Some(edge) = self.edges.get_mut(&(caller, module)) else {
            return;
        };
        if !double_loaded {
            edge.double_loaded = false;
            if let Some(state) = edge.semantics.as_mut() {
                state.clear_double_load();
            }
            return;
        }
        if edge.double_loaded {
            return;
        }
        edge.double_loaded = true;
        if let Some(state) = edge.semantics.as_mut() {
            state.mark_double_load();
        }
        let gap = RegistryGap {
            caller: Some(caller),
            module: Some(module),
            pid: Some(pid),
            subject: "same-file double-load detected".into(),
            reason: "this object is mapped twice with duplicate executable file offsets; observed calls cannot attribute to one instance and establish no claim"
                .into(),
            budget: None,
        };
        self.push_gap(gap);
    }

    /// One bound row's publication-time placement (P3): the caller
    /// edge its witness and count take together, from the same committed
    /// state — exactly one edged module, or the rejection the witness
    /// records. Both [`Self::apply_bound_witness`] and
    /// [`Self::apply_pending_count`] decide through this one function, so
    /// a count lands exactly where its witness did, or drops exactly
    /// where its witness went module-level.
    fn place_bound_row(&self, caller: CallerId, modules: &[ModuleKey]) -> RowPlacement {
        let edged: Vec<(&ModuleKey, ModuleId)> = modules
            .iter()
            .filter_map(|key| {
                self.modules_by_key
                    .get(key)
                    .copied()
                    .filter(|id| self.edges.contains_key(&(caller, *id)))
                    .map(|id| (key, id))
            })
            .collect();
        match (edged.as_slice(), modules) {
            ([(key, id)], _) => RowPlacement::Edge {
                key: (*key).clone(),
                id: *id,
            },
            ([], [key]) => RowPlacement::NoMapping { key: key.clone() },
            ([], []) => RowPlacement::Unresolved,
            _ => RowPlacement::Shared,
        }
    }

    /// The edge a coverage note names, or `None` with a gap: coverage
    /// notes never invent edges. Retired callers stay addressable —
    /// positive history survives retirement.
    fn apply_bound_witness(&mut self, caller: CallerId, modules: &[ModuleKey], first_ns: u64) {
        match self.place_bound_row(caller, modules) {
            RowPlacement::Edge { id, .. } => {
                let edge = self.edges.get_mut(&(caller, id)).expect("edged");
                let first = edge
                    .coverage
                    .witnessed_first_ns
                    .map_or(first_ns, |was| was.min(first_ns));
                edge.coverage.witnessed_first_ns = Some(first);
                self.witness_placement.edge += 1;
            }
            RowPlacement::NoMapping { key } => {
                // The caller is identified; only its mapping is missing.
                let id = self.modules_by_key.get(&key).copied();
                self.push_coverage_gap(
                    caller,
                    &key,
                    id,
                    WITNESS_WITHOUT_MAPPING,
                    format!(
                        "{} has no mapping edge to this module: the witnessed use stays \
                         module-level; a witness never invents a mapping",
                        caller.label()
                    ),
                );
                self.apply_unbound_use(
                    &key,
                    first_ns,
                    NO_MAPPING_EDGE,
                    "the bound caller has no mapping edge to the module",
                    false,
                    // Bound rows keep their counts in the pending-count
                    // pipeline; only unbound rows fold here.
                    0,
                    // The caller is known: never an unidentified image.
                    None,
                );
            }
            RowPlacement::Unresolved => self.witness_placement.unresolved += 1,
            RowPlacement::Shared => {
                self.apply_shared_endpoint(modules, "bound to a caller incarnation");
            }
        }
    }

    /// One pending count's publication: placement comes from
    /// [`Self::place_bound_row`] — the same decision its witness took —
    /// and admission mirrors the coordinator's `stage_pair_count` (only
    /// admitted modules count). On placement the count and its `Counted`
    /// coverage apply exactly as if staged placed — a demoted count
    /// accumulates its growth onto the edge (round 4, re-place); a
    /// first-sight rejection drops silently (the witness records the
    /// placement gaps, and no gap is owed twice), while a demoted
    /// rejection discloses under its own subject instead (F3-02). Every
    /// outcome is reported through [`Self::take_pending_count_decisions`].
    #[allow(clippy::too_many_arguments)]
    fn apply_pending_count(
        &mut self,
        pending_id: u64,
        caller: CallerId,
        modules: &[ModuleKey],
        count: u64,
        first_ns: u64,
        last_ns: u64,
        since_ns: u64,
        base: u64,
    ) {
        let outcome = match self.place_bound_row(caller, modules) {
            RowPlacement::Edge { key, .. } => {
                let admitted = self
                    .modules_by_key
                    .get(&key)
                    .and_then(|id| self.modules.get(id))
                    .is_some_and(|record| record.admission == AdmissionState::Admitted);
                if !admitted {
                    PendingCountOutcome::Unadmitted { module: key }
                } else {
                    self.apply(
                        Mutation::NoteCountedUse {
                            caller,
                            module: key.clone(),
                            count,
                            first_ns,
                            last_ns,
                            base,
                        },
                        None,
                    );
                    self.apply(
                        Mutation::NoteCoverage {
                            caller,
                            module: key.clone(),
                            note: CoverageNote::Counted { since_ns },
                        },
                        None,
                    );
                    PendingCountOutcome::Placed { module: key }
                }
            }
            RowPlacement::NoMapping { .. } | RowPlacement::Unresolved => {
                PendingCountOutcome::Rejected {
                    reason: PendingRejection::NoEdge,
                }
            }
            RowPlacement::Shared => PendingCountOutcome::Rejected {
                reason: PendingRejection::Ambiguous,
            },
        };
        if base > 0
            && let PendingCountOutcome::Rejected { reason } = &outcome
        {
            self.disclose_demoted_rejection(caller, modules, count, *reason);
        }
        self.pending_count_decisions.push(PendingCountDecision {
            pending_id,
            outcome,
        });
    }

    /// One demoted count's rejection disclosure (F3-02): the pair's
    /// witness resolved cleanly when the pair was sole-owned, so no
    /// witness in this window records the placement — the count records
    /// its own disclosure gaps, naming the unattributed growth, so a
    /// rejected demoted count never finalizes silently. The disclosure
    /// is gap-only: the rejected count has no witness row, so it must
    /// never account a witness placement or invent a module-level use
    /// row (round 4, census). Every arm pushes direct under its own
    /// subject, memoized nowhere: count disclosures share no memo
    /// bucket with witness gaps in either direction, and repeat
    /// rejections each disclose (identical repeats fold into the gap's
    /// repeat count; distinct ones stand on their own, bounded by the
    /// gap retention bound like every other gap). Ambiguity takes one
    /// gap per sharer; a single unedged candidate records a
    /// caller-scoped gap naming the missing edge; no candidate at all
    /// reports caller-wide (the endpoint left the attach set entirely).
    fn disclose_demoted_rejection(
        &mut self,
        caller: CallerId,
        modules: &[ModuleKey],
        count: u64,
        reason: PendingRejection,
    ) {
        match (reason, modules) {
            (PendingRejection::Ambiguous, _) => {
                for key in modules {
                    let id = self.modules_by_key.get(key).copied();
                    self.push_gap(RegistryGap {
                        caller: None,
                        module: id,
                        pid: None,
                        subject: DEMOTED_COUNT_REJECTED.into(),
                        reason: with_key(
                            format!(
                                "a native witness endpoint is shared by {} admitted modules \
                                 (re-resolved with {count} unattributed calls after sharing appeared): \
                                 which module was used is ambiguous, so no edge and no module-level use \
                                 is recorded",
                                modules.len()
                            ),
                            id,
                            key,
                        ),
                        budget: None,
                    });
                }
            }
            (PendingRejection::NoEdge, [key]) => {
                let id = self.modules_by_key.get(key).copied();
                self.push_gap(RegistryGap {
                    caller: Some(caller),
                    module: id,
                    pid: None,
                    subject: DEMOTED_COUNT_REJECTED.into(),
                    reason: with_key(
                        format!(
                            "{} has no mapping edge to this module: the re-resolved count ({count} calls) \
                             names no carrier, so no edge and no module-level use is recorded; a count never \
                             invents a mapping",
                            caller.label()
                        ),
                        id,
                        key,
                    ),
                    budget: None,
                });
            }
            (PendingRejection::NoEdge, []) => {
                self.push_gap(RegistryGap {
                    caller: Some(caller),
                    module: None,
                    pid: None,
                    subject: DEMOTED_COUNT_REJECTED.into(),
                    reason: format!(
                        "the pair re-resolved after its endpoint left the attach set ({count} calls): no module \
                         can carry them, so no edge and no module-level use is recorded; history stands on the \
                         stale edge"
                    ),
                    budget: None,
                });
            }
            // Multi-candidate placements reject ambiguous, never NoEdge.
            (PendingRejection::NoEdge, _) => {}
        }
    }

    /// A retirement boundary is uncertainty, never a witness or a count.
    /// The coordinator supplies disjoint absolute ranges through its watermark.
    pub(crate) fn note_retirement_count_gap(&mut self, caller: CallerId, base: u64, absolute: u64) {
        if absolute <= base {
            return;
        }
        self.record_gap(RegistryGap {
            caller: Some(caller), module: None, pid: None,
            subject: DEMOTED_COUNT_REJECTED.into(),
            reason: format!("the current physical owner is not proven for absolute count range ({base}, {absolute}] ({} unattributed calls); historical counts remain and no witness or module-level use is recorded", absolute - base),
            budget: None,
        });
    }

    /// One row whose endpoint several admitted modules share, with no
    /// single module (or single caller edge) to carry it: a gap per module,
    /// no edge, no module-level use.
    fn apply_shared_endpoint(&mut self, modules: &[ModuleKey], text: &str) {
        self.witness_placement.ambiguous += 1;
        for key in modules {
            let id = self.modules_by_key.get(key).copied();
            self.push_witness_gap(
                key,
                id,
                WITNESS_SHARED_ENDPOINT,
                format!(
                    "a native witness endpoint is shared by {} admitted modules ({text}): \
                     which module was used is ambiguous, so no edge and no module-level use \
                     is recorded",
                    modules.len()
                ),
            );
        }
    }

    /// One row of module-level use. `unidentified`: the row's caller image
    /// is unknown (a binder reason), so the module gets the
    /// unidentified-caller gap; a `no_mapping_edge` row's caller is known
    /// and its gap names the caller instead. `image` feeds the
    /// per-module and run-wide slice-1 sets on this committed path only
    /// (shared, unresolved and `no_mapping_edge` rows never insert).
    #[allow(clippy::too_many_arguments)] // The image joins the existing explicit apply seam; bundling would churn both call sites for no gain.
    fn apply_unbound_use(
        &mut self,
        key: &ModuleKey,
        first_ns: u64,
        code: &'static str,
        text: &str,
        unidentified: bool,
        entries: u64,
        image: Option<UnboundImage>,
    ) {
        let Some(id) = self.modules_by_key.get(key).copied() else {
            self.witness_placement.unresolved += 1;
            self.push_witness_gap(
                key,
                None,
                WITNESS_UNKNOWN_MODULE,
                format!(
                    "a native witness names a module no mapping note registered ({text}); \
                     the use cannot be shown"
                ),
            );
            return;
        };
        self.witness_placement.module += 1;
        let limits = self.unbound_image_limits;
        {
            let module = self.modules.get_mut(&id).expect("indexed module");
            let unbound = module.unbound_use.get_or_insert(UnboundUse {
                first_ns,
                rows: 0,
                reasons: BTreeMap::new(),
                entries: 0,
                images: HashMap::new(),
                images_saturated: false,
                pids_dropped: 0,
            });
            unbound.first_ns = unbound.first_ns.min(first_ns);
            unbound.rows = unbound.rows.saturating_add(1);
            unbound.entries = unbound.entries.saturating_add(entries);
            let count = unbound.reasons.entry(code).or_default();
            *count = count.saturating_add(1);
            if let Some(image) = image.clone() {
                Self::insert_unbound_image(
                    &mut unbound.images,
                    &mut unbound.images_saturated,
                    &mut unbound.pids_dropped,
                    limits.per_module,
                    image,
                );
            }
        }
        if let Some(image) = image {
            Self::insert_unbound_image(
                &mut self.unidentified_images,
                &mut self.unidentified_images_saturated,
                &mut self.unidentified_pids_dropped,
                limits.global,
                image,
            );
        }
        if unidentified {
            let module = self.modules.get(&id).expect("indexed module");
            let path = module.paths.iter().next().cloned().unwrap_or_default();
            self.push_witness_gap(
                key,
                Some(id),
                UNBOUND_USE_SUBJECT,
                format!(
                    "{path}: native witness rows of this module were not bound to a caller \
                     incarnation (first: {text}); module-level positive use only, never \
                     attributed by pid"
                ),
            );
        }
    }

    /// Insert `image` into a slice-1 image set: a known image keeps
    /// the earliest call, accumulates its folded calls, and keeps
    /// its first executable (resolve-once: only the EXEC backfill
    /// and the loss flip update it); a new image past the bound
    /// saturates and counts as dropped instead of growing.
    fn insert_unbound_image(
        images: &mut HashMap<DomainCookie, UnboundPid>,
        saturated: &mut bool,
        dropped: &mut u64,
        limit: usize,
        image: UnboundImage,
    ) {
        if let Some(known) = images.get_mut(&image.cookie) {
            known.first_call_ns = known.first_call_ns.min(image.first_call_ns);
            known.calls_at_least = known.calls_at_least.saturating_add(image.calls);
        } else if images.len() < limit {
            images.insert(
                image.cookie,
                UnboundPid {
                    pid_host: image.pid_host,
                    first_call_ns: image.first_call_ns,
                    calls_at_least: image.calls,
                    exe: image.exe,
                },
            );
        } else {
            *saturated = true;
            *dropped = dropped.saturating_add(1);
        }
    }

    /// Whether the run-wide image set holds `cookie`: the O(1)
    /// backfill index. A cookie the saturated run-wide set dropped
    /// but a module set kept misses the backfill and keeps its
    /// provisional verdict (an honest unknown, disclosed through
    /// the saturation accounting) — the price of never scanning
    /// every module per EXEC.
    pub(crate) fn has_unbound_image(&self, cookie: DomainCookie) -> bool {
        self.unidentified_images.contains_key(&cookie)
    }

    /// Backfill one joined executable into every image set holding
    /// `cookie` (the EXEC arrived after the row staged). Unknown
    /// cookies attach nowhere and refuse nothing.
    pub(crate) fn attach_unbound_exe(&mut self, cookie: DomainCookie, exe: UnboundExe) {
        if let Some(known) = self.unidentified_images.get_mut(&cookie) {
            known.exe = exe.clone();
        }
        for module in self.modules.values_mut() {
            if let Some(unbound) = module.unbound_use.as_mut()
                && let Some(known) = unbound.images.get_mut(&cookie)
            {
                known.exe = exe.clone();
            }
        }
    }

    /// Lifecycle evidence was lost in `domain`: every image of that
    /// domain still without a joined EXEC reads `exec_record_lost`.
    /// Images with a joined pair (resolved or unavailable) are
    /// unaffected: their EXEC provably arrived.
    pub(crate) fn flip_unbound_exec_loss(&mut self, domain: NativeDomainId) {
        let lost = UnboundExe {
            dev: 0,
            ino: 0,
            path: None,
            resolution: ExeResolution::ExecRecordLost,
            identity_candidates: Vec::new(),
        };
        for (cookie, known) in self.unidentified_images.iter_mut() {
            if cookie.domain() == domain && known.exe.resolution == ExeResolution::NoExecRecord {
                known.exe = lost.clone();
            }
        }
        for module in self.modules.values_mut() {
            let Some(unbound) = module.unbound_use.as_mut() else {
                continue;
            };
            for (cookie, known) in unbound.images.iter_mut() {
                if cookie.domain() == domain && known.exe.resolution == ExeResolution::NoExecRecord
                {
                    known.exe = lost.clone();
                }
            }
        }
    }

    /// One module-level witness gap, once per (module, subject).
    fn push_witness_gap(
        &mut self,
        key: &ModuleKey,
        module: Option<ModuleId>,
        subject: &'static str,
        reason: String,
    ) {
        let memo = (key.clone(), subject);
        if self.witness_gap_memo.contains(&memo) {
            return;
        }
        if self.witness_gap_memo.len() < self.limits.max_gaps {
            self.witness_gap_memo.insert(memo);
        }
        self.push_gap(RegistryGap {
            caller: None,
            module,
            pid: None,
            subject: subject.into(),
            reason: with_key(reason, module, key),
            budget: None,
        });
    }

    /// One absolute count install: only a strict advance moves the
    /// count or last-seen. Equal-or-less re-reads (a stale refresh, a
    /// repeated first sight) change nothing, so recency always names
    /// the read that observed the rise. Retired callers are not frozen
    /// out: like a witness, the count is pre-exit history arriving
    /// late. Coverage notes never invent edges (one memoized gap).
    fn apply_counted_install(
        &mut self,
        caller: CallerId,
        module: &ModuleKey,
        count: u64,
        first_ns: u64,
        last_ns: u64,
    ) {
        let counted_loss = self.counted_loss;
        let counted_clean_exit = self.counted_clean_exit;
        let Some(edge) = self.coverage_edge(caller, module) else {
            return;
        };
        if counted_loss {
            if !edge.coverage.lossy {
                edge.coverage.clean_exit = counted_clean_exit;
            }
            edge.coverage.lossy = true;
        }
        if count > edge.entry_count {
            edge.entry_rose_since_previous_pass = true;
            if count == MAX_EDGE_ENTRY_COUNT {
                edge.entry_count = MAX_EDGE_ENTRY_COUNT;
                edge.entry_saturated = true;
            } else {
                edge.entry_count = count;
            }
            edge.entry_first_seen_ns = Some(
                edge.entry_first_seen_ns
                    .map_or(first_ns, |was| was.min(first_ns)),
            );
            // Recency survives saturation: the count stops,
            // last-seen does not.
            edge.entry_last_seen_ns = Some(last_ns);
        }
    }

    /// One demoted count install (round 4, re-place): growth past the
    /// pair's accounted `base` accumulates onto the edge. The install
    /// is the edge's publication-start count plus the covered growth
    /// staged this publication — exact across any number of reads per
    /// commit — and still honors strict advance (an edge another pair
    /// already carried past the install keeps its maximum). Growth
    /// starting past the edge's publication-start count marks the edge
    /// (once per caller and module): its count is segment-relative, so
    /// per-segment exactness is unverifiable (round 4, window anchor).
    fn apply_demoted_use(
        &mut self,
        caller: CallerId,
        module: &ModuleKey,
        growth: u64,
        first_ns: u64,
        last_ns: u64,
        base: u64,
    ) {
        let id = self.modules_by_key.get(module).copied();
        let base_edge =
            id.and_then(|id| self.edges.get(&(caller, id)).map(|edge| edge.entry_count));
        let Some((id, base_edge)) = id.zip(base_edge) else {
            let _ = self.coverage_edge(caller, module);
            return;
        };
        if base > base_edge {
            self.push_coverage_gap(
                caller,
                module,
                Some(id),
                DEMOTED_COUNT_PLACED,
                "a demoted count placed post-demotion growth on this edge: the edge's count covers \
                 a workload segment starting at the base read, never the whole workload, so \
                 per-segment exactness is unverifiable and only the ledger window's upper bound \
                 applies"
                    .into(),
            );
        }
        let absolute = base.saturating_add(growth);
        let state = self
            .demoted_place_growth
            .entry((caller, id))
            .or_insert(DemotedGrowth {
                base_edge,
                segments: Vec::new(),
            });
        state.segments.push((base, absolute, first_ns, last_ns));
        let (first_ns, last_ns) = state.stamps();
        let install = state.base_edge.saturating_add(state.total());
        self.apply_counted_install(caller, module, install, first_ns, last_ns);
    }

    fn coverage_edge(&mut self, caller: CallerId, module: &ModuleKey) -> Option<&mut EdgeRecord> {
        let id = self.modules_by_key.get(module).copied();
        if let Some(id) = id
            && self.edges.contains_key(&(caller, id))
        {
            return self.edges.get_mut(&(caller, id));
        }
        self.push_coverage_gap(
            caller,
            module,
            id,
            COVERAGE_WITHOUT_MAPPING,
            "usage coverage never invents mappings; the note was dropped".into(),
        );
        None
    }

    /// One coverage-note gap, recorded once per (caller, module, subject)
    /// so a producer repeating a bad note every pass cannot flood the gap
    /// retention bound.
    fn push_coverage_gap(
        &mut self,
        caller: CallerId,
        key: &ModuleKey,
        module: Option<ModuleId>,
        subject: &'static str,
        reason: String,
    ) {
        let memo = (caller, key.clone(), subject);
        if self.coverage_gap_memo.contains(&memo) {
            return;
        }
        if self.coverage_gap_memo.len() < self.limits.max_gaps {
            self.coverage_gap_memo.insert(memo);
        }
        self.push_gap(RegistryGap {
            caller: Some(caller),
            module,
            pid: None,
            subject: subject.into(),
            reason: with_key(reason, module, key),
            budget: None,
        });
    }

    fn apply_coverage(&mut self, caller: CallerId, module: &ModuleKey, note: CoverageNote) {
        let retired = self.retired.contains_key(&caller);
        let admitted = self
            .modules_by_key
            .get(module)
            .and_then(|id| self.modules.get(id))
            .is_some_and(|record| record.admission == AdmissionState::Admitted);
        let module_id = self.modules_by_key.get(module).copied();
        let regression = self.last_health_regression_ns;
        let ended = self.watches_ended_ns.is_some();
        let counted_loss = self.counted_loss;
        let counted_clean_exit = self.counted_clean_exit;
        let positive = matches!(
            note,
            CoverageNote::Counted { .. } | CoverageNote::Watched { .. }
        );
        if positive && !admitted && module_id.is_some() {
            // Counting and watching both mean "instrumented": a module
            // whose admission is not admitted has neither, so the note is
            // a producer error and its zero stays unknown.
            if self.coverage_edge(caller, module).is_some() {
                self.push_coverage_gap(
                    caller,
                    module,
                    module_id,
                    COVERAGE_UNADMITTED,
                    "a coverage note named a module whose admission is not admitted; its usage stays unknown"
                        .into(),
                );
            }
            return;
        }
        let Some(edge) = self.coverage_edge(caller, module) else {
            return;
        };
        let coverage = &mut edge.coverage;
        match note {
            CoverageNote::Counted { .. } | CoverageNote::Watched { .. } if retired => {
                // The caller retired before this note: it covers nothing
                // that is still observable. An edge with no coverage at
                // all says so; existing coverage stays as it was.
                if coverage.counted_since_ns.is_none() && coverage.watch == Watch::Unset {
                    coverage.watch = Watch::Unknown(UnknownReason::RetiredBeforeCoverage);
                }
            }
            CoverageNote::Counted { since_ns } => {
                // Positive history: the first counting start stands.
                coverage.counted_since_ns = Some(
                    coverage
                        .counted_since_ns
                        .map_or(since_ns, |was| was.min(since_ns)),
                );
                if counted_loss {
                    if !coverage.lossy {
                        coverage.clean_exit = counted_clean_exit;
                    }
                    coverage.lossy = true;
                }
            }
            CoverageNote::Watched { since_ns } => {
                if ended
                    || coverage.use_before_admission
                    || matches!(coverage.watch, Watch::Watching { .. })
                {
                    // An ongoing watch keeps its earliest start; a frozen
                    // one is a fact; after the end nothing starts.
                } else {
                    // A new interval (also after a demotion: the demoted
                    // interval stays demoted) never starts before the
                    // last regression's detecting read.
                    let since_ns = regression.map_or(since_ns, |at| since_ns.max(at));
                    coverage.watch = Watch::Watching {
                        since_ns,
                        until_ns: None,
                    };
                    coverage.demoted = false;
                }
            }
            CoverageNote::Unknown(reason) => {
                let frozen = matches!(
                    coverage.watch,
                    Watch::Watching {
                        until_ns: Some(_),
                        ..
                    }
                );
                if !coverage.demoted && !frozen {
                    coverage.watch = Watch::Unknown(reason);
                }
            }
        }
    }

    /// I2: a retained module's admission follows later verdicts, rising
    /// only (`unresolved` < `refused` < `admitted`). A rise replaces the
    /// verdict, charges the endpoint census, keeps the change in
    /// `admission_history`, and records a gap; the same state refreshes
    /// the class, endpoint count, and reasons (the attach set's latest
    /// disclosure); a lower state never demotes it, so records never
    /// flap and an instrumented module never reads refused.
    fn follow_admission(
        &mut self,
        id: ModuleId,
        caller: CallerId,
        pid: u32,
        info: &ModuleInfo,
        at_ns: u64,
    ) {
        const fn rank(state: AdmissionState) -> u8 {
            match state {
                AdmissionState::Unresolved => 0,
                AdmissionState::Refused => 1,
                AdmissionState::Admitted => 2,
            }
        }
        let record = self.modules.get_mut(&id).expect("indexed module");
        let from = record.admission;
        if rank(info.admission) < rank(from) {
            // Never demoted, but never silent: the ignored verdict is
            // disclosed in the reasons (deduplicated, bounded).
            let detail = if info.admission_reasons.is_empty() {
                String::new()
            } else {
                format!(" ({})", info.admission_reasons.join("; "))
            };
            let note = format!(
                "a later verdict read {}{detail} and was not applied: the {} verdict stands",
                info.admission.label(),
                from.label(),
            );
            if record.admission_reasons.len() < MAX_ADMISSION_REASONS
                && !record.admission_reasons.contains(&note)
            {
                record.admission_reasons.push(note);
            }
            return;
        }
        let cost = |state: AdmissionState, endpoints: Option<usize>| match state {
            AdmissionState::Admitted => endpoints.unwrap_or(0),
            AdmissionState::Refused | AdmissionState::Unresolved => 0,
        };
        let old_cost = cost(from, record.admission_endpoints);
        let new_cost = cost(info.admission, info.admission_endpoints);
        record.admission = info.admission;
        record.admission_class = info.admission_class.clone();
        record.admission_endpoints = info.admission_endpoints;
        record.admission_reasons = info.admission_reasons.clone();
        // The record is retained already: the census follows the verdict
        // and never refuses it (the attach set is the authority).
        self.endpoints_total = self
            .endpoints_total
            .saturating_sub(old_cost)
            .saturating_add(new_cost);
        if info.admission == from {
            return;
        }
        record.admission_history.push(AdmissionChange {
            from,
            to: info.admission,
            at_ns,
        });
        let reasons = if info.admission_reasons.is_empty() {
            String::new()
        } else {
            format!(" ({})", info.admission_reasons.join("; "))
        };
        let reason = format!(
            "{}: admission changed from {} to {}{reasons}",
            info.path,
            from.label(),
            info.admission.label(),
        );
        self.push_gap(RegistryGap {
            caller: Some(caller),
            module: Some(id),
            pid: Some(pid),
            subject: "module admission changed".into(),
            reason,
            budget: None,
        });
    }

    fn apply_entries(
        &mut self,
        caller: CallerId,
        module: &ModuleKey,
        delta: u64,
        at_ns: u64,
    ) -> EntryOutcome {
        if self.retired.contains_key(&caller) {
            return EntryOutcome::FrozenRetired;
        }
        let Some(id) = self.modules_by_key.get(module).copied() else {
            self.push_gap(RegistryGap {
                caller: Some(caller),
                module: None,
                pid: None,
                subject: "entry without mapping evidence".into(),
                reason: "observed entries never invent mappings; the batch was dropped".into(),
                budget: None,
            });
            return EntryOutcome::UnknownEdge;
        };
        let counted_loss = self.counted_loss;
        let counted_clean_exit = self.counted_clean_exit;
        let Some(edge) = self.edges.get_mut(&(caller, id)) else {
            self.push_gap(RegistryGap {
                caller: Some(caller),
                module: Some(id),
                pid: None,
                subject: "entry without mapping evidence".into(),
                reason: "observed entries never invent mappings; the batch was dropped".into(),
                budget: None,
            });
            return EntryOutcome::UnknownEdge;
        };
        if counted_loss {
            if !edge.coverage.lossy {
                edge.coverage.clean_exit = counted_clean_exit;
            }
            edge.coverage.lossy = true;
        }
        let (count, overflowed) = edge.entry_count.overflowing_add(delta);
        if count > edge.entry_count {
            edge.entry_rose_since_previous_pass = true;
        }
        if count == MAX_EDGE_ENTRY_COUNT || overflowed {
            edge.entry_count = MAX_EDGE_ENTRY_COUNT;
            edge.entry_saturated = true;
        } else {
            edge.entry_count = count;
        }
        if edge.entry_first_seen_ns.is_none() {
            edge.entry_first_seen_ns = Some(at_ns);
        }
        // Recency survives saturation: the count stops, last-seen does not.
        edge.entry_last_seen_ns = Some(at_ns);
        EntryOutcome::Recorded
    }

    /// Feed one semantic call to its edge's reducer. Retired callers
    /// are frozen (the call is dropped, like late entries); calls
    /// without mapping evidence never invent edges (a named gap);
    /// first observation materializes the edge's state within the
    /// `max_semantic_states` budget (past it: a refusal gap plus the
    /// loss counter, never an eviction of retained state).
    fn apply_semantic(&mut self, caller: CallerId, module: &ModuleKey, call: &SemanticCall) {
        if self.retired.contains_key(&caller) {
            return;
        }
        let Some(id) = self.modules_by_key.get(module).copied() else {
            self.push_gap(RegistryGap {
                caller: Some(caller),
                module: None,
                pid: None,
                subject: "semantic call without mapping evidence".into(),
                reason: "observed calls never invent mappings; the call was dropped".into(),
                budget: None,
            });
            return;
        };
        if !self.edges.contains_key(&(caller, id)) {
            self.push_gap(RegistryGap {
                caller: Some(caller),
                module: Some(id),
                pid: None,
                subject: "semantic call without mapping evidence".into(),
                reason: "observed calls never invent mappings; the call was dropped".into(),
                budget: None,
            });
            return;
        }
        let needs_materialize = self
            .edges
            .get(&(caller, id))
            .is_some_and(|edge| edge.semantics.is_none());
        if needs_materialize {
            if self.semantic_occupied + self.instance_semantic_occupied()
                >= self.limits.max_semantic_states
            {
                self.semantic_refused = self.semantic_refused.saturating_add(1);
                let refusal = BudgetRefusal {
                    resource: "semantic_state",
                    limit: self.limits.max_semantic_states,
                    requested: self.semantic_occupied + self.instance_semantic_occupied() + 1,
                };
                self.push_gap(RegistryGap {
                    caller: Some(caller),
                    module: Some(id),
                    pid: None,
                    subject: "semantic state capacity exhausted".into(),
                    reason: format!(
                        "the registry retains at most {} semantic states (requested state {}); the call was dropped",
                        refusal.limit, refusal.requested,
                    ),
                    budget: Some(refusal),
                });
                return;
            }
            let reducer = match EdgeSemantics::with_resources(&self.semantic_resources) {
                Ok(reducer) => reducer,
                Err(refusal) => {
                    self.refuse_semantic_resource(caller, id, refusal);
                    return;
                }
            };
            self.edges
                .get_mut(&(caller, id))
                .expect("edge resolved above")
                .semantics = Some(reducer);
            self.semantic_occupied = self.semantic_occupied.saturating_add(1);
        }
        let edge = self
            .edges
            .get_mut(&(caller, id))
            .expect("edge resolved above");
        // Same-file double-load (F7b): the call happened, but no one
        // instance can own it — it establishes no claim.
        let unattributed;
        let call = if edge.double_loaded {
            unattributed = SemanticCall {
                attributable: false,
                ..call.clone()
            };
            &unattributed
        } else {
            call
        };
        let refused = edge
            .semantics
            .as_mut()
            .expect("semantic state materialized above")
            .observe_with_resources(call);
        match refused {
            Ok(refused) => self.semantic_refused = self.semantic_refused.saturating_add(refused),
            Err(refusal) => self.refuse_semantic_resource(caller, id, refusal),
        }
    }

    fn refuse_semantic_resource(
        &mut self,
        caller: CallerId,
        module: ModuleId,
        refusal: crate::semantics_edge::resources::SemanticResourceRefusal,
    ) {
        self.semantic_refused = self.semantic_refused.saturating_add(1);
        self.push_gap(RegistryGap {
            caller: Some(caller),
            module: Some(module),
            pid: None,
            subject: "semantic resource capacity exhausted".into(),
            reason: "semantic_resource_capacity".into(),
            budget: Some(BudgetRefusal {
                resource: "semantic_resource",
                limit: refusal.limit_bytes,
                requested: refusal.requested_bytes,
            }),
        });
    }

    fn apply_retire(
        &mut self,
        caller: CallerId,
        reason: String,
        at_ns: u64,
        shared: Option<&mut crate::semantics_objects::journal::StagingLedger>,
    ) {
        let _ = at_ns;
        self.retired.insert(caller, reason.clone());
        self.invalidate_physical_instances(caller, None, true, shared);
        let mut modules = BTreeSet::new();
        for edge in self
            .edges
            .range_mut((caller, ModuleId(0))..=(caller, ModuleId(u32::MAX)))
            .map(|(_, edge)| edge)
            .filter(|edge| matches!(edge.mapping, MappingState::Mapped | MappingState::Uncertain))
        {
            edge.mapping = MappingState::Ended;
            edge.mapping_reason = Some(reason.clone());
            // A retired edge keeps its claims (retained evidence) but
            // its live operations end unknown (C2) — retirement proves
            // an end, never a completion.
            if let Some(state) = edge.semantics.as_mut() {
                state.invalidate();
            }
            modules.insert(edge.module);
        }
        for module in modules {
            self.recompute_module(module);
        }
    }

    /// Module mapping currency from its edges: mapped while any edge
    /// maps it, unloaded once a complete rescan proved it gone (sticky
    /// until a mapping returns), unknown when no live mapping evidence
    /// remains — never a confident label on missing evidence.
    fn recompute_module(&mut self, module: ModuleId) {
        let (any_mapped, any_uncertain) = self
            .edges
            .values()
            .filter(|edge| edge.module == module)
            .fold((false, false), |(mapped, uncertain), edge| {
                (
                    mapped || edge.mapping == MappingState::Mapped,
                    uncertain || edge.mapping == MappingState::Uncertain,
                )
            });
        let Some(record) = self.modules.get_mut(&module) else {
            return;
        };
        record.lifecycle = if any_mapped {
            ModuleLifecycle::Mapped
        } else if record.unloaded_observed && !any_uncertain {
            ModuleLifecycle::Unloaded
        } else {
            ModuleLifecycle::Unknown
        };
    }

    fn apply_absent(
        &mut self,
        caller: CallerId,
        module: ModuleId,
        complete_scan: bool,
        at_ns: u64,
        shared: Option<&mut crate::semantics_objects::journal::StagingLedger>,
    ) {
        let _ = at_ns;
        {
            let Some(edge) = self.edges.get_mut(&(caller, module)) else {
                return;
            };
            if edge.mapping != MappingState::Mapped && edge.mapping != MappingState::Uncertain {
                return;
            }
            if !complete_scan {
                edge.mapping = MappingState::Uncertain;
                edge.mapping_reason = Some(
                    "the module was absent from an incomplete scan; the mapping is neither confirmed nor refuted"
                        .into(),
                );
            } else {
                if edge.mapping == MappingState::Mapped {
                    edge.mapping_interruptions = edge.mapping_interruptions.saturating_add(1);
                }
                edge.mapping = MappingState::Ended;
                edge.mapping_reason =
                    Some("the module was absent from a complete rescan of the live caller".into());
            }
            // Absence ends "right now": ended or uncertain, the live
            // operations lose their proven edge and end unknown (C2).
            if let Some(state) = edge.semantics.as_mut() {
                state.invalidate();
            }
        }
        self.invalidate_physical_instances(caller, Some(module), complete_scan, shared);
        // The module unloaded only when no edge still maps it or could:
        // mapped and uncertain edges both block the verdict (an
        // incomplete scan just marked this edge uncertain, so it
        // always blocks here).
        let still_possible = self.edges.values().any(|edge| {
            edge.module == module
                && matches!(edge.mapping, MappingState::Mapped | MappingState::Uncertain)
        });
        if !still_possible && let Some(record) = self.modules.get_mut(&module) {
            record.unloaded_observed = true;
        }
        self.recompute_module(module);
    }
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;

    /// The maps-domain reader takes its `(dev, ino)` from the mapping
    /// probe, not from stat: the scripted probe stands in for a
    /// split-device host, and the link text still names the target.
    /// The probe opens `/proc/<pid>/exe` itself, never the readlink
    /// target.
    #[test]
    fn maps_exe_reader_takes_identity_from_the_probe() {
        let pid = std::process::id();
        let proc_exe = format!("/proc/{pid}/exe");
        let link = std::fs::read_link(&proc_exe).unwrap();
        let link_text = link.to_string_lossy().into_owned();
        let seen = std::cell::RefCell::new(Vec::new());
        let exe = read_exe_maps_identity_with(pid, |path| {
            seen.borrow_mut().push(path.to_string());
            (path == proc_exe).then_some((0x0bad_1abe, 0xc0ffee))
        })
        .expect("our own exe reads");
        assert_eq!((exe.dev, exe.ino), (0x0bad_1abe, 0xc0ffee));
        assert_eq!(exe.path.as_deref(), Some(link_text.as_str()));
        assert_eq!(
            seen.borrow().as_slice(),
            &[proc_exe],
            "the probe opens the /proc exe link itself, exactly once"
        );
    }

    /// The real maps-domain reader agrees with the mapping probe on
    /// our own process, on every filesystem.
    #[test]
    fn maps_exe_reader_agrees_with_the_probe_on_self() {
        let pid = std::process::id();
        let exe = read_exe_maps_identity(pid).expect("our own exe reads");
        let link = std::fs::read_link(format!("/proc/{pid}/exe")).unwrap();
        let link_text = link.to_string_lossy().into_owned();
        assert_eq!(exe.path.as_deref(), Some(link_text.as_str()));
        let probed = crate::discovery::unbound_exe::real_maps_identity(&link_text)
            .expect("our own exe maps");
        assert_eq!((exe.dev, exe.ino), probed);
    }

    /// A symlink's own metadata is never an exe identity: the
    /// constructor refuses it, so a magic link that refused the
    /// follow can never claim an observed image. A regular file
    /// still builds.
    #[test]
    fn exe_identity_refuses_symlink_metadata() {
        let dir = tempfile::tempdir().unwrap();
        let target = dir.path().join("tool");
        std::fs::write(&target, b"tool").unwrap();
        let link = dir.path().join("link");
        std::os::unix::fs::symlink(&target, &link).unwrap();
        let link_meta = std::fs::symlink_metadata(&link).unwrap();
        assert!(link_meta.file_type().is_symlink());
        assert_eq!(
            exe_identity_from_followed_metadata(&link_meta, None),
            None,
            "link metadata is never an identity"
        );
        let file_meta = std::fs::metadata(&target).unwrap();
        assert!(file_meta.is_file());
        let exe = exe_identity_from_followed_metadata(&file_meta, Some("/bin/tool".to_string()))
            .expect("a regular file builds an identity");
        assert_eq!(exe.path.as_deref(), Some("/bin/tool"));
    }

    /// Live contract: an unprivileged observer reads no exe identity
    /// for pid 1 (its exe readlink is denied) but reads its own with
    /// a path. The probe always runs as a non-root user — when the
    /// suite runs as root the child drops to `nobody` first — so
    /// this is never a self-skip.
    #[test]
    fn exe_identity_denied_for_pid_1_as_a_nonroot_observer() {
        const MARKER: &str = "P11SCOPE_B1_NONROOT_PROBE_DONE";
        const CHILD_ENV: &str = "P11SCOPE_B1_NONROOT_PROBE";
        const CHILD_TEST: &str = "exe_identity_denied_for_pid_1_as_a_nonroot_observer";
        if std::env::var_os(CHILD_ENV).is_some() {
            // SAFETY: reading the effective uid has no preconditions.
            if unsafe { libc::geteuid() } == 0 {
                let name = std::ffi::CString::new("nobody").unwrap();
                // SAFETY: a valid NUL-terminated name; the return is checked.
                let entry = unsafe { libc::getpwnam(name.as_ptr()) };
                assert!(!entry.is_null(), "the nobody user must exist");
                // SAFETY: the entry is valid; only its id fields are read.
                let (uid, gid) = unsafe { ((*entry).pw_uid, (*entry).pw_gid) };
                assert_ne!(uid, 0, "nobody is unprivileged");
                // SAFETY: dropping to an unprivileged user in a probe
                // child that exits immediately afterwards.
                assert_eq!(unsafe { libc::setgid(gid) }, 0, "setgid(nobody)");
                assert_eq!(unsafe { libc::setuid(uid) }, 0, "setuid(nobody)");
            }
            // SAFETY: reading the effective uid has no preconditions.
            assert_ne!(
                unsafe { libc::geteuid() },
                0,
                "the probe runs as a non-root user"
            );
            assert!(
                std::fs::read_link("/proc/1/exe").is_err(),
                "pid 1 exe readlink is denied for the probe user"
            );
            assert_eq!(
                read_exe_identity(1),
                None,
                "a denied exe link reads no identity"
            );
            let own = std::process::id();
            let exe = read_exe_identity(own).expect("our own exe reads");
            assert!(exe.path.is_some(), "our own exe carries its path: {exe:?}");
            println!("{MARKER}");
            std::process::exit(0);
        }
        let exe = std::env::current_exe().expect("test binary path");
        // libtest names omit the crate prefix that `module_path!` carries.
        let module = module_path!()
            .split_once("::")
            .map(|(_, rest)| rest)
            .unwrap_or(module_path!());
        let test = format!("{module}::{CHILD_TEST}");
        let out = std::process::Command::new(&exe)
            .env(CHILD_ENV, "1")
            .args(["--exact", &test, "--nocapture"])
            .output()
            .expect("spawn the non-root probe");
        let stdout = String::from_utf8_lossy(&out.stdout);
        let stderr = String::from_utf8_lossy(&out.stderr);
        assert!(
            out.status.success(),
            "the non-root probe passes: status={} stdout={stdout} stderr={stderr}",
            out.status
        );
        assert!(
            stdout.contains(MARKER),
            "the probe ran to completion (no vacuous filter miss): stdout={stdout} stderr={stderr}"
        );
    }

    /// B1 consumer contract: a scoped mint with no exe identity must not
    /// claim to observe exec. Production gates currently forbid `None` at
    /// the mint site; this pins the decision seam so a literal `true` can
    /// never publish `exec_observed` with no observation.
    #[test]
    fn scoped_mint_leaves_unreadable_exe_unobserved() {
        let denied = crate::inspect_system::MemberGeneration {
            start_time: Some(7),
            exe: None,
        };
        assert!(
            !scoped_mint_exec_observed(&denied),
            "no exe identity means no exec observation"
        );
        let seen = crate::inspect_system::MemberGeneration {
            start_time: Some(7),
            exe: Some(ExeIdentity {
                dev: 1,
                ino: 2,
                mtime_secs: 3,
                mtime_nanos: 0,
                path: Some("/bin/tool".into()),
            }),
        };
        assert!(
            scoped_mint_exec_observed(&seen),
            "a carried exe identity still observes exec"
        );
    }

    /// Deliver only decisions produced by the real registry, in an adversarial
    /// order or more than once. This utility manufactures no outcome/handle.
    pub(crate) fn deliver_pending_decisions(
        registry: &mut CallerRegistry,
        decisions: &[PendingCountDecision],
    ) {
        registry
            .pending_count_decisions
            .extend_from_slice(decisions);
    }
    use std::cell::RefCell;
    use std::collections::HashMap;
    use std::rc::Rc;

    #[derive(Debug, Clone)]
    struct ScriptedProcess {
        alive: bool,
        start_time: u64,
        exe: Option<ExeIdentity>,
        /// The scripted maps-domain reading of the same process (what
        /// `exe_maps_identity` returns). `spawn`/`exec` keep it equal
        /// to `exe`; `diverge_maps_exe` splits them for a btrfs-style
        /// host where stat and mapped devices differ.
        exe_maps: Option<ExeIdentity>,
        /// The scripted `/proc/<pid>/stat` ppid (field 4). Readability
        /// follows `readable`: one stat line carries both, as in production.
        ppid: u32,
        /// False simulates an unreadable `/proc` (a race or a permission
        /// wall): liveness answers but identity reads fail.
        readable: bool,
        /// Scripted `/proc/<pid>/cgroup` text for user-manager and unit
        /// classification.
        cgroup: Option<String>,
        /// Scripted `NSpid` values (outermost first) for container-init
        /// and pid-namespace-boundary classification.
        nspid: Vec<u32>,
        /// Scripted `PF_KTHREAD` flag: no exe link can exist.
        kthread: bool,
        leader_exit: crate::process::leader_exit::LeaderExitObservation,
    }

    #[derive(Debug, Clone, Default)]
    struct ScriptedState {
        processes: HashMap<u32, ScriptedProcess>,
        /// H6 slice 2: when set, `open` fails for every pid while pins
        /// already held keep proving their process — the fd-exhaustion /
        /// permission shape where numeric-PID reopen is unavailable but
        /// retained custody works.
        reopen_poisoned: bool,
        reopen_attempts: usize,
        leader_exit_queries: usize,
        /// Scripted `/proc` mount options: a hidden process table.
        hidepid: bool,
    }

    /// Scripted source: the pid/exit/reuse/exec sequence is programmed,
    /// never observed from the host. Pins capture the start-time they
    /// opened, exactly like the `ProcStat` fallback.
    #[derive(Debug, Clone, Default)]
    pub(crate) struct ScriptedSource {
        state: Rc<RefCell<ScriptedState>>,
    }

    impl ScriptedSource {
        fn set(&self, pid: u32, process: ScriptedProcess) {
            self.state.borrow_mut().processes.insert(pid, process);
        }

        pub(crate) fn spawn(&self, pid: u32, start_time: u64) {
            let exe = Some(ExeIdentity {
                dev: 1,
                ino: 100,
                mtime_secs: 10,
                mtime_nanos: 0,
                path: Some("/bin/driver".into()),
            });
            self.set(
                pid,
                ScriptedProcess {
                    alive: true,
                    start_time,
                    exe: exe.clone(),
                    exe_maps: exe,
                    ppid: 0,
                    readable: true,
                    cgroup: None,
                    nspid: vec![pid],
                    kthread: false,
                    leader_exit: crate::process::leader_exit::LeaderExitObservation::Unresolved,
                },
            );
        }

        pub(crate) fn spawn_matching_process(&self, pid: u32) {
            let exe = read_exe_identity(pid);
            self.set(
                pid,
                ScriptedProcess {
                    alive: true,
                    start_time: process_start_time(pid).unwrap(),
                    exe: exe.clone(),
                    exe_maps: exe,
                    ppid: 0,
                    readable: true,
                    cgroup: None,
                    nspid: vec![pid],
                    kthread: false,
                    leader_exit: crate::process::leader_exit::LeaderExitObservation::Unresolved,
                },
            );
        }

        pub(crate) fn set_ppid(&self, pid: u32, ppid: u32) {
            if let Some(process) = self.state.borrow_mut().processes.get_mut(&pid) {
                process.ppid = ppid;
            }
        }

        pub(crate) fn blind(&self, pid: u32) {
            if let Some(process) = self.state.borrow_mut().processes.get_mut(&pid) {
                process.readable = false;
            }
        }

        pub(crate) fn kill(&self, pid: u32) {
            if let Some(process) = self.state.borrow_mut().processes.get_mut(&pid) {
                process.alive = false;
            }
        }

        pub(crate) fn set_leader_exit_observation(
            &self,
            pid: u32,
            observation: crate::process::leader_exit::LeaderExitObservation,
        ) {
            if let Some(process) = self.state.borrow_mut().processes.get_mut(&pid) {
                process.leader_exit = observation;
            }
        }

        fn hide_exe(&self, pid: u32) {
            self.hide_ancestor_exe(pid);
        }

        pub(crate) fn hide_ancestor_exe(&self, pid: u32) {
            if let Some(process) = self.state.borrow_mut().processes.get_mut(&pid) {
                process.exe = None;
                process.exe_maps = None;
            }
        }

        pub(crate) fn set_cgroup(&self, pid: u32, cgroup: &str) {
            if let Some(process) = self.state.borrow_mut().processes.get_mut(&pid) {
                process.cgroup = Some(cgroup.to_string());
            }
        }

        pub(crate) fn set_container_init(&self, pid: u32, container_init: bool) {
            if let Some(process) = self.state.borrow_mut().processes.get_mut(&pid) {
                process.nspid = if container_init { vec![pid, 1] } else { vec![pid] };
            }
        }

        pub(crate) fn set_nspid(&self, pid: u32, nspid: Vec<u32>) {
            if let Some(process) = self.state.borrow_mut().processes.get_mut(&pid) {
                process.nspid = nspid;
            }
        }

        pub(crate) fn set_kthread(&self, pid: u32, kthread: bool) {
            if let Some(process) = self.state.borrow_mut().processes.get_mut(&pid) {
                process.kthread = kthread;
            }
        }

        pub(crate) fn set_proc_hidepid(&self, hidepid: bool) {
            self.state.borrow_mut().hidepid = hidepid;
        }

        pub(crate) fn exec(&self, pid: u32, ino: u64, path: &str) {
            if let Some(process) = self.state.borrow_mut().processes.get_mut(&pid) {
                let exe = Some(ExeIdentity {
                    dev: 1,
                    ino,
                    mtime_secs: 20,
                    mtime_nanos: 0,
                    path: Some(path.into()),
                });
                process.exe_maps = exe.clone();
                process.exe = exe;
            }
        }

        /// Split the scripted maps-domain reading from the stat-domain
        /// one: a btrfs-style host where the two devices differ.
        pub(crate) fn diverge_maps_exe(&self, pid: u32, dev: u64, ino: u64, path: &str) {
            if let Some(process) = self.state.borrow_mut().processes.get_mut(&pid) {
                process.exe_maps = Some(ExeIdentity {
                    dev,
                    ino,
                    mtime_secs: 20,
                    mtime_nanos: 0,
                    path: Some(path.into()),
                });
            }
        }

        /// Poison every future numeric-PID reopen; held pins are unaffected.
        pub(crate) fn poison_reopen(&self) {
            self.state.borrow_mut().reopen_poisoned = true;
        }

        /// Numeric-PID reopen attempts so far, poisoned or not.
        pub(crate) fn reopen_attempts(&self) -> usize {
            self.state.borrow().reopen_attempts
        }

        pub(crate) fn leader_exit_queries(&self) -> usize {
            self.state.borrow().leader_exit_queries
        }
    }

    impl ProcessSource for ScriptedSource {
        type Pin = (u32, u64);

        fn open(&mut self, pid: u32) -> Result<Self::Pin, String> {
            let mut state = self.state.borrow_mut();
            state.reopen_attempts = state.reopen_attempts.saturating_add(1);
            if state.reopen_poisoned {
                return Err(format!("poisoned numeric-PID reopen of {pid}"));
            }
            let process = state
                .processes
                .get(&pid)
                .filter(|process| process.alive)
                .ok_or_else(|| format!("no live scripted process {pid}"))?;
            Ok((pid, process.start_time))
        }

        fn still_the_same(&self, pin: &Self::Pin) -> bool {
            self.state
                .borrow()
                .processes
                .get(&pin.0)
                .is_some_and(|process| process.alive && process.start_time == pin.1)
        }

        fn start_time(&self, pid: u32) -> Option<u64> {
            self.state
                .borrow()
                .processes
                .get(&pid)
                .filter(|process| process.alive && process.readable)
                .map(|process| process.start_time)
        }

        fn parent_pid(&self, pid: u32) -> Option<u32> {
            self.state
                .borrow()
                .processes
                .get(&pid)
                .filter(|process| process.alive && process.readable)
                .map(|process| process.ppid)
        }

        fn exe_identity(&self, pid: u32) -> Option<ExeIdentity> {
            self.state
                .borrow()
                .processes
                .get(&pid)
                .filter(|process| process.alive && process.readable)
                .and_then(|process| process.exe.clone())
        }

        fn exe_maps_identity(&self, pid: u32) -> Option<ExeIdentity> {
            self.state
                .borrow()
                .processes
                .get(&pid)
                .filter(|process| process.alive && process.readable)
                .and_then(|process| process.exe_maps.clone())
        }

        fn cgroup_text(&self, pid: u32) -> Option<String> {
            self.state
                .borrow()
                .processes
                .get(&pid)
                .filter(|process| process.alive && process.readable)
                .and_then(|process| process.cgroup.clone())
        }

        fn status_nspid(&self, pid: u32) -> Option<Vec<u32>> {
            self.state
                .borrow()
                .processes
                .get(&pid)
                .filter(|process| process.alive && process.readable)
                .map(|process| process.nspid.clone())
        }

        fn is_kthread(&self, pid: u32) -> bool {
            self.state
                .borrow()
                .processes
                .get(&pid)
                .is_some_and(|process| process.alive && process.readable && process.kthread)
        }

        fn proc_hidepid(&self) -> bool {
            self.state.borrow().hidepid
        }

        fn gone(&self, pid: u32) -> bool {
            !self
                .state
                .borrow()
                .processes
                .get(&pid)
                .is_some_and(|process| process.alive)
        }

        fn leader_exit_observation(
            &self,
            pin: &Self::Pin,
            _: &mut crate::process::leader_exit::LeaderExitReadBudget,
        ) -> crate::process::leader_exit::LeaderExitObservation {
            use crate::process::leader_exit::LeaderExitObservation;
            let mut state = self.state.borrow_mut();
            state.leader_exit_queries += 1;
            let Some(process) = state.processes.get(&pin.0) else {
                return LeaderExitObservation::GroupExited;
            };
            if !process.alive || process.start_time != pin.1 {
                LeaderExitObservation::GroupExited
            } else if !process.readable {
                LeaderExitObservation::Unresolved
            } else {
                process.leader_exit
            }
        }
    }

    const AUTHORITY: ImageAuthority = ImageAuthority::ScanPinned;

    #[test]
    fn shared_process_custody_factory_charges_actual_arc_allocations() {
        let registry = CallerRegistry::new(RegistryLimits::default_limits());
        let reserve = registry.semantic_storage_reserver();
        let before = registry.semantic_resource_snapshot().charged_bytes;
        let pin = PidPin::open(std::process::id()).unwrap();
        let inline = 2 * std::mem::size_of::<SharedCallerPin<PidPin>>();
        let requested = CustodyCharge::requested_bytes::<PidPin>(inline).unwrap();
        let (held, allocations, allocated_bytes) = crate::test_alloc::count_allocs_during(|| {
            SharedCallerPin::new(pin, &OsProcessSource, &reserve).unwrap()
        });
        assert_eq!(allocations, 2, "the original pin and its charge peer");
        assert_eq!(
            allocated_bytes
                + 2 * crate::semantics_edge::resources::OWNED_ALLOCATION_PADDING
                + inline,
            requested
        );
        assert_eq!(
            registry.semantic_resource_snapshot().charged_bytes,
            before + requested
        );
        let original = OsProcessSource.shared_semantic_custody(&held.pin).unwrap();
        let (shared, sharing_allocations, sharing_bytes) =
            crate::test_alloc::count_allocs_during(|| held.share());
        assert_eq!((sharing_allocations, sharing_bytes), (0, 0));
        assert!(Arc::ptr_eq(&original, &shared.pin));
        eprintln!(
            "actual shared custody: PidPin={} wrapper={} peer={} heap={} charge={}",
            std::mem::size_of::<PidPin>(),
            std::mem::size_of::<SharedCallerPin<PidPin>>(),
            std::mem::size_of::<CustodyCharge>(),
            allocated_bytes,
            requested
        );
        drop((original, shared, held));
        assert_eq!(registry.semantic_resource_snapshot().charged_bytes, before);
    }

    #[test]
    fn shared_process_custody_refuses_before_any_arc_allocation() {
        let mut registry = CallerRegistry::new(RegistryLimits::default_limits());
        let reserve = registry.semantic_storage_reserver();
        let before = registry.semantic_resource_snapshot().charged_bytes;
        registry.reference_semantic_resource_limit(before);
        let pin = PidPin::open(std::process::id()).unwrap();
        // The dup succeeding proves the pidfd is open; the witness proves
        // the failed preparation closed it without depending on the fd
        // number staying free (a parallel test may reuse it at once, and
        // every pidfd to one pid shares one identity).
        let witness = crate::discovery::identity::test_fixture::PidfdClosureWitness::record(
            pin.pidfd().unwrap(),
        );
        let (result, allocations, bytes) = crate::test_alloc::count_allocs_during(|| {
            SharedCallerPin::new(pin, &OsProcessSource, &reserve)
        });
        assert!(result.is_err());
        assert_eq!((allocations, bytes), (0, 0));
        // The just-failed owned preparation closed this pidfd: the number
        // is free (EBADF) or names a different open file description.
        witness.assert_closed();
        assert_eq!(registry.semantic_resource_snapshot().charged_bytes, before);
    }

    #[test]
    fn shared_process_custody_strong_and_paired_weak_lifetimes() {
        let registry = CallerRegistry::new(RegistryLimits::default_limits());
        let before = registry.semantic_resource_snapshot().charged_bytes;
        let held = SharedCallerPin::new(
            PidPin::open(std::process::id()).unwrap(),
            &OsProcessSource,
            &registry.semantic_storage_reserver(),
        )
        .unwrap();
        let original = OsProcessSource.shared_semantic_custody(&held.pin).unwrap();
        let second = Arc::clone(&original);
        let weak = PidPin::downgrade_shared(&original).unwrap();
        let weak_second = PidPin::downgrade_shared(&original).unwrap();
        // The dup succeeding proves the pidfd is open; the witness proves
        // the last Arc drop closed it without depending on the fd number
        // staying free (a parallel test may reuse it at once, and every
        // pidfd to one pid shares one identity).
        let witness = crate::discovery::identity::test_fixture::PidfdClosureWitness::record(
            original.pidfd().unwrap(),
        );
        assert!(weak.matches_original(&original));
        let charged = registry.semantic_resource_snapshot().charged_bytes;
        drop(held);
        drop(original);
        assert!(weak.matches_original(&second));
        assert_eq!(registry.semantic_resource_snapshot().charged_bytes, charged);
        drop(second);
        // The paired Weak retains the memory charge, never the pidfd: the
        // number is free (EBADF) or names a different open file description.
        witness.assert_closed();
        assert_eq!(
            registry.semantic_resource_snapshot().charged_bytes,
            charged,
            "paired Weak retains the memory charge, never the pidfd"
        );
        let replacement = Arc::new(PidPin::open(std::process::id()).unwrap());
        assert!(!weak.matches_original(&replacement));
        assert!(
            PidPin::downgrade_shared(&replacement).is_none(),
            "an uncharged Arc is not displayed original custody"
        );
        drop(weak);
        assert_eq!(registry.semantic_resource_snapshot().charged_bytes, charged);
        drop(weak_second);
        assert_eq!(registry.semantic_resource_snapshot().charged_bytes, before);
    }

    #[test]
    fn shared_process_custody_weak_drop_first_and_independent_duplicate() {
        use std::os::fd::AsRawFd as _;
        let registry = CallerRegistry::new(RegistryLimits::default_limits());
        let before = registry.semantic_resource_snapshot().charged_bytes;
        let held = SharedCallerPin::new(
            PidPin::open(std::process::id()).unwrap(),
            &OsProcessSource,
            &registry.semantic_storage_reserver(),
        )
        .unwrap();
        let original = OsProcessSource.shared_semantic_custody(&held.pin).unwrap();
        let duplicate = Arc::new(original.try_clone().unwrap());
        assert_ne!(
            original.pidfd().unwrap().as_raw_fd(),
            duplicate.pidfd().unwrap().as_raw_fd()
        );
        assert!(
            PidPin::downgrade_shared(&duplicate).is_none(),
            "a duplicated FD never inherits original allocation accounting"
        );
        let weak = PidPin::downgrade_shared(&original).unwrap();
        drop(weak);
        assert!(registry.semantic_resource_snapshot().charged_bytes > before);
        drop((held, original));
        assert_eq!(registry.semantic_resource_snapshot().charged_bytes, before);
        assert!(duplicate.still_the_same());
    }

    fn adapter() -> (ScriptedSource, CallerAdapter<ScriptedSource>) {
        let source = ScriptedSource::default();
        let adapter = CallerAdapter::new(
            source.clone(),
            CallerRegistry::new(RegistryLimits::default_limits()).semantic_storage_reserver(),
        );
        (source, adapter)
    }

    #[test]
    fn launcher_chain_records_parent_start_time_against_pid_reuse() {
        let (source, mut adapter) = adapter();
        source.spawn(1, 1);
        source.exec(1, 1, "/sbin/init");
        source.spawn(50, 5);
        source.exec(50, 50, "/bin/grand");
        source.set_ppid(50, 1);
        source.spawn(100, 11);
        source.exec(100, 101, "/bin/parent-a");
        source.set_ppid(100, 50);
        source.spawn(200, 22);
        source.set_ppid(200, 100);
        let id = adapter.admit(200, AUTHORITY, 10).unwrap();
        let record = adapter.record(id).unwrap();
        let chain = &record.launched_by;
        assert_eq!(
            chain.len(),
            2,
            "caller -> parent -> grand; init is never shown"
        );
        assert_eq!((chain[0].pid, chain[0].start_time), (100, Some(11)));
        assert_eq!(chain[0].exe.as_deref(), Some("parent-a"));
        assert_eq!((chain[1].pid, chain[1].start_time), (50, Some(5)));
        assert!(record.launcher_gap.is_none());
        assert_eq!(record.launched_by_origin.label(), "chain");
        assert!(record.launched_by_unit.is_none());
        // The parent pid is reused by a new generation: a later admission
        // must record the live generation, never the stale one, while the
        // first caller's chain stays frozen evidence.
        source.kill(100);
        source.spawn(100, 77);
        source.exec(100, 102, "/bin/parent-b");
        source.set_ppid(100, 50);
        // The new caller starts after the live parent generation: a
        // parent younger than its child would prove pid reuse.
        source.spawn(201, 99);
        source.set_ppid(201, 100);
        let id2 = adapter.admit(201, AUTHORITY, 11).unwrap();
        let chain2 = &adapter.record(id2).unwrap().launched_by;
        assert_eq!((chain2[0].pid, chain2[0].start_time), (100, Some(77)));
        assert_eq!(chain2[0].exe.as_deref(), Some("parent-b"));
        let frozen = &adapter.record(id).unwrap().launched_by;
        assert_eq!((frozen[0].pid, frozen[0].start_time), (100, Some(11)));
        assert_eq!(frozen[0].exe.as_deref(), Some("parent-a"));
    }

    #[test]
    fn launcher_chain_reports_an_exited_parent_as_a_named_gap() {
        let (source, mut adapter) = adapter();
        source.spawn(100, 11);
        source.kill(100);
        source.spawn(200, 22);
        source.set_ppid(200, 100);
        let id = adapter.admit(200, AUTHORITY, 10).unwrap();
        let record = adapter.record(id).unwrap();
        assert!(record.launched_by.is_empty());
        assert_eq!(
            record.launcher_gap.as_ref().map(|gap| gap.reason.as_str()),
            Some("launcher exited before read")
        );
        assert_eq!(record.launched_by_origin.label(), "gap");
        // A live parent with an exited grandparent keeps the partial chain.
        source.spawn(101, 12);
        source.exec(101, 103, "/bin/parent");
        source.set_ppid(101, 102);
        source.spawn(102, 13);
        source.kill(102);
        source.spawn(201, 23);
        source.set_ppid(201, 101);
        let id2 = adapter.admit(201, AUTHORITY, 11).unwrap();
        let record2 = adapter.record(id2).unwrap();
        assert_eq!(record2.launched_by.len(), 1);
        assert_eq!(
            (
                record2.launched_by[0].pid,
                record2.launched_by[0].start_time
            ),
            (101, Some(12))
        );
        assert_eq!(
            record2.launcher_gap.as_ref().map(|gap| gap.reason.as_str()),
            Some("launcher exited before read")
        );
        assert_eq!(record2.launched_by_origin.label(), "chain");
    }

    #[test]
    fn launcher_chain_stops_at_init_and_truncates_after_four() {
        let (source, mut adapter) = adapter();
        source.spawn(1, 1);
        source.exec(1, 1, "/sbin/init");
        source.spawn(311, 31);
        source.exec(311, 311, "/bin/mid");
        source.set_ppid(311, 1);
        // The caller starts after its parent: a younger parent would
        // prove pid reuse instead of an init stop.
        source.spawn(310, 32);
        source.set_ppid(310, 311);
        let id = adapter.admit(310, AUTHORITY, 10).unwrap();
        let record = adapter.record(id).unwrap();
        assert_eq!(record.launched_by.len(), 1, "init is never recorded");
        assert_eq!(record.launched_by[0].pid, 311);
        assert!(record.launcher_gap.is_none());
        assert_eq!(record.launched_by_origin.label(), "chain");
        // Six ancestors: four are kept, the fifth is a named truncation.
        for pid in 301..=305 {
            source.spawn(pid, pid as u64);
            source.set_ppid(pid, pid - 1);
        }
        source.set_ppid(301, 1);
        // The deep caller starts after every ancestor generation.
        source.spawn(300, 390);
        source.set_ppid(300, 305);
        let deep = adapter.admit(300, AUTHORITY, 11).unwrap();
        let record = adapter.record(deep).unwrap();
        assert_eq!(
            record
                .launched_by
                .iter()
                .map(|ancestor| ancestor.pid)
                .collect::<Vec<_>>(),
            vec![305, 304, 303, 302]
        );
        assert_eq!(
            record.launcher_gap.as_ref().map(|gap| gap.reason.as_str()),
            Some("parent chain truncated after 4 ancestors")
        );
        assert_eq!(record.launched_by_origin.label(), "chain");
    }

    #[test]
    fn launcher_chain_four_real_plus_init_stops_cleanly() {
        let (source, mut adapter) = adapter();
        source.spawn(1, 1);
        source.exec(1, 1, "/sbin/init");
        // Four real ancestors with init directly above the fourth: the
        // fifth link is a boundary, not a truncated ancestor.
        for pid in 302..=305 {
            source.spawn(pid, pid as u64);
            source.set_ppid(pid, pid - 1);
        }
        source.set_ppid(302, 1);
        source.spawn(300, 390);
        source.set_ppid(300, 305);
        let id = adapter.admit(300, AUTHORITY, 10).unwrap();
        let record = adapter.record(id).unwrap();
        assert_eq!(
            record
                .launched_by
                .iter()
                .map(|ancestor| ancestor.pid)
                .collect::<Vec<_>>(),
            vec![305, 304, 303, 302]
        );
        assert!(
            record.launcher_gap.is_none(),
            "init above the fourth ancestor ends the walk, never truncates it: {:?}",
            record.launcher_gap
        );
        assert_eq!(record.launched_by_origin.label(), "chain");
    }

    #[test]
    fn launcher_chain_four_real_plus_user_manager_stops_cleanly() {
        let (source, mut adapter) = adapter();
        source.spawn(1500, 9);
        source.exec(1500, 150, "/usr/lib/systemd/systemd");
        source.set_cgroup(
            1500,
            "0::/user.slice/user-1000.slice/user@1000.service/init.scope\n",
        );
        for pid in 302..=305 {
            source.spawn(pid, pid as u64);
            source.set_ppid(pid, pid - 1);
        }
        source.set_ppid(302, 1500);
        source.spawn(300, 390);
        source.set_ppid(300, 305);
        let id = adapter.admit(300, AUTHORITY, 10).unwrap();
        let record = adapter.record(id).unwrap();
        assert_eq!(
            record
                .launched_by
                .iter()
                .map(|ancestor| ancestor.pid)
                .collect::<Vec<_>>(),
            vec![305, 304, 303, 302]
        );
        assert!(
            record.launcher_gap.is_none(),
            "the user manager above the fourth ancestor ends the walk: {:?}",
            record.launcher_gap
        );
        assert_eq!(record.launched_by_origin.label(), "chain");
    }

    #[test]
    fn launcher_chain_four_real_plus_container_init_stops_cleanly() {
        let (source, mut adapter) = adapter();
        source.spawn(5000, 40);
        source.exec(5000, 500, "/sbin/tini");
        source.set_container_init(5000, true);
        for pid in 302..=305 {
            source.spawn(pid, pid as u64);
            source.set_ppid(pid, pid - 1);
        }
        source.set_ppid(302, 5000);
        source.spawn(300, 390);
        source.set_ppid(300, 305);
        let id = adapter.admit(300, AUTHORITY, 10).unwrap();
        let record = adapter.record(id).unwrap();
        assert_eq!(
            record
                .launched_by
                .iter()
                .map(|ancestor| ancestor.pid)
                .collect::<Vec<_>>(),
            vec![305, 304, 303, 302]
        );
        assert!(
            record.launcher_gap.is_none(),
            "a container init above the fourth ancestor ends the walk: {:?}",
            record.launcher_gap
        );
        assert_eq!(record.launched_by_origin.label(), "chain");
    }

    #[test]
    fn launcher_chain_ppid_zero_is_an_init_parent() {
        let (source, mut adapter) = adapter();
        // No parent in this pid namespace: a boundary, never an empty chain.
        source.spawn(200, 22);
        source.set_cgroup(200, "0::/system.slice/backup.service\n");
        let id = adapter.admit(200, AUTHORITY, 10).unwrap();
        let record = adapter.record(id).unwrap();
        assert!(
            record.launched_by.is_empty(),
            "no parent in this namespace means no launcher links"
        );
        assert!(record.launcher_gap.is_none());
        assert_eq!(record.launched_by_origin.label(), "init_parent");
        assert_eq!(record.launched_by_unit.as_deref(), Some("backup.service"));
        // Without a unit, init_parent still claims neither launch nor reparent.
        source.spawn(201, 23);
        let id2 = adapter.admit(201, AUTHORITY, 11).unwrap();
        let record2 = adapter.record(id2).unwrap();
        assert!(record2.launched_by.is_empty());
        assert!(record2.launcher_gap.is_none());
        assert_eq!(record2.launched_by_origin.label(), "init_parent");
        assert!(record2.launched_by_unit.is_none());
    }

    #[test]
    fn launcher_chain_reports_an_init_only_parent_with_its_unit() {
        let (source, mut adapter) = adapter();
        source.spawn(1, 1);
        source.exec(1, 1, "/sbin/init");
        source.spawn(200, 22);
        source.set_ppid(200, 1);
        source.set_cgroup(200, "0::/system.slice/backup.service\n");
        let id = adapter.admit(200, AUTHORITY, 10).unwrap();
        let record = adapter.record(id).unwrap();
        assert!(
            record.launched_by.is_empty(),
            "init is never shown as the launcher"
        );
        assert!(
            record.launcher_gap.is_none(),
            "init_parent is not a read failure"
        );
        assert_eq!(record.launched_by_origin.label(), "init_parent");
        assert_eq!(record.launched_by_unit.as_deref(), Some("backup.service"));
        // Without a unit, init_parent shows nothing but still claims neither
        // "launched by a service manager" nor "reparented".
        source.spawn(201, 23);
        source.set_ppid(201, 1);
        let id2 = adapter.admit(201, AUTHORITY, 11).unwrap();
        let record2 = adapter.record(id2).unwrap();
        assert!(record2.launched_by.is_empty());
        assert!(record2.launcher_gap.is_none());
        assert_eq!(record2.launched_by_origin.label(), "init_parent");
        assert!(record2.launched_by_unit.is_none());
    }

    #[test]
    fn launcher_chain_suppresses_the_systemd_user_manager() {
        let (source, mut adapter) = adapter();
        source.spawn(1500, 9);
        source.exec(1500, 150, "/usr/lib/systemd/systemd");
        source.set_cgroup(
            1500,
            "0::/user.slice/user-1000.slice/user@1000.service/init.scope\n",
        );
        source.spawn(200, 22);
        source.set_ppid(200, 1500);
        source.set_cgroup(
            200,
            "0::/user.slice/user-1000.slice/user@1000.service/app.slice/app-gated.scope\n",
        );
        let id = adapter.admit(200, AUTHORITY, 10).unwrap();
        let record = adapter.record(id).unwrap();
        assert!(
            record.launched_by.is_empty(),
            "the user manager is never shown as the launcher"
        );
        assert!(record.launcher_gap.is_none());
        assert_eq!(record.launched_by_origin.label(), "init_parent");
        assert_eq!(record.launched_by_unit.as_deref(), Some("app-gated.scope"));
    }

    #[test]
    fn launcher_chain_suppresses_a_container_init() {
        let (source, mut adapter) = adapter();
        source.spawn(5000, 40);
        source.exec(5000, 500, "/sbin/tini");
        source.set_container_init(5000, true);
        source.spawn(200, 50);
        source.set_ppid(200, 5000);
        let id = adapter.admit(200, AUTHORITY, 10).unwrap();
        let record = adapter.record(id).unwrap();
        assert!(
            record.launched_by.is_empty(),
            "a container init is never shown as the launcher"
        );
        assert!(record.launcher_gap.is_none());
        assert_eq!(record.launched_by_origin.label(), "init_parent");
    }

    #[test]
    fn launcher_chain_pid_namespace_boundary_is_an_init_parent() {
        let (source, mut adapter) = adapter();
        // A host parent (one NSpid level) above a container child (two
        // levels): the parent is outside the child's pid namespace, so
        // it is a boundary like a container init, never the launcher.
        source.spawn(100, 11);
        source.exec(100, 101, "/usr/bin/shim");
        source.set_nspid(100, vec![100]);
        source.spawn(200, 22);
        source.set_ppid(200, 100);
        source.set_nspid(200, vec![200, 42]);
        source.set_cgroup(200, "0::/system.slice/docker-abc.scope\n");
        let id = adapter.admit(200, AUTHORITY, 10).unwrap();
        let record = adapter.record(id).unwrap();
        assert!(
            record.launched_by.is_empty(),
            "a pid-namespace boundary is never shown as the launcher"
        );
        assert!(record.launcher_gap.is_none());
        assert_eq!(record.launched_by_origin.label(), "init_parent");
        assert_eq!(
            record.launched_by_unit.as_deref(),
            Some("docker-abc.scope")
        );
    }

    #[test]
    fn launcher_chain_pid_namespace_boundary_above_real_links_stops_cleanly() {
        let (source, mut adapter) = adapter();
        source.spawn(100, 11);
        source.exec(100, 101, "/usr/bin/shim");
        source.set_nspid(100, vec![100]);
        source.spawn(150, 15);
        source.exec(150, 150, "/bin/mid");
        source.set_ppid(150, 100);
        source.set_nspid(150, vec![150, 7]);
        source.spawn(200, 22);
        source.set_ppid(200, 150);
        source.set_nspid(200, vec![200, 42]);
        let id = adapter.admit(200, AUTHORITY, 10).unwrap();
        let record = adapter.record(id).unwrap();
        assert_eq!(
            record
                .launched_by
                .iter()
                .map(|ancestor| ancestor.pid)
                .collect::<Vec<_>>(),
            vec![150]
        );
        assert!(record.launcher_gap.is_none());
        assert_eq!(record.launched_by_origin.label(), "chain");
    }

    #[test]
    fn launcher_chain_container_init_caller_is_an_init_parent() {
        let (source, mut adapter) = adapter();
        // The caller is itself a container init (innermost NSpid 1):
        // its observer-visible parent did not launch it. The parent
        // keeps the same depth so only the caller rule can fire.
        source.spawn(100, 11);
        source.exec(100, 101, "/usr/bin/shim");
        source.set_nspid(100, vec![100, 7]);
        source.spawn(200, 22);
        source.set_ppid(200, 100);
        source.set_nspid(200, vec![200, 1]);
        source.set_cgroup(200, "0::/system.slice/docker-abc.scope\n");
        let id = adapter.admit(200, AUTHORITY, 10).unwrap();
        let record = adapter.record(id).unwrap();
        assert!(
            record.launched_by.is_empty(),
            "a container init's observer-visible parent is not its launcher"
        );
        assert!(record.launcher_gap.is_none());
        assert_eq!(record.launched_by_origin.label(), "init_parent");
        assert_eq!(
            record.launched_by_unit.as_deref(),
            Some("docker-abc.scope")
        );
    }

    #[test]
    fn launcher_chain_kthread_parent_is_a_boundary() {
        let (source, mut adapter) = adapter();
        // kthreadd has no exe link at all: an immediate kthread parent
        // bounds the walk like init instead of scaring the operator
        // about a missing ptrace read access.
        source.spawn(2, 2);
        source.hide_ancestor_exe(2);
        source.set_kthread(2, true);
        source.spawn(200, 22);
        source.set_ppid(200, 2);
        source.set_cgroup(200, "0::/system.slice/request-key.service\n");
        let id = adapter.admit(200, AUTHORITY, 10).unwrap();
        let record = adapter.record(id).unwrap();
        assert!(
            record.launched_by.is_empty(),
            "a kernel thread is never shown as the launcher"
        );
        assert!(record.launcher_gap.is_none());
        assert_eq!(record.launched_by_origin.label(), "init_parent");
        assert_eq!(
            record.launched_by_unit.as_deref(),
            Some("request-key.service")
        );
        // Above real links the kthread just ends the walk.
        source.spawn(101, 12);
        source.exec(101, 103, "/bin/parent");
        source.set_ppid(101, 2);
        source.spawn(201, 23);
        source.set_ppid(201, 101);
        let id2 = adapter.admit(201, AUTHORITY, 11).unwrap();
        let record2 = adapter.record(id2).unwrap();
        assert_eq!(
            record2
                .launched_by
                .iter()
                .map(|ancestor| ancestor.pid)
                .collect::<Vec<_>>(),
            vec![101]
        );
        assert!(record2.launcher_gap.is_none());
        assert_eq!(record2.launched_by_origin.label(), "chain");
    }

    #[test]
    fn launcher_chain_dead_generation_exe_reports_exit_not_unreadable() {
        // The ancestor stat reads generation 11, then the generation
        // dies before the revalidation stat: the exe gap names the
        // exit instead of blaming ptrace read access.
        let stats = Rc::new(RefCell::new(HashMap::from([
            (200u32, vec![(Some(22), Some(100))]),
            (100u32, vec![(Some(11), Some(0)), (None, None)]),
        ])));
        let source = FlappingSource { stats, gone: true };
        let captured = capture_launcher_chain(&source, 200, Some(22), Some(100));
        assert_eq!(captured.ancestors.len(), 1);
        assert!(captured.ancestors[0].exe.is_none());
        assert_eq!(
            captured.ancestors[0].exe_gap,
            Some(LAUNCHER_GAP_EXITED),
            "a dead generation's exe gap is the exit, never unreadable"
        );
        assert!(captured.gap.is_none());
    }

    #[test]
    fn launcher_chain_hidepid_reports_hidden_not_exited() {
        let (source, mut adapter) = adapter();
        // Pid 100 never lived here, but the mount table hides
        // processes: the unreadable parent is hidden-alive until
        // proven otherwise, never presumed exited.
        source.set_proc_hidepid(true);
        source.spawn(200, 22);
        source.set_ppid(200, 100);
        let id = adapter.admit(200, AUTHORITY, 10).unwrap();
        let record = adapter.record(id).unwrap();
        assert!(record.launched_by.is_empty());
        assert_eq!(
            record.launcher_gap.as_ref().map(|gap| gap.reason.as_str()),
            Some("launcher hidden by /proc hidepid")
        );
        assert_eq!(record.launched_by_origin.label(), "gap");
        // Without hidepid evidence the same absence is an exit.
        source.set_proc_hidepid(false);
        source.spawn(201, 23);
        source.set_ppid(201, 100);
        let id2 = adapter.admit(201, AUTHORITY, 11).unwrap();
        let record2 = adapter.record(id2).unwrap();
        assert_eq!(
            record2.launcher_gap.as_ref().map(|gap| gap.reason.as_str()),
            Some("launcher exited before read")
        );
        assert_eq!(record2.launched_by_origin.label(), "gap");
    }

    #[test]
    fn launcher_hidepid_mount_option_needs_positive_procfs_evidence() {
        let row = |super_options: &str| {
            format!(
                "31 23 0:27 / /proc rw,nosuid,nodev,noexec,relatime - proc proc {super_options}\n"
            )
        };
        assert!(proc_mount_hidepid_on(&row("rw,hidepid=2")));
        assert!(proc_mount_hidepid_on(&row("rw,hidepid=invisible")));
        assert!(proc_mount_hidepid_on(&row("rw,hidepid=1")));
        assert!(!proc_mount_hidepid_on(&row("rw")));
        assert!(!proc_mount_hidepid_on(&row("rw,hidepid=0")));
        assert!(!proc_mount_hidepid_on(&row("rw,hidepid=off")));
        // No procfs at /proc, or a malformed row: no evidence, no claim.
        assert!(!proc_mount_hidepid_on(""));
        assert!(!proc_mount_hidepid_on(
            "31 23 0:27 / /proc rw,nosuid,nodev,noexec,relatime - tmpfs tmpfs rw,hidepid=2\n"
        ));
        assert!(!proc_mount_hidepid_on("not a mount table\n"));
    }

    #[test]
    fn launcher_chain_refuses_a_parent_younger_than_its_child() {
        let (source, mut adapter) = adapter();
        // The parent pid was recycled after the caller started: the live
        // generation cannot be the original parent.
        source.spawn(100, 77);
        source.exec(100, 102, "/bin/parent-b");
        source.spawn(200, 22);
        source.set_ppid(200, 100);
        let id = adapter.admit(200, AUTHORITY, 10).unwrap();
        let record = adapter.record(id).unwrap();
        assert!(record.launched_by.is_empty());
        assert_eq!(
            record.launcher_gap.as_ref().map(|gap| gap.reason.as_str()),
            Some("launcher exited before read")
        );
        assert_eq!(record.launched_by_origin.label(), "gap");
        // A recycled grandparent keeps the partial chain plus the gap.
        source.spawn(101, 12);
        source.exec(101, 103, "/bin/parent");
        source.set_ppid(101, 102);
        source.spawn(102, 90);
        source.exec(102, 104, "/bin/recycled-grand");
        source.spawn(201, 23);
        source.set_ppid(201, 101);
        let id2 = adapter.admit(201, AUTHORITY, 11).unwrap();
        let record2 = adapter.record(id2).unwrap();
        assert_eq!(record2.launched_by.len(), 1);
        assert_eq!(record2.launched_by[0].pid, 101);
        assert_eq!(
            record2.launcher_gap.as_ref().map(|gap| gap.reason.as_str()),
            Some("launcher exited before read")
        );
        assert_eq!(record2.launched_by_origin.label(), "chain");
    }

    #[test]
    fn launcher_chain_marks_an_unreadable_ancestor_exe_with_a_named_gap() {
        let (source, mut adapter) = adapter();
        source.spawn(100, 11);
        source.exec(100, 101, "/bin/parent");
        source.hide_ancestor_exe(100);
        source.set_ppid(100, 0);
        source.spawn(200, 22);
        source.set_ppid(200, 100);
        let id = adapter.admit(200, AUTHORITY, 10).unwrap();
        let record = adapter.record(id).unwrap();
        assert_eq!(record.launched_by.len(), 1);
        assert!(record.launched_by[0].exe.is_none());
        assert_eq!(
            record.launched_by[0].exe_gap,
            Some(LAUNCHER_GAP_EXE_UNREADABLE),
            "a stat-readable ancestor with no exe read carries the exe gap"
        );
        assert!(
            record.launcher_gap.is_none(),
            "the chain itself stopped cleanly"
        );
        assert_eq!(record.launched_by_origin.label(), "chain");
    }

    type StatQueues = Rc<RefCell<HashMap<u32, Vec<(Option<u64>, Option<u32>)>>>>;

    /// A source whose stat answers flap between reads: scripted
    /// generation races the static scripted source cannot express.
    #[derive(Clone)]
    struct FlappingSource {
        stats: StatQueues,
        gone: bool,
    }

    impl ProcessSource for FlappingSource {
        type Pin = (u32, u64);
        fn open(&mut self, pid: u32) -> Result<Self::Pin, String> {
            Ok((pid, 22))
        }
        fn still_the_same(&self, _: &Self::Pin) -> bool {
            true
        }
        fn start_time(&self, _: u32) -> Option<u64> {
            Some(22)
        }
        fn exe_identity(&self, pid: u32) -> Option<ExeIdentity> {
            if pid == 100 {
                return Some(ExeIdentity {
                    dev: 1,
                    ino: 999,
                    mtime_secs: 20,
                    mtime_nanos: 0,
                    path: Some("/bin/recycled".into()),
                });
            }
            None
        }
        fn stat_pair(&self, pid: u32) -> (Option<u64>, Option<u32>) {
            let mut stats = self.stats.borrow_mut();
            let queue = stats.get_mut(&pid).expect("scripted stat queue");
            assert!(!queue.is_empty(), "unexpected extra stat read of {pid}");
            queue.remove(0)
        }
        fn gone(&self, _: u32) -> bool {
            self.gone
        }
    }

    #[test]
    fn launcher_chain_drops_an_exe_pinned_to_a_recycled_generation() {
        // Caller 200 (start 22) parented to 100. The first ancestor stat
        // reads generation 11; the exe read then races a recycle, and the
        // revalidation stat reads generation 77: the exe must be dropped.
        let stats = Rc::new(RefCell::new(HashMap::from([
            (200u32, vec![(Some(22), Some(100))]),
            (100u32, vec![(Some(11), Some(0)), (Some(77), Some(0))]),
        ])));
        let source = FlappingSource { stats, gone: false };
        let captured = capture_launcher_chain(&source, 200, Some(22), Some(100));
        assert_eq!(captured.ancestors.len(), 1);
        assert_eq!(captured.ancestors[0].pid, 100);
        assert_eq!(captured.ancestors[0].start_time, Some(11));
        assert!(
            captured.ancestors[0].exe.is_none(),
            "the recycled exe is dropped"
        );
        assert_eq!(
            captured.ancestors[0].exe_gap,
            Some(LAUNCHER_GAP_EXITED),
            "a recycle between the stat and the readlink names the exit"
        );
        assert!(captured.gap.is_none());
    }

    #[test]
    fn launcher_collapse_folds_adjacent_identical_wrappers() {
        let chain = vec![
            LauncherAncestor {
                pid: 100,
                start_time: Some(11),
                exe: Some("sh".into()),
                label: None,
                exe_gap: None,
            },
            LauncherAncestor {
                pid: 90,
                start_time: Some(9),
                exe: Some("sh".into()),
                label: None,
                exe_gap: None,
            },
            LauncherAncestor {
                pid: 80,
                start_time: Some(8),
                exe: Some("cron".into()),
                label: None,
                exe_gap: None,
            },
        ];
        let collapsed = collapse_launcher_chain(&chain);
        assert_eq!(collapsed.len(), 2);
        assert_eq!(collapsed[0].0.pid, 100, "the nearest of the run is kept");
        assert_eq!(collapsed[0].1, 1, "one additional wrapper folded");
        assert_eq!(collapsed[1].0.pid, 80);
        assert_eq!(collapsed[1].1, 0);
        // Non-adjacent repeats do not fold; labels distinguish wrappers.
        let chain = vec![
            LauncherAncestor {
                pid: 100,
                start_time: Some(11),
                exe: Some("sh".into()),
                label: Some("a".into()),
                exe_gap: None,
            },
            LauncherAncestor {
                pid: 90,
                start_time: Some(9),
                exe: Some("cron".into()),
                label: None,
                exe_gap: None,
            },
            LauncherAncestor {
                pid: 80,
                start_time: Some(8),
                exe: Some("sh".into()),
                label: Some("a".into()),
                exe_gap: None,
            },
        ];
        let collapsed = collapse_launcher_chain(&chain);
        assert_eq!(collapsed.len(), 3);
        // Nameless links never fold: without ptrace read access every
        // ancestor is `pid N`, and folding them would hide generations.
        let chain = vec![
            LauncherAncestor {
                pid: 100,
                start_time: Some(11),
                exe: None,
                label: None,
                exe_gap: Some(LAUNCHER_GAP_EXE_UNREADABLE),
            },
            LauncherAncestor {
                pid: 90,
                start_time: Some(9),
                exe: None,
                label: None,
                exe_gap: Some(LAUNCHER_GAP_EXE_UNREADABLE),
            },
        ];
        let collapsed = collapse_launcher_chain(&chain);
        assert_eq!(collapsed.len(), 2);
        assert_eq!((collapsed[0].1, collapsed[1].1), (0, 0));
    }

    fn module_info(path: &str, ino: u64, admission: AdmissionState) -> ModuleInfo {
        ModuleInfo {
            path: path.into(),
            key: ModuleKey::physical(8, 1, ino, Some(format!("sha{ino:04}")), path),
            double_loaded: false,
            build_id: None,
            identity_source: Some("mountinfo".into()),
            admission,
            admission_class: Some("exact".into()),
            admission_endpoints: Some(3),
            admission_reasons: Vec::new(),
        }
    }

    #[test]
    fn edges_of_ranges_one_callers_edges_and_notes_carry_their_evidence() {
        let mut registry = CallerRegistry::new(RegistryLimits::default_limits());
        for caller in 0..3 {
            for module in 0..3 {
                let info = module_info(
                    &format!("/opt/m{module}.so"),
                    50 + module,
                    AdmissionState::Admitted,
                );
                if caller == 1 && module == 2 {
                    registry.note_maps_match(CallerId(caller), 10 + caller, info, 5);
                } else {
                    registry.note_mapping(CallerId(caller), 10 + caller, info, 5);
                }
            }
        }
        registry.publish();
        let edges: Vec<(u32, u32, &str)> = registry
            .edges_of(CallerId(1))
            .map(|edge| (edge.caller.0, edge.module.0, edge.mapping_evidence.label()))
            .collect();
        assert_eq!(
            edges,
            vec![
                (1, 0, "deep_scan"),
                (1, 1, "deep_scan"),
                (1, 2, "maps_match")
            ]
        );
        assert_eq!(registry.edges_of(CallerId(7)).count(), 0);
        // The latest note's evidence wins.
        let info = module_info("/opt/m2.so", 52, AdmissionState::Admitted);
        registry.note_mapping(CallerId(1), 11, info, 6);
        registry.publish();
        let module = registry
            .module_id_for(&ModuleKey::physical(
                8,
                1,
                52,
                Some("sha0052".into()),
                "/opt/m2.so",
            ))
            .unwrap();
        assert_eq!(
            registry.edge(CallerId(1), module).unwrap().mapping_evidence,
            MappingEvidence::DeepScan
        );
    }

    #[test]
    fn exit_then_pid_reuse_mints_distinct_retained_incarnations() {
        let (source, mut adapter) = adapter();
        source.spawn(4242, 1000);
        let first = adapter.admit(4242, AUTHORITY, 10).unwrap();
        assert_eq!(adapter.record(first).unwrap().incarnation, 0);
        // Exit: the incarnation retires with its evidence retained.
        source.kill(4242);
        let events = adapter.reconcile(&BTreeSet::new(), &mut |_| AUTHORITY, 20);
        assert_eq!(events.len(), 1);
        assert!(matches!(events[0], CallerEvent::Exited { id, .. } if id == first));
        let retired = adapter.record(first).unwrap();
        assert!(retired.retired);
        assert_eq!(retired.lifecycle, CallerLifecycle::Exited);
        assert_eq!(retired.last_seen_ns, 20);
        assert!(adapter.live_id(4242).is_none());
        // Reuse: the same numeric pid with a distinct start epoch is a
        // new incarnation — never merged into the old one.
        source.spawn(4242, 2000);
        let mut observed = BTreeSet::new();
        observed.insert(4242);
        let events = adapter.reconcile(&observed, &mut |_| AUTHORITY, 30);
        assert_eq!(events.len(), 1);
        let second = match &events[0] {
            CallerEvent::Admitted { id } => *id,
            other => panic!("expected admission, got {other:?}"),
        };
        assert_ne!(first, second);
        let (old, new) = (
            adapter.record(first).unwrap(),
            adapter.record(second).unwrap(),
        );
        assert_eq!(old.start_time, Some(1000));
        assert_eq!(new.start_time, Some(2000));
        assert_eq!(new.incarnation, 1);
        assert!(!new.retired);
        // The old incarnation is retained with disjoint evidence.
        assert!(old.retired && old.last_seen_ns == 20 && new.first_seen_ns == 30);
    }

    #[test]
    fn live_reuse_without_a_quiet_period_still_splits() {
        let (source, mut adapter) = adapter();
        source.spawn(99, 50);
        let first = adapter.admit(99, AUTHORITY, 10).unwrap();
        // The generation turns over between passes with no quiet period:
        // the pin dies and a new generation answers at once.
        source.kill(99);
        source.spawn(99, 60);
        let mut observed = BTreeSet::new();
        observed.insert(99);
        let events = adapter.reconcile(&observed, &mut |_| AUTHORITY, 20);
        assert_eq!(events.len(), 1);
        let second = match &events[0] {
            CallerEvent::Reused { old, new } => {
                assert_eq!(*old, first);
                *new
            }
            other => panic!("expected reuse, got {other:?}"),
        };
        assert_ne!(first, second);
        assert_eq!(
            adapter.record(first).unwrap().lifecycle,
            CallerLifecycle::Exited
        );
        assert_eq!(adapter.record(second).unwrap().start_time, Some(60));
    }

    #[test]
    fn unreadable_turnover_retires_unknown_never_exited() {
        let (source, mut adapter) = adapter();
        source.spawn(99, 50);
        let first = adapter.admit(99, AUTHORITY, 10).unwrap();
        // The generation turns over and the pid's current state goes
        // unreadable at once: the pin dies, liveness answers, but no
        // identity read can prove the turnover.
        source.kill(99);
        source.spawn(99, 60);
        source.blind(99);
        let mut observed = BTreeSet::new();
        observed.insert(99);
        let events = adapter.reconcile(&observed, &mut |_| AUTHORITY, 20);
        assert_eq!(events.len(), 1);
        assert!(matches!(events[0], CallerEvent::Reused { old, .. } if old == first));
        assert_eq!(
            adapter.record(first).unwrap().lifecycle,
            CallerLifecycle::Unknown
        );
    }

    #[test]
    fn scoped_retirement_pages_eventually_check_later_live_callers() {
        let (source, mut adapter) = adapter();
        for pid in 1..=257 {
            source.spawn(pid, 500);
            adapter.admit(pid, AUTHORITY, 50).unwrap();
        }
        let later = adapter.live_id(257).unwrap();
        source.exec(257, 200, "/bin/later-image");
        for _ in 0..3 {
            adapter.reconcile_scoped(100, &mut || true);
        }
        assert!(adapter.record(later).unwrap().retired);
        assert_eq!(adapter.live_id(257), None);
        assert_eq!(
            adapter.len(),
            257,
            "no successor inherited scope membership"
        );
    }

    #[test]
    fn exec_retires_the_old_image_and_admits_the_new() {
        let (source, mut adapter) = adapter();
        source.spawn(7, 500);
        let first = adapter.admit(7, AUTHORITY, 10).unwrap();
        // Same pid, same generation, new image: leader or nonleader exec.
        source.exec(7, 200, "/bin/other");
        let mut observed = BTreeSet::new();
        observed.insert(7);
        let events = adapter.reconcile(&observed, &mut |_| AUTHORITY, 20);
        assert_eq!(events.len(), 1);
        let second = match &events[0] {
            CallerEvent::ExecRetired { old, new } => {
                assert_eq!(*old, first);
                *new
            }
            other => panic!("expected exec retirement, got {other:?}"),
        };
        let (old, new) = (
            adapter.record(first).unwrap(),
            adapter.record(second).unwrap(),
        );
        assert_eq!(old.lifecycle, CallerLifecycle::ExecRetired);
        assert!(old.retired);
        assert_eq!(old.start_time, new.start_time);
        assert_eq!(new.exe.as_ref().unwrap().ino, 200);
        assert_eq!(new.incarnation, 1);
    }

    #[test]
    fn a_native_exec_transition_retires_a_live_caller_and_ignores_a_retired_one() {
        let (source, mut adapter) = adapter();
        source.spawn(7, 500);
        let first = adapter.admit(7, AUTHORITY, 10).unwrap();
        let events = adapter.exec_transition(first, &mut |_| AUTHORITY, 20);
        let [CallerEvent::ExecRetired { old, new }] = events.as_slice() else {
            panic!("{events:?}");
        };
        assert_eq!(*old, first);
        let retired = adapter.record(first).unwrap();
        assert_eq!(retired.lifecycle, CallerLifecycle::ExecRetired);
        assert!(retired.retired);
        let successor = adapter.record(*new).unwrap();
        assert_eq!(successor.first_seen_ns, 20);
        assert_eq!(adapter.live_id(7), Some(*new));
        // A second proof for the retired incarnation changes nothing.
        assert!(
            adapter
                .exec_transition(first, &mut |_| AUTHORITY, 30)
                .is_empty()
        );
        assert_eq!(adapter.live_id(7), Some(*new));
        assert_eq!(adapter.len(), 2);
    }

    #[test]
    fn zombies_are_gone_and_refuse_admission() {
        // A real zombie: spawned, exited, deliberately unreaped until
        // the end of the test. `std::process::Child` never reaps on its
        // own, so the pid stays a zombie while we probe it.
        let mut child = std::process::Command::new("true").spawn().unwrap();
        let pid = child.id();
        let deadline = std::time::Instant::now() + std::time::Duration::from_secs(10);
        while !process_is_zombie(pid) {
            assert!(
                std::time::Instant::now() < deadline,
                "spawned `true` never became observable as exited"
            );
            std::thread::sleep(std::time::Duration::from_millis(5));
        }
        // The generation is dead but `/proc` still parses — exactly the
        // case that used to re-admit every pass as "PID reuse".
        assert!(process_start_time(pid).is_ok());
        assert!(!generation_gone(pid));
        let source = OsProcessSource;
        assert!(source.gone(pid));
        let mut adapter = CallerAdapter::new(
            OsProcessSource,
            CallerRegistry::new(RegistryLimits::default_limits()).semantic_storage_reserver(),
        );
        let error = adapter.admit(pid, AUTHORITY, 10).unwrap_err();
        assert!(
            format!("{error:#}").contains("no live process"),
            "zombie admission must fail honestly, got {error:#}"
        );
        assert!(adapter.live_id(pid).is_none());
        child.wait().unwrap();
    }

    #[test]
    fn unobservable_pids_are_admit_failed_events_not_silence() {
        let (_source, mut adapter) = adapter();
        let mut observed = BTreeSet::new();
        observed.insert(1234);
        let events = adapter.reconcile(&observed, &mut |_| AUTHORITY, 10);
        assert_eq!(events.len(), 1);
        assert!(matches!(
            events[0],
            CallerEvent::AdmitFailed { pid: 1234, .. }
        ));
    }

    #[test]
    fn registry_limits_reject_empty_envelopes() {
        for limits in [
            (0, 1, 1, 1, 1, 1),
            (1, 0, 1, 1, 1, 1),
            (1, 1, 0, 1, 1, 1),
            (1, 1, 1, 0, 1, 1),
            (1, 1, 1, 1, 0, 1),
            (1, 1, 1, 1, 1, 0),
        ] {
            assert!(
                RegistryLimits::new(limits.0, limits.1, limits.2, limits.3, limits.4, limits.5)
                    .is_err(),
                "envelope {limits:?} must be refused"
            );
        }
        assert!(RegistryLimits::new(1, 1, 1, 1, 1, 1).is_ok());
    }

    fn registry() -> CallerRegistry {
        CallerRegistry::new(RegistryLimits::default_limits())
    }

    #[test]
    fn facts_stage_behind_publish_and_revision_advances() {
        let mut registry = registry();
        assert_eq!(
            (registry.facts_revision(), registry.published_revision()),
            (1, 0)
        );
        let key = ModuleKey::physical(8, 1, 11, Some("sha0011".into()), "/lib/a.so");
        registry.note_mapping(
            CallerId(0),
            50,
            module_info("/lib/a.so", 11, AdmissionState::Admitted),
            100,
        );
        // Staged: invisible until the batch publishes.
        assert!(registry.module_id_for(&key).is_none());
        assert_eq!(registry.publish(), 1);
        let id = registry.module_id_for(&key).unwrap();
        assert_eq!(id, ModuleId(0));
        assert_eq!(
            (registry.facts_revision(), registry.published_revision()),
            (2, 2)
        );
        let edge = registry.edge(CallerId(0), id).unwrap();
        assert_eq!(edge.mapping, MappingState::Mapped);
        assert_eq!(
            (edge.mapping_first_seen_ns, edge.mapping_last_seen_ns),
            (100, 100)
        );
    }

    #[test]
    fn entry_counts_saturate_with_an_explicit_flag_and_keep_recency() {
        let mut registry = registry();
        let info = module_info("/lib/a.so", 11, AdmissionState::Admitted);
        let key = info.key.clone();
        registry.note_mapping(CallerId(0), 50, info, 100);
        registry.observe_entries(CallerId(0), &key, MAX_EDGE_ENTRY_COUNT - 1, 110);
        registry.observe_entries(CallerId(0), &key, 5, 120);
        registry.publish();
        let id = registry.module_id_for(&key).unwrap();
        let edge = registry.edge(CallerId(0), id).unwrap();
        assert_eq!(edge.entry_count, MAX_EDGE_ENTRY_COUNT);
        assert!(edge.entry_saturated);
        // The count stopped; recency did not.
        assert_eq!(edge.entry_first_seen_ns, Some(110));
        assert_eq!(edge.entry_last_seen_ns, Some(120));
        assert_eq!(registry.entry_observation(edge), EntryObservation::Observed);
        assert!(registry.entry_active_within(edge, 130, 20));
        assert!(!registry.entry_active_within(edge, 200, 20));
    }

    #[test]
    fn mapping_evidence_never_moves_entry_recency() {
        let mut registry = registry();
        let info = module_info("/lib/a.so", 11, AdmissionState::Admitted);
        let key = info.key.clone();
        registry.note_mapping(CallerId(0), 50, info.clone(), 100);
        registry.publish();
        registry.note_mapping(CallerId(0), 50, info, 500);
        registry.publish();
        let id = registry.module_id_for(&key).unwrap();
        let edge = registry.edge(CallerId(0), id).unwrap();
        assert_eq!(edge.mapping_last_seen_ns, 500);
        assert_eq!(edge.entry_count, 0);
        assert_eq!(edge.entry_last_seen_ns, None);
        // Mapped but quiet: no feed, no entries — unknown, never active.
        assert_eq!(
            registry.entry_observation(edge),
            EntryObservation::UnknownUnavailable
        );
        assert!(!registry.entry_active_within(edge, 500, 1_000_000));
    }

    #[test]
    fn double_load_notes_latch_fail_closed_gap_once_and_unlatch() {
        // F7b: a double-loaded mapping note latches the edge (later
        // calls void), pushes the named gap exactly once per
        // false→true transition, and a later single-load note
        // unlatches so calls attribute again.
        fn sign_init() -> SemanticCall {
            SemanticCall {
                function: "C_SignInit".into(),
                rv: 0,
                session: 7,
                mechanism: 0x000d,
                capture: p11scope_ebpf_common::capture::MECHANISM_VALUE
                    | p11scope_ebpf_common::capture::OUTPUT_NON_NULL,
                ts_ns: 100,
                ..SemanticCall::default()
            }
        }
        let mut registry = registry();
        let mut info = module_info("/lib/nss.so", 12, AdmissionState::Admitted);
        let key = info.key.clone();
        info.double_loaded = true;
        registry.note_mapping(CallerId(0), 50, info, 100);
        registry.publish();
        let id = registry.module_id_for(&key).unwrap();
        assert!(registry.edge(CallerId(0), id).unwrap().double_loaded);
        registry.observe_semantic(CallerId(0), &key, sign_init());
        registry.publish();
        let edge = registry.edge(CallerId(0), id).unwrap();
        let state = edge.semantics.as_ref().expect("materialized feed");
        assert!(!state.has_claims());
        assert_eq!(
            state.label(),
            crate::semantics_edge::SEMANTIC_UNKNOWN_DOUBLE_LOAD
        );
        let gaps = registry.gaps();
        assert_eq!(gaps.len(), 1);
        assert_eq!(gaps[0].subject, "same-file double-load detected");
        assert_eq!(gaps[0].caller, Some(CallerId(0)));
        assert_eq!(gaps[0].module, Some(id));
        // A steady double-load re-note: still latched, no second gap.
        let mut info = module_info("/lib/nss.so", 12, AdmissionState::Admitted);
        info.double_loaded = true;
        registry.note_mapping(CallerId(0), 50, info, 200);
        registry.publish();
        assert!(registry.edge(CallerId(0), id).unwrap().double_loaded);
        assert_eq!(registry.gaps().len(), 1);
        // A resolved double-load unlatches; later calls attribute.
        let info = module_info("/lib/nss.so", 12, AdmissionState::Admitted);
        registry.note_mapping(CallerId(0), 50, info, 300);
        registry.publish();
        assert!(!registry.edge(CallerId(0), id).unwrap().double_loaded);
        assert_eq!(registry.gaps().len(), 1);
        registry.observe_semantic(CallerId(0), &key, sign_init());
        registry.publish();
        let state = registry
            .edge(CallerId(0), id)
            .unwrap()
            .semantics
            .as_ref()
            .unwrap();
        assert!(state.has_claims());
        assert_eq!(state.started(), 1);
    }

    #[test]
    fn refused_modules_report_unknown_not_admitted_with_zero_invented_calls() {
        let mut registry = registry();
        let info = ModuleInfo {
            admission: AdmissionState::Refused,
            admission_class: Some("closure-array".into()),
            admission_endpoints: None,
            admission_reasons: vec!["closure arrays are not attached".into()],
            ..module_info("/lib/nss.so", 12, AdmissionState::Refused)
        };
        let key = info.key.clone();
        registry.note_mapping(CallerId(0), 50, info, 100);
        registry.publish();
        let id = registry.module_id_for(&key).unwrap();
        let edge = registry.edge(CallerId(0), id).unwrap();
        assert_eq!(edge.entry_count, 0);
        assert_eq!(
            registry.entry_observation(edge),
            EntryObservation::UnknownNotAdmitted
        );
        let module = registry.module(id).unwrap();
        assert_eq!(module.admission, AdmissionState::Refused);
        assert_eq!(module.admission_reasons.len(), 1);
    }

    #[test]
    fn retirement_freezes_counts_and_ends_edges_with_evidence_retained() {
        let mut registry = registry();
        let info = module_info("/lib/a.so", 11, AdmissionState::Admitted);
        let key = info.key.clone();
        registry.note_mapping(CallerId(0), 50, info, 100);
        registry.observe_entries(CallerId(0), &key, 7, 110);
        registry.publish();
        registry.retire_caller(
            CallerId(0),
            "process exited (pid names no process)".into(),
            120,
        );
        registry.observe_entries(CallerId(0), &key, 100, 130);
        registry.publish();
        let id = registry.module_id_for(&key).unwrap();
        let edge = registry.edge(CallerId(0), id).unwrap();
        assert_eq!(edge.mapping, MappingState::Ended);
        // Frozen: the post-retirement batch changed nothing.
        assert_eq!(edge.entry_count, 7);
        assert_eq!(edge.entry_last_seen_ns, Some(110));
    }

    #[test]
    fn entries_without_mappings_are_dropped_with_a_gap() {
        let mut registry = registry();
        let key = ModuleKey::physical(8, 1, 77, Some("sha0077".into()), "/lib/ghost.so");
        registry.observe_entries(CallerId(0), &key, 3, 100);
        registry.publish();
        assert!(registry.module_id_for(&key).is_none());
        assert_eq!(registry.gaps().len(), 1);
        assert_eq!(registry.gaps()[0].subject, "entry without mapping evidence");
    }

    #[test]
    fn capacity_exhaustion_drops_with_a_gap_never_an_eviction() {
        let mut registry = CallerRegistry::new(RegistryLimits::new(8, 1, 8, 8, 64, 8).unwrap());
        registry.note_mapping(
            CallerId(0),
            50,
            module_info("/lib/a.so", 11, AdmissionState::Admitted),
            100,
        );
        registry.note_mapping(
            CallerId(0),
            50,
            module_info("/lib/b.so", 12, AdmissionState::Admitted),
            100,
        );
        registry.publish();
        assert_eq!(registry.modules().count(), 1);
        assert!(
            registry
                .gaps()
                .iter()
                .any(|gap| gap.subject == "module capacity exhausted")
        );
        // The retained module is untouched: no eviction rewrote history.
        let key = ModuleKey::physical(8, 1, 11, Some("sha0011".into()), "/lib/a.so");
        assert!(registry.module_id_for(&key).is_some());
    }

    #[test]
    fn tiny_gap_bound_keeps_first_n_and_counts_the_rest_exactly() {
        // The `--max-gaps 3` shape: retention is first-N-wins and the
        // suppression counter accounts every gap past the bound, so
        // retained + suppressed always equals total evidence.
        let mut registry =
            CallerRegistry::new(RegistryLimits::new(64, 64, 64, 3, 1 << 20, 64).unwrap());
        for n in 0..10 {
            registry.record_gap(RegistryGap {
                caller: None,
                module: None,
                pid: Some(100 + n),
                subject: format!("subject-{n}"),
                reason: format!("reason-{n}"),
                budget: None,
            });
        }
        registry.publish();
        assert_eq!(registry.gaps().len(), 3);
        assert_eq!(registry.gaps_suppressed(), 7);
        assert_eq!(
            registry
                .gaps()
                .iter()
                .map(|gap| gap.pid)
                .collect::<Vec<_>>(),
            vec![Some(100), Some(101), Some(102)]
        );
    }

    fn collapse_gap() -> RegistryGap {
        RegistryGap {
            caller: None,
            module: None,
            pid: None,
            subject: "overlay collapse".into(),
            reason: "two overlay instances map one inode".into(),
            budget: None,
        }
    }

    #[test]
    fn a_twenty_pass_run_publishes_one_collapse_gap_with_twenty_repeats() {
        let mut registry = registry();
        for _ in 0..20 {
            registry.record_gap(collapse_gap());
            registry.publish();
        }
        assert_eq!(registry.gaps().len(), 1, "{:?}", registry.gaps());
        assert_eq!(registry.gap_repeats(), &[20]);
        assert_eq!(registry.gaps_suppressed(), 0);
    }

    #[test]
    fn duplicates_within_one_pass_count_too() {
        let mut registry = registry();
        registry.record_gap(collapse_gap());
        registry.record_gap(collapse_gap());
        registry.publish();
        assert_eq!(registry.gaps().len(), 1);
        assert_eq!(registry.gap_repeats(), &[2]);
    }

    #[test]
    fn distinct_gaps_each_appear_and_count_their_own_repeats() {
        // Every published field is identity: a gap differing in any one
        // field is a different gap.
        let base = collapse_gap();
        let variants = [
            RegistryGap {
                caller: Some(CallerId(1)),
                ..base.clone()
            },
            RegistryGap {
                module: Some(ModuleId(1)),
                ..base.clone()
            },
            RegistryGap {
                pid: Some(7),
                ..base.clone()
            },
            RegistryGap {
                subject: "other".into(),
                ..base.clone()
            },
            RegistryGap {
                reason: "other".into(),
                ..base.clone()
            },
            RegistryGap {
                budget: Some(BudgetRefusal {
                    resource: "callers",
                    limit: 1,
                    requested: 2,
                }),
                ..base.clone()
            },
            RegistryGap {
                budget: Some(BudgetRefusal {
                    resource: "callers",
                    limit: 1,
                    requested: 3,
                }),
                ..base.clone()
            },
        ];
        let mut registry = registry();
        for pass in 0..3 {
            registry.record_gap(base.clone());
            for variant in &variants {
                registry.record_gap(variant.clone());
            }
            registry.publish();
            assert_eq!(registry.gaps().len(), 1 + variants.len(), "pass {pass}");
        }
        assert_eq!(registry.gap_repeats(), &[3; 8]);
        assert_eq!(registry.gaps()[0], base, "first occurrence keeps its place");
    }

    #[test]
    fn duplicates_never_consume_the_gap_budget() {
        let mut registry =
            CallerRegistry::new(RegistryLimits::new(64, 64, 64, 3, 1 << 20, 64).unwrap());
        for pass in 0..10 {
            for n in 0..3 {
                registry.record_gap(RegistryGap {
                    pid: Some(100 + n),
                    subject: format!("subject-{n}"),
                    ..collapse_gap()
                });
            }
            registry.publish();
            assert_eq!(registry.gaps().len(), 3, "pass {pass}");
            assert_eq!(registry.gaps_suppressed(), 0, "pass {pass}: duplicates");
        }
        assert_eq!(registry.gap_repeats(), &[10, 10, 10]);
        // A genuinely new gap past the full budget is the only thing
        // that suppresses.
        registry.record_gap(RegistryGap {
            subject: "late".into(),
            ..collapse_gap()
        });
        registry.publish();
        assert_eq!(registry.gaps().len(), 3);
        assert_eq!(registry.gaps_suppressed(), 1);
    }

    #[test]
    fn a_suppressed_gap_that_recurs_is_counted_once() {
        let mut registry =
            CallerRegistry::new(RegistryLimits::new(64, 64, 64, 2, 1 << 20, 64).unwrap());
        for n in 0..2 {
            registry.record_gap(RegistryGap {
                pid: Some(n),
                ..collapse_gap()
            });
        }
        registry.publish();
        for _ in 0..10 {
            registry.record_gap(collapse_gap());
            registry.publish();
        }
        assert_eq!(registry.gaps().len(), 2);
        assert_eq!(registry.gaps_suppressed(), 1, "one distinct suppressed gap");
        registry.record_gap(RegistryGap {
            subject: "second".into(),
            ..collapse_gap()
        });
        registry.record_gap(collapse_gap());
        registry.publish();
        assert_eq!(registry.gaps_suppressed(), 2);
    }

    #[test]
    fn suppressed_gap_memory_is_bounded_and_overflow_over_counts() {
        let mut registry =
            CallerRegistry::new(RegistryLimits::new(64, 64, 64, 1, 1 << 20, 64).unwrap());
        registry.record_gap(collapse_gap());
        let extra = 10;
        let distinct = MAX_SUPPRESSED_GAP_MEMORY + extra;
        for round in 0..2 {
            for n in 0..distinct {
                registry.record_gap(RegistryGap {
                    pid: Some(n as u32 + 1),
                    ..collapse_gap()
                });
            }
            registry.publish();
            let expect = distinct + if round == 1 { extra } else { 0 };
            assert_eq!(registry.gaps_suppressed(), expect as u64, "round {round}");
        }
        assert!(registry.suppressed_seen.len() <= MAX_SUPPRESSED_GAP_MEMORY);
    }

    #[test]
    fn a_late_distinct_gap_is_retained_after_many_duplicate_passes() {
        let mut registry =
            CallerRegistry::new(RegistryLimits::new(64, 64, 64, 4, 1 << 20, 64).unwrap());
        for _ in 0..100 {
            registry.record_gap(collapse_gap());
            registry.publish();
        }
        registry.record_gap(RegistryGap {
            subject: "late".into(),
            ..collapse_gap()
        });
        registry.publish();
        assert_eq!(registry.gaps().len(), 2);
        assert_eq!(registry.gaps()[1].subject, "late");
        assert_eq!(registry.gap_repeats(), &[100, 1]);
        assert_eq!(registry.gaps_suppressed(), 0);
    }

    #[test]
    fn per_drain_unrouted_gaps_aggregate_into_one_counted_row() {
        // Suite flood: 746 per-drain "semantic calls unrouted from
        // other callers" rows (one per distinct shed count) filled
        // the 1024 budget. Repeated-subject drains must aggregate
        // into one counted row with summed calls.
        let mut registry = registry();
        registry.record_aggregated_unrouted(
            "semantic calls unrouted from other callers".into(),
            5,
            vec![("NoFile".into(), 5)],
            2,
        );
        registry.publish();
        registry.record_aggregated_unrouted(
            "semantic calls unrouted from other callers".into(),
            7,
            vec![("NoFile".into(), 4), ("foreign".into(), 3)],
            2,
        );
        registry.publish();
        registry.record_aggregated_unrouted(
            "semantic calls unrouted from other callers".into(),
            3,
            vec![("foreign".into(), 3)],
            2,
        );
        registry.publish();
        assert_eq!(registry.gaps().len(), 1, "{:?}", registry.gaps());
        let gap = &registry.gaps()[0];
        assert_eq!(gap.subject, "semantic calls unrouted from other callers");
        assert!(
            gap.reason.starts_with("15 calls shed without a route ("),
            "summed total: {}",
            gap.reason
        );
        assert!(
            gap.reason.contains("NoFile=9"),
            "summed label: {}",
            gap.reason
        );
        assert!(
            gap.reason.contains("foreign=6"),
            "summed label: {}",
            gap.reason
        );
        // The oracle multiplies count by repeats: a summed row keeps
        // repeats 1, never drains.
        assert_eq!(registry.gap_repeats(), &[1]);
        assert_eq!(registry.gaps_suppressed(), 0);
    }

    #[test]
    fn aggregated_unrouted_gaps_separate_pre_binding_from_bound_drains() {
        // Pre-binding sheds ("with 0 bindings") forgive against the
        // pre-binding note; post-binding sheds stay loss. Merging
        // across the 0/N boundary would erase that distinction, so
        // each bindings count aggregates separately.
        let mut registry = registry();
        registry.record_aggregated_unrouted(
            "semantic calls unrouted".into(),
            4,
            vec![("NoFile".into(), 4)],
            0,
        );
        registry.publish();
        registry.record_aggregated_unrouted(
            "semantic calls unrouted".into(),
            6,
            vec![("NoFile".into(), 6)],
            3,
        );
        registry.publish();
        registry.record_aggregated_unrouted(
            "semantic calls unrouted".into(),
            2,
            vec![("NoFile".into(), 2)],
            0,
        );
        registry.publish();
        assert_eq!(registry.gaps().len(), 2, "{:?}", registry.gaps());
        let zero = registry
            .gaps()
            .iter()
            .find(|gap| gap.reason.ends_with("with 0 bindings"))
            .expect("the 0-bindings row survives");
        assert!(
            zero.reason.starts_with("6 calls shed without a route ("),
            "0-bindings sum: {}",
            zero.reason
        );
        let bound = registry
            .gaps()
            .iter()
            .find(|gap| gap.reason.ends_with("with 3 bindings"))
            .expect("the bound row survives");
        assert!(
            bound.reason.starts_with("6 calls shed without a route ("),
            "bound sum: {}",
            bound.reason
        );
    }

    #[test]
    fn terminal_gaps_survive_a_per_drain_flood() {
        // Terminal/stop-time gaps stage last and must never be
        // crowded out by a per-drain flood: in-run gaps keep the full
        // bound, and terminal gaps use headroom above it.
        let mut registry = registry();
        for n in 0..1100 {
            registry.record_gap(RegistryGap {
                caller: None,
                module: None,
                pid: None,
                subject: format!("flood-{n}"),
                reason: "x".into(),
                budget: None,
            });
        }
        registry.publish();
        assert_eq!(
            registry.gaps().len(),
            DEFAULT_MAX_GAPS,
            "per-drain keeps the full bound"
        );
        assert_eq!(
            registry.gaps_suppressed(),
            76,
            "the 76 flood rows past the bound suppress exactly"
        );
        registry.enter_terminal_phase();
        for n in 0..TERMINAL_GAP_RESERVE {
            registry.record_gap(RegistryGap {
                caller: None,
                module: None,
                pid: None,
                subject: format!("terminal-{n}"),
                reason: "y".into(),
                budget: None,
            });
        }
        registry.publish();
        assert_eq!(
            registry.gaps().len(),
            DEFAULT_MAX_GAPS + TERMINAL_GAP_RESERVE
        );
        assert_eq!(
            registry.gaps_suppressed(),
            76,
            "terminal disclosures add headroom rows, never suppressions"
        );
        assert!(
            registry
                .gaps()
                .iter()
                .any(|gap| gap.subject == "terminal-0"),
            "first terminal gap retained"
        );
        assert!(
            registry
                .gaps()
                .iter()
                .any(|gap| gap.subject == format!("terminal-{}", TERMINAL_GAP_RESERVE - 1)),
            "last terminal gap retained"
        );
    }

    #[test]
    fn terminal_gaps_survive_a_staged_flood_in_a_single_publish() {
        // The staged interaction the split-publish twin hides: a flood
        // staged before the phase flip applies in the same publication
        // as terminal gaps staged after it. The per-staged-gap flag
        // holds the flood to the bound, so the headroom stays whole
        // for the terminal disclosures.
        let mut registry = registry();
        for n in 0..1100 {
            registry.record_gap(RegistryGap {
                caller: None,
                module: None,
                pid: None,
                subject: format!("flood-{n}"),
                reason: "x".into(),
                budget: None,
            });
        }
        registry.enter_terminal_phase();
        for n in 0..TERMINAL_GAP_RESERVE {
            registry.record_gap(RegistryGap {
                caller: None,
                module: None,
                pid: None,
                subject: format!("terminal-{n}"),
                reason: "y".into(),
                budget: None,
            });
        }
        registry.publish();
        assert_eq!(
            registry.gaps().len(),
            DEFAULT_MAX_GAPS + TERMINAL_GAP_RESERVE,
            "the flood keeps the bound, the terminal gaps the headroom"
        );
        assert_eq!(
            registry.gaps_suppressed(),
            76,
            "only the flood rows past the bound suppress"
        );
        for n in 0..TERMINAL_GAP_RESERVE {
            assert!(
                registry
                    .gaps()
                    .iter()
                    .any(|gap| gap.subject == format!("terminal-{n}")),
                "terminal gap {n} survives the staged flood"
            );
        }
    }

    #[test]
    fn tiny_gap_limits_keep_every_slot_for_per_drain_gaps() {
        // No reservation when the bound itself fits inside it:
        // small-limit twins keep their exact per-drain behavior.
        let mut registry =
            CallerRegistry::new(RegistryLimits::new(64, 64, 64, 3, 1 << 20, 64).unwrap());
        for n in 0..3 {
            registry.record_gap(RegistryGap {
                pid: Some(100 + n),
                subject: format!("subject-{n}"),
                ..collapse_gap()
            });
        }
        registry.publish();
        assert_eq!(registry.gaps().len(), 3);
        assert_eq!(registry.gaps_suppressed(), 0);
    }

    #[test]
    fn complete_absence_unloads_and_reload_recovers_with_history() {
        let mut registry = registry();
        let info = module_info("/lib/a.so", 11, AdmissionState::Admitted);
        let key = info.key.clone();
        registry.note_mapping(CallerId(0), 50, info.clone(), 100);
        registry.publish();
        let id = registry.module_id_for(&key).unwrap();
        registry.note_module_absent(CallerId(0), id, true, 200);
        registry.publish();
        let edge = registry.edge(CallerId(0), id).unwrap();
        assert_eq!(edge.mapping, MappingState::Ended);
        assert_eq!(edge.mapping_interruptions, 1);
        let module = registry.module(id).unwrap();
        assert_eq!(module.lifecycle, ModuleLifecycle::Unloaded);
        assert!(module.unloaded_observed);
        // Reload: mapped again, with the unload retained.
        registry.note_mapping(CallerId(0), 50, info, 300);
        registry.publish();
        let edge = registry.edge(CallerId(0), id).unwrap();
        assert_eq!(edge.mapping, MappingState::Mapped);
        assert_eq!(edge.mapping_interruptions, 1);
        let module = registry.module(id).unwrap();
        assert_eq!(module.lifecycle, ModuleLifecycle::Mapped);
        assert!(module.unloaded_observed);
    }

    #[test]
    fn incomplete_absence_marks_edge_and_module_uncertain_never_ended() {
        let mut registry = registry();
        let info = module_info("/lib/a.so", 11, AdmissionState::Admitted);
        let key = info.key.clone();
        registry.note_mapping(CallerId(0), 50, info, 100);
        registry.publish();
        let id = registry.module_id_for(&key).unwrap();
        registry.note_member_unscanned(CallerId(0));
        registry.publish();
        let edge = registry.edge(CallerId(0), id).unwrap();
        assert_eq!(edge.mapping, MappingState::Uncertain);
        assert_eq!(edge.mapping_interruptions, 0);
        // No live mapping evidence remains: the module reads unknown,
        // never a confident mapped on missing evidence.
        assert_eq!(
            registry.module(id).unwrap().lifecycle,
            ModuleLifecycle::Unknown
        );
    }

    #[test]
    fn same_path_distinct_objects_are_distinct_modules() {
        let mut registry = registry();
        let first = module_info("/opt/prov.so", 11, AdmissionState::Admitted);
        let mut second = module_info("/opt/prov.so", 12, AdmissionState::Admitted);
        second.key = ModuleKey::physical(8, 1, 12, Some("sha0012".into()), "/opt/prov.so");
        registry.note_mapping(CallerId(0), 50, first, 100);
        registry.note_mapping(CallerId(1), 51, second, 100);
        registry.publish();
        assert_eq!(registry.modules().count(), 2);
        assert_eq!(registry.edges().count(), 2);
    }

    #[test]
    fn in_flight_entries_read_as_active_now() {
        let mut registry = registry();
        let info = module_info("/lib/a.so", 11, AdmissionState::Admitted);
        let key = info.key.clone();
        registry.note_mapping(CallerId(0), 50, info, 100);
        registry.set_in_flight(CallerId(0), &key, true);
        registry.publish();
        let id = registry.module_id_for(&key).unwrap();
        let edge = registry.edge(CallerId(0), id).unwrap();
        assert!(edge.entry_in_flight);
        assert!(registry.entry_active_within(edge, 1_000_000, 10));
    }

    /// Map `caller` onto each `(path, ino, admission)` module and publish;
    /// returns the module keys in order.
    fn mapped(
        registry: &mut CallerRegistry,
        caller: CallerId,
        modules: &[(&str, u64, AdmissionState)],
    ) -> Vec<ModuleKey> {
        let mut keys = Vec::new();
        for (path, ino, admission) in modules {
            let info = module_info(path, *ino, *admission);
            keys.push(info.key.clone());
            registry.note_mapping(caller, 50 + caller.0, info, 100);
        }
        registry.publish();
        keys
    }

    fn edge_of<'a>(
        registry: &'a CallerRegistry,
        caller: CallerId,
        key: &ModuleKey,
    ) -> &'a EdgeRecord {
        let id = registry.module_id_for(key).expect("module retained");
        registry.edge(caller, id).expect("edge retained")
    }

    #[test]
    fn scan_only_edges_read_unknown_scan_only_never_observed() {
        let mut registry = registry();
        let keys = mapped(
            &mut registry,
            CallerId(0),
            &[
                ("/lib/a.so", 11, AdmissionState::Admitted),
                ("/lib/b.so", 12, AdmissionState::Refused),
            ],
        );
        let a = edge_of(&registry, CallerId(0), &keys[0]);
        assert_eq!(
            registry.coverage(a),
            UseCoverage::Unknown(UnknownReason::ScanOnly)
        );
        assert_eq!(
            registry.entry_observation(a),
            EntryObservation::UnknownUnavailable
        );
        let b = edge_of(&registry, CallerId(0), &keys[1]);
        assert_eq!(
            registry.coverage(b),
            UseCoverage::Unknown(UnknownReason::NotAdmitted)
        );
        assert!(!registry.usage_feed(), "the summary derives from edges");
    }

    #[test]
    fn partial_attach_reads_no_use_since_for_the_attached_module_only() {
        // The preflight's partial-coverage defect: one global flag made
        // every admitted zero read observed. Per edge, only the module
        // whose endpoints are all attached reads "no use since".
        let mut registry = registry();
        let keys = mapped(
            &mut registry,
            CallerId(0),
            &[
                ("/lib/a.so", 11, AdmissionState::Admitted),
                ("/lib/b.so", 12, AdmissionState::Refused),
                ("/lib/c.so", 13, AdmissionState::Admitted),
            ],
        );
        registry.set_uncovered_reason(UnknownReason::NotAttached);
        registry.note_coverage(
            CallerId(0),
            &keys[0],
            CoverageNote::Watched { since_ns: 150 },
        );
        // A watch note for a refused module is a producer error: it never
        // makes the refused module's zero a fact.
        registry.note_coverage(
            CallerId(0),
            &keys[1],
            CoverageNote::Watched { since_ns: 150 },
        );
        registry.publish();
        let a = edge_of(&registry, CallerId(0), &keys[0]);
        assert_eq!(a.entry_count, 0);
        assert_eq!(
            registry.coverage(a),
            UseCoverage::WatchedNoUse {
                since_ns: 150,
                until_ns: None
            }
        );
        assert_eq!(registry.entry_observation(a), EntryObservation::Observed);
        let b = edge_of(&registry, CallerId(0), &keys[1]);
        assert_eq!(b.entry_count, 0);
        assert_eq!(
            registry.coverage(b),
            UseCoverage::Unknown(UnknownReason::NotAdmitted)
        );
        assert_eq!(
            registry.entry_observation(b),
            EntryObservation::UnknownNotAdmitted
        );
        let c = edge_of(&registry, CallerId(0), &keys[2]);
        assert_eq!(
            registry.coverage(c),
            UseCoverage::Unknown(UnknownReason::NotAttached)
        );
        assert_eq!(
            registry.entry_observation(c),
            EntryObservation::UnknownUnavailable
        );
        assert!(registry.usage_feed());
        assert!(
            registry
                .gaps()
                .iter()
                .any(|gap| gap.subject == "coverage for an unadmitted module"),
            "{:?}",
            registry.gaps()
        );
    }

    #[test]
    fn a_health_regression_demotes_every_watched_interval_and_keeps_positives() {
        let mut registry = registry();
        let keys = mapped(
            &mut registry,
            CallerId(0),
            &[
                ("/lib/a.so", 11, AdmissionState::Admitted),
                ("/lib/b.so", 12, AdmissionState::Admitted),
                ("/lib/c.so", 13, AdmissionState::Admitted),
                ("/lib/d.so", 14, AdmissionState::Admitted),
            ],
        );
        registry.note_coverage(
            CallerId(0),
            &keys[0],
            CoverageNote::Watched { since_ns: 120 },
        );
        registry.note_coverage(
            CallerId(0),
            &keys[1],
            CoverageNote::Watched { since_ns: 130 },
        );
        registry.note_witness(CallerId(0), &keys[2], 140);
        registry.note_coverage(
            CallerId(0),
            &keys[3],
            CoverageNote::Counted { since_ns: 110 },
        );
        registry.observe_entries(CallerId(0), &keys[3], 3, 145);
        registry.publish();
        assert_eq!(
            registry.coverage(edge_of(&registry, CallerId(0), &keys[1])),
            UseCoverage::WatchedNoUse {
                since_ns: 130,
                until_ns: None
            }
        );
        registry.note_health_regression("COOKIE_CTL.create_failures rose from 0 to 2", 200, 200);
        registry.publish();
        for key in &keys[..2] {
            let edge = edge_of(&registry, CallerId(0), key);
            assert_eq!(
                registry.coverage(edge),
                UseCoverage::Unknown(UnknownReason::Loss(
                    "COOKIE_CTL.create_failures rose from 0 to 2".into()
                ))
            );
            assert_eq!(
                registry.entry_observation(edge),
                EntryObservation::UnknownUnavailable
            );
        }
        assert_eq!(
            registry.coverage(edge_of(&registry, CallerId(0), &keys[2])),
            UseCoverage::Witnessed { first_ns: 140 }
        );
        assert_eq!(
            registry.coverage(edge_of(&registry, CallerId(0), &keys[3])),
            UseCoverage::Counted {
                since_ns: 110,
                lossy: false,
                pid_exit: false
            }
        );
        let regressions = registry
            .gaps()
            .iter()
            .filter(|gap| gap.subject == "usage coverage health regression")
            .count();
        assert_eq!(regressions, 1, "{:?}", registry.gaps());
        // The demoted interval stays demoted; a later watch is a new
        // interval, starting no earlier than the detecting read (200).
        registry.note_coverage(
            CallerId(0),
            &keys[0],
            CoverageNote::Watched { since_ns: 150 },
        );
        registry.note_coverage(
            CallerId(0),
            &keys[1],
            CoverageNote::Watched { since_ns: 500 },
        );
        registry.publish();
        assert_eq!(
            registry.coverage(edge_of(&registry, CallerId(0), &keys[0])),
            UseCoverage::WatchedNoUse {
                since_ns: 200,
                until_ns: None
            }
        );
        assert_eq!(
            registry.coverage(edge_of(&registry, CallerId(0), &keys[1])),
            UseCoverage::WatchedNoUse {
                since_ns: 500,
                until_ns: None
            }
        );
    }

    #[test]
    fn a_witnessed_edge_reads_used_count_unavailable_never_quiet_or_recent() {
        let mut registry = registry();
        let keys = mapped(
            &mut registry,
            CallerId(0),
            &[("/lib/a.so", 11, AdmissionState::Admitted)],
        );
        registry.note_coverage(
            CallerId(0),
            &keys[0],
            CoverageNote::Watched { since_ns: 100 },
        );
        registry.note_witness(CallerId(0), &keys[0], 140);
        // A later, larger first-seen never moves the first witness.
        registry.note_witness(CallerId(0), &keys[0], 900);
        registry.publish();
        let edge = edge_of(&registry, CallerId(0), &keys[0]);
        let coverage = registry.coverage(edge);
        assert_eq!(coverage, UseCoverage::Witnessed { first_ns: 140 });
        assert!(coverage.is_witnessed());
        assert_eq!(edge.entry_count, 0);
        assert_eq!(
            registry.entry_observation(edge),
            EntryObservation::UnknownCountUnavailable
        );
        // Recency comes only from counted entries.
        assert_eq!(edge.entry_last_seen_ns, None);
        assert!(!registry.entry_recent_within(edge, 150, 1_000_000));
    }

    #[test]
    fn retirement_loss_and_unload_never_erase_witnessed_use() {
        let mut registry = registry();
        let keys = mapped(
            &mut registry,
            CallerId(0),
            &[
                ("/lib/a.so", 11, AdmissionState::Admitted),
                ("/lib/b.so", 12, AdmissionState::Admitted),
            ],
        );
        registry.note_witness(CallerId(0), &keys[0], 140);
        registry.publish();
        let b = registry.module_id_for(&keys[1]).unwrap();
        registry.note_module_absent(CallerId(0), b, true, 150);
        registry.note_capture_loss("EVENTS ring lost 4 records".into());
        registry.note_health_regression("USAGE_EVIDENCE rose", 158, 158);
        registry.retire_caller(CallerId(0), "process exited".into(), 160);
        // A row read after exit is still use: a late witness for the
        // retired caller lands, and moves first-seen earlier only.
        registry.note_witness(CallerId(0), &keys[1], 155);
        registry.publish();
        let a = edge_of(&registry, CallerId(0), &keys[0]);
        assert_eq!(a.mapping, MappingState::Ended);
        assert_eq!(
            registry.coverage(a),
            UseCoverage::Witnessed { first_ns: 140 }
        );
        let b = edge_of(&registry, CallerId(0), &keys[1]);
        assert_eq!(
            registry.coverage(b),
            UseCoverage::Witnessed { first_ns: 155 }
        );
        // ...while a watch note for the retired caller lands nowhere.
        let keys2 = mapped(
            &mut registry,
            CallerId(1),
            &[("/lib/a.so", 11, AdmissionState::Admitted)],
        );
        registry.retire_caller(CallerId(1), "process exited".into(), 170);
        registry.note_coverage(
            CallerId(1),
            &keys2[0],
            CoverageNote::Watched { since_ns: 165 },
        );
        registry.publish();
        assert_eq!(
            registry.coverage(edge_of(&registry, CallerId(1), &keys2[0])),
            UseCoverage::Unknown(UnknownReason::RetiredBeforeCoverage)
        );
    }

    #[test]
    fn a_lossy_counting_feed_never_reads_a_zero_as_observed() {
        let mut registry = registry();
        let keys = mapped(
            &mut registry,
            CallerId(0),
            &[
                ("/lib/a.so", 11, AdmissionState::Admitted),
                ("/lib/b.so", 12, AdmissionState::Admitted),
            ],
        );
        for key in &keys {
            registry.note_coverage(CallerId(0), key, CoverageNote::Counted { since_ns: 110 });
        }
        registry.observe_entries(CallerId(0), &keys[1], 2, 120);
        registry.publish();
        let a = edge_of(&registry, CallerId(0), &keys[0]);
        assert_eq!(registry.entry_observation(a), EntryObservation::Observed);
        registry.note_capture_loss("EVENTS ring lost 1 record".into());
        registry.publish();
        let a = edge_of(&registry, CallerId(0), &keys[0]);
        assert_eq!(
            registry.coverage(a),
            UseCoverage::Counted {
                since_ns: 110,
                lossy: true,
                pid_exit: false
            }
        );
        assert_eq!(
            registry.entry_observation(a),
            EntryObservation::UnknownLossy
        );
        // A positive count still reads observed (a lower bound), flagged.
        let b = edge_of(&registry, CallerId(0), &keys[1]);
        assert_eq!(
            registry.coverage(b),
            UseCoverage::Counted {
                since_ns: 110,
                lossy: true,
                pid_exit: false
            }
        );
        assert_eq!(registry.entry_observation(b), EntryObservation::Observed);
    }

    /// R-C51-1 after a loss demotion: the loss reason stands, and the
    /// flag still keeps a watch from starting again.
    #[test]
    fn use_before_admission_keeps_a_loss_reason_and_blocks_restarts() {
        let mut registry = registry();
        let keys = mapped(
            &mut registry,
            CallerId(0),
            &[("/lib/a.so", 11, AdmissionState::Admitted)],
        );
        registry.note_coverage(
            CallerId(0),
            &keys[0],
            CoverageNote::Watched { since_ns: 120 },
        );
        registry.note_watch_demotion("lifecycle lost", "ring loss", 150);
        registry.publish();
        registry.note_use_before_admission(CallerId(0), Some(keys[0].clone()));
        registry.note_coverage(
            CallerId(0),
            &keys[0],
            CoverageNote::Watched { since_ns: 900 },
        );
        registry.publish();
        assert!(matches!(
            registry.coverage(edge_of(&registry, CallerId(0), &keys[0])),
            UseCoverage::Unknown(UnknownReason::Loss(_))
        ));
    }

    /// F2 (use first, then loss): the reason names what first voided the
    /// watch. A loss demotion acts on watch intervals reaching into its
    /// window; a `use_before_admission` edge holds none, so a later loss
    /// neither renames it nor counts it as a demoted watch. Either order
    /// reads unknown with no restart (the loss-first order above keeps
    /// `loss`).
    #[test]
    fn a_later_loss_keeps_use_before_admission() {
        let mut registry = registry();
        let keys = mapped(
            &mut registry,
            CallerId(0),
            &[("/lib/a.so", 11, AdmissionState::Admitted)],
        );
        registry.note_coverage(
            CallerId(0),
            &keys[0],
            CoverageNote::Watched { since_ns: 120 },
        );
        registry.publish();
        registry.note_use_before_admission(CallerId(0), Some(keys[0].clone()));
        registry.publish();
        registry.note_watch_demotion("lifecycle lost", "ring loss", 150);
        registry.note_health_regression("counter rose", 150, 160);
        registry.note_coverage(
            CallerId(0),
            &keys[0],
            CoverageNote::Watched { since_ns: 900 },
        );
        registry.publish();
        assert_eq!(
            registry.coverage(edge_of(&registry, CallerId(0), &keys[0])),
            UseCoverage::Unknown(UnknownReason::UseBeforeAdmission)
        );
        let demoted: Vec<&str> = registry
            .gaps()
            .iter()
            .filter(|gap| gap.subject == "lifecycle lost")
            .map(|gap| gap.reason.as_str())
            .collect();
        assert!(
            matches!(demoted.as_slice(), [reason] if reason.contains("0 watched no-use edges were demoted")),
            "{demoted:?}"
        );
    }

    /// R-C51-1: the downgrade replaces an ongoing or frozen watch, blocks
    /// every later watch note, and leaves positive history alone; a watch
    /// a loss already demoted keeps its loss reason.
    #[test]
    fn use_before_admission_is_a_sticky_downgrade_of_the_watch_only() {
        let mut registry = registry();
        let keys = mapped(
            &mut registry,
            CallerId(0),
            &[
                ("/lib/a.so", 11, AdmissionState::Admitted),
                ("/lib/b.so", 12, AdmissionState::Admitted),
                ("/lib/c.so", 13, AdmissionState::Admitted),
            ],
        );
        for key in &keys {
            registry.note_coverage(CallerId(0), key, CoverageNote::Watched { since_ns: 120 });
        }
        registry.note_witness(CallerId(0), &keys[2], 140);
        registry.publish();
        // a: an ongoing watch is replaced, and no later note restarts one.
        registry.note_use_before_admission(CallerId(0), Some(keys[0].clone()));
        registry.note_coverage(
            CallerId(0),
            &keys[0],
            CoverageNote::Watched { since_ns: 500 },
        );
        registry.publish();
        // b's watch is a frozen fact; the downgrade still replaces it.
        registry.note_watch_end("stopped", 400);
        registry.publish();
        registry.note_use_before_admission(CallerId(0), Some(keys[1].clone()));
        registry.note_use_before_admission(CallerId(0), Some(keys[2].clone()));
        registry.publish();
        let unknown = UseCoverage::Unknown(UnknownReason::UseBeforeAdmission);
        assert_eq!(
            registry.coverage(edge_of(&registry, CallerId(0), &keys[0])),
            unknown
        );
        assert_eq!(
            registry.coverage(edge_of(&registry, CallerId(0), &keys[1])),
            unknown
        );
        assert_eq!(
            registry.coverage(edge_of(&registry, CallerId(0), &keys[2])),
            UseCoverage::Witnessed { first_ns: 140 }
        );
    }

    #[test]
    fn an_explicit_unknown_note_never_overrides_positive_history() {
        let mut registry = registry();
        let keys = mapped(
            &mut registry,
            CallerId(0),
            &[
                ("/lib/a.so", 11, AdmissionState::Admitted),
                ("/lib/b.so", 12, AdmissionState::Admitted),
            ],
        );
        registry.note_witness(CallerId(0), &keys[0], 140);
        registry.note_coverage(
            CallerId(0),
            &keys[0],
            CoverageNote::Unknown(UnknownReason::AttachFailed),
        );
        registry.note_coverage(
            CallerId(0),
            &keys[1],
            CoverageNote::Watched { since_ns: 120 },
        );
        registry.note_coverage(
            CallerId(0),
            &keys[1],
            CoverageNote::Unknown(UnknownReason::CapacityLimited("caller_pairs")),
        );
        registry.publish();
        assert_eq!(
            registry.coverage(edge_of(&registry, CallerId(0), &keys[0])),
            UseCoverage::Witnessed { first_ns: 140 }
        );
        let b = registry.coverage(edge_of(&registry, CallerId(0), &keys[1]));
        assert_eq!(
            b,
            UseCoverage::Unknown(UnknownReason::CapacityLimited("caller_pairs"))
        );
        // Re-attached later: watched again from the new instant.
        registry.note_coverage(
            CallerId(0),
            &keys[1],
            CoverageNote::Watched { since_ns: 300 },
        );
        registry.publish();
        assert_eq!(
            registry.coverage(edge_of(&registry, CallerId(0), &keys[1])),
            UseCoverage::WatchedNoUse {
                since_ns: 300,
                until_ns: None
            }
        );
    }

    #[test]
    fn coverage_notes_never_invent_edges() {
        let mut registry = registry();
        let key = ModuleKey::physical(8, 1, 77, Some("sha0077".into()), "/lib/ghost.so");
        registry.note_witness(CallerId(0), &key, 100);
        registry.note_coverage(CallerId(0), &key, CoverageNote::Watched { since_ns: 100 });
        registry.publish();
        assert!(registry.module_id_for(&key).is_none());
        assert_eq!(registry.edge_count(), 0);
        assert_eq!(
            registry
                .gaps()
                .iter()
                .filter(|gap| gap.subject == "usage coverage without mapping evidence")
                .count(),
            1,
            "one gap for the (caller, module) pair, however many notes",
        );
    }

    #[test]
    fn a_later_admission_replaces_a_first_pass_refusal_with_history() {
        // I2: the attach set may admit a module a first pass refused. The
        // registry follows its verdict (rising only), keeps the change as
        // history plus a gap, and never shows an instrumented module as
        // refused.
        let mut registry = registry();
        let mut refused = module_info("/lib/nss.so", 12, AdmissionState::Refused);
        refused.admission_endpoints = None;
        refused.admission_reasons = vec!["needs 544 more endpoints".into()];
        let key = refused.key.clone();
        registry.note_mapping(CallerId(0), 50, refused.clone(), 100);
        registry.publish();
        let id = registry.module_id_for(&key).unwrap();
        assert_eq!(registry.endpoints_total(), 0);
        let mut admitted = module_info("/lib/nss.so", 12, AdmissionState::Admitted);
        admitted.admission_endpoints = Some(544);
        registry.note_mapping(CallerId(0), 50, admitted, 200);
        registry.publish();
        let module = registry.module(id).unwrap();
        assert_eq!(module.admission, AdmissionState::Admitted);
        assert_eq!(module.admission_endpoints, Some(544));
        assert!(module.admission_reasons.is_empty());
        assert_eq!(
            module.admission_history,
            vec![AdmissionChange {
                from: AdmissionState::Refused,
                to: AdmissionState::Admitted,
                at_ns: 200,
            }]
        );
        assert_eq!(registry.endpoints_total(), 544);
        let changes: Vec<&RegistryGap> = registry
            .gaps()
            .iter()
            .filter(|gap| gap.subject == "module admission changed")
            .collect();
        assert_eq!(changes.len(), 1, "{:?}", registry.gaps());
        assert_eq!(changes[0].module, Some(id));
        assert!(
            changes[0].reason.contains("from refused to admitted"),
            "{}",
            changes[0].reason
        );
        // Never demoted: a later refusal leaves the admitted verdict.
        registry.note_mapping(CallerId(0), 50, refused, 300);
        registry.publish();
        let module = registry.module(id).unwrap();
        assert_eq!(module.admission, AdmissionState::Admitted);
        assert_eq!(module.admission_history.len(), 1);
        assert_eq!(registry.endpoints_total(), 544);
        // Unresolved rises to a verdict too.
        let mut unresolved = module_info("/lib/u.so", 13, AdmissionState::Unresolved);
        unresolved.admission_endpoints = None;
        let ukey = unresolved.key.clone();
        registry.note_mapping(CallerId(0), 50, unresolved, 100);
        registry.publish();
        let mut refused_u = module_info("/lib/u.so", 13, AdmissionState::Refused);
        refused_u.admission_endpoints = None;
        registry.note_mapping(CallerId(0), 50, refused_u, 400);
        registry.publish();
        let module = registry
            .module(registry.module_id_for(&ukey).unwrap())
            .unwrap();
        assert_eq!(module.admission, AdmissionState::Refused);
        assert_eq!(module.admission_history[0].from, AdmissionState::Unresolved);
    }

    #[test]
    fn the_semantic_census_counts_a_latched_edge_with_claims_as_unknown() {
        // DR-09: the census and the label share one predicate. An edge
        // that held claims and then latched on a same-file double-load
        // reads `unknown (same-file double-load)`, so it counts as an
        // unknown edge too.
        let mut registry = registry();
        let info = module_info("/lib/nss.so", 12, AdmissionState::Admitted);
        let key = info.key.clone();
        registry.note_mapping(CallerId(0), 50, info, 100);
        registry.observe_semantic(
            CallerId(0),
            &key,
            SemanticCall {
                function: "C_SignInit".into(),
                rv: 0,
                session: 7,
                mechanism: 0x000d,
                capture: p11scope_ebpf_common::capture::MECHANISM_VALUE
                    | p11scope_ebpf_common::capture::OUTPUT_NON_NULL,
                ts_ns: 110,
                ..SemanticCall::default()
            },
        );
        registry.publish();
        assert_eq!(registry.semantic_unknown_edges(), 0);
        let mut latched = module_info("/lib/nss.so", 12, AdmissionState::Admitted);
        latched.double_loaded = true;
        registry.note_mapping(CallerId(0), 50, latched, 200);
        registry.publish();
        let id = registry.module_id_for(&key).unwrap();
        let state = registry
            .edge(CallerId(0), id)
            .unwrap()
            .semantics
            .as_ref()
            .unwrap();
        assert!(state.has_claims(), "retained claims stand as history");
        assert_eq!(
            state.label(),
            crate::semantics_edge::SEMANTIC_UNKNOWN_DOUBLE_LOAD
        );
        assert_eq!(registry.semantic_unknown_edges(), 1);
    }

    #[test]
    fn a_watch_never_starts_before_the_last_health_regression() {
        // I2 (review): a regression is timestamped. A watch noted after
        // it — in a later batch or later in the same batch — covers only
        // the clean interval from the regression on; a watch staged
        // before it in the same batch is demoted with the others.
        let mut registry = registry();
        let keys = mapped(
            &mut registry,
            CallerId(0),
            &[
                ("/lib/a.so", 11, AdmissionState::Admitted),
                ("/lib/b.so", 12, AdmissionState::Admitted),
                ("/lib/c.so", 13, AdmissionState::Admitted),
            ],
        );
        registry.note_health_regression("CALLER_EVIDENCE rose", 200, 200);
        registry.publish();
        // A later batch, a watch whose start predates the regression.
        registry.note_coverage(
            CallerId(0),
            &keys[0],
            CoverageNote::Watched { since_ns: 150 },
        );
        registry.publish();
        assert_eq!(
            registry.coverage(edge_of(&registry, CallerId(0), &keys[0])),
            UseCoverage::WatchedNoUse {
                since_ns: 200,
                until_ns: None
            }
        );
        // One batch: a watch, the regression, then another watch.
        registry.note_coverage(
            CallerId(0),
            &keys[1],
            CoverageNote::Watched { since_ns: 250 },
        );
        registry.note_health_regression("COOKIE_CTL.unavailable rose", 300, 300);
        registry.note_coverage(
            CallerId(0),
            &keys[2],
            CoverageNote::Watched { since_ns: 260 },
        );
        registry.publish();
        assert!(matches!(
            registry.coverage(edge_of(&registry, CallerId(0), &keys[1])),
            UseCoverage::Unknown(UnknownReason::Loss(_))
        ));
        assert_eq!(
            registry.coverage(edge_of(&registry, CallerId(0), &keys[2])),
            UseCoverage::WatchedNoUse {
                since_ns: 300,
                until_ns: None
            }
        );
        // The earlier watch was demoted by the second regression too.
        assert!(matches!(
            registry.coverage(edge_of(&registry, CallerId(0), &keys[0])),
            UseCoverage::Unknown(UnknownReason::Loss(_))
        ));
    }

    #[test]
    fn an_ignored_lower_verdict_is_disclosed_in_bounded_reasons() {
        let mut registry = registry();
        let key = mapped(
            &mut registry,
            CallerId(0),
            &[("/lib/a.so", 11, AdmissionState::Admitted)],
        )
        .remove(0);
        let id = registry.module_id_for(&key).unwrap();
        for pass in 0..(MAX_ADMISSION_REASONS + 4) {
            let mut lower = module_info("/lib/a.so", 11, AdmissionState::Refused);
            lower.admission_reasons =
                vec![format!("refusal {}", pass % (MAX_ADMISSION_REASONS + 2))];
            registry.note_mapping(CallerId(0), 50, lower, 200);
            registry.publish();
        }
        let module = registry.module(id).unwrap();
        assert_eq!(module.admission, AdmissionState::Admitted);
        assert!(module.admission_history.is_empty());
        assert_eq!(module.admission_reasons.len(), MAX_ADMISSION_REASONS);
        assert!(
            module.admission_reasons[0].contains("refused (refusal 0)")
                && module.admission_reasons[0].contains("not applied"),
            "{:?}",
            module.admission_reasons
        );
        let distinct: BTreeSet<&String> = module.admission_reasons.iter().collect();
        assert_eq!(distinct.len(), module.admission_reasons.len(), "no repeats");
    }

    #[test]
    fn a_counting_note_for_an_unadmitted_module_is_refused_with_one_gap() {
        let mut registry = registry();
        let keys = mapped(
            &mut registry,
            CallerId(0),
            &[("/lib/r.so", 12, AdmissionState::Refused)],
        );
        for _ in 0..3 {
            registry.note_coverage(
                CallerId(0),
                &keys[0],
                CoverageNote::Counted { since_ns: 110 },
            );
            registry.note_coverage(
                CallerId(0),
                &keys[0],
                CoverageNote::Watched { since_ns: 110 },
            );
            registry.publish();
        }
        assert_eq!(
            registry.coverage(edge_of(&registry, CallerId(0), &keys[0])),
            UseCoverage::Unknown(UnknownReason::NotAdmitted)
        );
        let gaps = registry
            .gaps()
            .iter()
            .filter(|gap| gap.subject == "coverage for an unadmitted module")
            .count();
        assert_eq!(gaps, 1, "{:?}", registry.gaps());
        // The module is in the registry: its gap names it by id, and the
        // reason carries no key suffix.
        assert!(
            registry
                .gaps()
                .iter()
                .filter(|gap| gap.subject == "coverage for an unadmitted module")
                .all(|gap| gap.module.is_some() && !gap.reason.contains("[module key")),
            "{:?}",
            registry.gaps()
        );
    }

    #[test]
    fn coverage_gaps_are_remembered_once_per_caller_and_module() {
        let mut registry = registry();
        let ghost = ModuleKey::physical(8, 1, 77, Some("sha0077".into()), "/lib/ghost.so");
        let other = ModuleKey::physical(8, 1, 78, Some("sha0078".into()), "/lib/other.so");
        for _ in 0..5 {
            registry.note_witness(CallerId(0), &ghost, 100);
            registry.note_coverage(CallerId(0), &ghost, CoverageNote::Watched { since_ns: 100 });
            registry.note_witness(CallerId(1), &ghost, 100);
            registry.note_witness(CallerId(0), &other, 100);
            registry.publish();
        }
        let gaps = registry
            .gaps()
            .iter()
            .filter(|gap| gap.subject == "usage coverage without mapping evidence")
            .count();
        assert_eq!(gaps, 3, "one per (caller, module): {:?}", registry.gaps());
        assert_eq!(registry.gap_repeats(), &[1, 1, 1]);
    }

    #[test]
    fn a_witness_before_a_complete_absence_unload_survives_it() {
        let mut registry = registry();
        let keys = mapped(
            &mut registry,
            CallerId(0),
            &[("/lib/a.so", 11, AdmissionState::Admitted)],
        );
        registry.note_witness(CallerId(0), &keys[0], 140);
        registry.publish();
        let id = registry.module_id_for(&keys[0]).unwrap();
        registry.note_module_absent(CallerId(0), id, true, 150);
        registry.publish();
        assert_eq!(
            registry.module(id).unwrap().lifecycle,
            ModuleLifecycle::Unloaded
        );
        let edge = edge_of(&registry, CallerId(0), &keys[0]);
        assert_eq!(edge.mapping, MappingState::Ended);
        assert_eq!(
            registry.coverage(edge),
            UseCoverage::Witnessed { first_ns: 140 }
        );
    }

    #[test]
    fn ending_watches_freezes_intervals_and_starts_no_new_watch() {
        // C3 closure 1: stopping the producer ends every watch at the last
        // proven-clean instant; the interval stays a frozen fact.
        let mut registry = registry();
        let keys = mapped(
            &mut registry,
            CallerId(0),
            &[
                ("/lib/a.so", 11, AdmissionState::Admitted),
                ("/lib/b.so", 12, AdmissionState::Admitted),
                ("/lib/c.so", 13, AdmissionState::Admitted),
            ],
        );
        registry.note_coverage(
            CallerId(0),
            &keys[0],
            CoverageNote::Watched { since_ns: 100 },
        );
        // A watch no clean instant proved after its start.
        registry.note_coverage(
            CallerId(0),
            &keys[1],
            CoverageNote::Watched { since_ns: 400 },
        );
        registry.note_watch_end("stopped before a clean read", 300);
        registry.publish();
        assert_eq!(
            registry.coverage(edge_of(&registry, CallerId(0), &keys[0])),
            UseCoverage::WatchedNoUse {
                since_ns: 100,
                until_ns: Some(300)
            }
        );
        assert_eq!(
            registry.entry_observation(edge_of(&registry, CallerId(0), &keys[0])),
            EntryObservation::Observed
        );
        assert!(matches!(
            registry.coverage(edge_of(&registry, CallerId(0), &keys[1])),
            UseCoverage::Unknown(UnknownReason::Loss(reason)) if reason.contains("clean read")
        ));
        // Nothing starts or overwrites a frozen interval afterwards.
        for note in [
            CoverageNote::Watched { since_ns: 500 },
            CoverageNote::Unknown(UnknownReason::NotAttached),
        ] {
            registry.note_coverage(CallerId(0), &keys[0], note.clone());
            registry.note_coverage(CallerId(0), &keys[2], note.clone());
            registry.publish();
            assert_eq!(
                registry.coverage(edge_of(&registry, CallerId(0), &keys[0])),
                UseCoverage::WatchedNoUse {
                    since_ns: 100,
                    until_ns: Some(300)
                },
                "{note:?}"
            );
            assert!(
                !matches!(
                    registry.coverage(edge_of(&registry, CallerId(0), &keys[2])),
                    UseCoverage::WatchedNoUse { .. }
                ),
                "no watch starts after the end: {note:?}"
            );
        }
        // A regression whose window starts after the frozen end leaves it.
        registry.note_health_regression("EVIDENCE rose", 350, 360);
        registry.publish();
        assert_eq!(
            registry.coverage(edge_of(&registry, CallerId(0), &keys[0])),
            UseCoverage::WatchedNoUse {
                since_ns: 100,
                until_ns: Some(300)
            }
        );
    }

    #[test]
    fn a_regression_demotes_its_interval_and_restarts_only_from_the_detecting_read() {
        // C3 closure 2: the demoted interval stays demoted; a new interval
        // may start only from the detecting read, never inside the window
        // (baseline..detection) where the drop happened.
        let mut registry = registry();
        let keys = mapped(
            &mut registry,
            CallerId(0),
            &[("/lib/a.so", 11, AdmissionState::Admitted)],
        );
        let edge =
            |registry: &CallerRegistry| registry.coverage(edge_of(registry, CallerId(0), &keys[0]));
        registry.note_coverage(
            CallerId(0),
            &keys[0],
            CoverageNote::Watched { since_ns: 100 },
        );
        registry.note_health_regression("EVIDENCE[3] rose", 125, 160);
        registry.publish();
        assert!(matches!(
            edge(&registry),
            UseCoverage::Unknown(UnknownReason::Loss(_))
        ));
        // An Unknown note does not overwrite the demotion's reason.
        registry.note_coverage(
            CallerId(0),
            &keys[0],
            CoverageNote::Unknown(UnknownReason::NotAttached),
        );
        registry.publish();
        assert!(matches!(
            edge(&registry),
            UseCoverage::Unknown(UnknownReason::Loss(_))
        ));
        registry.note_coverage(
            CallerId(0),
            &keys[0],
            CoverageNote::Watched { since_ns: 100 },
        );
        registry.publish();
        assert_eq!(
            edge(&registry),
            UseCoverage::WatchedNoUse {
                since_ns: 160,
                until_ns: None
            },
            "a new interval starts at the detecting read, not the baseline"
        );
    }

    fn witnessed(registry: &CallerRegistry, caller: u32, key: &ModuleKey) -> bool {
        let id = registry.module_id_for(key).unwrap();
        registry
            .edge(CallerId(caller), id)
            .is_some_and(|edge| edge.coverage.witnessed_first_ns.is_some())
    }

    fn unbound_rows(registry: &CallerRegistry) -> u64 {
        registry
            .modules()
            .filter_map(|module| module.unbound_use.as_ref())
            .map(|unbound| unbound.rows)
            .sum()
    }

    fn unbound_exe(
        dev: u64,
        ino: u64,
        path: Option<&str>,
        resolution: ExeResolution,
    ) -> UnboundExe {
        UnboundExe {
            dev,
            ino,
            path: path.map(str::to_string),
            resolution,
            identity_candidates: path.map(|path| vec![path.to_string()]).unwrap_or_default(),
        }
    }

    fn unbound_image(
        cookie: DomainCookie,
        pid: u32,
        first_ns: u64,
        calls: u64,
        exe: UnboundExe,
    ) -> UnboundImage {
        UnboundImage {
            cookie,
            pid_host: pid,
            first_call_ns: first_ns,
            calls,
            exe,
        }
    }

    fn module_pids(registry: &CallerRegistry, key: &ModuleKey) -> Vec<UnboundPid> {
        registry
            .modules()
            .find(|module| &module.key == key)
            .and_then(|module| module.unbound_use.as_ref())
            .map(|unbound| unbound.pids_sorted())
            .unwrap_or_default()
    }

    /// Each staged row's folded entries accumulate per scope (the
    /// owning module, and run-wide): the image's call lower bound
    /// grows with every row, saturating, never reset.
    #[test]
    fn unbound_images_accumulate_folded_calls_per_scope() {
        let mut registry = registry();
        let keys = mapped(
            &mut registry,
            CallerId(0),
            &[
                ("/lib/a.so", 11, AdmissionState::Admitted),
                ("/lib/b.so", 12, AdmissionState::Admitted),
            ],
        );
        let domain = NativeDomainId::mint();
        let cookie = DomainCookie::scripted(domain, 41);
        let provisional = unbound_exe(0, 0, None, ExeResolution::NoExecRecord);
        for (modules, first_ns, entries) in [
            (vec![keys[0].clone()], 210, 2),
            (vec![keys[0].clone()], 220, 3),
            (vec![keys[1].clone()], 230, 7),
        ] {
            registry.note_unbound_witness_with_image(
                modules,
                first_ns,
                UnboundReason::NoLiveCaller,
                entries,
                Some(unbound_image(
                    cookie,
                    9,
                    first_ns,
                    entries,
                    provisional.clone(),
                )),
            );
            registry.publish();
        }
        let a = module_pids(&registry, &keys[0]);
        assert_eq!(a.len(), 1);
        assert_eq!((a[0].calls_at_least, a[0].first_call_ns), (5, 210));
        let b = module_pids(&registry, &keys[1]);
        assert_eq!(b.len(), 1);
        assert_eq!((b[0].calls_at_least, b[0].first_call_ns), (7, 230));
        let wide = registry.unidentified_pids();
        assert_eq!(wide.len(), 1);
        assert_eq!((wide[0].calls_at_least, wide[0].first_call_ns), (12, 210));
    }

    /// A staged image carries its resolved executable into every
    /// image set that holds it.
    #[test]
    fn unbound_images_carry_their_resolved_executable() {
        let mut registry = registry();
        let keys = mapped(
            &mut registry,
            CallerId(0),
            &[("/lib/a.so", 11, AdmissionState::Admitted)],
        );
        let cookie = DomainCookie::scripted(NativeDomainId::mint(), 41);
        let exe = unbound_exe(8, 99, Some("/bin/x"), ExeResolution::ProcAlive);
        registry.note_unbound_witness_with_image(
            vec![keys[0].clone()],
            210,
            UnboundReason::NoLiveCaller,
            2,
            Some(unbound_image(cookie, 9, 210, 2, exe.clone())),
        );
        registry.publish();
        assert_eq!(module_pids(&registry, &keys[0])[0].exe, exe);
        assert_eq!(registry.unidentified_pids()[0].exe, exe);
    }

    /// Resolve-once: a refresh row never replaces the stored
    /// executable (only the EXEC backfill and the loss flip update
    /// it); calls still accumulate and the first call stays minimal.
    #[test]
    fn unbound_image_refresh_keeps_the_first_executable() {
        let mut registry = registry();
        let keys = mapped(
            &mut registry,
            CallerId(0),
            &[("/lib/a.so", 11, AdmissionState::Admitted)],
        );
        let cookie = DomainCookie::scripted(NativeDomainId::mint(), 41);
        let first = unbound_exe(8, 99, Some("/bin/x"), ExeResolution::ProcAlive);
        let later = unbound_exe(8, 1000, Some("/bin/y"), ExeResolution::SystemIndex);
        registry.note_unbound_witness_with_image(
            vec![keys[0].clone()],
            210,
            UnboundReason::NoLiveCaller,
            2,
            Some(unbound_image(cookie, 9, 210, 2, first.clone())),
        );
        registry.note_unbound_witness_with_image(
            vec![keys[0].clone()],
            220,
            UnboundReason::NoLiveCaller,
            3,
            Some(unbound_image(cookie, 9, 220, 3, later)),
        );
        registry.publish();
        let pids = module_pids(&registry, &keys[0]);
        assert_eq!(pids.len(), 1);
        assert_eq!(pids[0].exe, first);
        assert_eq!((pids[0].calls_at_least, pids[0].first_call_ns), (5, 210));
    }

    /// The EXEC backfill updates every image set holding the cookie
    /// (the EXEC arrived after the row staged); other cookies keep
    /// their verdict.
    #[test]
    fn attach_unbound_exe_backfills_every_image_set_holding_the_cookie() {
        let mut registry = registry();
        let keys = mapped(
            &mut registry,
            CallerId(0),
            &[("/lib/a.so", 11, AdmissionState::Admitted)],
        );
        let domain = NativeDomainId::mint();
        let joined = DomainCookie::scripted(domain, 41);
        let other = DomainCookie::scripted(domain, 42);
        let provisional = unbound_exe(0, 0, None, ExeResolution::NoExecRecord);
        for (cookie, pid) in [(joined, 9), (other, 10)] {
            registry.note_unbound_witness_with_image(
                vec![keys[0].clone()],
                210,
                UnboundReason::NoLiveCaller,
                2,
                Some(unbound_image(cookie, pid, 210, 2, provisional.clone())),
            );
        }
        registry.publish();
        let exe = unbound_exe(8, 99, Some("/bin/x"), ExeResolution::SystemIndex);
        registry.attach_unbound_exe(joined, exe.clone());
        let module = module_pids(&registry, &keys[0]);
        assert_eq!(module.len(), 2);
        assert_eq!(module[0].exe, exe, "pid order: oldest first call first");
        assert_eq!(module[1].exe, provisional);
        let wide = registry.unidentified_pids();
        assert_eq!(wide.len(), 2);
        assert_eq!(wide[0].exe, exe);
        assert_eq!(wide[1].exe, provisional);
        // Unknown cookies attach nowhere and refuse nothing.
        registry.attach_unbound_exe(DomainCookie::scripted(domain, 43), exe);
        assert_eq!(registry.unidentified_pids().len(), 2);
    }

    /// The loss flip marks only the domain's still-unjoined images
    /// `exec_record_lost`: joined pairs and other domains keep their
    /// verdicts.
    #[test]
    fn exec_loss_flip_marks_only_domain_unknowns_lost() {
        let mut registry = registry();
        let keys = mapped(
            &mut registry,
            CallerId(0),
            &[("/lib/a.so", 11, AdmissionState::Admitted)],
        );
        let lost = NativeDomainId::mint();
        let kept = NativeDomainId::mint();
        let provisional = unbound_exe(0, 0, None, ExeResolution::NoExecRecord);
        let joined = unbound_exe(8, 99, Some("/bin/x"), ExeResolution::ProcAlive);
        for (cookie, pid, first_ns, exe) in [
            (
                DomainCookie::scripted(lost, 41),
                9,
                210,
                provisional.clone(),
            ),
            (DomainCookie::scripted(lost, 42), 10, 220, joined.clone()),
            (
                DomainCookie::scripted(kept, 43),
                11,
                230,
                provisional.clone(),
            ),
        ] {
            registry.note_unbound_witness_with_image(
                vec![keys[0].clone()],
                first_ns,
                UnboundReason::NoLiveCaller,
                2,
                Some(unbound_image(cookie, pid, first_ns, 2, exe)),
            );
        }
        registry.publish();
        registry.flip_unbound_exec_loss(lost);
        let lost_exe = unbound_exe(0, 0, None, ExeResolution::ExecRecordLost);
        for pids in [
            module_pids(&registry, &keys[0]),
            registry.unidentified_pids(),
        ] {
            assert_eq!(pids.len(), 3);
            let by_pid: HashMap<u32, &UnboundPid> =
                pids.iter().map(|pid| (pid.pid_host, pid)).collect();
            assert_eq!(
                by_pid[&9].exe, lost_exe,
                "the lost domain's unjoined image flips"
            );
            assert_eq!(
                by_pid[&10].exe, joined,
                "the joined image keeps its executable"
            );
            assert_eq!(
                by_pid[&11].exe, provisional,
                "other domains keep their verdict"
            );
        }
        // Flipping twice, or an empty domain, changes nothing.
        registry.flip_unbound_exec_loss(lost);
        registry.flip_unbound_exec_loss(NativeDomainId::mint());
        assert_eq!(registry.unidentified_pids().len(), 3);
    }

    /// I1/M3 (C4 review): an endpoint two admitted modules share witnesses
    /// an edge only when exactly one of them has an edge to the bound
    /// caller, and is module-level use only when it names one module.
    /// Every decided row lands in exactly one placement.
    #[test]
    fn a_shared_endpoint_witnesses_only_an_unambiguous_edge_and_counts_reconcile() {
        let mut registry = registry();
        let a = module_info("/lib/a.so", 11, AdmissionState::Admitted);
        let b = module_info("/lib/b.so", 12, AdmissionState::Admitted);
        let (ka, kb) = (a.key.clone(), b.key.clone());
        registry.note_mapping(CallerId(0), 50, a.clone(), 100);
        registry.note_mapping(CallerId(1), 51, a, 100);
        registry.note_mapping(CallerId(1), 51, b, 100);
        registry.publish();
        let shared = vec![ka.clone(), kb.clone()];

        // Caller 0 maps only A: its edge to A is the one sharer edge.
        registry.note_bound_witness(CallerId(0), shared.clone(), 200);
        // Caller 1 maps both: which module it used is ambiguous.
        registry.note_bound_witness(CallerId(1), shared.clone(), 210);
        // Caller 2 maps neither: ambiguous, never module-level.
        registry.note_bound_witness(CallerId(2), shared.clone(), 220);
        registry.note_unbound_witness(shared, 230, UnboundReason::NoLiveCaller, 0);
        registry.note_unbound_witness(vec![ka.clone()], 240, UnboundReason::NoLiveCaller, 0);
        registry.note_unresolved_witness();
        registry.publish();

        assert!(witnessed(&registry, 0, &ka));
        assert!(!witnessed(&registry, 1, &ka) && !witnessed(&registry, 1, &kb));
        let placement = registry.witness_placement();
        assert_eq!(
            placement,
            WitnessPlacement {
                edge: 1,
                module: 1,
                ambiguous: 3,
                unresolved: 1,
            }
        );
        assert_eq!(placement.total(), 6, "every decided row exactly once");
        assert_eq!(unbound_rows(&registry), placement.module);
        let b_id = registry.module_id_for(&kb).unwrap();
        assert!(registry.module(b_id).unwrap().unbound_use.is_none());
        let shared_gaps = registry
            .gaps()
            .iter()
            .filter(|gap| gap.subject == WITNESS_SHARED_ENDPOINT)
            .count();
        assert_eq!(shared_gaps, 2, "once per sharing module");
    }

    /// A shared-endpoint unbound row folds no entries anywhere: its count
    /// names no single module, so the ambiguous placement keeps it out of
    /// every module's lower bound.
    #[test]
    fn a_shared_unbound_row_folds_no_entries_into_any_module() {
        let mut registry = registry();
        let a = module_info("/lib/a.so", 11, AdmissionState::Admitted);
        let b = module_info("/lib/b.so", 12, AdmissionState::Admitted);
        let (ka, kb) = (a.key.clone(), b.key.clone());
        registry.note_mapping(CallerId(0), 50, a, 100);
        registry.note_mapping(CallerId(0), 50, b, 100);
        registry.publish();
        registry.note_unbound_witness(
            vec![ka.clone(), kb.clone()],
            230,
            UnboundReason::NoLiveCaller,
            744,
        );
        registry.publish();
        assert_eq!(registry.witness_placement().ambiguous, 1);
        for key in [&ka, &kb] {
            let id = registry.module_id_for(key).unwrap();
            assert!(
                registry.module(id).unwrap().unbound_use.is_none(),
                "ambiguous rows fold nothing"
            );
        }
        assert_eq!(unbound_rows(&registry), 0);
    }

    #[test]
    fn pending_counts_resolve_with_their_witness_and_report_decisions() {
        // P3: a pending count resolves at publication from the same
        // committed state its witness does — same edge or same
        // rejection — and every pending count reports its placement.
        let mut registry = registry();
        let a = module_info("/lib/a.so", 11, AdmissionState::Admitted);
        let b = module_info("/lib/b.so", 12, AdmissionState::Admitted);
        let (ka, kb) = (a.key.clone(), b.key.clone());
        // A committed; B's mapping stages in the same window as the use.
        registry.note_mapping(CallerId(0), 50, a.clone(), 100);
        registry.publish();
        registry.note_mapping(CallerId(0), 51, b.clone(), 110);
        registry.note_pending_count(
            7,
            CallerId(0),
            vec![ka.clone(), kb.clone()],
            9,
            120,
            130,
            120,
            0,
        );
        registry.note_bound_witness(CallerId(0), vec![ka.clone(), kb.clone()], 120);
        registry.publish();
        // Together: the witness reads ambiguous and the count drops.
        assert_eq!(registry.witness_placement().ambiguous, 1);
        let decisions = registry.take_pending_count_decisions();
        assert_eq!(decisions.len(), 1, "{decisions:?}");
        assert_eq!(decisions[0].pending_id, 7);
        assert!(
            matches!(
                decisions[0].outcome,
                PendingCountOutcome::Rejected {
                    reason: PendingRejection::Ambiguous
                }
            ),
            "{decisions:?}"
        );
        let count_of = |registry: &CallerRegistry, key: &ModuleKey| {
            registry
                .module_id_for(key)
                .and_then(|id| registry.edge(CallerId(0), id))
                .map(|edge| edge.entry_count)
        };
        assert_eq!(count_of(&registry, &ka), Some(0));
        assert_eq!(count_of(&registry, &kb), Some(0));
        assert!(registry.take_pending_count_decisions().is_empty());
        // A single edged module places witness and count together.
        registry.note_pending_count(8, CallerId(0), vec![ka.clone()], 12, 140, 150, 140, 0);
        registry.note_bound_witness(CallerId(0), vec![ka.clone()], 140);
        registry.publish();
        let decisions = registry.take_pending_count_decisions();
        assert_eq!(decisions.len(), 1, "{decisions:?}");
        assert!(
            matches!(
                decisions[0].outcome,
                PendingCountOutcome::Placed { ref module } if module == &ka
            ),
            "{decisions:?}"
        );
        assert_eq!(count_of(&registry, &ka), Some(12));
        // No mapping edge: the witness goes module-level and the count
        // rejects with it.
        registry.note_pending_count(9, CallerId(3), vec![ka.clone()], 4, 160, 170, 160, 0);
        registry.note_bound_witness(CallerId(3), vec![ka.clone()], 160);
        registry.publish();
        let decisions = registry.take_pending_count_decisions();
        assert_eq!(decisions.len(), 1, "{decisions:?}");
        assert!(
            matches!(
                decisions[0].outcome,
                PendingCountOutcome::Rejected {
                    reason: PendingRejection::NoEdge
                }
            ),
            "{decisions:?}"
        );
        assert_eq!(registry.witness_placement().module, 1);
        assert_eq!(count_of(&registry, &ka), Some(12));
    }

    /// M4 (C4 review): a bound row without a mapping edge names its caller
    /// (the caller is identified) and never reads as an unidentified image;
    /// no witness gap publishes a tgid.
    #[test]
    fn a_no_mapping_edge_row_names_its_caller_and_no_gap_carries_a_tgid() {
        let mut registry = registry();
        let a = module_info("/lib/a.so", 11, AdmissionState::Admitted);
        let ka = a.key.clone();
        registry.note_mapping(CallerId(0), 50, a, 100);
        registry.publish();
        registry.note_bound_witness(CallerId(3), vec![ka.clone()], 200);
        registry.publish();
        let id = registry.module_id_for(&ka).unwrap();
        let unbound = registry.module(id).unwrap().unbound_use.clone().unwrap();
        assert_eq!(unbound.reasons.get(NO_MAPPING_EDGE), Some(&1));
        let gaps = registry.gaps();
        assert!(
            gaps.iter().any(
                |gap| gap.subject == WITNESS_WITHOUT_MAPPING && gap.caller == Some(CallerId(3))
            ),
            "{gaps:?}"
        );
        assert!(
            gaps.iter().all(|gap| gap.subject != UNBOUND_USE_SUBJECT),
            "the caller is identified: {gaps:?}"
        );

        registry.note_unbound_witness(vec![ka.clone()], 210, UnboundReason::NoLiveCaller, 0);
        let ghost = ModuleKey::physical(8, 1, 77, Some("sha0077".into()), "/lib/ghost.so");
        registry.note_unbound_witness(vec![ghost], 220, UnboundReason::NoLiveCaller, 0);
        registry.publish();
        assert!(
            registry
                .gaps()
                .iter()
                .any(|gap| gap.subject == UNBOUND_USE_SUBJECT)
        );
        assert!(
            registry.gaps().iter().all(|gap| gap.pid.is_none()),
            "{:?}",
            registry.gaps()
        );
        assert_eq!(registry.witness_placement().unresolved, 1);
    }

    /// C1 (C4 review): the exec-coverage revalidation keeps only live
    /// incarnations admitted before the cutoff whose pin, start time and
    /// exe identity still prove the admitted image; anything unreadable
    /// fails.
    #[test]
    fn revalidation_keeps_only_unchanged_incarnations_admitted_before_the_cutoff() {
        let (source, mut adapter) = adapter();
        for pid in [1, 2, 3, 4, 5, 6] {
            source.spawn(pid, 500 + u64::from(pid));
        }
        let same = adapter.admit(1, AUTHORITY, 100).unwrap();
        let exec_d = adapter.admit(2, AUTHORITY, 100).unwrap();
        let hidden = adapter.admit(3, AUTHORITY, 100).unwrap();
        let blind = adapter.admit(4, AUTHORITY, 100).unwrap();
        let dead = adapter.admit(5, AUTHORITY, 100).unwrap();
        let late = adapter.admit(6, AUTHORITY, 200).unwrap();
        source.exec(2, 200, "/bin/bar");
        source.hide_exe(3);
        source.blind(4);
        source.kill(5);
        let kept = adapter.revalidate_admitted_before(200);
        assert_eq!(kept, HashSet::from([same]));
        for absent in [exec_d, hidden, blind, dead, late] {
            assert!(!kept.contains(&absent));
        }
        // An incarnation retired by the scan lane is never revalidated.
        adapter.reconcile(&BTreeSet::from([1, 2, 3, 4, 6]), &mut |_| AUTHORITY, 250);
        assert!(adapter.record(exec_d).unwrap().retired);
        let kept = adapter.revalidate_admitted_before(300);
        assert!(kept.contains(&same) && kept.contains(&late));
        assert!(!kept.contains(&exec_d), "{kept:?}");
    }

    #[test]
    fn counted_use_stages_absolute_counts_with_pass_resolution_recency() {
        // C7 C4: a bound pair's count is an absolute saturating lower
        // bound; only a strict advance moves the count or last-seen, so
        // recency is never faked by a re-observed count.
        let mut registry = registry();
        let keys = mapped(
            &mut registry,
            CallerId(0),
            &[("/lib/a.so", 11, AdmissionState::Admitted)],
        );
        registry.note_counted_use(CallerId(0), &keys[0], 5, 100, 200, 0);
        registry.publish();
        let edge = edge_of(&registry, CallerId(0), &keys[0]);
        assert_eq!(edge.entry_count, 5);
        assert!(!edge.entry_saturated);
        assert_eq!(edge.entry_first_seen_ns, Some(100));
        assert_eq!(edge.entry_last_seen_ns, Some(200));
        assert_eq!(
            registry.coverage(edge),
            UseCoverage::Counted {
                since_ns: 100,
                lossy: false,
                pid_exit: false
            }
        );
        assert_eq!(registry.entry_observation(edge), EntryObservation::Observed);
        // A strict advance moves the count and last-seen; first-seen is
        // the earliest first record.
        registry.note_counted_use(CallerId(0), &keys[0], 9, 100, 300, 0);
        registry.publish();
        let edge = edge_of(&registry, CallerId(0), &keys[0]);
        assert_eq!(edge.entry_count, 9);
        assert_eq!(edge.entry_first_seen_ns, Some(100));
        assert_eq!(edge.entry_last_seen_ns, Some(300));
        // A stale re-read changes nothing: no regression, no recency.
        registry.note_counted_use(CallerId(0), &keys[0], 7, 100, 400, 0);
        registry.publish();
        let edge = edge_of(&registry, CallerId(0), &keys[0]);
        assert_eq!(edge.entry_count, 9);
        assert_eq!(edge.entry_last_seen_ns, Some(300));
        // An equal count re-observed later is not activity either.
        registry.note_counted_use(CallerId(0), &keys[0], 9, 100, 500, 0);
        registry.publish();
        let edge = edge_of(&registry, CallerId(0), &keys[0]);
        assert_eq!(edge.entry_count, 9);
        assert_eq!(edge.entry_last_seen_ns, Some(300));
    }

    #[test]
    fn thirty_two_first_installs_on_one_edge_yield_one() {
        // G21 (Sol oracle correction): base == 0 dispatches to the maximum
        // install, so 32 first sightings at one unit produce A=1, not 32.
        // Only the first sight sets recency.
        let mut registry = registry();
        let keys = mapped(
            &mut registry,
            CallerId(0),
            &[("/lib/a.so", 11, AdmissionState::Admitted)],
        );
        for pair in 0..32 {
            registry.note_counted_use(CallerId(0), &keys[0], 1, 100, 200 + pair, 0);
        }
        registry.publish();
        let edge = edge_of(&registry, CallerId(0), &keys[0]);
        assert_eq!(edge.entry_count, 1);
        assert_eq!(edge.entry_first_seen_ns, Some(100));
        assert_eq!(edge.entry_last_seen_ns, Some(200));
    }

    #[test]
    fn overlapping_demoted_growth_contributes_one_unit() {
        // G21: demoted growth merges overlapping numeric intervals per
        // (caller, module), so 32 identical (1,2] segments in one
        // publication add one unit, not 32.
        let mut registry = registry();
        let keys = mapped(
            &mut registry,
            CallerId(0),
            &[("/lib/a.so", 11, AdmissionState::Admitted)],
        );
        registry.note_counted_use(CallerId(0), &keys[0], 1, 100, 200, 0);
        registry.publish();
        assert_eq!(edge_of(&registry, CallerId(0), &keys[0]).entry_count, 1);
        for pair in 0..32 {
            registry.note_counted_use(CallerId(0), &keys[0], 1, 300 + pair, 400 + pair, 1);
        }
        registry.publish();
        let edge = edge_of(&registry, CallerId(0), &keys[0]);
        assert_eq!(edge.entry_count, 2);
    }

    #[test]
    fn disjoint_demoted_growth_accumulates() {
        // G21: disjoint segments in one publication (a mid-publish rebase)
        // all accumulate: (1,2] plus (2,3] on an edge at 1 yields 3.
        let mut registry = registry();
        let keys = mapped(
            &mut registry,
            CallerId(0),
            &[("/lib/a.so", 11, AdmissionState::Admitted)],
        );
        registry.note_counted_use(CallerId(0), &keys[0], 1, 100, 200, 0);
        registry.publish();
        registry.note_counted_use(CallerId(0), &keys[0], 1, 300, 400, 1);
        registry.note_counted_use(CallerId(0), &keys[0], 1, 310, 410, 2);
        registry.publish();
        let edge = edge_of(&registry, CallerId(0), &keys[0]);
        assert_eq!(edge.entry_count, 3);
    }

    #[test]
    fn repeated_first_sight_rereads_change_nothing() {
        // G21: equal-or-less re-reads change nothing, even across 32 pairs
        // and repeated publications: no count growth, no recency shift.
        let mut registry = registry();
        let keys = mapped(
            &mut registry,
            CallerId(0),
            &[("/lib/a.so", 11, AdmissionState::Admitted)],
        );
        for pair in 0..32 {
            registry.note_counted_use(CallerId(0), &keys[0], 1, 100, 200 + pair, 0);
        }
        registry.publish();
        for pair in 0..32 {
            registry.note_counted_use(CallerId(0), &keys[0], 1, 100, 500 + pair, 0);
        }
        registry.publish();
        let edge = edge_of(&registry, CallerId(0), &keys[0]);
        assert_eq!(edge.entry_count, 1);
        assert_eq!(edge.entry_last_seen_ns, Some(200));
    }

    #[test]
    fn split_proof_publications_increment_per_proof_bearing_publish() {
        // G21 publication recurrence: 32 terminal proofs (659,660] staged
        // together yield B=1 (overlap). Split across N proof-bearing
        // publications they yield B=N, one unit per publication — never a
        // loose range.
        for (batches, expected) in [(vec![32], 1), (vec![16, 16], 2), (vec![1; 32], 32)] {
            let mut registry = registry();
            let keys = mapped(
                &mut registry,
                CallerId(0),
                &[("/lib/b.so", 12, AdmissionState::Admitted)],
            );
            for batch in batches {
                for _ in 0..batch {
                    registry.note_counted_use(CallerId(0), &keys[0], 1, 900, 910, 659);
                }
                registry.publish();
            }
            let edge = edge_of(&registry, CallerId(0), &keys[0]);
            assert_eq!(edge.entry_count, expected);
        }
    }

    #[test]
    fn counted_use_saturates_at_the_edge_cap() {
        let mut registry = registry();
        let keys = mapped(
            &mut registry,
            CallerId(0),
            &[("/lib/a.so", 11, AdmissionState::Admitted)],
        );
        registry.note_counted_use(CallerId(0), &keys[0], MAX_EDGE_ENTRY_COUNT, 100, 200, 0);
        registry.publish();
        let edge = edge_of(&registry, CallerId(0), &keys[0]);
        assert_eq!(edge.entry_count, MAX_EDGE_ENTRY_COUNT);
        assert!(edge.entry_saturated);
        assert_eq!(edge.entry_last_seen_ns, Some(200));
    }

    #[test]
    fn zero_counted_use_stages_nothing() {
        // Counted needs a count ≥ 1: a bound row that reports zero (only
        // scripted rows do; BPF inserts at one) leaves the edge to its
        // witness.
        let mut registry = registry();
        let keys = mapped(
            &mut registry,
            CallerId(0),
            &[("/lib/a.so", 11, AdmissionState::Admitted)],
        );
        registry.note_witness(CallerId(0), &keys[0], 100);
        registry.note_counted_use(CallerId(0), &keys[0], 0, 100, 200, 0);
        registry.publish();
        let edge = edge_of(&registry, CallerId(0), &keys[0]);
        assert_eq!(edge.entry_count, 0);
        assert_eq!(edge.entry_first_seen_ns, None);
        assert_eq!(edge.entry_last_seen_ns, None);
        assert_eq!(
            registry.coverage(edge),
            UseCoverage::Witnessed { first_ns: 100 }
        );
    }

    #[test]
    fn counted_use_is_history_for_a_retired_caller_but_never_invents_an_edge() {
        // Like a witness (and unlike a live entry delta), a bound row's
        // count stages for a retired caller: the use predates the exit.
        let mut registry = registry();
        let keys = mapped(
            &mut registry,
            CallerId(0),
            &[("/lib/a.so", 11, AdmissionState::Admitted)],
        );
        registry.retire_caller(CallerId(0), "exited".into(), 150);
        registry.note_counted_use(CallerId(0), &keys[0], 4, 100, 140, 0);
        registry.publish();
        let edge = edge_of(&registry, CallerId(0), &keys[0]);
        assert_eq!(edge.entry_count, 4);
        assert_eq!(edge.entry_last_seen_ns, Some(140));
        // Without a mapping edge the count is dropped with one memoized
        // gap, however often the refresh repeats it.
        let missing = ModuleKey::physical(8, 1, 99, Some("sha0099".into()), "/lib/z.so");
        registry.note_counted_use(CallerId(0), &missing, 4, 100, 140, 0);
        registry.publish();
        registry.note_counted_use(CallerId(0), &missing, 6, 100, 150, 0);
        registry.publish();
        assert_eq!(registry.gaps().len(), 1);
        assert_eq!(
            registry.gaps()[0].subject,
            "usage coverage without mapping evidence"
        );
    }

    #[test]
    fn pairs_uncounted_demotes_watches_and_keeps_positives() {
        // C7 C4: once a pair insert fails, absence proves nothing: every
        // ongoing watch reads `uncounted`, positives stand, and a frozen
        // interval stands.
        let mut registry = registry();
        let keys = mapped(
            &mut registry,
            CallerId(0),
            &[
                ("/lib/a.so", 11, AdmissionState::Admitted),
                ("/lib/b.so", 12, AdmissionState::Admitted),
                ("/lib/c.so", 13, AdmissionState::Admitted),
                ("/lib/d.so", 14, AdmissionState::Admitted),
            ],
        );
        registry.note_coverage(
            CallerId(0),
            &keys[0],
            CoverageNote::Watched { since_ns: 100 },
        );
        registry.note_coverage(
            CallerId(0),
            &keys[1],
            CoverageNote::Watched { since_ns: 100 },
        );
        registry.note_witness(CallerId(0), &keys[2], 110);
        registry.note_counted_use(CallerId(0), &keys[3], 5, 100, 140, 0);
        registry.publish();
        let evidence: std::sync::Arc<str> = "CALLER_EVIDENCE[2] PairInsertFailure rose 0->1".into();
        registry.note_pairs_uncounted(evidence.clone(), 140);
        registry.publish();
        for key in &keys[0..2] {
            let watched = edge_of(&registry, CallerId(0), key);
            assert_eq!(
                registry.coverage(watched),
                UseCoverage::Unknown(UnknownReason::Uncounted(evidence.clone())),
                "{key:?}"
            );
        }
        let witnessed = edge_of(&registry, CallerId(0), &keys[2]);
        assert_eq!(
            registry.coverage(witnessed),
            UseCoverage::Witnessed { first_ns: 110 }
        );
        let counted = edge_of(&registry, CallerId(0), &keys[3]);
        assert!(matches!(
            registry.coverage(counted),
            UseCoverage::Counted { .. }
        ));
        assert!(
            registry
                .gaps()
                .iter()
                .any(|gap| gap.subject == "usage coverage pair insert failure"),
            "{:?}",
            registry.gaps()
        );
        assert_eq!(UnknownReason::Uncounted(evidence).code(), "uncounted");
    }

    #[test]
    fn pairs_uncounted_leaves_an_interval_frozen_before_the_evidence() {
        let mut registry = registry();
        let keys = mapped(
            &mut registry,
            CallerId(0),
            &[("/lib/a.so", 11, AdmissionState::Admitted)],
        );
        registry.note_coverage(
            CallerId(0),
            &keys[0],
            CoverageNote::Watched { since_ns: 100 },
        );
        registry.publish();
        registry.note_watch_end("stopping", 120);
        registry.publish();
        registry.note_pairs_uncounted(Arc::from("CALLER_EVIDENCE[2] PairInsertFailure rose"), 140);
        registry.publish();
        let edge = edge_of(&registry, CallerId(0), &keys[0]);
        assert!(
            matches!(
                registry.coverage(edge),
                UseCoverage::WatchedNoUse {
                    until_ns: Some(120),
                    ..
                }
            ),
            "an interval frozen before the evidence stands: {:?}",
            registry.coverage(edge)
        );
    }

    #[test]
    fn uncounted_reason_codes_detail_and_text() {
        let reason = UnknownReason::Uncounted("CALLER_EVIDENCE[2] PairInsertFailure rose".into());
        assert_eq!(reason.code(), "uncounted");
        assert_eq!(
            reason.detail(),
            Some("CALLER_EVIDENCE[2] PairInsertFailure rose")
        );
        assert!(reason.text().starts_with("uncounted"), "{}", reason.text());
    }

    #[test]
    fn settlement_latency_toggle_takes_exactly_one() {
        use super::{
            DIAGNOSTIC_SETTLEMENT_LATENCY_ENV, diagnostic_settlement_latency_by_env_value,
        };
        use std::ffi::OsStr;
        assert_eq!(
            DIAGNOSTIC_SETTLEMENT_LATENCY_ENV,
            "P11SCOPE_DIAGNOSTIC_SETTLEMENT_LATENCY"
        );
        assert!(diagnostic_settlement_latency_by_env_value(Some(
            OsStr::new("1")
        )));
        for other in [
            None,
            Some(OsStr::new("")),
            Some(OsStr::new("0")),
            Some(OsStr::new("true")),
        ] {
            assert!(
                !diagnostic_settlement_latency_by_env_value(other),
                "only exactly 1 enables: {other:?}"
            );
        }
    }

    #[test]
    fn settlement_latency_histogram_percentiles_are_exact_to_1ms() {
        use super::SettlementLatencyHist;
        let mut hist = SettlementLatencyHist::new();
        assert_eq!(hist.summary().samples, 0);
        assert_eq!(hist.summary().p99_ms, None);
        // 100 samples at 0..100 ms (entry 1_000_000_000, now staggered).
        for ms in 0..100u64 {
            hist.record(1_000_000_000, 1_000_000_000 + ms * 1_000_000);
        }
        let summary = hist.summary();
        assert_eq!(summary.samples, 100);
        // rank ceil(0.5*100)=50 -> bucket 49; rank ceil(0.99*100)=99 -> 98.
        assert_eq!(summary.p50_ms, Some(49));
        assert_eq!(summary.p99_ms, Some(98));
        assert_eq!(summary.max_ms, 99);
        assert_eq!(summary.overflow, 0);
        assert_eq!(summary.unknown_ts, 0);
    }

    #[test]
    fn settlement_latency_histogram_overflow_unknown_and_max() {
        use super::SettlementLatencyHist;
        let mut hist = SettlementLatencyHist::new();
        hist.record(1_000, 1_000 + 250_000_000); // 250 ms in-bucket.
        hist.record(1_000, 1_000 + 12_000_000_000); // 12 s overflows.
        hist.record(0, 2_000); // no timestamp: unknown, not a sample.
        hist.record(1_000, 0); // failed clock read: unknown, not a sample.
        let summary = hist.summary();
        assert_eq!(summary.samples, 2);
        assert_eq!(summary.overflow, 1);
        assert_eq!(summary.unknown_ts, 2);
        assert_eq!(summary.max_ms, 12_000);
        // Both ranks land on the only in-bucket sample.
        assert_eq!(summary.p50_ms, Some(250));
        // rank ceil(0.99*2)=2 falls past the buckets: max bounds it.
        assert_eq!(summary.p99_ms, Some(12_000));
    }

    #[test]
    fn settlement_latency_setter_allocates_and_drops() {
        use super::RegistryLimits;
        let mut registry = super::CallerRegistry::new(RegistryLimits::default_limits());
        assert_eq!(registry.settlement_latency_summary(), None);
        registry.set_diagnostic_settlement_latency(true);
        let summary = registry
            .settlement_latency_summary()
            .expect("enabled registry reports");
        assert_eq!(summary.samples, 0);
        registry.set_diagnostic_settlement_latency(false);
        assert_eq!(registry.settlement_latency_summary(), None);
    }
}
