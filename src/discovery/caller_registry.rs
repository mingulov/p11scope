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

use crate::discovery::native_binding::{BindingCensus, UnboundReason};
use crate::process::{PidPin, generation_gone, process_is_zombie, process_start_time};
use crate::semantics_edge::{EdgeSemantics, SemanticCall};
use anyhow::{Result, anyhow, bail};
use std::collections::{BTreeMap, BTreeSet, HashMap, HashSet};
use std::hash::BuildHasher as _;
use std::os::unix::fs::MetadataExt as _;
use std::sync::Arc;

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

/// Which authority backs a caller incarnation's image reference.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum ImageAuthority {
    /// BPF task-cookie/exec-ID identity (the native lifecycle adapter).
    NativeExact { task_cookie: u64, exec_id: u64 },
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
    /// False when the exe identity was unreadable at admission: exec
    /// changes are then undetectable and the record says so.
    pub exec_observed: bool,
    pub authority: ImageAuthority,
    pub lifecycle: CallerLifecycle,
    pub lifecycle_reason: Option<String>,
    pub first_seen_ns: u64,
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
    /// True when `pid` names no live process: reaped, never existed, or
    /// a zombie awaiting its parent's `wait`. Zombies count as gone —
    /// the generation is dead even though `/proc` still parses — so a
    /// dead-but-unreaped target retires instead of re-admitting.
    fn gone(&self, pid: u32) -> bool;
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
    Some(ExeIdentity {
        dev: metadata.dev(),
        ino: metadata.ino(),
        mtime_secs: metadata.mtime(),
        mtime_nanos: metadata.mtime_nsec(),
        path: link,
    })
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

    fn exe_identity(&self, pid: u32) -> Option<ExeIdentity> {
        read_exe_identity(pid)
    }

    fn gone(&self, pid: u32) -> bool {
        generation_gone(pid) || process_is_zombie(pid)
    }
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

struct TrackedCaller<Pin> {
    record: CallerRecord,
    pin: Option<Pin>,
}

/// Tracks caller incarnations: admission, exit/exec/reuse retirement with
/// retained evidence. The live incarnation per pid is unique; history is
/// never rewritten and IDs are never reused.
pub(crate) struct CallerAdapter<Source: ProcessSource> {
    source: Source,
    next_id: u32,
    incarnations: BTreeMap<u32, u32>,
    callers: BTreeMap<CallerId, TrackedCaller<Source::Pin>>,
    live_by_pid: BTreeMap<u32, CallerId>,
    max_callers: usize,
    admit_refused: u64,
}

/// Why one admission attempt failed: an honest pin failure, or a budget
/// refusal carrying the resource, limit, and requested occupancy.
struct AdmitFailure {
    reason: String,
    budget: Option<BudgetRefusal>,
}

impl<Source: ProcessSource> CallerAdapter<Source> {
    pub(crate) fn new(source: Source) -> Self {
        Self {
            source,
            next_id: 0,
            incarnations: BTreeMap::new(),
            callers: BTreeMap::new(),
            live_by_pid: BTreeMap::new(),
            max_callers: DEFAULT_MAX_CALLERS,
            admit_refused: 0,
        }
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
        Some((&tracked.record, tracked.pin.as_ref()?))
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
        let pin = self
            .source
            .open(pid)
            .map_err(|error| anyhow!("cannot pin caller pid {pid}: {error}"))?;
        // A zombie pins successfully (its pidfd and `/proc` entries
        // survive until the parent reaps it), but admitting one mints a
        // caller for a dead generation that retires on the next pass —
        // one spurious incarnation per pass. Refuse up front instead.
        if self.source.gone(pid) {
            bail!("cannot pin caller pid {pid}: no live process with that pid (it exited)");
        }
        let start_time = self.source.start_time(pid);
        let exe = self.source.exe_identity(pid);
        let id = self.mint()?;
        let incarnation = self.incarnations.get(&pid).copied().unwrap_or(0);
        self.incarnations.insert(pid, incarnation.saturating_add(1));
        self.callers.insert(
            id,
            TrackedCaller {
                record: CallerRecord {
                    id,
                    pid,
                    start_time,
                    incarnation,
                    exec_observed: exe.is_some(),
                    exe,
                    authority,
                    lifecycle: CallerLifecycle::Mapped,
                    lifecycle_reason: None,
                    first_seen_ns: now_ns,
                    last_seen_ns: now_ns,
                    retired: false,
                },
                pin: Some(pin),
            },
        );
        self.live_by_pid.insert(pid, id);
        Ok(id)
    }

    /// Reconcile's admission: the budget refusal carries its
    /// resource/limit/requested structurally; pin failures stay bare.
    fn try_admit(
        &mut self,
        pid: u32,
        authority: ImageAuthority,
        now_ns: u64,
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
        self.admit(pid, authority, now_ns)
            .map_err(|error| AdmitFailure {
                reason: format!("{error:#}"),
                budget: None,
            })
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
    pub(crate) fn exec_transition(
        &mut self,
        id: CallerId,
        authority_for: &mut dyn FnMut(u32) -> ImageAuthority,
        now_ns: u64,
    ) -> Vec<CallerEvent> {
        let Some(pid) = self
            .callers
            .get(&id)
            .filter(|tracked| !tracked.record.retired)
            .map(|tracked| tracked.record.pid)
        else {
            return Vec::new();
        };
        self.retire(
            id,
            CallerLifecycle::ExecRetired,
            "a later image of the same task was witnessed natively (its exec sequence advanced \
             under its task cookie, or its leader task changed under the held pidfd)"
                .into(),
            now_ns,
        );
        vec![match self.try_admit(pid, authority_for(pid), now_ns) {
            Ok(new) => CallerEvent::ExecRetired { old: id, new },
            Err(failure) => CallerEvent::AdmitFailed {
                pid,
                reason: format!("post-exec re-admission failed: {}", failure.reason),
                budget: failure.budget,
            },
        }]
    }

    /// Reconcile tracked callers against one scan pass's observed pids:
    /// detect exit, exec (leader and nonleader — both change the exe
    /// identity while the pin holds), and PID reuse; admit newly observed
    /// pids. Every transition is an event; failures to admit are events,
    /// never silent. `authority_for` resolves the image authority per pid,
    /// so one pass can mix native-exact and scan-pinned incarnations.
    pub(crate) fn reconcile(
        &mut self,
        observed: &BTreeSet<u32>,
        authority_for: &mut dyn FnMut(u32) -> ImageAuthority,
        now_ns: u64,
    ) -> Vec<CallerEvent> {
        let mut events = Vec::new();
        let live: Vec<(u32, CallerId)> = self
            .live_by_pid
            .iter()
            .map(|(pid, id)| (*pid, *id))
            .collect();
        for (pid, id) in live {
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
                    self.retire(
                        id,
                        CallerLifecycle::ExecRetired,
                        "executable image changed while the generation pin held (exec)".into(),
                        now_ns,
                    );
                    match self.try_admit(pid, authority_for(pid), now_ns) {
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
                match self.try_admit(pid, authority_for(pid), now_ns) {
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
            match self.try_admit(pid, authority_for(pid), now_ns) {
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
            Self::CapacityLimited(_) => "capacity_limited",
            Self::Loss(_) => "loss",
            Self::RetiredBeforeCoverage => "retired_before_coverage",
            Self::UseBeforeAdmission => "use_before_admission",
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
            Self::CapacityLimited(resource) => format!("capacity limited: {resource}"),
            Self::Loss(reason) => format!("loss: {reason}"),
            Self::RetiredBeforeCoverage => "retired before coverage".into(),
            Self::UseBeforeAdmission => "use before admission".into(),
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
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct UnboundUse {
    /// Earliest first-association instant among the rows.
    pub first_ns: u64,
    pub rows: u64,
    /// Rows per reason code ([`UnboundReason::code`] or
    /// [`NO_MAPPING_EDGE`]).
    ///
    /// [`UnboundReason::code`]: crate::discovery::native_binding::UnboundReason::code
    pub reasons: BTreeMap<&'static str, u64>,
}

/// Reason code for a witness bound to a caller incarnation whose edge to
/// the module is not known (no mapping note reached it).
pub(crate) const NO_MAPPING_EDGE: &str = "no_mapping_edge";

const UNBOUND_USE_SUBJECT: &str = "used by an unidentified caller image";
const WITNESS_WITHOUT_MAPPING: &str = "native witness without mapping evidence";
const WITNESS_UNKNOWN_MODULE: &str = "native witness for an unknown module";
const WITNESS_SHARED_ENDPOINT: &str = "ambiguous shared endpoint";

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

impl WitnessPlacement {
    #[cfg(test)]
    pub(crate) fn total(&self) -> u64 {
        self.edge + self.module + self.ambiguous + self.unresolved
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

#[derive(Debug, Clone)]
enum Mutation {
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
        /// is sound).
        count: u64,
        /// The pair's first record (`recorded_at_ns`).
        first_ns: u64,
        /// The read that observed `count` (`rows_read_ns`): pass
        /// resolution, never a BPF timestamp.
        last_ns: u64,
    },
    NotePendingCount {
        caller: CallerId,
        /// The candidate modules (the witness's): placement resolves at
        /// publication, alongside the witness, against the mappings this
        /// same publication commits.
        modules: Vec<ModuleKey>,
        count: u64,
        first_ns: u64,
        last_ns: u64,
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
    },
}

/// The caller/module registry. Mutations stage in batch order and apply
/// only at `publish`, so readers (including the JSON renderer) observe
/// one consistent snapshot per batch and the ordering test can pin that
/// facts publish synchronously with the batch return.
pub(crate) struct CallerRegistry {
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
    staged: Vec<Mutation>,
    /// Why an edge no producer covered reads unknown: `ScanOnly` until a
    /// native usage producer runs (Task 6 C5 sets `NotAttached`).
    uncovered_reason: UnknownReason,
    /// Detection instant of the last global health regression: a new
    /// watch interval never starts before it.
    last_health_regression_ns: Option<u64>,
    /// The producer stopped: every watch ended here and none starts.
    watches_ended_ns: Option<u64>,
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
}

impl CallerRegistry {
    pub(crate) fn new(limits: RegistryLimits) -> Self {
        Self {
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
            staged: Vec::new(),
            uncovered_reason: UnknownReason::ScanOnly,
            last_health_regression_ns: None,
            watches_ended_ns: None,
            coverage_gap_memo: BTreeSet::new(),
            witness_gap_memo: BTreeSet::new(),
            witness_placement: WitnessPlacement::default(),
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
        }
    }

    /// Why edges no producer covered read unknown. The scan lane leaves
    /// `ScanOnly`; the native lane (Task 6 C5) sets `NotAttached`. This
    /// only names the reason — it never makes a zero read observed.
    #[cfg_attr(not(test), allow(dead_code))] // Task 6 C5 native lane.
    pub(crate) fn set_uncovered_reason(&mut self, reason: UnknownReason) {
        self.uncovered_reason = reason;
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
            };
        }
        if let Some(first_ns) = coverage.witnessed_first_ns {
            return UseCoverage::Witnessed { first_ns };
        }
        if let Some(since_ns) = coverage.counted_since_ns {
            return UseCoverage::Counted {
                since_ns,
                lossy: coverage.lossy,
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
    /// process is exactly what could not be identified.
    pub(crate) fn note_unbound_witness(
        &mut self,
        modules: Vec<ModuleKey>,
        first_ns: u64,
        reason: UnboundReason,
    ) {
        self.staged.push(Mutation::NoteUnboundWitness {
            modules,
            first_ns,
            reason,
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
    /// witness it never invents an edge (one memoized gap).
    pub(crate) fn note_counted_use(
        &mut self,
        caller: CallerId,
        module: &ModuleKey,
        count: u64,
        first_ns: u64,
        last_ns: u64,
    ) {
        self.staged.push(Mutation::NoteCountedUse {
            caller,
            module: module.clone(),
            count,
            first_ns,
            last_ns,
        });
    }

    /// Stage one bound pair's absolute entry count whose edge placement
    /// is not yet committed (its mapping stages in this same window and
    /// commits at publication, for example): placement resolves at
    /// publication, alongside the
    /// witness, against the mappings the publication commits — exactly
    /// one edged module takes the count, like the witness. Anything else
    /// (no edge, ambiguity, no admission) drops silently: the witness
    /// records the placement gaps, and a count never invents an edge.
    pub(crate) fn note_pending_count(
        &mut self,
        caller: CallerId,
        modules: Vec<ModuleKey>,
        count: u64,
        first_ns: u64,
        last_ns: u64,
    ) {
        self.staged.push(Mutation::NotePendingCount {
            caller,
            modules,
            count,
            first_ns,
            last_ns,
        });
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
        self.staged.push(Mutation::RecordGap { gap });
    }

    /// Apply every staged mutation in order and publish the snapshot.
    /// Returns the number of applied mutations.
    pub(crate) fn publish(&mut self) -> usize {
        let staged = std::mem::take(&mut self.staged);
        let applied = staged.len();
        // Per-pass activity starts quiet: advances below set it.
        for edge in self.edges.values_mut() {
            edge.entry_rose_since_previous_pass = false;
        }
        for mutation in staged {
            self.apply(mutation);
        }
        self.facts_revision = self.facts_revision.saturating_add(1);
        self.published_revision = self.facts_revision;
        applied
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
    /// counter then over-counts, never under-counts).
    fn push_gap(&mut self, gap: RegistryGap) {
        if let Some(&index) = self.gap_index.get(&gap) {
            self.gap_repeats[index] = self.gap_repeats[index].saturating_add(1);
            return;
        }
        if self.gaps.len() >= self.limits.max_gaps {
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

    fn apply(&mut self, mutation: Mutation) {
        match mutation {
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
                for edge in self.edges.values_mut() {
                    if let Some(state) = edge.semantics.as_mut() {
                        state.invalidate();
                    }
                    // Lost call records make every counted column a
                    // lower bound: a counted zero is no longer a fact.
                    if edge.coverage.counted_since_ns.is_some() || edge.entry_count > 0 {
                        edge.coverage.lossy = true;
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
                for edge in self.edges.values_mut() {
                    // A failed or skipped count re-read leaves every
                    // counted column a lower bound: observed counts
                    // stand, quiet claims do not.
                    if edge.coverage.counted_since_ns.is_some() || edge.entry_count > 0 {
                        edge.coverage.lossy = true;
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
            } => match modules.as_slice() {
                [key] => {
                    self.apply_unbound_use(key, first_ns, reason.code(), reason.text(), true);
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
                caller,
                modules,
                count,
                first_ns,
                last_ns,
            } => self.apply_pending_count(caller, &modules, count, first_ns, last_ns),
            Mutation::NoteCountedUse {
                caller,
                module,
                count,
                first_ns,
                last_ns,
            } => {
                let Some(edge) = self.coverage_edge(caller, &module) else {
                    return;
                };
                // Absolute staging: only a strict advance moves the
                // count or last-seen. Equal-or-less re-reads (a stale
                // refresh, a repeated first sight) change nothing, so
                // recency always names the read that observed the rise.
                // Retired callers are not frozen out: like a witness,
                // the count is pre-exit history arriving late.
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
            } => self.apply_retire(caller, reason, at_ns),
            Mutation::NoteModuleAbsent {
                caller,
                module,
                complete_scan,
                at_ns,
            } => self.apply_absent(caller, module, complete_scan, at_ns),
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
                    self.recompute_module(module);
                }
            }
            Mutation::RecordGap { gap } => self.push_gap(gap),
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

    /// The edge a coverage note names, or `None` with a gap: coverage
    /// notes never invent edges. Retired callers stay addressable —
    /// positive history survives retirement.
    fn apply_bound_witness(&mut self, caller: CallerId, modules: &[ModuleKey], first_ns: u64) {
        let edged: Vec<ModuleId> = modules
            .iter()
            .filter_map(|key| self.modules_by_key.get(key).copied())
            .filter(|id| self.edges.contains_key(&(caller, *id)))
            .collect();
        match (edged.as_slice(), modules) {
            ([id], _) => {
                let edge = self.edges.get_mut(&(caller, *id)).expect("edged");
                let first = edge
                    .coverage
                    .witnessed_first_ns
                    .map_or(first_ns, |was| was.min(first_ns));
                edge.coverage.witnessed_first_ns = Some(first);
                self.witness_placement.edge += 1;
            }
            ([], [key]) => {
                // The caller is identified; only its mapping is missing.
                let id = self.modules_by_key.get(key).copied();
                self.push_coverage_gap(
                    caller,
                    key,
                    id,
                    WITNESS_WITHOUT_MAPPING,
                    format!(
                        "{} has no mapping edge to this module: the witnessed use stays \
                         module-level; a witness never invents a mapping",
                        caller.label()
                    ),
                );
                self.apply_unbound_use(
                    key,
                    first_ns,
                    NO_MAPPING_EDGE,
                    "the bound caller has no mapping edge to the module",
                    false,
                );
            }
            ([], []) => self.witness_placement.unresolved += 1,
            _ => self.apply_shared_endpoint(modules, "bound to a caller incarnation"),
        }
    }

    /// One pending count's publication: placement mirrors
    /// [`Self::apply_bound_witness`] — exactly one edged module takes
    /// the count — and admission mirrors the coordinator's
    /// `stage_pair_count` (only admitted modules count). On placement
    /// the count and its `Counted` coverage apply exactly as if staged
    /// placed; anything else drops silently (the witness records the
    /// placement gaps, and no gap is owed twice).
    fn apply_pending_count(
        &mut self,
        caller: CallerId,
        modules: &[ModuleKey],
        count: u64,
        first_ns: u64,
        last_ns: u64,
    ) {
        let placed = modules
            .iter()
            .filter(|key| {
                self.modules_by_key
                    .get(*key)
                    .is_some_and(|id| self.edges.contains_key(&(caller, *id)))
            })
            .collect::<Vec<_>>();
        let [module] = placed.as_slice() else {
            return;
        };
        let admitted = self
            .modules_by_key
            .get(*module)
            .and_then(|id| self.modules.get(id))
            .is_some_and(|record| record.admission == AdmissionState::Admitted);
        if !admitted {
            return;
        }
        let module = (*module).clone();
        self.apply(Mutation::NoteCountedUse {
            caller,
            module: module.clone(),
            count,
            first_ns,
            last_ns,
        });
        self.apply(Mutation::NoteCoverage {
            caller,
            module,
            note: CoverageNote::Counted { since_ns: first_ns },
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
    /// and its gap names the caller instead.
    fn apply_unbound_use(
        &mut self,
        key: &ModuleKey,
        first_ns: u64,
        code: &'static str,
        text: &str,
        unidentified: bool,
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
        let module = self.modules.get_mut(&id).expect("indexed module");
        let path = module.paths.iter().next().cloned().unwrap_or_default();
        let unbound = module.unbound_use.get_or_insert(UnboundUse {
            first_ns,
            rows: 0,
            reasons: BTreeMap::new(),
        });
        unbound.first_ns = unbound.first_ns.min(first_ns);
        unbound.rows = unbound.rows.saturating_add(1);
        let count = unbound.reasons.entry(code).or_default();
        *count = count.saturating_add(1);
        if unidentified {
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
            if self.semantic_occupied >= self.limits.max_semantic_states {
                self.semantic_refused = self.semantic_refused.saturating_add(1);
                let refusal = BudgetRefusal {
                    resource: "semantic_state",
                    limit: self.limits.max_semantic_states,
                    requested: self.semantic_occupied + 1,
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
            self.edges
                .get_mut(&(caller, id))
                .expect("edge resolved above")
                .semantics = Some(EdgeSemantics::default());
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
            .observe(call);
        self.semantic_refused = self.semantic_refused.saturating_add(refused);
    }

    fn apply_retire(&mut self, caller: CallerId, reason: String, at_ns: u64) {
        let _ = at_ns;
        self.retired.insert(caller, reason.clone());
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
    use std::cell::RefCell;
    use std::collections::HashMap;
    use std::rc::Rc;

    #[derive(Debug, Clone)]
    struct ScriptedProcess {
        alive: bool,
        start_time: u64,
        exe: Option<ExeIdentity>,
        /// False simulates an unreadable `/proc` (a race or a permission
        /// wall): liveness answers but identity reads fail.
        readable: bool,
    }

    #[derive(Debug, Clone, Default)]
    struct ScriptedState {
        processes: HashMap<u32, ScriptedProcess>,
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
            self.set(
                pid,
                ScriptedProcess {
                    alive: true,
                    start_time,
                    exe: Some(ExeIdentity {
                        dev: 1,
                        ino: 100,
                        mtime_secs: 10,
                        mtime_nanos: 0,
                        path: Some("/bin/driver".into()),
                    }),
                    readable: true,
                },
            );
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

        fn hide_exe(&self, pid: u32) {
            if let Some(process) = self.state.borrow_mut().processes.get_mut(&pid) {
                process.exe = None;
            }
        }

        pub(crate) fn exec(&self, pid: u32, ino: u64, path: &str) {
            if let Some(process) = self.state.borrow_mut().processes.get_mut(&pid) {
                process.exe = Some(ExeIdentity {
                    dev: 1,
                    ino,
                    mtime_secs: 20,
                    mtime_nanos: 0,
                    path: Some(path.into()),
                });
            }
        }
    }

    impl ProcessSource for ScriptedSource {
        type Pin = (u32, u64);

        fn open(&mut self, pid: u32) -> Result<Self::Pin, String> {
            let state = self.state.borrow();
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

        fn exe_identity(&self, pid: u32) -> Option<ExeIdentity> {
            self.state
                .borrow()
                .processes
                .get(&pid)
                .filter(|process| process.alive && process.readable)
                .and_then(|process| process.exe.clone())
        }

        fn gone(&self, pid: u32) -> bool {
            !self
                .state
                .borrow()
                .processes
                .get(&pid)
                .is_some_and(|process| process.alive)
        }
    }

    const AUTHORITY: ImageAuthority = ImageAuthority::ScanPinned;

    fn adapter() -> (ScriptedSource, CallerAdapter<ScriptedSource>) {
        let source = ScriptedSource::default();
        let adapter = CallerAdapter::new(source.clone());
        (source, adapter)
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
        let mut adapter = CallerAdapter::new(OsProcessSource);
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
                lossy: false
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
                lossy: true
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
                lossy: true
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
        registry.note_unbound_witness(shared, 230, UnboundReason::NoLiveCaller);
        registry.note_unbound_witness(vec![ka.clone()], 240, UnboundReason::NoLiveCaller);
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

        registry.note_unbound_witness(vec![ka.clone()], 210, UnboundReason::NoLiveCaller);
        let ghost = ModuleKey::physical(8, 1, 77, Some("sha0077".into()), "/lib/ghost.so");
        registry.note_unbound_witness(vec![ghost], 220, UnboundReason::NoLiveCaller);
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
        registry.note_counted_use(CallerId(0), &keys[0], 5, 100, 200);
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
                lossy: false
            }
        );
        assert_eq!(registry.entry_observation(edge), EntryObservation::Observed);
        // A strict advance moves the count and last-seen; first-seen is
        // the earliest first record.
        registry.note_counted_use(CallerId(0), &keys[0], 9, 100, 300);
        registry.publish();
        let edge = edge_of(&registry, CallerId(0), &keys[0]);
        assert_eq!(edge.entry_count, 9);
        assert_eq!(edge.entry_first_seen_ns, Some(100));
        assert_eq!(edge.entry_last_seen_ns, Some(300));
        // A stale re-read changes nothing: no regression, no recency.
        registry.note_counted_use(CallerId(0), &keys[0], 7, 100, 400);
        registry.publish();
        let edge = edge_of(&registry, CallerId(0), &keys[0]);
        assert_eq!(edge.entry_count, 9);
        assert_eq!(edge.entry_last_seen_ns, Some(300));
        // An equal count re-observed later is not activity either.
        registry.note_counted_use(CallerId(0), &keys[0], 9, 100, 500);
        registry.publish();
        let edge = edge_of(&registry, CallerId(0), &keys[0]);
        assert_eq!(edge.entry_count, 9);
        assert_eq!(edge.entry_last_seen_ns, Some(300));
    }

    #[test]
    fn counted_use_saturates_at_the_edge_cap() {
        let mut registry = registry();
        let keys = mapped(
            &mut registry,
            CallerId(0),
            &[("/lib/a.so", 11, AdmissionState::Admitted)],
        );
        registry.note_counted_use(CallerId(0), &keys[0], MAX_EDGE_ENTRY_COUNT, 100, 200);
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
        registry.note_counted_use(CallerId(0), &keys[0], 0, 100, 200);
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
        registry.note_counted_use(CallerId(0), &keys[0], 4, 100, 140);
        registry.publish();
        let edge = edge_of(&registry, CallerId(0), &keys[0]);
        assert_eq!(edge.entry_count, 4);
        assert_eq!(edge.entry_last_seen_ns, Some(140));
        // Without a mapping edge the count is dropped with one memoized
        // gap, however often the refresh repeats it.
        let missing = ModuleKey::physical(8, 1, 99, Some("sha0099".into()), "/lib/z.so");
        registry.note_counted_use(CallerId(0), &missing, 4, 100, 140);
        registry.publish();
        registry.note_counted_use(CallerId(0), &missing, 6, 100, 150);
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
        registry.note_counted_use(CallerId(0), &keys[3], 5, 100, 140);
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
}
