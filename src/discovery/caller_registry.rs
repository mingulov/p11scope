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

use crate::process::{PidPin, generation_gone, process_is_zombie, process_start_time};
use crate::semantics_edge::{EdgeSemantics, SemanticCall};
use anyhow::{Result, anyhow, bail};
use std::collections::{BTreeMap, BTreeSet};
use std::os::unix::fs::MetadataExt as _;

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

    pub(crate) fn records(&self) -> impl Iterator<Item = &CallerRecord> {
        self.callers.values().map(|tracked| &tracked.record)
    }

    pub(crate) fn live_id(&self, pid: u32) -> Option<CallerId> {
        self.live_by_pid.get(&pid).copied()
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
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum EntryObservation {
    Observed,
    UnknownNotAdmitted,
    UnknownUnavailable,
}

impl EntryObservation {
    pub(crate) const fn label(self) -> &'static str {
        match self {
            Self::Observed => "observed",
            Self::UnknownNotAdmitted => "unknown (not admitted)",
            Self::UnknownUnavailable => "unknown (usage observation unavailable)",
        }
    }
}

/// One caller/module edge: mapping evidence plus cumulative usage.
#[derive(Debug)]
pub(crate) struct EdgeRecord {
    pub caller: CallerId,
    pub module: ModuleId,
    pub mapping: MappingState,
    pub mapping_reason: Option<String>,
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
    pub lifecycle: ModuleLifecycle,
    /// True once a complete rescan proved the module gone, even if it
    /// later reloaded: unload evidence is retained.
    pub unloaded_observed: bool,
}

/// One budget refusal, carried structurally so the rendered gap names
/// the resource, its limit, and the requested occupancy — never a bare
/// sentence a reader must parse.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct BudgetRefusal {
    pub resource: &'static str,
    pub limit: usize,
    pub requested: usize,
}

/// One explicit coverage gap: what is unknown and why. Never silent
/// absence.
#[derive(Debug, Clone, PartialEq, Eq)]
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

/// Default retained-table bounds. Exhaustion drops the association and
/// records a gap — never an eviction that rewrites published history.
pub(crate) const DEFAULT_MAX_CALLERS: usize = 4096;
pub(crate) const DEFAULT_MAX_MODULES: usize = 4096;
pub(crate) const DEFAULT_MAX_EDGES: usize = 32768;
pub(crate) const DEFAULT_MAX_GAPS: usize = 1024;
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
    gaps_suppressed: u64,
    staged: Vec<Mutation>,
    usage_feed: bool,
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
            gaps_suppressed: 0,
            staged: Vec::new(),
            usage_feed: false,
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

    /// Whether an entry-observation feed (BPF usage events or a scripted
    /// harness) is attached. Without one, admitted edges report their
    /// entry columns as unknown — never zero-as-fact.
    pub(crate) fn set_usage_feed(&mut self, attached: bool) {
        self.usage_feed = attached;
    }

    pub(crate) fn usage_feed(&self) -> bool {
        self.usage_feed
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

    pub(crate) fn gaps(&self) -> &[RegistryGap] {
        &self.gaps
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

    /// Edges lacking semantic claims: withheld edges plus tracked
    /// edges whose feed established no mechanism/operation claim.
    pub(crate) fn semantic_unknown_edges(&self) -> usize {
        self.edges
            .values()
            .filter(|edge| {
                edge.semantics
                    .as_ref()
                    .is_none_or(|state| !state.has_claims())
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

    /// What the edge's entry columns mean, from admission plus feed
    /// state. A positive count always reads as observed.
    pub(crate) fn entry_observation(&self, edge: &EdgeRecord) -> EntryObservation {
        if edge.entry_count > 0 {
            return EntryObservation::Observed;
        }
        let admitted = self
            .modules
            .get(&edge.module)
            .is_some_and(|module| module.admission == AdmissionState::Admitted);
        if !admitted {
            EntryObservation::UnknownNotAdmitted
        } else if self.usage_feed {
            EntryObservation::Observed
        } else {
            EntryObservation::UnknownUnavailable
        }
    }

    /// Recency answers "active now" from entry last-seen, not from any
    /// sticky bit: true when an entry was observed within `window_ns` of
    /// `now_ns`, or an entry is in flight. Test-gated: unit tests pin
    /// the combined predicate; production splits it through
    /// [`Self::entry_recent_within`] plus the in-flight flag.
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

    /// Stage one pass-wide semantic capture-loss boundary: every live
    /// operation on every semantically-tracked edge ends unknown with
    /// explicit accounting, and the loss itself is a gap — never
    /// silent completion, never silent loss.
    #[allow(dead_code)] // Privileged semantic-feed seam; unit tests pin the semantics.
    pub(crate) fn note_capture_loss(&mut self, reason: String) {
        self.staged.push(Mutation::NoteSemanticLoss { reason });
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
        for mutation in staged {
            self.apply(mutation);
        }
        self.facts_revision = self.facts_revision.saturating_add(1);
        self.published_revision = self.facts_revision;
        applied
    }

    fn push_gap(&mut self, gap: RegistryGap) {
        if self.gaps.len() >= self.limits.max_gaps {
            self.gaps_suppressed = self.gaps_suppressed.saturating_add(1);
            return;
        }
        self.gaps.push(gap);
    }

    fn apply(&mut self, mutation: Mutation) {
        match mutation {
            Mutation::NoteMapping {
                caller,
                pid,
                info,
                at_ns,
            } => self.apply_mapping(caller, pid, info, at_ns),
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
                    .values_mut()
                    .filter(|edge| edge.caller == caller && edge.mapping == MappingState::Mapped)
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

    fn apply_mapping(&mut self, caller: CallerId, pid: u32, info: ModuleInfo, at_ns: u64) {
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
                // Admission is deterministic scan-only lowering: the first
                // verdict stands so records never flap between passes.
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
                        lifecycle: ModuleLifecycle::Mapped,
                        unloaded_observed: false,
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
                        mapping_first_seen_ns: at_ns,
                        mapping_last_seen_ns: at_ns,
                        mapping_interruptions: 0,
                        entry_count: 0,
                        entry_saturated: false,
                        entry_first_seen_ns: None,
                        entry_last_seen_ns: None,
                        entry_in_flight: false,
                        semantics: None,
                        double_loaded: false,
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

    /// Same-file double-load evidence (F7b): the mapping note's scan
    /// evidence shows this object loaded twice in the caller's
    /// process. The merged edge stands (one key, one module — the
    /// `dlopen` shape stays correct), but its semantics fail closed:
    /// live operations end unknown and the latch voids future claims
    /// until a later note shows one load again. The named gap fires
    /// on the false→true transition only, so a steady double-load
    /// never spams the gap retention.
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
            return;
        }
        if edge.double_loaded {
            return;
        }
        edge.double_loaded = true;
        if let Some(state) = edge.semantics.as_mut() {
            state.invalidate();
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
        for edge in self.edges.values_mut().filter(|edge| {
            edge.caller == caller
                && matches!(edge.mapping, MappingState::Mapped | MappingState::Uncertain)
        }) {
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
mod tests {
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
    struct ScriptedSource {
        state: Rc<RefCell<ScriptedState>>,
    }

    impl ScriptedSource {
        fn set(&self, pid: u32, process: ScriptedProcess) {
            self.state.borrow_mut().processes.insert(pid, process);
        }

        fn spawn(&self, pid: u32, start_time: u64) {
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

        fn blind(&self, pid: u32) {
            if let Some(process) = self.state.borrow_mut().processes.get_mut(&pid) {
                process.readable = false;
            }
        }

        fn kill(&self, pid: u32) {
            if let Some(process) = self.state.borrow_mut().processes.get_mut(&pid) {
                process.alive = false;
            }
        }

        fn exec(&self, pid: u32, ino: u64, path: &str) {
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
        registry.set_usage_feed(true);
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
        registry.set_usage_feed(true);
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
        registry.set_usage_feed(true);
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
        registry.set_usage_feed(true);
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
        registry.set_usage_feed(true);
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
        registry.set_usage_feed(true);
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
}
