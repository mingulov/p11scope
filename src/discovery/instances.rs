//! SPDX-License-Identifier: GPL-3.0-or-later
//! Task 3 Stage A: load-instance continuity and per-call instance routing.
//!
//! A provider file can be loaded more than once in one process (`dlmopen`)
//! and unloaded/reloaded at the same address; file identity (`ModuleKey`)
//! cannot tell those apart. The native witness (`crates/ebpf/native/
//! instance_epoch.c`) keeps a per-(process, watched file) mutation epoch, a
//! per-file global epoch and a capture fault generation; every call carries
//! entry and return stamps of those three values plus its private entry IP.
//!
//! This module is the pure userspace half:
//!
//! - [`stable_scan`] brackets one `/proc/PID/maps` read with two epoch reads
//!   and accepts it only when they agree (a *stable observation*).
//! - [`InstanceRouter`] mints capture-local [`InstanceId`]s per load partition
//!   of a stable observation and joins a call to exactly one of them only when
//!   both stamps equal that observation's epochs, the fault era is current,
//!   and the entry IP lies in exactly one executable partition range at the
//!   attached file offset. Every other case is an explicit
//!   [`UnknownReason`], never a guess.
//!
//! Continuity is the identity of the epoch triple: under unrelated mapping
//! churn the triple does not move, so the ID stays; any change of a watched
//! file's VMAs moves it, so an unload/reload at the same address always gets
//! a new ID. A range that *appears* at an unchanged triple is impossible
//! under hook completeness and latches a sticky coverage fault for that
//! (process, file).
//!
//! Privacy (proposed allowlist-v3): entry IPs and map ranges are private,
//! generation-local routing inputs. Their `Debug` output is redacted, they
//! have no `Serialize`/`Display`, and only [`InstanceId`]s and finite
//! [`UnknownReason`]s leave this module.

use p11scope_ebpf_common::{InstanceStamp, instance};
use p11scope_manifest::maps::MapEntry;
use std::collections::{BTreeMap, BTreeSet, VecDeque};
use std::fmt;

/// Capture-wide instance-record ceiling (allowlist-v3 bounds, DR-16).
pub(crate) const MAX_INSTANCES: usize = 4_096;
/// Capture-wide retained executable/partition range ceiling (DR-16).
pub(crate) const MAX_RANGES: usize = 16_384;
/// Calls waiting for a stable observation (allowlist-v3 pending joins).
pub(crate) const MAX_PENDING: usize = 1_024;
/// Retained epoch keys per (process, file): older keys are evicted and their
/// late calls become [`UnknownReason::Evicted`].
pub(crate) const KEYS_PER_PROCESS_FILE: usize = 4;
/// Capture-wide registry ceilings (allowlist-v3 bounds): retained
/// (process, file) observation keys, coverage-faulted keys and retired
/// process cookies. Each is bounded at the instance-record ceiling; a full
/// registry evicts its smallest key first (cookies mint in capture order,
/// so the stalest process goes first) with a saturating counter. Eviction
/// degrades late calls to Pending/Unobserved, never a join.
pub(crate) const MAX_OBSERVED_KEYS: usize = 4_096;
pub(crate) const MAX_FAULTED_KEYS: usize = 4_096;
pub(crate) const MAX_RETIRED_COOKIES: usize = 4_096;

/// The private probed runtime address of one call. Never rendered.
#[derive(Clone, Copy, PartialEq, Eq)]
pub(crate) struct EntryIp(u64);

impl EntryIp {
    pub(crate) const fn new(raw: u64) -> Self {
        Self(raw)
    }
}

impl fmt::Debug for EntryIp {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("EntryIp(<private>)")
    }
}

/// One mapping range of a watched file in one process. Private addresses.
#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub(crate) struct MapRange {
    start: u64,
    end: u64,
    file_offset: u64,
    executable: bool,
}

impl MapRange {
    pub(crate) const fn new(start: u64, end: u64, file_offset: u64, executable: bool) -> Self {
        Self {
            start,
            end,
            file_offset,
            executable,
        }
    }

    fn contains(&self, ip: u64) -> bool {
        self.start <= ip && ip < self.end
    }
}

impl fmt::Debug for MapRange {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            formatter,
            "MapRange(<private>, executable={})",
            self.executable
        )
    }
}

/// The ranges of one file (by its maps-visible `dev:ino`) in a parsed snapshot.
pub(crate) fn ranges_for(
    entries: &[MapEntry],
    major: u64,
    minor: u64,
    inode: u64,
) -> Vec<MapRange> {
    let mut ranges: Vec<MapRange> = entries
        .iter()
        .filter(|entry| {
            entry.inode == inode
                && entry.inode != 0
                && entry.device.major == major
                && entry.device.minor == minor
        })
        .map(|entry| {
            MapRange::new(
                entry.start,
                entry.end,
                entry.file_offset,
                entry.permissions[2] == b'x',
            )
        })
        .collect();
    ranges.sort();
    ranges
}

/// The physical identity of one mapped file as `stat()` through its
/// `/proc/<pid>/map_files/<start>-<end>` link reports it. The maps key
/// (`i_sb->s_dev`, `i_ino`) is NOT unique: on btrfs inode numbers are unique
/// only per subvolume, and overlay without xino shares inode numbers across
/// layers. The map_files link resolves the VMA's own file, so this compares
/// like for like with the calibration mapping of the pinned fd.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct MappedFileIdentity {
    pub(crate) dev: u64,
    pub(crate) ino: u64,
}

/// Keeps exactly the candidate ranges (selected by the non-unique maps key)
/// whose mapped file is the watched one. A colliding file's ranges are
/// dropped; any range whose identity cannot be read refuses the whole scan
/// (it may have changed under the read), never a silent keep.
pub(crate) fn confirm_identity(
    ranges: Vec<MapRange>,
    watched: MappedFileIdentity,
    mut stat: impl FnMut(u64, u64) -> Result<MappedFileIdentity, String>,
) -> Result<Vec<MapRange>, String> {
    let mut kept = Vec::with_capacity(ranges.len());
    for range in ranges {
        if stat(range.start, range.end)? == watched {
            kept.push(range);
        }
    }
    Ok(kept)
}

/// A capture-local load-instance identity. Public-safe: monotonic, never a
/// raw address, epoch or digest, never reused.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub(crate) struct InstanceId(u64);

impl InstanceId {
    pub(crate) const fn get(self) -> u64 {
        self.0
    }
}

/// One bracketed epoch reading for (process, watched file). Private epoch
/// keys: `Debug` is redacted.
#[derive(Clone, Copy, PartialEq, Eq, Default)]
pub(crate) struct EpochReading {
    /// The process's image cookie read through its pidfd (proves the maps
    /// read named the same process; zero means none was assigned).
    pub(crate) cookie: u64,
    /// The process record's local epoch for this file (0 if absent).
    pub(crate) local: u64,
    /// The process record's flags (`instance::RECORD_*`).
    pub(crate) record_flags: u64,
    /// `G_EPOCH[file]`.
    pub(crate) global: u64,
    /// `INSTANCE_GEN[FAULT]`.
    pub(crate) fault: u64,
    /// `INSTANCE_GEN[STICKY]`.
    pub(crate) sticky: u64,
}

impl fmt::Debug for EpochReading {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("EpochReading(<private>)")
    }
}

/// What one scan needs: epochs (record through a pidfd, global and fault
/// cells) and the watched file's ranges from `/proc/PID/maps`.
pub(crate) trait ScanReader {
    fn epochs(&mut self) -> Result<EpochReading, String>;
    fn ranges(&mut self) -> Result<Vec<MapRange>, String>;
}

/// A maps read bracketed by two equal epoch readings.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct StableObservation {
    pub(crate) file_slot: u32,
    pub(crate) reading: EpochReading,
    pub(crate) ranges: Vec<MapRange>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) enum ScanRefusal {
    /// Every attempt saw an epoch move during the maps read.
    Unstable,
    /// The process has no image cookie (no identified call yet).
    NoCookie,
    Read(String),
}

/// The scan-validation protocol: epochs, maps, epochs again; accept only
/// equal brackets, retrying at most `tries` times.
pub(crate) fn stable_scan(
    reader: &mut impl ScanReader,
    file_slot: u32,
    tries: u32,
) -> Result<StableObservation, ScanRefusal> {
    for _ in 0..tries {
        let before = reader.epochs().map_err(ScanRefusal::Read)?;
        if before.cookie == 0 {
            return Err(ScanRefusal::NoCookie);
        }
        let mut ranges = reader.ranges().map_err(ScanRefusal::Read)?;
        let after = reader.epochs().map_err(ScanRefusal::Read)?;
        if before == after {
            ranges.sort();
            ranges.dedup();
            return Ok(StableObservation {
                file_slot,
                reading: before,
                ranges,
            });
        }
    }
    Err(ScanRefusal::Unstable)
}

/// The facts one completed call contributes to routing.
#[derive(Clone, Copy)]
pub(crate) struct CallFacts {
    /// Opaque caller token returned with a deferred resolution.
    pub(crate) token: u64,
    /// The call's image cookie (entry identity).
    pub(crate) cookie: u64,
    pub(crate) entry: InstanceStamp,
    pub(crate) ret: InstanceStamp,
    pub(crate) ip: EntryIp,
    /// The attached endpoint's file offset, when known: the IP must map to
    /// exactly this offset in its range.
    pub(crate) attached_offset: Option<u64>,
}

impl fmt::Debug for CallFacts {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("CallFacts")
            .field("token", &self.token)
            .finish_non_exhaustive()
    }
}

/// Why a call has no instance. Finite and public-safe.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub(crate) enum UnknownReason {
    /// The call carries no valid stamp (not stamped, or no task).
    Unstamped,
    /// The endpoint has no watched file (calibration refused or tracking off).
    NoFile,
    /// The caller shares its mm with another process (CLONE_VM non-thread).
    SharedMm,
    /// The caller's record could not localize a watched file.
    Overflow,
    /// A local fault was recorded for the caller.
    LocalFault,
    /// Entry and return stamps differ: the call straddled a mutation.
    Straddle,
    /// The fault generation moved after the stamp was taken.
    FaultEra,
    /// A capture-wide sticky refusal is set.
    Sticky,
    /// The (process, file) latched a coverage self-check fault.
    CoverageFault,
    /// The stamp's epochs were never stably observed and never can be.
    Unobserved,
    /// The stamp's observation was evicted by newer epochs.
    Evicted,
    /// The IP lies in no range of the observation.
    IpOutside,
    /// The containing range is not executable.
    NotExecutable,
    /// The IP does not map to the attached file offset.
    OffsetMismatch,
    /// The containing range precedes every load base.
    Unpartitionable,
    /// The instance-record ceiling refused this partition.
    InstanceCapacity,
    /// The range ceiling refused this observation.
    RangeCapacity,
    /// The pending-join ceiling refused this call.
    PendingCapacity,
    /// The process was retired before the call could join.
    Retired,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum Route {
    Joined(InstanceId),
    /// Waiting for a stable observation of the stamp's epochs.
    Pending,
    Unknown(UnknownReason),
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct RouterLimits {
    pub(crate) instances: usize,
    pub(crate) ranges: usize,
    pub(crate) pending: usize,
    pub(crate) observed_keys: usize,
    pub(crate) faulted_keys: usize,
    pub(crate) retired_cookies: usize,
}

impl Default for RouterLimits {
    fn default() -> Self {
        Self {
            instances: MAX_INSTANCES,
            ranges: MAX_RANGES,
            pending: MAX_PENDING,
            observed_keys: MAX_OBSERVED_KEYS,
            faulted_keys: MAX_FAULTED_KEYS,
            retired_cookies: MAX_RETIRED_COOKIES,
        }
    }
}

/// Outcome of one [`InstanceRouter::observe`].
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) enum ObserveOutcome {
    /// First stable observation of these epochs: partitions were minted.
    New,
    /// Same epochs and no new range: the same instances continue.
    Continued,
    /// A range appeared at unchanged epochs: sticky coverage fault.
    CoverageFault,
    /// The observation's fault era is not the router's current era.
    StaleEra,
    /// The process cookie is retired.
    Retired,
    /// The range ceiling refused the observation.
    RangeCapacity,
}

#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
struct EpochKey {
    local: u64,
    global: u64,
    fault: u64,
}

impl fmt::Debug for EpochKey {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("EpochKey(<private>)")
    }
}

impl EpochKey {
    fn of(reading: &EpochReading) -> Self {
        Self {
            local: reading.local,
            global: reading.global,
            fault: reading.fault,
        }
    }

    /// Low-32 matching (N4): stamps carry only the low words, so identity
    /// assumes fewer than 2^32 bumps per (process, file, global, fault)
    /// component per capture — 4 billion file-VMA events against one
    /// watched file. A stamp from exactly 2^32 bumps ago would match; that
    /// rate sustained against one file is outside the capture envelope, and
    /// the assumption is pinned by review, not by a counter.
    fn matches(&self, stamp: &InstanceStamp) -> bool {
        self.local as u32 == stamp.epoch
            && self.global as u32 == stamp.global
            && self.fault as u32 == stamp.fault
    }

    /// Whether `stamp` names epochs strictly older than these in some
    /// component (epochs only grow, so no later scan can observe it). The
    /// 2^31 wrapping window reads stamps more than 2^31 behind as "future":
    /// they wait as [`Route::Pending`] and expire [`UnknownReason::Unobserved`],
    /// never evicted or joined — fail closed on the far past.
    fn supersedes(&self, stamp: &InstanceStamp) -> bool {
        let older = |current: u64, stamped: u32| (current as u32).wrapping_sub(stamped) as i32 > 0;
        older(self.local, stamp.epoch)
            || older(self.global, stamp.global)
            || older(self.fault, stamp.fault)
    }
}

/// Partitions of one stable observation, keyed by load base.
#[derive(Clone, Debug)]
struct Observed {
    epochs: EpochKey,
    ranges: Vec<MapRange>,
    /// Load bases (offset-0 range starts, private) with minted IDs, ascending.
    partitions: Vec<(Base, Option<InstanceId>)>,
}

/// A private load-base address.
#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
struct Base(u64);

impl fmt::Debug for Base {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("Base(<private>)")
    }
}

#[derive(Clone, Debug)]
struct PendingCall {
    facts: CallFacts,
}

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub(crate) struct RouterCounters {
    pub(crate) joined: u64,
    pub(crate) observations: u64,
    pub(crate) continued: u64,
    pub(crate) coverage_faults: u64,
    pub(crate) eras: u64,
    /// Era advances latched by a hook-program miss the capture loop had not
    /// yet covered with a fault raise (a subset of `eras`).
    pub(crate) miss_eras: u64,
    /// Saturating registry evictions (F3): keys dropped from a full
    /// registry, whose late calls degrade to Pending/Unobserved.
    pub(crate) observed_evictions: u64,
    pub(crate) faulted_evictions: u64,
    pub(crate) retired_evictions: u64,
}

/// Capture-owned instance registry and per-call router. `Debug` is redacted
/// (N5): image cookies key the registries, and the fault generation is a
/// private epoch, so only lengths, limits, finite flags and public-safe
/// counters render.
pub(crate) struct InstanceRouter {
    limits: RouterLimits,
    /// (cookie, file slot) -> retained observations, oldest first.
    observed: BTreeMap<(u64, u32), VecDeque<Observed>>,
    faulted: BTreeSet<(u64, u32)>,
    retired: BTreeSet<u64>,
    pending: VecDeque<PendingCall>,
    fault: u64,
    sticky: u64,
    /// Last audited hook-program `recursion_misses` total. Any change the
    /// capture loop has not covered with a fault raise latches `miss_latched`.
    misses: u64,
    /// A miss arrived without a fault raise: no joins and no observations
    /// until the fault generation moves. Clearing alone would be unsound — a
    /// skipped relevant bump leaves stale epochs under changed ranges, which
    /// a fresh scan would accept as a new incarnation — so the latch holds
    /// until a kernel fault raise re-coheres the era.
    miss_latched: bool,
    next_id: u64,
    minted: usize,
    ranges: usize,
    unknown: BTreeMap<UnknownReason, u64>,
    counters: RouterCounters,
}

impl fmt::Debug for InstanceRouter {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("InstanceRouter")
            .field("limits", &self.limits)
            .field("observed_keys", &self.observed.len())
            .field("faulted_keys", &self.faulted.len())
            .field("retired_cookies", &self.retired.len())
            .field("pending", &self.pending.len())
            .field("sticky", &self.sticky)
            .field("misses", &self.misses)
            .field("miss_latched", &self.miss_latched)
            .field("minted", &self.minted)
            .field("ranges", &self.ranges)
            .field("unknown", &self.unknown)
            .field("counters", &self.counters)
            .finish_non_exhaustive()
    }
}

impl InstanceRouter {
    pub(crate) fn new(limits: RouterLimits) -> Self {
        Self {
            limits,
            observed: BTreeMap::new(),
            faulted: BTreeSet::new(),
            retired: BTreeSet::new(),
            pending: VecDeque::new(),
            fault: 0,
            sticky: 0,
            misses: 0,
            miss_latched: false,
            next_id: 1,
            minted: 0,
            ranges: 0,
            unknown: BTreeMap::new(),
            counters: RouterCounters::default(),
        }
    }

    pub(crate) fn instances_minted(&self) -> usize {
        self.minted
    }

    pub(crate) fn ranges_retained(&self) -> usize {
        self.ranges
    }

    pub(crate) fn pending_len(&self) -> usize {
        self.pending.len()
    }

    pub(crate) fn counters(&self) -> RouterCounters {
        self.counters
    }

    pub(crate) fn unknown_counts(&self) -> &BTreeMap<UnknownReason, u64> {
        &self.unknown
    }

    /// Batch audit, before routing a drained batch: the current fault
    /// generation (which the capture loop also raises on hook-program
    /// misses), the sticky bits, and the hook programs' summed
    /// `recursion_misses`. A changed fault ends every retained observation
    /// and every pending call, and releases the miss latch. A changed miss
    /// total WITHOUT a changed fault means the loop has not raised for those
    /// misses: the era latches (no joins, no observations) until a fault
    /// raise re-coheres it. Any miss change latches, including a decrease
    /// (a reloaded hook set starts its counters over). Returns the resolved
    /// pending calls.
    pub(crate) fn audit(&mut self, fault: u64, sticky: u64, misses: u64) -> Vec<(u64, Route)> {
        let mut resolved = Vec::new();
        if sticky != 0 && self.sticky == 0 {
            self.sticky = sticky;
            resolved.extend(self.fail_pending(|_| true, UnknownReason::Sticky));
        }
        self.sticky |= sticky;
        let fault_moved = fault != self.fault;
        let misses_moved = misses != self.misses;
        self.misses = misses;
        if fault_moved {
            self.fault = fault;
            self.miss_latched = false;
            self.counters.eras += 1;
            self.observed.clear();
            self.ranges = 0;
            resolved.extend(self.fail_pending(|_| true, UnknownReason::FaultEra));
        } else if misses_moved {
            self.miss_latched = true;
            self.counters.eras += 1;
            self.counters.miss_eras += 1;
            self.observed.clear();
            self.ranges = 0;
            resolved.extend(self.fail_pending(|_| true, UnknownReason::FaultEra));
        }
        resolved
    }

    /// Ends a process incarnation (exit or exec reported by lifecycle):
    /// frees its observations; its pending calls become unknown.
    pub(crate) fn retire_process(&mut self, cookie: u64) -> Vec<(u64, Route)> {
        evict_for_insert(
            &mut self.retired,
            &cookie,
            self.limits.retired_cookies,
            &mut self.counters.retired_evictions,
        );
        self.retired.insert(cookie);
        let keys: Vec<_> = self
            .observed
            .keys()
            .filter(|(owner, _)| *owner == cookie)
            .copied()
            .collect();
        for key in keys {
            if let Some(list) = self.observed.remove(&key) {
                self.ranges -= list.iter().map(|o| o.ranges.len()).sum::<usize>();
            }
        }
        self.fail_pending(|call| call.facts.cookie == cookie, UnknownReason::Retired)
    }

    /// Records one stable observation and resolves pending calls that it
    /// decides. Same epochs + no new range = continuity.
    pub(crate) fn observe(
        &mut self,
        observation: StableObservation,
    ) -> (ObserveOutcome, Vec<(u64, Route)>) {
        let cookie = observation.reading.cookie;
        let file = observation.file_slot;
        if self.retired.contains(&cookie) {
            return (ObserveOutcome::Retired, Vec::new());
        }
        if observation.reading.fault != self.fault || self.miss_latched {
            return (ObserveOutcome::StaleEra, Vec::new());
        }
        if observation.reading.sticky != 0 {
            let resolved = self.audit(self.fault, observation.reading.sticky, self.misses);
            return (ObserveOutcome::StaleEra, resolved);
        }
        self.counters.observations += 1;
        let epochs = EpochKey::of(&observation.reading);
        let key = (cookie, file);
        if self.faulted.contains(&key) {
            return (ObserveOutcome::CoverageFault, Vec::new());
        }
        let existing = self
            .observed
            .get(&key)
            .and_then(|list| list.iter().find(|o| o.epochs == epochs))
            .map(|o| o.ranges.clone());
        let outcome = match existing {
            Some(ranges) => {
                // Ranges may only disappear at unchanged epochs (teardown at
                // exec/exit is not bumped); one that appears is a hook gap.
                let appeared = observation
                    .ranges
                    .iter()
                    .any(|range| ranges.binary_search(range).is_err());
                if appeared {
                    self.counters.coverage_faults += 1;
                    evict_for_insert(
                        &mut self.faulted,
                        &key,
                        self.limits.faulted_keys,
                        &mut self.counters.faulted_evictions,
                    );
                    self.faulted.insert(key);
                    if let Some(list) = self.observed.remove(&key) {
                        self.ranges -= list.iter().map(|o| o.ranges.len()).sum::<usize>();
                    }
                    let resolved = self.fail_pending(
                        |call| call.facts.cookie == cookie && stamp_file(&call.facts) == Some(file),
                        UnknownReason::CoverageFault,
                    );
                    return (ObserveOutcome::CoverageFault, resolved);
                }
                self.counters.continued += 1;
                ObserveOutcome::Continued
            }
            None => {
                if self.ranges + observation.ranges.len() > self.limits.ranges {
                    let resolved = self.fail_pending(
                        |call| {
                            call.facts.cookie == cookie
                                && stamp_file(&call.facts) == Some(file)
                                && epochs.matches(&call.facts.entry)
                        },
                        UnknownReason::RangeCapacity,
                    );
                    return (ObserveOutcome::RangeCapacity, resolved);
                }
                let partitions = observation
                    .ranges
                    .iter()
                    .filter(|range| range.file_offset == 0)
                    .map(|range| (Base(range.start), self.mint()))
                    .collect();
                self.ranges += observation.ranges.len();
                while self.observed.len() >= self.limits.observed_keys
                    && !self.observed.contains_key(&key)
                {
                    let Some((_, evicted)) = self.observed.pop_first() else {
                        break;
                    };
                    self.ranges -= evicted.iter().map(|o| o.ranges.len()).sum::<usize>();
                    self.counters.observed_evictions =
                        self.counters.observed_evictions.saturating_add(1);
                }
                let list = self.observed.entry(key).or_default();
                list.push_back(Observed {
                    epochs,
                    ranges: observation.ranges,
                    partitions,
                });
                while list.len() > KEYS_PER_PROCESS_FILE {
                    if let Some(old) = list.pop_front() {
                        self.ranges -= old.ranges.len();
                    }
                }
                ObserveOutcome::New
            }
        };
        let resolved = self.resolve_pending(cookie, file);
        (outcome, resolved)
    }

    /// Routes one completed call: joined, pending (a scan is needed), or a
    /// finite unknown reason.
    pub(crate) fn route(&mut self, facts: CallFacts) -> Route {
        let route = self.decide(&facts, true);
        match route {
            Route::Pending => {
                if self.pending.len() >= self.limits.pending {
                    return self.unknown(UnknownReason::PendingCapacity);
                }
                self.pending.push_back(PendingCall { facts });
                Route::Pending
            }
            Route::Joined(_) => {
                self.counters.joined += 1;
                route
            }
            Route::Unknown(reason) => self.unknown(reason),
        }
    }

    /// Reason precedence (N2): first match wins, in this order —
    /// 1. capture-sticky refusal; 2. the ENTRY stamp's refusal flags
    ///    (`Unstamped` covers `NO_TASK`, which also means "never stamped");
    /// 3. entry/return inequality (`Straddle` — a refusal flag on the RETURN
    ///    stamp only therefore surfaces as `Straddle`, never as its flag);
    /// 4. the ambient era (stale fault generation or the latched miss era);
    /// 5. process state (`Retired`, then the sticky `CoverageFault`);
    /// 6. epoch knowledge (`Pending` while a newer-or-equal epoch may still
    ///    be observed — including evicted epochs, which resolve only when a
    ///    later observation arrives (no fail-on-evict) — else `Unobserved`
    ///    or `Evicted`); 7. the IP checks (`IpOutside`, `NotExecutable`,
    ///    `OffsetMismatch`, `Unpartitionable`, `InstanceCapacity`).
    ///
    /// Per-call facts beat ambient state; ambient state beats process state.
    /// (`observe` has its own gate order: `Retired`, stale era (fault or
    /// miss latch), then a sticky reading, which audits the sticky bits and
    /// reports `StaleEra`. Calls refused by `RangeCapacity` pend and expire
    /// as `Unobserved`.)
    fn decide(&self, facts: &CallFacts, may_wait: bool) -> Route {
        use UnknownReason as U;
        let entry = facts.entry;
        if self.sticky != 0 {
            return Route::Unknown(U::Sticky);
        }
        if entry.flags & instance::STAMP_VALID == 0 || entry.flags & instance::STAMP_NO_TASK != 0 {
            return Route::Unknown(U::Unstamped);
        }
        if entry.flags & instance::STAMP_NO_FILE != 0 || entry.file_slot_plus1 == 0 {
            return Route::Unknown(U::NoFile);
        }
        if entry.flags & instance::STAMP_SHARED_MM != 0 {
            return Route::Unknown(U::SharedMm);
        }
        if entry.flags & instance::STAMP_OVERFLOW != 0 {
            return Route::Unknown(U::Overflow);
        }
        if entry.flags & instance::STAMP_LOCAL_FAULT != 0 {
            return Route::Unknown(U::LocalFault);
        }
        if !instance::stamp_joinable(entry, facts.ret) {
            return Route::Unknown(U::Straddle);
        }
        // The miss latch is consulted here, not plumbed per call: stamps
        // carry no miss count, so a miss increase between the call's entry
        // and its routing can only surface as a latched era at audit time.
        if entry.fault != self.fault as u32 || self.miss_latched {
            return Route::Unknown(U::FaultEra);
        }
        if self.retired.contains(&facts.cookie) {
            return Route::Unknown(U::Retired);
        }
        let file = u32::from(entry.file_slot_plus1) - 1;
        let key = (facts.cookie, file);
        if self.faulted.contains(&key) {
            return Route::Unknown(U::CoverageFault);
        }
        let Some(list) = self.observed.get(&key) else {
            return if may_wait {
                Route::Pending
            } else {
                Route::Unknown(U::Unobserved)
            };
        };
        if let Some(observed) = list.iter().find(|o| o.epochs.matches(&entry)) {
            return route_ip(observed, facts);
        }
        let newest = list.back().expect("retained lists are never empty");
        let oldest = list.front().expect("retained lists are never empty");
        if newest.epochs.supersedes(&entry) {
            // Older than the newest observation and not retained: either it
            // was evicted, or it was never stable while current.
            if oldest.epochs.supersedes(&entry) && list.len() == KEYS_PER_PROCESS_FILE {
                return Route::Unknown(U::Evicted);
            }
            return Route::Unknown(U::Unobserved);
        }
        if may_wait {
            Route::Pending
        } else {
            Route::Unknown(U::Unobserved)
        }
    }

    fn resolve_pending(&mut self, cookie: u64, file: u32) -> Vec<(u64, Route)> {
        let mut resolved = Vec::new();
        let mut kept = VecDeque::with_capacity(self.pending.len());
        let pending = std::mem::take(&mut self.pending);
        for call in pending {
            if call.facts.cookie != cookie || stamp_file(&call.facts) != Some(file) {
                kept.push_back(call);
                continue;
            }
            match self.decide(&call.facts, true) {
                Route::Pending => kept.push_back(call),
                Route::Joined(id) => {
                    self.counters.joined += 1;
                    resolved.push((call.facts.token, Route::Joined(id)));
                }
                Route::Unknown(reason) => {
                    self.note_unknown_n(reason, 1);
                    resolved.push((call.facts.token, Route::Unknown(reason)));
                }
            }
        }
        self.pending = kept;
        resolved
    }

    /// Ends every pending call that a scan could not decide (for example the
    /// process exited before any stable scan): returns them as unknown.
    pub(crate) fn expire_pending(&mut self, cookie: u64) -> Vec<(u64, Route)> {
        self.fail_pending(
            |call| call.facts.cookie == cookie,
            UnknownReason::Unobserved,
        )
    }

    fn fail_pending(
        &mut self,
        matches: impl Fn(&PendingCall) -> bool,
        reason: UnknownReason,
    ) -> Vec<(u64, Route)> {
        let mut resolved = Vec::new();
        let pending = std::mem::take(&mut self.pending);
        for call in pending {
            if matches(&call) {
                self.note_unknown_n(reason, 1);
                resolved.push((call.facts.token, Route::Unknown(reason)));
            } else {
                self.pending.push_back(call);
            }
        }
        resolved
    }

    fn mint(&mut self) -> Option<InstanceId> {
        if self.minted >= self.limits.instances {
            return None;
        }
        let id = InstanceId(self.next_id);
        self.next_id = self.next_id.checked_add(1)?;
        self.minted += 1;
        Some(id)
    }

    fn unknown(&mut self, reason: UnknownReason) -> Route {
        self.note_unknown_n(reason, 1);
        Route::Unknown(reason)
    }

    fn note_unknown_n(&mut self, reason: UnknownReason, count: u64) {
        // A zero count must not mint an entry (N4): the map holds observed
        // reasons only.
        if count == 0 {
            return;
        }
        let cell = self.unknown.entry(reason).or_default();
        *cell = cell.saturating_add(count);
    }
}

fn stamp_file(facts: &CallFacts) -> Option<u32> {
    u32::from(facts.entry.file_slot_plus1).checked_sub(1)
}

/// Makes room for `key` in a bounded key set: evicts the smallest key first
/// with a saturating counter. A key already present needs no room.
fn evict_for_insert<K: Ord>(set: &mut BTreeSet<K>, key: &K, limit: usize, evictions: &mut u64) {
    while set.len() >= limit && !set.contains(key) {
        if set.pop_first().is_none() {
            break;
        }
        *evictions = evictions.saturating_add(1);
    }
}

fn route_ip(observed: &Observed, facts: &CallFacts) -> Route {
    use UnknownReason as U;
    let ip = facts.ip.0;
    let Some(range) = observed.ranges.iter().find(|range| range.contains(ip)) else {
        return Route::Unknown(U::IpOutside);
    };
    if !range.executable {
        return Route::Unknown(U::NotExecutable);
    }
    // An unknown attached offset cannot be matched: fail closed. The
    // addition is checked: a wrapped offset must refuse, never join (N4).
    let mapped = ip
        .checked_sub(range.start)
        .and_then(|delta| delta.checked_add(range.file_offset));
    let Some(mapped) = mapped else {
        return Route::Unknown(U::OffsetMismatch);
    };
    if facts.attached_offset != Some(mapped) {
        return Route::Unknown(U::OffsetMismatch);
    }
    match observed
        .partitions
        .iter()
        .rev()
        .find(|(base, _)| base.0 <= range.start)
    {
        None => Route::Unknown(U::Unpartitionable),
        Some((_, None)) => Route::Unknown(U::InstanceCapacity),
        Some((_, Some(id))) => Route::Joined(*id),
    }
}

#[cfg(test)]
#[path = "instances_tests.rs"]
mod tests;
