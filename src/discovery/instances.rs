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

use crate::attach::capture::NativeDomainId;
use crate::attach::image_query::{CompleteEpochs, ImageScanProof};
use p11scope_ebpf_common::{ImageIdentity, InstanceStamp, instance};
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
/// Capture-wide exact-registry ceilings. Observed eviction degrades late
/// calls; a coverage tombstone eviction latches unknown-key refusal. Retired
/// image eviction compresses permanent per-cookie refusals into132KiB bounded
/// negative metadata. Ordinary era changes clear positive observations and
/// advance a checked original-scan fence, never resetting negative metadata.
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
#[cfg(test)]
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
    /// The router's publication fence as read before the scan started
    /// (as sealed by the full-image scan). A fault-era advance bumps the router's
    /// fence, so a scan cached across the reset observes as `StaleEra`
    /// even when its fault reading already matches the new era.
    pub(crate) fence: u64,
}

#[cfg(test)]
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
///
/// `fence` is the router's current publication fence, read BEFORE the scan
/// starts, and is stamped onto the observation unchanged. The capture loop
/// audits only in its pump, so no reset can interleave a scan; a scan whose
/// observation is cached past a later fault-era advance then observes as
/// `StaleEra` (see [`InstanceRouter::observe`]). Stamping at observe time
/// instead would revalidate stale scans and defeat the fence.
#[cfg(test)]
pub(crate) fn stable_scan(
    reader: &mut impl ScanReader,
    file_slot: u32,
    tries: u32,
    fence: u64,
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
                fence,
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
    pub(crate) domain: NativeDomainId,
    /// The call's complete native entry identity.
    pub(crate) image: ImageIdentity,
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
    ForeignDomain,
    AuthorityExhausted,
    InvalidImage,
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
    /// A new cookie association exceeded retained original-pidfd capacity.
    BindingCapacity,
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
    ForeignDomain,
    InvalidImage,
    /// First stable observation of these epochs: partitions were minted.
    New,
    /// Same epochs and no new range: the same instances continue.
    Continued,
    /// A range appeared at unchanged epochs: sticky coverage fault.
    CoverageFault,
    /// The observation's fault era is not the router's current era, or
    /// the scan was acquired before the current publication fence.
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

#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
struct ImageKey {
    cookie: u64,
    exec: u64,
}

impl From<ImageIdentity> for ImageKey {
    fn from(image: ImageIdentity) -> Self {
        Self {
            cookie: image.task_cookie,
            exec: image.exec_id,
        }
    }
}

impl fmt::Debug for ImageKey {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("ImageKey(<private>)")
    }
}

const COOKIE_LIMIT: usize = p11scope_ebpf_common::IMAGE_IDENTITY_TICKET_LIMIT as usize;

/// Permanent negative metadata, bounded by the owning native domain's lifetime
/// tickets: 128 KiB exec watermarks plus two 2 KiB bitsets. Exec0 is valid.
struct RetirementLedger {
    through: Box<[u64]>,
    valid: Box<[u64]>,
    dead: Box<[u64]>,
}

impl RetirementLedger {
    fn new() -> Self {
        Self {
            through: vec![0; COOKIE_LIMIT].into_boxed_slice(),
            valid: vec![0; COOKIE_LIMIT / 64].into_boxed_slice(),
            dead: vec![0; COOKIE_LIMIT / 64].into_boxed_slice(),
        }
    }

    fn index(cookie: u64) -> Option<usize> {
        if cookie == 0 || cookie > p11scope_ebpf_common::IMAGE_IDENTITY_TICKET_LIMIT {
            None
        } else {
            Some(cookie as usize - 1)
        }
    }

    fn retire_image(&mut self, image: ImageKey) {
        if let Some(index) = Self::index(image.cookie) {
            self.through[index] = self.through[index].max(image.exec);
            self.valid[index / 64] |= 1 << (index % 64);
        }
    }

    fn retire_task(&mut self, cookie: u64) {
        if let Some(index) = Self::index(cookie) {
            self.dead[index / 64] |= 1 << (index % 64);
        }
    }

    fn retired(&self, image: ImageKey) -> bool {
        let Some(index) = Self::index(image.cookie) else {
            return true;
        };
        let bit = 1 << (index % 64);
        self.dead[index / 64] & bit != 0
            || self.valid[index / 64] & bit != 0 && image.exec <= self.through[index]
    }
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

    /// Full observed values are validated against the stamp representation
    /// before retention. Equality cannot truncate an unrepresentable value.
    fn matches(&self, stamp: &InstanceStamp) -> bool {
        self.local == u64::from(stamp.epoch)
            && self.global == u64::from(stamp.global)
            && self.fault == u64::from(stamp.fault)
    }

    /// Complete retained epochs are monotonic and representable; an older
    /// stamp can no longer gain an observation in this image and fault era.
    fn supersedes(&self, stamp: &InstanceStamp) -> bool {
        self.local > u64::from(stamp.epoch)
            || self.global > u64::from(stamp.global)
            || self.fault > u64::from(stamp.fault)
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
    /// registry. Observed late calls degrade to Pending/Unobserved; a
    /// faulted eviction latches refusal; a retired eviction compacts its
    /// negative identity into the permanent per-cookie ledger.
    pub(crate) observed_evictions: u64,
    pub(crate) faulted_evictions: u64,
    pub(crate) retired_evictions: u64,
}

/// Capture-owned instance registry and per-call router. `Debug` is redacted
/// (N5): image cookies key the registries, and the fault generation is a
/// private epoch, so only lengths, limits, finite flags and public-safe
/// counters render.
pub(crate) struct InstanceRouter {
    domain: NativeDomainId,
    limits: RouterLimits,
    /// (full image, file slot) -> retained observations, oldest first.
    observed: BTreeMap<(ImageKey, u32), VecDeque<Observed>>,
    faulted: BTreeSet<(ImageKey, u32)>,
    /// P2-1: a coverage-fault tombstone was evicted under capacity pressure.
    /// The router can no longer name the discredited key, so every unknown
    /// key (no retained observation) is refused with `CoverageFault` — fail
    /// closed. Capture-sticky: set once, never cleared (a fault-era advance
    /// clears observations, not the fault registry). Retained keys keep
    /// continuity; only unknown keys pay the availability cost — until a
    /// fault-era change clears all observations, after which every key is
    /// unknown and every observation and route is refused until the router
    /// is recreated. That total refusal is conservative and sound (the
    /// forgotten tombstones could be any of the cleared keys), and it is
    /// the documented price of bounding the fault registry.
    faulted_overflowed: bool,
    retired: BTreeSet<ImageKey>,
    /// Evicted image refusals and terminal task death remain permanent in
    /// this native domain. Ordinary fault eras never clear this ledger.
    retirement: RetirementLedger,
    authority_failed: bool,
    image_failed: bool,
    /// Original publication fence; checked advance or permanent refusal.
    fence: u64,
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
    /// Exact current partitions lost at the actual observation eviction.
    /// Nonempty entries contain unique minted IDs, so the lifetime bound is
    /// MAX_INSTANCES even when an adapter has not drained them yet.
    observation_losses: Vec<ObservationLoss>,
}

pub(crate) struct ObservationLoss {
    pub(crate) image: ImageIdentity,
    pub(crate) file_slot: u32,
    pub(crate) ids: Vec<InstanceId>,
}

impl fmt::Debug for InstanceRouter {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("InstanceRouter")
            .field("limits", &self.limits)
            .field("observed_keys", &self.observed.len())
            .field("faulted_keys", &self.faulted.len())
            .field("faulted_overflowed", &self.faulted_overflowed)
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
    pub(crate) fn new(domain: NativeDomainId, limits: RouterLimits) -> Self {
        Self {
            domain,
            limits,
            observed: BTreeMap::new(),
            faulted: BTreeSet::new(),
            faulted_overflowed: false,
            retired: BTreeSet::new(),
            retirement: RetirementLedger::new(),
            authority_failed: false,
            image_failed: false,
            fence: 0,
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
            observation_losses: Vec::new(),
        }
    }

    pub(crate) fn instances_minted(&self) -> usize {
        self.minted
    }

    pub(crate) fn domain(&self) -> NativeDomainId {
        self.domain
    }

    pub(crate) fn ranges_retained(&self) -> usize {
        self.ranges
    }

    pub(crate) fn pending_len(&self) -> usize {
        self.pending.len()
    }

    /// Current partition IDs only, for the owning adapter's exact prior-ID
    /// retirement output. Older observations remain valid historical joins.
    pub(crate) fn current_instances(
        &self,
        domain: NativeDomainId,
        image: ImageIdentity,
        file: u32,
    ) -> Vec<InstanceId> {
        if domain != self.domain {
            return Vec::new();
        }
        self.observed
            .get(&(image.into(), file))
            .and_then(|list| list.back())
            .map(|observation| {
                observation
                    .partitions
                    .iter()
                    .filter_map(|(_, id)| *id)
                    .collect()
            })
            .unwrap_or_default()
    }

    /// Registration needs the newest exact accepted observation. Historical
    /// epoch keys remain usable for call history, never for this authority.
    pub(crate) fn current_partition_matches(
        &self,
        domain: NativeDomainId,
        image: ImageIdentity,
        file: u32,
        epochs: CompleteEpochs,
        fence: u64,
        ids: &[InstanceId],
    ) -> bool {
        let image = ImageKey::from(image);
        if domain != self.domain
            || RetirementLedger::index(image.cookie).is_none()
            || file >= instance::FILE_SLOTS
            || self.authority_failed
            || self.image_failed
            || self.sticky != 0
            || self.miss_latched
            || self.image_retired(image)
            || self.faulted.contains(&(image, file))
            || fence != self.fence
            || epochs.fault != self.fault
            || epochs.sticky != 0
            || epochs.record_flags != 0
            || [epochs.local, epochs.global, epochs.fault]
                .into_iter()
                .any(|value| value > u64::from(u32::MAX))
            || ids.is_empty()
        {
            return false;
        }
        self.observed
            .get(&(image, file))
            .and_then(|list| list.back())
            .is_some_and(|current| {
                current.epochs
                    == EpochKey {
                        local: epochs.local,
                        global: epochs.global,
                        fault: epochs.fault,
                    }
                    && current
                        .partitions
                        .iter()
                        .filter_map(|(_, id)| *id)
                        .eq(ids.iter().copied())
            })
    }

    pub(crate) fn take_observation_losses(&mut self) -> Vec<ObservationLoss> {
        std::mem::take(&mut self.observation_losses)
    }

    pub(crate) fn refuse_image_pending(
        &mut self,
        domain: NativeDomainId,
        image: ImageIdentity,
        reason: UnknownReason,
    ) -> Vec<(u64, Route)> {
        if domain != self.domain {
            return Vec::new();
        }
        self.fail_pending(|call| call.facts.image == image, reason)
    }

    /// No scalar production adapter can declare task death. The private
    /// proof retains the exact original pin whose pidfd became READY.
    pub(crate) fn retire_task(
        &mut self,
        proof: crate::semantic_capture::TerminalTaskProof,
    ) -> Option<Vec<(u64, Route)>> {
        if proof.domain() != self.domain || RetirementLedger::index(proof.cookie()).is_none() {
            return None;
        }
        Some(self.retire_task_cookie(proof.cookie()))
    }

    /// The current publication fence for full-image sealing. Read before
    /// the scan starts; the consumer checks this exact original value again.
    pub(crate) fn fence(&self) -> u64 {
        self.fence
    }

    pub(crate) fn counters(&self) -> RouterCounters {
        self.counters
    }

    pub(crate) fn unknown_counts(&self) -> &BTreeMap<UnknownReason, u64> {
        &self.unknown
    }

    /// Apply the full current fault/sticky cells before routing. Required-hook
    /// health is audited by the Session owner; its failure calls
    /// `fail_image_coverage` and is never repaired by an ordinary era change.
    pub(crate) fn audit(&mut self, fault: u64, sticky: u64, misses: u64) -> Vec<(u64, Route)> {
        if self.authority_failed {
            return self.fail_pending(|_| true, UnknownReason::AuthorityExhausted);
        }
        if fault > u64::from(u32::MAX) || fault < self.fault {
            self.authority_failed = true;
            self.observed.clear();
            self.ranges = 0;
            return self.fail_pending(|_| true, UnknownReason::AuthorityExhausted);
        }
        let mut resolved = Vec::new();
        if sticky != 0 && self.sticky == 0 {
            resolved.extend(self.fail_pending(|_| true, UnknownReason::Sticky));
        }
        self.sticky |= sticky;
        let fault_moved = fault != self.fault;
        let misses_moved = misses != self.misses;
        self.misses = misses;
        if fault_moved {
            let Some(next_fence) = self.fence.checked_add(1) else {
                self.authority_failed = true;
                self.observed.clear();
                self.ranges = 0;
                resolved.extend(self.fail_pending(|_| true, UnknownReason::AuthorityExhausted));
                return resolved;
            };
            self.fault = fault;
            self.fence = next_fence;
            self.miss_latched = false;
            self.counters.eras = self.counters.eras.saturating_add(1);
            self.observed.clear();
            self.ranges = 0;
            resolved.extend(self.fail_pending(|_| true, UnknownReason::FaultEra));
        } else if misses_moved {
            // Legacy scalar backstop only: production uses complete same-object
            // Session health, and permanently fails on any required hook miss.
            self.miss_latched = true;
            self.counters.eras = self.counters.eras.saturating_add(1);
            self.counters.miss_eras = self.counters.miss_eras.saturating_add(1);
            self.observed.clear();
            self.ranges = 0;
            resolved.extend(self.fail_pending(|_| true, UnknownReason::FaultEra));
        }
        resolved
    }

    pub(crate) fn fail_image_coverage(&mut self) -> Vec<(u64, Route)> {
        self.image_failed = true;
        self.observed.clear();
        self.ranges = 0;
        self.fail_pending(|_| true, UnknownReason::CoverageFault)
    }

    pub(crate) fn refuse_exhaustion(&mut self) -> Vec<(u64, Route)> {
        self.authority_failed = true;
        self.observed.clear();
        self.ranges = 0;
        self.fail_pending(|_| true, UnknownReason::AuthorityExhausted)
    }

    fn image_retired(&self, image: ImageKey) -> bool {
        self.retired.contains(&image) || self.retirement.retired(image)
    }

    /// Ends this image only. Eviction compresses its refusal into permanent
    /// per-cookie metadata, without retiring a surviving task or successor.
    pub(crate) fn retire_image(&mut self, image: ImageIdentity) -> Vec<(u64, Route)> {
        if RetirementLedger::index(image.task_cookie).is_none() {
            return Vec::new();
        }
        let key = ImageKey::from(image);
        if self.limits.retired_cookies == 0 {
            self.retirement.retire_image(key);
        } else {
            if let Some(evicted) = evict_for_insert(
                &mut self.retired,
                &key,
                self.limits.retired_cookies,
                &mut self.counters.retired_evictions,
            ) {
                self.retirement.retire_image(evicted);
            }
            self.retired.insert(key);
        }
        let keys: Vec<_> = self
            .observed
            .keys()
            .filter(|(owner, _)| *owner == key)
            .copied()
            .collect();
        for key in keys {
            if let Some(list) = self.observed.remove(&key) {
                self.ranges -= list.iter().map(|o| o.ranges.len()).sum::<usize>();
            }
        }
        self.fail_pending(|call| call.facts.image == image, UnknownReason::Retired)
    }

    #[cfg(test)]
    pub(crate) fn retire_process(&mut self, cookie: u64) -> Vec<(u64, Route)> {
        self.retire_task_cookie(cookie)
    }

    // Accessible in production only through the adapter's sealed
    // original-pidfd terminal proof; tests exercise the same retirement body.
    fn retire_task_cookie(&mut self, cookie: u64) -> Vec<(u64, Route)> {
        if RetirementLedger::index(cookie).is_none() {
            return Vec::new();
        }
        self.retirement.retire_task(cookie);
        let mut resolved = self.retire_image(ImageIdentity {
            task_cookie: cookie,
            exec_id: 0,
        });
        let keys: Vec<_> = self
            .observed
            .keys()
            .filter(|(owner, _)| owner.cookie == cookie)
            .copied()
            .collect();
        for key in keys {
            if let Some(list) = self.observed.remove(&key) {
                self.ranges -= list.iter().map(|o| o.ranges.len()).sum::<usize>();
            }
        }
        resolved.extend(self.fail_pending(
            |call| call.facts.image.task_cookie == cookie,
            UnknownReason::Retired,
        ));
        resolved
    }

    /// Records one stable observation and resolves pending calls that it
    /// decides. Same epochs + no new range = continuity.
    pub(crate) fn observe(&mut self, proof: ImageScanProof) -> (ObserveOutcome, Vec<(u64, Route)>) {
        if proof.domain() != self.domain {
            return (ObserveOutcome::ForeignDomain, Vec::new());
        }
        let image = ImageKey::from(proof.image());
        let epochs = proof.epochs();
        self.observe_reading(
            image,
            StableObservation {
                file_slot: proof.file_slot(),
                reading: EpochReading {
                    cookie: proof.image().task_cookie,
                    local: epochs.local,
                    record_flags: epochs.record_flags,
                    global: epochs.global,
                    fault: epochs.fault,
                    sticky: epochs.sticky,
                },
                ranges: proof.ranges().to_vec(),
                fence: proof.fence(),
            },
        )
    }

    #[cfg(test)]
    pub(crate) fn observe_legacy(
        &mut self,
        observation: StableObservation,
    ) -> (ObserveOutcome, Vec<(u64, Route)>) {
        let image = ImageKey {
            cookie: observation.reading.cookie,
            exec: 0,
        };
        self.observe_reading(image, observation)
    }

    fn observe_reading(
        &mut self,
        image: ImageKey,
        observation: StableObservation,
    ) -> (ObserveOutcome, Vec<(u64, Route)>) {
        let file = observation.file_slot;
        if RetirementLedger::index(image.cookie).is_none() || file >= instance::FILE_SLOTS {
            return (ObserveOutcome::InvalidImage, Vec::new());
        }
        if self.authority_failed
            || self.image_failed
            || self.sticky != 0
            || observation.fence != self.fence
            || observation.reading.fault != self.fault
            || self.miss_latched
        {
            return (ObserveOutcome::StaleEra, Vec::new());
        }
        if self.image_retired(image) {
            return (ObserveOutcome::Retired, Vec::new());
        }
        if [
            observation.reading.local,
            observation.reading.global,
            observation.reading.fault,
        ]
        .into_iter()
        .any(|value| value > u64::from(u32::MAX))
            || observation.reading.record_flags != 0
        {
            return (ObserveOutcome::StaleEra, Vec::new());
        }
        if observation.reading.sticky != 0 {
            let resolved = self.audit(self.fault, observation.reading.sticky, self.misses);
            return (ObserveOutcome::StaleEra, resolved);
        }
        self.counters.observations += 1;
        let epochs = EpochKey::of(&observation.reading);
        let key = (image, file);
        if self.faulted.contains(&key) {
            return (ObserveOutcome::CoverageFault, Vec::new());
        }
        if self.faulted_overflowed && !self.observed.contains_key(&key) {
            // P2-1: a tombstone was evicted, so this unknown key may be a
            // discredited one: refuse, never accept as a new incarnation.
            // Keys with a retained observation keep continuity below.
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
                    let evictions = self.counters.faulted_evictions;
                    let _ = evict_for_insert(
                        &mut self.faulted,
                        &key,
                        self.limits.faulted_keys,
                        &mut self.counters.faulted_evictions,
                    );
                    if self.counters.faulted_evictions != evictions {
                        // P2-1: capacity pressure evicted a discredited key
                        // the router can no longer name: latch refusal for
                        // every unknown key (fail closed; retained keys
                        // keep continuity). Capture-sticky, like the faults.
                        self.faulted_overflowed = true;
                    }
                    self.faulted.insert(key);
                    if let Some(list) = self.observed.remove(&key) {
                        self.ranges -= list.iter().map(|o| o.ranges.len()).sum::<usize>();
                    }
                    let resolved = self.fail_pending(
                        |call| {
                            ImageKey::from(call.facts.image) == image
                                && stamp_file(&call.facts) == Some(file)
                        },
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
                            ImageKey::from(call.facts.image) == image
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
                    let Some(((owner, file_slot), evicted)) = self.observed.pop_first() else {
                        break;
                    };
                    let ids: Vec<_> = evicted
                        .back()
                        .into_iter()
                        .flat_map(|o| o.partitions.iter().filter_map(|(_, id)| *id))
                        .collect();
                    if !ids.is_empty() {
                        self.observation_losses.push(ObservationLoss {
                            image: ImageIdentity {
                                task_cookie: owner.cookie,
                                exec_id: owner.exec,
                            },
                            file_slot,
                            ids,
                        });
                    }
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
        let resolved = self.resolve_pending(image, file);
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

    /// Domain/identity and permanent authority failure precede call flags;
    /// clean equal stamps then require the current fault, a live full image,
    /// retained matching epochs and an executable range at the exact offset.
    fn decide(&self, facts: &CallFacts, may_wait: bool) -> Route {
        use UnknownReason as U;
        let entry = facts.entry;
        if facts.domain != self.domain {
            return Route::Unknown(U::ForeignDomain);
        }
        if RetirementLedger::index(facts.image.task_cookie).is_none() {
            return Route::Unknown(U::InvalidImage);
        }
        if self.authority_failed {
            return Route::Unknown(U::AuthorityExhausted);
        }
        if self.image_failed {
            return Route::Unknown(U::CoverageFault);
        }
        if self.sticky != 0 {
            return Route::Unknown(U::Sticky);
        }
        if entry.flags & instance::STAMP_VALID == 0 || entry.flags & instance::STAMP_NO_TASK != 0 {
            return Route::Unknown(U::Unstamped);
        }
        if entry.flags & instance::STAMP_NO_FILE != 0
            || entry.file_slot_plus1 == 0
            || u32::from(entry.file_slot_plus1) > instance::FILE_SLOTS
        {
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
        let image = ImageKey::from(facts.image);
        if self.image_retired(image) {
            return Route::Unknown(U::Retired);
        }
        let file = u32::from(entry.file_slot_plus1) - 1;
        let key = (image, file);
        if self.faulted.contains(&key) {
            return Route::Unknown(U::CoverageFault);
        }
        if self.faulted_overflowed && !self.observed.contains_key(&key) {
            // P2-1: the overflow latch refuses unknown keys at route time
            // too, so an evicted tombstone can never re-join.
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

    fn resolve_pending(&mut self, image: ImageKey, file: u32) -> Vec<(u64, Route)> {
        let mut resolved = Vec::new();
        let mut kept = VecDeque::with_capacity(self.pending.len());
        let pending = std::mem::take(&mut self.pending);
        for call in pending {
            if ImageKey::from(call.facts.image) != image || stamp_file(&call.facts) != Some(file) {
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
    pub(crate) fn expire_image(&mut self, image: ImageIdentity) -> Vec<(u64, Route)> {
        self.fail_pending(|call| call.facts.image == image, UnknownReason::Unobserved)
    }

    #[cfg(test)]
    pub(crate) fn expire_pending(&mut self, cookie: u64) -> Vec<(u64, Route)> {
        self.expire_cookie(cookie)
    }

    fn expire_cookie(&mut self, cookie: u64) -> Vec<(u64, Route)> {
        self.fail_pending(
            |call| call.facts.image.task_cookie == cookie,
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
        if self.minted >= self.limits.instances || self.next_id == 0 {
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
fn evict_for_insert<K: Ord + Clone>(
    set: &mut BTreeSet<K>,
    key: &K,
    limit: usize,
    evictions: &mut u64,
) -> Option<K> {
    let mut evicted = None;
    while set.len() >= limit && !set.contains(key) {
        let Some(first) = set.pop_first() else {
            break;
        };
        // Pops run smallest-first, so the last pop is the greatest evicted.
        evicted = Some(first);
        *evictions = evictions.saturating_add(1);
    }
    evicted
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
