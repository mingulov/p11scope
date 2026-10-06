//! SPDX-License-Identifier: GPL-3.0-or-later
//! Private caller preparation, exact map contract, immutable endpoint
//! publication and retained health for the dedicated caller object.

use super::{
    AttachBackend, BPF_F_RDONLY_PROG, ExactMapMetadata, InventoryBudget, InventoryMapKind,
    InventoryPreparation, compare_map_metadata, inventory_capacity, inventory_map_data,
    inventory_maps, map_metadata, prepare_inventory_with_kind, read_map_metadata,
};
use crate::capacity::CallerBudget;
use crate::discovery::identity::PinnedObjectId;
use anyhow::{Context as _, Result, bail};
use aya::Ebpf;
use aya::maps::{Array, Map, MapType, PerCpuArray};
use p11scope_ebpf_common::inventory_callers::{CallerObjectKey, CallerObjectUse, EndpointObject};
use p11scope_ebpf_common::{IMAGE_IDENTITY_TICKET_LIMIT, ImageIdentityControl};
use std::collections::{BTreeMap, BTreeSet};
use std::fmt;
use std::os::fd::{AsFd as _, AsRawFd as _};
use std::time::Instant;

/// CALLER_USE's capacity: the pair limit P. The map is insert-only
/// (`BPF_NOEXIST` in BPF, never deleted by either side), so it never holds
/// more than P distinct rows, and the facade's seen set is bounded by this
/// same value (`seen_limit`): a full seen set means a full map, whose
/// further inserts fail into CALLER_EVIDENCE. The coordinator's pair
/// precondition relies on this equality.
pub(super) fn caller_use_capacity(budget: CallerBudget) -> Result<u32> {
    Ok(u32::try_from(budget.pair_limit())?)
}

/// The facade's CALLER_USE seen-set bound: exactly the map's capacity.
pub(super) fn seen_limit(budget: CallerBudget) -> Result<usize> {
    Ok(usize::try_from(caller_use_capacity(budget)?)?)
}

pub(super) fn validate_caller_maps(
    actual: &BTreeMap<String, (InventoryMapKind, ExactMapMetadata)>,
    budget: CallerBudget,
) -> Result<()> {
    use InventoryMapKind as K;
    let n = inventory_capacity(budget.endpoint_budget())?;
    let p = caller_use_capacity(budget)?;
    let mut expected = inventory_maps(n);
    expected.extend([
        (
            "ENDPOINT_OBJECT",
            (
                K::Array,
                map_metadata(MapType::Array, 4, 8, n.get(), BPF_F_RDONLY_PROG),
            ),
        ),
        (
            "CALLER_USE",
            (K::Hash, map_metadata(MapType::Hash, 24, 40, p, 0)),
        ),
        (
            "CALLER_EVIDENCE",
            (
                K::PerCpuArray,
                map_metadata(MapType::PerCpuArray, 4, 8, 4, 0),
            ),
        ),
        (
            "TASK_COOKIE",
            (
                K::Unsupported,
                map_metadata(MapType::TaskStorage, 4, 8, 0, 1),
            ),
        ),
        (
            "COOKIE_CTL",
            (K::Array, map_metadata(MapType::Array, 4, 40, 1, 0)),
        ),
    ]);
    if !actual
        .keys()
        .map(String::as_str)
        .eq(expected.keys().copied())
    {
        bail!("caller Inventory map names differ from exact 18-map manifest");
    }
    for (name, (kind, metadata)) in expected {
        let (actual_kind, actual_metadata) = actual[name];
        if actual_kind != kind {
            bail!("caller Inventory {name} map variant differs");
        }
        compare_map_metadata(name, actual_metadata, metadata)?;
    }
    Ok(())
}

pub(super) fn validate_caller_control(control: ImageIdentityControl) -> Result<()> {
    if [
        control.limit,
        control.next_ticket,
        control.unavailable,
        control.create_failures,
        control.retry_exhausted,
    ] != [IMAGE_IDENTITY_TICKET_LIMIT, 0, 0, 0, 0]
    {
        bail!("COOKIE_CTL is not a fresh caller identity control");
    }
    Ok(())
}

pub(super) fn prepare_caller_inventory_with<T>(
    endpoint_budget: InventoryBudget,
    caller_budget: CallerBudget,
    backend: AttachBackend,
    state: T,
    operation: impl FnMut(&mut T, InventoryPreparation) -> Result<()>,
) -> Result<T> {
    if endpoint_budget != caller_budget.endpoint_budget() {
        bail!("caller endpoint budget differs from Inventory budget");
    }
    prepare_inventory_with_kind(backend, state, true, operation)
}

pub(super) fn validate_runtime_caller_maps(ebpf: &Ebpf, budget: CallerBudget) -> Result<()> {
    let actual = ebpf
        .maps()
        .map(|(name, map)| {
            let (kind, data) = inventory_map_data(name, map)?;
            Ok((name.to_string(), (kind, read_map_metadata(name, data)?)))
        })
        .collect::<Result<BTreeMap<_, _>>>()?;
    validate_caller_maps(&actual, budget)
}

impl CallerEndpointIo for Ebpf {
    fn read_endpoint(&mut self, endpoint: u32) -> Result<EndpointObject> {
        let map: Array<_, EndpointObject> = Array::try_from(
            self.map("ENDPOINT_OBJECT")
                .ok_or_else(|| anyhow::anyhow!("ENDPOINT_OBJECT map missing"))?,
        )?;
        Ok(map.get(&endpoint, 0)?)
    }

    fn write_endpoint(&mut self, endpoint: u32, value: EndpointObject) -> Result<()> {
        let mut map: Array<_, EndpointObject> = Array::try_from(
            self.map_mut("ENDPOINT_OBJECT")
                .ok_or_else(|| anyhow::anyhow!("ENDPOINT_OBJECT map missing"))?,
        )?;
        Ok(map.set(endpoint, value, 0)?)
    }
}

pub(super) trait CallerEndpointIo {
    fn read_endpoint(&mut self, endpoint: u32) -> Result<EndpointObject>;
    fn write_endpoint(&mut self, endpoint: u32, value: EndpointObject) -> Result<()>;
}

pub(super) fn publish_caller_endpoint_with<I: CallerEndpointIo>(
    io: &mut I,
    endpoint: u32,
    object: PinnedObjectId,
) -> Result<()> {
    let old = io.read_endpoint(endpoint)?;
    if !old.is_uncommitted() {
        bail!("caller endpoint {endpoint} is already committed or malformed");
    }
    let value = EndpointObject {
        object_id: object.0,
        class: p11scope_ebpf_common::inventory_callers::ENDPOINT_OBJECT_COMMITTED_PHYSICAL,
    };
    io.write_endpoint(endpoint, value)?;
    if io.read_endpoint(endpoint)? != value {
        bail!("caller endpoint {endpoint} readback differs from committed physical object");
    }
    Ok(())
}

pub(super) trait CallerHealthIo {
    fn evidence_cell(&mut self, index: u32) -> Result<u64>;
    fn identity_control(&mut self) -> Result<ImageIdentityControl>;
}

#[derive(Debug, Default)]
pub(super) struct CallerHealth {
    pub evidence: Option<[u64; 4]>,
    pub control: Option<ImageIdentityControl>,
    pub failures: Vec<String>,
}

pub(super) fn read_caller_health_with<I: CallerHealthIo>(
    io: &mut I,
    deadline: Instant,
) -> CallerHealth {
    let mut health = CallerHealth::default();
    let mut evidence = [0u64; 4];
    let mut unknown = false;
    for (index, value) in evidence.iter_mut().enumerate() {
        if Instant::now() >= deadline {
            health.failures.push(format!(
                "caller health deadline before CALLER_EVIDENCE[{index}]"
            ));
            unknown = true;
            continue;
        }
        match io.evidence_cell(index as u32) {
            Ok(read) => *value = read,
            Err(error) => {
                health
                    .failures
                    .push(format!("CALLER_EVIDENCE[{index}]: {error:#}"));
                unknown = true;
            }
        }
    }
    if !unknown {
        health.evidence = Some(evidence);
    }
    if Instant::now() >= deadline {
        health
            .failures
            .push("caller health deadline before COOKIE_CTL".into());
    } else {
        match io.identity_control() {
            Ok(control) => health.control = Some(control),
            Err(error) => health.failures.push(format!("COOKIE_CTL: {error:#}")),
        }
    }
    health
}

impl CallerHealthIo for &Ebpf {
    fn evidence_cell(&mut self, index: u32) -> Result<u64> {
        let map: PerCpuArray<_, u64> = PerCpuArray::try_from(
            self.map("CALLER_EVIDENCE")
                .ok_or_else(|| anyhow::anyhow!("CALLER_EVIDENCE map missing"))?,
        )?;
        map.get(&index, 0)?.iter().try_fold(0u64, |sum, value| {
            sum.checked_add(*value)
                .ok_or_else(|| anyhow::anyhow!("CALLER_EVIDENCE[{index}] per-CPU sum overflow"))
        })
    }

    fn identity_control(&mut self) -> Result<ImageIdentityControl> {
        let map: Array<_, ImageIdentityControl> = Array::try_from(
            self.map("COOKIE_CTL")
                .ok_or_else(|| anyhow::anyhow!("COOKIE_CTL map missing"))?,
        )?;
        Ok(map.get(&0, 0)?)
    }
}

/// The two kernel operations a CALLER_USE cursor needs: the next key after
/// a key (BPF_MAP_GET_NEXT_KEY) and one lookup. Rows are never deleted or
/// replaced (BPF inserts with BPF_NOEXIST only), so a cursor key stays
/// present and a sweep visits every row that existed when it began.
pub(super) trait CallerUseIo {
    fn next_key(&mut self, after: Option<&CallerObjectKey>) -> Result<Option<CallerObjectKey>>;
    fn lookup(&mut self, key: &CallerObjectKey) -> Result<Option<CallerObjectUse>>;
    /// One BPF_MAP_LOOKUP_BATCH step over CALLER_USE in kernel hash order,
    /// continuing from the previous step's opaque `after` token (`None`:
    /// from the beginning), returning up to `max` pairs. The default is
    /// unsupported: scripted maps without batch, and the count refresh
    /// falls back to per-key lookup.
    fn lookup_batch(&mut self, after: Option<&BatchToken>, max: usize) -> Result<CallerBatchStep> {
        let _ = (after, max);
        Err(BatchUnsupported.into())
    }
}

/// BPF_MAP_LOOKUP_BATCH failed with EINVAL: the running kernel (or map)
/// has no batch lookup. A probe signal, never a read failure: the count
/// refresh falls back to per-key lookup for the rest of the capture.
#[derive(Debug)]
pub(super) struct BatchUnsupported;

impl fmt::Display for BatchUnsupported {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("BPF_MAP_LOOKUP_BATCH is unsupported")
    }
}

impl std::error::Error for BatchUnsupported {}

/// One BPF_MAP_LOOKUP_BATCH step: up to `max` map pairs in kernel hash
/// order, whether the walk reached the end of the map, and — when it did
/// not — the kernel's out_batch continuation for the next step's in_batch.
#[derive(Debug, Default)]
pub(super) struct CallerBatchStep {
    pub pairs: Vec<(CallerObjectKey, CallerObjectUse)>,
    pub completed: bool,
    pub next_batch: Option<BatchToken>,
}

/// The opaque BPF batch continuation: the kernel's out_batch blob,
/// retained and round-tripped as the next step's in_batch, never
/// interpreted. For hash maps the kernel reads and writes a u32 bucket
/// index through these pointers (v6.12
/// `__htab_map_lookup_and_delete_batch`); key bytes are NOT a
/// continuation. Key-sized so any map's out_batch write lands inside.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(super) struct BatchToken([u8; std::mem::size_of::<CallerObjectKey>()]);

impl BatchToken {
    fn zero() -> Self {
        Self([0; std::mem::size_of::<CallerObjectKey>()])
    }

    fn as_ptr(&self) -> *const u8 {
        self.0.as_ptr()
    }

    fn as_mut_ptr(&mut self) -> *mut u8 {
        self.0.as_mut_ptr()
    }

    /// The hash-map token dialect (what the kernel reads/writes): the
    /// blob's first u32, little-endian. Test fakes only — production
    /// never interprets the bytes.
    #[cfg(test)]
    pub(super) fn from_bucket(bucket: u32) -> Self {
        let mut token = Self::zero();
        token.0[..4].copy_from_slice(&bucket.to_le_bytes());
        token
    }

    /// The hash-map token dialect (what the kernel reads/writes): the
    /// blob's first u32, little-endian. Test fakes only — production
    /// never interprets the bytes.
    #[cfg(test)]
    pub(super) fn bucket(&self) -> u32 {
        u32::from_le_bytes(self.0[..4].try_into().expect("four bytes"))
    }
}

impl CallerUseIo for &Ebpf {
    fn next_key(&mut self, after: Option<&CallerObjectKey>) -> Result<Option<CallerObjectKey>> {
        let data = match self.map("CALLER_USE").context("CALLER_USE map")? {
            Map::HashMap(data) => data,
            _ => bail!("CALLER_USE is not the exact hash map"),
        };
        let mut next = CallerObjectKey::default();
        let attr = crate::attach::BpfMapElementAttr {
            map_fd: data.fd().as_fd().as_raw_fd() as u32,
            key: after.map_or(0, |key| (key as *const CallerObjectKey) as u64),
            value: (&mut next as *mut CallerObjectKey) as u64,
            ..Default::default()
        };
        match crate::attach::bpf_map_element_syscall(
            BPF_MAP_GET_NEXT_KEY,
            &attr,
            std::mem::size_of_val(&attr),
        ) {
            Ok(()) => Ok(Some(next)),
            Err(error) if error.raw_os_error() == Some(libc::ENOENT) => Ok(None),
            Err(error) => Err(error).context("CALLER_USE next key"),
        }
    }

    fn lookup(&mut self, key: &CallerObjectKey) -> Result<Option<CallerObjectUse>> {
        let map: aya::maps::HashMap<_, CallerObjectKey, CallerObjectUse> =
            aya::maps::HashMap::try_from(self.map("CALLER_USE").context("CALLER_USE map")?)?;
        match map.get(key, 0) {
            Ok(value) => Ok(Some(value)),
            Err(aya::maps::MapError::KeyNotFound) => Ok(None),
            Err(error) => Err(error).context("CALLER_USE lookup"),
        }
    }

    fn lookup_batch(&mut self, after: Option<&BatchToken>, max: usize) -> Result<CallerBatchStep> {
        let data = match self.map("CALLER_USE").context("CALLER_USE map")? {
            Map::HashMap(data) => data,
            _ => bail!("CALLER_USE is not the exact hash map"),
        };
        // A zero count cannot make progress (ENOSPC); the quantum bound is
        // at least one in production, and a direct zero still terminates.
        let count = u32::try_from(max).unwrap_or(u32::MAX).max(1);
        let mut keys = vec![CallerObjectKey::default(); count as usize];
        let mut values = vec![CallerObjectUse::default(); count as usize];
        let mut out_batch = BatchToken::zero();
        let mut attr = BpfMapBatchAttr {
            in_batch: after.map_or(0, |token| token.as_ptr() as u64),
            out_batch: out_batch.as_mut_ptr() as u64,
            keys: keys.as_mut_ptr() as u64,
            values: values.as_mut_ptr() as u64,
            count,
            map_fd: data.fd().as_fd().as_raw_fd() as u32,
            ..Default::default()
        };
        let size = std::mem::size_of_val(&attr);
        let result = bpf_map_batch_syscall(BPF_MAP_LOOKUP_BATCH, &mut attr, size);
        // The kernel sets `count` to the pairs it filled, including on the
        // final ENOENT step; clamp defensively to what was asked.
        let filled = usize::try_from(attr.count)
            .unwrap_or(usize::MAX)
            .min(keys.len());
        keys.truncate(filled);
        values.truncate(filled);
        let pairs = keys.into_iter().zip(values).collect();
        match result {
            Ok(()) => Ok(CallerBatchStep {
                pairs,
                completed: false,
                next_batch: Some(out_batch),
            }),
            Err(error) if error.raw_os_error() == Some(libc::ENOENT) => Ok(CallerBatchStep {
                pairs,
                completed: true,
                next_batch: None,
            }),
            Err(error) if error.raw_os_error() == Some(libc::EINVAL) => {
                Err(BatchUnsupported.into())
            }
            Err(error) => Err(error).context("CALLER_USE batch lookup"),
        }
    }
}

const BPF_MAP_GET_NEXT_KEY: u32 = 4;
const BPF_MAP_LOOKUP_BATCH: u32 = 24;

/// `BPF_MAP_LOOKUP_BATCH` attr (`linux/bpf.h` `bpf_attr.batch`: the in/out
/// cursors, the key/value outputs, the in/out count, then the map fd).
/// The exact shape is pinned by `caller_batch_attr_matches_the_kernel_batch_layout`.
#[repr(C)]
#[derive(Default)]
struct BpfMapBatchAttr {
    in_batch: u64,
    out_batch: u64,
    keys: u64,
    values: u64,
    count: u32,
    map_fd: u32,
    elem_flags: u64,
    flags: u64,
}

/// Raw `bpf()` for one batch step, in the `crates/bpf-multi` style.
fn bpf_map_batch_syscall(
    command: u32,
    attr: &mut BpfMapBatchAttr,
    size: usize,
) -> std::io::Result<()> {
    // SAFETY: the attr and every buffer it points at (the in/out batch
    // tokens, the key/value arrays) are live for exactly this syscall.
    let rc = unsafe {
        libc::syscall(
            libc::SYS_bpf,
            command as libc::c_long,
            attr as *mut BpfMapBatchAttr,
            size,
        )
    };
    if rc == -1 {
        Err(std::io::Error::last_os_error())
    } else {
        Ok(())
    }
}

/// Total order over the wire key, for the cursor's seen set.
pub(super) type CallerRowKey = (u64, u64, u32, u32);

pub(super) fn row_key(key: &CallerObjectKey) -> CallerRowKey {
    (
        key.image.task_cookie,
        key.image.exec_id,
        key.object_id,
        key.reserved,
    )
}

/// A bounded, resumable CALLER_USE cursor. Each row is reported exactly
/// once for the capture (valid or not); the seen set is bounded by the
/// map's own pair capacity P. The cursor also re-reads witnessed rows'
/// entry counts (`refresh_with`): the witness sweep reports the unseen and
/// skips the seen, while the refresh sweep re-reads the seen and skips the
/// unseen, each from its own cursor.
pub(super) struct CallerUseCursor {
    after: Option<CallerObjectKey>,
    seen: BTreeSet<CallerRowKey>,
    seen_limit: usize,
    sweeps_completed: u64,
    /// The sweep in progress skipped a row (lookup failure or seen-set
    /// bound): it completes "with gaps".
    sweep_gaps: bool,
    /// The per-key fallback's map position (the key the next
    /// `BPF_MAP_GET_NEXT_KEY` continues after). The batch walk keeps its
    /// own opaque token below: key bytes are not a batch continuation.
    refresh_after: Option<CallerObjectKey>,
    /// The batch walk's opaque continuation (the last step's out_batch).
    /// `None` starts a sweep at the map's beginning; a transport error
    /// leaves it untouched, so the next quantum resumes the same sweep.
    refresh_batch: Option<BatchToken>,
    /// The last saturated count read for each witnessed (valid) row. A
    /// subset of the seen set: faulted rows seed no baseline and are never
    /// re-read.
    counts: BTreeMap<CallerRowKey, TrackedCount>,
    /// Whether BPF_MAP_LOOKUP_BATCH works here: probed on the first
    /// refresh, then latched (a transport error is never a verdict).
    batch: BatchProbe,
    refresh_sweeps_completed: u64,
    /// The refresh sweep in progress skipped a tracked row (a lookup
    /// failure): it completes "with gaps".
    refresh_sweep_gaps: bool,
}

/// The last saturated count read for one witnessed row, and whether its
/// integrity gap (a decrease, or a vanish) was already reported. Rows are
/// reported once: so is a row's gap.
#[derive(Debug, Clone, Copy)]
struct TrackedCount {
    last: u64,
    gap_reported: bool,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum BatchProbe {
    Untried,
    Works,
    Unsupported,
}

/// Why one CALLER_USE row is not usable evidence. Never dropped: each is
/// reported once, with the raw key and value.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(super) enum CallerRowFault {
    /// The key failed `CallerObjectKey::is_valid` (no image, reserved bits).
    InvalidKey,
    /// The value failed `CallerObjectUse::is_valid(N)`.
    InvalidValue,
    /// A key the iterator returned had no value (rows are never deleted).
    Vanished,
    /// The witness endpoint is not one this capture published.
    UnpublishedEndpoint,
    /// ENDPOINT_OBJECT bound the witness endpoint to another object.
    BindingMismatch { published: u32 },
    /// A further check the owner applies (PID scope: a foreign tgid).
    Rejected(String),
    /// A tracked row's re-read entry count is below its last read
    /// (saturated): an integrity gap, never a published regression. The
    /// published count stays `before`.
    CountDecrease { before: u64, after: u64 },
}

/// One cursor quantum.
#[derive(Debug, Default)]
pub(super) struct CallerRowsRead {
    pub(super) rows: Vec<(CallerObjectKey, CallerObjectUse)>,
    pub(super) faults: Vec<(CallerObjectKey, Option<CallerObjectUse>, CallerRowFault)>,
    pub(super) visited: usize,
    pub(super) sweep_completed: bool,
    pub(super) row_bound_reached: bool,
    pub(super) deadline_reached: bool,
    pub(super) read_failures: Vec<String>,
    /// Distinct rows past the seen-set bound: counted, never reported twice.
    pub(super) unrecorded: u64,
    /// `sweep_completed`, but the sweep skipped at least one row: not every
    /// row present when it began was reported.
    pub(super) sweep_gaps: bool,
}

/// One count-refresh quantum.
#[derive(Debug, Default)]
pub(super) struct CallerCountsRead {
    /// Tracked rows whose saturated entry count advanced, with the re-read
    /// value. Lower bounds while producers run; final after stop.
    pub(super) updates: Vec<(CallerObjectKey, CallerObjectUse)>,
    /// Tracked rows whose re-read is integrity evidence (a vanished row, a
    /// count that decreased): each reported once per row, never published.
    pub(super) gaps: Vec<(CallerObjectKey, Option<CallerObjectUse>, CallerRowFault)>,
    pub(super) visited: usize,
    pub(super) sweep_completed: bool,
    pub(super) row_bound_reached: bool,
    pub(super) deadline_reached: bool,
    pub(super) read_failures: Vec<String>,
    /// `sweep_completed`, but the sweep skipped a tracked row (a lookup
    /// failure): that row's count is stale, and the next sweep retries it.
    pub(super) sweep_gaps: bool,
}

impl CallerUseCursor {
    pub(super) fn new(pair_limit: usize) -> Self {
        Self {
            after: None,
            seen: BTreeSet::new(),
            seen_limit: pair_limit,
            sweeps_completed: 0,
            sweep_gaps: false,
            refresh_after: None,
            refresh_batch: None,
            counts: BTreeMap::new(),
            batch: BatchProbe::Untried,
            refresh_sweeps_completed: 0,
            refresh_sweep_gaps: false,
        }
    }

    pub(super) fn occupancy(&self) -> usize {
        self.seen.len()
    }

    pub(super) fn sweeps_completed(&self) -> u64 {
        self.sweeps_completed
    }

    pub(super) fn refresh_sweeps_completed(&self) -> u64 {
        self.refresh_sweeps_completed
    }

    /// Visits at most `max_rows` keys (two syscalls each) before
    /// `deadline`. `binding(endpoint)` is the object this capture
    /// published for an endpoint; `extra` is the owner's further check.
    /// Every valid row seeds its count baseline as it reports, so the
    /// refresh owns every witnessed row from its first sight.
    pub(super) fn read_with<I: CallerUseIo>(
        &mut self,
        io: &mut I,
        max_rows: usize,
        deadline: Instant,
        endpoint_capacity: u32,
        binding: impl Fn(u32) -> Option<u32>,
        extra: impl Fn(&CallerObjectKey, &CallerObjectUse) -> Option<String>,
    ) -> CallerRowsRead {
        let mut read = CallerRowsRead::default();
        while read.visited < max_rows {
            if Instant::now() >= deadline {
                read.deadline_reached = true;
                return read;
            }
            let next = match io.next_key(self.after.as_ref()) {
                Ok(next) => next,
                Err(error) => {
                    read.read_failures.push(format!("{error:#}"));
                    return read;
                }
            };
            let Some(key) = next else {
                // End of one sweep: the next quantum starts from the first key.
                self.sweeps_completed = self.sweeps_completed.saturating_add(1);
                self.after = None;
                read.sweep_completed = true;
                read.sweep_gaps = std::mem::take(&mut self.sweep_gaps);
                return read;
            };
            self.after = Some(key);
            read.visited += 1;
            let row = row_key(&key);
            if self.seen.contains(&row) {
                continue;
            }
            let value = match io.lookup(&key) {
                Ok(value) => value,
                Err(error) => {
                    // Not recorded as seen: the next sweep retries it.
                    read.read_failures.push(format!("{error:#}"));
                    self.sweep_gaps = true;
                    continue;
                }
            };
            if self.seen.len() >= self.seen_limit {
                read.unrecorded = read.unrecorded.saturating_add(1);
                self.sweep_gaps = true;
                continue;
            }
            self.seen.insert(row);
            let fault = match value {
                None => Some(CallerRowFault::Vanished),
                Some(_) if !key.is_valid() => Some(CallerRowFault::InvalidKey),
                Some(value) if !value.is_valid(endpoint_capacity) => {
                    Some(CallerRowFault::InvalidValue)
                }
                Some(value) => match binding(value.witness_endpoint) {
                    None => Some(CallerRowFault::UnpublishedEndpoint),
                    Some(published) if published != key.object_id => {
                        Some(CallerRowFault::BindingMismatch { published })
                    }
                    Some(_) => extra(&key, &value).map(CallerRowFault::Rejected),
                },
            };
            match (fault, value) {
                (None, Some(value)) => {
                    self.counts.insert(
                        row,
                        TrackedCount {
                            last: value.saturated_entry_count(),
                            gap_reported: false,
                        },
                    );
                    read.rows.push((key, value));
                }
                (Some(fault), value) => read.faults.push((key, value, fault)),
                (None, None) => unreachable!("a vanished row is a fault"),
            }
        }
        read.row_bound_reached = true;
        read
    }

    /// Re-reads the entry counts of witnessed (valid) rows: one quantum of
    /// at most `max_rows` map rows before `deadline`, resuming next quantum
    /// from the refresh cursor. Untracked rows (new or faulted) are visited
    /// but never reported: discovery stays the witness sweep's. Counts only
    /// move up: an advance is reported, a decrease or a vanish is integrity
    /// evidence (once per row), and a reread below the last read never
    /// moves the published count. One batch step per quantum where the
    /// probe says batch works (continuing from the retained opaque token),
    /// else a per-key walk from its own key cursor.
    pub(super) fn refresh_with<I: CallerUseIo>(
        &mut self,
        io: &mut I,
        max_rows: usize,
        deadline: Instant,
    ) -> CallerCountsRead {
        let mut read = CallerCountsRead::default();
        if Instant::now() >= deadline {
            read.deadline_reached = true;
            return read;
        }
        if max_rows == 0 {
            read.row_bound_reached = true;
            return read;
        }
        if self.batch != BatchProbe::Unsupported {
            match io.lookup_batch(self.refresh_batch.as_ref(), max_rows) {
                Ok(step) => {
                    self.batch = BatchProbe::Works;
                    self.absorb_step(step, max_rows, &mut read);
                    return read;
                }
                Err(error) if error.downcast_ref::<BatchUnsupported>().is_some() => {
                    self.batch = BatchProbe::Unsupported;
                }
                Err(error) => {
                    read.read_failures.push(format!("count refresh: {error:#}"));
                    return read;
                }
            }
        }
        self.refresh_per_key(io, max_rows, deadline, &mut read);
        read
    }

    /// Folds one batch step into the tracked counts, retaining the
    /// kernel's continuation token for the next step.
    fn absorb_step(&mut self, step: CallerBatchStep, max_rows: usize, read: &mut CallerCountsRead) {
        for (key, value) in step.pairs {
            read.visited += 1;
            self.refresh_row(key, Some(value), read);
        }
        if step.completed {
            self.refresh_sweeps_completed = self.refresh_sweeps_completed.saturating_add(1);
            self.refresh_batch = None;
            read.sweep_completed = true;
            read.sweep_gaps = std::mem::take(&mut self.refresh_sweep_gaps);
        } else {
            self.refresh_batch = step.next_batch;
            if read.visited >= max_rows {
                read.row_bound_reached = true;
            }
        }
    }

    /// The per-key fallback: the same map walk the witness sweep does,
    /// refreshing tracked rows and skipping the rest without a lookup.
    fn refresh_per_key<I: CallerUseIo>(
        &mut self,
        io: &mut I,
        max_rows: usize,
        deadline: Instant,
        read: &mut CallerCountsRead,
    ) {
        while read.visited < max_rows {
            if Instant::now() >= deadline {
                read.deadline_reached = true;
                return;
            }
            let next = match io.next_key(self.refresh_after.as_ref()) {
                Ok(next) => next,
                Err(error) => {
                    read.read_failures.push(format!("count refresh: {error:#}"));
                    return;
                }
            };
            let Some(key) = next else {
                // End of one refresh sweep: the next quantum starts over.
                self.refresh_sweeps_completed = self.refresh_sweeps_completed.saturating_add(1);
                self.refresh_after = None;
                read.sweep_completed = true;
                read.sweep_gaps = std::mem::take(&mut self.refresh_sweep_gaps);
                return;
            };
            self.refresh_after = Some(key);
            read.visited += 1;
            if !self.counts.contains_key(&row_key(&key)) {
                continue;
            }
            let value = match io.lookup(&key) {
                Ok(value) => value,
                Err(error) => {
                    // Unchanged baseline: the next sweep retries it.
                    read.read_failures.push(format!("count refresh: {error:#}"));
                    self.refresh_sweep_gaps = true;
                    continue;
                }
            };
            self.refresh_row(key, value, read);
        }
        read.row_bound_reached = true;
    }

    /// Folds one re-read row into its tracked count: an advance is
    /// reported; a decrease or a vanish is integrity evidence, reported
    /// once per row, and never moves the published count.
    fn refresh_row(
        &mut self,
        key: CallerObjectKey,
        value: Option<CallerObjectUse>,
        read: &mut CallerCountsRead,
    ) {
        let Some(tracked) = self.counts.get_mut(&row_key(&key)) else {
            return;
        };
        let Some(value) = value else {
            if !tracked.gap_reported {
                tracked.gap_reported = true;
                read.gaps.push((key, None, CallerRowFault::Vanished));
            }
            return;
        };
        let count = value.saturated_entry_count();
        if count < tracked.last {
            if !tracked.gap_reported {
                tracked.gap_reported = true;
                read.gaps.push((
                    key,
                    Some(value),
                    CallerRowFault::CountDecrease {
                        before: tracked.last,
                        after: count,
                    },
                ));
            }
        } else if count > tracked.last {
            tracked.last = count;
            read.updates.push((key, value));
        }
    }
}

#[cfg(test)]
mod tests;
