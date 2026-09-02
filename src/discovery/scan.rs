//! Finding PKCS#11 function tables by reading the target's mapped memory. No provider
//! code is executed and nothing is copied: `/proc/<pid>/maps` says what is mapped,
//! `.dynsym` says which objects could hand out a table, and the target's own
//! non-executable pages are searched for the `CK_FUNCTION_LIST` signature. Table
//! layout comes from `pkcs11_module::tables_for`/`read_fn_pointers` — the same
//! authority the offline helper uses — so a scanned offset equals a manifest offset.

use crate::discovery::hooks::HookRegistry;
use crate::process::{MountNamespaceId, ProcessView, ProcessViewId};
use p11scope_manifest::elf::exports_matching;
use p11scope_manifest::identity::open_object;
use p11scope_manifest::maps::{MapEntry, MapIndex, MappedPath, ObjectKey, Resolved, parse_maps};
use pkcs11_module::{Surface, TableSet, TableSpan, read_fn_pointers, tables_for};
use std::collections::{BTreeMap, HashMap};
use std::fs::File;
use std::io::Read;
use std::os::unix::fs::{FileExt as _, MetadataExt as _};
use std::path::{Path, PathBuf};
use std::time::Instant;

const WORD: usize = 8;
const INTERFACE_NAME_CAP: usize = 64;
/// One `CK_INTERFACE`: `{ char *name, void *function_list, CK_FLAGS flags }`.
const INTERFACE_BYTES: usize = 3 * WORD;
const READ_CHUNK: usize = 1024 * 1024;
const STANDARD_INTERFACE_NAME: &[u8] = b"PKCS 11";
const MAX_TABLE_CANDIDATES: usize = 512;
const MAX_DECODED_TABLE_ENTRIES: usize = 512 * 104;
const MAX_INTERFACE_RECORDS: usize = 512;
const MAX_MAPS_BYTES: u64 = 64 * 1024 * 1024;
const MAX_MAP_ENTRIES: usize = 1_048_576;
// ponytail: this independent ceiling is the calibration knob if real providers hit it.
const DEFAULT_WORK_CEILING: u64 = 16 * 1024 * 1024;
pub(crate) const IO_CEILING_REASON: &str =
    "capture attempted-I/O ceiling reached; remaining provider bytes were not read";
pub(crate) const WORK_CEILING_REASON: &str =
    "capture discovery work ceiling reached; remaining provider bytes were not scanned";
pub(crate) const SCAN_DEADLINE_REASON: &str =
    "capture discovery deadline reached; remaining provider bytes were not scanned";
pub(crate) const SCAN_CLOCK_REASON: &str =
    "monotonic clock read failed; remaining provider bytes were not scanned";
pub(crate) const MAPS_CEILING_REASON: &str =
    "capture /proc maps byte ceiling reached; remaining mappings were not read";
pub(crate) const MAPS_ENTRY_CEILING_REASON: &str =
    "capture /proc maps entry ceiling reached; remaining mappings were not read";

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ScanLimits {
    pub per_object_bytes: u64,
    pub total_bytes: u64,
}

impl Default for ScanLimits {
    fn default() -> Self {
        Self {
            per_object_bytes: 64 * 1024 * 1024,
            total_bytes: 512 * 1024 * 1024,
        }
    }
}

/// One capture's concrete discovery allowance. Memory snapshots and file hashes
/// spend the same byte total; cardinality counters stop decoded-record amplification.
#[derive(Debug)]
pub struct CaptureWorkBudget {
    limits: ScanLimits,
    attempted_io_bytes: u64,
    table_candidates: usize,
    decoded_table_entries: usize,
    interface_records: usize,
    table_exhaustion_reported: bool,
    interface_exhaustion_reported: bool,
    work_ceiling: u64,
    work_units: u64,
    deadline_ns: Option<u64>,
    /// Test-only: the deadline most recently *installed* (a `Some` passed to
    /// `set_deadline`). The end-of-batch `None` clear leaves it in place, so a
    /// test can observe what a finished batch apply actually forwarded.
    #[cfg(test)]
    pub(crate) last_installed_deadline: Option<u64>,
    scan_stop_reason: Option<&'static str>,
    scan_stop_reported: bool,
}

impl CaptureWorkBudget {
    pub fn new(limits: ScanLimits) -> Self {
        Self {
            limits,
            attempted_io_bytes: 0,
            table_candidates: 0,
            decoded_table_entries: 0,
            interface_records: 0,
            table_exhaustion_reported: false,
            interface_exhaustion_reported: false,
            work_ceiling: DEFAULT_WORK_CEILING,
            work_units: 0,
            deadline_ns: None,
            #[cfg(test)]
            last_installed_deadline: None,
            scan_stop_reason: None,
            scan_stop_reported: false,
        }
    }

    pub fn limits(&self) -> ScanLimits {
        self.limits
    }

    pub fn attempted_io_bytes(&self) -> u64 {
        self.attempted_io_bytes
    }

    pub(crate) fn allowed_io(&self, operation_bytes: u64, wanted: usize) -> usize {
        let operation_left = self.limits.per_object_bytes.saturating_sub(operation_bytes);
        let capture_left = self
            .limits
            .total_bytes
            .saturating_sub(self.attempted_io_bytes);
        wanted.min(
            operation_left
                .min(capture_left)
                .try_into()
                .unwrap_or(usize::MAX),
        )
    }

    pub(crate) fn record_io(&mut self, bytes: usize) {
        self.attempted_io_bytes = self.attempted_io_bytes.saturating_add(bytes as u64);
    }

    pub fn charge(&mut self, units: u64) -> bool {
        if self.scan_stop_reason.is_some() {
            return false;
        }
        let Some(next) = self.work_units.checked_add(units) else {
            self.scan_stop_reason = Some(WORK_CEILING_REASON);
            return false;
        };
        if next > self.work_ceiling {
            self.scan_stop_reason = Some(WORK_CEILING_REASON);
            return false;
        }
        self.work_units = next;
        true
    }

    pub fn set_deadline(&mut self, deadline_ns: Option<u64>) {
        #[cfg(test)]
        if deadline_ns.is_some() {
            self.last_installed_deadline = deadline_ns;
        }
        self.deadline_ns = deadline_ns;
        if deadline_ns.is_none()
            && matches!(
                self.scan_stop_reason,
                Some(SCAN_DEADLINE_REASON | SCAN_CLOCK_REASON)
            )
        {
            self.scan_stop_reason = None;
            self.scan_stop_reported = false;
        }
    }

    #[cfg(test)]
    pub(crate) fn deadline_for_test(&self) -> Option<u64> {
        self.deadline_ns
    }

    fn check_deadline(&mut self, now: Option<u64>) -> Option<&'static str> {
        if let Some(reason) = self.scan_stop_reason {
            return Some(reason);
        }
        let deadline = self.deadline_ns?;
        let reason = match now {
            Some(now) if now < deadline => return None,
            Some(_) => SCAN_DEADLINE_REASON,
            None => SCAN_CLOCK_REASON,
        };
        self.scan_stop_reason = Some(reason);
        Some(reason)
    }

    pub(crate) fn check_deadline_now(&mut self) -> Option<&'static str> {
        if self.deadline_ns.is_some() {
            self.check_deadline(crate::attach::monotonic_ns())
        } else {
            None
        }
    }

    /// The capture's stop, sticky reason first and otherwise one clock poll:
    /// the single question every live admission asks before doing more work.
    pub(crate) fn stopped_now(&mut self) -> Option<&'static str> {
        if let Some(reason) = self.scan_stop_reason {
            return Some(reason);
        }
        self.check_deadline_now()
    }

    /// One charged step of live map work, refused under the budget's own stop
    /// reason so a caller publishes what actually stopped it.
    pub(crate) fn spend(&mut self, units: u64) -> Result<(), &'static str> {
        if self.charge(units) {
            Ok(())
        } else {
            Err(self.scan_stop_reason.unwrap_or(WORK_CEILING_REASON))
        }
    }

    pub(crate) fn take_scan_stop_reason(&mut self) -> Option<&'static str> {
        let reason = self.scan_stop_reason?;
        if self.scan_stop_reported {
            None
        } else {
            self.scan_stop_reported = true;
            Some(reason)
        }
    }

    fn scan_stopped(&self) -> bool {
        self.scan_stop_reason.is_some()
    }

    fn allowed_capture_io(&self, wanted: usize) -> usize {
        self.limits
            .total_bytes
            .saturating_sub(self.attempted_io_bytes)
            .try_into()
            .map_or(usize::MAX, |left| wanted.min(left))
    }

    pub(crate) fn admit_table(&mut self, entries: usize) -> bool {
        if self.scan_stopped() {
            return false;
        }
        let Some(decoded) = self.decoded_table_entries.checked_add(entries) else {
            return false;
        };
        if self.table_candidates == MAX_TABLE_CANDIDATES || decoded > MAX_DECODED_TABLE_ENTRIES {
            return false;
        }
        self.table_candidates += 1;
        self.decoded_table_entries = decoded;
        true
    }

    fn tables_exhausted(&self) -> bool {
        self.table_candidates == MAX_TABLE_CANDIDATES
            || self.decoded_table_entries == MAX_DECODED_TABLE_ENTRIES
    }

    fn table_exhaustion_reason(&mut self) -> Option<String> {
        if std::mem::replace(&mut self.table_exhaustion_reported, true) {
            None
        } else {
            Some(format!(
                "capture table decode ceiling reached ({MAX_TABLE_CANDIDATES} candidates, \
                 {MAX_DECODED_TABLE_ENTRIES} entries); remaining table data was not decoded"
            ))
        }
    }

    pub(crate) fn admit_interface(&mut self) -> bool {
        if self.scan_stopped() {
            return false;
        }
        if self.interface_records == MAX_INTERFACE_RECORDS {
            return false;
        }
        self.interface_records += 1;
        true
    }

    fn interfaces_exhausted(&self) -> bool {
        self.interface_records == MAX_INTERFACE_RECORDS
    }

    fn interface_exhaustion_reason(&mut self) -> Option<String> {
        if std::mem::replace(&mut self.interface_exhaustion_reported, true) {
            None
        } else {
            Some(format!(
                "capture interface decode ceiling reached ({MAX_INTERFACE_RECORDS} records); \
                 remaining interface data was not decoded"
            ))
        }
    }
}

impl Default for CaptureWorkBudget {
    fn default() -> Self {
        Self::new(ScanLimits::default())
    }
}

pub struct ScanRequest<'a> {
    pub pid: u32,
    /// `--module` hints; empty means "every object exporting a registry symbol".
    pub hints: &'a [PathBuf],
    pub hooks: &'a HookRegistry,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ScannedEntry {
    pub name: &'static str,
    pub object: ObjectKey,
    pub object_path: String,
    pub file_offset: u64,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ScannedTable {
    pub version: (u8, u8),
    /// "full" or "known_prefix" — the `WalkOutcome` label the manifest uses.
    pub walk: &'static str,
    pub entries: Vec<ScannedEntry>,
    /// Published names whose slot held a NULL pointer — evidence, not entries.
    pub null_entries: Vec<&'static str>,
    /// Entries this scan decoded but reconciliation could not bind to a comparable
    /// pinned object. Kept here so they stay counted
    /// as *seen* and are reported as skipped, exactly like the NULL ones: a
    /// record the scan read and could not use is evidence, not silence.
    pub unpinned: Vec<Skipped>,
    /// Address of the version word in the target, for interface cross-reference.
    pub address: u64,
    /// Exact object-relative location of that version word. Runtime addresses
    /// are generation-local and never identify a table across remaps.
    pub file_offset: Option<u64>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ScannedInterface {
    pub index: usize,
    /// "exact_standard" | "other" | "null" | "unreadable". "unreadable" covers all
    /// ways a name does not become text: the read failed, no NUL appeared before the
    /// mapping end or `INTERFACE_NAME_CAP`, or the pointer was outside this object's
    /// readable pages and was deliberately not dereferenced.
    pub name_class: &'static str,
    /// Kept for `inspect` and manifests only; never rendered in capture output.
    pub name_lossy: Option<String>,
    /// Exact bounded bytes used only for private cross-view alias identity.
    /// They are never rendered in capture output.
    pub name_private: Option<Vec<u8>>,
    pub flags: u64,
    /// Index into `ScannedModule::tables`. A triple is only accepted as an interface
    /// when its function-list pointer names a table this scan decoded, so this is
    /// `Some` today; the option keeps room for recording undecoded targets later.
    pub table: Option<usize>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Skipped {
    pub subject: String,
    pub reason: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ScannedModule {
    /// Capture-local owner of every table and target contribution in this module.
    pub view: ProcessViewId,
    pub mount_namespace: MountNamespaceId,
    pub key: ObjectKey,
    pub path: String,
    pub exports: Vec<String>,
    pub tables: Vec<ScannedTable>,
    pub interfaces: Vec<ScannedInterface>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ScanOutcome {
    Scanned {
        modules: Vec<ScannedModule>,
        skipped: Vec<Skipped>,
        scan_ms: u64,
    },
    /// `/proc/<pid>/mem` was not accessible (spec §4.1 step 3, §4.9) — never fatal.
    /// Objects are still identified from `maps` + `.dynsym`, so `inspect` can answer
    /// "which providers does this process map" without any ptrace access; their
    /// `tables` are empty because tables live only in memory.
    Unavailable {
        reason: &'static str,
        modules: Vec<ScannedModule>,
        skipped: Vec<Skipped>,
    },
}

impl ScanOutcome {
    pub fn modules(&self) -> &[ScannedModule] {
        match self {
            Self::Scanned { modules, .. } | Self::Unavailable { modules, .. } => modules,
        }
    }

    pub fn skipped(&self) -> &[Skipped] {
        match self {
            Self::Scanned { skipped, .. } | Self::Unavailable { skipped, .. } => skipped,
        }
    }

    /// `Some(reason)` when the table scan could not run.
    pub fn unavailable_reason(&self) -> Option<&'static str> {
        match self {
            Self::Scanned { .. } => None,
            Self::Unavailable { reason, .. } => Some(reason),
        }
    }
}

/// Version word → the field spans that describe that layout. Returns `None` when the
/// word is not a plausible `CK_VERSION` header or the layout is one we refuse to walk.
pub(crate) fn spans_for(word: u64) -> Option<((u8, u8), &'static [TableSpan], &'static str)> {
    if word & !0xffff != 0 {
        return None;
    }
    let major = (word & 0xff) as u8;
    let minor = ((word >> 8) & 0xff) as u8;
    let plausible = match major {
        2 => minor <= 40,
        3 => minor <= 2,
        _ => false,
    };
    if !plausible {
        return None;
    }
    let version = cryptoki_sys::CK_VERSION { major, minor };
    // 2.x tables in memory are legacy CK_FUNCTION_LIST; 3.x tables are the
    // interface layouts (92/104 slots) — spec §4.1 step 4's N table.
    let surface = if major == 2 {
        Surface::LegacyFunctionList { version }
    } else {
        Surface::StandardInterface { version }
    };
    match tables_for(surface) {
        TableSet::Walk(spans) => Some(((major, minor), spans, "full")),
        TableSet::WalkKnownPrefix(spans) => Some(((major, minor), spans, "known_prefix")),
        TableSet::Refuse => None,
    }
}

/// How many bytes a layout occupies, including the version header word.
fn span_bytes(spans: &[TableSpan]) -> Option<usize> {
    spans
        .iter()
        .flat_map(|span| span.fields())
        .filter_map(|field| field.offset.checked_add(WORD))
        .max()
}

pub(crate) fn exact_table_bytes(header: &[u8]) -> Option<usize> {
    let word = u64::from_ne_bytes(header.get(..WORD)?.try_into().ok()?);
    let (_, spans, _) = spans_for(word)?;
    span_bytes(spans)
}

/// Returns every non-NULL function pointer in one complete table snapshot.
/// Addresses are capture-local and are used only to close the maps-A/maps-B
/// stability bracket; callers must not persist them as identity.
pub(crate) fn exact_table_addresses(snapshot: &[u8]) -> Option<Vec<u64>> {
    let word = u64::from_ne_bytes(snapshot.get(..WORD)?.try_into().ok()?);
    let (_, spans, _) = spans_for(word)?;
    let mut addresses = Vec::new();
    for span in spans {
        for field in span.fields() {
            let raw = field
                .offset
                .checked_add(WORD)
                .and_then(|end| snapshot.get(field.offset..end))?;
            let address = u64::from_ne_bytes(raw.try_into().ok()?);
            if address != 0 {
                addresses.push(address);
            }
        }
    }
    Some(addresses)
}

/// Decodes one candidate at `offset` inside `snapshot` (whose first byte is at
/// `base_address` in the target). Returns the table only when every published slot
/// is either NULL or points into a file-backed executable mapping — the criterion
/// that makes a run of pointers a function table rather than data that looks like one.
fn decode_candidate(
    snapshot: &[u8],
    offset: usize,
    base_address: u64,
    maps: &MapIndex<'_>,
    budget: &mut CaptureWorkBudget,
) -> Result<Option<(ScannedTable, usize)>, ()> {
    let Some(raw_word) = offset
        .checked_add(WORD)
        .and_then(|end| snapshot.get(offset..end))
    else {
        return Ok(None);
    };
    let word = u64::from_ne_bytes(raw_word.try_into().expect("one word"));
    let Some((version, spans, walk)) = spans_for(word) else {
        return Ok(None);
    };
    let Some(len) = span_bytes(spans) else {
        return Ok(None);
    };
    let Some(address) = base_address.checked_add(offset as u64) else {
        return Ok(None);
    };
    let file_offset = match maps.resolve(address) {
        Resolved::File { file_offset, .. } => Some(file_offset),
        _ => None,
    };
    let Some(bytes) = offset
        .checked_add(len)
        .and_then(|end| snapshot.get(offset..end))
    else {
        return Ok(None);
    };

    // Validate the whole candidate before reserving or allocating decoded records.
    let mut non_null = 0usize;
    for span in spans {
        for field in span.fields() {
            if !budget.charge(1) {
                return Err(());
            }
            let Some(raw) = field
                .offset
                .checked_add(WORD)
                .and_then(|end| bytes.get(field.offset..end))
            else {
                return Ok(None);
            };
            let value = usize::from_ne_bytes(raw.try_into().expect("one pointer"));
            if value == 0 {
                continue;
            }
            non_null += 1;
            let Resolved::File {
                permissions, path, ..
            } = maps.resolve(value as u64)
            else {
                return Ok(None); // anonymous or unmapped ⇒ not a function table
            };
            if permissions[2] != b'x' {
                return Ok(None); // a pointer into data ⇒ not a function table
            }
            let MappedPath::Usable(_) = path else {
                return Ok(None); // deleted/ambiguous pathname ⇒ cannot become an attach target
            };
        }
    }
    if non_null == 0 {
        return Ok(None);
    }
    let decoded_entries = spans.iter().map(|span| span.fields().len()).sum();
    if !budget.admit_table(decoded_entries) {
        return Err(());
    }

    let mut entries = Vec::with_capacity(non_null);
    let mut null_entries = Vec::with_capacity(decoded_entries - non_null);
    for span in spans {
        for (name, value) in read_fn_pointers(bytes, span.fields()).expect("validated above") {
            if value == 0 {
                null_entries.push(name);
                continue;
            }
            let Resolved::File {
                path,
                file_offset,
                device,
                inode,
                ..
            } = maps.resolve(value as u64)
            else {
                unreachable!("validated above")
            };
            let MappedPath::Usable(path) = path else {
                unreachable!("validated above")
            };
            entries.push(ScannedEntry {
                name,
                object: ObjectKey { device, inode },
                object_path: path.display().to_string(),
                file_offset,
            });
        }
    }
    Ok(Some((
        ScannedTable {
            version,
            walk,
            entries,
            null_entries,
            unpinned: Vec::new(),
            address,
            file_offset,
        },
        len,
    )))
}

/// Decode one table whose first byte is at `address`, using the same bounded
/// layout decoder as heuristic memory discovery.  Callers own the bounded
/// `/proc/<pid>/mem` read; this helper only accepts a complete table snapshot.
pub(crate) fn decode_exact_table(
    snapshot: &[u8],
    address: u64,
    maps: &MapIndex<'_>,
    budget: &mut CaptureWorkBudget,
) -> Result<Option<ScannedTable>, ()> {
    decode_candidate(snapshot, 0, address, maps, budget)
        .map(|decoded| decoded.map(|(table, _)| table))
}

/// Every 8-byte-aligned candidate in one snapshot, longest match kept on overlap.
/// The second return carries the one bounded exhaustion reason, if decoding stopped.
fn detect_tables(
    snapshot: &[u8],
    base_address: u64,
    maps: &MapIndex<'_>,
    budget: &mut CaptureWorkBudget,
) -> (Vec<ScannedTable>, Vec<String>) {
    detect_tables_with_clock(
        snapshot,
        base_address,
        maps,
        budget,
        crate::attach::monotonic_ns,
    )
}

fn detect_tables_with_clock<F: FnMut() -> Option<u64>>(
    snapshot: &[u8],
    base_address: u64,
    maps: &MapIndex<'_>,
    budget: &mut CaptureWorkBudget,
    mut now: F,
) -> (Vec<ScannedTable>, Vec<String>) {
    let mut skipped = Vec::new();
    let mut found: Vec<(usize, usize, ScannedTable)> = Vec::new();
    let mut offset = 0usize;
    while offset + WORD <= snapshot.len() {
        if (offset / WORD) % 4096 == 0
            && budget.deadline_ns.is_some()
            && budget.check_deadline(now()).is_some()
        {
            if let Some(reason) = budget.take_scan_stop_reason() {
                skipped.push(reason.into());
            }
            break;
        }
        if budget.tables_exhausted() {
            if let Some(reason) = budget.table_exhaustion_reason() {
                skipped.push(reason);
            }
            break;
        }
        if !budget.charge(1) {
            if let Some(reason) = budget.take_scan_stop_reason() {
                skipped.push(reason.into());
            }
            break;
        }
        match decode_candidate(snapshot, offset, base_address, maps, budget) {
            Ok(Some((table, len))) => found.push((offset, len, table)),
            Ok(None) => {}
            Err(()) => {
                if let Some(reason) = budget.take_scan_stop_reason() {
                    skipped.push(reason.into());
                } else if let Some(reason) = budget.table_exhaustion_reason() {
                    skipped.push(reason);
                }
                break;
            }
        }
        offset += WORD;
    }
    // Longest first, then drop anything overlapping an already-kept match.
    found.sort_by(|a, b| b.1.cmp(&a.1).then(a.0.cmp(&b.0)));
    let mut kept: Vec<(usize, usize, ScannedTable)> = Vec::new();
    for candidate in found {
        let overlaps = kept.iter().any(|(start, len, _)| {
            candidate.0 < start.saturating_add(*len)
                && *start < candidate.0.saturating_add(candidate.1)
        });
        if !overlaps {
            kept.push(candidate);
        }
    }
    kept.sort_by_key(|(start, _, _)| *start);
    (
        kept.into_iter().map(|(_, _, table)| table).collect(),
        skipped,
    )
}

/// `CK_INTERFACE` triples in one snapshot that name a table this scan decoded.
/// The triple's own address is not recorded, so no `base_address` is needed here.
fn scan_interfaces(
    snapshot: &[u8],
    mem: &File,
    tables: &[ScannedTable],
    maps: &MapIndex<'_>,
    key: ObjectKey,
    budget: &mut CaptureWorkBudget,
    operation_bytes: &mut u64,
) -> (Vec<ScannedInterface>, Vec<String>) {
    scan_interfaces_with_clock(
        snapshot,
        mem,
        tables,
        maps,
        key,
        budget,
        operation_bytes,
        crate::attach::monotonic_ns,
    )
}

#[allow(clippy::too_many_arguments)]
fn scan_interfaces_with_clock<F: FnMut() -> Option<u64>>(
    snapshot: &[u8],
    mem: &File,
    tables: &[ScannedTable],
    maps: &MapIndex<'_>,
    key: ObjectKey,
    budget: &mut CaptureWorkBudget,
    operation_bytes: &mut u64,
    mut now: F,
) -> (Vec<ScannedInterface>, Vec<String>) {
    let word_at = |offset: usize| -> Option<u64> {
        Some(u64::from_ne_bytes(
            snapshot
                .get(offset..offset.checked_add(WORD)?)?
                .try_into()
                .ok()?,
        ))
    };
    let mut found = Vec::new();
    let mut skipped = Vec::new();
    let mut io_exhausted = false;
    let by_address: HashMap<u64, usize> =
        tables
            .iter()
            .enumerate()
            .fold(HashMap::new(), |mut by_address, (index, table)| {
                by_address.entry(table.address).or_insert(index);
                by_address
            });
    let mut offset = 0usize;
    while offset + INTERFACE_BYTES <= snapshot.len() {
        if (offset / WORD) % 4096 == 0
            && budget.deadline_ns.is_some()
            && budget.check_deadline(now()).is_some()
        {
            if let Some(reason) = budget.take_scan_stop_reason() {
                skipped.push(reason.into());
            }
            break;
        }
        if budget.interfaces_exhausted() {
            if let Some(reason) = budget.interface_exhaustion_reason() {
                skipped.push(reason);
            }
            break;
        }
        if !budget.charge(1) {
            if let Some(reason) = budget.take_scan_stop_reason() {
                skipped.push(reason.into());
            }
            break;
        }
        let scanned = (|| {
            let name_ptr = word_at(offset)?;
            let table_ptr = word_at(offset + WORD)?;
            let flags = word_at(offset + 2 * WORD)?;
            // The function-list pointer is the anchor: without it a triple of words
            // is just data. Requiring a decoded table also keeps the byte budget —
            // only the provider's own mappings are ever read.
            let table = by_address.get(&table_ptr).copied()?;
            if !budget.admit_interface() {
                return None;
            }
            // Privacy boundary: a triple is accepted on `table_ptr` alone, so the name
            // pointer of a look-alike structure could aim anywhere. Only this object's
            // own readable pages — where a provider keeps its interface names — are
            // ever dereferenced; anything else is recorded without being read.
            let mapping_end = maps
                .containing(name_ptr)
                .filter(|entry| {
                    entry.permissions[0] == b'r'
                        && ObjectKey {
                            device: entry.device,
                            inode: entry.inode,
                        } == key
                        && entry
                            .raw_path
                            .as_deref()
                            .is_some_and(|path| path.starts_with(b"/"))
                })
                .map(|entry| entry.end);
            let (name_class, name_lossy, name_private) = match name_ptr {
                0 => ("null", None, None),
                _ if mapping_end.is_none() => ("unreadable", None, None),
                _ => {
                    match read_name(mem, name_ptr, mapping_end.unwrap(), budget, operation_bytes) {
                        Ok(Some(raw)) if raw == STANDARD_INTERFACE_NAME => (
                            "exact_standard",
                            Some(String::from_utf8_lossy(&raw).into_owned()),
                            Some(raw),
                        ),
                        Ok(Some(raw)) => (
                            "other",
                            Some(String::from_utf8_lossy(&raw).into_owned()),
                            Some(raw),
                        ),
                        Ok(None) => ("unreadable", None, None),
                        Err(()) => {
                            io_exhausted = true;
                            ("unreadable", None, None)
                        }
                    }
                }
            };
            Some(ScannedInterface {
                index: 0,
                name_class,
                name_lossy,
                name_private,
                flags,
                table: Some(table),
            })
        })();
        if let Some(scanned) = scanned {
            found.push(scanned);
        }
        if io_exhausted {
            skipped.push(
                budget
                    .take_scan_stop_reason()
                    .unwrap_or(IO_CEILING_REASON)
                    .into(),
            );
            break;
        }
        offset += WORD;
    }
    (found, skipped)
}

/// A NUL-terminated name of at most `INTERFACE_NAME_CAP` bytes, or `None` when the
/// target memory could not be read or the name reaches the mapping end or cap.
fn read_name(
    mem: &File,
    address: u64,
    mapping_end: u64,
    budget: &mut CaptureWorkBudget,
    operation_bytes: &mut u64,
) -> Result<Option<Vec<u8>>, ()> {
    let Some(mapping_bytes) = mapping_end.checked_sub(address) else {
        return Ok(None);
    };
    let limit = mapping_bytes.min(INTERFACE_NAME_CAP as u64) as usize;
    let mut raw: Vec<u8> = Vec::with_capacity(limit);
    while raw.len() < limit {
        if budget.check_deadline_now().is_some() {
            return Err(());
        }
        let mut chunk = [0u8; 32];
        let want = chunk.len().min(limit - raw.len());
        let Some(at) = address.checked_add(raw.len() as u64) else {
            return Ok(None);
        };
        let allowed = budget.allowed_io(*operation_bytes, want);
        if allowed == 0 {
            return Err(());
        }
        let read = match mem.read_at(&mut chunk[..allowed], at) {
            Ok(0) | Err(_) => return Ok(None),
            Ok(read) => read,
        };
        budget.record_io(read);
        *operation_bytes += read as u64;
        if let Some(nul) = chunk[..read].iter().position(|byte| *byte == 0) {
            raw.extend_from_slice(&chunk[..nul]);
            return Ok(Some(raw));
        }
        raw.extend_from_slice(&chunk[..read]);
    }
    Ok(None)
}

/// `entry.start..entry.end` from the target, in ≤1 MiB chunks. A partial read simply
/// advances and retries; only a failed or zero-length read ends the mapping, keeping
/// what was read so far. The second return says why it stopped short — everything past
/// that point went unscanned, and the caller must record that rather than imply it was
/// examined and found empty.
fn read_mapping(
    mem: &File,
    entry: &MapEntry,
    budget: &mut CaptureWorkBudget,
    operation_bytes: &mut u64,
) -> (Vec<u8>, Option<String>, bool) {
    let Some(len) = entry.end.checked_sub(entry.start).map(|len| len as usize) else {
        return (Vec::new(), None, false);
    };
    let mut bytes = Vec::with_capacity(len.min(READ_CHUNK));
    let mut done = 0usize;
    let mut short = None;
    let mut exhausted = false;
    while done < len {
        if budget.check_deadline_now().is_some() {
            short = budget.take_scan_stop_reason().map(str::to_owned);
            exhausted = true;
            break;
        }
        let requested = READ_CHUNK.min(len - done);
        let want = budget.allowed_io(*operation_bytes, requested);
        if want == 0 {
            short = Some(IO_CEILING_REASON.to_string());
            exhausted = true;
            break;
        }
        let Some(at) = entry.start.checked_add(done as u64) else {
            short = Some("address arithmetic overflowed".to_string());
            break;
        };
        bytes.resize(done + want, 0);
        match mem.read_at(&mut bytes[done..], at) {
            Ok(0) => {
                bytes.truncate(done);
                // Addresses stay out of the reason: it is published in the capture
                // document, which does not carry a target's runtime layout. The
                // byte counts say exactly how much of the mapping went unexamined.
                short = Some("the read returned no bytes".to_string());
                break;
            }
            Err(error) => {
                bytes.truncate(done);
                short = Some(format!("the read failed: {error}"));
                break;
            }
            Ok(read) => {
                bytes.truncate(done + read);
                budget.record_io(read);
                *operation_bytes += read as u64;
                done += read;
            }
        }
    }
    let short = short.map(|cause| {
        if exhausted {
            cause
        } else {
            format!("partial snapshot of one data mapping: read {done} of {len} bytes: {cause}")
        }
    });
    (bytes, short, exhausted)
}

/// File-backed mappings grouped by object, keeping groups that carry code.
fn candidate_groups(maps: &[MapEntry]) -> BTreeMap<ObjectKey, Vec<&MapEntry>> {
    let mut groups: BTreeMap<ObjectKey, Vec<&MapEntry>> = BTreeMap::new();
    for entry in maps.iter().filter(|entry| entry.inode != 0) {
        groups.entry(ObjectKey::of(entry)).or_default().push(entry);
    }
    groups.retain(|_, group| group.iter().any(|entry| entry.permissions[2] == b'x'));
    groups
}

/// Opens an object as the *target* sees it (spec §4.5: needs only `PTRACE_MODE_READ`;
/// `map_files` is never required, and a container's own file is never copied out).
fn open_in_target(view: &ProcessView, path: &str) -> Result<File, String> {
    view.run_while_same(|| open_object(Path::new(&format!("/proc/{}/root{path}", view.pid()))))?
}

/// `(inode, size)` for a `--module` hint, read through the *observer's* filesystem view.
/// `None` whenever the hint names a path that does not exist here — which is the normal
/// case for a containerized target, whose module lives only under `/proc/<pid>/root`.
fn hint_identity(hint: &Path) -> Option<(u64, u64)> {
    let metadata = open_object(hint).ok()?.metadata().ok()?;
    Some((metadata.ino(), metadata.len()))
}

/// How a `--module` hint matched a mapped object.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum HintMatch {
    /// The target's rendered pathname equals the hint verbatim.
    Path,
    /// The hint's own inode number equals the mapped object's.
    Inode,
}

/// Whether a hint match may be attributed to the object that was just opened.
///
/// Only an *inode* match needs corroboration: `/proc/<pid>/maps` renders the mount's
/// device rather than the file's `st_dev` (see `identity::mapping_file_key`), so the
/// device cannot be compared and a bare inode number can repeat across filesystems.
/// Size agreement stands in for it.
///
/// A *path* match must never be gated on size. Matching by inode requires
/// `hint_identity` to have succeeded, so `hint_size == None` implies the match was by
/// path — a target in another mount namespace, where the hint does not resolve on the
/// host at all. Gating that on a size the observer cannot read would reject every
/// correctly-matched containerized module.
fn hint_gate(
    kind: HintMatch,
    hint_size: Option<u64>,
    actual_size: Option<u64>,
) -> Result<(), String> {
    if kind == HintMatch::Path || hint_size == actual_size {
        return Ok(());
    }
    let bytes = |size: Option<u64>| size.map_or("unknown".to_string(), |size| size.to_string());
    Err(format!(
        "a --module hint has this object's inode number but a different size ({} bytes \
         in the hint, {} bytes in the target); refusing to attribute an object whose \
         inode number is reused on another filesystem",
        bytes(hint_size),
        bytes(actual_size)
    ))
}

/// Why `/proc/<pid>/mem` could not be opened, and whether that is a published
/// discovery loss. `ESRCH` is proof the process ended — the ordinary end of a
/// process, already recorded by `scan_unavailable`, and nothing a capture that
/// keeps running can still read. It would otherwise publish one undeduplicable
/// record per finished subprocess, the pid in both the subject and the message,
/// on every `--cgroup` capture of a workload that forks per unit of work. Every
/// refusal — ptrace, Yama, anything unreadable — is a real loss and stays loud.
fn mem_unavailable(error: &std::io::Error) -> (&'static str, bool) {
    match error.raw_os_error() {
        Some(libc::EACCES | libc::EPERM) => ("ptrace", true),
        Some(libc::ESRCH) => ("gone", false),
        _ => ("unreadable", true),
    }
}

fn capture_scan_reason(reason: &str) -> bool {
    matches!(
        reason,
        WORK_CEILING_REASON | SCAN_DEADLINE_REASON | SCAN_CLOCK_REASON
    )
}

fn scan_skip(subject: &str, reason: String) -> Skipped {
    Skipped {
        subject: if capture_scan_reason(&reason) {
            "capture discovery".into()
        } else {
            subject.into()
        },
        reason,
    }
}

fn read_maps_with_limits<R: Read, F: FnMut() -> Option<u64>>(
    mut reader: R,
    budget: &mut CaptureWorkBudget,
    max_bytes: u64,
    max_entries: usize,
    chunk_size: usize,
    mut now: F,
) -> std::io::Result<(Vec<u8>, Vec<&'static str>)> {
    let chunk_size = chunk_size.max(1);
    let mut bytes = Vec::new();
    let mut newline_count = 0usize;
    let mut byte_ceiling = false;
    let mut entry_ceiling = false;
    let mut io_ceiling = false;
    let mut deadline_stop = false;
    let mut chunk = vec![0; chunk_size];

    loop {
        if budget.deadline_ns.is_some() && budget.check_deadline(now()).is_some() {
            deadline_stop = true;
            break;
        }
        let read_so_far = u64::try_from(bytes.len()).unwrap_or(u64::MAX);
        let Some(left) = max_bytes.checked_sub(read_so_far) else {
            byte_ceiling = true;
            break;
        };
        let requested = left.saturating_add(1).min(chunk_size as u64);
        let requested = usize::try_from(requested).unwrap_or(chunk_size);
        let allowed = budget.allowed_capture_io(requested);
        if allowed == 0 {
            io_ceiling = true;
            break;
        }
        let read = reader.read(&mut chunk[..allowed])?;
        if read == 0 {
            break;
        }
        budget.record_io(read);
        newline_count = newline_count
            .saturating_add(chunk[..read].iter().filter(|byte| **byte == b'\n').count());
        bytes.extend_from_slice(&chunk[..read]);
        byte_ceiling = u64::try_from(bytes.len()).is_ok_and(|len| len > max_bytes);
        entry_ceiling = newline_count > max_entries;
        if byte_ceiling || entry_ceiling {
            break;
        }
    }

    let mut reasons = Vec::new();
    let original_len = bytes.len();
    let mut end = original_len;
    if byte_ceiling {
        reasons.push(MAPS_CEILING_REASON);
        end = end.min(usize::try_from(max_bytes).unwrap_or(usize::MAX));
    }
    if entry_ceiling {
        reasons.push(MAPS_ENTRY_CEILING_REASON);
        end = end.min(if max_entries == 0 {
            0
        } else {
            bytes
                .iter()
                .enumerate()
                .filter(|(_, byte)| **byte == b'\n')
                .nth(max_entries - 1)
                .map_or(0, |(index, _)| index + 1)
        });
    }
    if io_ceiling {
        reasons.push(IO_CEILING_REASON);
    }
    if deadline_stop {
        if let Some(reason) = budget.take_scan_stop_reason() {
            reasons.push(reason);
        }
    }
    if byte_ceiling || io_ceiling || deadline_stop {
        end = bytes[..end]
            .iter()
            .rposition(|byte| *byte == b'\n')
            .map_or(0, |index| index + 1);
    }
    bytes.truncate(end);
    Ok((bytes, reasons))
}

/// The live engine's `/proc/<pid>/maps` snapshot. The engine decides identity
/// and ownership from it, so unlike the scan path's trimmed-and-reported read
/// it is refused whole when the byte, entry, or total-I/O ceiling or the batch
/// deadline cuts it; an already-expired deadline refuses before a byte is read.
pub(crate) fn read_maps_or_refuse<R: Read, F: FnMut() -> Option<u64>>(
    reader: R,
    budget: &mut CaptureWorkBudget,
    mut now: F,
) -> Result<Vec<MapEntry>, String> {
    // The reader reports a stopped batch's reason only once; the refusal must
    // not depend on that, so ask the budget directly before reading.
    if budget.deadline_ns.is_some() {
        if let Some(reason) = budget.check_deadline(now()) {
            return Err(reason.into());
        }
    }
    let (bytes, reasons) = read_maps_with_limits(
        reader,
        budget,
        MAX_MAPS_BYTES,
        MAX_MAP_ENTRIES,
        64 * 1024,
        now,
    )
    .map_err(|error| error.to_string())?;
    if let Some(reason) = reasons.first() {
        return Err((*reason).into());
    }
    parse_maps(&bytes)
}

/// One validated `MapIndex` per accepted snapshot. The order/overlap validation
/// is O(entries) and is charged once here, so every live consumer does charged
/// O(log n) lookups against this index instead of rebuilding — and revalidating —
/// one per lookup.
pub(crate) fn index_maps_or_refuse<'a>(
    maps: &'a [MapEntry],
    budget: &mut CaptureWorkBudget,
) -> Result<MapIndex<'a>, String> {
    budget.spend(maps.len() as u64).map_err(String::from)?;
    MapIndex::new(maps)
        .ok_or_else(|| "reversed or overlapping /proc/<pid>/maps intervals".to_string())
}

pub fn scan_pid(
    request: &ScanRequest<'_>,
    budget: &mut CaptureWorkBudget,
) -> Result<ScanOutcome, String> {
    let view = ProcessView::open(ProcessViewId(0), request.pid)?;
    scan_process_view(request, &view, budget)
}

/// Scan through an already accepted process-generation pin. Capture discovery uses
/// this entry point so one monotonically allocated `ProcessViewId` owns every result.
pub fn scan_process_view(
    request: &ScanRequest<'_>,
    view: &ProcessView,
    budget: &mut CaptureWorkBudget,
) -> Result<ScanOutcome, String> {
    if request.pid != view.pid() {
        return Err("scan request pid does not match its process view".into());
    }
    if !view.still_the_same() {
        return Err(format!("pid {} exited before discovery", request.pid));
    }
    let started = Instant::now();
    let pid = request.pid;
    let (map_bytes, map_reasons) = view
        .run_while_same(|| {
            File::open(format!("/proc/{pid}/maps")).and_then(|maps_file| {
                read_maps_with_limits(
                    maps_file,
                    budget,
                    MAX_MAPS_BYTES,
                    MAX_MAP_ENTRIES,
                    64 * 1024,
                    crate::attach::monotonic_ns,
                )
                .map_err(std::io::Error::other)
            })
        })
        .map_err(|error| format!("/proc/{pid}/maps: {error}"))?
        .map_err(|error| format!("/proc/{pid}/maps: {error}"))?;
    let maps = parse_maps(&map_bytes)?;
    let map_index = MapIndex::new(&maps)
        .ok_or_else(|| "reversed or overlapping /proc/<pid>/maps intervals".to_string())?;
    let mut modules = Vec::new();
    let map_subject = format!("/proc/{pid}/maps");
    let mut skipped = map_reasons
        .into_iter()
        .map(|reason| scan_skip(&map_subject, reason.into()))
        .collect::<Vec<_>>();
    // `parse_maps`, `MapIndex::new` and `candidate_groups` are each O(entries)
    // on a snapshot the target sizes. Charge that preprocessing and answer the
    // capture's stop here: a dense map cannot defer the first check past it,
    // and a stop that arrived before this scan is published instead of
    // breaking the group loop with no reason at all.
    let scannable = budget.spend(maps.len() as u64).is_ok() && budget.stopped_now().is_none();
    if !scannable {
        if let Some(reason) = budget.take_scan_stop_reason() {
            skipped.push(scan_skip("capture discovery", reason.into()));
        }
    }
    // `/proc/<pid>/mem` is gated by PTRACE_MODE_ATTACH and Yama; losing it costs the
    // tables, never the object inventory (spec §4.1 step 3). Only an access refusal is
    // a ptrace refusal — a pid that died mid-scan gets its own label.
    let mem = view.run_while_same(|| File::open(format!("/proc/{pid}/mem")))?;
    let unavailable = mem.as_ref().err().map(|error| {
        let (class, publishes) = mem_unavailable(error);
        if publishes {
            skipped.push(Skipped {
                subject: format!("/proc/{pid}/mem"),
                reason: error.to_string(),
            });
        }
        class
    });
    let mem = mem.ok();

    let wanted = request.hooks.names();
    let hint_ids: Vec<Option<(u64, u64)>> =
        request.hints.iter().map(|h| hint_identity(h)).collect();
    let mut hint_matched = vec![false; request.hints.len()];

    let groups = if scannable {
        candidate_groups(&maps)
    } else {
        BTreeMap::new()
    };
    for (key, group) in groups {
        if budget.scan_stopped() {
            break;
        }
        if budget.check_deadline_now().is_some() {
            if let Some(reason) = budget.take_scan_stop_reason() {
                skipped.push(scan_skip("capture discovery", reason.into()));
            }
            break;
        }
        // A group with no `/`-rooted pathname (memfd, pseudo-path) is still a real
        // object: it is recorded as skipped rather than silently dropped.
        let named = group
            .iter()
            .find_map(|entry| match map_index.resolve(entry.start) {
                Resolved::File { path, raw_path, .. } => Some((path, raw_path)),
                _ => None,
            });
        let usable = match &named {
            Some((MappedPath::Usable(path), _)) => Some(path.clone()),
            _ => None,
        };
        // Path equality is the stronger evidence, so it wins when both hold.
        let matched: Vec<(usize, HintMatch)> = (0..request.hints.len())
            .filter_map(|index| {
                if usable.as_deref() == Some(request.hints[index].as_path()) {
                    Some((index, HintMatch::Path))
                } else if hint_ids[index].is_some_and(|(inode, _)| inode == key.inode) {
                    Some((index, HintMatch::Inode))
                } else {
                    None
                }
            })
            .collect();
        let hinted = !matched.is_empty();
        if !request.hints.is_empty() && !hinted {
            continue;
        }
        for (index, _) in &matched {
            hint_matched[*index] = true;
        }
        let subject = match &named {
            Some((_, raw_path)) => String::from_utf8_lossy(raw_path).into_owned(),
            None => format!(
                "device {}:{} inode {}",
                key.device.major, key.device.minor, key.inode
            ),
        };
        let Some(usable) = usable else {
            skipped.push(Skipped {
                subject,
                reason: match named {
                    Some((MappedPath::Unusable { reason }, _)) => reason,
                    _ => "no absolute pathname in /proc/<pid>/maps".into(),
                },
            });
            continue;
        };
        let path = usable.display().to_string();

        let file = match open_in_target(view, &path) {
            Ok(file) => file,
            Err(reason) => {
                skipped.push(Skipped { subject, reason });
                continue;
            }
        };
        // Corroborate an inode-only match before attributing the object to the hint.
        let actual_size = file.metadata().ok().map(|metadata| metadata.len());
        let mut refusal = None;
        let attributable = matched.iter().any(|(index, kind)| {
            match hint_gate(*kind, hint_ids[*index].map(|(_, size)| size), actual_size) {
                Ok(()) => true,
                Err(reason) => {
                    refusal = Some(reason);
                    false
                }
            }
        });
        if hinted && !attributable {
            skipped.push(Skipped {
                subject,
                reason: refusal
                    .unwrap_or_else(|| "no --module hint could be attributed here".into()),
            });
            continue;
        }
        let exports = match exports_matching(&file, &wanted) {
            Ok(exports) => exports,
            Err(reason) => {
                skipped.push(Skipped { subject, reason });
                continue;
            }
        };
        if request.hints.is_empty() && exports.is_empty() {
            continue;
        }
        let mut module = ScannedModule {
            view: view.id(),
            mount_namespace: view.mount_namespace(),
            key,
            path,
            exports: exports.into_iter().map(|(name, _)| name).collect(),
            tables: Vec::new(),
            interfaces: Vec::new(),
        };
        let Some(mem) = &mem else {
            modules.push(module);
            continue;
        };

        // Tables live in readable data pages: r-- (.data.rel.ro after RELRO) and rw-.
        let data: Vec<&MapEntry> = group
            .iter()
            .filter(|entry| entry.permissions[0] == b'r' && entry.permissions[2] != b'x')
            .copied()
            .collect();
        // One object never aborts the scan: unrepresentable sizes fail the cap check
        // below like any other over-budget object.
        let object_bytes = data.iter().try_fold(0u64, |sum, entry| {
            sum.checked_add(entry.end.checked_sub(entry.start)?)
        });
        if object_bytes.is_none_or(|bytes| bytes > budget.limits().per_object_bytes) {
            let object_bytes = object_bytes.map_or("unrepresentable".into(), |b| b.to_string());
            let limits = budget.limits();
            skipped.push(Skipped {
                subject,
                reason: format!(
                    "too_large ({object_bytes} readable data bytes; per-object cap is {})",
                    limits.per_object_bytes
                ),
            });
            modules.push(module);
            continue;
        }
        let mut snapshots = Vec::with_capacity(data.len());
        let mut operation_bytes = 0u64;
        let mut io_exhausted = false;
        for entry in &data {
            let (bytes, short, exhausted) = read_mapping(mem, entry, budget, &mut operation_bytes);
            // Bytes past a failed read were never examined; saying nothing here would
            // present a partial decode as a complete one.
            if let Some(reason) = short {
                skipped.push(scan_skip(&module.path, reason));
            }
            snapshots.push((entry.start, bytes));
            if exhausted {
                io_exhausted = true;
                break;
            }
        }
        for (base, snapshot) in &snapshots {
            let (tables, exhausted) = detect_tables(snapshot, *base, &map_index, budget);
            module.tables.extend(tables);
            skipped.extend(
                exhausted
                    .into_iter()
                    .map(|reason| scan_skip(&module.path, reason)),
            );
            if budget.scan_stopped() {
                break;
            }
        }
        if budget.scan_stopped() {
            modules.push(module);
            break;
        }
        for (_, snapshot) in &snapshots {
            let (interfaces, exhausted) = scan_interfaces(
                snapshot,
                mem,
                &module.tables,
                &map_index,
                key,
                budget,
                &mut operation_bytes,
            );
            module.interfaces.extend(interfaces);
            let interface_io_exhausted = exhausted.iter().any(|reason| reason == IO_CEILING_REASON);
            skipped.extend(
                exhausted
                    .into_iter()
                    .map(|reason| scan_skip(&module.path, reason)),
            );
            if interface_io_exhausted {
                io_exhausted = true;
                break;
            }
            if budget.scan_stopped() {
                break;
            }
        }
        for (index, interface) in module.interfaces.iter_mut().enumerate() {
            interface.index = index;
        }
        // A module that yielded nothing is owed an answer, whoever decided it was a
        // provider: an operator who named it with `--module`, or this scan itself,
        // which classified it by its exports and will report it in `discovery[]` and
        // `capture.modules[]` as a module the capture observed. Without this the
        // gap has nothing to show — no entry to skip, no attach to fail, no counter.
        if module.tables.is_empty() && !io_exhausted && !budget.scan_stopped() {
            let named = if hinted {
                "matched a --module hint; "
            } else {
                ""
            };
            skipped.push(Skipped {
                subject: module.path.clone(),
                reason: format!(
                    "{named}no function table was found in its file-backed data; a table \
                     built at run time in .bss or on the heap is outside the memory \
                     scan's reach"
                ),
            });
        }
        modules.push(module);
    }

    for (hint, matched) in request.hints.iter().zip(hint_matched) {
        if !matched {
            skipped.push(Skipped {
                subject: hint.display().to_string(),
                reason: "not mapped in the target".into(),
            });
        }
    }

    let outcome = match unavailable {
        None => ScanOutcome::Scanned {
            modules,
            skipped,
            scan_ms: started.elapsed().as_millis() as u64,
        },
        Some(reason) => ScanOutcome::Unavailable {
            reason,
            modules,
            skipped,
        },
    };
    view.run_while_same(|| ())?;
    Ok(outcome)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn source_pins_one_index_per_live_snapshot() {
        fn production_body<'a>(source: &'a str, start: &str, end: &str) -> &'a str {
            let source = &source[source.find(start).expect("production start marker")..];
            let body_start = source.find('{').expect("production body start");
            let body_end = source.find(end).expect("production end marker");
            &source[body_start..body_end]
        }

        let usable_path = production_body(
            include_str!("engine.rs"),
            "fn usable_path(",
            "\n}\n\n#[cfg(test)]\nfn exact_executable_mapping",
        );
        assert!(usable_path.contains("maps.resolve(mapping.start)"));
        assert!(!usable_path.contains("maps::resolve("));
        assert!(!usable_path.contains("resolve(&"));

        let index_maps_or_refuse = production_body(
            include_str!("scan.rs"),
            "pub(crate) fn index_maps_or_refuse<'a>(",
            "\n}\n\npub fn scan_pid(",
        );
        assert_eq!(
            index_maps_or_refuse.matches("MapIndex::new(").count(),
            1,
            "shared snapshot index must be constructed exactly once"
        );
    }

    /// Task 11 fix round 3 (shadow finding 5, scan branch). `parse_maps`,
    /// `MapIndex::new` and `candidate_groups` are each O(entries) on a snapshot
    /// the target sizes, and none of them charged or polled: a dense map could
    /// defer the capture's first check until after all three, and a stop that
    /// arrived before the scan broke the group loop with no published reason.
    /// The preprocessing is now charged and answers the stop before the first
    /// group, publishing exactly what stopped it.
    #[test]
    fn the_scan_charges_its_map_preprocessing_and_answers_the_stop_before_any_group() {
        let pid = std::process::id();
        let hooks = HookRegistry::builtin();
        let request = ScanRequest {
            pid,
            hints: &[],
            hooks: &hooks,
        };

        let mut budget = CaptureWorkBudget::default();
        assert!(
            !budget.charge(u64::MAX),
            "the work ceiling refuses and sticks"
        );
        let outcome = scan_pid(&request, &mut budget).expect("a stopped capture still scans");
        assert!(
            outcome.modules().is_empty(),
            "a stopped capture scans no group: {:?}",
            outcome.modules().len()
        );
        assert!(
            outcome
                .skipped()
                .iter()
                .any(|skip| skip.subject == "capture discovery"
                    && skip.reason == WORK_CEILING_REASON),
            "the stop is published, never a silent break: {:?}",
            outcome.skipped()
        );

        // The preprocessing itself is charged, one unit per snapshot entry: with
        // fewer units left than this process has mappings, the scan stops right
        // there. (The scan reads its own snapshot, so the allowance is one unit
        // short of the count read here — a mapping added in between only makes
        // the refusal more certain.)
        let mut budget = CaptureWorkBudget::default();
        let entries = parse_maps(&std::fs::read(format!("/proc/{pid}/maps")).unwrap())
            .unwrap()
            .len() as u64;
        assert!(budget.charge(DEFAULT_WORK_CEILING - entries + 1));
        let outcome = scan_pid(&request, &mut budget).expect("a scan of this process");
        assert!(
            outcome
                .skipped()
                .iter()
                .any(|skip| skip.subject == "capture discovery"
                    && skip.reason == WORK_CEILING_REASON),
            "the map preprocessing spends the last units and stops here: {:?}",
            outcome.skipped()
        );
        assert!(outcome.modules().is_empty());
    }

    /// Task 9.2-fix5 item A. A process that has already exited cannot have its
    /// memory read and cannot read any more of anyone else's: `scan_unavailable`
    /// records it, and a published skip would carry the pid in both its subject
    /// and its message, so a `--cgroup` capture of pkcs11-check's
    /// `--isolation file` shape published one undeduplicable public loss per
    /// finished subprocess. A refusal is a different thing entirely and stays
    /// loud.
    #[test]
    fn only_a_refusal_to_read_target_memory_is_a_published_loss() {
        use std::io::Error;

        assert_eq!(
            mem_unavailable(&Error::from_raw_os_error(libc::ESRCH)),
            ("gone", false)
        );
        assert_eq!(
            mem_unavailable(&Error::from_raw_os_error(libc::EACCES)),
            ("ptrace", true)
        );
        assert_eq!(
            mem_unavailable(&Error::from_raw_os_error(libc::EPERM)),
            ("ptrace", true)
        );
        assert_eq!(
            mem_unavailable(&Error::from_raw_os_error(libc::EIO)),
            ("unreadable", true)
        );
    }

    #[test]
    fn only_walkable_version_words_become_candidates() {
        // 67 / 68 / 92 / 104 slots + the version word, in bytes.
        for (word, expected) in [
            (0x0002u64, Some(((2u8, 0u8), 8 + 67 * 8))),
            (0x2802, Some(((2, 40), 8 + 68 * 8))),
            (0x0003, Some(((3, 0), 8 + 92 * 8))),
            (0x0203, Some(((3, 2), 8 + 104 * 8))),
        ] {
            let (version, spans, _) = spans_for(word).expect("walkable");
            assert_eq!(Some((version, span_bytes(spans).unwrap())), expected);
        }
        // Padding bytes set, implausible minor, unknown major, all-zero word.
        for word in [0x1_2802u64, 0x2902, 0x0304, 0x0004, 0] {
            assert!(spans_for(word).is_none(), "{word:#x} must not be a table");
        }
    }

    #[test]
    fn a_shorter_match_inside_a_longer_one_is_dropped() {
        let maps = parse_maps(b"1000-3000 r-xp 00000000 08:01 7 /lib/provider.so\n").unwrap();
        let map_index = MapIndex::new(&maps).unwrap();
        // A 3.2 table (104 slots) whose 68th..104th slots also start with a word that
        // reads as a valid 2.40 header would otherwise be reported twice.
        let mut snapshot = vec![0u8; 8 + 104 * 8];
        snapshot[..8].copy_from_slice(&0x0203u64.to_ne_bytes());
        for slot in 0..104 {
            let at = 8 + slot * 8;
            snapshot[at..at + 8].copy_from_slice(&0x1500u64.to_ne_bytes());
        }
        let inner = 8 + 30 * 8;
        snapshot[inner..inner + 8].copy_from_slice(&0x2802u64.to_ne_bytes());
        let (tables, truncated) = detect_tables(
            &snapshot,
            0x7000,
            &map_index,
            &mut CaptureWorkBudget::default(),
        );
        assert_eq!(tables.len(), 1);
        assert_eq!(tables[0].version, (3, 2));
        assert_eq!(tables[0].address, 0x7000);
        // The 2.40 header word is a NULL-looking non-pointer, so it is recorded as an
        // entry of the 3.2 table pointing into the provider's executable mapping.
        assert_eq!(tables[0].entries.len(), 104);
        assert!(truncated.is_empty(), "{truncated:?}");
    }

    #[test]
    fn a_header_whose_body_runs_past_the_snapshot_is_not_a_candidate() {
        let maps = parse_maps(b"1000-3000 r-xp 00000000 08:01 7 /lib/provider.so\n").unwrap();
        let map_index = MapIndex::new(&maps).unwrap();
        // A 2.40 header with only 10 of its 68 slots inside the snapshot: exactly the
        // shape of a table whose .bss has spilled into an anonymous mapping.
        let mut snapshot = vec![0u8; 8 + 10 * 8];
        snapshot[..8].copy_from_slice(&0x2802u64.to_ne_bytes());
        for slot in 0..10 {
            let at = 8 + slot * 8;
            snapshot[at..at + 8].copy_from_slice(&0x1500u64.to_ne_bytes());
        }
        let (tables, truncated) = detect_tables(
            &snapshot,
            0x7000,
            &map_index,
            &mut CaptureWorkBudget::default(),
        );
        assert!(tables.is_empty(), "an incomplete table is never decoded");
        assert!(truncated.is_empty(), "a version word alone is not evidence");
        // Ordinary data must not generate this diagnostic.
        assert!(
            detect_tables(
                &vec![0u8; 4096],
                0x7000,
                &map_index,
                &mut CaptureWorkBudget::default()
            )
            .1
            .is_empty()
        );
    }

    #[test]
    fn dense_candidates_and_interfaces_stop_at_capture_caps() {
        let maps = parse_maps(b"1000-3000 r-xp 00000000 08:01 7 /lib/provider.so\n").unwrap();
        let map_index = MapIndex::new(&maps).unwrap();
        let table_len = 8 + 104 * 8;
        let mut snapshot = vec![0u8; 513 * table_len];
        for table in 0..513 {
            let base = table * table_len;
            snapshot[base..base + 8].copy_from_slice(&0x0203u64.to_ne_bytes());
            for slot in 0..104 {
                let at = base + 8 + slot * 8;
                snapshot[at..at + 8].copy_from_slice(&0x1500u64.to_ne_bytes());
            }
        }
        let mut budget = CaptureWorkBudget::default();
        let (tables, skipped) = detect_tables(&snapshot, 0x7000, &map_index, &mut budget);
        assert_eq!(tables.len(), 512, "candidate amplification must be bounded");
        assert_eq!(
            tables
                .iter()
                .map(|table| table.entries.len())
                .sum::<usize>(),
            53_248,
            "decoded entry amplification must be bounded"
        );
        assert_eq!(skipped.len(), 1, "one bounded exhaustion result");

        let table = tables[0].clone();
        let mut interfaces = vec![0u8; 513 * INTERFACE_BYTES];
        for interface in 0..513 {
            let base = interface * INTERFACE_BYTES;
            interfaces[base + WORD..base + 2 * WORD].copy_from_slice(&table.address.to_ne_bytes());
        }
        let mem = tempfile::tempfile().unwrap();
        let mut operation_bytes = 0;
        let (interfaces, interface_skips) = scan_interfaces(
            &interfaces,
            &mem,
            &[table],
            &map_index,
            ObjectKey::of(&maps[0]),
            &mut budget,
            &mut operation_bytes,
        );
        assert_eq!(
            interfaces.len(),
            512,
            "interface amplification must be bounded"
        );
        assert_eq!(interface_skips.len(), 1, "one bounded exhaustion result");
        assert_eq!(
            interface_skips[0],
            "capture interface decode ceiling reached (512 records); remaining interface data \
             was not decoded"
        );
    }

    #[test]
    fn interface_address_index_keeps_the_first_duplicate_table() {
        let maps = parse_maps(b"1000-3000 r-xp 00000000 08:01 7 /lib/provider.so\n").unwrap();
        let map_index = MapIndex::new(&maps).unwrap();
        let tables = [
            ScannedTable {
                version: (2, 40),
                walk: "full",
                entries: Vec::new(),
                null_entries: Vec::new(),
                unpinned: Vec::new(),
                address: 0x7000,
                file_offset: Some(0),
            },
            ScannedTable {
                version: (3, 2),
                walk: "full",
                entries: Vec::new(),
                null_entries: Vec::new(),
                unpinned: Vec::new(),
                address: 0x7000,
                file_offset: Some(0),
            },
        ];
        let mut snapshot = vec![0u8; INTERFACE_BYTES];
        snapshot[WORD..2 * WORD].copy_from_slice(&0x7000u64.to_ne_bytes());
        let mem = tempfile::tempfile().unwrap();
        let mut operation_bytes = 0;
        let (interfaces, skipped) = scan_interfaces(
            &snapshot,
            &mem,
            &tables,
            &map_index,
            ObjectKey::of(&maps[0]),
            &mut CaptureWorkBudget::default(),
            &mut operation_bytes,
        );
        assert!(skipped.is_empty());
        assert_eq!(interfaces[0].table, Some(0));
    }

    #[test]
    fn interface_name_reads_share_the_capture_io_budget() {
        let maps = parse_maps(
            b"0-1000 r--p 00000000 08:01 7 /lib/provider.so\n\
              1000-3000 r-xp 00001000 08:01 7 /lib/provider.so\n",
        )
        .unwrap();
        let map_index = MapIndex::new(&maps).unwrap();
        let name_file = tempfile::NamedTempFile::new().unwrap();
        std::fs::write(name_file.path(), b"_PKCS 11\0").unwrap();
        let mem = File::open(name_file.path()).unwrap();
        let table = ScannedTable {
            version: (2, 40),
            walk: "full",
            entries: vec![],
            null_entries: vec![],
            unpinned: vec![],
            address: 0x7000,
            file_offset: Some(0),
        };
        let mut snapshot = vec![0u8; INTERFACE_BYTES];
        snapshot[..WORD].copy_from_slice(&1u64.to_ne_bytes());
        snapshot[WORD..2 * WORD].copy_from_slice(&table.address.to_ne_bytes());
        let mut budget = CaptureWorkBudget::new(ScanLimits {
            per_object_bytes: 64,
            total_bytes: 1,
        });
        let mut operation_bytes = 0;
        let (interfaces, skipped) = scan_interfaces(
            &snapshot,
            &mem,
            &[table],
            &map_index,
            ObjectKey::of(&maps[0]),
            &mut budget,
            &mut operation_bytes,
        );
        assert_eq!(interfaces.len(), 1);
        assert_eq!(interfaces[0].name_class, "unreadable");
        assert_eq!(budget.attempted_io_bytes(), 1);
        assert_eq!(
            skipped.len(),
            1,
            "the unread name remainder is one omission"
        );
        assert_eq!(skipped[0], IO_CEILING_REASON);
    }

    #[test]
    fn interface_name_in_non_absolute_mapping_is_not_dereferenced() {
        let maps = parse_maps(b"0-2000 r--p 00000000 08:01 7 provider.so\n").unwrap();
        let map_index = MapIndex::new(&maps).unwrap();
        let mem_file = tempfile::NamedTempFile::new().unwrap();
        std::fs::write(mem_file.path(), b"xPKCS 11\0").unwrap();
        let mem = File::open(mem_file.path()).unwrap();
        let table = ScannedTable {
            version: (2, 40),
            walk: "full",
            entries: Vec::new(),
            null_entries: Vec::new(),
            unpinned: Vec::new(),
            address: 0x7000,
            file_offset: Some(0),
        };
        let mut snapshot = vec![0u8; INTERFACE_BYTES];
        snapshot[..WORD].copy_from_slice(&1u64.to_ne_bytes());
        snapshot[WORD..2 * WORD].copy_from_slice(&table.address.to_ne_bytes());
        let mut budget = CaptureWorkBudget::default();
        let mut operation_bytes = 0;
        let (interfaces, skipped) = scan_interfaces(
            &snapshot,
            &mem,
            &[table],
            &map_index,
            ObjectKey::of(&maps[0]),
            &mut budget,
            &mut operation_bytes,
        );
        assert!(skipped.is_empty());
        assert_eq!(interfaces.len(), 1);
        assert_eq!(interfaces[0].name_class, "unreadable");
        assert_eq!(operation_bytes, 0);
        assert_eq!(budget.attempted_io_bytes(), 0);
    }

    /// Case 3 is the one that matters and the one no end-to-end test can reach here:
    /// a hint naming a path that exists only inside the target's mount namespace has no
    /// local identity at all, so the size gate must not apply to it. Reproducing that
    /// for real needs a container or a second mount namespace, which this slice's tests
    /// deliberately do not require; the docker gate in a later task exercises it.
    #[test]
    fn only_an_inode_match_is_gated_on_size() {
        // 1. Inode match, sizes agree.
        assert_eq!(hint_gate(HintMatch::Inode, Some(4096), Some(4096)), Ok(()));
        // 2. Inode match, sizes differ: refused, and the reason names the collision.
        let refused = hint_gate(HintMatch::Inode, Some(4096), Some(8192)).unwrap_err();
        assert!(
            refused.contains("inode number")
                && refused.contains("4096")
                && refused.contains("8192")
                && refused.contains("reused on another filesystem"),
            "{refused}"
        );
        // 3. Path match with no local identity (containerized target): accepted.
        assert_eq!(hint_gate(HintMatch::Path, None, Some(8192)), Ok(()));
        // A path match is never gated on size even when both sizes are known.
        assert_eq!(hint_gate(HintMatch::Path, Some(1), Some(2)), Ok(()));
        // An inode match cannot arise without a local identity, but must not be
        // silently accepted if one ever did.
        assert!(hint_gate(HintMatch::Inode, None, Some(8192)).is_err());
    }

    #[test]
    fn a_short_read_returns_what_it_got_and_says_why_it_stopped() {
        let file = tempfile::NamedTempFile::new().unwrap();
        std::fs::write(file.path(), vec![7u8; 64]).unwrap();
        let mem = File::open(file.path()).unwrap();
        let entry = &parse_maps(b"0-1000 rw-p 00000000 08:01 7 /lib/provider.so\n").unwrap()[0];
        let (bytes, short, exhausted) =
            read_mapping(&mem, entry, &mut CaptureWorkBudget::default(), &mut 0);
        assert!(!exhausted);
        assert_eq!(bytes, vec![7u8; 64], "what was read is kept");
        let short = short.expect("a short snapshot must say so");
        assert!(
            short.contains("read 64 of 4096 bytes") && short.contains("no bytes"),
            "{short}"
        );
    }

    #[test]
    fn a_pointer_into_data_or_nowhere_rejects_the_whole_candidate() {
        let maps = parse_maps(
            b"1000-2000 r-xp 00000000 08:01 7 /lib/provider.so\n\
              2000-3000 rw-p 00001000 08:01 7 /lib/provider.so\n",
        )
        .unwrap();
        let map_index = MapIndex::new(&maps).unwrap();
        let build = |bad: u64| {
            let mut snapshot = vec![0u8; 8 + 68 * 8];
            snapshot[..8].copy_from_slice(&0x2802u64.to_ne_bytes());
            for slot in 0..68 {
                let at = 8 + slot * 8;
                snapshot[at..at + 8].copy_from_slice(&0x1500u64.to_ne_bytes());
            }
            snapshot[8..16].copy_from_slice(&bad.to_ne_bytes());
            snapshot
        };
        assert_eq!(
            detect_tables(
                &build(0x1600),
                0x2000,
                &map_index,
                &mut CaptureWorkBudget::default()
            )
            .0
            .len(),
            1
        );
        assert!(
            detect_tables(
                &build(0x2500),
                0x2000,
                &map_index,
                &mut CaptureWorkBudget::default()
            )
            .0
            .is_empty()
        ); // rw- data
        assert!(
            detect_tables(
                &build(0x9000),
                0x2000,
                &map_index,
                &mut CaptureWorkBudget::default()
            )
            .0
            .is_empty()
        ); // unmapped
        // Every slot NULL: a zeroed page is not a table.
        assert!(
            detect_tables(
                &vec![0u8; 8 + 68 * 8],
                0x2000,
                &map_index,
                &mut CaptureWorkBudget::default()
            )
            .0
            .is_empty()
        );
        // One NULL slot among live ones is legitimate evidence, not a rejection.
        let mut with_null = build(0x1600);
        with_null[16..24].copy_from_slice(&0u64.to_ne_bytes());
        let (tables, _) = detect_tables(
            &with_null,
            0x2000,
            &map_index,
            &mut CaptureWorkBudget::default(),
        );
        assert_eq!(tables[0].null_entries.len(), 1);
        assert_eq!(tables[0].entries.len(), 67);
    }

    #[test]
    fn exact_table_addresses_keep_non_null_fields_in_canonical_order() {
        let mut snapshot = vec![0u8; 8 + 68 * 8];
        snapshot[..8].copy_from_slice(&0x2802u64.to_ne_bytes());
        snapshot[8..16].copy_from_slice(&0x1110u64.to_ne_bytes());
        snapshot[16..24].copy_from_slice(&0u64.to_ne_bytes());
        snapshot[24..32].copy_from_slice(&0x3330u64.to_ne_bytes());

        assert_eq!(exact_table_addresses(&snapshot).unwrap(), [0x1110, 0x3330]);
    }

    #[test]
    fn work_budget_allows_exact_ceiling_and_rejects_overflow() {
        let mut budget = CaptureWorkBudget {
            work_ceiling: 4,
            ..Default::default()
        };
        assert!(budget.charge(4));
        assert!(!budget.charge(1));
        budget.work_units = u64::MAX;
        assert!(!budget.charge(1));
    }

    #[test]
    fn near_miss_field_validation_stops_at_work_ceiling() {
        let maps = parse_maps(b"1000-3000 r-xp 00000000 08:01 7 /lib/provider.so\n").unwrap();
        let map_index = MapIndex::new(&maps).unwrap();
        let mut snapshot = vec![0u8; 8 + 104 * 8];
        snapshot[..8].copy_from_slice(&0x0203u64.to_ne_bytes());
        for slot in 0..104 {
            let at = 8 + slot * 8;
            snapshot[at..at + 8].copy_from_slice(&0x1500u64.to_ne_bytes());
        }
        snapshot[8 + 103 * 8..8 + 104 * 8].copy_from_slice(&0x9000u64.to_ne_bytes());
        let mut budget = CaptureWorkBudget {
            work_ceiling: 104,
            ..Default::default()
        };
        let (tables, skipped) = detect_tables(&snapshot, 0x7000, &map_index, &mut budget);
        assert!(tables.is_empty());
        assert_eq!(skipped, vec![WORK_CEILING_REASON]);
    }

    #[test]
    fn taking_an_empty_stop_does_not_hide_a_later_work_stop() {
        let mut budget = CaptureWorkBudget {
            work_ceiling: 0,
            ..Default::default()
        };
        assert_eq!(budget.take_scan_stop_reason(), None);
        assert!(!budget.charge(1));
        assert_eq!(budget.take_scan_stop_reason(), Some(WORK_CEILING_REASON));
        assert_eq!(budget.take_scan_stop_reason(), None);
    }

    #[test]
    fn deadline_polling_uses_the_local_window_boundary_after_variable_work() {
        let maps = parse_maps(b"1000-3000 r-xp 00000000 08:01 7 /lib/provider.so\n").unwrap();
        let map_index = MapIndex::new(&maps).unwrap();
        let second_offset = 4095 * WORD;
        let mut snapshot = vec![0u8; second_offset + 8 + 104 * WORD];
        for offset in [0, second_offset] {
            snapshot[offset..offset + 8].copy_from_slice(&0x0203u64.to_ne_bytes());
            for slot in 0..104 {
                let at = offset + 8 + slot * WORD;
                snapshot[at..at + WORD].copy_from_slice(&0x1500u64.to_ne_bytes());
            }
        }
        let mut budget = CaptureWorkBudget::default();
        budget.set_deadline(Some(10));
        let mut polls = 0;
        let (tables, skipped) =
            detect_tables_with_clock(&snapshot, 0x7000, &map_index, &mut budget, || {
                polls += 1;
                Some(if polls == 1 { 0 } else { 10 })
            });
        assert_eq!(polls, 2, "initial and next local 4096-window boundary");
        assert!(
            tables
                .iter()
                .any(|table| table.address == 0x7000 + second_offset as u64)
        );
        assert_eq!(skipped, vec![SCAN_DEADLINE_REASON]);
    }

    #[test]
    fn maps_reader_distinguishes_eof_byte_entry_io_and_deadline_bounds() {
        use std::io::Cursor;

        let run = |input: &[u8], max_bytes, max_entries, total_bytes, clock: Vec<Option<u64>>| {
            let mut budget = CaptureWorkBudget::new(ScanLimits {
                per_object_bytes: u64::MAX,
                total_bytes,
            });
            budget.set_deadline(Some(5));
            let mut clock = clock.into_iter();
            read_maps_with_limits(
                Cursor::new(input),
                &mut budget,
                max_bytes,
                max_entries,
                4,
                || clock.next().unwrap_or(Some(0)),
            )
            .unwrap()
        };

        let (_, reasons) = run(b"aa\nbb\n", 6, 10, 100, vec![Some(0), Some(0), Some(0)]);
        assert!(
            reasons.is_empty(),
            "exact EOF is not a byte cut: {reasons:?}"
        );

        let (bytes, reasons) = run(b"aa\nbb\n", 5, 10, 100, vec![Some(0), Some(0), Some(0)]);
        assert_eq!(bytes, b"aa\n");
        assert!(reasons.contains(&MAPS_CEILING_REASON));

        let (bytes, reasons) = run(b"aa\nbb\n", 100, 1, 100, vec![Some(0), Some(0), Some(0)]);
        assert_eq!(bytes, b"aa\n");
        assert!(reasons.contains(&MAPS_ENTRY_CEILING_REASON));

        let (bytes, reasons) = run(b"aa\nbb\n", 100, 10, 3, vec![Some(0), Some(0), Some(0)]);
        assert_eq!(bytes, b"aa\n");
        assert!(reasons.contains(&IO_CEILING_REASON));

        let (bytes, reasons) = run(b"aa\nbb\n", 5, 1, 100, vec![Some(0), Some(0), Some(10)]);
        assert_eq!(bytes, b"aa\n");
        assert!(reasons.contains(&MAPS_CEILING_REASON));
        assert!(reasons.contains(&MAPS_ENTRY_CEILING_REASON));
    }

    #[test]
    fn maps_reader_trims_incomplete_lines_on_deadline_and_clock_failure() {
        use std::io::Cursor;

        for (clock, reason) in [
            (vec![Some(0), Some(10)], SCAN_DEADLINE_REASON),
            (vec![Some(0), None], SCAN_CLOCK_REASON),
        ] {
            let mut budget = CaptureWorkBudget::new(ScanLimits::default());
            budget.set_deadline(Some(5));
            let mut clock = clock.into_iter();
            let (bytes, reasons) =
                read_maps_with_limits(Cursor::new(b"aa\nbb\n"), &mut budget, 100, 10, 4, || {
                    clock.next().unwrap_or(Some(0))
                })
                .unwrap();
            assert_eq!(bytes, b"aa\n");
            assert!(reasons.contains(&reason), "{reasons:?}");
        }
    }

    /// Task 11 fix round 2 (csf_ce5962b root closure): the live engine's
    /// per-record snapshot is refused whole — never trimmed — at the byte,
    /// entry, and total-I/O ceilings and at the batch deadline; an already
    /// expired deadline refuses before a byte is read, on every read of the
    /// stopped batch, not only the once the reader reports it.
    #[test]
    fn live_maps_snapshot_is_refused_whole_at_every_bound() {
        use std::io::Cursor;

        let line: &[u8] = b"7f0000000000-7f0000001000 r-xp 00000000 08:01 12345 /opt/p.so\n";
        let snapshot = |budget: &mut CaptureWorkBudget, input: &[u8], clock: Vec<Option<u64>>| {
            let mut clock = clock.into_iter();
            read_maps_or_refuse(Cursor::new(input), budget, || {
                clock.next().unwrap_or(Some(0))
            })
        };

        // Lines long enough that the byte ceiling lands before the entry ceiling.
        let long_line = [&line[..line.len() - 1], &[b'p'; 64][..], b"\n"].concat();
        let oversized =
            long_line.repeat(usize::try_from(MAX_MAPS_BYTES).unwrap() / long_line.len() + 1);
        assert!(u64::try_from(oversized.len()).unwrap() > MAX_MAPS_BYTES);
        let mut budget = CaptureWorkBudget::default();
        assert_eq!(
            snapshot(&mut budget, &oversized, vec![]).err(),
            Some(MAPS_CEILING_REASON.into()),
            "one byte over the byte ceiling is refused, not trimmed"
        );

        let short_line: &[u8] = b"0-1 ---p 0 0:0 0\n";
        let mut budget = CaptureWorkBudget::default();
        assert_eq!(
            snapshot(&mut budget, &short_line.repeat(MAX_MAP_ENTRIES + 1), vec![]).err(),
            Some(MAPS_ENTRY_CEILING_REASON.into()),
            "one entry over the entry ceiling is refused, not trimmed"
        );

        let mut budget = CaptureWorkBudget::new(ScanLimits {
            per_object_bytes: u64::MAX,
            total_bytes: 8,
        });
        assert_eq!(
            snapshot(&mut budget, &line.repeat(2), vec![]).err(),
            Some(IO_CEILING_REASON.into()),
            "the capture's total-I/O ceiling refuses the snapshot"
        );

        let mut budget = CaptureWorkBudget::default();
        budget.set_deadline(Some(5));
        assert_eq!(
            snapshot(
                &mut budget,
                &line.repeat(2),
                vec![Some(0), Some(0), Some(10)]
            )
            .err(),
            Some(SCAN_DEADLINE_REASON.into()),
            "a deadline reached during the read refuses the snapshot"
        );

        let mut budget = CaptureWorkBudget::default();
        budget.set_deadline(Some(5));
        for attempt in 1..=2 {
            assert_eq!(
                snapshot(&mut budget, line, vec![Some(10)]).err(),
                Some(SCAN_DEADLINE_REASON.into()),
                "read {attempt} of a stopped batch is refused"
            );
            assert_eq!(
                budget.attempted_io_bytes(),
                0,
                "read {attempt} read nothing"
            );
        }

        let mut budget = CaptureWorkBudget::default();
        let entries = snapshot(&mut budget, line, vec![]).unwrap();
        assert_eq!(entries.len(), 1);
        assert_eq!(
            budget.attempted_io_bytes(),
            u64::try_from(line.len()).unwrap(),
            "a complete snapshot is charged to the capture's I/O total"
        );
    }
}
