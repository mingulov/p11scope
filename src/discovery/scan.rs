//! SPDX-License-Identifier: GPL-3.0-or-later
//! Finding PKCS#11 function tables by reading the target's mapped memory. No provider
//! code is executed and nothing is copied: `/proc/<pid>/maps` says what is mapped,
//! `.dynsym` says which objects could hand out a table, and the target's own
//! non-executable pages are searched for the `CK_FUNCTION_LIST` signature. Table
//! layout comes from `pkcs11_module::tables_for`/`read_fn_pointers` — the same
//! authority the offline helper uses — so a scanned offset equals a manifest offset.

use crate::discovery::hooks::HookRegistry;
use crate::discovery::identity::{Pin, pin_of};
use crate::process::{MountNamespaceId, ProcessView, ProcessViewId};
use p11scope_manifest::elf::{ElfAbi, ElfSnapshot};
use p11scope_manifest::identity::{InspectedObject, open_object};
use p11scope_manifest::maps::{
    Device, MapEntry, MapIndex, MappedPath, ObjectKey, Resolved, parse_maps,
};
use pkcs11_module::{
    LinuxLayout, Surface, TableSet, TableSpan, function_name, read_function_pointer, read_word_le,
    table_bytes, tables_for,
};
use std::collections::{BTreeMap, BTreeSet, HashMap};
use std::fs::File;
use std::io::Read;
use std::os::unix::fs::{FileExt as _, MetadataExt as _};
use std::path::{Path, PathBuf};
use std::time::Instant;

const INTERFACE_NAME_CAP: usize = 64;
#[cfg(test)]
const WORD: usize = 8;
#[cfg(test)]
const INTERFACE_BYTES: usize = 3 * WORD;
const READ_CHUNK: usize = 1024 * 1024;
const STANDARD_INTERFACE_NAME: &[u8] = b"PKCS 11";
const MAX_TABLE_CANDIDATES: usize = 512;
const MAX_DECODED_TABLE_ENTRIES: usize = 512 * 104;
const MAX_INTERFACE_RECORDS: usize = 512;
const MAX_MAPS_BYTES: u64 = 64 * 1024 * 1024;
const MAX_MAP_ENTRIES: usize = 1_048_576;
const MAX_MOUNTINFO_BYTES: u64 = 64 * 1024 * 1024;
const MAX_MOUNTINFO_ENTRIES: usize = 1_048_576;
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
pub(crate) const MOUNTINFO_CEILING_REASON: &str =
    "capture mountinfo byte ceiling reached; the incomplete mount table was refused";
pub(crate) const MOUNTINFO_ENTRY_CEILING_REASON: &str =
    "capture mountinfo entry ceiling reached; the incomplete mount table was refused";

pub(crate) fn target_layout(abi: ElfAbi) -> LinuxLayout {
    match abi {
        ElfAbi::Lp64 => LinuxLayout::Lp64,
        ElfAbi::Ilp32 => LinuxLayout::Ilp32,
    }
}

pub(crate) fn read_elf_snapshot(
    file: &File,
    budget: &mut CaptureWorkBudget,
) -> Result<ElfSnapshot, String> {
    read_elf_snapshot_with(
        file,
        budget,
        CaptureWorkBudget::check_deadline_now,
        |file, bytes, offset| file.read_at(bytes, offset),
    )
}

fn read_elf_snapshot_with(
    file: &File,
    budget: &mut CaptureWorkBudget,
    mut deadline: impl FnMut(&mut CaptureWorkBudget) -> Option<&'static str>,
    mut reader: impl FnMut(&File, &mut [u8], u64) -> std::io::Result<usize>,
) -> Result<ElfSnapshot, String> {
    let size = file
        .metadata()
        .map_err(|error| format!("metadata failed: {error}"))?
        .len();
    if size > budget.limits().per_object_bytes {
        return Err(format!(
            "too_large ({size} bytes; per-object cap is {})",
            budget.limits().per_object_bytes,
        ));
    }
    let mut operation_bytes = 0u64;
    ElfSnapshot::read_with_reader(file, |file, bytes, offset| {
        if let Some(reason) = deadline(budget) {
            return Err(std::io::Error::other(reason));
        }
        let allowed = budget.allowed_io(operation_bytes, bytes.len());
        if allowed == 0 {
            return Err(std::io::Error::other(IO_CEILING_REASON));
        }
        let read = reader(file, &mut bytes[..allowed], offset)?;
        budget.record_io(read);
        operation_bytes += read as u64;
        Ok(read)
    })
}

/// Demand-paged export facts for the scan path: the ELF tables are queried
/// through a mapping instead of a whole-file snapshot, so no whole-size gate
/// applies here. The table charge posts to the capture budget all-or-nothing:
/// when the remaining capture allowance cannot cover it, the path reports the
/// identical ceiling skip a mid-read abort produces, and the budget saturates.
fn read_export_facts_budgeted(
    file: &File,
    wanted: &[&str],
    budget: &mut CaptureWorkBudget,
) -> Result<(ElfAbi, Vec<(String, u64)>), String> {
    let (abi, exports, charged) = p11scope_manifest::elf::read_export_facts(file, wanted)?;
    let remaining = budget
        .limits()
        .total_bytes
        .saturating_sub(budget.attempted_io_bytes());
    if charged > remaining {
        budget.record_io(usize::try_from(remaining).unwrap_or(usize::MAX));
        return Err(format!("read failed: {IO_CEILING_REASON}"));
    }
    budget.record_io(usize::try_from(charged).unwrap_or(usize::MAX));
    Ok((abi, exports))
}

pub(crate) fn read_mountinfo<R: Read>(
    reader: R,
    budget: &mut CaptureWorkBudget,
) -> Result<String, String> {
    read_mountinfo_with(
        reader,
        budget,
        READ_CHUNK,
        CaptureWorkBudget::check_deadline_now,
    )
}

pub(crate) fn read_mountinfo_with<R: Read>(
    mut reader: R,
    budget: &mut CaptureWorkBudget,
    chunk_size: usize,
    mut deadline: impl FnMut(&mut CaptureWorkBudget) -> Option<&'static str>,
) -> Result<String, String> {
    let table_cap = budget.limits().per_object_bytes.min(MAX_MOUNTINFO_BYTES);
    if table_cap == 0 {
        return Err(MOUNTINFO_CEILING_REASON.into());
    }

    let mut table = Vec::new();
    let mut observed_lines = 0usize;
    let mut newline_count = 0usize;
    let mut chunk = vec![0; chunk_size.max(1)];
    loop {
        if let Some(reason) = budget.scan_stop_reason {
            return Err(reason.into());
        }
        if let Some(reason) = deadline(budget) {
            return Err(reason.into());
        }

        let capture_left = budget
            .limits()
            .total_bytes
            .saturating_sub(budget.attempted_io_bytes());
        if capture_left == 0 {
            return Err(IO_CEILING_REASON.into());
        }
        let table_bytes = u64::try_from(table.len()).unwrap_or(u64::MAX);
        let table_left = table_cap.saturating_sub(table_bytes);
        let wanted = u64::try_from(chunk.len())
            .unwrap_or(u64::MAX)
            .min(capture_left)
            .min(table_left.saturating_add(1));
        let wanted = usize::try_from(wanted).unwrap_or(chunk.len());
        if wanted == 0 {
            return Err(MOUNTINFO_CEILING_REASON.into());
        }
        budget.spend(1).map_err(str::to_string)?;

        let read = match reader.read(&mut chunk[..wanted]) {
            Ok(read) => read,
            Err(error) if error.kind() == std::io::ErrorKind::Interrupted => continue,
            Err(error) => return Err(format!("cannot read mount table: {error}")),
        };
        budget.record_io(read);
        if read == 0 {
            if let Some(reason) = deadline(budget) {
                return Err(reason.into());
            }
            return String::from_utf8(table)
                .map_err(|error| format!("mount table is not valid UTF-8: {error}"));
        }

        let next_len = table
            .len()
            .checked_add(read)
            .ok_or_else(|| MOUNTINFO_CEILING_REASON.to_string())?;
        let newlines = chunk[..read].iter().filter(|byte| **byte == b'\n').count();
        let next_newline_count = newline_count
            .checked_add(newlines)
            .ok_or_else(|| MOUNTINFO_ENTRY_CEILING_REASON.to_string())?;
        let next_lines = next_newline_count
            .checked_add(usize::from(chunk[read - 1] != b'\n'))
            .ok_or_else(|| MOUNTINFO_ENTRY_CEILING_REASON.to_string())?;
        let added_lines = next_lines.saturating_sub(observed_lines);
        budget
            .spend(u64::try_from(added_lines).unwrap_or(u64::MAX))
            .map_err(str::to_string)?;
        if u64::try_from(next_len).unwrap_or(u64::MAX) > table_cap {
            return Err(MOUNTINFO_CEILING_REASON.into());
        }
        if next_lines > MAX_MOUNTINFO_ENTRIES {
            return Err(MOUNTINFO_ENTRY_CEILING_REASON.into());
        }
        table.extend_from_slice(&chunk[..read]);
        newline_count = next_newline_count;
        observed_lines = next_lines;
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ScanLimits {
    pub per_object_bytes: u64,
    pub total_bytes: u64,
}

impl Default for ScanLimits {
    fn default() -> Self {
        Self {
            // Measured (cgroup-256 Task 5, 2026-09-17): libxul.so is
            // 183,575,264 bytes on disk with 63,639,548 readable data bytes,
            // so the old 64 MiB cap refused its snapshots and held its data
            // at a 5% margin. 256 MiB covers the largest known real-world
            // object with headroom, matches the manifest per-object cap
            // (`MAX_OBJECT_BYTES`), and still refuses absurd files; the
            // unchanged 512 MiB total keeps bounding the worst case.
            per_object_bytes: 256 * 1024 * 1024,
            total_bytes: 512 * 1024 * 1024,
        }
    }
}

/// Identity of one decoded provider table: the file holding its version word
/// plus the word and the decoded extent. Repeats skip the candidate+entry
/// admission charge but still decode per view — this key is never a decode
/// cache: runtime addresses stay out because they are generation-local.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub(crate) struct TableIdentity {
    pub(crate) device: Device,
    pub(crate) inode: u64,
    pub(crate) file_offset: u64,
    pub(crate) version_word: u64,
    pub(crate) usable: usize,
}

/// The cached inspection of one file: exactly what `inspect_file_with_reader`
/// returns. Only the digest-sized result is kept, never the file bytes.
pub(crate) type InspectedFile = InspectedObject;

/// Identity of one inspected file: the maps-comparable (device, inode) plus the
/// `(ino, size, ctime)` pin the inspection was read under. A repeat pin of the
/// unchanged file reuses the cached inspection with zero reads; a changed file
/// misses and is read (and charged) again.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub(crate) struct InspectedFileKey {
    pub(crate) device: Device,
    pub(crate) inode: u64,
    pub(crate) pin: Pin,
}

/// The digest-sized facts one ELF contributes to every scan: its ABI plus the
/// `(name, file offset)` exports matching the capture's hook names. File-derived
/// only — safe to share across views the way the raw snapshot never is.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct ElfExportFacts {
    pub(crate) abi: ElfAbi,
    pub(crate) exports: Vec<(String, u64)>,
}

/// One capture's concrete discovery allowance. Memory snapshots and file hashes
/// spend the same byte total; cardinality counters stop decoded-record amplification.
#[derive(Debug)]
pub struct CaptureWorkBudget {
    limits: ScanLimits,
    attempted_io_bytes: u64,
    table_candidates: usize,
    decoded_table_entries: usize,
    admitted_tables: BTreeSet<TableIdentity>,
    inspected_files: BTreeMap<InspectedFileKey, InspectedFile>,
    elf_export_facts: BTreeMap<InspectedFileKey, ElfExportFacts>,
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
            admitted_tables: BTreeSet::new(),
            inspected_files: BTreeMap::new(),
            elf_export_facts: BTreeMap::new(),
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

    pub(crate) fn table_already_admitted(&self, id: &TableIdentity) -> bool {
        self.admitted_tables.contains(id)
    }

    pub(crate) fn note_table_admitted(&mut self, id: TableIdentity) {
        self.admitted_tables.insert(id);
    }

    pub(crate) fn inspected_file(&self, key: &InspectedFileKey) -> Option<InspectedFile> {
        self.inspected_files.get(key).cloned()
    }

    pub(crate) fn note_inspected_file(&mut self, key: InspectedFileKey, value: InspectedFile) {
        self.inspected_files.insert(key, value);
    }

    pub(crate) fn elf_export_facts_for(&self, key: &InspectedFileKey) -> Option<ElfExportFacts> {
        self.elf_export_facts.get(key).cloned()
    }

    pub(crate) fn note_elf_export_facts(&mut self, key: InspectedFileKey, value: ElfExportFacts) {
        self.elf_export_facts.insert(key, value);
    }

    #[cfg(test)]
    pub(crate) fn table_candidates_count(&self) -> usize {
        self.table_candidates
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
    /// ABI used by the userspace memory decoder. Present only when this module
    /// came from `scan_process_view`; mapping and kernel-record projections do
    /// not manufacture this provenance.
    #[doc(hidden)]
    pub decoder_abi: Option<ElfAbi>,
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

/// Publication evidence for one candidate table, strongest first: a table
/// named by an interface triple outranks a live-return address match, which
/// outranks a manifest offset match, which outranks bare size/version
/// plausibility. Field order is the priority — the derived `Ord` sorts the
/// strongest score last, so admission ordering reverses it.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub(crate) struct TableEvidenceScore {
    pub(crate) linked: bool,
    pub(crate) live_return: bool,
    pub(crate) manifest: bool,
    pub(crate) full_walk: bool,
}

/// Pure evidence score for the candidate at `index`: interface linkage (via
/// `ScannedInterface.table`) first, then live-return identity, then manifest
/// offset, then walk plausibility. No I/O — every input is already-decoded
/// scan data or caller-held evidence.
pub(crate) fn table_evidence_score(
    index: usize,
    tables: &[ScannedTable],
    interfaces: &[ScannedInterface],
    live_return_addresses: &[u64],
    manifest_offsets: &[u64],
) -> TableEvidenceScore {
    let table = &tables[index];
    TableEvidenceScore {
        linked: interfaces
            .iter()
            .any(|interface| interface.table == Some(index)),
        live_return: live_return_addresses.contains(&table.address),
        manifest: table
            .file_offset
            .is_some_and(|offset| manifest_offsets.contains(&offset)),
        full_walk: table.walk == "full",
    }
}

/// Indices of `tables` strongest-evidence first. Stable: equal evidence keeps
/// discovery order, so scoring never reorders what it cannot distinguish.
pub(crate) fn order_tables_by_evidence(
    tables: &[ScannedTable],
    interfaces: &[ScannedInterface],
    live_return_addresses: &[u64],
    manifest_offsets: &[u64],
) -> Vec<usize> {
    let mut order: Vec<usize> = (0..tables.len()).collect();
    order.sort_by_cached_key(|&index| {
        std::cmp::Reverse(table_evidence_score(
            index,
            tables,
            interfaces,
            live_return_addresses,
            manifest_offsets,
        ))
    });
    order
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
fn span_bytes(layout: LinuxLayout, spans: &[TableSpan]) -> Option<usize> {
    table_bytes(layout, spans.iter().map(|span| span.fields().len()).sum()).ok()
}

pub(crate) fn exact_table_bytes(header: &[u8], layout: LinuxLayout) -> Option<usize> {
    let word = read_word_le(header, layout, 0).ok()?;
    let (_, spans, _) = spans_for(word)?;
    span_bytes(layout, spans)
}

/// Returns every non-NULL function pointer in one complete table snapshot.
/// Addresses are capture-local and are used only to close the maps-A/maps-B
/// stability bracket; callers must not persist them as identity.
pub(crate) fn exact_table_addresses(snapshot: &[u8], layout: LinuxLayout) -> Option<Vec<u64>> {
    let word = read_word_le(snapshot, layout, 0).ok()?;
    let (_, spans, _) = spans_for(word)?;
    let mut addresses = Vec::new();
    for ordinal in 0..spans.iter().map(|span| span.fields().len()).sum() {
        let address = read_function_pointer(snapshot, layout, ordinal).ok()?;
        if address != 0 {
            addresses.push(address);
        }
    }
    Some(addresses)
}

/// Decodes one candidate at `offset` inside `snapshot` (whose first byte is at
/// `base_address` in the target). Returns the table only when every published slot
/// is either NULL or points into a file-backed executable mapping — the criterion
/// that makes a run of pointers a function table rather than data that looks like one.
fn decode_candidate(
    layout: LinuxLayout,
    snapshot: &[u8],
    offset: usize,
    base_address: u64,
    maps: &MapIndex<'_>,
    budget: &mut CaptureWorkBudget,
) -> Result<Option<(ScannedTable, usize)>, ()> {
    let width = layout.word_bytes();
    let Some(raw_word) = offset
        .checked_add(width)
        .and_then(|end| snapshot.get(offset..end))
    else {
        return Ok(None);
    };
    let word = read_word_le(raw_word, layout, 0).expect("one target word");
    let Some((version, spans, walk)) = spans_for(word) else {
        return Ok(None);
    };
    let Some(len) = span_bytes(layout, spans) else {
        return Ok(None);
    };
    let Some(address) = base_address.checked_add(offset as u64) else {
        return Ok(None);
    };
    let table_owner = match maps.resolve(address) {
        Resolved::File {
            device,
            inode,
            file_offset,
            ..
        } => Some((device, inode, file_offset)),
        _ => None,
    };
    let file_offset = table_owner.map(|(_, _, file_offset)| file_offset);
    let Some(bytes) = offset
        .checked_add(len)
        .and_then(|end| snapshot.get(offset..end))
    else {
        return Ok(None);
    };

    // Validate the whole candidate before reserving or allocating decoded records.
    let mut non_null = 0usize;
    let field_count = spans.iter().map(|span| span.fields().len()).sum();
    for ordinal in 0..field_count {
        if !budget.charge(1) {
            return Err(());
        }
        let Ok(value) = read_function_pointer(bytes, layout, ordinal) else {
            return Ok(None);
        };
        if value == 0 {
            continue;
        }
        non_null += 1;
        let Resolved::File {
            permissions, path, ..
        } = maps.resolve(value)
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
    if non_null == 0 {
        return Ok(None);
    }
    let decoded_entries = spans.iter().map(|span| span.fields().len()).sum();
    // Byte-identical repeats skip the candidate+entry charge but still decode
    // below; without a stable file owner there is no identity, so charge.
    let identity =
        table_owner
            .filter(|(_, inode, _)| *inode != 0)
            .map(|(device, inode, file_offset)| TableIdentity {
                device,
                inode,
                file_offset,
                version_word: word,
                usable: decoded_entries,
            });
    let repeat = identity
        .as_ref()
        .is_some_and(|id| budget.table_already_admitted(id));
    if !repeat {
        if !budget.admit_table(decoded_entries) {
            return Err(());
        }
        if let Some(id) = identity {
            budget.note_table_admitted(id);
        }
    }

    let mut entries = Vec::with_capacity(non_null);
    let mut null_entries = Vec::with_capacity(decoded_entries - non_null);
    for ordinal in 0..field_count {
        let name = function_name(ordinal).expect("validated shared field count");
        let value = read_function_pointer(bytes, layout, ordinal).expect("validated above");
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
        } = maps.resolve(value)
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
    layout: LinuxLayout,
    maps: &MapIndex<'_>,
    budget: &mut CaptureWorkBudget,
) -> Result<Option<ScannedTable>, ()> {
    decode_candidate(layout, snapshot, 0, address, maps, budget)
        .map(|decoded| decoded.map(|(table, _)| table))
}

/// Every 8-byte-aligned candidate in one snapshot, longest match kept on overlap.
/// The second return carries the one bounded exhaustion reason, if decoding stopped.
#[cfg(test)]
fn detect_tables(
    snapshot: &[u8],
    base_address: u64,
    maps: &MapIndex<'_>,
    budget: &mut CaptureWorkBudget,
) -> (Vec<ScannedTable>, Vec<String>) {
    detect_tables_for_layout(LinuxLayout::Lp64, snapshot, base_address, maps, budget)
}

fn detect_tables_for_layout(
    layout: LinuxLayout,
    snapshot: &[u8],
    base_address: u64,
    maps: &MapIndex<'_>,
    budget: &mut CaptureWorkBudget,
) -> (Vec<ScannedTable>, Vec<String>) {
    detect_tables_with_clock(
        layout,
        snapshot,
        base_address,
        maps,
        budget,
        crate::attach::monotonic_ns,
    )
}

fn detect_tables_with_clock<F: FnMut() -> Option<u64>>(
    layout: LinuxLayout,
    snapshot: &[u8],
    base_address: u64,
    maps: &MapIndex<'_>,
    budget: &mut CaptureWorkBudget,
    mut now: F,
) -> (Vec<ScannedTable>, Vec<String>) {
    let mut skipped = Vec::new();
    let mut found: Vec<(usize, usize, ScannedTable)> = Vec::new();
    let mut offset = 0usize;
    let width = layout.word_bytes();
    while offset + width <= snapshot.len() {
        if (offset / width) % 4096 == 0
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
        match decode_candidate(layout, snapshot, offset, base_address, maps, budget) {
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
        offset += width;
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
#[cfg(test)]
fn scan_interfaces(
    snapshot: &[u8],
    mem: &impl ScanMemory,
    tables: &[ScannedTable],
    maps: &MapIndex<'_>,
    key: ObjectKey,
    budget: &mut CaptureWorkBudget,
    operation_bytes: &mut u64,
) -> (Vec<ScannedInterface>, Vec<String>) {
    scan_interfaces_for_layout(
        LinuxLayout::Lp64,
        snapshot,
        mem,
        tables,
        maps,
        key,
        budget,
        operation_bytes,
    )
}

#[allow(clippy::too_many_arguments)]
fn scan_interfaces_for_layout(
    layout: LinuxLayout,
    snapshot: &[u8],
    mem: &impl ScanMemory,
    tables: &[ScannedTable],
    maps: &MapIndex<'_>,
    key: ObjectKey,
    budget: &mut CaptureWorkBudget,
    operation_bytes: &mut u64,
) -> (Vec<ScannedInterface>, Vec<String>) {
    scan_interfaces_with_clock(
        layout,
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
    layout: LinuxLayout,
    snapshot: &[u8],
    mem: &impl ScanMemory,
    tables: &[ScannedTable],
    maps: &MapIndex<'_>,
    key: ObjectKey,
    budget: &mut CaptureWorkBudget,
    operation_bytes: &mut u64,
    mut now: F,
) -> (Vec<ScannedInterface>, Vec<String>) {
    let word_at = |offset: usize| read_word_le(snapshot, layout, offset).ok();
    let interface = layout.interface();
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
    while offset + interface.stride <= snapshot.len() {
        if (offset / layout.word_bytes()) % 4096 == 0
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
            let name_ptr = word_at(offset + interface.name_offset)?;
            let table_ptr = word_at(offset + interface.function_list_offset)?;
            let flags = word_at(offset + interface.flags_offset)?;
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
        offset += layout.word_bytes();
    }
    (found, skipped)
}

/// A NUL-terminated name of at most `INTERFACE_NAME_CAP` bytes, or `None` when the
/// target memory could not be read or the name reaches the mapping end or cap.
fn read_name(
    mem: &impl ScanMemory,
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
        let read = match mem.read_memory_at(&mut chunk[..allowed], at) {
            Ok(0) | Err(_) => return Ok(None),
            Ok(read) => read,
        };
        budget.record_io(read);
        *operation_bytes = (*operation_bytes).saturating_add(read as u64);
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
    mem: &impl ScanMemory,
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
        match mem.read_memory_at(&mut bytes[done..], at) {
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
                *operation_bytes = (*operation_bytes).saturating_add(read as u64);
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
fn opened_file_identity_guard(
    view: &ProcessView,
    file: &File,
    expected: ObjectKey,
    budget: &mut CaptureWorkBudget,
) -> Result<(), String> {
    let actual = crate::discovery::identity::retained_object_key(view, file, budget)?;
    if actual == expected {
        return Ok(());
    }
    Err(format!(
        "opened object identity {}:{} inode {} does not match mapped object {}:{} inode {}",
        actual.device.major,
        actual.device.minor,
        actual.inode,
        expected.device.major,
        expected.device.minor,
        expected.inode
    ))
}

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
        .map_err(|_| "reversed or overlapping /proc/<pid>/maps intervals".to_string())
}

pub fn scan_pid(
    request: &ScanRequest<'_>,
    budget: &mut CaptureWorkBudget,
) -> Result<ScanOutcome, String> {
    let view = ProcessView::open(ProcessViewId(0), request.pid)?;
    scan_process_view(request, &view, budget)
}

// Private I/O seam: production and mutation tests share the entire acquisition loop.
trait ScanMemory {
    fn read_memory_at(&self, bytes: &mut [u8], offset: u64) -> std::io::Result<usize>;
}

impl ScanMemory for File {
    fn read_memory_at(&self, bytes: &mut [u8], offset: u64) -> std::io::Result<usize> {
        std::os::unix::fs::FileExt::read_at(self, bytes, offset)
    }
}

trait ScanIo {
    type Memory: ScanMemory;
    fn open_maps(
        &mut self,
        view: &ProcessView,
        budget: &CaptureWorkBudget,
    ) -> std::io::Result<Box<dyn Read>>;
    fn open_mem(&mut self, view: &ProcessView) -> std::io::Result<Self::Memory>;
    fn final_generation(&mut self, view: &ProcessView) -> Result<(), String>;
    fn maps_now(&self) -> Option<u64> {
        crate::attach::monotonic_ns()
    }
}

struct ProcScanIo;

impl ScanIo for ProcScanIo {
    type Memory = File;

    fn open_maps(
        &mut self,
        view: &ProcessView,
        _: &CaptureWorkBudget,
    ) -> std::io::Result<Box<dyn Read>> {
        Ok(Box::new(File::open(format!("/proc/{}/maps", view.pid()))?))
    }

    fn open_mem(&mut self, view: &ProcessView) -> std::io::Result<File> {
        File::open(format!("/proc/{}/mem", view.pid()))
    }

    fn final_generation(&mut self, view: &ProcessView) -> Result<(), String> {
        view.run_while_same(|| ())
    }
}

pub(crate) const MAPPING_CHANGED_REASON: &str =
    "memory scan refused: mapping changed during acquisition";
const FINAL_MAPS_UNAVAILABLE_REASON: &str =
    "memory scan refused: final mapping validation unavailable";
const INITIAL_MAPS_UNAVAILABLE_REASON: &str =
    "memory scan refused: initial mapping validation unavailable";
const SCAN_GENERATION_CHANGED_REASON: &str =
    "memory scan refused: process generation changed during acquisition";

/// All provider mappings establish inventory authority. They also cover every
/// searched data snapshot (even empty ones), complete interface descriptors, and
/// same-object name reads, including their bounded read-ahead. Function targets
/// can belong to other objects and must be retained separately, from decoded bytes.
#[derive(Default)]
struct ScanDependencies<'a> {
    inventory: Vec<&'a MapEntry>,
    targets: BTreeMap<u64, &'a MapEntry>,
    invalid_span: bool,
}

impl<'a> ScanDependencies<'a> {
    fn retain_tables(
        &mut self,
        tables: &[ScannedTable],
        snapshot: &[u8],
        base: u64,
        layout: LinuxLayout,
        maps: &MapIndex<'a>,
        budget: &mut CaptureWorkBudget,
    ) {
        for table in tables {
            let dependency = (|| {
                let offset = usize::try_from(table.address.checked_sub(base)?).ok()?;
                let bytes = snapshot.get(offset..)?;
                let len = exact_table_bytes(bytes, layout)?;
                let bytes = bytes.get(..len)?;
                let end = table.address.checked_add(len as u64)?;
                let mapping = maps.containing(table.address)?;
                if mapping.permissions[0] != b'r' || end > mapping.end {
                    return None;
                }
                let addresses = exact_table_addresses(bytes, layout)?;
                for address in addresses {
                    budget.spend(1).ok()?;
                    let target = maps.containing(address)?;
                    self.targets.insert(target.start, target);
                }
                Some(())
            })();
            if dependency.is_none() {
                self.invalid_span = true;
            }
        }
    }

    fn validate(
        &self,
        module: &ScannedModule,
        maps_b: &MapIndex<'_>,
        groups_b: &BTreeMap<ObjectKey, Vec<&MapEntry>>,
        budget: &mut CaptureWorkBudget,
    ) -> Result<bool, &'static str> {
        if self.invalid_span {
            return Ok(false);
        }
        for entry in self
            .inventory
            .iter()
            .copied()
            .chain(self.targets.values().copied())
        {
            // Account for both the lookup and full mapping/path comparison.
            budget.spend(1 + entry.raw_path.as_ref().map_or(0, |path| path.len() as u64))?;
            if maps_b.containing(entry.start) != Some(entry) {
                return Ok(false);
            }
        }
        // Absence of a decoded table is evidence only for the entire searched
        // provider data set; additions in B must not escape a vacuous table loop.
        if module.tables.is_empty() {
            let data =
                |entry: &&MapEntry| entry.permissions[0] == b'r' && entry.permissions[2] != b'x';
            let before = self.inventory.iter().copied().filter(data);
            let after = groups_b
                .get(&module.key)
                .into_iter()
                .flatten()
                .copied()
                .filter(data);
            let mut before = before;
            let mut after = after;
            loop {
                budget.spend(1)?;
                match (before.next(), after.next()) {
                    (None, None) => break,
                    (Some(a), Some(b)) if a == b => {}
                    _ => return Ok(false),
                }
            }
        }
        Ok(true)
    }
}

fn acquire_scan_maps(
    view: &ProcessView,
    budget: &mut CaptureWorkBudget,
    io: &mut impl ScanIo,
) -> Result<Vec<MapEntry>, String> {
    if let Some(reason) = budget.stopped_now() {
        return Err(reason.into());
    }
    let reader = view
        .run_while_same(|| io.open_maps(view, budget))?
        .map_err(|error| error.to_string())?;
    budget.spend(1).map_err(str::to_owned)?;
    let (bytes, reasons) = read_maps_with_limits(
        reader,
        budget,
        MAX_MAPS_BYTES,
        MAX_MAP_ENTRIES,
        64 * 1024,
        || io.maps_now(),
    )
    .map_err(|error| error.to_string())?;
    if let Some(reason) = reasons.first().copied().or(budget.stopped_now()) {
        return Err(reason.into());
    }
    if bytes.is_empty() || !bytes.ends_with(b"\n") {
        return Err("empty or truncated /proc maps snapshot".into());
    }
    // Parsing is charged independently of the single charged index construction.
    budget
        .spend(bytes.iter().filter(|byte| **byte == b'\n').count() as u64)
        .map_err(str::to_owned)?;
    let maps = parse_maps(&bytes)?;
    if maps.is_empty() {
        return Err("empty /proc maps snapshot".into());
    }
    Ok(maps)
}

/// Scan through an already accepted process-generation pin. Capture discovery uses
/// this entry point so one monotonically allocated `ProcessViewId` owns every result.
pub fn scan_process_view(
    request: &ScanRequest<'_>,
    view: &ProcessView,
    budget: &mut CaptureWorkBudget,
) -> Result<ScanOutcome, String> {
    scan_process_view_with_io(request, view, budget, &mut ProcScanIo)
}

/// Enumerates and pins the current module/export surface while deliberately
/// postponing target-memory table reads. The maps-A/maps-B and final-generation
/// bracket remains authoritative for the inventory returned here.
pub(crate) fn scan_process_view_without_memory(
    request: &ScanRequest<'_>,
    view: &ProcessView,
    budget: &mut CaptureWorkBudget,
) -> Result<ScanOutcome, String> {
    scan_process_view_with_io_mode(request, view, budget, &mut ProcScanIo, false)
}

fn scan_process_view_with_io(
    request: &ScanRequest<'_>,
    view: &ProcessView,
    budget: &mut CaptureWorkBudget,
    io: &mut impl ScanIo,
) -> Result<ScanOutcome, String> {
    scan_process_view_with_io_mode(request, view, budget, io, true)
}

/// Post-read pin check: the export facts read after `before` are trusted only
/// when a fresh pin still matches it. A mismatch refuses with the changed-file
/// retry message; a failed re-pin refuses with the pin's own I/O message so a
/// non-change error is never misdescribed as a change. Fail-safe either way.
fn check_pin_after_read(after: Result<Pin, String>, before: &Pin) -> Result<(), String> {
    match after {
        Ok(pin) if pin == *before => Ok(()),
        Ok(_) => Err("file changed while it was being scanned — retry".into()),
        Err(error) => Err(error),
    }
}

fn scan_process_view_with_io_mode(
    request: &ScanRequest<'_>,
    view: &ProcessView,
    budget: &mut CaptureWorkBudget,
    io: &mut impl ScanIo,
    scan_memory: bool,
) -> Result<ScanOutcome, String> {
    if request.pid != view.pid() {
        return Err("scan request pid does not match its process view".into());
    }
    if !view.still_the_same() {
        return Err(format!("pid {} exited before discovery", request.pid));
    }
    let started = Instant::now();
    let pid = request.pid;
    let refused_initial = |reason: String| {
        let mut skipped = vec![scan_skip(
            "capture discovery",
            format!("{INITIAL_MAPS_UNAVAILABLE_REASON}: {reason}"),
        )];
        if capture_scan_reason(&reason) {
            skipped.push(scan_skip("capture discovery", reason));
        }
        ScanOutcome::Scanned {
            modules: Vec::new(),
            skipped,
            scan_ms: started.elapsed().as_millis() as u64,
        }
    };
    let maps = match acquire_scan_maps(view, budget, io) {
        Ok(maps) => maps,
        Err(reason) => return Ok(refused_initial(reason)),
    };
    let map_index = match index_maps_or_refuse(&maps, budget) {
        Ok(index) => index,
        Err(reason) => return Ok(refused_initial(reason)),
    };
    let mut modules = Vec::new();
    let mut dependencies = BTreeMap::new();
    let mut skipped = Vec::new();
    // Group construction also consumes the capture's existing work allowance.
    if let Err(reason) = budget.spend(maps.len() as u64) {
        return Ok(refused_initial(reason.into()));
    }
    // `/proc/<pid>/mem` is gated by PTRACE_MODE_ATTACH and Yama; losing it costs the
    // tables, never the object inventory (spec §4.1 step 3). Only an access refusal is
    // a ptrace refusal — a pid that died mid-scan gets its own label.
    let (mem, unavailable) = if scan_memory {
        let mem = match view.run_while_same(|| io.open_mem(view)) {
            Ok(mem) => mem,
            Err(reason) => {
                return Ok(refused_initial(format!(
                    "{SCAN_GENERATION_CHANGED_REASON}: {reason}"
                )));
            }
        };
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
        (mem.ok(), unavailable)
    } else {
        (None, None)
    };

    let wanted = request.hooks.names();
    let hint_ids: Vec<Option<(u64, u64)>> =
        request.hints.iter().map(|h| hint_identity(h)).collect();
    let mut hint_matched = vec![false; request.hints.len()];

    let groups = candidate_groups(&maps);
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
        if let Err(reason) = opened_file_identity_guard(view, &file, key, budget) {
            skipped.push(Skipped { subject, reason });
            continue;
        }
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
        // A repeat scan of the unchanged file reuses the cached export facts with
        // zero reads. The key's (device, inode) is the maps identity the guard
        // above validated against the opened file.
        let before = match pin_of(&file) {
            Ok(pin) => pin,
            Err(reason) => {
                skipped.push(Skipped { subject, reason });
                continue;
            }
        };
        // No whole-size gate on the export check: the tables are demand-paged,
        // so cost follows touched pages rather than file size. `actual_size`
        // stays above for hint attribution.
        let cache_key = InspectedFileKey {
            device: key.device,
            inode: key.inode,
            pin: before,
        };
        // Nothing is read for this hit, but the file may have changed since
        // `before`; only the still-unchanged file may reuse the cached facts.
        let cached = budget
            .elf_export_facts_for(&cache_key)
            .filter(|_| pin_of(&file).is_ok_and(|after| after == before));
        let (abi, exports) = match cached {
            Some(facts) => (facts.abi, facts.exports),
            None => {
                let (abi, exports) = match read_export_facts_budgeted(&file, &wanted, budget) {
                    Ok(facts) => facts,
                    Err(reason) => {
                        skipped.push(Skipped { subject, reason });
                        continue;
                    }
                };
                // The pin was taken before the bytes were read; a write that lands
                // during the read must not become the facts the capture trusts.
                match check_pin_after_read(pin_of(&file), &before) {
                    Ok(()) => {
                        budget.note_elf_export_facts(
                            cache_key,
                            ElfExportFacts {
                                abi,
                                exports: exports.clone(),
                            },
                        );
                        (abi, exports)
                    }
                    Err(reason) => {
                        skipped.push(Skipped { subject, reason });
                        continue;
                    }
                }
            }
        };
        let layout = target_layout(abi);
        if request.hints.is_empty() && exports.is_empty() {
            continue;
        }
        let mut module = ScannedModule {
            view: view.id(),
            mount_namespace: view.mount_namespace(),
            key,
            path,
            decoder_abi: Some(abi),
            exports: exports.into_iter().map(|(name, _)| name).collect(),
            tables: Vec::new(),
            interfaces: Vec::new(),
        };
        let dependency = dependencies.entry(key).or_insert_with(|| ScanDependencies {
            inventory: group.clone(),
            ..ScanDependencies::default()
        });
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
            let (tables, exhausted) =
                detect_tables_for_layout(layout, snapshot, *base, &map_index, budget);
            dependency.retain_tables(&tables, snapshot, *base, layout, &map_index, budget);
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
            let (interfaces, exhausted) = scan_interfaces_for_layout(
                layout,
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

    // No pending module escapes until the second complete snapshot, dependency
    // comparisons and final generation check have all succeeded. A failed bracket
    // remains an explicit occurrence even when a later scan or manifest attaches.
    let validation = (|| {
        let maps_b = acquire_scan_maps(view, budget, io)?;
        let index_b = index_maps_or_refuse(&maps_b, budget)?;
        budget.spend(maps_b.len() as u64).map_err(str::to_owned)?;
        let groups_b = candidate_groups(&maps_b);
        let mut accepted = Vec::with_capacity(modules.len());
        for module in &modules {
            accepted.push(
                dependencies[&module.key]
                    .validate(module, &index_b, &groups_b, budget)
                    .map_err(str::to_owned)?,
            );
        }
        if let Some(reason) = budget.stopped_now() {
            return Err(reason.into());
        }
        Ok::<_, String>(accepted)
    })();
    let generation = io.final_generation(view);
    match (validation, generation) {
        (Ok(accepted), Ok(())) => {
            modules = modules
                .into_iter()
                .zip(accepted)
                .filter_map(|(module, accepted)| {
                    if accepted {
                        Some(module)
                    } else {
                        skipped.push(scan_skip(&module.path, MAPPING_CHANGED_REASON.into()));
                        None
                    }
                })
                .collect();
        }
        (validation, generation) => {
            if let Err(reason) = validation {
                skipped.push(scan_skip(
                    "capture discovery",
                    format!("{FINAL_MAPS_UNAVAILABLE_REASON}: {reason}"),
                ));
            }
            if let Err(reason) = generation {
                skipped.push(scan_skip(
                    "capture discovery",
                    format!("{SCAN_GENERATION_CHANGED_REASON}: {reason}"),
                ));
            }
            modules.clear();
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
    Ok(outcome)
}

#[cfg(test)]
pub(crate) fn bracket_refusal_for_test(
    view: &ProcessView,
    budget: &mut CaptureWorkBudget,
) -> ScanOutcome {
    tests::bracket_refusal(view, budget)
}

#[cfg(test)]
mod tests {
    use super::*;

    pub(super) fn bracket_refusal(
        view: &ProcessView,
        budget: &mut CaptureWorkBudget,
    ) -> ScanOutcome {
        let mut fixture = BracketFixture::new(8, true);
        fixture.maps_b = fixture.maps_b.replace("4000-6000", "4000-4810");
        let hints = [fixture.path.clone()];
        scan_process_view_with_io(
            &ScanRequest {
                pid: view.pid(),
                hints: &hints,
                hooks: &HookRegistry::builtin(),
            },
            view,
            budget,
            &mut fixture,
        )
        .unwrap()
    }

    // Raw maps text is authored independently of candidate_groups/MapIndex. Only
    // the temporary file identity is interpolated; no production maps builder is used.
    struct BracketFixture {
        _dir: tempfile::TempDir,
        path: PathBuf,
        view: ProcessView,
        maps_a: String,
        maps_b: String,
        mem: File,
        log: std::rc::Rc<std::cell::RefCell<Vec<String>>>,
        maps_reads: usize,
        before_b: Option<(u64, u64)>,
        fail_open_b: bool,
        fail_read_b: bool,
        fail_generation: bool,
        expire_at_b: bool,
    }

    struct BracketMemory {
        file: File,
        log: std::rc::Rc<std::cell::RefCell<Vec<String>>>,
    }

    impl ScanMemory for BracketMemory {
        fn read_memory_at(&self, bytes: &mut [u8], offset: u64) -> std::io::Result<usize> {
            self.log
                .borrow_mut()
                .push(format!("memory {offset:x} {}", bytes.len()));
            self.file.read_at(bytes, offset)
        }
    }

    impl ScanIo for BracketFixture {
        type Memory = BracketMemory;
        fn open_maps(
            &mut self,
            _: &ProcessView,
            budget: &CaptureWorkBudget,
        ) -> std::io::Result<Box<dyn Read>> {
            self.maps_reads += 1;
            if self.maps_reads == 2 {
                self.before_b = Some((budget.attempted_io_bytes(), budget.work_units));
            }
            self.log
                .borrow_mut()
                .push(format!("maps {}", self.maps_reads));
            if self.maps_reads == 2 && self.fail_open_b {
                return Err(std::io::Error::other("injected maps B open failure"));
            }
            if self.maps_reads == 2 && self.fail_read_b {
                struct FailedRead;
                impl Read for FailedRead {
                    fn read(&mut self, _: &mut [u8]) -> std::io::Result<usize> {
                        Err(std::io::Error::other("injected maps B read failure"))
                    }
                }
                return Ok(Box::new(FailedRead));
            }
            Ok(Box::new(std::io::Cursor::new(
                if self.maps_reads == 1 {
                    &self.maps_a
                } else {
                    &self.maps_b
                }
                .as_bytes()
                .to_vec(),
            )))
        }
        fn open_mem(&mut self, _: &ProcessView) -> std::io::Result<BracketMemory> {
            Ok(BracketMemory {
                file: self.mem.try_clone()?,
                log: self.log.clone(),
            })
        }
        fn maps_now(&self) -> Option<u64> {
            if self.expire_at_b && self.maps_reads == 2 {
                Some(u64::MAX)
            } else {
                crate::attach::monotonic_ns()
            }
        }
        fn final_generation(&mut self, view: &ProcessView) -> Result<(), String> {
            self.log.borrow_mut().push("final generation".into());
            if self.fail_generation {
                Err("injected generation loss".into())
            } else {
                view.run_while_same(|| ())
            }
        }
    }

    impl BracketFixture {
        fn new(width: usize, populated: bool) -> Self {
            let dir = tempfile::tempdir().unwrap();
            let path = dir.path().join("provider.so");
            // Minimal independent x86 ELF header; the real ELF reader selects ABI.
            let mut elf = vec![0u8; 64];
            elf[..7].copy_from_slice(&[
                0x7f,
                b'E',
                b'L',
                b'F',
                if width == 8 { 2 } else { 1 },
                1,
                1,
            ]);
            elf[16..18].copy_from_slice(&3u16.to_le_bytes());
            elf[18..20].copy_from_slice(&(if width == 8 { 62u16 } else { 3 }).to_le_bytes());
            elf[20..24].copy_from_slice(&1u32.to_le_bytes());
            if width == 8 {
                elf[52..54].copy_from_slice(&64u16.to_le_bytes());
                elf[54..56].copy_from_slice(&56u16.to_le_bytes());
                elf[58..60].copy_from_slice(&64u16.to_le_bytes());
            } else {
                elf[40..42].copy_from_slice(&52u16.to_le_bytes());
                elf[42..44].copy_from_slice(&32u16.to_le_bytes());
                elf[46..48].copy_from_slice(&40u16.to_le_bytes());
            }
            std::fs::write(&path, elf).unwrap();
            let view = ProcessView::open(ProcessViewId(71), std::process::id()).unwrap();
            let file = File::open(&path).unwrap();
            let key = crate::discovery::identity::retained_object_key(
                &view,
                &file,
                &mut CaptureWorkBudget::default(),
            )
            .unwrap();
            let identity = format!(
                "{:x}:{:x} {} {}",
                key.device.major,
                key.device.minor,
                key.inode,
                path.display()
            );
            let maps_a = format!(
                "1000-2000 r-xp 00000000 {identity}\n\
                 4000-6000 rw-p 00002000 {identity}\n\
                 7000-8000 r--p 00004000 {identity}\n\
                 9000-a000 r-xp 00000000 08:01 999 /dependency.so\n\
                 b000-c000 r-xp 00005000 {identity}\n"
            );
            let mem = tempfile::tempfile().unwrap();
            mem.set_len(0xc000).unwrap();
            if populated {
                let mut table = vec![0u8; 69 * width];
                table[..2].copy_from_slice(&[2, 40]);
                for slot in 0..68 {
                    // Null slot plus both provider and dependency function targets.
                    let pointer: u64 = match slot {
                        0 => 0x1100,
                        1 => 0,
                        _ => 0x9100,
                    };
                    table[(slot + 1) * width..(slot + 2) * width]
                        .copy_from_slice(&pointer.to_le_bytes()[..width]);
                }
                mem.write_all_at(&table, 0x4800).unwrap();
                for (slot, value) in [0xb100u64, 0x4800, 0].into_iter().enumerate() {
                    mem.write_all_at(
                        &value.to_le_bytes()[..width],
                        0x7100 + (slot * width) as u64,
                    )
                    .unwrap();
                }
                mem.write_all_at(b"PKCS 11\0PRIVATE_READ_AHEAD_CANARY", 0xb100)
                    .unwrap();
            }
            Self {
                _dir: dir,
                path,
                view,
                maps_b: maps_a.clone(),
                maps_a,
                mem,
                log: Default::default(),
                maps_reads: 0,
                before_b: None,
                fail_open_b: false,
                fail_read_b: false,
                fail_generation: false,
                expire_at_b: false,
            }
        }

        fn run(&mut self, budget: &mut CaptureWorkBudget) -> Result<ScanOutcome, String> {
            let view = ProcessView::open(self.view.id(), self.view.pid()).unwrap();
            let hints = [self.path.clone()];
            let hooks = HookRegistry::builtin();
            let outcome = scan_process_view_with_io(
                &ScanRequest {
                    pid: view.pid(),
                    hints: &hints,
                    hooks: &hooks,
                },
                &view,
                budget,
                self,
            );
            self.log.borrow_mut().push("publication".into());
            outcome
        }

        fn assert_refused(&mut self, budget: &mut CaptureWorkBudget, reason: &str) {
            let outcome = self
                .run(budget)
                .expect("refusals must carry evidence, not discard it in Err");
            assert_eq!(
                outcome
                    .modules()
                    .iter()
                    .map(|m| m.tables.len() + m.interfaces.len())
                    .sum::<usize>(),
                0,
                "unvalidated tables/interfaces escaped"
            );
            assert!(
                outcome
                    .skipped()
                    .iter()
                    .any(|skip| skip.reason.contains(reason)),
                "missing explicit {reason:?}: {:?}",
                outcome.skipped()
            );
        }
    }

    #[test]
    fn p2_bracket_split_span_with_unchanged_generation() {
        let mut f = BracketFixture::new(8, true);
        let original = f
            .maps_b
            .lines()
            .find(|line| line.starts_with("4000-"))
            .unwrap()
            .to_owned();
        let identity = original.split_once("00002000 ").unwrap().1;
        f.maps_b = f.maps_b.replace(
            &original,
            &format!("4000-5000 rw-p 00002000 {identity}\n5000-6000 r--p 00003000 {identity}"),
        );
        f.assert_refused(
            &mut CaptureWorkBudget::default(),
            "memory scan refused: mapping changed during acquisition",
        );
        assert!(f.view.still_the_same());
    }

    #[test]
    fn p2_bracket_function_dependency_full_mapping_equality() {
        for replacement in [
            "9000-a000 r-xp 00000010 08:01 999 /dependency.so",
            "9000-a000 r-xp 00000000 08:01 998 /dependency.so",
            "9000-a000 r-xp 00000000 08:02 999 /dependency.so",
            "9000-a000 r--p 00000000 08:01 999 /dependency.so",
            "9000-a000 r-xs 00000000 08:01 999 /dependency.so",
            "9080-a000 r-xp 00000000 08:01 999 /dependency.so",
            "9000-a000 r-xp 00000000 08:01 999 /replacement.so",
        ] {
            let mut f = BracketFixture::new(8, true);
            f.maps_b = f.maps_b.replace(
                "9000-a000 r-xp 00000000 08:01 999 /dependency.so",
                replacement,
            );
            f.assert_refused(
                &mut CaptureWorkBudget::default(),
                "mapping changed during acquisition",
            );
        }
    }

    #[test]
    fn p2_bracket_span_end_both_abis() {
        for width in [8, 4] {
            let mut f = BracketFixture::new(width, true);
            f.maps_b = f.maps_b.replace("4000-6000", "4000-4810");
            f.assert_refused(
                &mut CaptureWorkBudget::default(),
                "mapping changed during acquisition",
            );
        }
    }

    #[test]
    fn p2_bracket_empty_result_checks_changed_and_added_data() {
        for added in [false, true] {
            let mut f = BracketFixture::new(8, false);
            if added {
                let identity = f
                    .maps_a
                    .lines()
                    .next()
                    .unwrap()
                    .split_once("00000000 ")
                    .unwrap()
                    .1;
                f.maps_b
                    .push_str(&format!("d000-e000 rw-p 00006000 {identity}\n"));
            } else {
                f.maps_b = f.maps_b.replace("4000-6000", "4000-5000");
            }
            f.assert_refused(
                &mut CaptureWorkBudget::default(),
                "mapping changed during acquisition",
            );
        }
    }

    #[test]
    fn p2_bracket_interface_descriptor_and_name_mapping() {
        for (old, new) in [("7000-8000", "7000-7110"), ("b000-c000", "b000-b110")] {
            let mut f = BracketFixture::new(8, true);
            f.maps_b = f.maps_b.replace(old, new);
            f.assert_refused(
                &mut CaptureWorkBudget::default(),
                "mapping changed during acquisition",
            );
            let reads = f
                .log
                .borrow()
                .iter()
                .filter(|event| event.starts_with("memory b100"))
                .count();
            assert_eq!(reads, 1, "validation must not dereference names again");
        }
    }

    #[test]
    fn p2_bracket_blank_maps_b_is_unavailable() {
        let mut f = BracketFixture::new(8, true);
        f.maps_b = "\n".into();
        f.assert_refused(
            &mut CaptureWorkBudget::default(),
            "final mapping validation unavailable",
        );
    }

    #[test]
    fn p2_bracket_unavailable_b() {
        for case in [
            "open",
            "read",
            "malformed",
            "overlap",
            "truncated",
            "empty",
            "bytes",
            "entries",
        ] {
            let mut f = BracketFixture::new(8, true);
            match case {
                "open" => f.fail_open_b = true,
                "read" => f.fail_read_b = true,
                "malformed" => f.maps_b.push_str("malformed\n"),
                "overlap" => f.maps_b.push_str("b000-d000 r--p 0 0:0 0\n"),
                "truncated" => {
                    f.maps_b.pop();
                }
                "empty" => f.maps_b.clear(),
                "bytes" => f.maps_b.push_str(&format!(
                    "d000-e000 r--p 0 0:0 0 /{}\n",
                    "x".repeat(MAX_MAPS_BYTES as usize)
                )),
                "entries" => f
                    .maps_b
                    .push_str(&"d000-e000 r--p 0 0:0 0\n".repeat(MAX_MAP_ENTRIES + 1)),
                _ => unreachable!(),
            }
            let detail = match case {
                "open" => "injected maps B open failure",
                "read" => "injected maps B read failure",
                "malformed" => "invalid /proc maps line",
                "overlap" => "reversed or overlapping",
                "truncated" | "empty" => "empty or truncated",
                "bytes" => MAPS_CEILING_REASON,
                "entries" => MAPS_ENTRY_CEILING_REASON,
                _ => unreachable!(),
            };
            f.assert_refused(
                &mut CaptureWorkBudget::default(),
                &format!("{FINAL_MAPS_UNAVAILABLE_REASON}: {detail}"),
            );
            eprintln!("unavailable B case {case}: refused with {detail}");
        }
    }

    #[test]
    fn p2_bracket_incomplete_a_never_scans() {
        let mut control = BracketFixture::new(8, true);
        assert_eq!(
            control
                .run(&mut CaptureWorkBudget::default())
                .unwrap()
                .modules()
                .len(),
            1
        );

        let mut f = BracketFixture::new(8, true);
        let mut budget = CaptureWorkBudget::new(ScanLimits {
            per_object_bytes: u64::MAX,
            total_bytes: f.maps_a.len() as u64 - 1,
        });
        f.assert_refused(
            &mut budget,
            "memory scan refused: initial mapping validation unavailable",
        );
        assert!(
            !f.log
                .borrow()
                .iter()
                .any(|event| event.starts_with("memory "))
        );

        let mut invalid = BracketFixture::new(8, true);
        invalid
            .maps_a
            .push_str("b000-d000 r--p 0 0:0 0 [overlap]\n");
        invalid.assert_refused(
            &mut CaptureWorkBudget::default(),
            "memory scan refused: initial mapping validation unavailable: reversed or overlapping",
        );
        assert!(
            !invalid
                .log
                .borrow()
                .iter()
                .any(|event| event.starts_with("memory "))
        );
    }

    #[test]
    fn p2_bracket_generation_loss_keeps_refusal() {
        let mut f = BracketFixture::new(8, true);
        f.fail_generation = true;
        f.assert_refused(
            &mut CaptureWorkBudget::default(),
            "memory scan refused: process generation changed during acquisition",
        );
    }

    #[test]
    fn p2_bracket_b_consumes_capture_io_allowance() {
        let mut control = BracketFixture::new(8, true);
        let mut measured = CaptureWorkBudget::default();
        assert_eq!(
            control.run(&mut measured).unwrap().modules()[0]
                .tables
                .len(),
            1
        );
        let mut f = BracketFixture::new(8, true);
        let mut budget = CaptureWorkBudget::new(ScanLimits {
            per_object_bytes: u64::MAX,
            // Unfixed A-only cost plus less than one B snapshot.
            total_bytes: control
                .before_b
                .map_or(measured.attempted_io_bytes(), |b| b.0)
                + f.maps_b.len() as u64 / 2,
        });
        f.assert_refused(&mut budget, "final mapping validation unavailable");
    }

    #[test]
    fn p2_bracket_b_consumes_work_allowance() {
        let mut control = BracketFixture::new(8, true);
        let mut measured = CaptureWorkBudget::default();
        assert_eq!(
            control.run(&mut measured).unwrap().modules()[0]
                .tables
                .len(),
            1
        );
        let mut f = BracketFixture::new(8, true);
        let mut budget = CaptureWorkBudget {
            work_ceiling: control.before_b.map_or(measured.work_units, |b| b.1) + 1,
            ..CaptureWorkBudget::default()
        };
        f.assert_refused(&mut budget, "final mapping validation unavailable");
    }

    #[test]
    fn p2_bracket_independent_module_survives_refused_neighbor() {
        let mut f = BracketFixture::new(8, true);
        let neighbor = BracketFixture::new(8, true);
        let extra = neighbor
            .maps_a
            .lines()
            .filter(|line| !line.contains("/dependency.so"))
            .map(|line| {
                line.replace("1000-2000", "11000-12000")
                    .replace("4000-6000", "14000-16000")
                    .replace("7000-8000", "17000-18000")
                    .replace("b000-c000", "1b000-1c000")
            })
            .collect::<Vec<_>>()
            .join("\n")
            + "\n";
        f.maps_a.push_str(&extra);
        f.maps_b = f.maps_a.replacen("4000-6000 rw-p", "4000-4810 rw-p", 1);
        f.mem.set_len(0x1c000).unwrap();
        let mut table = [0; 69 * 8];
        neighbor.mem.read_exact_at(&mut table, 0x4800).unwrap();
        f.mem.write_all_at(&table, 0x14800).unwrap();
        let view = ProcessView::open(ProcessViewId(71), std::process::id()).unwrap();
        let hints = [f.path.clone(), neighbor.path.clone()];
        let outcome = scan_process_view_with_io(
            &ScanRequest {
                pid: view.pid(),
                hints: &hints,
                hooks: &HookRegistry::builtin(),
            },
            &view,
            &mut CaptureWorkBudget::default(),
            &mut f,
        )
        .unwrap();
        assert_eq!(
            outcome.modules().len(),
            1,
            "only the independent module should survive"
        );
        assert_eq!(
            outcome.modules()[0].path,
            neighbor.path.display().to_string()
        );
        assert_eq!(outcome.modules()[0].tables.len(), 1);
        assert!(
            outcome
                .skipped()
                .iter()
                .any(|skip| skip.subject == f.path.display().to_string()
                    && skip.reason == MAPPING_CHANGED_REASON)
        );
    }

    #[test]
    fn p2_bracket_b_checks_deadline() {
        let mut f = BracketFixture::new(8, true);
        f.expire_at_b = true;
        let mut budget = CaptureWorkBudget::default();
        budget.set_deadline(Some(u64::MAX));
        f.assert_refused(&mut budget, "final mapping validation unavailable");
    }

    #[test]
    fn p2_bracket_stable_and_unrelated_vma_positive_controls() {
        for width in [8, 4] {
            for unrelated in [false, true] {
                let mut f = BracketFixture::new(width, true);
                if unrelated {
                    f.maps_a.push_str("d000-e000 rw-p 0 0:0 0 [unrelated]\n");
                    f.maps_b.push_str("d000-f000 rw-p 0 0:0 0 [unrelated]\n");
                }
                let mut budget = CaptureWorkBudget::default();
                let outcome = f.run(&mut budget).unwrap();
                assert_eq!(outcome.modules().len(), 1, "{outcome:?}");
                assert_eq!(outcome.modules()[0].tables.len(), 1, "{outcome:?}");
                assert_eq!(outcome.modules()[0].tables[0].entries.len(), 67);
                assert_eq!(outcome.modules()[0].tables[0].null_entries.len(), 1);
                assert_eq!(outcome.modules()[0].interfaces.len(), 1);
                assert_eq!(
                    outcome.modules()[0].interfaces[0].name_lossy.as_deref(),
                    Some("PKCS 11")
                );
                assert!(outcome.skipped().is_empty(), "{outcome:?}");
                let log = f.log.borrow();
                assert_eq!(log.first().unwrap(), "maps 1");
                assert_eq!(
                    &log[log.len() - 3..],
                    ["maps 2", "final generation", "publication"]
                );
                assert!(
                    log[1..log.len() - 3]
                        .iter()
                        .all(|event| event.starts_with("memory "))
                );
                assert!(
                    budget.attempted_io_bytes()
                        >= (f.maps_a.len() + f.maps_b.len()) as u64 + 0x3000 + 32 + 64
                );
            }
        }
    }

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

        // The preprocessing itself is charged, one unit per snapshot entry.
        // Leave one unit: every live process has multiple mappings, so the scan
        // stops there without racing a separate read of this process's map count.
        let mut budget = CaptureWorkBudget::default();
        assert!(budget.charge(DEFAULT_WORK_CEILING - 1));
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
            assert_eq!(
                Some((version, span_bytes(LinuxLayout::Lp64, spans).unwrap())),
                expected
            );
        }
        // Padding bytes set, implausible minor, unknown major, all-zero word.
        for word in [0x1_2802u64, 0x2902, 0x0304, 0x0004, 0] {
            assert!(spans_for(word).is_none(), "{word:#x} must not be a table");
        }
    }

    #[test]
    fn ilp32_tables_use_four_byte_words_and_ignore_adjacent_poison() {
        let maps = parse_maps(b"1000-3000 r-xp 00000000 08:01 7 /lib/provider.so\n").unwrap();
        let map_index = MapIndex::new(&maps).unwrap();
        for (version, fields) in [(0x0002u32, 67), (0x2802, 68), (0x0003, 92), (0x0203, 104)] {
            let mut snapshot = vec![0xa5; 4 + fields * 4 + 3];
            snapshot[..4].copy_from_slice(&version.to_le_bytes());
            for ordinal in 0..fields {
                let offset = 4 + ordinal * 4;
                snapshot[offset..offset + 4].copy_from_slice(&0x1500u32.to_le_bytes());
            }
            assert_eq!(
                exact_table_bytes(&snapshot[..4], LinuxLayout::Ilp32),
                Some(4 + fields * 4)
            );
            let (tables, skipped) = detect_tables_for_layout(
                LinuxLayout::Ilp32,
                &snapshot,
                0x7000,
                &map_index,
                &mut CaptureWorkBudget::default(),
            );
            assert!(skipped.is_empty(), "{version:#x}: {skipped:?}");
            assert_eq!(tables.len(), 1, "{version:#x}");
            assert_eq!(tables[0].entries.len(), fields, "{version:#x}");

            snapshot.truncate(4 + fields * 4 - 1);
            assert!(
                detect_tables_for_layout(
                    LinuxLayout::Ilp32,
                    &snapshot,
                    0x7000,
                    &map_index,
                    &mut CaptureWorkBudget::default(),
                )
                .0
                .is_empty(),
                "a truncated final target word is never decoded"
            );
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
    fn opened_file_identity_rejects_same_size_inode_before_hint_matching() {
        let directory = tempfile::tempdir().unwrap();
        let original_path = directory.path().join("provider.so");
        let replacement_path = directory.path().join("replacement.so");
        std::fs::write(&original_path, b"same-size provider bytes").unwrap();
        std::fs::copy(&original_path, &replacement_path).unwrap();

        let original_file = p11scope_manifest::identity::open_object(&original_path).unwrap();
        let original_identity =
            p11scope_manifest::identity::mapping_file_key(&original_file).unwrap();
        let captured = ObjectKey {
            device: p11scope_manifest::maps::Device {
                major: original_identity.device_major,
                minor: original_identity.device_minor,
            },
            inode: original_identity.inode,
        };
        let replacement_file = p11scope_manifest::identity::open_object(&replacement_path).unwrap();
        let replacement_identity =
            p11scope_manifest::identity::mapping_file_key(&replacement_file).unwrap();
        assert_eq!(
            original_file.metadata().unwrap().len(),
            replacement_file.metadata().unwrap().len(),
            "the replacement must be the same size"
        );
        assert_ne!(captured.inode, replacement_identity.inode);
        let view = ProcessView::open(ProcessViewId(0), std::process::id()).unwrap();
        assert!(
            opened_file_identity_guard(
                &view,
                &replacement_file,
                captured,
                &mut CaptureWorkBudget::default(),
            )
            .is_err(),
            "a same-size replacement inode must be refused before hint matching"
        );

        let scan_body = &include_str!("scan.rs")[include_str!("scan.rs")
            .find("pub fn scan_process_view(")
            .expect("scan entry")..];
        let scan_lines = scan_body.lines().map(str::trim).collect::<Vec<_>>();
        let guard = scan_lines
            .iter()
            .position(|line| {
                *line
                    == "if let Err(reason) = opened_file_identity_guard(view, &file, key, budget) {"
            })
            .expect("the shared identity guard must run in the scan");
        assert_eq!(
            scan_lines[guard - 1],
            "};",
            "the identity guard must immediately follow every successful target open"
        );
        assert_eq!(
            &scan_lines[guard + 1..guard + 4],
            [
                "skipped.push(Skipped { subject, reason });",
                "continue;",
                "}"
            ],
            "identity mismatch must always skip the opened object"
        );
        let hint_gate = scan_lines
            .iter()
            .position(|line| *line == "let attributable = matched.iter().any(|(index, kind)| {")
            .expect("hint-specific attribution must remain after the guard");
        assert!(
            guard < hint_gate,
            "identity must be checked before hint gating"
        );
        let guard_body = &include_str!("scan.rs")[include_str!("scan.rs")
            .find("fn opened_file_identity_guard(")
            .expect("identity guard")..];
        assert!(
            guard_body
                .contains("crate::discovery::identity::retained_object_key(view, file, budget)")
        );
        for decision in [
            "if !request.hints.is_empty() && !hinted {\n            continue;\n        }",
            "if hinted && !attributable {",
            "if request.hints.is_empty() && exports.is_empty() {\n            continue;\n        }",
        ] {
            assert!(
                scan_body.contains(decision),
                "missing scan decision: {decision}"
            );
        }
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

        assert_eq!(
            exact_table_addresses(&snapshot, LinuxLayout::Lp64).unwrap(),
            [0x1110, 0x3330]
        );
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
        let (tables, skipped) = detect_tables_with_clock(
            LinuxLayout::Lp64,
            &snapshot,
            0x7000,
            &map_index,
            &mut budget,
            || {
                polls += 1;
                Some(if polls == 1 { 0 } else { 10 })
            },
        );
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
    fn budgeted_elf_reader_never_overspends_or_reads_after_deadline() {
        let short = tempfile::tempfile().unwrap();
        short.set_len(8).unwrap();
        let mut budget = CaptureWorkBudget::new(ScanLimits {
            per_object_bytes: 8,
            total_bytes: 7,
        });
        let mut requests = Vec::new();
        let error = read_elf_snapshot_with(
            &short,
            &mut budget,
            |_| None,
            |file, bytes, offset| {
                requests.push(bytes.len());
                file.read_at(bytes, offset)
            },
        )
        .unwrap_err();
        assert!(error.contains(IO_CEILING_REASON), "{error}");
        assert_eq!(
            requests,
            [7],
            "the underlying reader sees only admitted bytes"
        );
        assert_eq!(budget.attempted_io_bytes(), 7);

        let mut budget = CaptureWorkBudget::default();
        let mut reads = 0;
        let error = read_elf_snapshot_with(
            &short,
            &mut budget,
            |_| Some(SCAN_DEADLINE_REASON),
            |file, bytes, offset| {
                reads += 1;
                file.read_at(bytes, offset)
            },
        )
        .unwrap_err();
        assert!(error.contains(SCAN_DEADLINE_REASON), "{error}");
        assert_eq!(
            reads, 0,
            "an expired deadline refuses before the first read"
        );
        assert_eq!(budget.attempted_io_bytes(), 0);

        let long = tempfile::tempfile().unwrap();
        long.set_len((READ_CHUNK + 1) as u64).unwrap();
        let mut budget = CaptureWorkBudget::default();
        let mut polls = 0;
        let mut reads = 0;
        let error = read_elf_snapshot_with(
            &long,
            &mut budget,
            |_| {
                polls += 1;
                (polls == 2).then_some(SCAN_DEADLINE_REASON)
            },
            |file, bytes, offset| {
                reads += 1;
                file.read_at(bytes, offset)
            },
        )
        .unwrap_err();
        assert!(error.contains(SCAN_DEADLINE_REASON), "{error}");
        assert_eq!(polls, 2);
        assert_eq!(reads, 1, "expiry between chunks prevents the next read");
        assert_eq!(budget.attempted_io_bytes(), READ_CHUNK as u64);
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

    #[derive(Debug)]
    enum ReaderStep {
        Bytes(Vec<u8>),
        Error(std::io::ErrorKind),
        Eof,
    }

    #[derive(Debug)]
    struct RecordingReader {
        steps: std::collections::VecDeque<ReaderStep>,
        requests: Vec<usize>,
    }

    impl RecordingReader {
        fn new(steps: impl IntoIterator<Item = ReaderStep>) -> Self {
            Self {
                steps: steps.into_iter().collect(),
                requests: Vec::new(),
            }
        }
    }

    impl Read for &mut RecordingReader {
        fn read(&mut self, buffer: &mut [u8]) -> std::io::Result<usize> {
            self.requests.push(buffer.len());
            match self.steps.pop_front().unwrap_or(ReaderStep::Eof) {
                ReaderStep::Bytes(bytes) => {
                    assert!(bytes.len() <= buffer.len());
                    buffer[..bytes.len()].copy_from_slice(&bytes);
                    Ok(bytes.len())
                }
                ReaderStep::Error(kind) => Err(std::io::Error::from(kind)),
                ReaderStep::Eof => Ok(0),
            }
        }
    }

    #[test]
    fn mountinfo_reader_proves_eof_at_the_exact_byte_cap_and_refuses_excess() {
        let mut exact =
            RecordingReader::new([ReaderStep::Bytes(b"abc\n".to_vec()), ReaderStep::Eof]);
        let mut budget = CaptureWorkBudget::new(ScanLimits {
            per_object_bytes: 4,
            total_bytes: 5,
        });
        assert_eq!(
            read_mountinfo_with(&mut exact, &mut budget, 8, |_| None).unwrap(),
            "abc\n"
        );
        assert_eq!(exact.requests, [5, 1], "the final request is EOF lookahead");
        assert_eq!(budget.attempted_io_bytes(), 4);

        let mut excess = RecordingReader::new([ReaderStep::Bytes(b"abc\nx".to_vec())]);
        let mut budget = CaptureWorkBudget::new(ScanLimits {
            per_object_bytes: 4,
            total_bytes: 5,
        });
        assert_eq!(
            read_mountinfo_with(&mut excess, &mut budget, 8, |_| None).unwrap_err(),
            MOUNTINFO_CEILING_REASON
        );
        assert_eq!(excess.requests, [5]);
        assert_eq!(budget.attempted_io_bytes(), 5, "the excess byte is charged");
    }

    #[test]
    fn mountinfo_reader_charges_lines_and_reused_aggregate_budget() {
        let exact_lines = vec![b'\n'; MAX_MOUNTINFO_ENTRIES];
        let mut exact = RecordingReader::new([ReaderStep::Bytes(exact_lines), ReaderStep::Eof]);
        let mut budget = CaptureWorkBudget::default();
        assert!(read_mountinfo_with(&mut exact, &mut budget, 2 * 1024 * 1024, |_| None).is_ok());
        let first_bytes = budget.attempted_io_bytes();
        assert_eq!(exact.requests.len(), 2);

        let mut excess =
            RecordingReader::new([ReaderStep::Bytes(vec![b'\n'; MAX_MOUNTINFO_ENTRIES + 1])]);
        assert_eq!(
            read_mountinfo_with(&mut excess, &mut budget, 2 * 1024 * 1024, |_| None).unwrap_err(),
            MOUNTINFO_ENTRY_CEILING_REASON
        );
        assert_eq!(
            budget.attempted_io_bytes(),
            first_bytes + u64::try_from(MAX_MOUNTINFO_ENTRIES + 1).unwrap()
        );
    }

    #[test]
    fn mountinfo_reader_retries_interrupted_reads_but_refuses_other_partial_errors() {
        let mut interrupted = RecordingReader::new([
            ReaderStep::Bytes(b"17 ".to_vec()),
            ReaderStep::Error(std::io::ErrorKind::Interrupted),
            ReaderStep::Bytes(b"1\n".to_vec()),
            ReaderStep::Eof,
        ]);
        let mut budget = CaptureWorkBudget::default();
        assert_eq!(
            read_mountinfo_with(&mut interrupted, &mut budget, 3, |_| None).unwrap(),
            "17 1\n"
        );
        assert_eq!(interrupted.requests.len(), 4, "EINTR and EOF are attempts");
        assert_eq!(budget.attempted_io_bytes(), 5);
        assert_eq!(budget.work_units, 5, "four attempts plus one observed line");

        let mut failed = RecordingReader::new([
            ReaderStep::Bytes(b"17 1 8:1 /".to_vec()),
            ReaderStep::Error(std::io::ErrorKind::Other),
        ]);
        let mut budget = CaptureWorkBudget::default();
        assert!(read_mountinfo_with(&mut failed, &mut budget, 32, |_| None).is_err());
        assert_eq!(failed.requests.len(), 2);
        assert_eq!(budget.attempted_io_bytes(), 10);
    }

    #[test]
    fn mountinfo_reader_never_reads_after_exhaustion_and_rechecks_deadline_before_publish() {
        for mut budget in [
            CaptureWorkBudget::new(ScanLimits {
                per_object_bytes: 0,
                total_bytes: 8,
            }),
            CaptureWorkBudget::new(ScanLimits {
                per_object_bytes: 8,
                total_bytes: 0,
            }),
        ] {
            let mut reader = RecordingReader::new([ReaderStep::Bytes(b"x".to_vec())]);
            assert!(read_mountinfo_with(&mut reader, &mut budget, 8, |_| None).is_err());
            assert!(reader.requests.is_empty());
        }

        let mut aggregate_exact =
            RecordingReader::new([ReaderStep::Bytes(b"abc\n".to_vec()), ReaderStep::Eof]);
        let mut budget = CaptureWorkBudget::new(ScanLimits {
            per_object_bytes: 4,
            total_bytes: 4,
        });
        assert_eq!(
            read_mountinfo_with(&mut aggregate_exact, &mut budget, 8, |_| None).unwrap_err(),
            IO_CEILING_REASON
        );
        assert_eq!(
            aggregate_exact.requests,
            [4],
            "aggregate exhaustion refuses without an EOF probe"
        );
        assert_eq!(budget.attempted_io_bytes(), 4);

        let mut budget = CaptureWorkBudget::default();
        assert!(!budget.charge(u64::MAX));
        let mut stopped = RecordingReader::new([ReaderStep::Bytes(b"x".to_vec())]);
        assert_eq!(
            read_mountinfo_with(&mut stopped, &mut budget, 8, |_| None).unwrap_err(),
            WORK_CEILING_REASON
        );
        assert!(stopped.requests.is_empty());

        let mut deadline =
            RecordingReader::new([ReaderStep::Bytes(b"17 1\n".to_vec()), ReaderStep::Eof]);
        let mut budget = CaptureWorkBudget::default();
        let mut polls = 0;
        let error = read_mountinfo_with(&mut deadline, &mut budget, 8, |_| {
            polls += 1;
            (polls == 3).then_some(SCAN_DEADLINE_REASON)
        })
        .unwrap_err();
        assert_eq!(error, SCAN_DEADLINE_REASON);
        assert_eq!(deadline.requests.len(), 2);
        assert_eq!(polls, 3, "before each read and after EOF publication");

        let mut between = RecordingReader::new([
            ReaderStep::Bytes(b"17 ".to_vec()),
            ReaderStep::Bytes(b"1\n".to_vec()),
        ]);
        let mut budget = CaptureWorkBudget::default();
        let mut polls = 0;
        assert_eq!(
            read_mountinfo_with(&mut between, &mut budget, 3, |_| {
                polls += 1;
                (polls == 2).then_some(SCAN_DEADLINE_REASON)
            })
            .unwrap_err(),
            SCAN_DEADLINE_REASON
        );
        assert_eq!(between.requests.len(), 1, "expiry prevents the next chunk");
    }

    /// Fix A: admission charges each unique table once. Byte-identical
    /// repeats skip the candidate charge but still decode (per-view results
    /// are never served from a cache); byte-different tables charge again.
    #[test]
    fn repeat_table_bytes_skip_the_candidate_charge_but_still_decode() {
        fn table_snapshot(version: u64, fields: usize) -> Vec<u8> {
            let mut snapshot = vec![0u8; 8 + fields * 8];
            snapshot[..8].copy_from_slice(&version.to_le_bytes());
            for slot in 0..fields {
                let at = 8 + slot * 8;
                snapshot[at..at + 8].copy_from_slice(&0x1500u64.to_le_bytes());
            }
            snapshot
        }

        let maps = parse_maps(
            b"1000-3000 r-xp 00000000 08:01 7 /lib/provider.so\n\
              7000-9000 r--p 00001000 08:01 7 /lib/provider.so\n",
        )
        .unwrap();
        let map_index = MapIndex::new(&maps).unwrap();
        let mut budget = CaptureWorkBudget::default();

        let first_snapshot = table_snapshot(0x0203, 104);
        let first = decode_exact_table(
            &first_snapshot,
            0x7000,
            LinuxLayout::Lp64,
            &map_index,
            &mut budget,
        )
        .expect("a valid table decodes")
        .expect("all slots walkable");
        assert_eq!(budget.table_candidates_count(), 1);

        let repeat = decode_exact_table(
            &first_snapshot,
            0x7000,
            LinuxLayout::Lp64,
            &map_index,
            &mut budget,
        )
        .expect("a valid table decodes")
        .expect("the repeat decodes too, never from a cache");
        assert_eq!(repeat, first);
        assert_eq!(
            budget.table_candidates_count(),
            1,
            "byte-identical repeats must not burn another candidate"
        );

        let other_snapshot = table_snapshot(0x0003, 92);
        let other = decode_exact_table(
            &other_snapshot,
            0x7000,
            LinuxLayout::Lp64,
            &map_index,
            &mut budget,
        )
        .expect("a valid table decodes")
        .expect("different bytes decode");
        assert_ne!(other.version, first.version);
        assert_eq!(
            budget.table_candidates_count(),
            2,
            "byte-different tables burn again"
        );
    }

    // Two scans, one file: authored maps reference a real copied binary so the
    // ELF-snapshot read has real bytes to charge. Executable mapping only: the
    // group carries code (candidate_groups keeps it) but no readable data
    // pages, so no target-memory reads pollute the per-scan I/O delta.
    struct ElfExportFactsFixture {
        _dir: tempfile::TempDir,
        path: PathBuf,
        maps: String,
        mem: File,
        next_view: u32,
    }

    impl ScanIo for ElfExportFactsFixture {
        type Memory = File;
        fn open_maps(
            &mut self,
            _: &ProcessView,
            _: &CaptureWorkBudget,
        ) -> std::io::Result<Box<dyn Read>> {
            Ok(Box::new(std::io::Cursor::new(
                self.maps.clone().into_bytes(),
            )))
        }
        fn open_mem(&mut self, _: &ProcessView) -> std::io::Result<File> {
            self.mem.try_clone()
        }
        fn final_generation(&mut self, view: &ProcessView) -> Result<(), String> {
            view.run_while_same(|| ())
        }
    }

    impl ElfExportFactsFixture {
        fn new() -> Self {
            let dir = tempfile::tempdir().unwrap();
            let path = dir.path().join("provider.so");
            std::fs::copy("/bin/sh", &path).unwrap();
            Self::wrap(dir, path)
        }

        /// A real hook-exporting provider, so sparse tests pin facts — not
        /// just the absence of facts — on files the whole-size gate refused.
        fn new_provider() -> Self {
            let dir = tempfile::tempdir().unwrap();
            let c = dir.path().join("provider.c");
            let path = dir.path().join("provider.so");
            std::fs::write(
                &c,
                "unsigned long C_GetFunctionList(void **p){(void)p;return 0;}\n\
                 unsigned long NSC_GetFunctionList(void **p){(void)p;return 0;}\n",
            )
            .unwrap();
            let ok = std::process::Command::new("gcc")
                .args(["-shared", "-fPIC", "-o"])
                .arg(&path)
                .arg(&c)
                .status()
                .unwrap()
                .success();
            assert!(ok, "gcc failed for the provider fixture");
            Self::wrap(dir, path)
        }

        fn wrap(dir: tempfile::TempDir, path: PathBuf) -> Self {
            let view = ProcessView::open(ProcessViewId(71), std::process::id()).unwrap();
            let file = File::open(&path).unwrap();
            let key = crate::discovery::identity::retained_object_key(
                &view,
                &file,
                &mut CaptureWorkBudget::default(),
            )
            .unwrap();
            let maps = format!(
                "1000-2000 r-xp 00000000 {:x}:{:x} {} {}\n",
                key.device.major,
                key.device.minor,
                key.inode,
                path.display(),
            );
            let mem = tempfile::tempfile().unwrap();
            mem.set_len(0x2000).unwrap();
            Self {
                _dir: dir,
                path,
                maps,
                mem,
                next_view: 72,
            }
        }

        fn scan(&mut self, budget: &mut CaptureWorkBudget) -> ScanOutcome {
            let id = self.next_view;
            self.next_view += 1;
            let view = ProcessView::open(ProcessViewId(id), std::process::id()).unwrap();
            let hints = [self.path.clone()];
            let hooks = HookRegistry::builtin();
            scan_process_view_with_io(
                &ScanRequest {
                    pid: view.pid(),
                    hints: &hints,
                    hooks: &hooks,
                },
                &view,
                budget,
                self,
            )
            .unwrap()
        }
    }

    #[test]
    fn second_view_of_same_file_reads_no_elf_bytes() {
        let mut fixture = ElfExportFactsFixture::new();
        let file_len = std::fs::metadata(&fixture.path).unwrap().len();
        assert!(file_len > 0, "the fixture must have bytes worth caching");
        let mut budget = CaptureWorkBudget::default();

        // First scan reads the sparse ELF tables (plus maps and the mount table).
        let first = fixture.scan(&mut budget);
        let charged_first = budget.attempted_io_bytes();
        assert!(
            charged_first < file_len,
            "first scan charges sparse ELF tables, not the whole file: \
             {charged_first} < {file_len}"
        );
        assert_eq!(first.modules().len(), 1, "skipped: {:?}", first.skipped());

        // Second scan of the same file: maps/mountinfo bytes only, no ELF re-read.
        let second = fixture.scan(&mut budget);
        let charged_second = budget.attempted_io_bytes() - charged_first;
        assert_eq!(second.modules().len(), 1, "skipped: {:?}", second.skipped());
        assert_eq!(
            second.modules()[0].decoder_abi,
            first.modules()[0].decoder_abi,
            "both scans report the same ABI"
        );
        assert_eq!(
            second.modules()[0].exports,
            first.modules()[0].exports,
            "both scans report the same export names"
        );
        assert!(
            charged_second < file_len,
            "second scan must not re-read {file_len} ELF bytes (charged {charged_second})"
        );
        assert!(
            charged_second < charged_first,
            "the cache hit charges no ELF bytes: {charged_second} < {charged_first}"
        );
    }

    #[test]
    fn changed_file_rereads_elf() {
        use std::io::Write as _;

        let mut fixture = ElfExportFactsFixture::new();
        let mut budget = CaptureWorkBudget::default();
        let first = fixture.scan(&mut budget);
        assert_eq!(first.modules().len(), 1, "skipped: {:?}", first.skipped());
        let charged_first = budget.attempted_io_bytes();

        // A size-changing rewrite between scans (same path and inode).
        let mut rewritten = std::fs::OpenOptions::new()
            .append(true)
            .open(&fixture.path)
            .unwrap();
        rewritten.write_all(&[0; 1024]).unwrap();
        drop(rewritten);
        let new_len = std::fs::metadata(&fixture.path).unwrap().len();

        // A changed file misses the cache: the ELF tables are read and charged again.
        let second = fixture.scan(&mut budget);
        let charged_second = budget.attempted_io_bytes() - charged_first;
        assert!(
            charged_second < new_len,
            "changed file is re-read sparsely: {charged_second} < {new_len}"
        );
        assert_eq!(second.modules().len(), 1, "skipped: {:?}", second.skipped());

        // A third scan hits the new pin: strictly fewer bytes than the re-read.
        let third = fixture.scan(&mut budget);
        let charged_third = budget.attempted_io_bytes() - charged_first - charged_second;
        assert_eq!(third.modules().len(), 1, "skipped: {:?}", third.skipped());
        assert!(
            charged_third < charged_second,
            "the re-read tables are cached again: {charged_third} < {charged_second}"
        );

        // The reported facts come from the new bytes, not the cached read.
        let file = File::open(&fixture.path).unwrap();
        let snapshot = ElfSnapshot::read(&file).unwrap();
        let hooks = HookRegistry::builtin();
        let wanted = hooks.names();
        let expected: Vec<String> = snapshot
            .exports_matching(&wanted)
            .unwrap()
            .into_iter()
            .map(|(name, _)| name)
            .collect();
        assert_eq!(second.modules()[0].decoder_abi, Some(snapshot.abi()));
        assert_eq!(second.modules()[0].exports, expected);
    }

    #[test]
    fn oversize_file_exports_are_checked_sparsely() {
        // A hook-exporting provider sparsely extended past the scan
        // per-object cap (the libxul shape): the export check still reports
        // facts, charging tables rather than the file. Explicit small limits:
        // the default cap now equals the manifest pin gate, so sizing past
        // the default would trip a different gate than the one tested here.
        let mut fixture = ElfExportFactsFixture::new_provider();
        let oversize = 2 * 1024 * 1024;
        std::fs::OpenOptions::new()
            .write(true)
            .open(&fixture.path)
            .unwrap()
            .set_len(oversize)
            .unwrap();
        let file_len = std::fs::metadata(&fixture.path).unwrap().len();
        let limits = ScanLimits {
            per_object_bytes: 1024 * 1024,
            total_bytes: u64::MAX,
        };
        assert!(file_len > limits.per_object_bytes);

        let mut budget = CaptureWorkBudget::new(limits);
        let outcome = fixture.scan(&mut budget);
        assert_eq!(
            outcome.modules().len(),
            1,
            "skipped: {:?}",
            outcome.skipped()
        );
        assert!(
            !outcome.modules()[0].exports.is_empty(),
            "hook exports must be reported past the per-object cap"
        );
        assert!(
            outcome
                .skipped()
                .iter()
                .all(|skip| !skip.reason.contains("too_large")),
            "no whole-size gate on the export check: {:?}",
            outcome.skipped()
        );
        assert!(
            budget.attempted_io_bytes() < file_len,
            "charged bytes must be tables, not the {file_len}-byte file: {}",
            budget.attempted_io_bytes()
        );
    }

    #[test]
    fn sparse_read_charges_bounded_bytes() {
        // A 2 MiB provider: a whole-file read would charge megabytes, while
        // the export tables cost kilobytes.
        let mut fixture = ElfExportFactsFixture::new_provider();
        std::fs::OpenOptions::new()
            .write(true)
            .open(&fixture.path)
            .unwrap()
            .set_len(2 * 1024 * 1024)
            .unwrap();

        let mut budget = CaptureWorkBudget::default();
        let outcome = fixture.scan(&mut budget);
        assert_eq!(
            outcome.modules().len(),
            1,
            "skipped: {:?}",
            outcome.skipped()
        );
        assert!(
            !outcome.modules()[0].exports.is_empty(),
            "hook exports must be reported"
        );
        assert!(
            budget.attempted_io_bytes() < 1024 * 1024,
            "first scan must charge ELF tables, not the 2 MiB file: {}",
            budget.attempted_io_bytes()
        );
    }

    #[test]
    fn sparse_export_charge_applies_capture_ceiling_post_hoc() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("provider.so");
        std::fs::copy("/bin/sh", &path).unwrap();
        let file = File::open(&path).unwrap();
        let hooks = HookRegistry::builtin();
        let wanted = hooks.names();

        // No room for even the ELF header: the identical ceiling skip today's
        // mid-read abort produces, with the budget saturated as today.
        let mut budget = CaptureWorkBudget::new(ScanLimits {
            per_object_bytes: u64::MAX,
            total_bytes: 10,
        });
        let error = read_export_facts_budgeted(&file, &wanted, &mut budget).unwrap_err();
        assert_eq!(error, format!("read failed: {IO_CEILING_REASON}"));
        assert_eq!(budget.attempted_io_bytes(), 10);

        // Room for the tables: bounded bytes charged, facts equal the oracle.
        let mut budget = CaptureWorkBudget::new(ScanLimits {
            per_object_bytes: u64::MAX,
            total_bytes: u64::MAX,
        });
        let (abi, exports) = read_export_facts_budgeted(&file, &wanted, &mut budget).unwrap();
        let charged = budget.attempted_io_bytes();
        assert!(
            charged > 0 && charged < 1024 * 1024,
            "the tables must cost bounded bytes: {charged}"
        );
        let snapshot = ElfSnapshot::read(&file).unwrap();
        assert_eq!(abi, snapshot.abi());
        assert_eq!(exports, snapshot.exports_matching(&wanted).unwrap());
    }

    /// A3-M1 hardening: a failed post-read re-pin refuses with the pin's own
    /// I/O message — never folded into the changed-file retry. `before` and
    /// the mismatching pin are real `pin_of` values from two files (distinct
    /// inodes, so deterministically unequal); the I/O error carries `pin_of`'s
    /// verbatim `fstat failed` shape. (An end-to-end injection would need an
    /// fd-closing hook — racy under parallel tests — or a `pin_of` seam, so
    /// the decision itself is pinned here; the call-site wiring is enforced
    /// by the dead-code lint denying an uncalled helper.)
    #[test]
    fn post_read_pin_io_error_reports_its_own_message() {
        let dir = tempfile::tempdir().unwrap();
        let first = dir.path().join("first.so");
        let second = dir.path().join("second.so");
        std::fs::copy("/bin/sh", &first).unwrap();
        std::fs::copy("/bin/sh", &second).unwrap();
        let before = pin_of(&File::open(&first).unwrap()).unwrap();
        let other = pin_of(&File::open(&second).unwrap()).unwrap();
        assert_ne!(other, before, "distinct files pin distinctly");

        // The I/O arm: a failed re-pin reports its own message, still refused.
        let io = "fstat failed: simulated I/O failure".to_string();
        assert_eq!(
            check_pin_after_read(Err(io.clone()), &before),
            Err(io),
            "a pin I/O error must not be misdescribed as a change"
        );
        // The refusal arm: a changed file keeps the retry message.
        assert_eq!(
            check_pin_after_read(Ok(other), &before),
            Err("file changed while it was being scanned — retry".to_string())
        );
        // The stable arm: an unchanged file passes with no refusal.
        assert_eq!(check_pin_after_read(Ok(before), &before), Ok(()));
    }
}
