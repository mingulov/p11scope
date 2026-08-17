//! Finding PKCS#11 function tables by reading the target's mapped memory. No provider
//! code is executed and nothing is copied: `/proc/<pid>/maps` says what is mapped,
//! `.dynsym` says which objects could hand out a table, and the target's own
//! non-executable pages are searched for the `CK_FUNCTION_LIST` signature. Table
//! layout comes from `pkcs11_module::tables_for`/`read_fn_pointers` — the same
//! authority the offline helper uses — so a scanned offset equals a manifest offset.

use crate::discovery::hooks::HookRegistry;
use p11scope_manifest::elf::exports_matching;
use p11scope_manifest::identity::open_object;
use p11scope_manifest::maps::{MapEntry, MappedPath, ObjectKey, Resolved, parse_maps, resolve};
use pkcs11_module::{Surface, TableSet, TableSpan, read_fn_pointers, tables_for};
use std::collections::BTreeMap;
use std::fs::File;
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
pub(crate) const IO_CEILING_REASON: &str =
    "capture attempted-I/O ceiling reached; remaining provider bytes were not read";

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
        self.attempted_io_bytes += bytes as u64;
    }

    fn admit_table(&mut self, entries: usize) -> bool {
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

    fn admit_interface(&mut self) -> bool {
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
    /// Entries this scan decoded but dropped because their object could not be
    /// pinned (`main::drop_unpinned_entries`). Kept here so they stay counted
    /// as *seen* and are reported as skipped, exactly like the NULL ones: a
    /// record the scan read and could not use is evidence, not silence.
    pub unpinned: Vec<Skipped>,
    /// Address of the version word in the target, for interface cross-reference.
    pub address: u64,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ScannedInterface {
    pub index: usize,
    /// "exact_standard" | "other" | "null" | "unreadable". "unreadable" covers all
    /// three ways a name does not become text: the read failed, the name ran past
    /// `INTERFACE_NAME_CAP`, or the pointer was outside this object's readable pages
    /// and was deliberately not dereferenced.
    pub name_class: &'static str,
    /// Kept for `inspect` and manifests only; never rendered in capture output.
    pub name_lossy: Option<String>,
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
fn spans_for(word: u64) -> Option<((u8, u8), &'static [TableSpan], &'static str)> {
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

/// Decodes one candidate at `offset` inside `snapshot` (whose first byte is at
/// `base_address` in the target). Returns the table only when every published slot
/// is either NULL or points into a file-backed executable mapping — the criterion
/// that makes a run of pointers a function table rather than data that looks like one.
fn decode_candidate(
    snapshot: &[u8],
    offset: usize,
    base_address: u64,
    maps: &[MapEntry],
    mapped: &std::ops::Range<u64>,
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
            if !mapped.contains(&(value as u64)) {
                return Ok(None); // outside every mapping ⇒ resolve would say Unmapped
            }
            let Resolved::File {
                permissions, path, ..
            } = resolve(maps, value as u64)
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
            } = resolve(maps, value as u64)
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
        },
        len,
    )))
}

/// Every 8-byte-aligned candidate in one snapshot, longest match kept on overlap.
/// The second return carries the one bounded exhaustion reason, if decoding stopped.
fn detect_tables(
    snapshot: &[u8],
    base_address: u64,
    maps: &[MapEntry],
    budget: &mut CaptureWorkBudget,
) -> (Vec<ScannedTable>, Vec<String>) {
    // One pass over the maps here saves a linear `resolve` scan per rejected word.
    let (low, high) = maps.iter().fold((u64::MAX, 0), |(low, high), entry| {
        (low.min(entry.start), high.max(entry.end))
    });
    let mapped = low..high;
    let mut skipped = Vec::new();
    let mut found: Vec<(usize, usize, ScannedTable)> = Vec::new();
    let mut offset = 0usize;
    while offset + WORD <= snapshot.len() {
        if budget.tables_exhausted() {
            if let Some(reason) = budget.table_exhaustion_reason() {
                skipped.push(reason);
            }
            break;
        }
        match decode_candidate(snapshot, offset, base_address, maps, &mapped, budget) {
            Ok(Some((table, len))) => found.push((offset, len, table)),
            Ok(None) => {}
            Err(()) => {
                if let Some(reason) = budget.table_exhaustion_reason() {
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
    maps: &[MapEntry],
    key: ObjectKey,
    budget: &mut CaptureWorkBudget,
    operation_bytes: &mut u64,
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
    let mut offset = 0usize;
    while offset + INTERFACE_BYTES <= snapshot.len() {
        if budget.interfaces_exhausted() {
            if let Some(reason) = budget.interface_exhaustion_reason() {
                skipped.push(reason);
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
            let table = tables.iter().position(|t| t.address == table_ptr)?;
            if !budget.admit_interface() {
                return None;
            }
            // Privacy boundary: a triple is accepted on `table_ptr` alone, so the name
            // pointer of a look-alike structure could aim anywhere. Only this object's
            // own readable pages — where a provider keeps its interface names — are
            // ever dereferenced; anything else is recorded without being read.
            let readable_here = matches!(
                resolve(maps, name_ptr),
                Resolved::File {
                    device, inode, permissions, ..
                } if permissions[0] == b'r' && ObjectKey { device, inode } == key
            );
            let (name_class, name_lossy) = match name_ptr {
                0 => ("null", None),
                _ if !readable_here => ("unreadable", None),
                _ => match read_name(mem, name_ptr, budget, operation_bytes) {
                    Ok(Some(raw)) if raw == STANDARD_INTERFACE_NAME => (
                        "exact_standard",
                        Some(String::from_utf8_lossy(&raw).into_owned()),
                    ),
                    Ok(Some(raw)) => ("other", Some(String::from_utf8_lossy(&raw).into_owned())),
                    Ok(None) => ("unreadable", None),
                    Err(()) => {
                        io_exhausted = true;
                        ("unreadable", None)
                    }
                },
            };
            Some(ScannedInterface {
                index: 0,
                name_class,
                name_lossy,
                flags,
                table: Some(table),
            })
        })();
        if let Some(scanned) = scanned {
            found.push(scanned);
        }
        if io_exhausted {
            skipped.push(IO_CEILING_REASON.into());
            break;
        }
        offset += WORD;
    }
    (found, skipped)
}

/// A NUL-terminated name of at most `INTERFACE_NAME_CAP` bytes, or `None` when the
/// target memory could not be read or the name runs past the cap.
fn read_name(
    mem: &File,
    address: u64,
    budget: &mut CaptureWorkBudget,
    operation_bytes: &mut u64,
) -> Result<Option<Vec<u8>>, ()> {
    let mut raw: Vec<u8> = Vec::with_capacity(INTERFACE_NAME_CAP);
    while raw.len() < INTERFACE_NAME_CAP {
        let mut chunk = [0u8; 32];
        let want = chunk.len().min(INTERFACE_NAME_CAP - raw.len());
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
fn open_in_target(pid: u32, path: &str) -> Result<File, String> {
    open_object(Path::new(&format!("/proc/{pid}/root{path}")))
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

pub fn scan_pid(
    request: &ScanRequest<'_>,
    budget: &mut CaptureWorkBudget,
) -> Result<ScanOutcome, String> {
    let started = Instant::now();
    let pid = request.pid;
    let maps = parse_maps(
        &std::fs::read(format!("/proc/{pid}/maps"))
            .map_err(|error| format!("/proc/{pid}/maps: {error}"))?,
    )?;

    let mut modules = Vec::new();
    let mut skipped = Vec::new();
    // `/proc/<pid>/mem` is gated by PTRACE_MODE_ATTACH and Yama; losing it costs the
    // tables, never the object inventory (spec §4.1 step 3). Only an access refusal is
    // a ptrace refusal — a pid that died mid-scan gets its own label.
    let mem = File::open(format!("/proc/{pid}/mem"));
    let unavailable = mem.as_ref().err().map(|error| {
        skipped.push(Skipped {
            subject: format!("/proc/{pid}/mem"),
            reason: error.to_string(),
        });
        match error.raw_os_error() {
            Some(libc::EACCES | libc::EPERM) => "ptrace",
            Some(libc::ESRCH) => "gone",
            _ => "unreadable",
        }
    });
    let mem = mem.ok();

    let wanted = request.hooks.names();
    let hint_ids: Vec<Option<(u64, u64)>> =
        request.hints.iter().map(|h| hint_identity(h)).collect();
    let mut hint_matched = vec![false; request.hints.len()];

    for (key, group) in candidate_groups(&maps) {
        // A group with no `/`-rooted pathname (memfd, pseudo-path) is still a real
        // object: it is recorded as skipped rather than silently dropped.
        let named = group
            .iter()
            .find_map(|entry| match resolve(&maps, entry.start) {
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

        let file = match open_in_target(pid, &path) {
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
                skipped.push(Skipped {
                    subject: module.path.clone(),
                    reason,
                });
            }
            snapshots.push((entry.start, bytes));
            if exhausted {
                io_exhausted = true;
                break;
            }
        }
        for (base, snapshot) in &snapshots {
            let (tables, exhausted) = detect_tables(snapshot, *base, &maps, budget);
            module.tables.extend(tables);
            skipped.extend(exhausted.into_iter().map(|reason| Skipped {
                subject: module.path.clone(),
                reason,
            }));
        }
        for (_, snapshot) in &snapshots {
            let (interfaces, exhausted) = scan_interfaces(
                snapshot,
                mem,
                &module.tables,
                &maps,
                key,
                budget,
                &mut operation_bytes,
            );
            module.interfaces.extend(interfaces);
            let interface_io_exhausted = exhausted.iter().any(|reason| reason == IO_CEILING_REASON);
            skipped.extend(exhausted.into_iter().map(|reason| Skipped {
                subject: module.path.clone(),
                reason,
            }));
            if interface_io_exhausted {
                io_exhausted = true;
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
        if module.tables.is_empty() && !io_exhausted {
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

    Ok(match unavailable {
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
    })
}

#[cfg(test)]
mod tests {
    use super::*;

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
        let (tables, truncated) =
            detect_tables(&snapshot, 0x7000, &maps, &mut CaptureWorkBudget::default());
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
        // A 2.40 header with only 10 of its 68 slots inside the snapshot: exactly the
        // shape of a table whose .bss has spilled into an anonymous mapping.
        let mut snapshot = vec![0u8; 8 + 10 * 8];
        snapshot[..8].copy_from_slice(&0x2802u64.to_ne_bytes());
        for slot in 0..10 {
            let at = 8 + slot * 8;
            snapshot[at..at + 8].copy_from_slice(&0x1500u64.to_ne_bytes());
        }
        let (tables, truncated) =
            detect_tables(&snapshot, 0x7000, &maps, &mut CaptureWorkBudget::default());
        assert!(tables.is_empty(), "an incomplete table is never decoded");
        assert!(truncated.is_empty(), "a version word alone is not evidence");
        // Ordinary data must not generate this diagnostic.
        assert!(
            detect_tables(
                &vec![0u8; 4096],
                0x7000,
                &maps,
                &mut CaptureWorkBudget::default()
            )
            .1
            .is_empty()
        );
    }

    #[test]
    fn dense_candidates_and_interfaces_stop_at_capture_caps() {
        let maps = parse_maps(b"1000-3000 r-xp 00000000 08:01 7 /lib/provider.so\n").unwrap();
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
        let (tables, skipped) = detect_tables(&snapshot, 0x7000, &maps, &mut budget);
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
            &maps,
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
    fn interface_name_reads_share_the_capture_io_budget() {
        let maps = parse_maps(
            b"0-1000 r--p 00000000 08:01 7 /lib/provider.so\n\
              1000-3000 r-xp 00001000 08:01 7 /lib/provider.so\n",
        )
        .unwrap();
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
            &maps,
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
                &maps,
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
                &maps,
                &mut CaptureWorkBudget::default()
            )
            .0
            .is_empty()
        ); // rw- data
        assert!(
            detect_tables(
                &build(0x9000),
                0x2000,
                &maps,
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
                &maps,
                &mut CaptureWorkBudget::default()
            )
            .0
            .is_empty()
        );
        // One NULL slot among live ones is legitimate evidence, not a rejection.
        let mut with_null = build(0x1600);
        with_null[16..24].copy_from_slice(&0u64.to_ne_bytes());
        let (tables, _) =
            detect_tables(&with_null, 0x2000, &maps, &mut CaptureWorkBudget::default());
        assert_eq!(tables[0].null_entries.len(), 1);
        assert_eq!(tables[0].entries.len(), 67);
    }
}
