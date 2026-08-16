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

pub struct ScanRequest<'a> {
    pub pid: u32,
    /// `--module` hints; empty means "every object exporting a registry symbol".
    pub hints: &'a [PathBuf],
    pub hooks: &'a HookRegistry,
    pub limits: ScanLimits,
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
    /// Address of the version word in the target, for interface cross-reference.
    pub address: u64,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ScannedInterface {
    pub index: usize,
    /// "exact_standard" | "other" | "null" | "unreadable"
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
) -> Option<(ScannedTable, usize)> {
    let word = u64::from_ne_bytes(
        snapshot
            .get(offset..offset.checked_add(WORD)?)?
            .try_into()
            .ok()?,
    );
    let (version, spans, walk) = spans_for(word)?;
    let len = span_bytes(spans)?;
    let bytes = snapshot.get(offset..offset.checked_add(len)?)?;
    let address = base_address.checked_add(offset as u64)?;

    let mut entries = Vec::new();
    let mut null_entries = Vec::new();
    let mut non_null = 0usize;
    for span in spans {
        let values = read_fn_pointers(bytes, span.fields()).ok()?;
        for (name, value) in values {
            if value == 0 {
                null_entries.push(name);
                continue;
            }
            non_null += 1;
            let Resolved::File {
                path,
                file_offset,
                device,
                inode,
                permissions,
                ..
            } = resolve(maps, value as u64)
            else {
                return None; // anonymous or unmapped ⇒ not a function table
            };
            if permissions[2] != b'x' {
                return None; // a pointer into data ⇒ not a function table
            }
            let MappedPath::Usable(path) = path else {
                return None; // deleted/ambiguous pathname ⇒ cannot become an attach target
            };
            entries.push(ScannedEntry {
                name,
                object: ObjectKey { device, inode },
                object_path: path.display().to_string(),
                file_offset,
            });
        }
    }
    if non_null == 0 {
        return None;
    }
    Some((
        ScannedTable {
            version,
            walk,
            entries,
            null_entries,
            address,
        },
        len,
    ))
}

/// Every 8-byte-aligned candidate in one snapshot, longest match kept on overlap.
fn detect_tables(snapshot: &[u8], base_address: u64, maps: &[MapEntry]) -> Vec<ScannedTable> {
    let mut found: Vec<(usize, usize, ScannedTable)> = Vec::new();
    let mut offset = 0usize;
    while offset + WORD <= snapshot.len() {
        if let Some((table, len)) = decode_candidate(snapshot, offset, base_address, maps) {
            found.push((offset, len, table));
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
    kept.into_iter().map(|(_, _, table)| table).collect()
}

/// `CK_INTERFACE` triples in one snapshot that name a table this scan decoded.
/// The triple's own address is not recorded, so no `base_address` is needed here.
fn scan_interfaces(snapshot: &[u8], mem: &File, tables: &[ScannedTable]) -> Vec<ScannedInterface> {
    let word_at = |offset: usize| -> Option<u64> {
        Some(u64::from_ne_bytes(
            snapshot
                .get(offset..offset.checked_add(WORD)?)?
                .try_into()
                .ok()?,
        ))
    };
    let mut found = Vec::new();
    let mut offset = 0usize;
    while offset + INTERFACE_BYTES <= snapshot.len() {
        let scanned = (|| {
            let name_ptr = word_at(offset)?;
            let table_ptr = word_at(offset + WORD)?;
            let flags = word_at(offset + 2 * WORD)?;
            // The function-list pointer is the anchor: without it a triple of words
            // is just data. Requiring a decoded table also keeps the byte budget —
            // only the provider's own mappings are ever read.
            let table = tables.iter().position(|t| t.address == table_ptr)?;
            let (name_class, name_lossy) = if name_ptr == 0 {
                ("null", None)
            } else {
                match read_name(mem, name_ptr) {
                    Some(raw) if raw == STANDARD_INTERFACE_NAME => (
                        "exact_standard",
                        Some(String::from_utf8_lossy(&raw).into_owned()),
                    ),
                    Some(raw) => ("other", Some(String::from_utf8_lossy(&raw).into_owned())),
                    None => ("unreadable", None),
                }
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
        offset += WORD;
    }
    found
}

/// A NUL-terminated name of at most `INTERFACE_NAME_CAP` bytes, or `None` when the
/// target memory could not be read or the name runs past the cap.
fn read_name(mem: &File, address: u64) -> Option<Vec<u8>> {
    let mut raw: Vec<u8> = Vec::with_capacity(INTERFACE_NAME_CAP);
    while raw.len() < INTERFACE_NAME_CAP {
        let mut chunk = [0u8; 32];
        let want = chunk.len().min(INTERFACE_NAME_CAP - raw.len());
        let at = address.checked_add(raw.len() as u64)?;
        let read = match mem.read_at(&mut chunk[..want], at) {
            Ok(0) | Err(_) => return None,
            Ok(read) => read,
        };
        if let Some(nul) = chunk[..read].iter().position(|byte| *byte == 0) {
            raw.extend_from_slice(&chunk[..nul]);
            return Some(raw);
        }
        raw.extend_from_slice(&chunk[..read]);
    }
    None
}

/// `entry.start..entry.end` from the target, in ≤1 MiB chunks. A short or failed read
/// ends this mapping and keeps what was read: a guard page must not lose the rest.
fn read_mapping(mem: &File, entry: &MapEntry) -> Vec<u8> {
    let Some(len) = entry.end.checked_sub(entry.start).map(|len| len as usize) else {
        return Vec::new();
    };
    let mut bytes = vec![0u8; len];
    let mut done = 0usize;
    while done < len {
        let want = READ_CHUNK.min(len - done);
        let Some(at) = entry.start.checked_add(done as u64) else {
            break;
        };
        match mem.read_at(&mut bytes[done..done + want], at) {
            Ok(0) | Err(_) => break,
            Ok(read) => done += read,
        }
    }
    bytes.truncate(done);
    bytes
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

fn hint_inode(hint: &Path) -> Option<u64> {
    open_object(hint)
        .ok()?
        .metadata()
        .ok()
        .map(|metadata| metadata.ino())
}

pub fn scan_pid(request: &ScanRequest<'_>) -> Result<ScanOutcome, String> {
    let started = Instant::now();
    let pid = request.pid;
    let maps = parse_maps(
        &std::fs::read(format!("/proc/{pid}/maps"))
            .map_err(|error| format!("/proc/{pid}/maps: {error}"))?,
    )?;

    let mut modules = Vec::new();
    let mut skipped = Vec::new();
    // `/proc/<pid>/mem` is gated by PTRACE_MODE_ATTACH and Yama; losing it costs the
    // tables, never the object inventory (spec §4.1 step 3).
    let mem = match File::open(format!("/proc/{pid}/mem")) {
        Ok(mem) => Some(mem),
        Err(error) => {
            skipped.push(Skipped {
                subject: format!("/proc/{pid}/mem"),
                reason: error.to_string(),
            });
            None
        }
    };

    let wanted = request.hooks.names();
    let hint_inodes: Vec<Option<u64>> = request.hints.iter().map(|h| hint_inode(h)).collect();
    let mut hint_matched = vec![false; request.hints.len()];
    let mut total_bytes = 0u64;

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
        let matched: Vec<usize> = (0..request.hints.len())
            .filter(|index| {
                hint_inodes[*index] == Some(key.inode)
                    || usable.as_deref() == Some(request.hints[*index].as_path())
            })
            .collect();
        if !request.hints.is_empty() && matched.is_empty() {
            continue;
        }
        for index in matched {
            hint_matched[index] = true;
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
        let running = object_bytes.and_then(|bytes| total_bytes.checked_add(bytes));
        if object_bytes.is_none_or(|bytes| bytes > request.limits.per_object_bytes)
            || running.is_none_or(|running| running > request.limits.total_bytes)
        {
            let object_bytes = object_bytes.map_or("unrepresentable".into(), |b| b.to_string());
            skipped.push(Skipped {
                subject,
                reason: format!(
                    "too_large ({object_bytes} readable data bytes; caps are \
                     {} per object and {} per capture, {total_bytes} already read)",
                    request.limits.per_object_bytes, request.limits.total_bytes
                ),
            });
            modules.push(module);
            continue;
        }
        total_bytes = running.unwrap_or(total_bytes);

        let snapshots: Vec<(u64, Vec<u8>)> = data
            .iter()
            .map(|entry| (entry.start, read_mapping(mem, entry)))
            .collect();
        for (base, snapshot) in &snapshots {
            module.tables.extend(detect_tables(snapshot, *base, &maps));
        }
        for (_, snapshot) in &snapshots {
            module
                .interfaces
                .extend(scan_interfaces(snapshot, mem, &module.tables));
        }
        for (index, interface) in module.interfaces.iter_mut().enumerate() {
            interface.index = index;
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

    Ok(match mem {
        Some(_) => ScanOutcome::Scanned {
            modules,
            skipped,
            scan_ms: started.elapsed().as_millis() as u64,
        },
        None => ScanOutcome::Unavailable {
            reason: "ptrace",
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
        let tables = detect_tables(&snapshot, 0x7000, &maps);
        assert_eq!(tables.len(), 1);
        assert_eq!(tables[0].version, (3, 2));
        assert_eq!(tables[0].address, 0x7000);
        // The 2.40 header word is a NULL-looking non-pointer, so it is recorded as an
        // entry of the 3.2 table pointing into the provider's executable mapping.
        assert_eq!(tables[0].entries.len(), 104);
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
        assert_eq!(detect_tables(&build(0x1600), 0x2000, &maps).len(), 1);
        assert!(detect_tables(&build(0x2500), 0x2000, &maps).is_empty()); // rw- data
        assert!(detect_tables(&build(0x9000), 0x2000, &maps).is_empty()); // unmapped
        // Every slot NULL: a zeroed page is not a table.
        assert!(detect_tables(&vec![0u8; 8 + 68 * 8], 0x2000, &maps).is_empty());
        // One NULL slot among live ones is legitimate evidence, not a rejection.
        let mut with_null = build(0x1600);
        with_null[16..24].copy_from_slice(&0u64.to_ne_bytes());
        let tables = detect_tables(&with_null, 0x2000, &maps);
        assert_eq!(tables[0].null_entries.len(), 1);
        assert_eq!(tables[0].entries.len(), 67);
    }
}
