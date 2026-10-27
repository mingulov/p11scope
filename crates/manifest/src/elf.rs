//! SPDX-License-Identifier: GPL-3.0-or-later
//! ELF facts the observer needs about an object's *bytes*: which registry symbols it
//! exports and where they live as file offsets. Offsets are ELF object-file byte
//! offsets (docs/notes/aya-offset-semantics.md) — the same domain manifest records use,
//! so a scanned offset and a manifest offset are directly comparable.

use std::ops::Range;

use crate::identity::{read_object_bytes, read_object_bytes_with};
use object::read::elf::FileHeader as _;
use object::read::elf::ProgramHeader as _;
use object::read::elf::SectionHeader as _;
use object::{Architecture, BinaryFormat, Object as _, ObjectSegment as _, ObjectSymbol as _, elf};

const MAX_INTERPRETER_BYTES: usize = 4096;

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub struct SymbolFact {
    pub virtual_address: u64,
    pub file_offset: u64,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum ElfAbi {
    Lp64,
    Ilp32,
}

/// File-derived facts for raw memory scanning. Structural metadata may
/// contain function addresses, but those words are not ordinal anchors.
#[derive(Debug)]
pub struct RawScanElfFacts {
    pub abi: ElfAbi,
    pub exports: Vec<(String, u64)>,
    pub excluded_anchor_ranges: Vec<(u64, u64)>,
    pub structural_bytes: u64,
    pub work_units: u64,
}

/// One bounded read of an already-opened ELF, retained for every later query.
#[derive(Debug)]
pub struct ElfSnapshot {
    data: Vec<u8>,
    abi: ElfAbi,
    interpreter: Option<Range<usize>>,
    executable_ranges: Vec<(u64, u64)>,
}

/// Structural classification only (ELF magic, endianness, class/machine);
/// segment ranges are unchecked. Never translate addresses or offsets from
/// the returned object — use `classified_validated_object` for any export
/// walk or range query.
pub fn classified_object(data: &[u8]) -> Result<(object::File<'_>, ElfAbi), String> {
    let object = object::File::parse(data)
        .map_err(|error| format!("not parseable as an ELF object: {error}"))?;
    if object.format() != BinaryFormat::Elf {
        return Err(format!("not an ELF object ({:?})", object.format()));
    }
    if !object.is_little_endian() {
        return Err("not a little-endian ELF object".into());
    }
    let abi = match (object.is_64(), object.architecture()) {
        (true, Architecture::X86_64) => ElfAbi::Lp64,
        (false, Architecture::I386) => ElfAbi::Ilp32,
        _ => {
            return Err(format!(
                "not a conventional x86 Linux ELF object (class {}, architecture {:?}); \
                 x32, class/machine mismatches and foreign architectures are refused",
                if object.is_64() { 64 } else { 32 },
                object.architecture()
            ));
        }
    };
    Ok((object, abi))
}

fn parse(data: &[u8]) -> Result<object::File<'_>, String> {
    classified_object(data).map(|(object, _)| object)
}

/// Segment-range validation shared by the snapshot and demand-paged paths:
/// every segment's virtual range must not overflow `u64`, and every file
/// range must lie within the `data_len` bytes actually present. Returns the
/// executable file ranges for the snapshot's attachability index. Both
/// query paths refuse corrupt headers here, before any address translation.
fn validated_segment_ranges(
    object: &object::File<'_>,
    data_len: u64,
) -> Result<Vec<(u64, u64)>, String> {
    let mut executable_ranges = Vec::new();
    for segment in object.segments() {
        segment
            .address()
            .checked_add(segment.size())
            .ok_or_else(|| "segment virtual-address range overflows u64".to_string())?;
        let file_range = {
            let (start, size) = segment.file_range();
            let end = start
                .checked_add(size)
                .ok_or_else(|| "segment file range overflows u64".to_string())?;
            if end > data_len {
                return Err("segment file range extends past the ELF bytes".into());
            }
            (start, end)
        };
        if segment.permissions().executable() {
            executable_ranges.push(file_range);
        }
    }
    Ok(executable_ranges)
}

/// `classified_object` plus the snapshot's segment-range validation, with
/// the executable file ranges the parse produced. Every export walk goes
/// through here so corrupt headers refuse before any address translation.
/// The snapshot constructor keeps its own order (interpreter first) and does
/// not use this entry, preserving its error precedence for doubly-corrupt
/// images.
// The tuple return matches the file's existing export-facts tuples; no alias
// without a new shared type.
#[allow(clippy::type_complexity)]
pub(crate) fn classified_validated_object(
    data: &[u8],
) -> Result<(object::File<'_>, ElfAbi, Vec<(u64, u64)>), String> {
    let (object, abi) = classified_object(data)?;
    let executable_ranges = validated_segment_ranges(&object, data.len() as u64)?;
    Ok((object, abi, executable_ranges))
}

fn file_offset(object: &object::File<'_>, address: u64) -> Option<u64> {
    object.segments().find_map(|segment| {
        let start = segment.address();
        let end = start.checked_add(segment.size())?;
        if !(start..end).contains(&address) {
            return None;
        }
        let (file_start, file_size) = segment.file_range();
        let delta = address - start;
        (delta < file_size)
            .then(|| file_start.checked_add(delta))
            .flatten()
    })
}

fn load_memory_contains(object: &object::File<'_>, address: u64, end: u64) -> bool {
    macro_rules! contains {
        ($elf:expr) => {{
            let endian = $elf.endian();
            $elf.elf_program_headers()
                .iter()
                .filter(|segment| segment.p_type(endian) == elf::PT_LOAD)
                .any(|segment| {
                    let start: u64 = segment.p_vaddr(endian).into();
                    let size: u64 = segment.p_memsz(endian).into();
                    start <= address
                        && start
                            .checked_add(size)
                            .is_some_and(|segment_end| end <= segment_end)
                })
        }};
    }
    match object {
        object::File::Elf32(object) => contains!(object),
        object::File::Elf64(object) => contains!(object),
        _ => false,
    }
}

fn interpreter(object: &object::File<'_>) -> Result<Option<Range<usize>>, String> {
    let mut found = None;
    macro_rules! read_interpreter {
        ($elf:expr) => {{
            for segment in $elf
                .elf_program_headers()
                .iter()
                .filter(|segment| segment.p_type($elf.endian()) == elf::PT_INTERP)
            {
                if found.is_some() {
                    return Err("ELF contains more than one PT_INTERP segment".into());
                }
                let bytes = segment
                    .data($elf.endian(), $elf.data())
                    .map_err(|_| "malformed PT_INTERP file range".to_string())?;
                if bytes.is_empty() || bytes.len() > MAX_INTERPRETER_BYTES {
                    return Err(format!(
                        "PT_INTERP length {} is outside 1..={MAX_INTERPRETER_BYTES}",
                        bytes.len()
                    ));
                }
                let Some(path) = bytes.strip_suffix(&[0]) else {
                    return Err("PT_INTERP is not terminated by one trailing NUL".into());
                };
                if path.is_empty() || path.contains(&0) {
                    return Err("PT_INTERP contains an empty path or embedded NUL".into());
                }
                let (offset, _) = segment.file_range($elf.endian());
                let start: usize = offset
                    .try_into()
                    .map_err(|_| "PT_INTERP offset does not fit usize")?;
                let end = start
                    .checked_add(path.len())
                    .ok_or_else(|| "PT_INTERP range overflows usize".to_string())?;
                found = Some(start..end);
            }
        }};
    }
    match object {
        object::File::Elf32(object) => read_interpreter!(object),
        object::File::Elf64(object) => read_interpreter!(object),
        _ => return Err("not an ELF object".into()),
    }
    Ok(found)
}

impl ElfSnapshot {
    pub fn read(file: &std::fs::File) -> Result<Self, String> {
        let data = read_object_bytes(file)?;
        Self::from_data(data)
    }

    pub fn read_with_reader(
        file: &std::fs::File,
        reader: impl FnMut(&std::fs::File, &mut [u8], u64) -> std::io::Result<usize>,
    ) -> Result<Self, String> {
        let data = read_object_bytes_with(file, reader)?;
        Self::from_data(data)
    }

    fn from_data(data: Vec<u8>) -> Result<Self, String> {
        let (object, abi) = classified_object(&data)?;
        let interpreter = interpreter(&object)?;
        let executable_ranges = validated_segment_ranges(&object, data.len() as u64)?;

        Ok(Self {
            data,
            abi,
            interpreter,
            executable_ranges,
        })
    }

    pub fn abi(&self) -> ElfAbi {
        self.abi
    }

    pub fn interpreter(&self) -> Option<&[u8]> {
        self.interpreter
            .as_ref()
            .map(|range| &self.data[range.clone()])
    }

    pub fn defined_symbol(&self, name: &str) -> Result<Option<SymbolFact>, String> {
        let object = parse(&self.data)?;
        let mut found = None;
        for symbol in object.dynamic_symbols().chain(object.symbols()) {
            if symbol.name() != Ok(name) || !symbol.is_definition() {
                continue;
            }
            let Some(file_offset) = file_offset(&object, symbol.address()) else {
                continue;
            };
            let fact = SymbolFact {
                virtual_address: symbol.address(),
                file_offset,
            };
            match found {
                None => found = Some(fact),
                Some(previous) if previous == fact => {}
                Some(_) => {
                    return Err(format!(
                        "ELF contains duplicate definitions of symbol {name:?}"
                    ));
                }
            }
        }
        Ok(found)
    }

    /// Address of one definition whose complete value lies in PT_LOAD memory.
    /// Unlike `defined_symbol`, this intentionally accepts zero-filled BSS.
    pub fn defined_symbol_virtual_address(
        &self,
        name: &str,
        size: usize,
    ) -> Result<Option<u64>, String> {
        let object = parse(&self.data)?;
        let size = u64::try_from(size).map_err(|_| "symbol size does not fit u64")?;
        let mut found = None;
        for symbol in object.dynamic_symbols().chain(object.symbols()) {
            if symbol.name() != Ok(name) || !symbol.is_definition() {
                continue;
            }
            let address = symbol.address();
            let end = address
                .checked_add(size)
                .ok_or_else(|| format!("symbol {name:?} memory range overflows u64"))?;
            if !load_memory_contains(&object, address, end) {
                continue;
            }
            match found {
                None => found = Some(address),
                Some(previous) if previous == address => {}
                Some(_) => {
                    return Err(format!(
                        "ELF contains duplicate definitions of symbol {name:?}"
                    ));
                }
            }
        }
        Ok(found)
    }

    pub fn is_executable_offset(&self, offset: u64) -> bool {
        self.executable_ranges
            .iter()
            .any(|(start, end)| *start <= offset && offset < *end)
    }

    pub fn exports_matching(&self, wanted: &[&str]) -> Result<Vec<(String, u64)>, String> {
        // The bytes were validated at construction, so the shared validation
        // always passes here; the walk still goes through the one entry.
        let (object, _, _) = classified_validated_object(&self.data)?;
        Ok(exports_matching_in_object(&object, wanted))
    }

    pub fn raw_scan_facts(&self, wanted: &[&str]) -> Result<RawScanElfFacts, String> {
        raw_scan_facts_from_bytes(&self.data, wanted)
    }
}

fn raw_scan_facts_from_bytes(data: &[u8], wanted: &[&str]) -> Result<RawScanElfFacts, String> {
    let (object, abi, _) = classified_validated_object(data)?;
    let mut ranges = Vec::new();
    macro_rules! collect {
        ($elf:expr) => {{
            let elf = $elf;
            let endian = elf.endian();
            let sections = elf.elf_section_table();
            // The existing parser handles ELF32/64 and extended indexes.
            // Only exact GOT names need strings, and each check examines
            // at most nine bytes rather than searching an unbounded name.
            let names = elf
                .elf_header()
                .section_strings_index(endian, elf.data())
                .ok()
                .and_then(|index| sections.section(index).ok())
                .and_then(|section| section.data(endian, elf.data()).ok())
                .unwrap_or(&[]);
            for section in sections.iter() {
                let kind = section.sh_type(endian);
                let got = kind == elf::SHT_PROGBITS
                    && names
                        .get(section.sh_name(endian) as usize..)
                        .is_some_and(|name| {
                            name.starts_with(b".got\0") || name.starts_with(b".got.plt\0")
                        });
                let metadata = matches!(
                    kind,
                    elf::SHT_SYMTAB
                        | elf::SHT_STRTAB
                        | elf::SHT_RELA
                        | elf::SHT_HASH
                        | elf::SHT_DYNAMIC
                        | elf::SHT_NOTE
                        | elf::SHT_REL
                        | elf::SHT_DYNSYM
                        | elf::SHT_INIT_ARRAY
                        | elf::SHT_FINI_ARRAY
                        | elf::SHT_PREINIT_ARRAY
                        | elf::SHT_GROUP
                        | elf::SHT_SYMTAB_SHNDX
                        | elf::SHT_RELR
                        | elf::SHT_GNU_HASH
                        | elf::SHT_GNU_VERDEF
                        | elf::SHT_GNU_VERNEED
                        | elf::SHT_GNU_VERSYM
                );
                if !metadata && !got {
                    continue;
                }
                // Exclude only proven file ranges. A malformed unrelated
                // section must not suppress usable provider observations.
                if let Some((start, len)) = section.file_range(endian)
                    && let Some(end) = start.checked_add(len)
                    && start < end
                    && end <= data.len() as u64
                {
                    ranges.push((start, end));
                }
            }
            (names.len() as u64, sections.len() as u64)
        }};
    }
    let (names_bytes, work_units) = match &object {
        object::File::Elf32(elf) => collect!(elf),
        object::File::Elf64(elf) => collect!(elf),
        _ => unreachable!("classified ELF"),
    };
    ranges.sort_unstable();
    let mut merged: Vec<(u64, u64)> = Vec::new();
    for (start, end) in ranges {
        if let Some(last) = merged.last_mut().filter(|last| start <= last.1) {
            last.1 = last.1.max(end);
        } else {
            merged.push((start, end));
        }
    }
    Ok(RawScanElfFacts {
        abi,
        exports: exports_matching_in_object(&object, wanted),
        excluded_anchor_ranges: merged,
        structural_bytes: export_table_bytes(&object, data.len() as u64)
            .saturating_add(names_bytes)
            .min(data.len() as u64),
        work_units,
    })
}

/// The raw-scan companion to `read_export_facts_bounded`, using the same
/// object parser and mapping bound. Existing export-only APIs are unchanged.
pub fn read_raw_scan_facts_bounded(
    file: &std::fs::File,
    wanted: &[&str],
    max_mapped_bytes: u64,
) -> Result<RawScanElfFacts, String> {
    let len = file
        .metadata()
        .map_err(|error| format!("metadata failed: {error}"))?
        .len();
    if len > max_mapped_bytes {
        return Err(format!(
            "file length {len} exceeds reserved mapped-byte bound {max_mapped_bytes}"
        ));
    }
    let len = usize::try_from(len).map_err(|_| "ELF file length does not fit address space")?;
    // SAFETY: read-only and no longer than the current file/reservation;
    // the caller retains the existing pin-before/after discipline.
    let bytes = unsafe { memmap2::MmapOptions::new().len(len).map(file) }
        .map_err(|error| format!("read failed: {error}"))?;
    raw_scan_facts_from_bytes(&bytes, wanted)
}

/// The shared exports walk: names from `wanted` that the image exports in
/// `.dynsym`, in dynsym order with their file offsets. Per-symbol faults skip
/// the symbol; the walk itself cannot fail.
pub(crate) fn exports_matching_in_object(
    object: &object::File<'_>,
    wanted: &[&str],
) -> Vec<(String, u64)> {
    let mut found = Vec::new();
    for symbol in object.dynamic_symbols() {
        let Ok(name) = symbol.name() else { continue };
        if !wanted.contains(&name) || !symbol.is_definition() {
            continue;
        }
        if let Some(offset) = file_offset(object, symbol.address()) {
            found.push((name.to_string(), offset));
        }
    }
    found
}

/// Structural bytes the export query logically consumed: the ELF header, the
/// program- and section-header tables, and the dynamic-symbol, dynamic-string
/// and dynamic tables as present. Computed from the parsed tables — an honest
/// lower bound any correct implementation must move — clamped to the mapped
/// length so a corrupt section header claiming a larger-than-file table
/// cannot inflate the charge beyond the logical mapped range.
fn export_table_bytes(object: &object::File<'_>, mmap_len: u64) -> u64 {
    macro_rules! tables {
        ($elf:expr) => {{
            let elf = $elf;
            let endian = elf.endian();
            let mut bytes = std::mem::size_of_val(elf.elf_header()) as u64;
            bytes = bytes.saturating_add(std::mem::size_of_val(elf.elf_program_headers()) as u64);
            let sections = elf.elf_section_table();
            let shdr = sections
                .iter()
                .next()
                .map(|header| {
                    (sections.len() as u64).saturating_mul(std::mem::size_of_val(header) as u64)
                })
                .unwrap_or(0);
            bytes = bytes.saturating_add(shdr);
            let dynsym = elf.elf_dynamic_symbol_table();
            bytes = bytes.saturating_add(std::mem::size_of_val(dynsym.symbols()) as u64);
            let strings = dynsym.string_section();
            if strings.0 != 0 {
                if let Ok(header) = sections.section(strings) {
                    let size: u64 = header.sh_size(endian).into();
                    bytes = bytes.saturating_add(size);
                }
            }
            if let Ok(dynamic) = elf.elf_dynamic_table() {
                bytes = bytes.saturating_add(std::mem::size_of_val(dynamic.dynamics()) as u64);
            }
            bytes
        }};
    }
    match object {
        object::File::Elf32(object) => tables!(object).min(mmap_len),
        object::File::Elf64(object) => tables!(object).min(mmap_len),
        // Only reachable without the `classified_object` gate, which the one
        // caller applies; no ELF tables exist to charge.
        _ => 0,
    }
}

#[allow(clippy::type_complexity)]
fn export_facts_from_mmap(
    mmap: &memmap2::Mmap,
    wanted: &[&str],
) -> Result<(ElfAbi, Vec<(String, u64)>, u64 /* charged_bytes */), String> {
    // The same segment-range validation the snapshot applies: without it,
    // `file_offset` translates through corrupt headers to offsets past EOF.
    let (object, abi, _) = classified_validated_object(mmap)?;
    let exports = exports_matching_in_object(&object, wanted);
    Ok((abi, exports, export_table_bytes(&object, mmap.len() as u64)))
}

/// `(abi, exports)` for `wanted` without reading the whole file: the image is
/// demand-paged through a shared mapping and queried with the same
/// `object`-based core as [`ElfSnapshot`], so facts and segment-range
/// refusals agree exactly with the snapshot oracle (PT_INTERP validation is
/// snapshot-side only). Returns the structural table bytes the query
/// logically consumed, for budget charging. Every mapping failure takes
/// the read-failure skip shape; parsed bytes are never retained.
// The tuple return is the frozen A5 API; no alias without a new public type.
#[allow(clippy::type_complexity)]
pub fn read_export_facts(
    file: &std::fs::File,
    wanted: &[&str],
) -> Result<(ElfAbi, Vec<(String, u64)>, u64 /* charged_bytes */), String> {
    // SAFETY: a read-only shared mapping of the file; the bytes are only read
    // through the parser's checked accessors, never written or retained.
    // This relies on memmap2's no-concurrent-modification contract: the file
    // must not be modified while mapped. A truncation landing mid-parse
    // raises SIGBUS and aborts the process rather than surfacing a catchable
    // error. The window is microseconds (parse, walk, and charge touch table
    // pages only); torn reads are fenced by the pin-before/after discipline
    // on the scan path (`src/discovery/scan.rs`: pin at 1910-1929, recheck
    // at 1942, facts cached only when the pins agree), upgrades replace
    // files by rename rather than in-place truncation, and the residual
    // exposure is the plan-accepted ld.so-class risk every consumer of a
    // mapped executable shares.
    let mmap =
        unsafe { memmap2::Mmap::map(file) }.map_err(|error| format!("read failed: {error}"))?;
    export_facts_from_mmap(&mmap, wanted)
}

/// The export-facts query with an explicit upper bound on the logical byte
/// range mapped from `file`. This is an admission bound, not a measurement of
/// disk reads, page faults, allocator use, or resident memory.
#[allow(clippy::type_complexity)]
pub fn read_export_facts_bounded(
    file: &std::fs::File,
    wanted: &[&str],
    max_mapped_bytes: u64,
) -> Result<(ElfAbi, Vec<(String, u64)>, u64 /* charged_bytes */), String> {
    let file_len = file
        .metadata()
        .map_err(|error| format!("metadata failed: {error}"))?
        .len();
    if file_len > max_mapped_bytes {
        return Err(format!(
            "read failed: file length {file_len} exceeds reserved mapped-byte bound {max_mapped_bytes}"
        ));
    }
    let mapped_len = usize::try_from(file_len)
        .map_err(|_| format!("read failed: file length {file_len} does not fit address space"))?;
    // SAFETY: the declared mapping is read-only and no longer than both the
    // current file and the caller's reservation. The same concurrent file
    // modification limitation documented on `read_export_facts` applies.
    let mmap = unsafe { memmap2::MmapOptions::new().len(mapped_len).map(file) }
        .map_err(|error| format!("read failed: {error}"))?;
    export_facts_from_mmap(&mmap, wanted)
}

/// Names from `wanted` that the object exports in .dynsym, with their file offsets.
/// Offsets are ELF object-file byte offsets — the same domain as manifest offsets
/// and `UProbeAttachLocation::AbsoluteOffset` (docs/notes/aya-offset-semantics.md).
pub fn exports_matching(
    file: &std::fs::File,
    wanted: &[&str],
) -> Result<Vec<(String, u64)>, String> {
    ElfSnapshot::read(file)?.exports_matching(wanted)
}

/// File offset of one defined symbol, or `Ok(None)` when it is not defined.
pub fn symbol_file_offset(file: &std::fs::File, name: &str) -> Result<Option<u64>, String> {
    Ok(ElfSnapshot::read(file)?
        .defined_symbol(name)?
        .map(|fact| fact.file_offset))
}

/// File offset of the ELF entry point, or `Ok(None)` when no loaded segment
/// covers it. Lets a statically linked observer attach its self-probe to its
/// own entry point when there is no libc mapping to borrow (the entry point
/// itself never runs during the check — the probe is dropped immediately —
/// so this only proves attach works, exactly like the libc-anchored probe).
pub fn entry_file_offset(file: &std::fs::File) -> Result<Option<u64>, String> {
    let snapshot = ElfSnapshot::read(file)?;
    let object = parse(&snapshot.data)?;
    Ok(file_offset(&object, object.entry()))
}
