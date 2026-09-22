//! SPDX-License-Identifier: GPL-3.0-or-later
//! ELF facts the observer needs about an object's *bytes*: which registry symbols it
//! exports and where they live as file offsets. Offsets are ELF object-file byte
//! offsets (docs/notes/aya-offset-semantics.md) — the same domain manifest records use,
//! so a scanned offset and a manifest offset are directly comparable.

use std::ops::Range;

use crate::identity::{read_object_bytes, read_object_bytes_with};
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

/// One bounded read of an already-opened ELF, retained for every later query.
#[derive(Debug)]
pub struct ElfSnapshot {
    data: Vec<u8>,
    abi: ElfAbi,
    interpreter: Option<Range<usize>>,
    executable_ranges: Vec<(u64, u64)>,
}

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
        let mut executable_ranges = Vec::new();
        let data_len = data.len() as u64;
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
        let object = parse(&self.data)?;
        Ok(exports_matching_in_object(&object, wanted))
    }
}

/// The shared exports walk: names from `wanted` that the image exports in
/// `.dynsym`, in dynsym order with their file offsets. Per-symbol faults skip
/// the symbol; the walk itself cannot fail.
fn exports_matching_in_object(object: &object::File<'_>, wanted: &[&str]) -> Vec<(String, u64)> {
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
    let (object, abi) = classified_object(mmap)?;
    let exports = exports_matching_in_object(&object, wanted);
    Ok((abi, exports, export_table_bytes(&object, mmap.len() as u64)))
}

/// `(abi, exports)` for `wanted` without reading the whole file: the image is
/// demand-paged through a shared mapping and queried with the same
/// `object`-based core as [`ElfSnapshot`], so facts and refusals agree
/// exactly with the snapshot oracle. Returns the structural table bytes the
/// query logically consumed, for budget charging. Every mapping failure takes
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
