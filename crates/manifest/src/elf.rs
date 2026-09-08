//! ELF facts the observer needs about an object's *bytes*: which registry symbols it
//! exports and where they live as file offsets. Offsets are ELF object-file byte
//! offsets (docs/notes/aya-offset-semantics.md) — the same domain manifest records use,
//! so a scanned offset and a manifest offset are directly comparable.

use std::ops::Range;

use crate::identity::{read_object_bytes, read_object_bytes_with};
use object::read::elf::ProgramHeader as _;
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
        let mut found = Vec::new();
        for symbol in object.dynamic_symbols() {
            let Ok(name) = symbol.name() else { continue };
            if !wanted.contains(&name) || !symbol.is_definition() {
                continue;
            }
            if let Some(offset) = file_offset(&object, symbol.address()) {
                found.push((name.to_string(), offset));
            }
        }
        Ok(found)
    }
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
