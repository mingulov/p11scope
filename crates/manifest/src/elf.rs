//! ELF facts the observer needs about an object's *bytes*: which registry symbols it
//! exports and where they live as file offsets. Offsets are ELF object-file byte
//! offsets (docs/notes/aya-offset-semantics.md) — the same domain manifest records use,
//! so a scanned offset and a manifest offset are directly comparable.

use crate::identity::read_object_bytes;
use object::{Architecture, BinaryFormat, Object as _, ObjectSegment as _, ObjectSymbol as _};

fn parse(data: &[u8]) -> Result<object::File<'_>, String> {
    let object = object::File::parse(data)
        .map_err(|error| format!("not parseable as an ELF object: {error}"))?;
    if object.format() != BinaryFormat::Elf {
        return Err(format!("not an ELF object ({:?})", object.format()));
    }
    if !object.is_64() || object.architecture() != Architecture::X86_64 {
        return Err(format!(
            "not a 64-bit x86-64 ELF object (architecture {:?}); 32-bit and foreign \
             architectures are recorded as skipped, never misread",
            object.architecture()
        ));
    }
    Ok(object)
}

/// A virtual address inside a PT_LOAD segment → its byte offset in the file.
///
/// Only addresses backed by actual file bytes qualify: a segment's file size can be
/// smaller than its memory size (the `.bss` tail, zero-filled at load time and not
/// present in the file), so an address past `file_size` bytes into the segment has no
/// file offset and must not produce one.
fn file_offset(object: &object::File<'_>, address: u64) -> Option<u64> {
    object.segments().find_map(|segment| {
        let start = segment.address();
        let end = start.checked_add(segment.size())?;
        if !(start..end).contains(&address) {
            return None;
        }
        let (file_start, file_size) = segment.file_range();
        let delta = address - start;
        (delta < file_size).then(|| file_start + delta)
    })
}

/// Names from `wanted` that the object exports in .dynsym, with their file offsets.
/// Offsets are ELF object-file byte offsets — the same domain as manifest offsets
/// and `UProbeAttachLocation::AbsoluteOffset` (docs/notes/aya-offset-semantics.md).
pub fn exports_matching(
    file: &std::fs::File,
    wanted: &[&str],
) -> Result<Vec<(String, u64)>, String> {
    let data = read_object_bytes(file)?;
    let object = parse(&data)?;
    let mut found = Vec::new();
    for symbol in object.dynamic_symbols() {
        let Ok(name) = symbol.name() else { continue };
        if !wanted.contains(&name) || symbol.address() == 0 {
            continue;
        }
        if let Some(offset) = file_offset(&object, symbol.address()) {
            found.push((name.to_string(), offset));
        }
    }
    Ok(found)
}

/// File offset of one exported symbol, or `Ok(None)` when it is not exported.
pub fn symbol_file_offset(file: &std::fs::File, name: &str) -> Result<Option<u64>, String> {
    let data = read_object_bytes(file)?;
    let object = parse(&data)?;
    Ok(object
        .dynamic_symbols()
        .chain(object.symbols())
        .filter(|symbol| symbol.name() == Ok(name) && symbol.address() != 0)
        .find_map(|symbol| file_offset(&object, symbol.address())))
}
