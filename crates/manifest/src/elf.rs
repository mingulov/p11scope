//! SPDX-License-Identifier: GPL-3.0-or-later
//! SPDX-FileCopyrightText: 2026 Denis Mingulov <denis@mingulov.com>
//! ELF facts the observer needs about an object's *bytes*: which registry symbols it
//! exports and where they live as file offsets. Offsets are ELF object-file byte
//! offsets (docs/notes/aya-offset-semantics.md) — the same domain manifest records use,
//! so a scanned offset and a manifest offset are directly comparable.

use std::ops::Range;

use crate::identity::{read_object_bytes, read_object_bytes_with};
use object::read::elf::FileHeader as _;
use object::read::elf::ProgramHeader as _;
use object::read::elf::SectionHeader as _;
use object::{
    Architecture, BinaryFormat, Object as _, ObjectSection as _, ObjectSegment as _,
    ObjectSymbol as _, SymbolKind, elf,
};

const MAX_INTERPRETER_BYTES: usize = 4096;

/// Bound on an ELF program-header table any parse may walk: 64 KiB
/// (1,170 entries at 56 bytes). Tables are demand-paged, but the
/// export parse builds one map entry per load segment and one range
/// per executable segment, so an unbounded table is unbounded memory
/// (a 224 MiB / 4M-segment file reached about 1 GiB RSS). Real tables
/// are tiny (896 bytes max over 9,467 system ELFs), so the cap refuses
/// only crafted files — never a size gate on the file itself.
pub const MAX_PROGRAM_TABLE_BYTES: u64 = 64 * 1024;

/// Bound on an ELF section-header table any parse may walk: 1 MiB
/// (16,384 entries at 64 bytes). Real tables are kilobytes (4 KiB max
/// over 9,467 system ELFs, in libc), so the cap refuses only crafted
/// files — never a size gate on the file itself.
pub const MAX_SECTION_TABLE_BYTES: u64 = 1024 * 1024;

// Dynamic spans carry no fixed cap here: they are only sized, and the
// scan refuses them against the whole window it charges them to (see
// `ElfTableBounds::span_refusal`), cached per object on the demand-paged
// path. Paths that already read and charged every byte (snapshots, pins)
// and run's launch classification never apply span refusals, so real
// spans (pandoc: 11.5 MB `.dynsym`, 43.7 MB `.dynstr`) parse on every
// path. There is deliberately no `MAX_DYN_SPAN_BYTES`: a fixed per-span
// cap refuses real files.

/// Header-table and dynamic-span sizes one ELF parse will walk, read
/// from the ELF header (plus section 0 for extended counts, plus the
/// already-bounded section table for the spans) before any walked
/// page is touched.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ElfTableBounds {
    /// ELF header bytes (64 for 64-bit, 52 for 32-bit).
    pub header_bytes: u64,
    /// Program-header table bytes (`e_phnum * e_phentsize`).
    pub program_table_bytes: u64,
    /// Section-header table bytes (`e_shnum * e_shentsize`).
    pub section_table_bytes: u64,
    /// Dynamic-symbol table bytes (sum of `SHT_DYNSYM` `sh_size`).
    pub dynsym_bytes: u64,
    /// Dynamic-string table bytes (linked `sh_size` per `SHT_DYNSYM`).
    pub dynstr_bytes: u64,
    /// Dynamic table bytes (sum of `SHT_DYNAMIC` `sh_size`).
    pub dynamic_bytes: u64,
    /// Program-header entries the parse will walk.
    pub program_entries: u64,
    /// Section-header entries the parse will walk.
    pub section_entries: u64,
}

impl ElfTableBounds {
    /// Bytes the admitted parse will walk: the header, both tables,
    /// and the dynamic spans.
    pub fn table_bytes(&self) -> u64 {
        self.header_bytes
            .saturating_add(self.program_table_bytes)
            .saturating_add(self.section_table_bytes)
            .saturating_add(self.dynsym_bytes)
            .saturating_add(self.dynstr_bytes)
            .saturating_add(self.dynamic_bytes)
    }

    /// Table entries the admitted parse will walk.
    pub fn table_entries(&self) -> u64 {
        self.program_entries.saturating_add(self.section_entries)
    }

    /// The cached per-object refusal when these bounds exceed the whole
    /// window the walk would be charged to (`window_bytes`: the scan
    /// policy's production window, never the remaining bytes — a refusal
    /// cached under a drained window would skip a real file on later
    /// passes). Checks each dynamic span first, then the walked total,
    /// so the reason names the oversized span when one exists. Returns
    /// `None` when everything fits: real spans (pandoc's 11.5 MB
    /// `.dynsym` / 43.7 MB `.dynstr`, 55 MB total) fit a 64 MiB window.
    /// Only the demand-paged scan path applies this; snapshots, pins
    /// and run's launch classification admit whatever fits here.
    pub fn span_refusal(&self, window_bytes: u64) -> Option<String> {
        if self.dynsym_bytes > window_bytes {
            return Some(dynsym_span_reason(self.dynsym_bytes, window_bytes));
        }
        if self.dynstr_bytes > window_bytes {
            return Some(dynstr_span_reason(self.dynstr_bytes, window_bytes));
        }
        if self.dynamic_bytes > window_bytes {
            return Some(dynamic_span_reason(self.dynamic_bytes, window_bytes));
        }
        let total = self.table_bytes();
        if total > window_bytes {
            return Some(tables_span_reason(total, window_bytes));
        }
        None
    }

    /// Bounds for a header this gate cannot read: admit with nothing
    /// owed and let the legacy parser rule with its historical errors.
    fn unreadable() -> Self {
        Self {
            header_bytes: 0,
            program_table_bytes: 0,
            section_table_bytes: 0,
            dynsym_bytes: 0,
            dynstr_bytes: 0,
            dynamic_bytes: 0,
            program_entries: 0,
            section_entries: 0,
        }
    }
}

fn program_table_reason(table_bytes: u64) -> String {
    format!("ELF program-header table is {table_bytes} bytes; limit is {MAX_PROGRAM_TABLE_BYTES}")
}

fn section_table_reason(table_bytes: u64) -> String {
    format!("ELF section-header table is {table_bytes} bytes; limit is {MAX_SECTION_TABLE_BYTES}")
}

fn dynsym_span_reason(span_bytes: u64, window_bytes: u64) -> String {
    format!("ELF dynamic-symbol table is {span_bytes} bytes; limit is {window_bytes}")
}

fn dynstr_span_reason(span_bytes: u64, window_bytes: u64) -> String {
    format!("ELF dynamic-string table is {span_bytes} bytes; limit is {window_bytes}")
}

fn dynamic_span_reason(span_bytes: u64, window_bytes: u64) -> String {
    format!("ELF dynamic table is {span_bytes} bytes; limit is {window_bytes}")
}

fn tables_span_reason(table_bytes: u64, window_bytes: u64) -> String {
    format!("ELF tables are {table_bytes} bytes; limit is {window_bytes}")
}

/// Whether a refusal reason names an over-cap table: the fixed header
/// caps plus the whole-window dynamic-span (and walked-total) refusals.
/// The scan caches exactly these per file identity, so the prefix match
/// cannot drift from the reasons above.
pub fn is_table_cap_reason(reason: &str) -> bool {
    reason.starts_with("ELF program-header table is ")
        || reason.starts_with("ELF section-header table is ")
        || reason.starts_with("ELF dynamic-symbol table is ")
        || reason.starts_with("ELF dynamic-string table is ")
        || reason.starts_with("ELF dynamic table is ")
        || reason.starts_with("ELF tables are ")
}

/// Whether a refusal reason names a file the gate refuses before any
/// parse: non-ELF magic (including unknown class and short files),
/// non-ELF kinds, and big-endian ELF. The texts are the legacy
/// parser's, so the prefix matches cannot drift from them.
pub fn is_format_refusal_reason(reason: &str) -> bool {
    reason.starts_with("not an ELF object")
        || reason == "not a little-endian ELF object"
        || reason.starts_with("not parseable as an ELF object: ")
}

/// Whether a refusal is cacheable per file identity: over-cap tables
/// (header and dynamic spans) plus the pre-parse format refusals. The
/// scan caches exactly these under the pin bracket, so the match cannot
/// drift from the reasons above.
pub fn is_gate_refusal_reason(reason: &str) -> bool {
    is_table_cap_reason(reason) || is_format_refusal_reason(reason)
}

/// One ELF header's field layout: the header size, the section-table
/// offset, the program/section entry-size and count offsets, the
/// section-header size, and section 0's count-carrier offsets. Shared
/// by the bounds gate and the section-0 locator so the two cannot
/// drift.
#[derive(Debug, Clone, Copy)]
struct ElfHeaderLayout {
    ehdr: usize,
    o_shoff: usize,
    o_phentsize: usize,
    o_phnum: usize,
    o_shentsize: usize,
    o_shnum: usize,
    shdr: usize,
    o_info: usize,
    o_size: usize,
    w_size: usize,
}

const ELF_LAYOUT64: ElfHeaderLayout = ElfHeaderLayout {
    ehdr: 64,
    o_shoff: 40,
    o_phentsize: 54,
    o_phnum: 56,
    o_shentsize: 58,
    o_shnum: 60,
    shdr: 64,
    o_info: 44,
    o_size: 32,
    w_size: 8,
};

const ELF_LAYOUT32: ElfHeaderLayout = ElfHeaderLayout {
    ehdr: 52,
    o_shoff: 32,
    o_phentsize: 42,
    o_phnum: 44,
    o_shentsize: 46,
    o_shnum: 48,
    shdr: 40,
    o_info: 28,
    o_size: 20,
    w_size: 4,
};

fn elf_header_layout(class: u8) -> Option<ElfHeaderLayout> {
    match class {
        1 => Some(ELF_LAYOUT32),
        2 => Some(ELF_LAYOUT64),
        _ => None,
    }
}

/// Table bounds from one ELF header plus section 0 when the extended
/// counts are used. Mirrors `object` 0.39's extended-count rules
/// (`FileHeader::phnum`/`shnum`): `e_phnum == PN_XNUM` reads the real
/// count from section 0's `sh_info`; `e_shnum == 0` with a section
/// table present reads it from section 0's `sh_size`. Non-ELF magic
/// (including unknown class and short files), non-ELF kinds, and
/// big-endian ELF refuse here with the legacy texts, before any
/// `object::File::parse` walks a table. Anything else this gate
/// cannot read (short ELF header, wrong entry sizes, missing
/// section 0) admits with zero bounds: the legacy parser fails fast
/// on those without a per-entry walk. Over-cap header tables refuse
/// with the named gap reason, identical on every entry point so
/// identical files fold; dynamic spans are only sized by the callers
/// and refused scan-side against the whole window.
pub fn table_bounds_from_header(
    header: &[u8],
    section0: Option<&[u8]>,
) -> Result<ElfTableBounds, String> {
    fn word<const N: usize>(bytes: &[u8], at: usize) -> Option<u64> {
        let slice = bytes.get(at..at + N)?;
        let mut padded = [0u8; 8];
        padded[..N].copy_from_slice(slice);
        Some(u64::from_le_bytes(padded))
    }
    // C1: refuse before any parse. `FileKind::parse` reads only the
    // 16-byte magic, so the legacy texts stay byte-exact — except PE,
    // whose signature sits past the 64 header bytes the gate passes it
    // (`e_lfanew` points beyond them), so the kind parse fails with
    // "Unknown MS-DOS file" where the full parser says Pe. DOS magic
    // keeps the legacy Pe text byte-exact for Wine/Proton DLLs.
    let kind = match object::FileKind::parse(header) {
        Ok(kind) => kind,
        Err(error) => {
            if header.starts_with(b"MZ") {
                return Err(format!(
                    "not an ELF object ({:?})",
                    object::BinaryFormat::Pe
                ));
            }
            return Err(format!("not parseable as an ELF object: {error}"));
        }
    };
    match kind {
        object::FileKind::Elf32 | object::FileKind::Elf64 => {}
        object::FileKind::MachO32 | object::FileKind::MachO64 => {
            return Err(format!(
                "not an ELF object ({:?})",
                object::BinaryFormat::MachO
            ));
        }
        object::FileKind::Pe32 | object::FileKind::Pe64 => {
            return Err(format!(
                "not an ELF object ({:?})",
                object::BinaryFormat::Pe
            ));
        }
        object::FileKind::Coff | object::FileKind::CoffBig => {
            return Err(format!(
                "not an ELF object ({:?})",
                object::BinaryFormat::Coff
            ));
        }
        object::FileKind::Xcoff32 | object::FileKind::Xcoff64 => {
            return Err(format!(
                "not an ELF object ({:?})",
                object::BinaryFormat::Xcoff
            ));
        }
        _ => {
            return Err("not parseable as an ELF object: Unsupported file format".into());
        }
    }
    if header.get(5).copied() != Some(1) {
        return Err("not a little-endian ELF object".into());
    }
    let class = header.get(4).copied().unwrap_or(0);
    let Some(layout) = elf_header_layout(class) else {
        return Err("not parseable as an ELF object: Unknown file magic".into());
    };
    let ElfHeaderLayout {
        ehdr,
        o_shoff,
        o_phentsize,
        o_phnum,
        o_shentsize,
        o_shnum,
        shdr,
        o_info,
        o_size,
        w_size,
    } = layout;
    if header.len() < ehdr {
        return Ok(ElfTableBounds::unreadable());
    }
    let Some(phentsize) = word::<2>(header, o_phentsize) else {
        return Ok(ElfTableBounds::unreadable());
    };
    let Some(e_phnum) = word::<2>(header, o_phnum) else {
        return Ok(ElfTableBounds::unreadable());
    };
    let Some(shentsize) = word::<2>(header, o_shentsize) else {
        return Ok(ElfTableBounds::unreadable());
    };
    let Some(e_shnum) = word::<2>(header, o_shnum) else {
        return Ok(ElfTableBounds::unreadable());
    };
    // Extended counts need section 0 with the exact entry size the
    // parser requires; anything else admits and the parser rules it.
    let section0 = (e_phnum == 0xffff || e_shnum == 0).then(|| {
        let bytes = section0?;
        if shentsize as usize != shdr || bytes.len() < shdr {
            return None;
        }
        Some(bytes)
    });
    let phnum = if e_phnum < 0xffff {
        e_phnum
    } else {
        let Some(section0) = section0.flatten() else {
            return Ok(ElfTableBounds::unreadable());
        };
        word::<4>(section0, o_info).unwrap_or(0)
    };
    let shnum = if e_shnum > 0 {
        e_shnum
    } else {
        let shoff = if class == 2 {
            word::<8>(header, o_shoff).unwrap_or(0)
        } else {
            word::<4>(header, o_shoff).unwrap_or(0)
        };
        if shoff == 0 {
            0
        } else {
            let Some(section0) = section0.flatten() else {
                return Ok(ElfTableBounds::unreadable());
            };
            if w_size == 8 {
                word::<8>(section0, o_size).unwrap_or(0)
            } else {
                word::<4>(section0, o_size).unwrap_or(0)
            }
        }
    };
    let program_table_bytes = phnum.saturating_mul(phentsize);
    if program_table_bytes > MAX_PROGRAM_TABLE_BYTES {
        return Err(program_table_reason(program_table_bytes));
    }
    let section_table_bytes = shnum.saturating_mul(shentsize);
    if section_table_bytes > MAX_SECTION_TABLE_BYTES {
        return Err(section_table_reason(section_table_bytes));
    }
    Ok(ElfTableBounds {
        header_bytes: ehdr as u64,
        program_table_bytes,
        section_table_bytes,
        // Dynamic spans are sized from the section table by the callers
        // (`read_table_bounds_with`, `gate_table_bounds`); only the
        // demand-paged scan path refuses them, against the whole window
        // (`span_refusal`), before any walk.
        dynsym_bytes: 0,
        dynstr_bytes: 0,
        dynamic_bytes: 0,
        program_entries: phnum,
        section_entries: shnum,
    })
}

/// Section 0's file offset and size when the header's counts may need
/// it (`e_phnum == PN_XNUM`, or `e_shnum == 0` with a section table
/// present): `None` when unneeded or undeterminable, in which case
/// the gate admits and the legacy parser rules.
fn section0_location(header: &[u8]) -> Option<(u64, usize)> {
    let class = header.get(4).copied()?;
    let layout = elf_header_layout(class)?;
    let ElfHeaderLayout {
        ehdr,
        o_shoff,
        o_phnum,
        o_shentsize,
        o_shnum,
        shdr,
        ..
    } = layout;
    if header.len() < ehdr {
        return None;
    }
    let at = |offset: usize| -> Option<u16> {
        u16::from_le_bytes(header.get(offset..offset + 2)?.try_into().ok()?).into()
    };
    let shoff = {
        let width = if class == 2 { 8 } else { 4 };
        let slice = header.get(o_shoff..o_shoff + width)?;
        let mut padded = [0u8; 8];
        padded[..width].copy_from_slice(slice);
        u64::from_le_bytes(padded)
    };
    let extended = at(o_phnum)? == 0xffff || (at(o_shnum)? == 0 && shoff != 0);
    if !extended {
        return None;
    }
    // Extended counts need section 0 with the exact entry size the
    // parser requires; anything else admits and the parser rules it.
    if at(o_shentsize)? as usize != shdr || shoff == 0 {
        return None;
    }
    Some((shoff, shdr))
}

/// Dynamic spans from one already-bounded section table (little-endian
/// only; big-endian never reaches here): the summed `SHT_DYNSYM` and
/// `SHT_DYNAMIC` sizes plus each `SHT_DYNSYM`'s linked string-table
/// size. Only sizes, never refuses: `file_len` is the file (or mapped)
/// length, and a span claiming more than the file is lying (I-1) — the
/// lazy walk skips it and it charges nothing, so it sizes as zero. A
/// truncated table sizes as zeros and the parser fails fast. The scan
/// refuses oversized spans against the whole window (`span_refusal`).
fn dyn_span_sizes(
    section_table: &[u8],
    layout: ElfHeaderLayout,
    shnum: u64,
    file_len: u64,
) -> (u64, u64, u64) {
    let ElfHeaderLayout {
        shdr,
        o_size,
        o_info,
        w_size,
        ..
    } = layout;
    let o_link = o_info.saturating_sub(4);
    let shnum_usize = usize::try_from(shnum).unwrap_or(usize::MAX);
    if section_table.len() < shnum_usize.saturating_mul(shdr) {
        return (0, 0, 0);
    }
    let mut dynsym_bytes = 0u64;
    let mut dynamic_bytes = 0u64;
    let mut dynsym_links = Vec::new();
    for index in 0..shnum_usize {
        let base = index.saturating_mul(shdr);
        let sh_type = u32::from_le_bytes(
            section_table[base + 4..base + 8]
                .try_into()
                .unwrap_or([0u8; 4]),
        );
        let sh_size_raw = {
            let slice = &section_table[base + o_size..base + o_size + w_size];
            let mut padded = [0u8; 8];
            padded[..w_size].copy_from_slice(slice);
            u64::from_le_bytes(padded)
        };
        // Lying spans (bigger than the file) size as zero: the lazy
        // walk skips them (I-1), so they charge nothing.
        let sh_size = if sh_size_raw > file_len {
            0
        } else {
            sh_size_raw
        };
        if sh_type == 11 {
            dynsym_bytes = dynsym_bytes.saturating_add(sh_size);
            let link = u32::from_le_bytes(
                section_table[base + o_link..base + o_link + 4]
                    .try_into()
                    .unwrap_or([0u8; 4]),
            );
            dynsym_links.push(link);
        } else if sh_type == 6 {
            dynamic_bytes = dynamic_bytes.saturating_add(sh_size);
        }
    }
    let mut dynstr_bytes = 0u64;
    for link in dynsym_links {
        if link == 0 {
            continue;
        }
        let Ok(index) = usize::try_from(link) else {
            continue;
        };
        if index >= shnum_usize {
            continue;
        }
        let base = index.saturating_mul(shdr);
        let sh_size_raw = {
            let slice = &section_table[base + o_size..base + o_size + w_size];
            let mut padded = [0u8; 8];
            padded[..w_size].copy_from_slice(slice);
            u64::from_le_bytes(padded)
        };
        let sh_size = if sh_size_raw > file_len {
            0
        } else {
            sh_size_raw
        };
        dynstr_bytes = dynstr_bytes.saturating_add(sh_size);
    }
    (dynsym_bytes, dynstr_bytes, dynamic_bytes)
}

/// Section-table file range from one admitted header: `(offset, bytes)`
/// when a table is present and bounded, `None` when absent or
/// unreadable (the parser fails fast on those).
fn section_table_range(header: &[u8], bounds: &ElfTableBounds) -> Option<(u64, usize)> {
    if bounds.section_table_bytes == 0 || bounds.section_entries == 0 {
        return None;
    }
    let class = header.get(4).copied()?;
    let layout = elf_header_layout(class)?;
    if header.len() < layout.ehdr {
        return None;
    }
    let width = layout.w_size;
    let slice = header.get(layout.o_shoff..layout.o_shoff + width)?;
    let mut padded = [0u8; 8];
    padded[..width].copy_from_slice(slice);
    let offset = u64::from_le_bytes(padded);
    if offset == 0 {
        return None;
    }
    let bytes = usize::try_from(bounds.section_table_bytes).ok()?;
    Some((offset, bytes))
}

/// Table bounds for one opened file, read before any mapping: the ELF
/// header, plus section 0 for extended counts, plus the already-bounded
/// section table for the dynamic spans. At most 128 bytes move for the
/// header probe, plus at most 1 MiB for the section table; over-cap
/// header tables refuse with their named gap reasons, and non-ELF,
/// unknown-class, and big-endian files refuse with the legacy texts
/// before any parse. Spans are only sized here; the scan refuses them
/// against the whole window. A header read failure refuses as a read
/// error; a
/// short section table admits and the parser fails fast. Returns the
/// outcome plus the probe bytes read, so refusals charge exactly what
/// moved.
pub fn read_table_bounds(file: &std::fs::File) -> (Result<ElfTableBounds, String>, u64) {
    use std::os::unix::fs::FileExt as _;
    let file_len = file.metadata().map(|meta| meta.len()).unwrap_or(u64::MAX);
    read_table_bounds_with(|buf, offset| file.read_at(buf, offset), file_len)
}

/// [`read_table_bounds`] with an injectable positioned reader (tests
/// count the probe bytes; production reads the file). `file_len` is the
/// file length for lying-span clamping (`u64::MAX` fails closed when
/// unknown).
pub fn read_table_bounds_with(
    mut reader: impl FnMut(&mut [u8], u64) -> std::io::Result<usize>,
    file_len: u64,
) -> (Result<ElfTableBounds, String>, u64) {
    let mut header = [0u8; 64];
    let len = match reader(&mut header, 0) {
        Ok(len) => len,
        Err(error) => return (Err(format!("read failed: {error}")), 0),
    };
    // Own the header bytes: the section-table read below needs them
    // while the reader borrows mutably.
    let header_owned = header[..len].to_vec();
    let header: &[u8] = &header_owned;
    let mut moved = len as u64;
    let mut section0 = [0u8; 64];
    let section0 = section0_location(header).and_then(|(offset, size)| {
        let buf = &mut section0[..size];
        let read = reader(buf, offset).ok()?;
        moved += read as u64;
        (read == size).then_some(buf as &[u8])
    });
    let mut bounds = match table_bounds_from_header(header, section0) {
        Ok(bounds) => bounds,
        Err(reason) => return (Err(reason), moved),
    };
    let Some((offset, bytes)) = section_table_range(header, &bounds) else {
        return (Ok(bounds), moved);
    };
    let class = header.get(4).copied().unwrap_or(0);
    let Some(layout) = elf_header_layout(class) else {
        return (Ok(bounds), moved);
    };
    let mut table = vec![0u8; bytes];
    let mut at = 0usize;
    while at < bytes {
        match reader(&mut table[at..], offset + at as u64) {
            Ok(0) | Err(_) => return (Ok(bounds), moved),
            Ok(read) => {
                moved += read as u64;
                at += read;
            }
        }
    }
    if at != bytes {
        return (Ok(bounds), moved);
    }
    let (dynsym, dynstr, dynamic) =
        dyn_span_sizes(&table, layout, bounds.section_entries, file_len);
    bounds.dynsym_bytes = dynsym;
    bounds.dynstr_bytes = dynstr;
    bounds.dynamic_bytes = dynamic;
    (Ok(bounds), moved)
}

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
    /// A 3.x interface getter name (`C_GetInterface`/`C_GetInterfaceList`)
    /// appears among the image's dynamic symbols in any symbol type —
    /// including non-definitions (`STT_GNU_IFUNC`, absolute) that
    /// `is_definition` excludes from `exports`.
    pub getter_present: bool,
    /// Sticky: the exports walk skipped a symbol it could not read
    /// (unreadable name) or translate (a wanted definition outside every
    /// segment), so `exports` may be incomplete.
    pub witness_fault: bool,
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
    table_bounds: ElfTableBounds,
}

/// Table bounds for bytes already in memory (mappings, snapshots):
/// the ELF header prefix plus section 0 sliced from the same bytes,
/// plus the already-bounded section table for the dynamic spans.
/// Refuses over-cap header tables with their named gap reasons and
/// non-ELF, unknown-class, and big-endian files with the legacy texts
/// before any parse; spans are only sized, never refused here, so
/// snapshots, pins and run's launch classification admit real spans.
/// Anything else unreadable admits for the legacy parser's fast failure.
fn gate_table_bounds(data: &[u8]) -> Result<ElfTableBounds, String> {
    let header = data.get(..64).unwrap_or(data);
    let section0 = section0_location(header).and_then(|(offset, size)| {
        usize::try_from(offset)
            .ok()
            .and_then(|offset| data.get(offset..offset.checked_add(size)?))
    });
    let mut bounds = table_bounds_from_header(header, section0)?;
    let Some((offset, bytes)) = section_table_range(header, &bounds) else {
        return Ok(bounds);
    };
    let class = header.get(4).copied().unwrap_or(0);
    let Some(layout) = elf_header_layout(class) else {
        return Ok(bounds);
    };
    let Ok(offset) = usize::try_from(offset) else {
        return Ok(bounds);
    };
    let Some(end) = offset.checked_add(bytes) else {
        return Ok(bounds);
    };
    let Some(table) = data.get(offset..end) else {
        return Ok(bounds);
    };
    let file_len = data.len() as u64;
    let (dynsym, dynstr, dynamic) = dyn_span_sizes(table, layout, bounds.section_entries, file_len);
    bounds.dynsym_bytes = dynsym;
    bounds.dynstr_bytes = dynstr;
    bounds.dynamic_bytes = dynamic;
    Ok(bounds)
}

/// Structural classification only (ELF magic, endianness, class/machine);
/// segment ranges are unchecked. Never translate addresses or offsets from
/// the returned object — use `classified_validated_object` for any export
/// walk or range query. The table gate runs first, so every entry point
/// funnelling here refuses over-cap header tables and non-ELF,
/// unknown-class, and big-endian files before the parser walks them;
/// dynamic spans are only sized here, never refused. The checks below
/// are defense in depth for what the gate admits.
pub fn classified_object(data: &[u8]) -> Result<(object::File<'_>, ElfAbi), String> {
    gate_table_bounds(data)?;
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
    translate_file_offset(object, address, false)
}

/// `file_offset` restricted to executable segments: a function-entry
/// proof must resolve through a `PF_X` segment, so an address in a
/// data segment (a decoy symbol, a corrupt unwind entry) translates
/// to no file offset and contributes no proof. Data lookups keep the
/// unrestricted `file_offset` above.
fn executable_file_offset(object: &object::File<'_>, address: u64) -> Option<u64> {
    translate_file_offset(object, address, true)
}

fn translate_file_offset(
    object: &object::File<'_>,
    address: u64,
    executable_only: bool,
) -> Option<u64> {
    object.segments().find_map(|segment| {
        if executable_only && !segment.permissions().executable() {
            return None;
        }
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
        // The bounds are kept for pre-parse charging; `classified_object`
        // below re-runs the same header-only gate before parsing.
        let table_bounds = gate_table_bounds(&data)?;
        let (object, abi) = classified_object(&data)?;
        let interpreter = interpreter(&object)?;
        let executable_ranges = validated_segment_ranges(&object, data.len() as u64)?;

        Ok(Self {
            data,
            abi,
            interpreter,
            executable_ranges,
            table_bounds,
        })
    }

    pub fn abi(&self) -> ElfAbi {
        self.abi
    }

    /// The header-table bounds this snapshot was admitted under, for
    /// pre-parse charging by callers that read the bytes first.
    pub fn table_bounds(&self) -> ElfTableBounds {
        self.table_bounds
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
        Ok(exports_matching_in_object(&object, wanted).exports)
    }

    pub fn raw_scan_facts(&self, wanted: &[&str]) -> Result<RawScanElfFacts, String> {
        raw_scan_facts_from_bytes(&self.data, wanted)
    }
}

// Sorted disjoint intervals keep section/segment clipping linear after one
// indexed collection; untrusted ELF tables never cause an S x P walk.
fn merge_raw_metadata_ranges(ranges: &mut Vec<(u64, u64)>, work: &mut u64) {
    let count = ranges.len() as u64;
    *work = work.saturating_add(count.saturating_mul(u64::from(count.max(1).ilog2()) + 2));
    ranges.sort_unstable();
    let mut kept = 0usize;
    for index in 0..ranges.len() {
        let (start, end) = ranges[index];
        if kept > 0 && start <= ranges[kept - 1].1 {
            ranges[kept - 1].1 = ranges[kept - 1].1.max(end);
        } else {
            ranges[kept] = (start, end);
            kept += 1;
        }
    }
    ranges.truncate(kept);
}

fn intersect_raw_metadata_ranges(
    left: &[(u64, u64)],
    right: &[(u64, u64)],
    out: &mut Vec<(u64, u64)>,
    work: &mut u64,
) {
    let (mut a, mut b) = (0, 0);
    while a < left.len() && b < right.len() {
        *work = work.saturating_add(1);
        let start = left[a].0.max(right[b].0);
        let end = left[a].1.min(right[b].1);
        if start < end {
            out.push((start, end));
        }
        if left[a].1 <= right[b].1 {
            a += 1;
        } else {
            b += 1;
        }
    }
}

fn subtract_raw_zero_fill_projections(
    ranges: Vec<(u64, u64)>,
    zero_fill: &[(u64, u64)],
    work: &mut u64,
) -> Vec<(u64, u64)> {
    let mut retained = Vec::new();
    let mut at = 0;
    for (mut start, end) in ranges {
        *work = work.saturating_add(1);
        while at < zero_fill.len() && zero_fill[at].1 <= start {
            *work = work.saturating_add(1);
            at += 1;
        }
        while at < zero_fill.len() && zero_fill[at].0 < end {
            *work = work.saturating_add(1);
            if start < zero_fill[at].0 {
                retained.push((start, zero_fill[at].0));
            }
            start = start.max(zero_fill[at].1);
            if start >= end {
                break;
            }
            at += 1;
        }
        if start < end {
            retained.push((start, end));
        }
    }
    retained
}

fn raw_scan_facts_from_bytes(data: &[u8], wanted: &[&str]) -> Result<RawScanElfFacts, String> {
    let (object, abi, _) = classified_validated_object(data)?;
    let mut ranges = Vec::new();
    let mut work_units = 0u64;
    macro_rules! collect {
        ($elf:expr) => {{
            let elf = $elf;
            let endian = elf.endian();
            let sections = elf.elf_section_table();
            let programs = elf.elf_program_headers();
            work_units = work_units.saturating_add((sections.len() + programs.len()) as u64);
            let mut by_bias = std::collections::BTreeMap::new();
            let mut loaded_file = Vec::new();
            let mut zero_fill = Vec::new();
            for segment in programs {
                if segment.p_type(endian) != elf::PT_LOAD {
                    continue;
                }
                let (offset, size) = segment.file_range(endian);
                let address: u64 = segment.p_vaddr(endian).into();
                let memory_size: u64 = segment.p_memsz(endian).into();
                // classified_validated_object already checked every LOAD's
                // file/virtual arithmetic and actual file extent.
                let end = offset + size;
                if offset < end {
                    let bias = i128::from(address) - i128::from(offset);
                    let (loads, _) = by_bias
                        .entry(bias)
                        .or_insert_with(|| (Vec::new(), Vec::new()));
                    loads.push((offset, end));
                    loaded_file.push((offset, end));
                }
                if memory_size > size {
                    // A file-named VMA can include the loader-zeroed tail.
                    // Its projected offsets cannot prove metadata ownership,
                    // even if another LOAD really contains metadata there.
                    // memsz removes authority only; it never extends filesz.
                    zero_fill.push((end, offset.saturating_add(memory_size)));
                }
            }
            let index_work = u64::from((by_bias.len() as u64).max(1).ilog2()) + 1;
            work_units = work_units
                .saturating_add((sections.len() as u64).saturating_mul(index_work))
                .saturating_add((programs.len() as u64).saturating_mul(index_work));
            // The existing parser handles ELF32/64 and extended indexes.
            // Only exact GOT names need strings, and each check examines
            // at most nine bytes rather than searching an unbounded name —
            // so the charge below counts examined bytes, never the whole
            // name table (a 2 GiB sparse `.shstrtab` costs bytes, and a
            // later real object still scans in the same pass).
            let names = elf
                .elf_header()
                .section_strings_index(endian, elf.data())
                .ok()
                .and_then(|index| sections.section(index).ok())
                .and_then(|section| section.data(endian, elf.data()).ok())
                .unwrap_or(&[]);
            let mut got_checks = 0u64;
            for section in sections.iter() {
                let flags: u64 = section.sh_flags(endian).into();
                if flags & u64::from(elf::SHF_ALLOC) == 0 {
                    continue;
                }
                let kind = section.sh_type(endian);
                if kind == elf::SHT_PROGBITS {
                    got_checks = got_checks.saturating_add(1);
                }
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
                let address: u64 = section.sh_addr(endian).into();
                // File ranges alone are insufficient: section and LOAD must
                // agree on their virtual/file translation at every retained
                // byte, and only actual p_filesz bytes can be structural.
                if let Some((start, len)) = section.file_range(endian)
                    && let Some(end) = start.checked_add(len)
                    && address.checked_add(len).is_some()
                    && start < end
                    && end <= data.len() as u64
                    && let Some((_, metadata)) =
                        by_bias.get_mut(&(i128::from(address) - i128::from(start)))
                {
                    metadata.push((start, end));
                }
            }
            for (loads, metadata) in by_bias.values_mut() {
                merge_raw_metadata_ranges(loads, &mut work_units);
                merge_raw_metadata_ranges(metadata, &mut work_units);
                intersect_raw_metadata_ranges(metadata, loads, &mut ranges, &mut work_units);
            }
            merge_raw_metadata_ranges(&mut loaded_file, &mut work_units);
            // Headers remain structural even without a section table, but
            // only their actually loaded bytes exclude a raw observation.
            let mut headers = vec![(0, std::mem::size_of_val(elf.elf_header()) as u64)];
            let phoff: u64 = elf.elf_header().e_phoff(endian).into();
            let phbytes = std::mem::size_of_val(programs) as u64;
            if let Some(end) = phoff.checked_add(phbytes)
                && phoff < end
                && end <= data.len() as u64
            {
                headers.push((phoff, end));
            }
            merge_raw_metadata_ranges(&mut headers, &mut work_units);
            intersect_raw_metadata_ranges(&headers, &loaded_file, &mut ranges, &mut work_units);
            merge_raw_metadata_ranges(&mut ranges, &mut work_units);
            merge_raw_metadata_ranges(&mut zero_fill, &mut work_units);
            ranges = subtract_raw_zero_fill_projections(ranges, &zero_fill, &mut work_units);
            got_checks.saturating_mul(9).min(names.len() as u64)
        }};
    }
    let examined_names_bytes = match &object {
        object::File::Elf32(elf) => collect!(elf),
        object::File::Elf64(elf) => collect!(elf),
        _ => unreachable!("classified ELF"),
    };
    let walk = exports_matching_in_object(&object, wanted);
    Ok(RawScanElfFacts {
        abi,
        exports: walk.exports,
        getter_present: walk.getter_present,
        witness_fault: walk.witness_fault,
        excluded_anchor_ranges: ranges,
        // export_table_bytes already includes the ELF/program headers.
        structural_bytes: export_table_bytes(&object, data.len() as u64)
            .saturating_add(examined_names_bytes)
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
/// `.dynsym`, in dynsym order with their file offsets, plus the two
/// witness-completeness bits the legacy-prefix proof relies on (see
/// [`RawScanElfFacts`]). Per-symbol faults skip the symbol; the walk
/// itself cannot fail.
#[derive(Debug, Default)]
pub(crate) struct ExportWalk {
    pub(crate) exports: Vec<(String, u64)>,
    pub(crate) getter_present: bool,
    pub(crate) witness_fault: bool,
}

pub(crate) fn exports_matching_in_object(object: &object::File<'_>, wanted: &[&str]) -> ExportWalk {
    let mut found = Vec::new();
    let mut getter_present = false;
    let mut witness_fault = false;
    for symbol in object.dynamic_symbols() {
        let Ok(name) = symbol.name() else {
            // An unreadable name: the walk cannot tell whether this
            // symbol was wanted, so the witness may be incomplete.
            witness_fault = true;
            continue;
        };
        // Getter presence is recorded whatever the symbol type —
        // including non-definitions (`STT_GNU_IFUNC`, absolute) the
        // `is_definition` filter below excludes from `found` — and
        // whatever the caller asked for, so a narrow `wanted` cannot
        // hide a 3.x route from the legacy-prefix proof.
        if name == "C_GetInterface" || name == "C_GetInterfaceList" {
            getter_present = true;
        }
        if !wanted.contains(&name) || !symbol.is_definition() {
            continue;
        }
        if let Some(offset) = file_offset(object, symbol.address()) {
            found.push((name.to_string(), offset));
        } else {
            // A wanted definition outside every segment: dropped from
            // the witness, so the witness may be incomplete.
            witness_fault = true;
        }
    }
    ExportWalk {
        exports: found,
        getter_present,
        witness_fault,
    }
}

/// File offsets of proven function entries: every `STT_FUNC` definition in
/// `.dynsym`/`.symtab` plus every `.eh_frame_hdr` FDE start, mapped through
/// the executable load segments only. A symbol or FDE start in a data
/// segment contributes nothing — a uprobe is never proven at a data
/// offset. Sorted, deduplicated. Best-effort over already-parsed
/// bytes: a corrupt unwind table contributes nothing (its symbols still
/// count), and an absent `.eh_frame_hdr` is simply no FDE proof — the
/// caller fails closed when the set is empty. No I/O.
pub(crate) fn function_starts_in_object(object: &object::File<'_>) -> Vec<u64> {
    let mut starts = Vec::new();
    for symbol in object.dynamic_symbols().chain(object.symbols()) {
        if !symbol.is_definition() || symbol.kind() != SymbolKind::Text {
            continue;
        }
        if let Some(offset) = executable_file_offset(object, symbol.address()) {
            starts.push(offset);
        }
    }
    if let Some(section) = object.section_by_name(".eh_frame_hdr")
        && let Ok(data) = section.data()
    {
        starts.extend(eh_frame_hdr_starts(object, section.address(), data));
    }
    starts.sort_unstable();
    starts.dedup();
    starts
}

/// FDE initial locations from `.eh_frame_hdr`'s binary-search table, as file
/// offsets. Parses only the header's table (never the full `.eh_frame`):
/// version, three pointer encodings, the frame pointer, the FDE count, then
/// that many `(initial_location, fde_address)` pairs. Every read is
/// bounds-checked; any corrupt/truncated/unsupported encoding yields the
/// locations parsed so far (possibly none) instead of an error, so callers
/// treat a missing proof as unproven rather than a parse failure.
fn eh_frame_hdr_starts(object: &object::File<'_>, section_address: u64, data: &[u8]) -> Vec<u64> {
    let mut starts = Vec::new();
    if data.len() < 4 || data[0] != 1 {
        return starts;
    }
    let eh_frame_ptr_enc = data[1];
    let fde_count_enc = data[2];
    let table_enc = data[3];
    if table_enc == 0xff {
        return starts;
    }
    // Indirect table entries point through runtime addresses the observer
    // must not dereference; a table that needs them contributes no proof.
    if table_enc & 0x80 != 0 {
        return starts;
    }
    let address_size = match object.architecture() {
        Architecture::X86_64 => 8,
        Architecture::I386 => 4,
        _ => return starts,
    };
    let mut pos = 4usize;
    // The frame pointer itself is not a function start; skip it.
    let Some(next) = eh_pe_skip(data, pos, eh_frame_ptr_enc, address_size) else {
        return starts;
    };
    pos = next;
    let Some((fde_count, next)) =
        eh_pe_read(data, pos, section_address, fde_count_enc, address_size)
    else {
        return starts;
    };
    pos = next;
    let Ok(fde_count) = usize::try_from(fde_count) else {
        return starts;
    };
    for _ in 0..fde_count {
        let Some((location, next)) =
            eh_pe_read(data, pos, section_address, table_enc, address_size)
        else {
            break;
        };
        pos = next;
        let Some(next) = eh_pe_skip(data, pos, table_enc, address_size) else {
            break;
        };
        pos = next;
        if let Some(offset) = executable_file_offset(object, location) {
            starts.push(offset);
        }
    }
    starts
}

/// Size of one `DW_EH_PE_*` value, or `None` when the encoding is omitted,
/// indirect, unknown, or runs past `data`.
fn eh_pe_skip(data: &[u8], pos: usize, encoding: u8, address_size: usize) -> Option<usize> {
    if encoding == 0xff || encoding & 0x80 != 0 {
        return None;
    }
    match encoding & 0x0f {
        0x00 => data
            .len()
            .checked_sub(pos)
            .and_then(|left| (left >= address_size).then(|| pos + address_size)),
        0x02 | 0x0a => (data.len() >= pos + 2).then(|| pos + 2),
        0x03 | 0x0b => (data.len() >= pos + 4).then(|| pos + 4),
        0x04 | 0x0c => (data.len() >= pos + 8).then(|| pos + 8),
        0x01 | 0x09 => {
            let mut end = pos;
            loop {
                let byte = *data.get(end)?;
                end += 1;
                if byte & 0x80 == 0 {
                    break;
                }
                // A LEB128 longer than 10 bytes cannot be a 64-bit value.
                if end - pos > 10 {
                    return None;
                }
            }
            Some(end)
        }
        _ => None,
    }
}

/// One `DW_EH_PE_*` value plus the offset past it. `pcrel` is relative to
/// the value's own address (`section_address + pos`); `datarel` in an
/// `.eh_frame_hdr` table is relative to the header's own address.
fn eh_pe_read(
    data: &[u8],
    pos: usize,
    section_address: u64,
    encoding: u8,
    address_size: usize,
) -> Option<(u64, usize)> {
    if encoding == 0xff || encoding & 0x80 != 0 {
        return None;
    }
    let raw: i64 = match encoding & 0x0f {
        0x00 => {
            if address_size == 8 {
                i64::from_le_bytes(data.get(pos..pos + 8)?.try_into().ok()?)
            } else {
                i64::from(u32::from_le_bytes(data.get(pos..pos + 4)?.try_into().ok()?))
            }
        }
        0x02 => i64::from(u16::from_le_bytes(data.get(pos..pos + 2)?.try_into().ok()?)),
        0x03 => i64::from(u32::from_le_bytes(data.get(pos..pos + 4)?.try_into().ok()?)),
        0x04 => u64::from_le_bytes(data.get(pos..pos + 8)?.try_into().ok()?) as i64,
        0x0a => i64::from(i16::from_le_bytes(data.get(pos..pos + 2)?.try_into().ok()?)),
        0x0b => i64::from(i32::from_le_bytes(data.get(pos..pos + 4)?.try_into().ok()?)),
        0x0c => i64::from_le_bytes(data.get(pos..pos + 8)?.try_into().ok()?),
        0x01 => {
            let mut value: u64 = 0;
            let mut shift = 0;
            let mut end = pos;
            loop {
                let byte = *data.get(end)?;
                end += 1;
                if shift < 64 {
                    value |= u64::from(byte & 0x7f) << shift;
                }
                if byte & 0x80 == 0 {
                    break;
                }
                shift += 7;
                if end - pos > 10 {
                    return None;
                }
            }
            value as i64
        }
        0x09 => {
            let mut value: i64 = 0;
            let mut shift = 0;
            let mut end = pos;
            let byte = loop {
                let byte = *data.get(end)?;
                end += 1;
                if shift < 64 {
                    value |= i64::from(byte & 0x7f) << shift;
                }
                shift += 7;
                if byte & 0x80 == 0 {
                    break byte;
                }
                if end - pos > 10 {
                    return None;
                }
            };
            if shift < 64 && byte & 0x40 != 0 {
                value |= !0 << shift;
            }
            value
        }
        _ => return None,
    };
    let next = eh_pe_skip(data, pos, encoding, address_size)?;
    let base: i64 = match encoding & 0x70 {
        0x00 => 0,
        0x10 => (section_address as i64).wrapping_add(pos as i64),
        0x30 => section_address as i64,
        _ => return None,
    };
    Some((base.wrapping_add(raw) as u64, next))
}

/// Structural bytes the export query logically consumed: the ELF header, the
/// program- and section-header tables, and the dynamic-symbol, dynamic-string
/// and dynamic tables as present. Computed from the parsed tables — an honest
/// lower bound any correct implementation must move — clamped to the mapped
/// length so a corrupt section header claiming a larger-than-file table
/// cannot inflate the charge beyond the logical mapped range. Lying spans
/// (out-of-bounds data) charge nothing: the lazy walk skips them (I-1).
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
                    // Lying dynstr (data past EOF) charges nothing: the walk
                    // skips its names (I-1), so the charge must not trust the
                    // raw `sh_size`.
                    if header.data(endian, elf.data()).is_ok() {
                        let size: u64 = header.sh_size(endian).into();
                        bytes = bytes.saturating_add(size);
                    }
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
    let exports = exports_matching_in_object(&object, wanted).exports;
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

/// DT_NEEDED library names of an ELF object, in dynamic-section order.
/// Parsed from a read-only mapping with the same classification and
/// segment-range validation as the export queries, so corrupt headers
/// refuse before any string is read. An object without a dynamic section
/// (statically linked) needs nothing and yields an empty list. Names are
/// returned verbatim; the caller decides which ones to resolve and how.
pub fn needed_libraries(file: &std::fs::File) -> Result<Vec<String>, String> {
    // SAFETY: a read-only shared mapping of the file; the bytes are only read
    // through the parser's checked accessors, never written or retained.
    // This relies on memmap2's no-concurrent-modification contract, the same
    // residual exposure documented on `read_export_facts`.
    let mmap =
        unsafe { memmap2::Mmap::map(file) }.map_err(|error| format!("read failed: {error}"))?;
    needed_libraries_from_mmap(&mmap)
}

fn needed_libraries_from_mmap(mmap: &memmap2::Mmap) -> Result<Vec<String>, String> {
    let (object, _, _) = classified_validated_object(mmap)?;
    needed_libraries_in_object(&object)
}

pub(crate) fn needed_libraries_in_object(object: &object::File<'_>) -> Result<Vec<String>, String> {
    macro_rules! walk {
        ($elf:expr) => {{
            // Absent dynamic section means statically linked: no names.
            // Corrupt table data refuses instead of yielding a partial list.
            let table = $elf
                .elf_dynamic_table()
                .map_err(|_| "invalid ELF dynamic table".to_string())?;
            let mut needed = Vec::new();
            for entry in table.iter() {
                if entry.tag != elf::DT_NEEDED {
                    continue;
                }
                let bytes = table
                    .string(entry)
                    .map_err(|_| "invalid DT_NEEDED string".to_string())?;
                let name = std::str::from_utf8(bytes)
                    .map_err(|_| "DT_NEEDED name is not valid UTF-8".to_string())?;
                needed.push(name.to_string());
            }
            return Ok(needed);
        }};
    }
    match object {
        object::File::Elf32(object) => walk!(object),
        object::File::Elf64(object) => walk!(object),
        _ => unreachable!("classified ELF"),
    }
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
