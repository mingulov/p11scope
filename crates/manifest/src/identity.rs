//! Per-object identity for manifest-reuse decisions. A manifest may only be
//! reused against a file whose identity matches (Gate G1: reuse refused on
//! content mismatch). Whole-file SHA-256 is authoritative; a GNU build ID is
//! retained as producer-supplied evidence. Non-ELF/unreadable input is
//! explicitly not reusable.

#[cfg(feature = "identify")]
use object::{
    BinaryFormat, Endianness, Object as _, ObjectSegment as _, elf,
    read::elf::{Dyn as _, FileHeader as _, ProgramHeader as _},
};
use serde::{Deserialize, Serialize};
#[cfg(feature = "identify")]
use sha2::{Digest as _, Sha256};
#[cfg(feature = "identify")]
use std::os::fd::AsRawFd as _;
#[cfg(feature = "identify")]
use std::os::unix::fs::{FileExt as _, OpenOptionsExt as _};
#[cfg(feature = "identify")]
use std::{
    ffi::OsString,
    os::unix::ffi::OsStringExt as _,
    path::{Path, PathBuf},
};

#[cfg(feature = "identify")]
pub const MAX_OBJECT_BYTES: u64 = 256 * 1024 * 1024;

#[cfg(feature = "identify")]
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub struct MappingFileKey {
    pub device_major: u64,
    pub device_minor: u64,
    pub inode: u64,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum IdentityKind {
    GnuBuildId,
    Sha256,
    Unavailable,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ObjectIdentity {
    pub kind: IdentityKind,
    /// Hex digest; `None` only when `kind == Unavailable`.
    pub value: Option<String>,
    /// Whole-file cryptographic identity used for authorization. GNU build IDs
    /// remain useful evidence but are producer-chosen and cannot authenticate
    /// a byte-identical safe copy on their own.
    pub sha256: Option<String>,
    /// Whether a manifest may be reused against a file with this identity.
    pub reusable: bool,
    pub note: Option<String>,
}

#[cfg(feature = "identify")]
pub fn identify(path: &Path) -> ObjectIdentity {
    match open_object(path).and_then(|file| inspect_file(&file)) {
        Ok(inspected) => inspected.identity,
        Err(note) => unavailable(note),
    }
}

#[cfg(feature = "identify")]
pub struct InspectedObject {
    pub identity: ObjectIdentity,
    pub executable_ranges: Vec<(u64, u64)>,
}

#[cfg(feature = "identify")]
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ElfLoader {
    pub interpreter: Option<PathBuf>,
    pub needed: Vec<OsString>,
    pub soname: Option<OsString>,
}

#[cfg(feature = "identify")]
#[derive(Debug, Clone, Copy)]
struct ProgramRange {
    file_start: u64,
    file_end: u64,
    virtual_start: u64,
    virtual_file_end: u64,
    virtual_end: u64,
}

#[cfg(feature = "identify")]
impl InspectedObject {
    pub fn contains_executable_offset(&self, offset: u64) -> bool {
        self.executable_ranges
            .iter()
            .any(|(start, end)| *start <= offset && offset < *end)
    }
}

#[cfg(feature = "identify")]
pub fn open_object(path: &Path) -> Result<std::fs::File, String> {
    let file = open_regular(path)?;
    let metadata = file
        .metadata()
        .map_err(|error| format!("metadata failed: {error}"))?;
    if metadata.len() > MAX_OBJECT_BYTES {
        return Err(format!(
            "object is {} bytes; limit is {MAX_OBJECT_BYTES}",
            metadata.len()
        ));
    }
    Ok(file)
}

/// Returns the device/inode tuple rendered for this fd's mappings in
/// `/proc/*/maps`. On filesystems such as btrfs, `st_dev` can be an anonymous
/// subvolume device while maps reports the containing mount's device.
#[cfg(feature = "identify")]
pub fn mapping_file_key(file: &std::fs::File) -> Result<MappingFileKey, String> {
    use std::os::unix::fs::MetadataExt as _;

    let metadata = file
        .metadata()
        .map_err(|error| format!("metadata failed: {error}"))?;
    let fdinfo = std::fs::read_to_string(format!("/proc/self/fdinfo/{}", file.as_raw_fd()))
        .map_err(|error| format!("reading fd mount identity failed: {error}"))?;
    let mount_id = fdinfo
        .lines()
        .find_map(|line| line.strip_prefix("mnt_id:\t"))
        .ok_or_else(|| "fd mount identity is missing".to_string())?;
    let mountinfo = std::fs::read_to_string("/proc/self/mountinfo")
        .map_err(|error| format!("reading mount table failed: {error}"))?;
    let device = mountinfo
        .lines()
        .find_map(|line| {
            let mut fields = line.split_ascii_whitespace();
            (fields.next()? == mount_id)
                .then(|| fields.nth(1))
                .flatten()
        })
        .ok_or_else(|| format!("fd mount {mount_id} is missing from the mount table"))?;
    let (major, minor) = device
        .split_once(':')
        .ok_or_else(|| format!("invalid mount device {device:?}"))?;
    Ok(MappingFileKey {
        device_major: major
            .parse()
            .map_err(|_| format!("invalid mount device {device:?}"))?,
        device_minor: minor
            .parse()
            .map_err(|_| format!("invalid mount device {device:?}"))?,
        inode: metadata.ino(),
    })
}

/// Pins the pathname without invoking device/FIFO open semantics, verifies
/// the pinned inode is regular, then obtains a readable descriptor for that
/// same inode. Normal provider symlinks remain supported safely.
#[cfg(feature = "identify")]
pub fn open_regular(path: &Path) -> Result<std::fs::File, String> {
    let pinned = std::fs::OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_PATH | libc::O_CLOEXEC)
        .open(path)
        .map_err(|error| format!("open failed: {error}"))?;
    let metadata = pinned
        .metadata()
        .map_err(|error| format!("metadata failed: {error}"))?;
    if !metadata.file_type().is_file() {
        return Err("not a regular file".into());
    }
    std::fs::OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_CLOEXEC)
        .open(format!("/proc/self/fd/{}", pinned.as_raw_fd()))
        .map_err(|error| format!("opening pinned regular file failed: {error}"))
}

#[cfg(feature = "identify")]
pub fn inspect_file(file: &std::fs::File) -> Result<InspectedObject, String> {
    let data = read_object_bytes(file)?;
    let object = object::File::parse(&*data)
        .map_err(|error| format!("not parseable as an object file: {error}"))?;
    if object.format() != BinaryFormat::Elf {
        return Err(format!("not an ELF object ({:?})", object.format()));
    }
    let sha256 = hex(&Sha256::digest(&data));
    let mut note = None;
    // object reads the build-id from PT_NOTE program headers too, so a
    // stripped section table does not lose it (review finding, 2026-08-11).
    let identity = match object.build_id() {
        Ok(Some(id)) => ObjectIdentity {
            kind: IdentityKind::GnuBuildId,
            value: Some(hex(id)),
            sha256: Some(sha256.clone()),
            reusable: true,
            note: None,
        },
        Ok(None) => ObjectIdentity {
            kind: IdentityKind::Sha256,
            value: Some(sha256.clone()),
            sha256: Some(sha256.clone()),
            reusable: true,
            note,
        },
        Err(error) => {
            note = Some(format!("build-id read failed: {error}"));
            ObjectIdentity {
                kind: IdentityKind::Sha256,
                value: Some(sha256.clone()),
                sha256: Some(sha256),
                reusable: true,
                note,
            }
        }
    };
    let executable_ranges = object
        .segments()
        .filter(|segment| segment.permissions().executable())
        .filter_map(|segment| {
            let (start, size) = segment.file_range();
            start.checked_add(size).map(|end| (start, end))
        })
        .collect();
    Ok(InspectedObject {
        identity,
        executable_ranges,
    })
}

#[cfg(feature = "identify")]
pub fn inspect_elf_loader(file: &std::fs::File) -> Result<ElfLoader, String> {
    let data = read_object_bytes(file)?;
    if data.get(4) != Some(&elf::ELFCLASS64) {
        return Err("loader object is not ELF64".into());
    }
    if data.get(5) != Some(&elf::ELFDATA2LSB) {
        return Err("loader object is not little-endian".into());
    }

    type Header = elf::FileHeader64<Endianness>;
    let header =
        Header::parse(&*data).map_err(|error| format!("invalid ELF64 loader header: {error}"))?;
    let endian = header
        .endian()
        .map_err(|error| format!("invalid ELF loader endian: {error}"))?;
    if header.e_machine(endian) != elf::EM_X86_64 {
        return Err("loader object is not x86-64".into());
    }
    if !matches!(header.e_type(endian), elf::ET_EXEC | elf::ET_DYN) {
        return Err("loader object is not ET_EXEC or ET_DYN".into());
    }
    if header.e_version(endian) != u32::from(elf::EV_CURRENT) {
        return Err("loader object has an unsupported ELF version".into());
    }
    if usize::from(header.e_ehsize(endian)) != std::mem::size_of::<Header>() {
        return Err("invalid ELF header size".into());
    }
    if header.e_phoff(endian) == 0 || header.e_phnum(endian) == 0 {
        return Err("loader object has no coherent program header table".into());
    }
    if header.e_phnum(endian) == elf::PN_XNUM {
        return Err("loader object uses an unsupported extended program header count".into());
    }
    let program_headers = header
        .program_headers(endian, &*data)
        .map_err(|error| format!("invalid ELF program header: {error}"))?;

    let mut interpreter = None;
    let mut dynamic_header = None;
    let mut dynamic_range = None;
    let mut load_ranges = Vec::new();
    let mut previous_load_vaddr = None;
    let mut saw_load = false;
    for program in program_headers {
        match program.p_type(endian) {
            elf::PT_INTERP => {
                if saw_load {
                    return Err("PT_INTERP must precede every PT_LOAD".into());
                }
                if interpreter.is_some() {
                    return Err("loader object has multiple PT_INTERP headers".into());
                }
                let bytes = program
                    .data(endian, &*data)
                    .map_err(|_| "invalid PT_INTERP bounds".to_string())?;
                let Some((&0, path)) = bytes.split_last() else {
                    return Err("PT_INTERP is not exactly NUL-terminated".into());
                };
                if path.is_empty() || path.contains(&0) {
                    return Err("PT_INTERP is not exactly NUL-terminated".into());
                }
                let path = PathBuf::from(OsString::from_vec(path.to_vec()));
                if !path.is_absolute() {
                    return Err("PT_INTERP is not an absolute path".into());
                }
                interpreter = Some(path);
            }
            elf::PT_LOAD => {
                saw_load = true;
                let range = program_range(program, endian, data.len(), "PT_LOAD")?;
                if previous_load_vaddr.is_some_and(|previous| range.virtual_start <= previous) {
                    return Err("PT_LOAD headers are not in ascending virtual address order".into());
                }
                previous_load_vaddr = Some(range.virtual_start);
                load_ranges.push(range);
            }
            elf::PT_DYNAMIC => {
                if dynamic_header.replace(program).is_some() {
                    return Err("loader object has multiple PT_DYNAMIC headers".into());
                }
                dynamic_range = Some(program_range(program, endian, data.len(), "PT_DYNAMIC")?);
            }
            _ => {}
        }
    }
    if !saw_load {
        return Err("loader object must contain at least one PT_LOAD".into());
    }

    if let Some(dynamic) = dynamic_range {
        let matching_loads = load_ranges
            .iter()
            .filter(|load| {
                dynamic.file_start >= load.file_start
                    && dynamic.file_end <= load.file_end
                    && dynamic.virtual_start >= load.virtual_start
                    && dynamic.virtual_file_end <= load.virtual_file_end
                    && dynamic.virtual_end <= load.virtual_end
                    && dynamic.file_start - load.file_start
                        == dynamic.virtual_start - load.virtual_start
            })
            .count();
        if matching_loads != 1 {
            return Err(
                "PT_DYNAMIC mapping is not covered by exactly one PT_LOAD with identical file/runtime translation"
                    .into(),
            );
        }
    }

    let mut needed_offsets = Vec::new();
    let mut soname_offset = None;
    let mut string_address = None;
    let mut string_size = None;
    if let Some(program) = dynamic_header {
        let dynamics = program
            .dynamic(endian, &*data)
            .map_err(|error| format!("invalid PT_DYNAMIC segment: {error}"))?
            .ok_or_else(|| "invalid PT_DYNAMIC segment".to_string())?;
        let mut terminated = false;
        for dynamic in dynamics {
            let tag = dynamic.tag(endian);
            let value = dynamic.val(endian);
            if terminated {
                if tag != elf::DT_NULL || value != 0 {
                    return Err("PT_DYNAMIC contains data after DT_NULL".into());
                }
                continue;
            }
            match tag {
                elf::DT_NULL => terminated = true,
                elf::DT_NEEDED => needed_offsets.push(value),
                elf::DT_SONAME => set_once(&mut soname_offset, value, "DT_SONAME")?,
                elf::DT_STRTAB => set_once(&mut string_address, value, "DT_STRTAB")?,
                elf::DT_STRSZ => set_once(&mut string_size, value, "DT_STRSZ")?,
                elf::DT_RPATH
                | elf::DT_RUNPATH
                | elf::DT_AUDIT
                | elf::DT_DEPAUDIT
                | elf::DT_FILTER
                | elf::DT_AUXILIARY => {
                    return Err(format!("forbidden dynamic tag {tag:#x}"));
                }
                _ => {}
            }
        }
        if !terminated {
            return Err("PT_DYNAMIC has no DT_NULL terminator".into());
        }
    }

    let uses_strings = string_address.is_some()
        || string_size.is_some()
        || !needed_offsets.is_empty()
        || soname_offset.is_some();
    let strings = if uses_strings {
        let address = string_address.ok_or_else(|| "missing DT_STRTAB".to_string())?;
        let size = string_size.ok_or_else(|| "missing DT_STRSZ".to_string())?;
        let mut found = None;
        for program in program_headers
            .iter()
            .filter(|program| program.p_type(endian) == elf::PT_LOAD)
        {
            if let Some(bytes) = program
                .data_range(endian, &*data, address, size)
                .map_err(|_| "invalid PT_LOAD bounds while locating string table".to_string())?
            {
                if found.replace(bytes).is_some() {
                    return Err(
                        "dynamic string table is covered by more than exactly one PT_LOAD".into(),
                    );
                }
            }
        }
        found.ok_or_else(|| "dynamic string table is outside every PT_LOAD".to_string())?
    } else {
        &[]
    };

    let mut total_name_bytes = 0usize;
    let mut needed = Vec::with_capacity(needed_offsets.len());
    for offset in needed_offsets {
        let name = dynamic_string(strings, offset, "DT_NEEDED")?;
        if name.contains(&b'/') {
            return Err("DT_NEEDED contains '/'".into());
        }
        total_name_bytes = bounded_name_total(total_name_bytes, name.len(), data.len())?;
        needed.push(OsString::from_vec(name.to_vec()));
    }
    let soname = if let Some(offset) = soname_offset {
        let name = dynamic_string(strings, offset, "DT_SONAME")?;
        let _ = bounded_name_total(total_name_bytes, name.len(), data.len())?;
        Some(OsString::from_vec(name.to_vec()))
    } else {
        None
    };

    Ok(ElfLoader {
        interpreter,
        needed,
        soname,
    })
}

#[cfg(feature = "identify")]
fn read_object_bytes(file: &std::fs::File) -> Result<Vec<u8>, String> {
    let metadata = file
        .metadata()
        .map_err(|error| format!("metadata failed: {error}"))?;
    if !metadata.file_type().is_file() {
        return Err("not a regular file".into());
    }
    let len = metadata.len();
    if len > MAX_OBJECT_BYTES {
        return Err(format!(
            "object is {len} bytes; limit is {MAX_OBJECT_BYTES}"
        ));
    }
    let len: usize = len
        .try_into()
        .map_err(|_| "object length does not fit usize")?;
    let mut data = vec![0u8; len];
    let mut done = 0;
    while done < data.len() {
        let read = file
            .read_at(&mut data[done..], done as u64)
            .map_err(|error| format!("read failed: {error}"))?;
        if read == 0 {
            return Err(format!("short read: {done} of {} bytes", data.len()));
        }
        done += read;
    }
    Ok(data)
}

#[cfg(feature = "identify")]
fn program_range(
    program: &elf::ProgramHeader64<Endianness>,
    endian: Endianness,
    data_len: usize,
    name: &str,
) -> Result<ProgramRange, String> {
    let file_start = program.p_offset(endian);
    let file_size = program.p_filesz(endian);
    let memory_size = program.p_memsz(endian);
    if file_size > memory_size {
        return Err(format!("{name} file size exceeds memory size"));
    }
    let file_end = file_start
        .checked_add(file_size)
        .ok_or_else(|| format!("{name} file range overflows"))?;
    if file_end > data_len as u64 {
        return Err(format!("{name} file range is outside the object"));
    }
    let virtual_start = program.p_vaddr(endian);
    let virtual_file_end = virtual_start
        .checked_add(file_size)
        .ok_or_else(|| format!("{name} virtual range overflows"))?;
    let virtual_end = virtual_start
        .checked_add(memory_size)
        .ok_or_else(|| format!("{name} virtual range overflows"))?;
    let align = program.p_align(endian);
    if align > 1 {
        if !align.is_power_of_two() {
            return Err(format!("{name} alignment is not a power of two"));
        }
        if file_start % align != virtual_start % align {
            return Err(format!("{name} file/runtime alignment mismatch"));
        }
    }
    Ok(ProgramRange {
        file_start,
        file_end,
        virtual_start,
        virtual_file_end,
        virtual_end,
    })
}

#[cfg(feature = "identify")]
fn set_once(slot: &mut Option<u64>, value: u64, name: &str) -> Result<(), String> {
    if slot.replace(value).is_some() {
        return Err(format!("multiple {name} entries"));
    }
    Ok(())
}

#[cfg(feature = "identify")]
fn dynamic_string<'a>(strings: &'a [u8], offset: u64, name: &str) -> Result<&'a [u8], String> {
    let offset: usize = offset
        .try_into()
        .map_err(|_| format!("invalid {name} string offset"))?;
    let rest = strings
        .get(offset..)
        .ok_or_else(|| format!("invalid {name} string offset"))?;
    let end = rest
        .iter()
        .position(|byte| *byte == 0)
        .ok_or_else(|| format!("{name} is not NUL-terminated"))?;
    if end == 0 {
        return Err(format!("empty {name}"));
    }
    Ok(&rest[..end])
}

#[cfg(feature = "identify")]
fn bounded_name_total(current: usize, added: usize, limit: usize) -> Result<usize, String> {
    current
        .checked_add(added)
        .filter(|total| *total <= limit)
        .ok_or_else(|| "loader names exceed the bounded object size".to_string())
}

#[cfg(feature = "identify")]
fn unavailable(note: String) -> ObjectIdentity {
    ObjectIdentity {
        kind: IdentityKind::Unavailable,
        value: None,
        sha256: None,
        reusable: false,
        note: Some(note),
    }
}

#[cfg(feature = "identify")]
pub fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}
