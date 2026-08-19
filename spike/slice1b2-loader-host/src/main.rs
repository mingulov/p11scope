// Task 7 host side: §7.3 cookie round-trip, 256-entry monotonic registry, and
// the ptrace-free pre-exec loader attach (`loader-hit`), plus the §8.1 no-cookie
// negative and the Task 2-style STATS diagnostic. The A/B artifact's
// spike/slice1b2-kernel files are never touched (Task 5 freeze boundary).

#[path = "../../slice1b2-loader-bpf/common.rs"]
pub mod common;

use std::collections::BTreeMap;
use std::error::Error;
use std::ffi::{CStr, CString};
use std::fs::File;
use std::io::{self, Read as _, Write as _};
use std::num::NonZeroU32;
use std::os::fd::{AsRawFd as _, FromRawFd as _, OwnedFd};
use std::os::unix::ffi::OsStrExt as _;
use std::os::unix::fs::{DirBuilderExt as _, MetadataExt as _, OpenOptionsExt as _};
use std::path::{Path, PathBuf};
use std::time::{Duration, Instant};

use sha2::{Digest as _, Sha256};

unsafe impl aya::Pod for common::StateKey {}
unsafe impl aya::Pod for common::StartState {}

const LOADER_PROGRAM: &str = "dl_debug_state";
/// Corrective design §7.3: loader event records reuse the existing 896-byte
/// DiscoveryRecord with `kind = LOADER = 3`.
pub const KIND_LOADER: u8 = 3;
/// §7.3 `status_flags` bit 0x04 = loader_context_invalid.
pub const STATUS_CONTEXT_INVALID: u8 = 0x04;
/// §7.3 registry capacity; context IDs are allocated 1..=256 and never reused.
pub const REGISTRY_CAPACITY: u16 = 256;
/// glibc `enum r_state`: `RT_CONSISTENT = 0`, `RT_ADD = 1`.
pub const RT_CONSISTENT: u32 = 0;
pub const RT_ADD: u32 = 1;

pub fn decode_discovery_record(bytes: &[u8]) -> Result<common::DiscoveryRecord, &'static str> {
    if bytes.len() != std::mem::size_of::<common::DiscoveryRecord>() {
        return Err("discovery record length is not 896 bytes");
    }
    // SAFETY: the byte slice has exactly the repr(C) record's size; the copy
    // reinterprets initialized ring bytes only, at u64 alignment via read_unaligned.
    Ok(unsafe { core::ptr::read_unaligned(bytes.as_ptr() as *const common::DiscoveryRecord) })
}

// ---------------------------------------------------------------------------
// §7.3 registry: immutable payload + mutable registration shell, 256 slots,
// monotonic IDs that are never reused.
// ---------------------------------------------------------------------------

#[derive(Clone, Debug, PartialEq)]
pub struct LoaderContext {
    pub generation: u64,
    pub loader_sha256: String,
    pub loader_device: u64,
    pub loader_inode: u64,
    pub hook_vaddr: u64,
    pub hook_file_offset: u64,
    pub r_debug_vaddr: Option<u64>,
    pub delta: Option<i64>,
}

#[derive(Clone, Copy, Debug, PartialEq)]
pub enum RegistrationShell {
    Prepared,
    Attached { has_link: bool },
    Tombstoned { former_link: bool },
}

pub struct LoaderRegistry {
    slots: Vec<Option<(LoaderContext, RegistrationShell)>>,
    next_id: u16,
    generation: u64,
}

impl Default for LoaderRegistry {
    fn default() -> Self {
        Self::new()
    }
}

impl LoaderRegistry {
    pub fn new() -> Self {
        let mut slots = Vec::with_capacity(usize::from(REGISTRY_CAPACITY));
        for _ in 0..REGISTRY_CAPACITY {
            slots.push(None);
        }
        LoaderRegistry {
            slots,
            next_id: 1,
            generation: 0,
        }
    }

    /// Allocates the next context ID with a `prepared` shell. Exactly 256 IDs
    /// exist per session-local registry and are never reused. The payload's
    /// generation is assigned here and is immutable afterwards.
    pub fn allocate(&mut self, mut payload: LoaderContext) -> Result<u16, &'static str> {
        let id = self.next_id;
        if id > REGISTRY_CAPACITY || id == 0 {
            return Err("registry capacity");
        }
        self.next_id += 1;
        self.generation += 1;
        payload.generation = self.generation;
        self.slots[usize::from(id - 1)] = Some((payload, RegistrationShell::Prepared));
        Ok(id)
    }

    pub fn mark_attached(&mut self, id: u16) -> Result<(), &'static str> {
        let shell = self.slot_mut(id)?;
        if matches!(shell, RegistrationShell::Prepared) {
            *shell = RegistrationShell::Attached { has_link: true };
            Ok(())
        } else {
            Err("registry phase")
        }
    }

    pub fn mark_tombstoned(&mut self, id: u16, former_link: bool) -> Result<(), &'static str> {
        let shell = self.slot_mut(id)?;
        if matches!(
            shell,
            RegistrationShell::Attached { .. } | RegistrationShell::Prepared
        ) {
            *shell = RegistrationShell::Tombstoned { former_link };
            Ok(())
        } else {
            Err("registry phase")
        }
    }

    /// A decoder accepts an `attached` shell or a `tombstoned` shell that
    /// retains the former successful link binding during the final drain; it
    /// rejects a `prepared` shell and an attach-failure tombstone.
    pub fn decodable(&self, id: u16) -> bool {
        matches!(
            self.slot(id),
            Some(RegistrationShell::Attached { has_link: true })
                | Some(RegistrationShell::Tombstoned { former_link: true })
        )
    }

    fn slot(&self, id: u16) -> Option<&RegistrationShell> {
        self.slots
            .get(usize::from(id.checked_sub(1)?))?
            .as_ref()
            .map(|(_, shell)| shell)
    }

    fn slot_mut(&mut self, id: u16) -> Result<&mut RegistrationShell, &'static str> {
        let filled = self
            .slots
            .get_mut(usize::from(id.checked_sub(1).ok_or("registry index")?))
            .ok_or("registry index")?
            .as_mut()
            .ok_or("registry index")?;
        Ok(&mut filled.1)
    }
}

// ---------------------------------------------------------------------------
// ELF facts (own minimal helpers; p11scope-manifest keeps the product paths)
// ---------------------------------------------------------------------------

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct SymbolLocation {
    pub vaddr: u64,
    /// `None` when the symbol lives in a non-file-backed region (`.bss`).
    pub file_offset: Option<u64>,
}

fn parse_elf(bytes: &[u8]) -> Result<object::File<'_>, &'static str> {
    use object::Object as _;
    let object = object::File::parse(bytes).map_err(|_| "not parseable as an ELF object")?;
    if object.architecture() != object::Architecture::X86_64 {
        return Err("not a 64-bit x86-64 ELF object");
    }
    Ok(object)
}

/// Virtual address + optional file offset of one symbol (dynsym first, then
/// symtab). `file_offset` is `None` for symbols outside any file-backed
/// segment — e.g. glibc keeps `_r_debug` in `.bss`, which still yields a
/// usable vaddr for the §7.3 delta.
pub fn elf_symbol(bytes: &[u8], name: &str) -> Result<Option<SymbolLocation>, &'static str> {
    use object::{Object as _, ObjectSegment as _, ObjectSymbol as _};
    let object = parse_elf(bytes)?;
    let segments: Vec<(u64, u64, u64)> = object
        .segments()
        .map(|segment| {
            let (file_start, file_size) = segment.file_range();
            (segment.address(), file_start, file_size)
        })
        .collect();
    let file_offset = |vaddr: u64| {
        segments.iter().find_map(|&(start, file_start, file_size)| {
            let delta = vaddr.checked_sub(start)?;
            (delta < file_size).then(|| file_start + delta)
        })
    };
    for symbol in object.dynamic_symbols().chain(object.symbols()) {
        if symbol.name() != Ok(name) || symbol.address() == 0 {
            continue;
        }
        return Ok(Some(SymbolLocation {
            vaddr: symbol.address(),
            file_offset: file_offset(symbol.address()),
        }));
    }
    Ok(None)
}

/// `PT_INTERP` loader path of an executable ELF, read from the program headers.
pub fn elf_interp(bytes: &[u8]) -> Result<PathBuf, &'static str> {
    const PT_INTERP: u32 = 3;
    let read_u16 = |offset: usize| -> Result<u16, &'static str> {
        let end = offset.checked_add(2).ok_or("PT_INTERP bounds")?;
        let raw = bytes.get(offset..end).ok_or("PT_INTERP bounds")?;
        Ok(u16::from_le_bytes([raw[0], raw[1]]))
    };
    let read_u64 = |offset: usize| -> Result<u64, &'static str> {
        let end = offset.checked_add(8).ok_or("PT_INTERP bounds")?;
        let raw = bytes.get(offset..end).ok_or("PT_INTERP bounds")?;
        Ok(u64::from_le_bytes([
            raw[0], raw[1], raw[2], raw[3], raw[4], raw[5], raw[6], raw[7],
        ]))
    };
    if bytes.len() < 64 || bytes.get(0..4) != Some(&[0x7f, b'E', b'L', b'F']) {
        return Err("PT_INTERP elf");
    }
    let phoff = read_u64(0x20)? as usize;
    let phentsize = read_u16(0x36)? as usize;
    let phnum = read_u16(0x38)? as usize;
    if phentsize < 56 {
        return Err("PT_INTERP phentsize");
    }
    for index in 0..phnum {
        let base = phoff
            .checked_add(index.checked_mul(phentsize).ok_or("PT_INTERP bounds")?)
            .ok_or("PT_INTERP bounds")?;
        if base.checked_add(56).ok_or("PT_INTERP bounds")? > bytes.len() {
            return Err("PT_INTERP bounds");
        }
        let p_type = u32::from_le_bytes([
            bytes[base],
            bytes[base + 1],
            bytes[base + 2],
            bytes[base + 3],
        ]);
        if p_type != PT_INTERP {
            continue;
        }
        let offset = read_u64(base + 8)? as usize;
        let size = read_u64(base + 32)? as usize;
        let end = offset.checked_add(size).ok_or("PT_INTERP bounds")?;
        let raw = bytes.get(offset..end).ok_or("PT_INTERP bounds")?;
        let nul = raw
            .iter()
            .position(|byte| *byte == 0)
            .ok_or("PT_INTERP nul")?;
        return Ok(PathBuf::from(
            std::ffi::OsStr::from_bytes(&raw[..nul]).to_os_string(),
        ));
    }
    Err("PT_INTERP missing")
}

// ---------------------------------------------------------------------------
// Environment facts (mirrors the A/B runner's helpers)
// ---------------------------------------------------------------------------

fn kernel_release() -> Result<String, &'static str> {
    let mut uts = libc::utsname {
        sysname: [0; 65],
        nodename: [0; 65],
        release: [0; 65],
        version: [0; 65],
        machine: [0; 65],
        domainname: [0; 65],
    };
    // SAFETY: uts points to an initialized utsname of the size uname expects.
    if unsafe { libc::uname(&mut uts) } != 0 {
        return Err("uname");
    }
    let release: Vec<u8> = uts
        .release
        .iter()
        .take_while(|byte| **byte != 0)
        .cloned()
        .filter_map(|byte| u8::try_from(byte).ok())
        .collect();
    String::from_utf8(release).map_err(|_| "kernel release encoding")
}

fn glibc_version() -> Result<String, &'static str> {
    // SAFETY: gnu_get_libc_version writes a short nul-terminated constant string.
    let pointer = unsafe { libc::gnu_get_libc_version() };
    // SAFETY: the returned pointer is a live nul-terminated C string.
    let bytes = unsafe { CStr::from_ptr(pointer) }.to_bytes();
    let version = String::from_utf8(bytes.to_vec()).map_err(|_| "glibc version")?;
    Ok(format!("glibc {version}"))
}

fn kernel_matches(actual: &str, prefix: &str) -> bool {
    actual == prefix
        || actual
            .strip_prefix(prefix)
            .is_some_and(|tail| tail.starts_with('.') || tail.starts_with('-'))
}

// ---------------------------------------------------------------------------
// Fork barrier child: ready byte, blocked release read, then exec. The loader
// runs only after exec, so the loader uprobe can be attached to the still
// pre-exec child (§7.3 one-process scope, pinned file offset).
// ---------------------------------------------------------------------------

struct BarrierChild {
    pid: i32,
    release: OwnedFd,
}

fn pipe_pair(flags: i32) -> io::Result<(OwnedFd, OwnedFd)> {
    let mut fds = [-1; 2];
    // SAFETY: fds addresses two writable ints; success yields two live descriptors.
    if unsafe { libc::pipe2(fds.as_mut_ptr(), flags) } != 0 {
        return Err(io::Error::last_os_error());
    }
    // SAFETY: both descriptors were just created and are uniquely owned here.
    Ok(unsafe { (OwnedFd::from_raw_fd(fds[0]), OwnedFd::from_raw_fd(fds[1])) })
}

fn fork_exec_child(fixture: &Path) -> Result<BarrierChild, &'static str> {
    let (ready_read, ready_write) = pipe_pair(libc::O_CLOEXEC).map_err(|_| "fixture pipes")?;
    let (release_read, release_write) = pipe_pair(0).map_err(|_| "fixture pipes")?;
    let fixture_c =
        CString::new(fixture.as_os_str().as_encoded_bytes()).map_err(|_| "fixture path")?;
    let arg0 = CString::new("slice1b2-loader-fixture").map_err(|_| "fixture path")?;
    // SAFETY: fork duplicates this single-threaded process; the child runs only
    // async-signal-safe libc calls before exec and _exit, and never returns.
    let pid = unsafe { libc::fork() };
    if pid < 0 {
        return Err("fork");
    }
    if pid == 0 {
        unsafe {
            libc::close(ready_read.as_raw_fd());
            libc::close(release_write.as_raw_fd());
            libc::dup2(release_read.as_raw_fd(), 0);
            libc::close(release_read.as_raw_fd());
            let byte = b'R';
            libc::write(ready_write.as_raw_fd(), &byte as *const u8 as *const _, 1);
            let mut gate = 0u8;
            loop {
                let read = libc::read(0, &mut gate as *mut u8 as *mut _, 1);
                if read == 1 {
                    break;
                }
                if read < 0 && io::Error::last_os_error().kind() == io::ErrorKind::Interrupted {
                    continue;
                }
                libc::_exit(126);
            }
            let argv: [*const libc::c_char; 2] = [arg0.as_ptr(), std::ptr::null()];
            libc::execv(fixture_c.as_ptr(), argv.as_ptr());
            libc::_exit(127);
        }
    }
    drop(ready_write);
    drop(release_read);
    let mut byte = 0u8;
    let deadline = Instant::now() + Duration::from_secs(5);
    loop {
        if Instant::now() > deadline {
            let _ = unsafe { libc::kill(pid, libc::SIGKILL) };
            let _ = wait_pid(pid);
            return Err("fixture ready timeout");
        }
        // SAFETY: one-byte buffer, owned fd.
        let read = unsafe {
            libc::read(
                ready_read.as_raw_fd(),
                &mut byte as *mut u8 as *const _ as *mut _,
                1,
            )
        };
        if read == 1 && byte == b'R' {
            break;
        }
        if read < 0 && io::Error::last_os_error().kind() == io::ErrorKind::Interrupted {
            continue;
        }
        let _ = unsafe { libc::kill(pid, libc::SIGKILL) };
        let _ = wait_pid(pid);
        return Err("pipe byte");
    }
    drop(ready_read);
    Ok(BarrierChild {
        pid,
        release: release_write,
    })
}

fn wait_pid(pid: i32) -> Result<i32, &'static str> {
    let deadline = Instant::now() + Duration::from_secs(30);
    loop {
        let mut status = 0;
        // SAFETY: status is an initialized int for the owned child pid.
        let waited = unsafe { libc::waitpid(pid, &mut status, libc::WNOHANG) };
        if waited == pid {
            return Ok(status);
        }
        if waited < 0 {
            return Err("child wait");
        }
        if Instant::now() > deadline {
            return Err("child exit timeout");
        }
        std::thread::sleep(Duration::from_millis(2));
    }
}

fn write_release(child: &mut BarrierChild) -> Result<(), &'static str> {
    // SAFETY: one byte, owned fd.
    let byte = b'G';
    let wrote =
        unsafe { libc::write(child.release.as_raw_fd(), &byte as *const u8 as *const _, 1) };
    if wrote != 1 {
        return Err("child release");
    }
    Ok(())
}

fn kill_and_reap(pid: i32) {
    // SAFETY: scalar pid and signals for an owned child.
    unsafe {
        libc::kill(pid, libc::SIGKILL);
    }
    let _ = wait_pid(pid);
}

// ---------------------------------------------------------------------------
// Loader mapping bias: lowest (start - file offset) across the loader inode's
// mappings in the still-running child's /proc/<pid>/maps.
// ---------------------------------------------------------------------------

/// True once the child's `/proc/<pid>/exe` points at the fixture: before
/// `execve` the forked child still shows the runner's image (including its
/// own inherited loader mapping), which would yield the wrong load bias.
fn child_execed(pid: i32, fixture: &Path) -> bool {
    let exe = format!("/proc/{pid}/exe");
    match std::fs::read_link(&exe) {
        Ok(target) => target == fixture,
        Err(_) => false,
    }
}

fn loader_load_bias(
    pid: i32,
    dev_major: u64,
    dev_minor: u64,
    inode: u64,
    canonical_path: &Path,
) -> Result<u64, &'static str> {
    let maps = std::fs::read_to_string(format!("/proc/{pid}/maps")).map_err(|_| "process maps")?;
    let mut best: Option<u64> = None;
    for line in maps.lines() {
        let fields = line.split_whitespace().collect::<Vec<_>>();
        if fields.len() < 5 {
            continue;
        }
        let Some((major, minor)) = fields[3].split_once(':') else {
            continue;
        };
        let (Ok(major), Ok(minor), Ok(map_inode)) = (
            u64::from_str_radix(major, 16),
            u64::from_str_radix(minor, 16),
            fields[4].parse::<u64>(),
        ) else {
            continue;
        };
        let path_matches = fields
            .get(5)
            .is_some_and(|path| Path::new(path) == canonical_path);
        if map_inode != inode || ((major != dev_major || minor != dev_minor) && !path_matches) {
            continue;
        }
        let Some((start, _end)) = fields[0].split_once('-') else {
            continue;
        };
        let (Ok(start), Ok(file_offset)) = (
            u64::from_str_radix(start, 16),
            u64::from_str_radix(fields[2], 16),
        ) else {
            continue;
        };
        let bias = start
            .checked_sub(file_offset)
            .ok_or("loader mapping bias")?;
        best = Some(best.map_or(bias, |current: u64| current.min(bias)));
    }
    best.ok_or("loader executable mapping")
}

fn canonical_loader_path(pid: i32, interp: &Path) -> Result<PathBuf, &'static str> {
    let relative = interp.strip_prefix("/").map_err(|_| "loader path")?;
    std::fs::canonicalize(PathBuf::from(format!("/proc/{pid}/root")).join(relative))
        .map_err(|_| "loader path")
}

// ---------------------------------------------------------------------------
// Attach helpers
// ---------------------------------------------------------------------------

fn attach_program(
    ebpf: &mut aya::Ebpf,
    offset: u64,
    target: &Path,
    pid: u32,
    cookie: Option<u64>,
) -> Result<aya::programs::uprobe::UProbeLinkId, &'static str> {
    attach_named(ebpf, LOADER_PROGRAM, offset, target, pid, cookie)
}

fn attach_named(
    ebpf: &mut aya::Ebpf,
    program_name: &str,
    offset: u64,
    target: &Path,
    pid: u32,
    cookie: Option<u64>,
) -> Result<aya::programs::uprobe::UProbeLinkId, &'static str> {
    use aya::programs::UProbe;
    use aya::programs::uprobe::{UProbeAttachLocation, UProbeAttachPoint, UProbeScope};
    let program: &mut UProbe = ebpf
        .program_mut(program_name)
        .ok_or("program missing")?
        .try_into()
        .map_err(|_| "program type")?;
    let scope = UProbeScope::OneProcess(NonZeroU32::new(pid).ok_or("child pid is zero")?);
    let point = UProbeAttachPoint {
        location: UProbeAttachLocation::AbsoluteOffset(offset),
        cookie,
    };
    program
        .attach(point, target, scope)
        .map_err(|_| "program attach")
}

fn detach_program(
    ebpf: &mut aya::Ebpf,
    link: aya::programs::uprobe::UProbeLinkId,
) -> Result<(), &'static str> {
    detach_named(ebpf, LOADER_PROGRAM, link)
}

fn detach_named(
    ebpf: &mut aya::Ebpf,
    program_name: &str,
    link: aya::programs::uprobe::UProbeLinkId,
) -> Result<(), &'static str> {
    use aya::programs::UProbe;
    let program: &mut UProbe = ebpf
        .program_mut(program_name)
        .ok_or("program missing")?
        .try_into()
        .map_err(|_| "program type")?;
    program.detach(link).map_err(|_| "program detach")
}

fn read_counters(
    counters: &aya::maps::Array<aya::maps::MapData, u64>,
) -> Result<[u64; 6], &'static str> {
    let mut values = [0u64; 6];
    for (index, value) in values.iter_mut().enumerate() {
        *value = counters
            .get(&(index as u32), 0)
            .map_err(|_| "counter read")?;
    }
    Ok(values)
}

fn drain_loader_records(
    ring: &mut aya::maps::RingBuf<aya::maps::MapData>,
) -> Result<Vec<common::DiscoveryRecord>, &'static str> {
    let mut records = Vec::new();
    while let Some(item) = ring.next() {
        records.push(decode_discovery_record(&item)?);
    }
    Ok(records)
}

fn sha256_hex(bytes: &[u8]) -> String {
    let mut hasher = Sha256::new();
    hasher.update(bytes);
    let digest = hasher.finalize();
    digest.iter().map(|byte| format!("{byte:02x}")).collect()
}

fn create_private_dir(path: &Path) -> io::Result<()> {
    std::fs::DirBuilder::new().mode(0o700).create(path)
}

fn create_private_file(path: &Path) -> io::Result<File> {
    std::fs::OpenOptions::new()
        .mode(0o600)
        .create_new(true)
        .write(true)
        .open(path)
}

fn valid_hex(value: &str, length: usize) -> bool {
    value.len() == length && value.bytes().all(|byte| byte.is_ascii_hexdigit())
}

fn read_regular(path: &Path, ceiling: u64) -> Result<Vec<u8>, &'static str> {
    let file = File::open(path).map_err(|_| "input open")?;
    let size = file.metadata().map_err(|_| "input metadata")?.len();
    if size > ceiling {
        return Err("input size");
    }
    let mut bytes = Vec::new();
    (&file)
        .take(ceiling)
        .read_to_end(&mut bytes)
        .map_err(|_| "input read")?;
    Ok(bytes)
}

fn json_string<'a>(value: &'a serde_json::Value, name: &str) -> Result<&'a str, &'static str> {
    value
        .get(name)
        .and_then(serde_json::Value::as_str)
        .ok_or("manifest field")
}

fn write_json_line(file: &mut File, value: serde_json::Value) -> Result<(), &'static str> {
    serde_json::to_writer(&mut *file, &value).map_err(|_| "JSON write")?;
    file.write_all(b"\n").map_err(|_| "JSON write")
}

fn verifier_error_chain(error: &(dyn Error + 'static)) -> String {
    let mut text = error.to_string();
    let mut source = error.source();
    while let Some(error) = source {
        text.push_str("\ncaused_by=");
        text.push_str(&error.to_string());
        source = error.source();
    }
    text
}

// ---------------------------------------------------------------------------
// Provenance (digest-bound bundle, guest lane identity)
// ---------------------------------------------------------------------------

struct LoaderPaths {
    source_manifest: PathBuf,
    build_evidence: PathBuf,
    execution_manifest: PathBuf,
    bpf: PathBuf,
    fixture: PathBuf,
    out: PathBuf,
}

fn parse_loader_args(args: &[String]) -> Result<LoaderPaths, &'static str> {
    if args.len() != 12 {
        return Err("loader-hit arguments");
    }
    let mut values = BTreeMap::new();
    for pair in args.chunks_exact(2) {
        if !matches!(
            pair[0].as_str(),
            "--source-manifest"
                | "--build-evidence"
                | "--execution-manifest"
                | "--bpf"
                | "--fixture"
                | "--out"
        ) || values.insert(pair[0].as_str(), pair[1].as_str()).is_some()
        {
            return Err("loader-hit arguments");
        }
    }
    let path = |name| {
        values
            .get(name)
            .map(PathBuf::from)
            .ok_or("loader-hit arguments")
    };
    Ok(LoaderPaths {
        source_manifest: path("--source-manifest")?,
        build_evidence: path("--build-evidence")?,
        execution_manifest: path("--execution-manifest")?,
        bpf: path("--bpf")?,
        fixture: path("--fixture")?,
        out: path("--out")?,
    })
}

#[derive(Clone)]
struct LoaderMetadata {
    source_commit: String,
    bpf_sha256: String,
    runner_sha256: String,
    fixture_sha256: String,
    kernel_release: String,
    glibc_version: String,
    lane: String,
}

impl LoaderMetadata {
    fn record(
        &self,
        pass: bool,
        failure_category: &str,
    ) -> serde_json::Map<String, serde_json::Value> {
        let mut value = serde_json::Map::new();
        value.insert("schema_version".into(), 1.into());
        value.insert("source_commit".into(), self.source_commit.clone().into());
        value.insert("bpf_sha256".into(), self.bpf_sha256.clone().into());
        value.insert("runner_sha256".into(), self.runner_sha256.clone().into());
        value.insert("fixture_sha256".into(), self.fixture_sha256.clone().into());
        value.insert("kernel_release".into(), self.kernel_release.clone().into());
        value.insert("glibc_version".into(), self.glibc_version.clone().into());
        value.insert("lane".into(), self.lane.clone().into());
        value.insert("run_id".into(), format!("loader-{}", self.lane).into());
        value.insert("pass".into(), pass.into());
        value.insert("failure_category".into(), failure_category.into());
        value
    }
}

#[allow(clippy::type_complexity)]
fn validate_loader_provenance(
    paths: &LoaderPaths,
) -> Result<(LoaderMetadata, Vec<u8>, Vec<u8>, u64), &'static str> {
    if unsafe { libc::geteuid() } != 0 || std::env::consts::ARCH != "x86_64" {
        return Err("guest identity");
    }
    let source_bytes = read_regular(&paths.source_manifest, 4 * 1024 * 1024)?;
    let build_bytes = read_regular(&paths.build_evidence, 16 * 1024 * 1024)?;
    let execution_bytes = read_regular(&paths.execution_manifest, 1024 * 1024)?;
    let bpf_bytes = read_regular(&paths.bpf, 16 * 1024 * 1024)?;
    let fixture_bytes = read_regular(&paths.fixture, 64 * 1024 * 1024)?;
    let runner_bytes = read_regular(
        &std::env::current_exe().map_err(|_| "runner path")?,
        64 * 1024 * 1024,
    )?;
    let source: serde_json::Value =
        serde_json::from_slice(&source_bytes).map_err(|_| "source manifest")?;
    let execution: serde_json::Value =
        serde_json::from_slice(&execution_bytes).map_err(|_| "execution manifest")?;
    for (name, actual) in [
        ("source_manifest_sha256", sha256_hex(&source_bytes)),
        ("build_evidence_sha256", sha256_hex(&build_bytes)),
        ("bpf_sha256", sha256_hex(&bpf_bytes)),
        ("runner_sha256", sha256_hex(&runner_bytes)),
        ("fixture_sha256", sha256_hex(&fixture_bytes)),
    ] {
        if json_string(&execution, name)? != actual {
            return Err("execution manifest digest mismatch");
        }
    }
    if json_string(&source, "bpf_sha256")? != sha256_hex(&bpf_bytes) {
        return Err("source manifest BPF mismatch");
    }
    let source_commit = json_string(&source, "source_commit")?;
    if !valid_hex(source_commit, 40) || json_string(&execution, "source_commit")? != source_commit {
        return Err("source commit mismatch");
    }
    let kernel = kernel_release()?;
    let glibc = glibc_version()?;
    let lane = if kernel_matches(&kernel, "5.15") && glibc == "glibc 2.35" {
        "5.15"
    } else if kernel_matches(&kernel, "6.8") && glibc == "glibc 2.39" {
        "6.8"
    } else {
        return Err("guest kernel or glibc identity");
    };
    let hook = elf_symbol(&fixture_bytes, "spike_loader_negative_hook")
        .map_err(|_| "fixture ELF")?
        .ok_or("fixture symbol")?;
    Ok((
        LoaderMetadata {
            source_commit: source_commit.to_owned(),
            bpf_sha256: sha256_hex(&bpf_bytes),
            runner_sha256: sha256_hex(&runner_bytes),
            fixture_sha256: sha256_hex(&fixture_bytes),
            kernel_release: kernel,
            glibc_version: glibc,
            lane: lane.into(),
        },
        bpf_bytes,
        fixture_bytes,
        hook.file_offset.ok_or("fixture symbol file offset")?,
    ))
}

// ---------------------------------------------------------------------------
// loader-hit
// ---------------------------------------------------------------------------

enum FlowResult {
    /// Finite facts merged into the metadata record (§9: counts, enums and
    /// booleans only — never raw addresses, cookies, deltas, or context IDs).
    Done(serde_json::Map<String, serde_json::Value>),
    Runtime(&'static str),
}

fn run_loader_hit(paths: LoaderPaths) -> Result<bool, &'static str> {
    // SAFETY: a process-local restrictive umask has no memory-safety preconditions.
    unsafe { libc::umask(0o077) };
    create_private_dir(&paths.out).map_err(|_| "output directory")?;
    let mut environment =
        create_private_file(&paths.out.join("environment.txt")).map_err(|_| "environment file")?;
    let mut verifier_log =
        create_private_file(&paths.out.join("verifier.log")).map_err(|_| "verifier log")?;
    let mut verifier_results = create_private_file(&paths.out.join("verifier-results.jsonl"))
        .map_err(|_| "verifier results")?;
    let mut facts_file =
        create_private_file(&paths.out.join("loader-facts.jsonl")).map_err(|_| "facts file")?;
    let mut runner_status =
        create_private_file(&paths.out.join("runner-status.txt")).map_err(|_| "runner status")?;

    let (metadata, bpf_bytes, fixture_bytes, fixture_hook_offset) =
        validate_loader_provenance(&paths)?;
    writeln!(
        environment,
        "kernel_release={}\narch=x86_64\nglibc_version={}\nlane={}",
        metadata.kernel_release, metadata.glibc_version, metadata.lane
    )
    .map_err(|_| "environment write")?;

    let mut loader = aya::EbpfLoader::new();
    loader.verifier_log_level(aya::VerifierLogLevel::VERBOSE | aya::VerifierLogLevel::STATS);
    let mut ebpf = match loader.load(&bpf_bytes) {
        Ok(ebpf) => ebpf,
        Err(error) => {
            writeln!(
                verifier_log,
                "object=loader outcome=rejected\n{}",
                verifier_error_chain(&error)
            )
            .map_err(|_| "verifier write")?;
            writeln!(runner_status, "status=FAIL\nfailure_category=object_load")
                .map_err(|_| "runner status write")?;
            return Ok(false);
        }
    };
    {
        let result = (|| -> Result<(), Box<dyn Error>> {
            use aya::programs::UProbe;
            let program: &mut UProbe = ebpf
                .program_mut(LOADER_PROGRAM)
                .ok_or("program missing")?
                .try_into()?;
            program.load()?;
            Ok(())
        })();
        let accepted = result.is_ok();
        let mut value = metadata.record(accepted, if accepted { "none" } else { "verifier" });
        value.insert("program".into(), LOADER_PROGRAM.into());
        value.insert("load_attempted".into(), true.into());
        value.insert("accepted".into(), accepted.into());
        value.insert(
            "success_log_contract".into(),
            if accepted {
                "accepted_line_only"
            } else {
                "rejection_error_chain"
            }
            .into(),
        );
        write_json_line(&mut verifier_results, serde_json::Value::Object(value))?;
        if let Err(error) = result {
            writeln!(
                verifier_log,
                "program={LOADER_PROGRAM} outcome=rejected error_chain={}",
                verifier_error_chain(error.as_ref())
            )
            .map_err(|_| "verifier write")?;
            writeln!(runner_status, "status=FAIL\nfailure_category=verifier")
                .map_err(|_| "runner status write")?;
            return Ok(false);
        }
        writeln!(
            verifier_log,
            "program={LOADER_PROGRAM} outcome=accepted success_verifier_text=unavailable_aya_0_14"
        )
        .map_err(|_| "verifier write")?;
    }

    let mut ring = aya::maps::RingBuf::try_from(ebpf.take_map("DISCOVERY").ok_or("discovery map")?)
        .map_err(|_| "discovery ring")?;
    let counters =
        aya::maps::Array::<_, u64>::try_from(ebpf.take_map("COUNTERS").ok_or("counter map")?)
            .map_err(|_| "counter map")?;
    let mut start = aya::maps::HashMap::<_, common::StateKey, common::StartState>::try_from(
        ebpf.take_map("START").ok_or("start map")?,
    )
    .map_err(|_| "start map")?;

    let counters_before = read_counters(&counters)?;
    let mut registry = LoaderRegistry::new();

    // Flow 1 (positive): pre-exec loader attach on the fixture's PT_INTERP.
    let positive = run_startup_flow(
        &mut ebpf,
        &mut ring,
        &counters,
        counters_before,
        &mut start,
        &mut registry,
        &paths.fixture,
        &fixture_bytes,
    );
    let (positive_pass, positive_facts) = match positive {
        FlowResult::Done(mut facts) => {
            facts.insert("flow".into(), "loader_startup".into());
            let pass = facts.get("pass").and_then(serde_json::Value::as_bool) == Some(true);
            (pass, facts)
        }
        FlowResult::Runtime(reason) => {
            let mut facts = metadata.record(false, "runtime");
            facts.insert("flow".into(), "loader_startup".into());
            facts.insert("runtime_failure_reason".into(), reason.into());
            (false, facts)
        }
    };
    // The positive row carries the metadata envelope (schema, digests, lane)
    // plus its per-flow oracle outcome; an oracle failure still runs the
    // negative flow so every lane exports complete evidence.
    let positive_runtime = positive_facts
        .get("runtime_failure_reason")
        .and_then(serde_json::Value::as_str)
        .map(str::to_owned);
    let mut positive_row = metadata.record(
        positive_pass,
        if positive_runtime.is_some() {
            "runtime"
        } else if positive_pass {
            "none"
        } else {
            "oracle"
        },
    );
    for (key, value) in positive_facts {
        positive_row.insert(key, value);
    }
    write_json_line(&mut facts_file, serde_json::Value::Object(positive_row))?;
    if let Some(reason) = positive_runtime.as_deref() {
        writeln!(verifier_log, "runtime_failure=loader_startup:{reason}")
            .map_err(|_| "runtime failure write")?;
        writeln!(runner_status, "status=FAIL\nfailure_category=runtime")
            .map_err(|_| "runner status write")?;
        return Ok(false);
    }
    if !positive_pass {
        writeln!(verifier_log, "oracle_failure=loader_startup")
            .map_err(|_| "oracle failure write")?;
    }

    // Flow 2: §8.1 no-cookie negative on the fixture's single-hit hook.
    let negative = run_no_cookie_flow(
        &mut ebpf,
        &mut ring,
        &counters,
        &paths.fixture,
        fixture_hook_offset,
    );
    let (negative_pass, negative_facts) = match negative {
        FlowResult::Done(mut facts) => {
            facts.insert("flow".into(), "no_cookie_negative".into());
            let pass = facts.get("pass").and_then(serde_json::Value::as_bool) == Some(true);
            (pass, facts)
        }
        FlowResult::Runtime(reason) => {
            let mut facts = metadata.record(false, "runtime");
            facts.insert("flow".into(), "no_cookie_negative".into());
            facts.insert("runtime_failure_reason".into(), reason.into());
            (false, facts)
        }
    };
    let negative_runtime = negative_facts
        .get("runtime_failure_reason")
        .and_then(serde_json::Value::as_str)
        .map(str::to_owned);
    let mut negative_row = metadata.record(
        negative_pass,
        if negative_runtime.is_some() {
            "runtime"
        } else if negative_pass {
            "none"
        } else {
            "oracle"
        },
    );
    for (key, value) in negative_facts {
        negative_row.insert(key, value);
    }
    write_json_line(&mut facts_file, serde_json::Value::Object(negative_row))?;
    if let Some(reason) = negative_runtime.as_deref() {
        writeln!(verifier_log, "runtime_failure=no_cookie_negative:{reason}")
            .map_err(|_| "runtime failure write")?;
    } else if !negative_pass {
        writeln!(verifier_log, "oracle_failure=no_cookie_negative")
            .map_err(|_| "oracle failure write")?;
    }

    let start_empty = start.keys().next().is_none();
    let pass = positive_pass && negative_pass && start_empty;
    let final_category = if !pass && negative_runtime.is_some() {
        "runtime"
    } else if !pass {
        "oracle"
    } else {
        "none"
    };
    writeln!(
        runner_status,
        "status={}\nfailure_category={}",
        if pass { "PASS" } else { "FAIL" },
        final_category
    )
    .map_err(|_| "runner status write")?;
    Ok(pass)
}

fn counters_fact(values: &[u64]) -> serde_json::Value {
    serde_json::Value::Array(
        values
            .iter()
            .map(|value| serde_json::Value::from(*value))
            .collect(),
    )
}

fn diff_counters(before: &[u64; 6], after: &[u64; 6]) -> [u64; 6] {
    let mut delta = [0u64; 6];
    for (index, slot) in delta.iter_mut().enumerate() {
        *slot = after[index].saturating_sub(before[index]);
    }
    delta
}

#[allow(clippy::too_many_arguments)]
fn run_startup_flow(
    ebpf: &mut aya::Ebpf,
    ring: &mut aya::maps::RingBuf<aya::maps::MapData>,
    counters: &aya::maps::Array<aya::maps::MapData, u64>,
    counters_before: [u64; 6],
    start: &mut aya::maps::HashMap<aya::maps::MapData, common::StateKey, common::StartState>,
    registry: &mut LoaderRegistry,
    fixture: &Path,
    fixture_bytes: &[u8],
) -> FlowResult {
    // §7.3 pre-exec method, all while the child sits behind the fork barrier.
    let mut inner = || -> Result<FlowResult, &'static str> {
        let interp = elf_interp(fixture_bytes).map_err(|_| "fixture PT_INTERP")?;
        let loader_file = File::open(&interp).map_err(|_| "loader open")?;
        let mut loader_bytes = Vec::new();
        (&loader_file)
            .take(64 * 1024 * 1024)
            .read_to_end(&mut loader_bytes)
            .map_err(|_| "loader read")?;
        let loader_meta = loader_file.metadata().map_err(|_| "loader metadata")?;
        let hook = elf_symbol(&loader_bytes, "_dl_debug_state")
            .map_err(|_| "loader ELF")?
            .ok_or("loader symbol")?;
        // The attach offset must be file-backed; `_r_debug` may legitimately
        // sit in `.bss` (glibc), so only its vaddr is required for the delta.
        let hook_file_offset = hook.file_offset.ok_or("loader symbol file offset")?;
        let r_debug = elf_symbol(&loader_bytes, "_r_debug").map_err(|_| "loader ELF")?;
        let delta = match r_debug {
            Some(r_debug) => {
                let delta = (r_debug.vaddr as i64)
                    .checked_sub(hook.vaddr as i64)
                    .filter(|delta| delta.abs() <= (1i64 << 54))
                    .ok_or("loader delta")?;
                Some(delta)
            }
            None => None,
        };
        let loader_dev_major = u64::from(libc::major(loader_meta.dev()));
        let loader_dev_minor = u64::from(libc::minor(loader_meta.dev()));

        let mut child = fork_exec_child(fixture)?;
        // Prepared before link attachment.
        let context_id = registry
            .allocate(LoaderContext {
                generation: 0, // assigned by the registry
                loader_sha256: sha256_hex(&loader_bytes),
                loader_device: loader_meta.dev(),
                loader_inode: loader_meta.ino(),
                hook_vaddr: hook.vaddr,
                hook_file_offset,
                r_debug_vaddr: r_debug.map(|symbol| symbol.vaddr),
                delta,
            })
            .map_err(|_| "registry capacity")?;
        let cookie = common::cookie_encode(context_id, delta);
        let link = match attach_program(
            ebpf,
            hook_file_offset,
            &interp,
            child.pid as u32,
            Some(cookie),
        ) {
            Ok(link) => link,
            Err(error) => {
                let _ = registry.mark_tombstoned(context_id, false);
                let _ = write_release(&mut child);
                kill_and_reap(child.pid);
                return Ok(FlowResult::Runtime(error));
            }
        };
        registry
            .mark_attached(context_id)
            .map_err(|_| "registry phase")?;
        if let Err(error) = write_release(&mut child) {
            let _ = detach_program(ebpf, link);
            let _ = registry.mark_tombstoned(context_id, true);
            kill_and_reap(child.pid);
            return Ok(FlowResult::Runtime(error));
        }

        // The loader runs during exec: poll until the loader mapping exists and
        // at least two loader records arrived, then capture the bias while the
        // child still lives (the fixture blocks on stdin until this side closes).
        let deadline = Instant::now() + Duration::from_secs(10);
        let mut records = Vec::new();
        let mut bias: Option<u64> = None;
        loop {
            records.extend(drain_loader_records(ring).map_err(|_| "ring drain")?);
            if bias.is_none() && child_execed(child.pid, fixture) {
                if let Ok(path) = canonical_loader_path(child.pid, &interp) {
                    if let Ok(found) = loader_load_bias(
                        child.pid,
                        loader_dev_major,
                        loader_dev_minor,
                        loader_meta.ino(),
                        &path,
                    ) {
                        bias = Some(found);
                    }
                }
            }
            let hits = records
                .iter()
                .filter(|record| record.kind == KIND_LOADER)
                .count();
            if hits >= 2 && bias.is_some() {
                break;
            }
            if Instant::now() > deadline {
                let _ = detach_program(ebpf, link);
                let _ = registry.mark_tombstoned(context_id, true);
                kill_and_reap(child.pid);
                return Ok(FlowResult::Runtime("loader records timeout"));
            }
            std::thread::sleep(Duration::from_millis(2));
        }
        let bias = bias.unwrap_or_default();
        drop(child.release); // the fixture drains stdin to EOF and exits
        let status = match wait_pid(child.pid) {
            Ok(status) => status,
            Err(error) => {
                let _ = detach_program(ebpf, link);
                let _ = registry.mark_tombstoned(context_id, true);
                return Ok(FlowResult::Runtime(error));
            }
        };
        if !libc::WIFEXITED(status) || libc::WEXITSTATUS(status) != 0 {
            let _ = detach_program(ebpf, link);
            let _ = registry.mark_tombstoned(context_id, true);
            return Ok(FlowResult::Runtime("child wait"));
        }
        records.extend(drain_loader_records(ring).map_err(|_| "ring drain")?);
        let counters_after = read_counters(counters).map_err(|_| "counter read")?;
        if let Err(error) = detach_program(ebpf, link) {
            let _ = registry.mark_tombstoned(context_id, true);
            return Ok(FlowResult::Runtime(error));
        }
        registry
            .mark_tombstoned(context_id, true)
            .map_err(|_| "registry phase")?;

        let hits: Vec<&common::DiscoveryRecord> = records
            .iter()
            .filter(|record| record.kind == KIND_LOADER)
            .collect();
        let pid_matches = hits
            .iter()
            .all(|record| record.pid_tgid >> 32 == child.pid as u64);
        let r_states: Vec<u32> = hits.iter().map(|record| record.announced_count).collect();
        let formula_holds = hits
            .iter()
            .all(|record| record.table_ptr == bias.wrapping_add(hook.vaddr));
        let r_debug_vaddr = r_debug.map(|symbol| symbol.vaddr);
        let derived_debug_ok = delta.is_none_or(|delta| {
            r_debug_vaddr.is_some_and(|expected_vaddr| {
                let expected = bias.wrapping_add(expected_vaddr);
                hits.iter().all(|record| {
                    (record.table_ptr as i64)
                        .checked_add(delta)
                        .is_some_and(|derived| derived as u64 == expected)
                })
            })
        });
        let invalid_records = hits
            .iter()
            .filter(|record| record.status_flags & STATUS_CONTEXT_INVALID != 0)
            .count();
        let start_empty = start.keys().next().is_none();
        let counters_delta = diff_counters(&counters_before, &counters_after);
        let [
            ring_loss,
            state_failures,
            loader_hits,
            state_read_failures,
            cookie_zero_hits,
            func_ip_zero_hits,
        ] = counters_delta;
        let decodable = registry.decodable(context_id);

        // §9/§7.3: only counts, enums, booleans, digests — never raw addresses,
        // cookies, deltas, or context IDs.
        let mut facts = serde_json::Map::new();
        facts.insert("hits".into(), (hits.len() as u64).into());
        facts.insert(
            "r_states".into(),
            serde_json::Value::Array(
                r_states
                    .iter()
                    .map(|state| serde_json::Value::from(*state))
                    .collect(),
            ),
        );
        facts.insert("pid_matches".into(), pid_matches.into());
        facts.insert("formula_holds".into(), formula_holds.into());
        facts.insert("derived_debug_address_ok".into(), derived_debug_ok.into());
        facts.insert("invalid_records".into(), (invalid_records as u64).into());
        facts.insert("state_present_delta".into(), delta.is_some().into());
        facts.insert("ring_loss".into(), ring_loss.into());
        facts.insert("state_failures".into(), state_failures.into());
        facts.insert("loader_hits_counter".into(), loader_hits.into());
        facts.insert("state_read_failures".into(), state_read_failures.into());
        facts.insert("cookie_zero_hits".into(), cookie_zero_hits.into());
        facts.insert("func_ip_zero_hits".into(), func_ip_zero_hits.into());
        facts.insert("counters_before".into(), counters_fact(&counters_before));
        facts.insert("counters_after".into(), counters_fact(&counters_after));
        facts.insert("start_empty".into(), start_empty.into());
        facts.insert("registry_decodable_after_drain".into(), decodable.into());
        facts.insert("loader_sha256".into(), sha256_hex(&loader_bytes).into());
        let pass = hits.len() == 2
            && pid_matches
            && r_states == [RT_ADD, RT_CONSISTENT]
            && formula_holds
            && derived_debug_ok
            && invalid_records == 0
            && state_read_failures == 0
            && cookie_zero_hits == 0
            && func_ip_zero_hits == 0
            && ring_loss == 0
            && state_failures == 0
            && start_empty
            && decodable;
        facts.insert("pass".into(), pass.into());
        Ok(FlowResult::Done(facts))
    };
    match inner() {
        Ok(result) => result,
        Err(reason) => FlowResult::Runtime(reason),
    }
}

fn run_no_cookie_flow(
    ebpf: &mut aya::Ebpf,
    ring: &mut aya::maps::RingBuf<aya::maps::MapData>,
    counters: &aya::maps::Array<aya::maps::MapData, u64>,
    fixture: &Path,
    hook_offset: u64,
) -> FlowResult {
    let mut inner = || -> Result<FlowResult, &'static str> {
        let before = read_counters(counters).map_err(|_| "counter read")?;
        let mut child = fork_exec_child(fixture)?;
        let link = match attach_program(ebpf, hook_offset, fixture, child.pid as u32, None) {
            Ok(link) => link,
            Err(error) => {
                let _ = write_release(&mut child);
                kill_and_reap(child.pid);
                return Ok(FlowResult::Runtime(error));
            }
        };
        if let Err(error) = write_release(&mut child) {
            let _ = detach_program(ebpf, link);
            kill_and_reap(child.pid);
            return Ok(FlowResult::Runtime(error));
        }
        drop(child.release);
        let status = match wait_pid(child.pid) {
            Ok(status) => status,
            Err(error) => {
                let _ = detach_program(ebpf, link);
                return Ok(FlowResult::Runtime(error));
            }
        };
        if !libc::WIFEXITED(status) || libc::WEXITSTATUS(status) != 0 {
            let _ = detach_program(ebpf, link);
            return Ok(FlowResult::Runtime("child wait"));
        }
        let records = drain_loader_records(ring).map_err(|_| "ring drain")?;
        let after = read_counters(counters).map_err(|_| "counter read")?;
        if let Err(error) = detach_program(ebpf, link) {
            return Ok(FlowResult::Runtime(error));
        }
        let hits: Vec<&common::DiscoveryRecord> = records
            .iter()
            .filter(|record| record.kind == KIND_LOADER)
            .collect();
        let invalid: Vec<&common::DiscoveryRecord> = hits
            .iter()
            .copied()
            .filter(|record| record.status_flags & STATUS_CONTEXT_INVALID != 0)
            .collect();
        let exactly_one_invalid = invalid.len() == 1 && hits.len() == 1;
        let no_ip_op = invalid.iter().all(|record| record.table_ptr == 0);
        let no_state_op = invalid.iter().all(|record| record.announced_count == 0);
        let no_case_id = invalid.iter().all(|record| record.case_id == 0);
        let [
            ring_loss,
            state_failures,
            loader_hits,
            state_read_failures,
            cookie_zero_hits,
            func_ip_zero_hits,
        ] = diff_counters(&before, &after);

        let mut facts = serde_json::Map::new();
        facts.insert("hits".into(), (hits.len() as u64).into());
        facts.insert("invalid_records".into(), (invalid.len() as u64).into());
        facts.insert("exactly_one_invalid".into(), exactly_one_invalid.into());
        facts.insert("no_ip_operation".into(), no_ip_op.into());
        facts.insert("no_state_operation".into(), no_state_op.into());
        facts.insert("no_context_id_copied".into(), no_case_id.into());
        facts.insert("ring_loss".into(), ring_loss.into());
        facts.insert("state_failures".into(), state_failures.into());
        facts.insert("loader_hits_counter".into(), loader_hits.into());
        facts.insert("state_read_failures".into(), state_read_failures.into());
        facts.insert("cookie_zero_hits".into(), cookie_zero_hits.into());
        facts.insert("func_ip_zero_hits".into(), func_ip_zero_hits.into());
        let pass = exactly_one_invalid
            && no_ip_op
            && no_state_op
            && no_case_id
            && loader_hits == 1
            && cookie_zero_hits == 1
            && state_read_failures == 0
            && ring_loss == 0
            && state_failures == 0;
        facts.insert("pass".into(), pass.into());
        Ok(FlowResult::Done(facts))
    };
    match inner() {
        Ok(result) => result,
        Err(reason) => FlowResult::Runtime(reason),
    }
}

// ---------------------------------------------------------------------------
// STATS diagnostic (Task 2 form) and self-check
// ---------------------------------------------------------------------------

// ---------------------------------------------------------------------------
// Task 8: loader-protect — attach-first experiment (D3 decision input)
// ---------------------------------------------------------------------------
//
// With the owned child stopped at a `_dl_debug_state` hit for the new mapping
// (negative-timing loader), userspace attaches from the frozen A/B object
// bytes: the `function_list_entry`/`function_list_return` pair at
// `C_GetFunctionList` (the return record carries the 104 relocated table
// pointers), and — for the `exported` build — one pair per exported `C_*`
// symbol. A `--second-pause` variant re-arms the §5.2 owner and pauses again
// at a 3-nop marker inside `C_GetFunctionList` (the export return), attaching
// hidden-build table slots while stopped. The loader program provides both
// pauses; the A/B object bytes are read-only.

const AB_FUNCTION_LIST_KIND: u8 = 1; // mirrors the frozen A/B object's FUNCTION_LIST
const AB_COUNTER_ENTRIES: usize = 5;
const EXPORT_COOKIE: u64 = 200;
const PROVIDER_TABLE_POINTERS: usize = 104;
const PROTECT_ATTEMPTS: usize = 20;
const NOP_MARKER: [u8; 3] = [0x90, 0x90, 0x90];
const AB_PROGRAMS: [&str; 2] = ["function_list_entry", "function_list_return"];

/// §5.2 pause-owner protocol, copied into this crate (never shared source).
trait PauseOwnerMap {
    fn insert_armed(&mut self, key: &common::StateKey) -> Result<(), &'static str>;
    fn remove_owner(&mut self, key: &common::StateKey) -> Result<(), &'static str>;
    fn entry_count(&self) -> Result<u64, &'static str>;
}

impl PauseOwnerMap
    for aya::maps::HashMap<aya::maps::MapData, common::StateKey, common::StartState>
{
    fn insert_armed(&mut self, key: &common::StateKey) -> Result<(), &'static str> {
        self.insert(
            key,
            common::StartState {
                arg0: common::PAUSE_ARMED,
                arg1: 0,
            },
            common::BPF_NOEXIST_FLAG,
        )
        .map(|_| ())
        .map_err(|_| "start map insert")
    }

    fn remove_owner(&mut self, key: &common::StateKey) -> Result<(), &'static str> {
        self.remove(key).map(|_| ()).map_err(|_| "start map remove")
    }

    fn entry_count(&self) -> Result<u64, &'static str> {
        let mut count = 0u64;
        for key in self.keys() {
            let _ = key.map_err(|_| "start map read")?;
            count += 1;
        }
        Ok(count)
    }
}

/// Copy of the A/B runner's START-entry guard: the entry is removed on every
/// exit path; the guard never resumes the child itself.
struct PauseOwnerGuard {
    key: common::StateKey,
    armed: bool,
    closed: bool,
}

impl PauseOwnerGuard {
    fn new(key: common::StateKey) -> Self {
        Self {
            key,
            armed: true,
            closed: false,
        }
    }

    fn close<M: PauseOwnerMap>(&mut self, map: &mut M) -> Result<(), &'static str> {
        if !self.closed {
            map.remove_owner(&self.key)?;
            self.closed = true;
        }
        self.armed = false;
        Ok(())
    }

    fn disarm_for_cleanup<M: PauseOwnerMap>(&mut self, map: &mut M) {
        if self.armed && !self.closed {
            let _ = map.remove_owner(&self.key);
        }
        self.armed = false;
    }
}

/// Lowest (start - file offset) across the mappings of `path` in the child.
fn path_load_bias(pid: i32, path: &Path) -> Result<u64, &'static str> {
    let maps = std::fs::read_to_string(format!("/proc/{pid}/maps")).map_err(|_| "process maps")?;
    let suffix = format!(" {}", path.display());
    let mut best: Option<u64> = None;
    for line in maps.lines() {
        if !line.ends_with(&suffix) {
            continue;
        }
        let fields = line.split_whitespace().collect::<Vec<_>>();
        if fields.len() < 5 {
            continue;
        }
        let Some((start, _end)) = fields[0].split_once('-') else {
            continue;
        };
        let (Ok(start), Ok(file_offset)) = (
            u64::from_str_radix(start, 16),
            u64::from_str_radix(fields[2], 16),
        ) else {
            continue;
        };
        let bias = start
            .checked_sub(file_offset)
            .ok_or("loader mapping bias")?;
        best = Some(best.map_or(bias, |current: u64| current.min(bias)));
    }
    best.ok_or("provider mapping")
}

fn provider_mapped(pid: i32, path: &Path) -> bool {
    let Ok(maps) = std::fs::read_to_string(format!("/proc/{pid}/maps")) else {
        return false;
    };
    let suffix = format!(" {}", path.display());
    maps.lines().any(|line| line.ends_with(&suffix))
}

/// One `bpf_probe_read_user`-compatible bounded read of owned-child memory
/// (used only at the second pause, on the entry-probe argument chain).
fn read_child_memory(pid: i32, address: u64, length: usize) -> Result<Vec<u8>, &'static str> {
    if address == 0 {
        return Err("child memory address");
    }
    let mut buffer = vec![0u8; length];
    let local = libc::iovec {
        iov_base: buffer.as_mut_ptr().cast::<libc::c_void>(),
        iov_len: length,
    };
    let remote = libc::iovec {
        iov_base: usize::try_from(address).map_err(|_| "child memory address")?
            as *mut libc::c_void,
        iov_len: length,
    };
    // SAFETY: two initialized iovecs; the local buffer owns `length` bytes.
    let read = unsafe { libc::process_vm_readv(pid, &local, 1, &remote, 1, 0) };
    if read < 0 || read as usize != length {
        return Err("child memory read");
    }
    Ok(buffer)
}

/// `/proc/<pid>/stat` process state (after the comm field, which may contain
/// spaces and parentheses).
#[cfg(test)]
fn child_state(pid: i32) -> Option<char> {
    let stat = std::fs::read_to_string(format!("/proc/{pid}/stat")).ok()?;
    let after_comm = stat.rfind(')')?;
    let mut fields = stat[after_comm + 1..].split_whitespace();
    let state = fields.next()?;
    state.chars().next()
}

fn parse_task_state(stat: &str) -> Result<u8, &'static str> {
    let start = stat.rfind(") ").ok_or("stat comm delimiter")? + 2;
    let state = stat.as_bytes().get(start).copied().ok_or("stat state")?;
    state
        .is_ascii_alphabetic()
        .then_some(state)
        .ok_or("stat state")
}

fn task_states(pid: i32) -> Result<BTreeMap<u32, u8>, &'static str> {
    let mut tasks = BTreeMap::new();
    for entry in std::fs::read_dir(format!("/proc/{pid}/task")).map_err(|_| "task list")? {
        let entry = entry.map_err(|_| "task list")?;
        let tid = entry
            .file_name()
            .to_str()
            .and_then(|value| value.parse::<u32>().ok())
            .ok_or("task id")?;
        let stat = std::fs::read_to_string(entry.path().join("stat")).map_err(|_| "task stat")?;
        if tasks.insert(tid, parse_task_state(&stat)?).is_some() {
            return Err("task set");
        }
    }
    Ok(tasks)
}

#[derive(Clone, Copy, Debug, Default, PartialEq)]
struct StopSnapshot {
    elapsed_us: u64,
    count: u32,
    exact_expected_task_set: bool,
    all_tasks_stopped: bool,
    state_counts: [u32; 9],
}

fn stop_snapshot(pid: i32, expected: &BTreeMap<u32, u8>) -> Result<StopSnapshot, &'static str> {
    let actual = task_states(pid)?;
    let mut snapshot = StopSnapshot {
        elapsed_us: 0,
        count: u32::try_from(actual.len()).map_err(|_| "task count")?,
        exact_expected_task_set: actual.keys().eq(expected.keys()),
        all_tasks_stopped: !actual.is_empty() && actual.values().all(|state| *state == b'T'),
        state_counts: [0; 9],
    };
    for state in actual.values() {
        let bucket = b"RSDTtZXI"
            .iter()
            .position(|known| known == state)
            .unwrap_or(8);
        snapshot.state_counts[bucket] += 1;
    }
    Ok(snapshot)
}

const STOP_WAIT_CEILING_US: u64 = 100_000;

fn confirm(samples: &[StopSnapshot]) -> Option<(usize, usize)> {
    samples.windows(2).enumerate().find_map(|(index, pair)| {
        let [first, second] = pair else { return None };
        (first.exact_expected_task_set
            && first.all_tasks_stopped
            && second.exact_expected_task_set
            && second.all_tasks_stopped
            && second.elapsed_us.saturating_sub(first.elapsed_us) >= 1_000
            && second.elapsed_us <= STOP_WAIT_CEILING_US)
            .then_some((index, index + 1))
    })
}

fn monotonic_ns() -> Result<u64, &'static str> {
    let mut time = libc::timespec {
        tv_sec: 0,
        tv_nsec: 0,
    };
    // SAFETY: time points to writable storage for CLOCK_MONOTONIC.
    if unsafe { libc::clock_gettime(libc::CLOCK_MONOTONIC, &mut time) } != 0 {
        return Err("monotonic clock");
    }
    u64::try_from(time.tv_sec)
        .ok()
        .and_then(|seconds| seconds.checked_mul(1_000_000_000))
        .and_then(|seconds| {
            u64::try_from(time.tv_nsec)
                .ok()
                .and_then(|nanos| seconds.checked_add(nanos))
        })
        .ok_or("monotonic clock")
}

fn confirm_owned_stop(
    pid: i32,
    expected: &BTreeMap<u32, u8>,
    hook_ts_ns: u64,
) -> Result<Vec<StopSnapshot>, &'static str> {
    let deadline_ns = hook_ts_ns
        .checked_add(STOP_WAIT_CEILING_US * 1_000)
        .ok_or("deadline overflow")?;
    let mut samples = Vec::with_capacity(101);
    loop {
        if monotonic_ns()? > deadline_ns || samples.len() >= 101 {
            return Err("pause confirm timeout");
        }
        let mut snapshot = stop_snapshot(pid, expected)?;
        snapshot.elapsed_us = monotonic_ns()?
            .checked_sub(hook_ts_ns)
            .ok_or("clock reversal")?
            / 1_000;
        samples.push(snapshot);
        if confirm(&samples).is_some() {
            return Ok(samples);
        }
        std::thread::sleep(Duration::from_millis(1));
    }
}

struct ProviderPlan {
    bytes: Vec<u8>,
    sha256: String,
    /// `C_GetFunctionList` file offset (attach point of the export pair).
    c_gfl_offset: u64,
    /// vaddr of the 3-nop export-return marker inside `C_GetFunctionList`.
    nop_vaddr: u64,
    nop_offset: u64,
    /// Exported build only: `(name, file offset)` sorted by offset, excluding
    /// `C_GetFunctionList` itself (the export pair covers it).
    symbols: Vec<(String, u64)>,
}

/// Exported `C_*` functions of a shared object (dynsym, global, defined, code).
fn elf_exported_c_functions(bytes: &[u8]) -> Result<Vec<(String, u64, u64)>, &'static str> {
    use object::{Object as _, ObjectSegment as _, ObjectSymbol as _};
    let object = parse_elf(bytes)?;
    let segments: Vec<(u64, u64, u64)> = object
        .segments()
        .map(|segment| {
            let (file_start, file_size) = segment.file_range();
            (segment.address(), file_start, file_size)
        })
        .collect();
    let mut out = Vec::new();
    for symbol in object.dynamic_symbols() {
        if symbol.is_undefined() || !symbol.is_global() {
            continue;
        }
        let Ok(name) = symbol.name() else {
            continue;
        };
        if !name.starts_with("C_") || symbol.kind() != object::SymbolKind::Text {
            continue;
        }
        let vaddr = symbol.address();
        if vaddr == 0 {
            continue;
        }
        let Some(file_offset) = segments.iter().find_map(|&(start, file_start, file_size)| {
            let delta = vaddr.checked_sub(start)?;
            (delta < file_size).then(|| file_start + delta)
        }) else {
            continue;
        };
        out.push((name.to_owned(), file_offset, symbol.size()));
    }
    Ok(out)
}

/// File offset of the single 3-nop export-return marker inside
/// `C_GetFunctionList` (byte window [offset, offset + size)).
fn find_nop_marker(
    bytes: &[u8],
    function: &(String, u64, u64),
) -> Result<(u64, u64), &'static str> {
    let (_, file_offset, size) = function;
    let start = *file_offset as usize;
    let end = start
        .checked_add(*size as usize)
        .ok_or("nop marker bounds")?;
    let window = bytes.get(start..end).ok_or("nop marker bounds")?;
    let mut hits = Vec::new();
    for index in 0..window.len().saturating_sub(NOP_MARKER.len() - 1) {
        if window[index..index + NOP_MARKER.len()] == NOP_MARKER {
            hits.push(*file_offset + index as u64);
        }
    }
    if hits.len() != 1 {
        return Err("nop marker");
    }
    Ok((hits[0], hits[0]))
}

fn build_provider_plan(mode: &str, bytes: Vec<u8>) -> Result<ProviderPlan, &'static str> {
    let sha = sha256_hex(&bytes);
    let mut functions = elf_exported_c_functions(&bytes)?;
    let c_gfl = functions
        .iter()
        .find(|(name, _, _)| name == "C_GetFunctionList")
        .cloned()
        .ok_or("provider symbols")?;
    if mode == "hidden" && functions.len() != 1 {
        return Err("provider symbols");
    }
    let (nop_offset, _) = find_nop_marker(&bytes, &c_gfl)?;
    functions.retain(|(name, _, _)| name != "C_GetFunctionList");
    functions.sort_by_key(|(_, offset, _)| *offset);
    let mut symbols = Vec::new();
    for (name, offset, _) in functions {
        symbols.push((name, offset));
    }
    if mode == "exported" && symbols.len() != PROVIDER_TABLE_POINTERS {
        return Err("provider symbols");
    }
    if mode == "exported" && !symbols.iter().any(|(name, _)| name == "C_Initialize") {
        return Err("provider symbols");
    }
    // The nop marker's vaddr equals its file offset only when the text segment
    // maps identity; derive it from the symbol's own (vaddr - offset) shift.
    let vaddr_shift = c_gfl_vaddr(&bytes)?
        .checked_sub(c_gfl.1)
        .ok_or("nop marker")?;
    Ok(ProviderPlan {
        c_gfl_offset: c_gfl.1,
        nop_vaddr: nop_offset.checked_add(vaddr_shift).ok_or("nop marker")?,
        nop_offset,
        symbols,
        sha256: sha,
        bytes,
    })
}

fn c_gfl_vaddr(bytes: &[u8]) -> Result<u64, &'static str> {
    elf_symbol(bytes, "C_GetFunctionList")
        .map_err(|_| "provider ELF")?
        .map(|location| location.vaddr)
        .ok_or("provider symbols")
}

struct LoaderIdentity {
    interp: PathBuf,
    sha256: String,
    dev_major: u64,
    dev_minor: u64,
    inode: u64,
    hook_offset: u64,
    hook_vaddr: u64,
    r_debug_vaddr: u64,
    delta: i64,
}

fn signed_runtime_delta(target: u64, hook: u64) -> Result<i64, &'static str> {
    let delta = i128::from(target) - i128::from(hook);
    (delta.unsigned_abs() <= (1u128 << 54))
        .then(|| i64::try_from(delta).ok())
        .flatten()
        .ok_or("loader delta")
}

fn resolve_loader_identity(launcher_bytes: &[u8]) -> Result<LoaderIdentity, &'static str> {
    let interp = elf_interp(launcher_bytes).map_err(|_| "launcher ELF")?;
    let loader_file = File::open(&interp).map_err(|_| "loader open")?;
    let mut loader_bytes = Vec::new();
    (&loader_file)
        .take(64 * 1024 * 1024)
        .read_to_end(&mut loader_bytes)
        .map_err(|_| "loader read")?;
    let loader_meta = loader_file.metadata().map_err(|_| "loader metadata")?;
    let hook = elf_symbol(&loader_bytes, "_dl_debug_state")
        .map_err(|_| "loader ELF")?
        .ok_or("loader symbol")?;
    let hook_offset = hook.file_offset.ok_or("loader symbol file offset")?;
    let r_debug = elf_symbol(&loader_bytes, "_r_debug")
        .map_err(|_| "loader ELF")?
        .ok_or("loader symbol")?;
    let delta = signed_runtime_delta(r_debug.vaddr, hook.vaddr)?;
    Ok(LoaderIdentity {
        dev_major: u64::from(libc::major(loader_meta.dev())),
        dev_minor: u64::from(libc::minor(loader_meta.dev())),
        inode: loader_meta.ino(),
        sha256: sha256_hex(&loader_bytes),
        interp,
        hook_offset,
        hook_vaddr: hook.vaddr,
        r_debug_vaddr: r_debug.vaddr,
        delta,
    })
}

struct PidfdChild {
    pid: i32,
    original_pidfd: OwnedFd,
    may_be_stopped: bool,
    reaped: bool,
    resume_attempts: u64,
}

impl PidfdChild {
    fn open(pid: i32) -> io::Result<Self> {
        // SAFETY: pidfd_open takes the owned child's numeric pid and scalar flags.
        let fd = unsafe { libc::syscall(libc::SYS_pidfd_open, pid, 0) } as i32;
        if fd < 0 {
            return Err(io::Error::last_os_error());
        }
        Ok(Self {
            pid,
            // SAFETY: the successful syscall returned a uniquely owned descriptor.
            original_pidfd: unsafe { OwnedFd::from_raw_fd(fd) },
            may_be_stopped: false,
            reaped: false,
            resume_attempts: 0,
        })
    }

    fn pid(&self) -> i32 {
        self.pid
    }

    fn send(&self, signal: i32) -> io::Result<()> {
        // SAFETY: the pidfd is retained by this guard; siginfo is null and flags are zero.
        let rc = unsafe {
            libc::syscall(
                libc::SYS_pidfd_send_signal,
                self.original_pidfd.as_raw_fd(),
                signal,
                std::ptr::null::<libc::siginfo_t>(),
                0,
            )
        };
        if rc == 0 {
            Ok(())
        } else {
            Err(io::Error::last_os_error())
        }
    }

    fn mark_stopped(&mut self) {
        self.may_be_stopped = true;
    }

    fn resume_owned_stop(&mut self) -> io::Result<()> {
        if !self.may_be_stopped {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "child has no owned stop",
            ));
        }
        self.resume_attempts += 1;
        self.send(libc::SIGCONT)?;
        self.may_be_stopped = false;
        Ok(())
    }

    fn mark_reaped(&mut self) {
        self.reaped = true;
        self.may_be_stopped = false;
    }

    /// Returns whether this call had to signal the child.
    fn terminate(&mut self) -> io::Result<bool> {
        if self.reaped {
            return Ok(false);
        }
        if self.may_be_stopped {
            self.resume_attempts += 1;
            self.send(libc::SIGCONT)?;
            self.may_be_stopped = false;
        }
        self.send(libc::SIGKILL)?;
        wait_pid(self.pid).map_err(io::Error::other)?;
        self.mark_reaped();
        Ok(true)
    }
}

impl Drop for PidfdChild {
    fn drop(&mut self) {
        let _ = self.terminate();
    }
}

struct CapturedChild {
    lifecycle: PidfdChild,
    release: OwnedFd,
    stderr_fd: OwnedFd,
}

impl CapturedChild {
    fn pid(&self) -> i32 {
        self.lifecycle.pid()
    }
}

/// Fork barrier child whose stderr is captured through a pipe; the child
/// execs the launcher with the provider path as its only argument after the
/// first release byte, and the launcher gates its `dlopen` on a second byte.
fn fork_provider_child(launcher: &Path, provider: &Path) -> Result<CapturedChild, &'static str> {
    let (ready_read, ready_write) =
        pipe_pair(libc::O_CLOEXEC).map_err(|_| "provider child pipes")?;
    let (release_read, release_write) = pipe_pair(0).map_err(|_| "provider child pipes")?;
    let (stderr_read, stderr_write) = pipe_pair(0).map_err(|_| "provider child pipes")?;
    let launcher_c =
        CString::new(launcher.as_os_str().as_encoded_bytes()).map_err(|_| "provider path")?;
    let provider_c =
        CString::new(provider.as_os_str().as_encoded_bytes()).map_err(|_| "provider path")?;
    let arg0 = CString::new("slice1b2-provider-launcher").map_err(|_| "provider path")?;
    // SAFETY: fork duplicates this single-threaded process; the child runs only
    // async-signal-safe libc calls before exec and _exit, and never returns.
    let pid = unsafe { libc::fork() };
    if pid < 0 {
        return Err("fork");
    }
    if pid == 0 {
        unsafe {
            libc::close(ready_read.as_raw_fd());
            libc::close(release_write.as_raw_fd());
            libc::dup2(release_read.as_raw_fd(), 0);
            libc::close(release_read.as_raw_fd());
            libc::dup2(stderr_write.as_raw_fd(), 2);
            libc::close(stderr_write.as_raw_fd());
            let byte = b'R';
            libc::write(ready_write.as_raw_fd(), &byte as *const u8 as *const _, 1);
            let mut gate = 0u8;
            loop {
                let read = libc::read(0, &mut gate as *mut u8 as *mut _, 1);
                if read == 1 {
                    break;
                }
                if read < 0 && io::Error::last_os_error().kind() == io::ErrorKind::Interrupted {
                    continue;
                }
                libc::_exit(126);
            }
            let argv: [*const libc::c_char; 3] =
                [arg0.as_ptr(), provider_c.as_ptr(), std::ptr::null()];
            libc::execv(launcher_c.as_ptr(), argv.as_ptr());
            libc::_exit(127);
        }
    }
    let lifecycle = match PidfdChild::open(pid) {
        Ok(lifecycle) => lifecycle,
        Err(_) => {
            let _ = unsafe { libc::kill(pid, libc::SIGKILL) };
            let _ = wait_pid(pid);
            return Err("pidfd open");
        }
    };
    drop(ready_write);
    drop(release_read);
    drop(stderr_write);
    let mut byte = 0u8;
    let deadline = Instant::now() + Duration::from_secs(5);
    loop {
        if Instant::now() > deadline {
            let _ = unsafe { libc::kill(pid, libc::SIGKILL) };
            let _ = wait_pid(pid);
            return Err("fixture ready timeout");
        }
        // SAFETY: one-byte buffer, owned fd.
        let read = unsafe {
            libc::read(
                ready_read.as_raw_fd(),
                &mut byte as *mut u8 as *const _ as *mut _,
                1,
            )
        };
        if read == 1 && byte == b'R' {
            break;
        }
        if read < 0 && io::Error::last_os_error().kind() == io::ErrorKind::Interrupted {
            continue;
        }
        let _ = unsafe { libc::kill(pid, libc::SIGKILL) };
        let _ = wait_pid(pid);
        return Err("pipe byte");
    }
    drop(ready_read);
    // SAFETY: clearing O_NONBLOCK on an owned pipe descriptor.
    unsafe {
        let flags = libc::fcntl(stderr_read.as_raw_fd(), libc::F_GETFL);
        if flags >= 0 {
            libc::fcntl(
                stderr_read.as_raw_fd(),
                libc::F_SETFL,
                flags | libc::O_NONBLOCK,
            );
        }
    }
    Ok(CapturedChild {
        lifecycle,
        release: release_write,
        stderr_fd: stderr_read,
    })
}

fn read_stderr_chunk(fd: i32, buffer: &mut String) -> Result<bool, &'static str> {
    let mut chunk = [0u8; 4096];
    // SAFETY: chunk-sized buffer, owned fd.
    let read = unsafe { libc::read(fd, chunk.as_mut_ptr() as *mut _, chunk.len()) };
    if read > 0 {
        buffer.push_str(&String::from_utf8_lossy(&chunk[..read as usize]));
        return Ok(false);
    }
    if read == 0 {
        return Ok(true);
    }
    match io::Error::last_os_error().kind() {
        io::ErrorKind::WouldBlock => Ok(false),
        io::ErrorKind::Interrupted => Ok(false),
        _ => Err("pipe read"),
    }
}

fn read_ab_counters(
    counters: &aya::maps::Array<aya::maps::MapData, u64>,
) -> Result<[u64; AB_COUNTER_ENTRIES], &'static str> {
    let mut values = [0u64; AB_COUNTER_ENTRIES];
    for (index, value) in values.iter_mut().enumerate() {
        *value = counters
            .get(&(index as u32), 0)
            .map_err(|_| "counter read")?;
    }
    Ok(values)
}

fn purge_start_entries(
    map: &mut aya::maps::HashMap<aya::maps::MapData, common::StateKey, common::StartState>,
    pid: i32,
) -> u64 {
    let mut stale = Vec::new();
    for key in map.keys().flatten() {
        if key.pid_tgid >> 32 == pid as u64 {
            stale.push(key);
        }
    }
    let removed = stale.len() as u64;
    for key in stale {
        let _ = map.remove(&key);
    }
    removed
}

#[allow(clippy::too_many_arguments)]
fn run_protect_attempt(
    metadata: &LoaderMetadata,
    mode: &str,
    second_pause: bool,
    launcher: &Path,
    provider_path: &Path,
    plan: &ProviderPlan,
    loader_identity: &LoaderIdentity,
    loader_ebpf: &mut aya::Ebpf,
    loader_ring: &mut aya::maps::RingBuf<aya::maps::MapData>,
    loader_counters: &aya::maps::Array<aya::maps::MapData, u64>,
    loader_start: &mut aya::maps::HashMap<aya::maps::MapData, common::StateKey, common::StartState>,
    ab_ebpf: &mut aya::Ebpf,
    ab_ring: &mut aya::maps::RingBuf<aya::maps::MapData>,
    ab_counters: &aya::maps::Array<aya::maps::MapData, u64>,
    ab_start: &mut aya::maps::HashMap<aya::maps::MapData, common::StateKey, common::StartState>,
    registry: &mut LoaderRegistry,
    attempt: usize,
) -> serde_json::Map<String, serde_json::Value> {
    let loader_before = read_counters(loader_counters).unwrap_or([0u64; 6]);
    let ab_before = read_ab_counters(ab_counters).unwrap_or([0u64; AB_COUNTER_ENTRIES]);
    let mut child: Option<CapturedChild> = None;
    let mut child_pid: i32 = 0;
    let mut loader_links: Vec<aya::programs::uprobe::UProbeLinkId> = Vec::new();
    let mut ab_links: Vec<(&'static str, aya::programs::uprobe::UProbeLinkId)> = Vec::new();
    let mut owners: Vec<PauseOwnerGuard> = Vec::new();
    let mut registry_ids: Vec<u16> = Vec::new();
    let mut stderr_text = String::new();
    let mut ab_records: Vec<common::DiscoveryRecord> = Vec::new();
    let mut loader_records: Vec<common::DiscoveryRecord> = Vec::new();
    let mut attach_gap_us: Option<u64> = None;
    let mut hit_to_attach_us: Option<u64> = None;
    let mut pause1_confirmed = false;
    let mut pause1_samples = 0u64;
    let mut pause1_confirmation_gap_us: Option<u64> = None;
    let mut pause1_r_state: Option<u32> = None;
    let mut provider_mapped_at_pause = false;
    let mut symbol_pairs: Option<u64> = None;
    let mut c_init_cookie: Option<u64> = None;
    let mut pause2_confirmed: Option<bool> = None;
    let mut pause2_samples: Option<u64> = None;
    let mut pause2_confirmation_gap_us: Option<u64> = None;
    let mut pause2_r_state: Option<u32> = None;
    let mut slot_pairs: Option<u64> = None;
    let mut slot_attach_failures = 0u64;
    let mut export_to_slot_attach_us: Option<u64> = None;
    let mut child_exit_zero = false;

    let flow = (|| -> Result<(), &'static str> {
        let captured = fork_provider_child(launcher, provider_path)?;
        child_pid = captured.pid();
        let pid = captured.pid();
        child = Some(captured);
        let context_id = registry
            .allocate(LoaderContext {
                generation: 0,
                loader_sha256: loader_identity.sha256.clone(),
                loader_device: 0,
                loader_inode: loader_identity.inode,
                hook_vaddr: loader_identity.hook_vaddr,
                hook_file_offset: loader_identity.hook_offset,
                r_debug_vaddr: Some(loader_identity.r_debug_vaddr),
                delta: Some(loader_identity.delta),
            })
            .map_err(|_| "registry capacity")?;
        registry_ids.push(context_id);
        let cookie1 = common::cookie_encode(context_id, Some(loader_identity.delta));
        let link = attach_program(
            loader_ebpf,
            loader_identity.hook_offset,
            &loader_identity.interp,
            pid as u32,
            Some(cookie1),
        )?;
        loader_links.push(link);
        registry
            .mark_attached(context_id)
            .map_err(|_| "registry phase")?;
        write_gate(&child.as_ref().ok_or("provider child pipes")?.release)?;

        // Startup loader hits ([RT_ADD, RT_CONSISTENT] on the exec) drain with
        // no armed owner, so nothing pauses before the dlopen release.
        let deadline = Instant::now() + Duration::from_secs(10);
        loop {
            loader_records.extend(drain_loader_records(loader_ring)?);
            let hits = loader_records
                .iter()
                .filter(|record| record.kind == KIND_LOADER)
                .count();
            if hits >= 2 {
                break;
            }
            if Instant::now() > deadline {
                return Err("startup records timeout");
            }
            std::thread::sleep(Duration::from_millis(2));
        }
        let expected_tasks = task_states(pid)?;

        // Arm the first owned pause, then release the dlopen gate.
        let owner_key = common::StateKey {
            pid_tgid: (pid as u64) << 32,
            attach_cookie: u64::MAX,
        };
        loader_start.insert_armed(&owner_key)?;
        owners.push(PauseOwnerGuard::new(owner_key));
        write_gate(&child.as_ref().ok_or("provider child pipes")?.release)?;

        // Pause 1: the provider's RT_ADD loader hit wins the CAS and
        // self-stops inside the hook.
        let t_hit;
        let pause1_record;
        let deadline = Instant::now() + Duration::from_secs(5);
        loop {
            let before = loader_records.len();
            loader_records.extend(drain_loader_records(loader_ring)?);
            let fresh = loader_records
                .iter()
                .skip(before)
                .find(|record| record.kind == KIND_LOADER && record.pid_tgid >> 32 == pid as u64)
                .copied();
            if let Some(record) = fresh {
                t_hit = Instant::now();
                pause1_record = record;
                break;
            }
            if Instant::now() > deadline {
                return Err("pause record timeout");
            }
            std::thread::sleep(Duration::from_millis(1));
        }
        let samples = confirm_owned_stop(pid, &expected_tasks, pause1_record.hook_ts_ns)?;
        pause1_samples = samples.len() as u64;
        let (first, second) = confirm(&samples).ok_or("pause confirm timeout")?;
        pause1_confirmation_gap_us = Some(
            samples[second]
                .elapsed_us
                .saturating_sub(samples[first].elapsed_us),
        );
        child
            .as_mut()
            .ok_or("provider child pipes")?
            .lifecycle
            .mark_stopped();
        pause1_confirmed = true;
        let t_stop = Instant::now();
        provider_mapped_at_pause = provider_mapped(pid, provider_path);
        if !provider_mapped_at_pause {
            return Err("provider mapping");
        }
        let provider_bias = path_load_bias(pid, provider_path)?;
        let loader_path = canonical_loader_path(pid, &loader_identity.interp)?;
        let ldso_bias = loader_load_bias(
            pid,
            loader_identity.dev_major,
            loader_identity.dev_minor,
            loader_identity.inode,
            &loader_path,
        )?;
        if let Some(record) = loader_records
            .iter()
            .rev()
            .find(|record| record.kind == KIND_LOADER && record.pid_tgid >> 32 == pid as u64)
        {
            pause1_r_state = Some(record.announced_count);
        }

        // Attach phase while stopped: the loader hit buys this gap.
        attach_probe_pair(
            ab_ebpf,
            &mut ab_links,
            provider_path,
            pid,
            plan.c_gfl_offset,
            EXPORT_COOKIE,
        )?;
        if mode == "exported" {
            for (index, (name, offset)) in plan.symbols.iter().enumerate() {
                let cookie = index as u64 + 1;
                if name == "C_Initialize" {
                    c_init_cookie = Some(cookie);
                }
                attach_probe_pair(ab_ebpf, &mut ab_links, provider_path, pid, *offset, cookie)?;
            }
            c_init_cookie.ok_or("provider symbols")?;
            symbol_pairs = Some(plan.symbols.len() as u64);
        }
        if second_pause {
            let delta2 = signed_runtime_delta(
                ldso_bias
                    .checked_add(loader_identity.r_debug_vaddr)
                    .ok_or("loader delta")?,
                provider_bias
                    .checked_add(plan.nop_vaddr)
                    .ok_or("loader delta")?,
            )?;
            let context2 = registry
                .allocate(LoaderContext {
                    generation: 0,
                    loader_sha256: loader_identity.sha256.clone(),
                    loader_device: 0,
                    loader_inode: loader_identity.inode,
                    hook_vaddr: plan.nop_vaddr,
                    hook_file_offset: plan.nop_offset,
                    r_debug_vaddr: Some(loader_identity.r_debug_vaddr),
                    delta: Some(delta2),
                })
                .map_err(|_| "registry capacity")?;
            registry_ids.push(context2);
            let cookie2 = common::cookie_encode(context2, Some(delta2));
            let nop_link = attach_program(
                loader_ebpf,
                plan.nop_offset,
                provider_path,
                pid as u32,
                Some(cookie2),
            )?;
            loader_links.push(nop_link);
            registry
                .mark_attached(context2)
                .map_err(|_| "registry phase")?;
            // Detach the ld.so link so only the export-return marker can win
            // the second CAS (post-relocation loader hits stay silent).
            let ldso_link = loader_links.remove(0);
            detach_program(loader_ebpf, ldso_link)?;
        }
        let t_attach_done = Instant::now();
        attach_gap_us = Some((t_attach_done - t_stop).as_micros() as u64);
        hit_to_attach_us = Some((t_attach_done - t_hit).as_micros() as u64);

        // The one-pause case resumes before removing its owner. The two-pause
        // experiment must replace REQUESTED with a fresh ARMED owner while the
        // child is still stopped, otherwise the marker can race the re-arm.
        if second_pause {
            if let Some(owner) = owners.first_mut() {
                owner.close(loader_start)?;
            }
            loader_start.insert_armed(&owner_key)?;
            owners.push(PauseOwnerGuard::new(owner_key));
        }
        child
            .as_mut()
            .ok_or("provider child pipes")?
            .lifecycle
            .resume_owned_stop()
            .map_err(|_| "child release")?;
        if !second_pause {
            if let Some(owner) = owners.first_mut() {
                owner.close(loader_start)?;
            }
        }

        if second_pause {
            pause2_confirmed = Some(false);
            let deadline = Instant::now() + Duration::from_secs(5);
            let t_export_seen;
            let pause2_record;
            loop {
                let before = loader_records.len();
                loader_records.extend(drain_loader_records(loader_ring)?);
                let fresh = loader_records
                    .iter()
                    .skip(before)
                    .find(|record| record.kind == KIND_LOADER)
                    .copied();
                if let Some(record) = fresh {
                    t_export_seen = Instant::now();
                    pause2_record = record;
                    break;
                }
                if Instant::now() > deadline {
                    return Err("second pause record");
                }
                std::thread::sleep(Duration::from_millis(1));
            }
            let samples = confirm_owned_stop(pid, &expected_tasks, pause2_record.hook_ts_ns)?;
            pause2_samples = Some(samples.len() as u64);
            let (first, second) = confirm(&samples).ok_or("pause confirm timeout")?;
            pause2_confirmation_gap_us = Some(
                samples[second]
                    .elapsed_us
                    .saturating_sub(samples[first].elapsed_us),
            );
            child
                .as_mut()
                .ok_or("provider child pipes")?
                .lifecycle
                .mark_stopped();
            pause2_confirmed = Some(true);
            if let Some(record) = loader_records
                .iter()
                .rev()
                .find(|record| record.kind == KIND_LOADER)
            {
                pause2_r_state = Some(record.announced_count);
            }
            if mode == "hidden" {
                // Slot addresses derive from the entry probe's stored argument:
                // arg0 -> table pointer -> the 104 relocated slot pointers.
                let arg_key = common::StateKey {
                    pid_tgid: (pid as u64) << 32,
                    attach_cookie: EXPORT_COOKIE,
                };
                let state = ab_start.get(&arg_key, 0).map_err(|_| "start map read")?;
                let table_ptr = u64::from_le_bytes(
                    read_child_memory(pid, state.arg0, 8)?[..8]
                        .try_into()
                        .map_err(|_| "child memory read")?,
                );
                let table_bytes =
                    read_child_memory(pid, table_ptr + 8, PROVIDER_TABLE_POINTERS * 8)?;
                for index in 0..PROVIDER_TABLE_POINTERS {
                    let pointer = u64::from_le_bytes(
                        table_bytes[index * 8..index * 8 + 8]
                            .try_into()
                            .map_err(|_| "child memory read")?,
                    );
                    let vaddr = pointer
                        .checked_sub(provider_bias)
                        .ok_or("child memory address")?;
                    let offset = vaddr_to_file_offset(&plan.bytes, vaddr).ok_or("slot offset")?;
                    let cookie = index as u64 + 1; // slot 0 = C_Initialize
                    attach_probe_pair(ab_ebpf, &mut ab_links, provider_path, pid, offset, cookie)?;
                    if index == 0 {
                        c_init_cookie = Some(cookie);
                    }
                }
                slot_pairs = Some(PROVIDER_TABLE_POINTERS as u64);
                export_to_slot_attach_us =
                    Some((Instant::now() - t_export_seen).as_micros() as u64);
            }
            child
                .as_mut()
                .ok_or("provider child pipes")?
                .lifecycle
                .resume_owned_stop()
                .map_err(|_| "child release")?;
            if let Some(mut owner) = owners.pop() {
                owner.close(loader_start)?;
            }
        }

        // Observe: drain both rings and stderr until the launcher exits. The
        // hidden build without a second pause attaches slot pairs inline, as
        // soon as the first export-return record is observed (the racing
        // window the experiment measures).
        let mut slot_pending = mode == "hidden" && !second_pause;
        let mut exited = false;
        let mut exit_status = 0;
        let mut stderr_eof = false;
        let deadline = Instant::now() + Duration::from_secs(15);
        loop {
            let before_ab = ab_records.len();
            let before_loader = loader_records.len();
            ab_records.extend(drain_loader_records(ab_ring)?);
            loader_records.extend(drain_loader_records(loader_ring)?);
            if !stderr_eof {
                stderr_eof = read_stderr_chunk(
                    child
                        .as_ref()
                        .map(|captured| captured.stderr_fd.as_raw_fd())
                        .ok_or("provider child pipes")?,
                    &mut stderr_text,
                )?;
            }
            if slot_pending {
                let export = ab_records
                    .iter()
                    .find(|record| {
                        record.kind == AB_FUNCTION_LIST_KIND
                            && record.case_id == EXPORT_COOKIE as u8
                    })
                    .copied();
                if let Some(record) = export {
                    let t_seen = Instant::now();
                    let mut attached = 0u64;
                    for index in 0..PROVIDER_TABLE_POINTERS {
                        let pointer = record.pointers[index];
                        let vaddr = pointer
                            .checked_sub(provider_bias)
                            .ok_or("child memory address")?;
                        let offset =
                            vaddr_to_file_offset(&plan.bytes, vaddr).ok_or("slot offset")?;
                        let cookie = index as u64 + 1;
                        if attach_probe_pair(
                            ab_ebpf,
                            &mut ab_links,
                            provider_path,
                            pid,
                            offset,
                            cookie,
                        )
                        .is_err()
                        {
                            slot_attach_failures += 1;
                            break;
                        }
                        attached += 1;
                        if index == 0 {
                            c_init_cookie = Some(cookie);
                        }
                    }
                    slot_pairs = Some(attached);
                    export_to_slot_attach_us = Some((Instant::now() - t_seen).as_micros() as u64);
                    slot_pending = false;
                }
            }
            if !exited {
                let mut status = 0;
                // SAFETY: status is an initialized int for the owned child.
                let waited = unsafe { libc::waitpid(pid, &mut status, libc::WNOHANG) };
                if waited == pid {
                    exited = true;
                    exit_status = status;
                    child
                        .as_mut()
                        .ok_or("provider child pipes")?
                        .lifecycle
                        .mark_reaped();
                }
            }
            let quiet = ab_records.len() == before_ab && loader_records.len() == before_loader;
            if exited && quiet && stderr_eof {
                break;
            }
            if Instant::now() > deadline {
                break;
            }
            std::thread::sleep(Duration::from_millis(1));
        }
        child_exit_zero = libc::WIFEXITED(exit_status) && libc::WEXITSTATUS(exit_status) == 0;
        if !exited {
            return Err("child wait");
        }
        ab_records.extend(drain_loader_records(ab_ring)?);
        loader_records.extend(drain_loader_records(loader_ring)?);
        if let Some(captured) = child.as_ref() {
            let _ = read_stderr_chunk(captured.stderr_fd.as_raw_fd(), &mut stderr_text);
        }
        Ok(())
    })();

    // Cleanup on every path: disarm owners, resume, detach every link, purge
    // stale START entries, reap the child.
    for mut owner in owners.drain(..) {
        owner.disarm_for_cleanup(loader_start);
    }
    let mut detach_failures = 0u64;
    for link in loader_links.drain(..) {
        if detach_program(loader_ebpf, link).is_err() {
            detach_failures += 1;
        }
    }
    for (program_name, link) in ab_links.drain(..) {
        if detach_named(ab_ebpf, program_name, link).is_err() {
            detach_failures += 1;
        }
    }
    let mut resume_attempts = 0u64;
    let mut resume_via_original_pidfd = child_pid == 0;
    if let Some(mut captured) = child.take() {
        if captured.lifecycle.terminate().is_err() {
            detach_failures += 1;
        }
        resume_attempts = captured.lifecycle.resume_attempts;
        resume_via_original_pidfd = true;
    }
    for id in registry_ids {
        let _ = registry.mark_tombstoned(id, true);
    }
    let _ = purge_start_entries(loader_start, child_pid);
    let _ = purge_start_entries(ab_start, child_pid);
    let loader_start_entries = loader_start.entry_count().unwrap_or(u64::MAX);
    let ab_start_entries = ab_start.entry_count().unwrap_or(u64::MAX);
    let loader_after = read_counters(loader_counters).unwrap_or([0u64; 6]);
    let ab_after = read_ab_counters(ab_counters).unwrap_or([0u64; AB_COUNTER_ENTRIES]);

    // Facts (§9: counts, enums, booleans, timings — never raw addresses,
    // cookies, deltas, or context IDs).
    let mut facts = serde_json::Map::new();
    facts.insert("flow".into(), "protect".into());
    facts.insert("mode".into(), mode.into());
    facts.insert("second_pause".into(), second_pause.into());
    facts.insert("attempt".into(), (attempt as u64).into());
    let startup_r_states: Vec<serde_json::Value> = loader_records
        .iter()
        .filter(|record| record.kind == KIND_LOADER)
        .take(2)
        .map(|record| serde_json::Value::from(record.announced_count))
        .collect();
    facts.insert(
        "startup_r_states".into(),
        serde_json::Value::Array(startup_r_states),
    );
    facts.insert("pause1_confirmed".into(), pause1_confirmed.into());
    facts.insert("pause1_samples".into(), pause1_samples.into());
    facts.insert(
        "pause1_confirmation_gap_us".into(),
        pause1_confirmation_gap_us.map_or(serde_json::Value::Null, |value| value.into()),
    );
    facts.insert(
        "pause1_r_state".into(),
        pause1_r_state.map_or(serde_json::Value::Null, |state| state.into()),
    );
    facts.insert(
        "provider_mapped_at_pause".into(),
        provider_mapped_at_pause.into(),
    );
    facts.insert(
        "attach_gap_us".into(),
        attach_gap_us.map_or(serde_json::Value::Null, |value| value.into()),
    );
    facts.insert(
        "hit_to_attach_us".into(),
        hit_to_attach_us.map_or(serde_json::Value::Null, |value| value.into()),
    );
    facts.insert(
        "symbol_pairs".into(),
        symbol_pairs.map_or(serde_json::Value::Null, |value| value.into()),
    );
    facts.insert(
        "pause2_confirmed".into(),
        pause2_confirmed.map_or(serde_json::Value::Null, |value| value.into()),
    );
    facts.insert(
        "pause2_samples".into(),
        pause2_samples.map_or(serde_json::Value::Null, |value| value.into()),
    );
    facts.insert(
        "pause2_confirmation_gap_us".into(),
        pause2_confirmation_gap_us.map_or(serde_json::Value::Null, |value| value.into()),
    );
    facts.insert(
        "pause2_r_state".into(),
        pause2_r_state.map_or(serde_json::Value::Null, |state| state.into()),
    );
    facts.insert(
        "slot_pairs_attached".into(),
        slot_pairs.map_or(serde_json::Value::Null, |value| value.into()),
    );
    facts.insert("slot_attach_failures".into(), slot_attach_failures.into());
    facts.insert(
        "export_to_slot_attach_us".into(),
        export_to_slot_attach_us.map_or(serde_json::Value::Null, |value| value.into()),
    );

    let mut export_records: Vec<&common::DiscoveryRecord> = ab_records
        .iter()
        .filter(|record| {
            record.kind == AB_FUNCTION_LIST_KIND && record.case_id == EXPORT_COOKIE as u8
        })
        .collect();
    export_records.sort_by_key(|record| record.hook_ts_ns);
    facts.insert(
        "export_return_records".into(),
        (export_records.len() as u64).into(),
    );
    let first_export = export_records.first().copied();
    facts.insert(
        "export_return_nonzero_pointers".into(),
        first_export.map_or(serde_json::Value::Null, |record| {
            record
                .pointers
                .iter()
                .filter(|pointer| **pointer != 0)
                .count()
                .into()
        }),
    );
    facts.insert(
        "export_return_version_32".into(),
        first_export.map_or(serde_json::Value::Null, |record| {
            (record.version_major == 3 && record.version_minor == 2).into()
        }),
    );

    let mut c_init_records: Vec<&common::DiscoveryRecord> = ab_records
        .iter()
        .filter(|record| {
            record.kind == AB_FUNCTION_LIST_KIND && Some(record.case_id as u64) == c_init_cookie
        })
        .collect();
    c_init_records.sort_by_key(|record| record.hook_ts_ns);
    let ctor_init_records = c_init_records.len() as u64;
    let ctor_init_observed = !c_init_records.is_empty();
    let ctor_init_witness = match (mode, c_init_cookie) {
        ("exported", Some(_)) => Some("symbol-pair"),
        ("hidden", Some(_)) => Some("slot-pair"),
        _ => None,
    };
    let export_before_ctor_init = match (first_export, c_init_records.first()) {
        (Some(export), Some(init)) => Some(export.hook_ts_ns < init.hook_ts_ns),
        _ => None,
    };
    let ctor_init_escaped = match mode {
        "hidden" => Some(ctor_init_records < 2),
        _ => None,
    };
    facts.insert(
        "ctor_init_records".into(),
        c_init_cookie.map_or(serde_json::Value::Null, |_| ctor_init_records.into()),
    );
    facts.insert(
        "ctor_init_observed".into(),
        c_init_cookie.map_or(serde_json::Value::Null, |_| ctor_init_observed.into()),
    );
    facts.insert(
        "ctor_init_witness".into(),
        ctor_init_witness.map_or(serde_json::Value::Null, |witness| witness.into()),
    );
    facts.insert(
        "export_before_ctor_init".into(),
        export_before_ctor_init.map_or(serde_json::Value::Null, |value| value.into()),
    );
    facts.insert(
        "ctor_init_escaped".into(),
        ctor_init_escaped.map_or(serde_json::Value::Null, |value| value.into()),
    );
    facts.insert(
        "provider_ctor_init_line".into(),
        stderr_text.contains("PROVIDER_CTOR_INIT").into(),
    );
    facts.insert(
        "launcher_post_return_line".into(),
        stderr_text.contains("LAUNCHER_POST_RETURN").into(),
    );
    facts.insert(
        "dlopen_failed_line".into(),
        stderr_text.contains("DLOPEN_FAILED").into(),
    );
    facts.insert("child_exit_zero".into(), child_exit_zero.into());
    facts.insert("loader_start_entries".into(), loader_start_entries.into());
    facts.insert("ab_start_entries".into(), ab_start_entries.into());
    facts.insert("detach_failures".into(), detach_failures.into());
    facts.insert("resume_attempts".into(), resume_attempts.into());
    facts.insert(
        "resume_via_original_pidfd".into(),
        resume_via_original_pidfd.into(),
    );
    let loader_delta = diff_counters(&loader_before, &loader_after);
    facts.insert(
        "loader_counters_delta".into(),
        counters_list_fact(&loader_delta),
    );
    let ab_delta: [u64; AB_COUNTER_ENTRIES] = {
        let mut values = [0u64; AB_COUNTER_ENTRIES];
        for (index, value) in values.iter_mut().enumerate() {
            *value = ab_after[index].saturating_sub(ab_before[index]);
        }
        values
    };
    facts.insert("ab_counters_delta".into(), counters_list_fact(&ab_delta));

    // Oracle.
    let [
        l_ring_loss,
        l_state_failures,
        _l_loader_hits,
        l_state_read_failures,
        l_cookie_zero,
        l_func_ip_zero,
    ] = loader_delta;
    let [
        a_ring_loss,
        a_read_failures,
        a_state_failures,
        _a_truncated,
        _a_late_hits,
    ] = ab_delta;
    let runtime_reason = flow.err();
    let structural = runtime_reason.is_none()
        && startup_r_states_ok(&loader_records)
        && pause1_confirmed
        && pause1_r_state == Some(RT_ADD)
        && provider_mapped_at_pause
        && child_exit_zero
        && stderr_text.contains("PROVIDER_CTOR_INIT")
        && stderr_text.contains("LAUNCHER_POST_RETURN")
        && !stderr_text.contains("DLOPEN_FAILED")
        && export_records.len() == 2
        && first_export.is_some_and(|record| {
            record.pointers.iter().all(|pointer| *pointer != 0)
                && record.version_major == 3
                && record.version_minor == 2
        })
        && l_ring_loss == 0
        && l_state_failures == 0
        && l_state_read_failures == 0
        && l_cookie_zero == 0
        && l_func_ip_zero == 0
        && a_ring_loss == 0
        && a_read_failures == 0
        && a_state_failures == 0
        && resume_attempts == 1 + u64::from(second_pause)
        && resume_via_original_pidfd
        && loader_start_entries == 0
        && ab_start_entries == 0;
    let mode_ok = match (mode, second_pause) {
        ("exported", false) => {
            ctor_init_observed && ctor_init_records == 2 && export_before_ctor_init == Some(true)
        }
        ("exported", true) => {
            ctor_init_observed
                && ctor_init_records == 2
                && export_before_ctor_init == Some(true)
                && pause2_confirmed == Some(true)
                && pause2_r_state.is_some()
        }
        ("hidden", false) => hidden_race_measurement_complete(
            slot_pairs,
            export_to_slot_attach_us,
            ctor_init_escaped,
        ),
        ("hidden", true) => {
            slot_pairs == Some(PROVIDER_TABLE_POINTERS as u64)
                && export_to_slot_attach_us.is_some()
                && pause2_confirmed == Some(true)
                && pause2_r_state.is_some()
                && ctor_init_observed
                && ctor_init_records == 2
                && export_before_ctor_init == Some(true)
                && ctor_init_escaped == Some(false)
        }
        _ => false,
    };
    let pass = structural && mode_ok;
    let category = if runtime_reason.is_some() {
        "runtime"
    } else if pass {
        "none"
    } else {
        "oracle"
    };
    let mut row = metadata.record(pass, category);
    for (key, value) in facts {
        row.insert(key, value);
    }
    if let Some(reason) = runtime_reason {
        row.insert("runtime_failure_reason".into(), reason.into());
    }
    row
}

fn attach_probe_pair(
    ab_ebpf: &mut aya::Ebpf,
    ab_links: &mut Vec<(&'static str, aya::programs::uprobe::UProbeLinkId)>,
    provider_path: &Path,
    pid: i32,
    offset: u64,
    cookie: u64,
) -> Result<(), &'static str> {
    for program_name in AB_PROGRAMS {
        let link = attach_named(
            ab_ebpf,
            program_name,
            offset,
            provider_path,
            pid as u32,
            Some(cookie),
        )?;
        ab_links.push((program_name, link));
    }
    Ok(())
}

fn load_uprobe(ebpf: &mut aya::Ebpf, name: &str) -> Result<(), Box<dyn Error>> {
    use aya::programs::UProbe;
    let program: &mut UProbe = ebpf
        .program_mut(name)
        .ok_or("program missing")?
        .try_into()?;
    program.load()?;
    Ok(())
}

fn write_gate(fd: &OwnedFd) -> Result<(), &'static str> {
    let byte = b'G';
    // SAFETY: one byte, owned descriptor.
    let wrote = unsafe { libc::write(fd.as_raw_fd(), &byte as *const u8 as *const _, 1) };
    if wrote != 1 {
        return Err("child release");
    }
    Ok(())
}

fn startup_r_states_ok(records: &[common::DiscoveryRecord]) -> bool {
    let states: Vec<u32> = records
        .iter()
        .filter(|record| record.kind == KIND_LOADER)
        .take(2)
        .map(|record| record.announced_count)
        .collect();
    states == [RT_ADD, RT_CONSISTENT]
}

fn counters_list_fact(values: &[u64]) -> serde_json::Value {
    serde_json::Value::Array(
        values
            .iter()
            .map(|value| serde_json::Value::from(*value))
            .collect(),
    )
}

fn vaddr_to_file_offset(bytes: &[u8], vaddr: u64) -> Option<u64> {
    use object::{Object as _, ObjectSegment as _};
    let object = object::File::parse(bytes).ok()?;
    for segment in object.segments() {
        let (file_start, file_size) = segment.file_range();
        if let Some(delta) = vaddr.checked_sub(segment.address()) {
            if delta < file_size {
                return Some(file_start + delta);
            }
        }
    }
    None
}

fn hidden_race_measurement_complete(
    slot_pairs: Option<u64>,
    window_us: Option<u64>,
    escaped: Option<bool>,
) -> bool {
    slot_pairs.is_some_and(|count| count <= PROVIDER_TABLE_POINTERS as u64)
        && window_us.is_some()
        && escaped.is_some()
}

fn median(values: &mut [u64]) -> Option<u64> {
    if values.is_empty() {
        return None;
    }
    values.sort_unstable();
    Some(values[values.len() / 2])
}

// ---------------------------------------------------------------------------
// loader-protect driver
// ---------------------------------------------------------------------------

struct ProtectPaths {
    mode: String,
    second_pause: bool,
    source_manifest: PathBuf,
    build_evidence: PathBuf,
    execution_manifest: PathBuf,
    bpf: PathBuf,
    abpf: PathBuf,
    abpf_manifest: PathBuf,
    launcher: PathBuf,
    provider: PathBuf,
    out: PathBuf,
}

fn parse_protect_args(args: &[String]) -> Result<ProtectPaths, &'static str> {
    if args.is_empty() || !matches!(args[0].as_str(), "exported" | "hidden") {
        return Err("loader-protect arguments");
    }
    let mut second_pause = false;
    let mut values = BTreeMap::new();
    let mut index = 1;
    while index < args.len() {
        if args[index] == "--second-pause" {
            if second_pause {
                return Err("loader-protect arguments");
            }
            second_pause = true;
            index += 1;
            continue;
        }
        let Some(pair) = args.get(index..index + 2) else {
            return Err("loader-protect arguments");
        };
        if !matches!(
            pair[0].as_str(),
            "--source-manifest"
                | "--build-evidence"
                | "--execution-manifest"
                | "--bpf"
                | "--abpf"
                | "--abpf-manifest"
                | "--launcher"
                | "--provider"
                | "--out"
        ) || values.insert(pair[0].as_str(), pair[1].as_str()).is_some()
        {
            return Err("loader-protect arguments");
        }
        index += 2;
    }
    let path = |name| {
        values
            .get(name)
            .map(PathBuf::from)
            .ok_or("loader-protect arguments")
    };
    Ok(ProtectPaths {
        mode: args[0].clone(),
        second_pause,
        source_manifest: path("--source-manifest")?,
        build_evidence: path("--build-evidence")?,
        execution_manifest: path("--execution-manifest")?,
        bpf: path("--bpf")?,
        abpf: path("--abpf")?,
        abpf_manifest: path("--abpf-manifest")?,
        launcher: path("--launcher")?,
        provider: path("--provider")?,
        out: path("--out")?,
    })
}

struct ProtectSetup {
    metadata: LoaderMetadata,
    bpf_bytes: Vec<u8>,
    abpf_bytes: Vec<u8>,
    abpf_source_commit: String,
    launcher_sha256: String,
    provider_plan: ProviderPlan,
    loader_identity: LoaderIdentity,
}

#[allow(clippy::type_complexity)]
fn validate_protect_provenance(paths: &ProtectPaths) -> Result<ProtectSetup, &'static str> {
    if unsafe { libc::geteuid() } != 0 || std::env::consts::ARCH != "x86_64" {
        return Err("guest identity");
    }
    let source_bytes = read_regular(&paths.source_manifest, 4 * 1024 * 1024)?;
    let build_bytes = read_regular(&paths.build_evidence, 16 * 1024 * 1024)?;
    let execution_bytes = read_regular(&paths.execution_manifest, 1024 * 1024)?;
    let bpf_bytes = read_regular(&paths.bpf, 16 * 1024 * 1024)?;
    let abpf_bytes = read_regular(&paths.abpf, 16 * 1024 * 1024)?;
    let abpf_manifest_bytes = read_regular(&paths.abpf_manifest, 1024 * 1024)?;
    let launcher_bytes = read_regular(&paths.launcher, 64 * 1024 * 1024)?;
    let provider_bytes = read_regular(&paths.provider, 64 * 1024 * 1024)?;
    let runner_bytes = read_regular(
        &std::env::current_exe().map_err(|_| "runner path")?,
        64 * 1024 * 1024,
    )?;
    let source: serde_json::Value =
        serde_json::from_slice(&source_bytes).map_err(|_| "source manifest")?;
    let execution: serde_json::Value =
        serde_json::from_slice(&execution_bytes).map_err(|_| "execution manifest")?;
    let abpf_manifest: serde_json::Value =
        serde_json::from_slice(&abpf_manifest_bytes).map_err(|_| "execution manifest")?;
    for (name, actual) in [
        ("source_manifest_sha256", sha256_hex(&source_bytes)),
        ("build_evidence_sha256", sha256_hex(&build_bytes)),
        ("bpf_sha256", sha256_hex(&bpf_bytes)),
        ("runner_sha256", sha256_hex(&runner_bytes)),
    ] {
        if json_string(&execution, name)? != actual {
            return Err("execution manifest digest mismatch");
        }
    }
    if json_string(&source, "bpf_sha256")? != sha256_hex(&bpf_bytes) {
        return Err("source manifest BPF mismatch");
    }
    let source_commit = json_string(&source, "source_commit")?;
    if !valid_hex(source_commit, 40) || json_string(&execution, "source_commit")? != source_commit {
        return Err("source commit mismatch");
    }
    // The frozen A/B object is consumed read-only; its manifest pins its bytes.
    if json_string(&abpf_manifest, "bpf_sha256")? != sha256_hex(&abpf_bytes) {
        return Err("execution manifest digest mismatch");
    }
    let abpf_source_commit = json_string(&abpf_manifest, "source_commit")?.to_owned();
    if !valid_hex(&abpf_source_commit, 40) {
        return Err("source commit mismatch");
    }

    let kernel = kernel_release()?;
    let glibc = glibc_version()?;
    // Task 8 endpoints: host 7.0 (glibc 2.39) and the Noble guest 6.8/2.39.
    // Jammy 5.15 is structurally excluded: bpf_get_func_ip returns 0 there
    // (Task 7), which gates off the pause path this experiment needs.
    let lane = if kernel_matches(&kernel, "7.0") && glibc == "glibc 2.39" {
        "7.0"
    } else if kernel_matches(&kernel, "6.8") && glibc == "glibc 2.39" {
        "6.8"
    } else {
        return Err("guest kernel or glibc identity");
    };
    let provider_plan = build_provider_plan(&paths.mode, provider_bytes)?;
    let loader_identity = resolve_loader_identity(&launcher_bytes)?;
    let launcher_sha256 = sha256_hex(&launcher_bytes);
    Ok(ProtectSetup {
        metadata: LoaderMetadata {
            source_commit: source_commit.to_owned(),
            bpf_sha256: sha256_hex(&bpf_bytes),
            runner_sha256: sha256_hex(&runner_bytes),
            fixture_sha256: provider_plan.sha256.clone(),
            kernel_release: kernel,
            glibc_version: glibc,
            lane: lane.into(),
        },
        bpf_bytes,
        abpf_bytes,
        abpf_source_commit,
        launcher_sha256,
        provider_plan,
        loader_identity,
    })
}

fn run_loader_protect(paths: ProtectPaths) -> Result<bool, &'static str> {
    // SAFETY: a process-local restrictive umask has no memory-safety preconditions.
    unsafe { libc::umask(0o077) };
    create_private_dir(&paths.out).map_err(|_| "output directory")?;
    let mut environment =
        create_private_file(&paths.out.join("environment.txt")).map_err(|_| "environment file")?;
    let mut verifier_log =
        create_private_file(&paths.out.join("verifier.log")).map_err(|_| "verifier log")?;
    let mut verifier_results = create_private_file(&paths.out.join("verifier-results.jsonl"))
        .map_err(|_| "verifier results")?;
    let mut facts_file =
        create_private_file(&paths.out.join("protect-facts.jsonl")).map_err(|_| "facts file")?;
    let mut runner_status =
        create_private_file(&paths.out.join("runner-status.txt")).map_err(|_| "runner status")?;

    let setup = validate_protect_provenance(&paths)?;
    let metadata = setup.metadata.clone();
    writeln!(
        environment,
        "kernel_release={}\narch=x86_64\nglibc_version={}\nlane={}\nmode={}\nsecond_pause={}\nabpf_sha256={}\nabpf_source_commit={}\nlauncher_sha256={}\nprovider_sha256={}",
        metadata.kernel_release,
        metadata.glibc_version,
        metadata.lane,
        paths.mode,
        paths.second_pause,
        sha256_hex(&setup.abpf_bytes),
        setup.abpf_source_commit,
        setup.launcher_sha256,
        setup.provider_plan.sha256,
    )
    .map_err(|_| "environment write")?;

    // Both objects load up front; the A/B object is read-only witness bytes.
    let mut loader = aya::EbpfLoader::new();
    loader.verifier_log_level(aya::VerifierLogLevel::VERBOSE | aya::VerifierLogLevel::STATS);
    let mut loader_ebpf = match loader.load(&setup.bpf_bytes) {
        Ok(ebpf) => ebpf,
        Err(error) => {
            writeln!(
                verifier_log,
                "object=loader outcome=rejected\n{}",
                verifier_error_chain(&error)
            )
            .map_err(|_| "verifier write")?;
            writeln!(runner_status, "status=FAIL\nfailure_category=object_load")
                .map_err(|_| "runner status write")?;
            return Ok(false);
        }
    };
    let mut ab_ebpf = match aya::EbpfLoader::new().load(&setup.abpf_bytes) {
        Ok(ebpf) => ebpf,
        Err(error) => {
            writeln!(
                verifier_log,
                "object=ab outcome=rejected\n{}",
                verifier_error_chain(&error)
            )
            .map_err(|_| "verifier write")?;
            writeln!(
                verifier_results,
                "{}",
                serde_json::Value::Object({
                    let mut value = metadata.record(false, "verifier");
                    value.insert("object".into(), "ab".into());
                    value
                })
            )
            .map_err(|_| "JSON write")?;
            writeln!(runner_status, "status=FAIL\nfailure_category=verifier")
                .map_err(|_| "runner status write")?;
            return Ok(false);
        }
    };
    let load_results = [
        (
            "loader",
            LOADER_PROGRAM,
            load_uprobe(&mut loader_ebpf, LOADER_PROGRAM),
        ),
        (
            "ab",
            AB_PROGRAMS[0],
            load_uprobe(&mut ab_ebpf, AB_PROGRAMS[0]),
        ),
        (
            "ab",
            AB_PROGRAMS[1],
            load_uprobe(&mut ab_ebpf, AB_PROGRAMS[1]),
        ),
    ];
    let mut load_failed = false;
    for (object, program, result) in load_results {
        let accepted = result.is_ok();
        let mut value = metadata.record(accepted, if accepted { "none" } else { "verifier" });
        value.insert("object".into(), object.into());
        value.insert("program".into(), program.into());
        write_json_line(&mut verifier_results, serde_json::Value::Object(value))?;
        if let Err(error) = result {
            load_failed = true;
            writeln!(
                verifier_log,
                "object={object} program={program} outcome=rejected error_chain={}",
                verifier_error_chain(error.as_ref())
            )
            .map_err(|_| "verifier write")?;
        } else {
            writeln!(
                verifier_log,
                "object={object} program={program} outcome=accepted success_verifier_text=unavailable_aya_0_14"
            )
            .map_err(|_| "verifier write")?;
        }
    }
    if load_failed {
        writeln!(runner_status, "status=FAIL\nfailure_category=verifier")
            .map_err(|_| "runner status write")?;
        return Ok(false);
    }

    let mut loader_ring =
        aya::maps::RingBuf::try_from(loader_ebpf.take_map("DISCOVERY").ok_or("discovery map")?)
            .map_err(|_| "discovery ring")?;
    let loader_counters = aya::maps::Array::<_, u64>::try_from(
        loader_ebpf.take_map("COUNTERS").ok_or("counter map")?,
    )
    .map_err(|_| "counter map")?;
    let mut loader_start = aya::maps::HashMap::<_, common::StateKey, common::StartState>::try_from(
        loader_ebpf.take_map("START").ok_or("start map")?,
    )
    .map_err(|_| "start map")?;
    let mut ab_ring =
        aya::maps::RingBuf::try_from(ab_ebpf.take_map("DISCOVERY").ok_or("discovery map")?)
            .map_err(|_| "discovery ring")?;
    let ab_counters =
        aya::maps::Array::<_, u64>::try_from(ab_ebpf.take_map("COUNTERS").ok_or("counter map")?)
            .map_err(|_| "counter map")?;
    let mut ab_start = aya::maps::HashMap::<_, common::StateKey, common::StartState>::try_from(
        ab_ebpf.take_map("START").ok_or("start map")?,
    )
    .map_err(|_| "start map")?;
    let mut registry = LoaderRegistry::new();

    let launcher = paths.launcher.clone();
    let provider_path = paths.provider.canonicalize().map_err(|_| "provider path")?;
    let mut all_pass = true;
    let mut any_runtime = false;
    let mut passed_count = 0u64;
    let mut attach_gaps: Vec<u64> = Vec::new();
    let mut windows: Vec<u64> = Vec::new();
    let mut pause1_count = 0u64;
    let mut pause2_count = 0u64;
    let mut ctor_observed_count = 0u64;
    let mut escaped_count = 0u64;

    for attempt in 0..PROTECT_ATTEMPTS {
        let row = run_protect_attempt(
            &metadata,
            &paths.mode,
            paths.second_pause,
            &launcher,
            &provider_path,
            &setup.provider_plan,
            &setup.loader_identity,
            &mut loader_ebpf,
            &mut loader_ring,
            &loader_counters,
            &mut loader_start,
            &mut ab_ebpf,
            &mut ab_ring,
            &ab_counters,
            &mut ab_start,
            &mut registry,
            attempt,
        );
        if row.get("pass").and_then(serde_json::Value::as_bool) != Some(true) {
            all_pass = false;
        } else {
            passed_count += 1;
        }
        if row
            .get("failure_category")
            .and_then(serde_json::Value::as_str)
            == Some("runtime")
        {
            any_runtime = true;
            let reason = row
                .get("runtime_failure_reason")
                .and_then(serde_json::Value::as_str)
                .unwrap_or("runtime");
            writeln!(verifier_log, "runtime_failure=protect:{reason}")
                .map_err(|_| "verifier write")?;
        } else if row.get("pass").and_then(serde_json::Value::as_bool) != Some(true) {
            writeln!(verifier_log, "oracle_failure=protect").map_err(|_| "verifier write")?;
        }
        if row
            .get("pause1_confirmed")
            .and_then(serde_json::Value::as_bool)
            == Some(true)
        {
            pause1_count += 1;
        }
        if row
            .get("pause2_confirmed")
            .and_then(serde_json::Value::as_bool)
            == Some(true)
        {
            pause2_count += 1;
        }
        if row
            .get("ctor_init_observed")
            .and_then(serde_json::Value::as_bool)
            == Some(true)
        {
            ctor_observed_count += 1;
        }
        if row
            .get("ctor_init_escaped")
            .and_then(serde_json::Value::as_bool)
            == Some(true)
        {
            escaped_count += 1;
        }
        if let Some(value) = row.get("attach_gap_us").and_then(serde_json::Value::as_u64) {
            attach_gaps.push(value);
        }
        if let Some(value) = row
            .get("export_to_slot_attach_us")
            .and_then(serde_json::Value::as_u64)
        {
            windows.push(value);
        }
        write_json_line(&mut facts_file, serde_json::Value::Object(row))?;
    }

    let attach_bounds = [
        attach_gaps.iter().copied().min(),
        median(&mut attach_gaps),
        attach_gaps.iter().copied().max(),
    ];
    let window_bounds = [
        windows.iter().copied().min(),
        median(&mut windows),
        windows.iter().copied().max(),
    ];
    let opt_to_json =
        |value: &Option<u64>| value.map_or(serde_json::Value::Null, |number| number.into());
    let mut summary = metadata.record(
        all_pass,
        if all_pass {
            "none"
        } else if any_runtime {
            "runtime"
        } else {
            "oracle"
        },
    );
    summary.insert("flow".into(), "protect-summary".into());
    summary.insert("mode".into(), paths.mode.clone().into());
    summary.insert("second_pause".into(), paths.second_pause.into());
    summary.insert("attempts".into(), (PROTECT_ATTEMPTS as u64).into());
    summary.insert("passed".into(), passed_count.into());
    summary.insert("pause1_count".into(), pause1_count.into());
    summary.insert("pause2_count".into(), pause2_count.into());
    summary.insert(
        "ctor_init_observed_count".into(),
        ctor_observed_count.into(),
    );
    summary.insert("ctor_init_escaped_count".into(), escaped_count.into());
    summary.insert(
        "attach_gap_us_min_med_max".into(),
        serde_json::Value::Array(attach_bounds.iter().map(&opt_to_json).collect()),
    );
    summary.insert(
        "export_to_slot_attach_us_min_med_max".into(),
        serde_json::Value::Array(window_bounds.iter().map(opt_to_json).collect()),
    );
    write_json_line(&mut facts_file, serde_json::Value::Object(summary))?;

    let category = if all_pass {
        "none"
    } else if any_runtime {
        "runtime"
    } else {
        "oracle"
    };
    writeln!(
        runner_status,
        "status={}\nfailure_category={}\nattempts={}\npassed={}\npause1_count={}\npause2_count={}",
        if all_pass { "PASS" } else { "FAIL" },
        category,
        PROTECT_ATTEMPTS,
        passed_count,
        pause1_count,
        pause2_count,
    )
    .map_err(|_| "runner status write")?;
    Ok(all_pass)
}

fn self_check() -> Result<(), &'static str> {
    let kernel = kernel_release()?;
    let glibc = glibc_version()?;
    if std::env::consts::ARCH != "x86_64"
        || !((kernel_matches(&kernel, "5.15") && glibc == "glibc 2.35")
            || (kernel_matches(&kernel, "6.8") && glibc == "glibc 2.39"))
    {
        return Err("guest identity");
    }
    Ok(())
}

/// One finite JSON line per program: no raw verifier text beyond a 2 KiB tail.
fn diag_line(
    program: &str,
    outcome: Result<Option<u32>, (Option<i32>, String)>,
    duration_ms: u128,
) -> String {
    let mut v = serde_json::Map::new();
    v.insert("program".into(), program.into());
    v.insert(
        "duration_ms".into(),
        u64::try_from(duration_ms).unwrap_or(u64::MAX).into(),
    );
    match outcome {
        Ok(insns) => {
            v.insert("accepted".into(), true.into());
            v.insert("verified_insns".into(), insns.into()); // None on 5.15 (bpf_prog_info field added in 5.16)
        }
        Err((errno, log)) => {
            v.insert("accepted".into(), false.into());
            v.insert("errno".into(), errno.into());
            v.insert("log_bytes".into(), (log.len() as u64).into());
            let tail: String = log
                .chars()
                .rev()
                .take(2048)
                .collect::<Vec<_>>()
                .into_iter()
                .rev()
                .collect();
            v.insert("log_tail".into(), tail.into());
        }
    }
    serde_json::Value::Object(v).to_string()
}

/// Diagnostic-only loader verdict lane: one STATS-only load, never the frozen
/// VERBOSE | STATS gate (D2 form, as in Task 2).
fn run_loader_diag(bpf_path: &str, out_dir: &str) -> Result<bool, &'static str> {
    std::fs::create_dir_all(out_dir).map_err(|_| "out dir")?;
    let bytes = std::fs::read(bpf_path).map_err(|_| "bpf read")?;
    let mut sink =
        std::fs::File::create(format!("{out_dir}/diag.jsonl")).map_err(|_| "diag file")?;
    let mut loader = aya::EbpfLoader::new();
    loader.verifier_log_level(aya::VerifierLogLevel::STATS);
    let mut ebpf = loader.load(&bytes).map_err(|_| "object load")?;
    let started = Instant::now();
    let outcome: Result<Option<u32>, (Option<i32>, String)> = match ebpf.program_mut(LOADER_PROGRAM)
    {
        None => Err((None, "program missing".into())),
        Some(program) => match <&mut aya::programs::UProbe>::try_from(program) {
            Err(error) => Err((None, error.to_string())),
            Ok(program) => match program.load() {
                Ok(()) => Ok(program
                    .info()
                    .ok()
                    .and_then(|info| info.verified_instruction_count())),
                Err(aya::programs::ProgramError::LoadError {
                    io_error,
                    verifier_log,
                }) => Err((io_error.raw_os_error(), verifier_log.to_string())),
                Err(other) => Err((None, other.to_string())),
            },
        },
    };
    let accepted = outcome.is_ok();
    writeln!(
        sink,
        "{}",
        diag_line(LOADER_PROGRAM, outcome, started.elapsed().as_millis())
    )
    .map_err(|_| "diag write")?;
    Ok(accepted)
}

fn main() {
    let args = std::env::args().collect::<Vec<_>>();
    let result = match args.get(1).map(String::as_str) {
        Some("--self-check") if args.len() == 2 => self_check().map(|()| true),
        Some("loader-hit") => parse_loader_args(&args[2..]).and_then(run_loader_hit),
        Some("loader-protect") => parse_protect_args(&args[2..]).and_then(run_loader_protect),
        Some("loader-diag") if args.len() == 4 => run_loader_diag(&args[2], &args[3]),
        _ => Err("usage"),
    };
    match result {
        Ok(true) => {}
        Ok(false) => std::process::exit(1),
        Err(error) => {
            eprintln!("slice1b2-loader-host: {error}");
            std::process::exit(2);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn kernel_matches_accepts_lane_kernels_only_by_prefix() {
        assert!(kernel_matches("5.15.0-187-generic", "5.15"));
        assert!(kernel_matches("6.8.0-137-generic", "6.8"));
        assert!(kernel_matches("5.15", "5.15"));
        assert!(!kernel_matches("5.15.0-187-generic", "6.8"));
        assert!(!kernel_matches("6.8.0-137-generic", "5.15"));
        assert!(!kernel_matches("51.5.0", "5.15"));
        assert!(!kernel_matches("6.89.0", "6.8"));
    }

    #[test]
    fn cookie_round_trip_covers_all_contexts_and_bounds() {
        use common::{cookie_decode, cookie_encode};
        for id in 1..=256u16 {
            assert_eq!(cookie_decode(cookie_encode(id, None)).unwrap(), (id, None));
            for delta in [0i64, -(1 << 54), (1 << 54) - 1] {
                assert_eq!(
                    cookie_decode(cookie_encode(id, Some(delta))).unwrap(),
                    (id, Some(delta))
                );
            }
        }
        assert_eq!(cookie_encode(1, None), 512); // absent state: id_bits | (1 << 9), never zero
        assert_eq!(cookie_encode(1, Some(0)), 256); // present state, zero delta: id_bits | (1 << 8)
        assert!(cookie_decode(0).is_err()); // zero cookie rejected before any lookup
        assert!(cookie_decode(2 << 9).is_err()); // absent state with payload != 1 rejected
    }

    fn payload(generation: u64) -> LoaderContext {
        LoaderContext {
            generation,
            loader_sha256: format!("{generation:064x}"),
            loader_device: generation,
            loader_inode: generation,
            hook_vaddr: 0x1000,
            hook_file_offset: 0x800,
            r_debug_vaddr: Some(0x2000),
            delta: Some(0x1000),
        }
    }

    #[test]
    fn registry_allocates_monotonic_ids_and_never_reuses() {
        let mut registry = LoaderRegistry::new();
        for id in 1..=REGISTRY_CAPACITY {
            assert_eq!(registry.allocate(payload(u64::from(id))).unwrap(), id);
        }
        assert_eq!(registry.allocate(payload(257)), Err("registry capacity"));
        // Tombstoning the first slot never frees ID 1 for reuse.
        registry.mark_attached(1).unwrap();
        registry.mark_tombstoned(1, true).unwrap();
        assert_eq!(registry.allocate(payload(258)), Err("registry capacity"));
    }

    #[test]
    fn registry_shell_transitions_are_phase_exact() {
        let mut registry = LoaderRegistry::new();
        let id = registry.allocate(payload(1)).unwrap();
        assert!(!registry.decodable(id), "prepared shell is not decodable");
        assert_eq!(registry.mark_tombstoned(id, false), Ok(()));
        assert!(
            !registry.decodable(id),
            "attach-failure tombstone is not decodable"
        );
        let id = registry.allocate(payload(2)).unwrap();
        registry.mark_attached(id).unwrap();
        assert!(registry.decodable(id));
        assert_eq!(registry.mark_attached(id), Err("registry phase"));
        registry.mark_tombstoned(id, true).unwrap();
        assert!(
            registry.decodable(id),
            "post-attach tombstone stays decodable for the drain"
        );
        assert_eq!(registry.mark_tombstoned(id, true), Err("registry phase"));
        assert!(!registry.decodable(REGISTRY_CAPACITY + 1));
    }

    #[test]
    fn registry_generation_is_assigned_and_monotonic() {
        let mut registry = LoaderRegistry::new();
        registry.allocate(payload(99)).unwrap();
        let second = registry.allocate(payload(99)).unwrap();
        let shell = registry.slot(second);
        assert!(shell.is_some());
    }

    #[test]
    fn elf_helpers_read_the_host_loader() {
        // The test binary itself is a dynamically linked x86-64 ELF.
        let bytes = std::fs::read(std::env::current_exe().unwrap()).unwrap();
        let interp = elf_interp(&bytes).unwrap();
        assert!(interp.to_string_lossy().contains("ld-"), "{interp:?}");
        let loader_bytes = std::fs::read(&interp).unwrap();
        let hook = elf_symbol(&loader_bytes, "_dl_debug_state")
            .unwrap()
            .expect("host loader symbol");
        assert!(hook.vaddr != 0 && hook.file_offset.is_some());
        // glibc keeps `_r_debug` outside the file-backed image (`.bss`), so
        // only its vaddr is guaranteed — and that is all the §7.3 delta needs.
        let r_debug = elf_symbol(&loader_bytes, "_r_debug")
            .unwrap()
            .expect("host loader _r_debug symbol");
        assert_ne!(r_debug.vaddr, 0);
        let delta = (r_debug.vaddr as i64)
            .checked_sub(hook.vaddr as i64)
            .unwrap();
        assert!(delta.abs() <= (1i64 << 54));
    }

    #[test]
    fn loader_bpf_source_keeps_the_contracted_shapes() {
        let source = std::fs::read_to_string(concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/../slice1b2-loader-bpf/src/main.rs"
        ))
        .unwrap();
        assert_eq!(source.matches("bpf_send_signal(19)").count(), 1);
        // validation precedes the IP read; the pause path follows the IP read
        let validation_index = source
            .find("let invalid = zero_cookie || invalid_absent;")
            .expect("cookie validation");
        let ip_index = source.find("helpers::bpf_get_func_ip").expect("IP read");
        let pause_index = source.find("pause_owner_key())").expect("pause path");
        assert!(validation_index < ip_index);
        assert!(pause_index > ip_index);
        // one 4-byte r_state read at the frozen offset
        assert!(source.contains("R_STATE_OFFSET"));
        assert!(source.contains("bpf_probe_read_user(address as *const u32)"));
        // the 112-store initializer inside the guard's scoped emitter
        assert!(source.contains("zero_words!(words;"));
        assert!(source.contains("111,"));
        assert!(source.contains("#[inline(never)]"));
    }

    #[test]
    fn run_sh_passes_bash_n_and_pins_lanes() {
        let script = concat!(env!("CARGO_MANIFEST_DIR"), "/run.sh");
        let status = std::process::Command::new("bash")
            .arg("-n")
            .arg(script)
            .status()
            .unwrap();
        assert!(status.success());
        let output = std::process::Command::new("bash")
            .arg("-c")
            .arg("source \"$1\"; lane_config jammy; lane_config noble")
            .arg("bash")
            .arg(script)
            .output()
            .unwrap();
        assert!(output.status.success());
        let lines = String::from_utf8(output.stdout).unwrap();
        let lines: Vec<&str> = lines.lines().collect();
        assert_eq!(lines.len(), 2);
        assert!(lines[0].starts_with("/tmp/p11scope-slice1b2-vms/jammy/overlay.qcow2|"));
        assert!(lines[1].starts_with("/tmp/p11scope-slice1b2-vms/noble/overlay.qcow2|"));
    }

    #[test]
    fn pidfd_child_resumes_only_owned_stops_and_never_signals_after_reap() {
        let mut child = std::process::Command::new("/bin/sleep")
            .arg("60")
            .spawn()
            .unwrap();
        let mut lifecycle = PidfdChild::open(child.id() as i32).unwrap();
        lifecycle.send(libc::SIGSTOP).unwrap();
        let deadline = Instant::now() + Duration::from_secs(2);
        while child_state(lifecycle.pid()) != Some('T') {
            assert!(Instant::now() < deadline, "child did not stop");
            std::thread::sleep(Duration::from_millis(1));
        }
        lifecycle.mark_stopped();
        lifecycle.resume_owned_stop().unwrap();
        assert_eq!(
            lifecycle.resume_owned_stop().unwrap_err().kind(),
            io::ErrorKind::InvalidInput
        );
        lifecycle.send(libc::SIGKILL).unwrap();
        child.wait().unwrap();
        lifecycle.mark_reaped();
        assert!(
            !lifecycle.terminate().unwrap(),
            "reaped child was signalled"
        );
    }

    #[test]
    fn pause_confirmation_requires_two_exact_stopped_samples_one_ms_apart() {
        let stopped = StopSnapshot {
            elapsed_us: 10,
            count: 2,
            exact_expected_task_set: true,
            all_tasks_stopped: true,
            state_counts: [0, 0, 0, 2, 0, 0, 0, 0, 0],
        };
        assert_eq!(
            confirm(&[
                stopped,
                StopSnapshot {
                    elapsed_us: 1_010,
                    ..stopped
                },
            ]),
            Some((0, 1))
        );
        assert_eq!(
            confirm(&[
                stopped,
                StopSnapshot {
                    elapsed_us: 999,
                    ..stopped
                },
            ]),
            None
        );
        assert_eq!(
            confirm(&[
                stopped,
                StopSnapshot {
                    elapsed_us: 1_010,
                    all_tasks_stopped: false,
                    ..stopped
                },
            ]),
            None
        );
    }

    #[test]
    fn runtime_delta_supports_both_mapping_orders() {
        assert_eq!(signed_runtime_delta(0x3000, 0x1000), Ok(0x2000));
        assert_eq!(signed_runtime_delta(0x1000, 0x3000), Ok(-0x2000));
        assert_eq!(signed_runtime_delta(1u64 << 55, 0), Err("loader delta"));
    }

    #[test]
    fn provider_fixture_has_exported_and_hidden_table_shapes_and_runs() {
        let source = Path::new(env!("CARGO_MANIFEST_DIR")).join("fixture-provider.c");
        let directory = std::env::temp_dir().join(format!(
            "slice1b2-provider-{}-{}",
            std::process::id(),
            monotonic_ns().unwrap()
        ));
        std::fs::create_dir(&directory).unwrap();
        let launcher = directory.join("launcher");
        let exported = directory.join("exported.so");
        let hidden = directory.join("hidden.so");
        for (output, extra) in [
            (&launcher, vec!["-ldl"]),
            (
                &exported,
                vec![
                    "-shared",
                    "-fPIC",
                    "-fvisibility=hidden",
                    "-DFIXTURE_PROVIDER",
                    "-DC_TABLE_EXPORTED",
                ],
            ),
            (
                &hidden,
                vec![
                    "-shared",
                    "-fPIC",
                    "-fvisibility=hidden",
                    "-DFIXTURE_PROVIDER",
                ],
            ),
        ] {
            let status = std::process::Command::new("gcc")
                .args(["-std=c11", "-O2", "-Wall", "-Wextra", "-Werror"])
                .args(extra)
                .arg(&source)
                .arg("-o")
                .arg(output)
                .status()
                .unwrap();
            assert!(status.success());
        }
        assert_eq!(
            build_provider_plan("exported", std::fs::read(&exported).unwrap())
                .unwrap()
                .symbols
                .len(),
            PROVIDER_TABLE_POINTERS
        );
        assert!(
            build_provider_plan("hidden", std::fs::read(&hidden).unwrap())
                .unwrap()
                .symbols
                .is_empty()
        );
        for provider in [&exported, &hidden] {
            let mut child = std::process::Command::new(&launcher)
                .arg(provider)
                .stdin(std::process::Stdio::piped())
                .stderr(std::process::Stdio::piped())
                .spawn()
                .unwrap();
            child.stdin.take().unwrap().write_all(b"G").unwrap();
            let output = child.wait_with_output().unwrap();
            assert!(output.status.success());
            let stderr = String::from_utf8(output.stderr).unwrap();
            assert!(stderr.contains("PROVIDER_CTOR_INIT"));
            assert!(stderr.contains("LAUNCHER_POST_RETURN"));
        }
        std::fs::remove_dir_all(directory).unwrap();
    }

    #[test]
    fn loader_protect_parser_is_finite_and_rejects_duplicates() {
        let mut args = vec!["hidden".to_owned(), "--second-pause".to_owned()];
        for name in [
            "--source-manifest",
            "--build-evidence",
            "--execution-manifest",
            "--bpf",
            "--abpf",
            "--abpf-manifest",
            "--launcher",
            "--provider",
            "--out",
        ] {
            args.extend([name.to_owned(), format!("/{name}")]);
        }
        let parsed = parse_protect_args(&args).unwrap();
        assert_eq!(parsed.mode, "hidden");
        assert!(parsed.second_pause);
        args.extend(["--out".to_owned(), "/again".to_owned()]);
        assert!(parse_protect_args(&args).is_err());
    }

    #[test]
    fn proc_root_loader_identity_matches_its_mapping() {
        let bytes = std::fs::read(std::env::current_exe().unwrap()).unwrap();
        let interp = elf_interp(&bytes).unwrap();
        let pid = std::process::id() as i32;
        let metadata = std::fs::metadata(&interp).unwrap();
        let path = canonical_loader_path(pid, &interp).unwrap();
        assert!(
            loader_load_bias(
                pid,
                u64::from(libc::major(metadata.dev())),
                u64::from(libc::minor(metadata.dev())),
                metadata.ino(),
                &path,
            )
            .is_ok()
        );
    }

    #[test]
    fn hidden_one_pause_accepts_a_bounded_race_measurement_not_only_full_attachment() {
        assert!(hidden_race_measurement_complete(
            Some(0),
            Some(25),
            Some(true)
        ));
        assert!(hidden_race_measurement_complete(
            Some(PROVIDER_TABLE_POINTERS as u64),
            Some(100),
            Some(false)
        ));
        assert!(!hidden_race_measurement_complete(
            None,
            Some(25),
            Some(true)
        ));
        assert!(!hidden_race_measurement_complete(
            Some((PROVIDER_TABLE_POINTERS + 1) as u64),
            Some(25),
            Some(true)
        ));
    }
}
