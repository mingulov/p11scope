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
    pub file_offset: u64,
}

fn parse_elf(bytes: &[u8]) -> Result<object::File<'_>, &'static str> {
    use object::Object as _;
    let object = object::File::parse(bytes).map_err(|_| "not parseable as an ELF object")?;
    if object.architecture() != object::Architecture::X86_64 {
        return Err("not a 64-bit x86-64 ELF object");
    }
    Ok(object)
}

/// Virtual address + file offset of one symbol (dynsym first, then symtab).
/// Only addresses backed by actual file bytes qualify.
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
        if let Some(offset) = file_offset(symbol.address()) {
            return Ok(Some(SymbolLocation {
                vaddr: symbol.address(),
                file_offset: offset,
            }));
        }
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
    actual.split('.').next() == Some(prefix)
        || actual == prefix
        || actual
            .strip_suffix("-generic")
            .is_some_and(|base| base.split('.').next() == Some(prefix))
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

fn loader_load_bias(
    pid: i32,
    dev_major: u64,
    dev_minor: u64,
    inode: u64,
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
        if major != dev_major || minor != dev_minor || map_inode != inode {
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
    use aya::programs::UProbe;
    use aya::programs::uprobe::{UProbeAttachLocation, UProbeAttachPoint, UProbeScope};
    let program: &mut UProbe = ebpf
        .program_mut(LOADER_PROGRAM)
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
    use aya::programs::UProbe;
    let program: &mut UProbe = ebpf
        .program_mut(LOADER_PROGRAM)
        .ok_or("program missing")?
        .try_into()
        .map_err(|_| "program type")?;
    program.detach(link).map_err(|_| "program detach")
}

fn read_counters(
    counters: &aya::maps::Array<aya::maps::MapData, u64>,
) -> Result<[u64; 4], &'static str> {
    let mut values = [0u64; 4];
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
        hook.file_offset,
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
    write_json_line(&mut facts_file, serde_json::Value::Object(positive_facts))?;
    if !positive_pass {
        writeln!(verifier_log, "runtime_failure=loader_startup")
            .map_err(|_| "runtime failure write")?;
        writeln!(runner_status, "status=FAIL\nfailure_category=runtime")
            .map_err(|_| "runner status write")?;
        return Ok(false);
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
    write_json_line(&mut facts_file, serde_json::Value::Object(negative_facts))?;
    if !negative_pass {
        writeln!(verifier_log, "runtime_failure=no_cookie_negative")
            .map_err(|_| "runtime failure write")?;
    }

    let start_empty = start.keys().next().is_none();
    let pass = negative_pass && start_empty;
    writeln!(
        runner_status,
        "status={}\nfailure_category={}",
        if pass { "PASS" } else { "FAIL" },
        if pass { "none" } else { "oracle" }
    )
    .map_err(|_| "runner status write")?;
    Ok(pass)
}

fn counters_fact(values: [u64; 4]) -> serde_json::Value {
    serde_json::Value::Array(
        values
            .iter()
            .map(|value| serde_json::Value::from(*value))
            .collect(),
    )
}

fn diff_counters(before: [u64; 4], after: [u64; 4]) -> [u64; 4] {
    [
        after[0].saturating_sub(before[0]),
        after[1].saturating_sub(before[1]),
        after[2].saturating_sub(before[2]),
        after[3].saturating_sub(before[3]),
    ]
}

#[allow(clippy::too_many_arguments)]
fn run_startup_flow(
    ebpf: &mut aya::Ebpf,
    ring: &mut aya::maps::RingBuf<aya::maps::MapData>,
    counters: &aya::maps::Array<aya::maps::MapData, u64>,
    counters_before: [u64; 4],
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
                hook_file_offset: hook.file_offset,
                r_debug_vaddr: r_debug.map(|symbol| symbol.vaddr),
                delta,
            })
            .map_err(|_| "registry capacity")?;
        let cookie = common::cookie_encode(context_id, delta);
        let link = match attach_program(
            ebpf,
            hook.file_offset,
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
            if bias.is_none() {
                if let Ok(found) = loader_load_bias(
                    child.pid,
                    loader_dev_major,
                    loader_dev_minor,
                    loader_meta.ino(),
                ) {
                    bias = Some(found);
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
        let counters_delta = diff_counters(counters_before, counters_after);
        let [ring_loss, state_failures, loader_hits, state_read_failures] = counters_delta;
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
        facts.insert("counters_before".into(), counters_fact(counters_before));
        facts.insert("counters_after".into(), counters_fact(counters_after));
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
        let [ring_loss, state_failures, loader_hits, state_read_failures] =
            diff_counters(before, after);

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
        let pass = exactly_one_invalid
            && no_ip_op
            && no_state_op
            && no_case_id
            && loader_hits == 1
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
        assert!(hook.vaddr != 0 && hook.file_offset != 0);
        if let Some(r_debug) = elf_symbol(&loader_bytes, "_r_debug").unwrap() {
            let delta = (r_debug.vaddr as i64)
                .checked_sub(hook.vaddr as i64)
                .unwrap();
            assert!(delta.abs() <= (1i64 << 54));
        }
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
        let ip_index = source.find("bpf_get_func_ip").expect("IP read");
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
}
