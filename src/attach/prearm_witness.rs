//! SPDX-License-Identifier: GPL-3.0-or-later
//! Pre-arm mapping-instant witness (WU-13 P-C phase 2): short-lived startup
//! object proving no scope member had the pinned provider mapped between
//! scope start and attach-complete.

pub(crate) static WITNESS_OBJECT: &[u8] =
    aya::include_bytes_aligned!(concat!(env!("OUT_DIR"), "/p11scope-ebpf-prearm-witness"));

pub(crate) const PROGRAM_UNMAP: &str = "p11_pw_unmap";
pub(crate) const PROGRAM_DEPART_EXIT: &str = "p11_pw_depart_exit";
pub(crate) const PROGRAM_DEPART_EXEC: &str = "p11_pw_depart_exec";
pub(crate) const PROGRAM_DEPART: &str = "p11_pw_depart";
pub(crate) const PROGRAM_TORN: &str = "p11_pw_torn";
pub(crate) const PROGRAM_MIGRATE: &str = "p11_pw_migrate";
pub(crate) const PROGRAM_WALK: &str = "p11_pw_walk";

/// ABI mirrors of `crates/ebpf/native/prearm_witness.h`. Sizes are pinned by
/// the object-shape test below; change both together.
#[repr(C)]
#[derive(Clone, Copy, Debug, Default)]
pub(crate) struct PwCfg {
    pub active: u32,
    pub scope_kind: u32,
    pub target_tgid: u32,
    pub calib_tid: u32,
    pub cgroup_id: u64,
    pub calib_index: u32,
    pub pad: u32,
}

#[repr(C)]
#[derive(Clone, Copy, Debug, Default)]
pub(crate) struct PwWatchedKey {
    pub s_dev: u64,
    pub i_ino: u64,
}

#[repr(C)]
#[derive(Clone, Copy, Debug, Default)]
pub(crate) struct PwCalibSlot {
    pub hits: u64,
    pub s_dev: u64,
    pub i_ino: u64,
}

#[repr(C)]
#[derive(Clone, Copy, Debug, Default)]
pub(crate) struct PwState {
    pub busy: u64,
    pub seq: u64,
    pub latch_slots: u64,
    pub torn_slots: u64,
    pub found_slots: u64,
    pub migrations: u64,
    pub pending_in: u64,
    pub pending_out: u64,
    pub faults: u64,
    pub stuck: u64,
    pub walk_end: u64,
    pub walk_runs: u64,
    pub walk_vmas: u64,
}

const _: () = assert!(size_of::<PwCfg>() == 32);
const _: () = assert!(size_of::<PwWatchedKey>() == 16);
const _: () = assert!(size_of::<PwCalibSlot>() == 24);
const _: () = assert!(size_of::<PwState>() == 104);

// SAFETY: repr(C) with only integer fields; all bit patterns valid.
unsafe impl aya::Pod for PwCfg {}
unsafe impl aya::Pod for PwWatchedKey {}
unsafe impl aya::Pod for PwCalibSlot {}
unsafe impl aya::Pod for PwState {}

/// Load error for the witness object.
#[derive(Debug)]
pub(crate) enum LoadError {
    /// A required program is missing from the object.
    MissingProgram(&'static str),
    /// aya failed to load (includes unparseable bytes).
    Aya(String),
}

impl std::fmt::Display for LoadError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            LoadError::MissingProgram(name) => write!(f, "witness program missing: {name}"),
            LoadError::Aya(detail) => write!(f, "witness load failed: {detail}"),
        }
    }
}

impl std::error::Error for LoadError {}

/// A loaded witness object with verified programs. The departure family
/// (exit/exec pair vs single) is resolved by the caller (P2-3); this loader
/// verifies the five family-independent programs plus whichever depart
/// programs the caller names.
pub(crate) struct StrictWitness {
    pub ebpf: aya::Ebpf,
}

/// Programs to verify at load: the family-independent set plus the
/// caller's departure programs. The migrate program loads only for
/// `--cgroup` (spec §4.4).
pub(crate) fn witness_load_names(
    depart_programs: &[&'static str],
    need_migrate: bool,
) -> Vec<&'static str> {
    let mut names = vec![PROGRAM_UNMAP, PROGRAM_TORN, PROGRAM_WALK];
    if need_migrate {
        names.push(PROGRAM_MIGRATE);
    }
    names.extend(depart_programs.iter().copied());
    names
}

/// Strict load: maps plus the named programs, with CO-RE relocated against
/// readable `btf`. Every named program must verify; a missing target fails
/// here (no silent skip).
pub(crate) fn load_witness_programs(
    btf: &aya::Btf,
    depart_programs: &[&'static str],
    need_migrate: bool,
) -> Result<StrictWitness, LoadError> {
    let mut loader = aya::EbpfLoader::new();
    loader.btf(Some(btf));
    let mut ebpf = loader
        .load(WITNESS_OBJECT)
        .map_err(|error| LoadError::Aya(format!("{error:#}")))?;
    for name in witness_load_names(depart_programs, need_migrate) {
        let program = ebpf
            .program_mut(name)
            .ok_or(LoadError::MissingProgram(name))?;
        match name {
            PROGRAM_WALK => {
                let program: &mut aya::programs::Iter =
                    program
                        .try_into()
                        .map_err(|error: aya::programs::ProgramError| {
                            LoadError::Aya(format!("{error:#}"))
                        })?;
                program
                    .load(crate::attach::identity_iter::ITER_TYPE_TASK_VMA, btf)
                    .map_err(|error| LoadError::Aya(format!("{error:#}")))?;
            }
            PROGRAM_TORN => {
                let program: &mut aya::programs::FExit =
                    program
                        .try_into()
                        .map_err(|error: aya::programs::ProgramError| {
                            LoadError::Aya(format!("{error:#}"))
                        })?;
                program
                    .load("exit_mmap", btf)
                    .map_err(|error| LoadError::Aya(format!("{error:#}")))?;
            }
            PROGRAM_UNMAP => {
                let program: &mut aya::programs::FEntry =
                    program
                        .try_into()
                        .map_err(|error: aya::programs::ProgramError| {
                            LoadError::Aya(format!("{error:#}"))
                        })?;
                program
                    .load("uprobe_munmap", btf)
                    .map_err(|error| LoadError::Aya(format!("{error:#}")))?;
            }
            PROGRAM_MIGRATE => {
                let program: &mut aya::programs::FEntry =
                    program
                        .try_into()
                        .map_err(|error: aya::programs::ProgramError| {
                            LoadError::Aya(format!("{error:#}"))
                        })?;
                program
                    .load("cgroup_migrate", btf)
                    .map_err(|error| LoadError::Aya(format!("{error:#}")))?;
            }
            PROGRAM_DEPART_EXIT => {
                let program: &mut aya::programs::FEntry =
                    program
                        .try_into()
                        .map_err(|error: aya::programs::ProgramError| {
                            LoadError::Aya(format!("{error:#}"))
                        })?;
                program
                    .load("exit_mm_release", btf)
                    .map_err(|error| LoadError::Aya(format!("{error:#}")))?;
            }
            PROGRAM_DEPART_EXEC => {
                let program: &mut aya::programs::FEntry =
                    program
                        .try_into()
                        .map_err(|error: aya::programs::ProgramError| {
                            LoadError::Aya(format!("{error:#}"))
                        })?;
                program
                    .load("exec_mm_release", btf)
                    .map_err(|error| LoadError::Aya(format!("{error:#}")))?;
            }
            PROGRAM_DEPART => {
                let program: &mut aya::programs::FEntry =
                    program
                        .try_into()
                        .map_err(|error: aya::programs::ProgramError| {
                            LoadError::Aya(format!("{error:#}"))
                        })?;
                program
                    .load("mm_exit_exec_release", btf)
                    .map_err(|error| LoadError::Aya(format!("{error:#}")))?;
            }
            _ => return Err(LoadError::MissingProgram(name)),
        }
    }
    Ok(StrictWitness { ebpf })
}

/// Departure family resolved from kernel BTF.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum DepartFamily {
    /// Linux 6.6-7.2: `exit_mm_release` + `exec_mm_release`.
    Pair,
    /// Linux 7.3+: `mm_exit_exec_release`.
    Single,
}

/// Why the witness is unavailable (keeps today's output).
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) enum Unavailable {
    Btf(String),
    Lto(String),
    Ftrace(String),
    Pidns(String),
    TooManyFiles,
    /// A calibration step refused: per-file calibration (mmap, calib
    /// slot read, identity match) or the departure calibration. Kept
    /// separate from BTF problems so the diagnostic names the step —
    /// an observer in its own mount namespace fails here when its
    /// mount table cannot resolve the layer files, fail closed.
    Calibration(String),
}

impl Unavailable {
    /// Reason class for the §6.1 diagnostic line (no values).
    pub(crate) fn class(&self) -> &'static str {
        match self {
            Unavailable::Btf(_) => "btf",
            Unavailable::Lto(_) => "lto",
            Unavailable::Ftrace(_) => "ftrace",
            Unavailable::Pidns(_) => "pidns",
            Unavailable::TooManyFiles => "too-many-files",
            Unavailable::Calibration(_) => "calibration",
        }
    }
}

/// Raw BTF prototype checker following the `instance.rs` precedent: exact
/// FUNC name (exactly one), arity, return void/int, and for pointer params
/// the pointee struct name; scalar params must be integers (typedefs
/// resolved, so `bool` passes as Int).
fn btf_proto_is_exact(raw: &[u8], func: &[u8], ret_int: bool, params: &[Param]) -> bool {
    let word = |bytes: &[u8], at: usize| -> Option<u32> {
        Some(u32::from_le_bytes(
            bytes.get(at..at.checked_add(4)?)?.try_into().ok()?,
        ))
    };
    let checked = || -> Option<bool> {
        if raw.get(..4)? != [0x9f, 0xeb, 1, 0] {
            return Some(false);
        }
        let header = word(raw, 4)? as usize;
        if header < 24 {
            return Some(false);
        }
        let type_start = header.checked_add(word(raw, 8)? as usize)?;
        let type_end = type_start.checked_add(word(raw, 12)? as usize)?;
        let string_start = header.checked_add(word(raw, 16)? as usize)?;
        let string_end = string_start.checked_add(word(raw, 20)? as usize)?;
        let types = raw.get(type_start..type_end)?;
        let strings = raw.get(string_start..string_end)?;
        let name = |offset: u32| -> Option<&[u8]> {
            let tail = strings.get(offset as usize..)?;
            Some(&tail[..tail.iter().position(|byte| *byte == 0)?])
        };
        let mut nodes = vec![&[][..]];
        let mut cursor = 0usize;
        while cursor < types.len() {
            let record = types.get(cursor..)?;
            let info = word(record, 4)?;
            let kind = (info >> 24) & 31;
            let count = (info & 65535) as usize;
            let extra = match kind {
                0 | 2 | 7 | 8 | 9 | 10 | 11 | 12 | 16 | 18 => 0,
                1 | 14 | 17 => 4,
                3 => 12,
                4 | 5 | 15 | 19 => count.checked_mul(12)?,
                6 | 13 => count.checked_mul(8)?,
                _ => return Some(false),
            };
            let length = 12usize.checked_add(extra)?;
            nodes.push(record.get(..length)?);
            cursor = cursor.checked_add(length)?;
        }
        let resolve = |mut id: u32| -> Option<&[u8]> {
            for _ in 0..32 {
                let node = *nodes.get(id as usize)?;
                let kind = (word(node, 4)? >> 24) & 31;
                if !matches!(kind, 8 | 9 | 10 | 11 | 18) {
                    return Some(node);
                }
                id = word(node, 8)?;
            }
            None
        };
        let node_kind = |node: &[u8]| -> Option<u32> { Some((word(node, 4)? >> 24) & 31) };
        let mut functions = nodes.iter().skip(1).filter(|node| {
            word(node, 4).is_some_and(|info| (info >> 24) & 31 == 12)
                && word(node, 0).and_then(name) == Some(func)
        });
        let function = functions.next()?;
        if functions.next().is_some() {
            return Some(false);
        }
        let proto = resolve(word(function, 8)?)?;
        if node_kind(proto)? != 13 {
            return Some(false);
        }
        let vlen = (word(proto, 4)? & 65535) as usize;
        if vlen != params.len() {
            return Some(false);
        }
        let ret_id = word(proto, 8)?;
        if ret_int {
            let ret = resolve(ret_id)?;
            if node_kind(ret)? != 1 {
                return Some(false);
            }
        } else if ret_id != 0 {
            return Some(false);
        }
        for (index, want) in params.iter().enumerate() {
            let param_id = word(proto, 16 + index * 8)?;
            match want {
                Param::Int => {
                    let param = resolve(param_id)?;
                    if node_kind(param)? != 1 {
                        return Some(false);
                    }
                }
                Param::Ptr(struct_name) => {
                    let pointer = resolve(param_id)?;
                    if node_kind(pointer)? != 2 {
                        return Some(false);
                    }
                    let target = resolve(word(pointer, 8)?)?;
                    if node_kind(target)? != 4 {
                        return Some(false);
                    }
                    if name(word(target, 0)?)? != struct_name.as_bytes() {
                        return Some(false);
                    }
                }
            }
        }
        Some(true)
    };
    checked().unwrap_or(false)
}

#[derive(Clone, Copy)]
enum Param {
    Int,
    Ptr(&'static str),
}

fn exit_mm_proto_is_exact(raw: &[u8]) -> bool {
    btf_proto_is_exact(
        raw,
        b"exit_mm_release",
        false,
        &[Param::Ptr("task_struct"), Param::Ptr("mm_struct")],
    )
}

fn mm_exit_exec_proto_is_exact(raw: &[u8]) -> bool {
    btf_proto_is_exact(
        raw,
        b"mm_exit_exec_release",
        false,
        &[Param::Ptr("task_struct"), Param::Ptr("mm_struct")],
    )
}

fn unmap_proto_is_exact(raw: &[u8]) -> bool {
    btf_proto_is_exact(
        raw,
        b"uprobe_munmap",
        false,
        &[Param::Ptr("vm_area_struct"), Param::Int, Param::Int],
    )
}

fn exit_mmap_proto_is_exact(raw: &[u8]) -> bool {
    btf_proto_is_exact(raw, b"exit_mmap", false, &[Param::Ptr("mm_struct")])
}

fn migrate_proto_is_exact(raw: &[u8]) -> bool {
    btf_proto_is_exact(
        raw,
        b"cgroup_migrate",
        true,
        &[
            Param::Ptr("task_struct"),
            Param::Int,
            Param::Ptr("cgroup_mgctx"),
        ],
    )
}

/// Resolve the departure family from raw host BTF: exactly one of the
/// 6.6-7.2 pair or the 7.3+ single, each with an exact prototype.
pub(crate) fn resolve_depart_family(raw_btf: &[u8]) -> Result<DepartFamily, Unavailable> {
    let pair =
        exit_mm_proto_is_exact(raw_btf) && super::instance::exec_release_proto_is_exact(raw_btf);
    let single = mm_exit_exec_proto_is_exact(raw_btf);
    match (pair, single) {
        (true, false) => Ok(DepartFamily::Pair),
        (false, true) => Ok(DepartFamily::Single),
        _ => Err(Unavailable::Btf(
            "no exact departure family: need the exit/exec pair or the single".into(),
        )),
    }
}

/// Check every witness target prototype; `need_migrate` is true for
/// `--cgroup` only. The departure family must resolve exactly.
pub(crate) fn check_target_protos(raw_btf: &[u8], need_migrate: bool) -> Result<(), Unavailable> {
    if !unmap_proto_is_exact(raw_btf) {
        return Err(Unavailable::Btf(
            "no exact uprobe_munmap hook: void(vm_area_struct *, start, end)".into(),
        ));
    }
    if !exit_mmap_proto_is_exact(raw_btf) {
        return Err(Unavailable::Btf(
            "no exact exit_mmap hook: void(mm_struct *)".into(),
        ));
    }
    if need_migrate && !migrate_proto_is_exact(raw_btf) {
        return Err(Unavailable::Btf(
            "no exact cgroup_migrate hook: int(task_struct *, threadgroup, cgroup_mgctx *)".into(),
        ));
    }
    resolve_depart_family(raw_btf).map(|_| ())
}

/// Startup gates: file count, PID namespace, ftrace, LTO (addendum §8.1).
pub(crate) fn gate_startup(
    paths_len: usize,
    pidns_initial: bool,
    ftrace_enabled: Option<String>,
    lto_refusal: Option<String>,
) -> Result<(), Unavailable> {
    if !(1..=64).contains(&paths_len) {
        return Err(Unavailable::TooManyFiles);
    }
    if !pidns_initial {
        return Err(Unavailable::Pidns(
            "witness needs the initial PID namespace".into(),
        ));
    }
    match ftrace_enabled.as_deref().map(str::trim) {
        Some("1") => {}
        _ => {
            return Err(Unavailable::Ftrace(
                "witness needs /proc/sys/kernel/ftrace_enabled = 1".into(),
            ));
        }
    }
    if let Some(reason) = lto_refusal {
        return Err(Unavailable::Lto(reason));
    }
    Ok(())
}

// P2-4 startup driver seam (RED stubs).

/// Scriptable kernel backend for `start_with`: map writes/reads, attach.
/// Production uses live aya maps; tests script every return.
pub(crate) trait WitnessBackend {
    type Error: std::fmt::Debug;
    fn write_cfg(&mut self, cfg: &PwCfg) -> Result<(), Self::Error>;
    fn attach(&mut self, family: DepartFamily, need_migrate: bool) -> Result<(), Self::Error>;
    fn read_calib(&mut self, index: u32) -> Result<PwCalibSlot, Self::Error>;
    fn read_self_departs(&mut self) -> Result<u64, Self::Error>;
    fn insert_watched(&mut self, key: &PwWatchedKey, slot: u32) -> Result<(), Self::Error>;
}

/// One calibrated pre-arm file: held fd, fstat identity, kernel key.
pub(crate) struct WitnessFile {
    #[allow(dead_code)]
    pub fd: std::os::fd::OwnedFd,
    /// fstat identity for the P2-6 pin comparison (kernel key above is for BPF).
    #[allow(dead_code)]
    pub dev: u64,
    #[allow(dead_code)]
    pub ino: u64,
    /// The witness fd's open-time `(ino, size, ctime)`: condition 4
    /// requires it to equal the pre-arm pin's held baseline (a copy-up
    /// between the witness start and the pin rewrites ctime — size is
    /// preserved — while the overlay `(dev, ino)` stays stable, so the
    /// proof relies on ctime), and finalize re-checks it.
    pub pin: crate::discovery::identity::Pin,
    pub key: PwWatchedKey,
}

/// Started witness awaiting finalize (P2-5 owns the walk/close).
pub(crate) struct StartupWitness<B> {
    #[allow(dead_code)]
    pub backend: B,
    pub files: Vec<WitnessFile>,
    pub active_ns: u64,
    /// The scope-start stamp the witness precedes, recorded by the engine
    /// right after `set_scope_start_ns` (§6.2). `None` until recorded.
    pub scope_start_ns: Option<u64>,
}

impl<B: FinalizeBackend> StartupWitness<B> {
    /// Driver finalize (§6.1): `owned` drops the witness and yields no
    /// verdict; otherwise stamp the walk start, run the walk and close,
    /// and assemble per-slot verdicts with their fd identities.
    pub(crate) fn finalize(mut self, owned: bool) -> Option<WitnessVerdict> {
        if owned {
            return None;
        }
        let walk_started_ns = crate::attach::monotonic_ns().unwrap_or(0);
        let ftrace = std::fs::read_to_string("/proc/sys/kernel/ftrace_enabled").ok();
        let verdicts = finalize_with(&mut self.backend, self.files.len(), ftrace);
        let slots = verdicts
            .into_iter()
            .zip(self.files.iter())
            .map(|(verdict, file)| {
                // The witness fd's own pin re-check: a change between
                // startup and finalize (a copy-up rewrites ctime; size is
                // preserved) voids the calibration-time key, so the slot
                // keeps its window even when the walk was clean.
                use std::os::unix::io::AsFd as _;
                let unchanged = crate::discovery::identity::pin_of_fd(file.fd.as_fd())
                    .is_ok_and(|current| current == file.pin);
                WitnessSlot {
                    verdict: if unchanged {
                        verdict
                    } else {
                        FileVerdict::Keep(KeepReason::Calibration)
                    },
                    fd_dev: file.dev,
                    fd_ino: file.ino,
                    pin: file.pin,
                }
            })
            .collect();
        Some(WitnessVerdict {
            active_ns: self.active_ns,
            scope_start_ns: self.scope_start_ns,
            walk_started_ns,
            slots,
        })
    }
}

/// `stat()` of one `map_files` entry while the range is still mapped.
fn map_file_identity(start: u64, end: u64) -> std::result::Result<(u64, u64), String> {
    use std::os::unix::fs::MetadataExt as _;
    let link = std::path::PathBuf::from(format!("/proc/self/map_files/{start:x}-{end:x}"));
    let metadata = std::fs::metadata(&link)
        .map_err(|error| format!("identity of mapped range {start:x}-{end:x}: {error}"))?;
    Ok((metadata.dev(), metadata.ino()))
}

/// Whether the upper layer file is a metadata-only copy-up: the kernel
/// marks those with the `trusted.overlay.metacopy` xattr. Presence is
/// the marker — the value is empty on current kernels (measured
/// 7.0.0-38: the xattr lists, reads 0 bytes, and the file serves the
/// lower data), or 4 bytes plus the digest with verity; the probe reads
/// presence only, so both forms report true. Any probe failure
/// (unprivileged `trusted.*` reads, no xattr) reports false — the
/// fallback then refuses a lower match, fail closed.
pub(crate) fn upper_is_metacopy(upper: &std::path::Path) -> bool {
    upper_is_metacopy_with(upper, |path, name| {
        // SAFETY: path and name are NUL-terminated; a NULL value with
        // size 0 probes presence (returns the value size, 0 for the
        // empty marker). lgetxattr never follows a trailing symlink.
        unsafe { libc::lgetxattr(path.as_ptr(), name.as_ptr(), std::ptr::null_mut(), 0) }
    })
}

/// [`upper_is_metacopy`] with an injectable presence probe (unprivileged
/// unit tests cannot fabricate a `trusted.*` xattr).
fn upper_is_metacopy_with(
    upper: &std::path::Path,
    probe: impl Fn(&std::ffi::CStr, &std::ffi::CStr) -> libc::ssize_t,
) -> bool {
    use std::os::unix::ffi::OsStrExt as _;
    let path = match std::ffi::CString::new(upper.as_os_str().as_bytes()) {
        Ok(path) => path,
        Err(_) => return false,
    };
    let name = c"trusted.overlay.metacopy";
    probe(path.as_c_str(), name) >= 0
}

/// Backing-vs-backing acceptance for an overlay split: the BPF slot
/// carries the backing inode while the mapped-range identity carries
/// the overlay (xino) inode, so direct equality can never hold there.
/// Only the topmost existing layer entry selects the backing file —
/// the upper when it exists, else the first lower that has the path —
/// so a stale lower inode under a live upper copy refuses. A lower
/// match under an existing upper is allowed only for a metacopy
/// upper, which still backs reads from the lower file. Layer files
/// are read with `symlink_metadata` and must be regular files.
/// `table` is the observer mount table, read once per start through
/// the capture budget by the caller. Fail closed: unreadable tables,
/// unstatable candidates, escapes and non-overlay paths all refuse.
fn calibration_backing_accepted(merged: &std::path::Path, slot_ino: u64, table: &str) -> bool {
    calibration_backing_accepted_with(merged, slot_ino, table, upper_is_metacopy)
}

/// [`calibration_backing_accepted`] with an injectable metacopy probe
/// (the live `trusted.overlay.metacopy` read needs a real metacopy
/// upper, which unprivileged unit tests cannot fabricate).
fn calibration_backing_accepted_with(
    merged: &std::path::Path,
    slot_ino: u64,
    table: &str,
    is_metacopy: impl Fn(&std::path::Path) -> bool,
) -> bool {
    let merged = std::fs::canonicalize(merged).unwrap_or_else(|_| merged.to_path_buf());
    // One layer entry's backing inode: `Ok(None)` when the layer holds
    // no entry at all, `Ok(Some)` for a regular file, `Err` for a
    // non-regular entry (whiteout, symlink, directory) — the topmost
    // existing entry selects the backing file, so a non-regular topmost
    // entry refuses instead of falling through. Read with
    // `symlink_metadata`, which only skips the last path component;
    // intermediate symlinks are still followed.
    fn layer_entry(path: &std::path::Path) -> Result<Option<u64>, ()> {
        use std::os::unix::fs::MetadataExt as _;
        let meta = match std::fs::symlink_metadata(path) {
            Ok(meta) => meta,
            Err(_) => return Ok(None),
        };
        if meta.file_type().is_file() {
            Ok(Some(meta.ino()))
        } else {
            Err(())
        }
    }
    let upper = crate::discovery::scan::upper_candidate_from_mountinfo(table, &merged);
    let upper_ino = match upper.as_deref().map(layer_entry) {
        None | Some(Ok(None)) => None,
        Some(Ok(Some(ino))) => Some(ino),
        Some(Err(())) => return false,
    };
    let mut lower_ino = None;
    for candidate in crate::discovery::scan::lower_candidates_from_mountinfo(table, &merged) {
        match layer_entry(&candidate) {
            Ok(None) => continue,
            Ok(Some(ino)) => {
                lower_ino = Some(ino);
                break;
            }
            Err(()) => return false,
        }
    }
    match (upper_ino, lower_ino) {
        // The topmost existing entry selects the backing file.
        (Some(upper), _) if slot_ino == upper => true,
        (None, Some(lower)) if slot_ino == lower => true,
        // A metadata-only upper still backs reads from the lower file.
        (Some(_), Some(lower))
            if upper.as_deref().is_some_and(&is_metacopy) && slot_ino == lower =>
        {
            true
        }
        _ => false,
    }
}

/// Test seam: an observer fired between the witness `open()` and its
/// fstat in `start_with`, so unprivileged twins can mutate the file in
/// that window (the live copy-up the pre-open pin refuses). Production
/// builds fire nothing.
#[cfg(test)]
pub(crate) mod open_race_test {
    use std::cell::RefCell;

    type Observer = Box<dyn FnMut(&std::path::Path)>;
    thread_local! {
        static OBSERVER: RefCell<Option<Observer>> = RefCell::new(None);
    }

    struct Restore(Option<Observer>);
    impl Drop for Restore {
        fn drop(&mut self) {
            OBSERVER.with(|observer| observer.replace(self.0.take()));
        }
    }

    pub(crate) fn observe<T>(
        observer: impl FnMut(&std::path::Path) + 'static,
        run: impl FnOnce() -> T,
    ) -> T {
        let previous = OBSERVER.with(|current| current.replace(Some(Box::new(observer))));
        let _restore = Restore(previous);
        run()
    }

    pub(super) fn fired(path: &std::path::Path) {
        OBSERVER.with(|observer| {
            if let Some(observer) = observer.borrow_mut().as_mut() {
                observer(path);
            }
        });
    }
}

/// Start the witness: open + calibrate each file, departure calibration,
/// insert keys, activate. Pure over the backend seam; file syscalls are
/// real (temp files in tests, provider paths in production).
#[allow(clippy::too_many_arguments)]
pub(crate) fn start_with<B: WitnessBackend>(
    paths: &[std::path::PathBuf],
    scope_kind: u32,
    target_tgid: u32,
    cgroup_id: u64,
    need_migrate: bool,
    family: DepartFamily,
    mut backend: B,
    clock: impl Fn() -> u64,
    budget: &mut crate::discovery::scan::CaptureWorkBudget,
) -> Result<StartupWitness<B>, Unavailable> {
    if paths.is_empty() || paths.len() > 64 {
        return Err(Unavailable::TooManyFiles);
    }
    // Open each path, require a regular file, keep fd + fstat.
    use std::os::unix::fs::OpenOptionsExt as _;
    let mut opened: Vec<(
        std::path::PathBuf,
        std::os::fd::OwnedFd,
        u64,
        u64,
        crate::discovery::identity::Pin,
    )> = Vec::new();
    for path in paths {
        // The pre-open pin: a copy-up landing between open() and the
        // open-time pin below would leave the calibration mmap on the
        // lower file while the recorded pin reads post-copy-up state.
        // Copy-up is one-way and always rewrites ctime, so equal pins
        // across the stat→fstat span mean the held fd has the recorded
        // state.
        let pre = crate::discovery::identity::pin_from_metadata(&std::fs::metadata(path).map_err(
            |_| Unavailable::Calibration(format!("witness cannot stat {}", path.display())),
        )?);
        let file = std::fs::OpenOptions::new()
            .read(true)
            .custom_flags(libc::O_NONBLOCK | libc::O_NOCTTY | libc::O_CLOEXEC)
            .open(path)
            .map_err(|_| {
                Unavailable::Calibration(format!("witness cannot open {}", path.display()))
            })?;
        #[cfg(test)]
        open_race_test::fired(path);
        let meta = file
            .metadata()
            .map_err(|_| Unavailable::Calibration("witness fstat failed".into()))?;
        if !meta.file_type().is_file() {
            return Err(Unavailable::Btf(format!(
                "witness needs regular files: {}",
                path.display()
            )));
        }
        // The open-time pin condition 4 joins against the pre-arm pin's
        // held baseline: recorded here, and required to equal the
        // pre-open pin, so a copy-up inside the open window refuses.
        let open_pin = crate::discovery::identity::pin_of(&file)
            .map_err(|_| Unavailable::Calibration("witness fstat failed".into()))?;
        if open_pin != pre {
            return Err(Unavailable::Calibration(
                "witness file changed while opening".into(),
            ));
        }
        use std::os::unix::fs::MetadataExt as _;
        use std::os::unix::io::{FromRawFd as _, IntoRawFd as _};
        let (dev, ino) = (meta.dev(), meta.ino());
        let raw = file.into_raw_fd();
        // SAFETY: owned fd from an open File.
        let fd = unsafe { std::os::fd::OwnedFd::from_raw_fd(raw) };
        opened.push((path.clone(), fd, dev, ino, open_pin));
    }
    // Inactive cfg, then attach.
    let mut cfg = PwCfg {
        active: 0,
        scope_kind,
        target_tgid,
        calib_tid: 0,
        cgroup_id,
        calib_index: 0,
        pad: 0,
    };
    backend
        .write_cfg(&cfg)
        .map_err(|error| Unavailable::Btf(format!("witness cfg write: {error:?}")))?;
    backend
        .attach(family, need_migrate)
        .map_err(|error| Unavailable::Btf(format!("witness attach: {error:?}")))?;
    // Per-file unmap calibration.
    // SAFETY: gettid has no preconditions.
    let tid = unsafe { libc::syscall(libc::SYS_gettid) } as u32;
    // The observer mount table, read once and lazily through the bounded
    // reader: only a direct calibration mismatch needs it, and one read
    // serves every file of this start. A failed read refuses (fail
    // closed) without retrying per file.
    let mut mountinfo_cache: Option<Option<String>> = None;
    let mut files: Vec<WitnessFile> = Vec::new();
    for (index, (path, fd, dev, ino, open_pin)) in opened.into_iter().enumerate() {
        cfg.calib_tid = tid;
        cfg.calib_index = index as u32;
        backend
            .write_cfg(&cfg)
            .map_err(|error| Unavailable::Calibration(format!("witness calib cfg: {error:?}")))?;
        use std::os::unix::io::AsRawFd as _;
        // SAFETY: fresh private read-only mapping of an open regular file.
        let addr = unsafe {
            libc::mmap(
                std::ptr::null_mut(),
                4096,
                libc::PROT_READ,
                libc::MAP_PRIVATE,
                fd.as_raw_fd(),
                0,
            )
        };
        if addr == libc::MAP_FAILED {
            return Err(Unavailable::Calibration(
                "witness calibration mmap failed".into(),
            ));
        }
        let start = addr as u64;
        // Prefer the mapped-range identity (as instance calibrate does);
        // fall back to the held fd's fstat when map_files is unreadable
        // (unprivileged unit tests; same file either way).
        let identity = map_file_identity(start, start + 4096).unwrap_or((dev, ino));
        // SAFETY: exactly the mapping created above.
        unsafe { libc::munmap(addr, 4096) };
        let slot = backend
            .read_calib(index as u32)
            .map_err(|error| Unavailable::Calibration(format!("witness calib read: {error:?}")))?;
        if slot.hits != 1 || slot.i_ino == 0 {
            return Err(Unavailable::Calibration(
                "witness calibration mismatch".into(),
            ));
        }
        // Note: s_dev is not compared (Btrfs st_dev differs from the
        // mapped s_dev); the inode plus the held fd identify the file,
        // and the kernel key below carries the true s_dev for BPF.
        // On xino overlay files the slot carries the backing inode
        // while the mapped-range identity carries the overlay inode,
        // so a direct mismatch falls back to backing-vs-backing
        // through the layer candidates — never fstat against maps.
        if slot.i_ino != identity.1 {
            let cached = mountinfo_cache.get_or_insert_with(|| {
                std::fs::File::open("/proc/self/mountinfo")
                    .ok()
                    .and_then(|table| crate::discovery::scan::read_mountinfo(table, budget).ok())
            });
            let accepted = cached
                .as_deref()
                .is_some_and(|table| calibration_backing_accepted(&path, slot.i_ino, table));
            if !accepted {
                return Err(Unavailable::Calibration(
                    "witness calibration mismatch".into(),
                ));
            }
        }
        files.push(WitnessFile {
            fd,
            dev,
            ino,
            pin: open_pin,
            key: PwWatchedKey {
                s_dev: slot.s_dev,
                i_ino: slot.i_ino,
            },
        });
    }
    // Departure calibration: one thread exit must self-depart.
    let departed = std::thread::spawn(|| {}).join().is_ok();
    if !departed {
        return Err(Unavailable::Calibration(
            "witness departure thread failed".into(),
        ));
    }
    let self_departs = backend
        .read_self_departs()
        .map_err(|error| Unavailable::Calibration(format!("witness departs read: {error:?}")))?;
    if self_departs < 1 {
        return Err(Unavailable::Calibration(
            "witness departure calibration missed".into(),
        ));
    }
    // Insert keys, then activate; stamp after the write.
    for (slot, file) in files.iter().enumerate() {
        backend
            .insert_watched(&file.key, slot as u32)
            .map_err(|error| Unavailable::Btf(format!("witness key insert: {error:?}")))?;
    }
    cfg.active = 1;
    cfg.calib_tid = 0;
    backend
        .write_cfg(&cfg)
        .map_err(|error| Unavailable::Btf(format!("witness activate: {error:?}")))?;
    let active_ns = clock();
    Ok(StartupWitness {
        backend,
        files,
        active_ns,
        scope_start_ns: None,
    })
}

/// Live kernel backend: real aya maps + held attach links.
/// Presence-walk deadline (§4.5, §9.3): 10 s, fails closed. An
/// engineering limit to raise when measured.
pub(crate) const WITNESS_WALK_DEADLINE: std::time::Duration = std::time::Duration::from_secs(10);

pub(crate) struct LiveBackend {
    ebpf: aya::Ebpf,
    #[allow(dead_code)]
    links: Vec<Box<dyn std::any::Any>>,
    last_cfg: PwCfg,
    pidfd: Option<std::os::fd::OwnedFd>,
    #[cfg(test)]
    last_active: u32,
    /// Last walk's `EAGAIN` resumptions and wall time (P2-7 scale cell).
    #[cfg(test)]
    last_walk_resumptions: u64,
    #[cfg(test)]
    last_walk_ns: u64,
}

impl LiveBackend {
    pub(crate) fn from_loaded(ebpf: aya::Ebpf) -> Self {
        Self {
            ebpf,
            links: Vec::new(),
            last_cfg: PwCfg::default(),
            pidfd: None,
            #[cfg(test)]
            last_active: 0,
            #[cfg(test)]
            last_walk_resumptions: 0,
            #[cfg(test)]
            last_walk_ns: 0,
        }
    }

    /// Last walk's measurement: (`EAGAIN` resumptions, wall nanoseconds).
    #[cfg(test)]
    pub(crate) fn last_walk_measurement(&self) -> (u64, u64) {
        (self.last_walk_resumptions, self.last_walk_ns)
    }

    pub(crate) fn set_pidfd(&mut self, pidfd: Option<std::os::fd::OwnedFd>) {
        self.pidfd = pidfd;
    }

    /// Last written `active` (privileged twin check; avoids a CFG map read
    /// so the STATE/CALIB-only contract holds).
    #[cfg(test)]
    pub(crate) fn read_active(&self) -> Result<u32, String> {
        Ok(self.last_active)
    }
}

impl WitnessBackend for LiveBackend {
    type Error = String;
    fn write_cfg(&mut self, cfg: &PwCfg) -> Result<(), String> {
        use aya::maps::{Array, MapData};
        let mut map: Array<&mut MapData, PwCfg> = Array::try_from(
            self.ebpf
                .map_mut("PW_CFG")
                .ok_or_else(|| "missing PW_CFG map".to_string())?,
        )
        .map_err(|e| format!("{e:?}"))?;
        map.set(0, *cfg, 0).map_err(|e| format!("{e:?}"))?;
        self.last_cfg = *cfg;
        #[cfg(test)]
        {
            self.last_active = cfg.active;
        }
        Ok(())
    }
    fn attach(&mut self, family: DepartFamily, need_migrate: bool) -> Result<(), String> {
        let mut names = vec![PROGRAM_UNMAP, PROGRAM_TORN];
        if need_migrate {
            names.push(PROGRAM_MIGRATE);
        }
        match family {
            DepartFamily::Pair => {
                names.push(PROGRAM_DEPART_EXIT);
                names.push(PROGRAM_DEPART_EXEC);
            }
            DepartFamily::Single => names.push(PROGRAM_DEPART),
        }
        for name in names {
            if name == PROGRAM_TORN {
                let program: &mut aya::programs::FExit = self
                    .ebpf
                    .program_mut(name)
                    .ok_or_else(|| format!("missing program {name}"))?
                    .try_into()
                    .map_err(|e: aya::programs::ProgramError| format!("{e:?}"))?;
                let link = program.attach().map_err(|e| format!("{e:?}"))?;
                self.links.push(Box::new(link));
                continue;
            }
            let program: &mut aya::programs::FEntry = self
                .ebpf
                .program_mut(name)
                .ok_or_else(|| format!("missing program {name}"))?
                .try_into()
                .map_err(|e: aya::programs::ProgramError| format!("{e:?}"))?;
            let link = program.attach().map_err(|e| format!("{e:?}"))?;
            self.links.push(Box::new(link));
        }
        Ok(())
    }
    fn read_calib(&mut self, index: u32) -> Result<PwCalibSlot, String> {
        use aya::maps::{Array, MapData};
        let map: Array<&MapData, PwCalibSlot> = Array::try_from(
            self.ebpf
                .map("PW_CALIB")
                .ok_or_else(|| "missing PW_CALIB map".to_string())?,
        )
        .map_err(|e| format!("{e:?}"))?;
        map.get(&index, 0).map_err(|e| format!("{e:?}"))
    }
    fn read_self_departs(&mut self) -> Result<u64, String> {
        use aya::maps::{Array, MapData};
        let map: Array<&MapData, PwCalibSlot> = Array::try_from(
            self.ebpf
                .map("PW_CALIB")
                .ok_or_else(|| "missing PW_CALIB map".to_string())?,
        )
        .map_err(|e| format!("{e:?}"))?;
        map.get(&64, 0)
            .map(|slot| slot.hits)
            .map_err(|e| format!("{e:?}"))
    }
    fn insert_watched(&mut self, key: &PwWatchedKey, slot: u32) -> Result<(), String> {
        use aya::maps::HashMap;
        let mut map: HashMap<_, PwWatchedKey, u32> = HashMap::try_from(
            self.ebpf
                .map_mut("PW_WATCHED")
                .ok_or_else(|| "missing PW_WATCHED map".to_string())?,
        )
        .map_err(|e| format!("{e:?}"))?;
        map.insert(key, slot, 0).map_err(|e| format!("{e:?}"))
    }
}

/// `bpf_prog_info` prefix through `recursion_misses` (mirrors instance.rs).
#[repr(C)]
struct WitnessProgInfo {
    head: [u8; 192],
    run_time_ns: u64,
    run_cnt: u64,
    recursion_misses: u64,
}

fn witness_prog_misses(fd: std::os::fd::BorrowedFd<'_>) -> std::result::Result<u64, String> {
    use std::os::unix::io::AsRawFd as _;
    #[repr(C)]
    #[derive(Default)]
    struct Attr {
        bpf_fd: u32,
        info_len: u32,
        info: u64,
    }
    let mut info = WitnessProgInfo {
        head: [0; 192],
        run_time_ns: 0,
        run_cnt: 0,
        recursion_misses: 0,
    };
    let mut attr = Attr {
        bpf_fd: fd.as_raw_fd() as u32,
        info_len: size_of_val(&info) as u32,
        info: (&mut info as *mut WitnessProgInfo) as u64,
    };
    // SAFETY: BPF_OBJ_GET_INFO_BY_FD (15) with a live attr and buffer.
    let rc = unsafe {
        libc::syscall(
            libc::SYS_bpf,
            15u32,
            &mut attr as *mut Attr,
            size_of_val(&attr),
        )
    };
    if rc == -1 {
        return Err(format!("prog info: {}", std::io::Error::last_os_error()));
    }
    if attr.info_len < 216 {
        return Err("prog info omits recursion misses".into());
    }
    Ok(info.recursion_misses)
}

impl FinalizeBackend for LiveBackend {
    type Error = String;
    fn run_walk(&mut self) -> Result<WalkOutcome, String> {
        use std::os::fd::AsFd as _;
        let prog_fd = self
            .ebpf
            .program(PROGRAM_WALK)
            .ok_or_else(|| "missing walk program".to_string())?
            .fd()
            .map_err(|e| format!("{e:?}"))?
            .as_fd()
            .try_clone_to_owned()
            .map_err(|e| format!("{e:?}"))?;
        let link = crate::attach::identity_iter::link_create_task_vma(
            prog_fd.as_fd(),
            self.pidfd.as_ref().map(|fd| fd.as_fd()),
        )
        .map_err(|e| format!("link: {e:?}"))?;
        let iter = crate::attach::identity_iter::iter_create(link.as_fd())
            .map_err(|e| format!("iter: {e:?}"))?;
        // The walk program writes no bytes: cap 0 fails closed on any
        // output. EAGAIN resumes the same iterator (§4.5); the deadline
        // and any read error fail the walk.
        let started = std::time::Instant::now();
        let (result, _resumptions) = crate::attach::identity_iter::read_run_counted(
            iter.as_fd(),
            started + WITNESS_WALK_DEADLINE,
            0,
        );
        #[cfg(test)]
        {
            self.last_walk_resumptions = _resumptions;
            self.last_walk_ns = started.elapsed().as_nanos() as u64;
        }
        match result {
            Ok(_) => Ok(WalkOutcome::Done),
            Err(error) => Ok(WalkOutcome::Fatal(format!("{error:?}"))),
        }
    }
    fn read_state(&mut self) -> Result<PwState, String> {
        use aya::maps::{Array, MapData};
        let map: Array<&MapData, PwState> = Array::try_from(
            self.ebpf
                .map("PW_STATE")
                .ok_or_else(|| "missing PW_STATE map".to_string())?,
        )
        .map_err(|e| format!("{e:?}"))?;
        map.get(&0, 0).map_err(|e| format!("{e:?}"))
    }
    fn deactivate(&mut self) -> Result<(), String> {
        // Rewrite the cached cfg with active = 0 (no CFG map read).
        let mut cfg = self.last_cfg;
        cfg.active = 0;
        cfg.calib_tid = 0;
        self.write_cfg(&cfg).map(|_| ())
    }
    fn settle_busy(&mut self, max_flips: u32) -> Result<bool, String> {
        for _ in 0..=max_flips {
            if self.read_state()?.busy == 0 {
                return Ok(true);
            }
            std::thread::sleep(std::time::Duration::from_millis(1));
        }
        Ok(self.read_state()?.busy == 0)
    }
    fn release(&mut self) -> Result<(), String> {
        self.links.clear();
        Ok(())
    }
    fn recursion_misses(&mut self, program: &str) -> Result<u64, String> {
        use std::os::fd::AsFd as _;
        let Some(prog) = self.ebpf.program(program) else {
            return Ok(0);
        };
        let Ok(fd) = prog.fd() else {
            return Ok(0);
        };
        witness_prog_misses(fd.as_fd())
    }
}

// P2-5 finalize seam (RED stubs).

/// One walk attempt outcome.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) enum WalkOutcome {
    /// Walk reached END cleanly (EAGAIN resumptions included).
    Done,
    /// Walk failure (create, read error, deadline, output): keep windows.
    Fatal(String),
}

/// Per-file finalize verdict (P-C phase 2, §6.1: clean or a reason).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum FileVerdict {
    /// All conditions hold: the engine may clear the window.
    Clear,
    /// Keep today's window, for the named reason.
    Keep(KeepReason),
}

/// Why a slot keeps today's window: the §6.1 vocabulary over §8 groups 3-5.
/// Global reasons (walk, close, evidence) apply to every slot; per-slot
/// latch/torn/found apply to their slot only.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum KeepReason {
    /// `latch_slots` has this slot's bit (§8 group 5).
    Latched,
    /// `torn_slots` has this slot's bit (§8 group 5).
    Torn,
    /// `found_slots` has this slot's bit (§8 group 5).
    Found,
    /// A scope member migrated out while active (§8 group 5).
    Migration,
    /// Departures still unresolved at close (§8 group 5).
    Pending,
    /// Kernel faults, or an unreadable close-time state (§8 groups 4-5).
    Fault,
    /// A stuck iterator or hook at close (§8 group 5).
    Stuck,
    /// Verifier recursion misses on a witness program (§8 group 4).
    Recursion,
    /// `ftrace_enabled` dropped before close (§8 group 4).
    Ftrace,
    /// Walk failure: link/iterator, read error, deadline, or END count
    /// (§8 group 3).
    Walk,
    /// The close never quiesced (§8 group 4).
    Quiesce,
    /// The witness fd's own pin changed between startup and finalize
    /// (a copy-up rewrites ctime): the slot keeps its window even when
    /// the walk was clean. `start_with` calibration failures abort with
    /// `Unavailable` before any verdict exists; only `finalize` emits
    /// this reason.
    Calibration,
}

impl KeepReason {
    /// The exact §6.1 lowercase spelling, for twin assertions.
    #[cfg(test)]
    pub(crate) fn as_str(self) -> &'static str {
        match self {
            Self::Latched => "latched",
            Self::Torn => "torn",
            Self::Found => "found",
            Self::Migration => "migration",
            Self::Pending => "pending",
            Self::Fault => "fault",
            Self::Stuck => "stuck",
            Self::Recursion => "recursion",
            Self::Ftrace => "ftrace",
            Self::Walk => "walk",
            Self::Quiesce => "quiesce",
            Self::Calibration => "calibration",
        }
    }

    /// Every §6.1 reason, for exhaustive twin coverage.
    #[cfg(test)]
    pub(crate) fn all() -> [Self; 12] {
        [
            Self::Latched,
            Self::Torn,
            Self::Found,
            Self::Migration,
            Self::Pending,
            Self::Fault,
            Self::Stuck,
            Self::Recursion,
            Self::Ftrace,
            Self::Walk,
            Self::Quiesce,
            Self::Calibration,
        ]
    }
}

/// One finalized slot: the per-slot verdict plus the witness fd identity
/// the engine matches against the trusted pin (§6.1).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct WitnessSlot {
    pub(crate) verdict: FileVerdict,
    pub(crate) fd_dev: u64,
    pub(crate) fd_ino: u64,
    /// The witness fd's open-time pin, for the condition-4 baseline join.
    pub(crate) pin: crate::discovery::identity::Pin,
}

/// The driver's finalize product (§6.1): stamps plus one slot per input
/// path, in input order. The engine keys slots to objects by pin identity
/// and adds the recorded scope stamp (engine domain) per object.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct WitnessVerdict {
    pub(crate) active_ns: u64,
    pub(crate) scope_start_ns: Option<u64>,
    pub(crate) walk_started_ns: u64,
    pub(crate) slots: Vec<WitnessSlot>,
}

/// Quiescent-close deadline (§4.6 step 3): 1 s as busy-poll flips.
/// Each flip is one 1 ms sleep plus a state read.
pub(crate) const QUIESCE_MAX_FLIPS: u32 = 1000;

/// Backend operations for finalize (extends the start seam).
pub(crate) trait FinalizeBackend {
    type Error: std::fmt::Debug;
    /// Run one presence walk to EOF.
    fn run_walk(&mut self) -> Result<WalkOutcome, Self::Error>;
    /// Read PW_STATE.
    fn read_state(&mut self) -> Result<PwState, Self::Error>;
    /// Deactivate (active = 0).
    fn deactivate(&mut self) -> Result<(), Self::Error>;
    /// Poll busy until 0; returns true if quiesced within `max_flips` reads.
    fn settle_busy(&mut self, max_flips: u32) -> Result<bool, Self::Error>;
    /// Release hooks and close the object.
    fn release(&mut self) -> Result<(), Self::Error>;
    /// Verifier recursion misses for one program (0 when healthy).
    fn recursion_misses(&mut self, program: &str) -> Result<u64, Self::Error>;
}

/// Finalize: one walk, deactivate, settle, read, release. Returns
/// per-slot verdicts; any failure keeps windows with its §8 group 3-5
/// reason. Ordering (walk vs attach) is the engine builder's: only
/// `finish_prearm_capture` knows each object's exact attach stamp.
/// Checks run in close order; the first failure wins for every slot.
///
/// The walk runs exactly once: an abandoned walk emits no END, so a
/// second walk could never satisfy `walk_end == 1` (§8 group 3).
/// EAGAIN resumes inside the single walk (§4.5).
pub(crate) fn finalize_with<B: FinalizeBackend>(
    backend: &mut B,
    slots: usize,
    ftrace_enabled: Option<String>,
) -> Vec<FileVerdict> {
    let keep_all = |reason: KeepReason| vec![FileVerdict::Keep(reason); slots];
    let walk_ok = matches!(backend.run_walk(), Ok(WalkOutcome::Done));
    // Close ordering: deactivate, settle, read, release (always
    // release). A failed deactivate still drains the close, but the
    // state read is then untrusted: the hooks may have stayed live.
    let deactivated = backend.deactivate().is_ok();
    let settled = backend.settle_busy(QUIESCE_MAX_FLIPS).unwrap_or(false);
    // Single close-time read (§4.6 step 4): pending is frozen after
    // deactivate + settle, so re-reading cannot observe a change.
    let state = backend.read_state().ok();
    let _ = backend.release();
    if !walk_ok {
        return keep_all(KeepReason::Walk);
    }
    if !deactivated {
        return keep_all(KeepReason::Quiesce);
    }
    if !settled {
        return keep_all(KeepReason::Quiesce);
    }
    let state = match state {
        Some(state) => state,
        // An unreadable close-time state is a fault, not evidence.
        None => return keep_all(KeepReason::Fault),
    };
    // Global conditions (§2.5-7).
    if state.walk_end != 1 {
        return keep_all(KeepReason::Walk);
    }
    if state.faults != 0 {
        return keep_all(KeepReason::Fault);
    }
    if state.stuck != 0 {
        return keep_all(KeepReason::Stuck);
    }
    if state.pending_in != state.pending_out {
        return keep_all(KeepReason::Pending);
    }
    if state.migrations != 0 {
        return keep_all(KeepReason::Migration);
    }
    if ftrace_enabled.as_deref().map(str::trim) != Some("1") {
        return keep_all(KeepReason::Ftrace);
    }
    for program in [
        PROGRAM_UNMAP,
        PROGRAM_DEPART_EXIT,
        PROGRAM_DEPART_EXEC,
        PROGRAM_DEPART,
        PROGRAM_TORN,
        PROGRAM_MIGRATE,
        PROGRAM_WALK,
    ] {
        // Missing programs report 0 misses (not attached on this
        // kernel); an unreadable count on a loaded program is missing
        // health evidence, not a clean bill.
        if !matches!(backend.recursion_misses(program), Ok(0)) {
            return keep_all(KeepReason::Recursion);
        }
    }
    // Per-slot lattice: any bit keeps that slot. A slot with several
    // bits reports found first, then latch, then torn: a positive
    // sighting at close dominates (mprotect splits fire the unmap hook
    // via vma_prepare/complete without detaching anything, so latch can
    // be spurious while found is ground truth); a live detach dominates
    // exit-path (accounted) activity. Pinned live by the P2-7
    // mprotect-dance cell.
    (0..slots)
        .map(|slot| {
            let bit = 1u64 << slot;
            if state.found_slots & bit != 0 {
                FileVerdict::Keep(KeepReason::Found)
            } else if state.latch_slots & bit != 0 {
                FileVerdict::Keep(KeepReason::Latched)
            } else if state.torn_slots & bit != 0 {
                FileVerdict::Keep(KeepReason::Torn)
            } else {
                FileVerdict::Clear
            }
        })
        .collect()
}

/// Top-level start (engine entry): gates, BTF resolve, load, calibrate,
/// activate. Returns Unavailable (never fatal) when the witness cannot
/// run on this kernel/scope; the capture proceeds with today's windows.
pub(crate) fn start(
    paths: &[std::path::PathBuf],
    scope: &crate::attach::Scope,
    pidns_initial: bool,
    budget: &mut crate::discovery::scan::CaptureWorkBudget,
) -> Result<StartupWitness<LiveBackend>, Unavailable> {
    let ftrace = std::fs::read_to_string("/proc/sys/kernel/ftrace_enabled").ok();
    let lto = super::instance::lto_refusal();
    gate_startup(paths.len(), pidns_initial, ftrace, lto)?;
    let raw_btf = std::fs::read("/sys/kernel/btf/vmlinux")
        .map_err(|error| Unavailable::Btf(format!("host BTF unreadable: {error}")))?;
    let (scope_kind, target_tgid, cgroup_id, need_migrate) = match scope {
        crate::attach::Scope::Pid(pid) => (1u32, *pid, 0u64, false),
        crate::attach::Scope::Cgroup { id, .. } => (2u32, 0, *id, true),
        crate::attach::Scope::System => (3u32, 0, 0, false),
    };
    check_target_protos(&raw_btf, need_migrate)?;
    let family = resolve_depart_family(&raw_btf)?;
    let btf = aya::Btf::from_sys_fs().map_err(|error| Unavailable::Btf(format!("{error:?}")))?;
    let depart: &[&'static str] = match family {
        DepartFamily::Pair => &[PROGRAM_DEPART_EXIT, PROGRAM_DEPART_EXEC],
        DepartFamily::Single => &[PROGRAM_DEPART],
    };
    let loaded = load_witness_programs(&btf, depart, need_migrate)
        .map_err(|error| Unavailable::Btf(format!("{error}")))?;
    let mut backend = LiveBackend::from_loaded(loaded.ebpf);
    // --pid walks use a pidfd link; cgroup/system walk whole-system.
    if let crate::attach::Scope::Pid(pid) = scope {
        // SAFETY: pidfd_open on a live pid; closed with the backend.
        let raw = unsafe { libc::syscall(libc::SYS_pidfd_open, *pid, 0) };
        if raw < 0 {
            return Err(Unavailable::Btf("witness pidfd_open failed".into()));
        }
        use std::os::unix::io::FromRawFd as _;
        // SAFETY: owned fd from a successful pidfd_open.
        let pidfd = unsafe { std::os::fd::OwnedFd::from_raw_fd(raw as i32) };
        backend.set_pidfd(Some(pidfd));
    }
    start_with(
        paths,
        scope_kind,
        target_tgid,
        cgroup_id,
        need_migrate,
        family,
        backend,
        || crate::attach::monotonic_ns().unwrap_or(0),
        budget,
    )
}

#[cfg(test)]
#[path = "prearm_witness_tests.rs"]
mod prearm_witness_tests;

#[cfg(test)]
mod tests {
    use std::collections::BTreeSet;

    #[test]
    fn witness_object_carries_exact_programs_and_maps() {
        let parsed = aya_obj::Object::parse(super::WITNESS_OBJECT).expect("witness object parses");
        let programs: BTreeSet<&str> = parsed.programs.keys().map(String::as_str).collect();
        let expected_programs: BTreeSet<&str> = [
            "p11_pw_unmap",
            "p11_pw_depart_exit",
            "p11_pw_depart_exec",
            "p11_pw_depart",
            "p11_pw_torn",
            "p11_pw_migrate",
            "p11_pw_walk",
        ]
        .into_iter()
        .collect();
        assert_eq!(programs, expected_programs, "exact 7 witness programs");
        for (name, section_kind) in [
            ("p11_pw_unmap", "fentry"),
            ("p11_pw_depart_exit", "fentry"),
            ("p11_pw_depart_exec", "fentry"),
            ("p11_pw_depart", "fentry"),
            ("p11_pw_torn", "fexit"),
            ("p11_pw_migrate", "fentry"),
            ("p11_pw_walk", "iter"),
        ] {
            let program = parsed.programs.get(name).unwrap();
            let kind = match program.section {
                aya_obj::ProgramSection::FEntry { .. } => "fentry",
                aya_obj::ProgramSection::FExit { .. } => "fexit",
                aya_obj::ProgramSection::Iter { .. } => "iter",
                ref other => panic!("{name} has unexpected section {other:?}"),
            };
            assert_eq!(kind, section_kind, "{name} section kind");
        }
        // Eight maps with exact shapes (addendum §4.0; PW_CALIB is 64 slots
        // plus the self-departs cell at index 64).
        let expected_maps: &[(&str, u32, u32, u32, u32, u32)] = &[
            ("PW_CFG", 2, 4, 32, 1, 128),
            ("PW_WATCHED", 1, 16, 4, 64, 128),
            ("PW_CALIB", 2, 4, 24, 65, 0),
            ("PW_STATE", 2, 4, 104, 1, 0),
            ("PW_DEPARTED", 1, 8, 24, 16384, 1),
            ("PW_VISITED", 1, 8, 1, 65536, 1),
            ("PW_SELF", 2, 4, 8, 1, 0),
            ("PW_RUN", 2, 4, 56, 1, 0),
        ];
        let maps: BTreeSet<&str> = parsed.maps.keys().map(String::as_str).collect();
        let expected_names: BTreeSet<&str> = expected_maps.iter().map(|(name, ..)| *name).collect();
        assert_eq!(maps, expected_names, "exact 8 witness maps");
        for (name, map_type, key_size, value_size, max_entries, flags) in expected_maps {
            let actual = parsed.maps.get(*name).unwrap();
            assert_eq!(actual.map_type(), *map_type, "{name} type");
            assert_eq!(actual.key_size(), *key_size, "{name} key");
            assert_eq!(actual.value_size(), *value_size, "{name} value");
            assert_eq!(actual.max_entries(), *max_entries, "{name} entries");
            assert_eq!(actual.map_flags(), *flags, "{name} flags");
        }
    }

    #[test]
    fn witness_load_names_gates_migrate_on_cgroup() {
        // Spec §4.4: the migrate program loads only for `--cgroup`.
        let depart: &[&'static str] = &[super::PROGRAM_DEPART_EXIT, super::PROGRAM_DEPART_EXEC];
        let with = super::witness_load_names(depart, true);
        assert!(
            with.contains(&super::PROGRAM_MIGRATE),
            "cgroup loads migrate: {with:?}"
        );
        let without = super::witness_load_names(depart, false);
        assert!(
            !without.contains(&super::PROGRAM_MIGRATE),
            "pid/system skip migrate: {without:?}"
        );
        for name in [
            super::PROGRAM_UNMAP,
            super::PROGRAM_TORN,
            super::PROGRAM_WALK,
            super::PROGRAM_DEPART_EXIT,
            super::PROGRAM_DEPART_EXEC,
        ] {
            assert!(with.contains(&name), "{name} loads for cgroup");
            assert!(without.contains(&name), "{name} loads for pid/system");
        }
    }

    /// Privileged: the witness object loads and attaches on the host kernel.
    /// Records per-program verifier instruction counts via eprintln (copied
    /// into the phase report and P2-9 budgets).
    #[test]
    #[ignore = "privileged: loads the witness object on the host kernel"]
    fn privileged_prearm_witness_loads_and_attaches() {
        let btf = aya::Btf::from_sys_fs().expect("readable host BTF");
        // Departure family by kernel: 7.3+ has the single, older the pair.
        let has_single = btf
            .id_by_type_name_kind("mm_exit_exec_release", aya_obj::btf::BtfKind::Func)
            .is_ok();
        let depart: &[&'static str] = if has_single {
            &[super::PROGRAM_DEPART]
        } else {
            &[super::PROGRAM_DEPART_EXIT, super::PROGRAM_DEPART_EXEC]
        };
        let mut loaded =
            super::load_witness_programs(&btf, depart, true).expect("witness programs verify");
        // Attach every loaded program; links drop at scope end.
        let mut attached = Vec::new();
        for name in [
            super::PROGRAM_UNMAP,
            super::PROGRAM_TORN,
            super::PROGRAM_MIGRATE,
            super::PROGRAM_WALK,
        ]
        .into_iter()
        .chain(depart.iter().copied())
        {
            if name == super::PROGRAM_WALK {
                let program: &mut aya::programs::Iter =
                    loaded.ebpf.program_mut(name).unwrap().try_into().unwrap();
                let link = program.attach().expect("attach walk");
                attached.push(format!("{name}: iter link"));
                let _ = link;
                continue;
            }
            if name == super::PROGRAM_TORN {
                let program: &mut aya::programs::FExit =
                    loaded.ebpf.program_mut(name).unwrap().try_into().unwrap();
                let _link = program.attach().expect("attach fexit");
                attached.push(format!("{name}: fexit"));
                continue;
            }
            let program: &mut aya::programs::FEntry =
                loaded.ebpf.program_mut(name).unwrap().try_into().unwrap();
            let _link = program.attach().expect("attach fentry");
            attached.push(format!("{name}: fentry"));
        }
        eprintln!("witness attach ok: {}", attached.join(", "));
        // Instruction counts come from the verifier-stats probe in P2-7/P2-9;
        // this cell proves load+attach on the host.
        assert!(!attached.is_empty());
    }

    // P2-3 resolver tests with raw BTF fixtures.
    //
    // Minimal BTF builder: empty structs, ints, pointers, protos and funcs.
    // Type IDs are assigned in construction order (1-based; 0 is void).
    struct BtfBuild {
        strings: Vec<u8>,
        str_off: std::collections::HashMap<String, u32>,
        types: Vec<u8>,
        next_id: u32,
    }

    impl BtfBuild {
        fn new() -> Self {
            Self {
                strings: vec![0],
                str_off: std::collections::HashMap::new(),
                types: Vec::new(),
                next_id: 1,
            }
        }

        fn str_id(&mut self, name: &str) -> u32 {
            if let Some(id) = self.str_off.get(name) {
                return *id;
            }
            let id = self.strings.len() as u32;
            self.strings.extend(name.bytes());
            self.strings.push(0);
            self.str_off.insert(name.to_string(), id);
            id
        }

        fn push_words(&mut self, words: &[u32]) {
            for word in words {
                self.types.extend(word.to_le_bytes());
            }
        }

        fn add_struct(&mut self, name: &str) -> u32 {
            let name_off = self.str_id(name);
            let id = self.next_id;
            self.next_id += 1;
            self.push_words(&[name_off, 4 << 24, 0]);
            id
        }

        fn add_int(&mut self, name: &str, size: u32) -> u32 {
            let name_off = self.str_id(name);
            let id = self.next_id;
            self.next_id += 1;
            self.push_words(&[name_off, 1 << 24, size, 0x20]);
            id
        }

        fn add_ptr(&mut self, pointee: u32) -> u32 {
            let id = self.next_id;
            self.next_id += 1;
            self.push_words(&[0, 2 << 24, pointee]);
            id
        }

        fn add_proto(&mut self, ret: u32, params: &[u32]) -> u32 {
            let id = self.next_id;
            self.next_id += 1;
            self.push_words(&[0, (13 << 24) | (params.len() as u32), ret]);
            for param in params {
                self.push_words(&[0, *param]);
            }
            id
        }

        fn add_func(&mut self, name: &str, proto: u32) -> u32 {
            let name_off = self.str_id(name);
            let id = self.next_id;
            self.next_id += 1;
            self.push_words(&[name_off, (12 << 24) | 1, proto]);
            id
        }

        fn finish(self) -> Vec<u8> {
            let mut bytes = vec![0x9f, 0xeb, 1, 0];
            let header_len = 24u32;
            for word in [
                header_len,
                0,
                self.types.len() as u32,
                self.types.len() as u32,
                self.strings.len() as u32,
            ] {
                bytes.extend(word.to_le_bytes());
            }
            bytes.extend(self.types);
            bytes.extend(self.strings);
            bytes
        }
    }

    /// BTF with the witness targets. `family`: 0 = neither, 1 = pair only
    /// (6.6-shape), 2 = single only (7.3-shape), 3 = both. `mutate` optionally
    /// rewrites one target's proto (name, argc, return, params) to a wrong shape.
    fn witness_btf_fixture(family: u32, mutate: Option<(&str, usize)>) -> Vec<u8> {
        let mut b = BtfBuild::new();
        let task = b.add_struct("task_struct");
        let mm = b.add_struct("mm_struct");
        let vma = b.add_struct("vm_area_struct");
        let mgctx = b.add_struct("cgroup_mgctx");
        let int = b.add_int("int", 4);
        let lulong = b.add_int("long unsigned int", 8);
        let task_p = b.add_ptr(task);
        let mm_p = b.add_ptr(mm);
        let vma_p = b.add_ptr(vma);
        let mgctx_p = b.add_ptr(mgctx);
        // (name, ret, params)
        let mut targets: Vec<(&str, u32, Vec<u32>)> = vec![
            ("uprobe_munmap", 0, vec![vma_p, lulong, lulong]),
            ("exit_mmap", 0, vec![mm_p]),
            ("cgroup_migrate", int, vec![task_p, int, mgctx_p]),
        ];
        if family & 1 != 0 {
            targets.push(("exit_mm_release", 0, vec![task_p, mm_p]));
            targets.push(("exec_mm_release", 0, vec![task_p, mm_p]));
        }
        if family & 2 != 0 {
            targets.push(("mm_exit_exec_release", 0, vec![task_p, mm_p]));
        }
        for (name, ret, params) in targets {
            let (ret, params) = if mutate.is_some_and(|(m, _)| m == name) {
                let (_, which) = mutate.unwrap();
                match which {
                    // Wrong arity: drop last param.
                    0 => (ret, params[..params.len() - 1].to_vec()),
                    // Wrong kind: first pointer replaced by a scalar.
                    _ => {
                        let mut p = params.clone();
                        p[0] = int;
                        (ret, p)
                    }
                }
            } else {
                (ret, params)
            };
            let proto = b.add_proto(ret, &params);
            b.add_func(name, proto);
        }
        b.finish()
    }

    #[test]
    fn resolver_accepts_pair_and_single_shapes() {
        assert_eq!(
            super::resolve_depart_family(&witness_btf_fixture(1, None)).unwrap(),
            super::DepartFamily::Pair
        );
        assert_eq!(
            super::resolve_depart_family(&witness_btf_fixture(2, None)).unwrap(),
            super::DepartFamily::Single
        );
        super::check_target_protos(&witness_btf_fixture(1, None), true).unwrap();
        super::check_target_protos(&witness_btf_fixture(2, None), true).unwrap();
        // Without --cgroup, migrate is not required.
        super::check_target_protos(&witness_btf_fixture(1, None), false).unwrap();
    }

    #[test]
    fn resolver_refuses_both_or_neither_departure_family() {
        assert!(super::resolve_depart_family(&witness_btf_fixture(3, None)).is_err());
        assert!(super::resolve_depart_family(&witness_btf_fixture(0, None)).is_err());
    }

    #[test]
    fn resolver_refuses_wrong_shape_for_each_target() {
        for target in [
            "uprobe_munmap",
            "exit_mmap",
            "cgroup_migrate",
            "exit_mm_release",
            "exec_mm_release",
            "mm_exit_exec_release",
        ] {
            let family = if target == "mm_exit_exec_release" {
                2
            } else {
                1
            };
            for which in [0, 1] {
                let bytes = witness_btf_fixture(family, Some((target, which)));
                let resolved = super::check_target_protos(&bytes, true);
                let family_ok = super::resolve_depart_family(&bytes).is_ok();
                assert!(
                    resolved.is_err() || !family_ok,
                    "{target} mutant {which} must be unavailable"
                );
            }
        }
    }

    #[test]
    fn startup_gates_cover_lto_ftrace_pidns_and_file_count() {
        use super::{Unavailable, gate_startup};
        // Clean: 1 file, initial pidns, ftrace 1, no LTO.
        gate_startup(1, true, Some("1\n".into()), None).unwrap();
        gate_startup(64, true, Some("1".into()), None).unwrap();
        // LTO.
        assert_eq!(
            gate_startup(1, true, Some("1".into()), Some("LTO".into())).unwrap_err(),
            Unavailable::Lto("LTO".into())
        );
        // ftrace 0 or unreadable.
        assert!(matches!(
            gate_startup(1, true, Some("0\n".into()), None).unwrap_err(),
            Unavailable::Ftrace(_)
        ));
        assert!(matches!(
            gate_startup(1, true, None, None).unwrap_err(),
            Unavailable::Ftrace(_)
        ));
        // Nested/unknown pidns.
        assert!(matches!(
            gate_startup(1, false, Some("1".into()), None).unwrap_err(),
            Unavailable::Pidns(_)
        ));
        // 65 paths.
        assert_eq!(
            gate_startup(65, true, Some("1".into()), None).unwrap_err(),
            Unavailable::TooManyFiles
        );
        assert_eq!(
            gate_startup(0, true, Some("1".into()), None).unwrap_err(),
            Unavailable::TooManyFiles
        );
    }

    #[test]
    fn unavailable_class_names_reason_without_values() {
        use super::Unavailable;
        assert_eq!(Unavailable::Btf("detail".into()).class(), "btf");
        assert_eq!(Unavailable::Lto("detail".into()).class(), "lto");
        assert_eq!(Unavailable::Ftrace("detail".into()).class(), "ftrace");
        assert_eq!(Unavailable::Pidns("detail".into()).class(), "pidns");
        assert_eq!(Unavailable::TooManyFiles.class(), "too-many-files");
        assert_eq!(
            Unavailable::Calibration("detail".into()).class(),
            "calibration"
        );
    }

    /// Privileged: the cgroup id from `Scope::Cgroup` (directory inode)
    /// matches the kernel's kernfs id, proven by a one-task witness walk
    /// that finds a watched mapping in a member task.
    #[test]
    #[ignore = "privileged: cgroup id matches kernfs id via witness walk"]
    fn privileged_cgroup_id_matches_kernfs_id() {
        use std::os::fd::{AsFd as _, FromRawFd as _};
        // This test's own cgroup.
        let self_cgroup = std::fs::read_to_string("/proc/self/cgroup")
            .expect("read self cgroup")
            .lines()
            .find_map(|line| line.strip_prefix("0::").map(str::to_string))
            .expect("cgroup v2 path");
        let cgroup_path =
            std::path::PathBuf::from("/sys/fs/cgroup").join(self_cgroup.trim_start_matches('/'));
        let scope = crate::scope::cgroup(&cgroup_path).expect("scope for self cgroup");
        let crate::attach::Scope::Cgroup { id, .. } = scope else {
            panic!("not a cgroup scope");
        };
        // Load the witness, configure for this cgroup, watch a file the test
        // maps itself, and walk the test process via pidfd: FOUND proves the
        // kernel resolved our id to this task's cgroup.
        let btf = aya::Btf::from_sys_fs().expect("host BTF");
        let has_single = btf
            .id_by_type_name_kind("mm_exit_exec_release", aya_obj::btf::BtfKind::Func)
            .is_ok();
        let depart: &[&'static str] = if has_single {
            &[super::PROGRAM_DEPART]
        } else {
            &[super::PROGRAM_DEPART_EXIT, super::PROGRAM_DEPART_EXEC]
        };
        let mut loaded = super::load_witness_programs(&btf, depart, true).expect("witness loads");
        // Calibrate the kernel file key via a real unmap (Btrfs st_dev can
        // differ from the mapped s_dev, so fstat alone is wrong): attach the
        // unmap hook, mmap+munmap one page, and read back PW_CALIB.
        let exe = std::fs::File::open("/proc/self/exe").expect("open self exe");
        let exe_fd = std::os::unix::io::AsRawFd::as_raw_fd(&exe);
        let tid = unsafe { libc::syscall(libc::SYS_gettid) } as u32;
        {
            use aya::maps::{Array, MapData};
            let mut cfg_map: Array<&mut MapData, super::PwCfg> =
                Array::try_from(loaded.ebpf.map_mut("PW_CFG").expect("PW_CFG"))
                    .expect("typed PW_CFG");
            cfg_map
                .set(
                    0,
                    super::PwCfg {
                        active: 0,
                        scope_kind: 2,
                        target_tgid: 0,
                        calib_tid: tid,
                        cgroup_id: id,
                        calib_index: 0,
                        pad: 0,
                    },
                    0,
                )
                .expect("write calib cfg");
        }
        let _unmap_link = {
            let program: &mut aya::programs::FEntry = loaded
                .ebpf
                .program_mut(super::PROGRAM_UNMAP)
                .expect("unmap program")
                .try_into()
                .expect("fentry");
            program.attach().expect("attach unmap for calib")
        };
        let calib_addr = unsafe {
            libc::mmap(
                std::ptr::null_mut(),
                4096,
                libc::PROT_READ,
                libc::MAP_PRIVATE,
                exe_fd,
                0,
            )
        };
        assert_ne!(calib_addr, libc::MAP_FAILED);
        unsafe { libc::munmap(calib_addr, 4096) };
        let (kdev, kino) = {
            use aya::maps::{Array, MapData};
            let calib_map: Array<&MapData, super::PwCalibSlot> =
                Array::try_from(loaded.ebpf.map("PW_CALIB").expect("PW_CALIB"))
                    .expect("typed calib");
            let slot = calib_map.get(&0, 0).expect("read calib");
            assert_eq!(slot.hits, 1, "calibration recorded");
            assert_ne!(slot.i_ino, 0, "calibration inode nonzero");
            (slot.s_dev, slot.i_ino)
        };
        let _ = _unmap_link;
        // Map a page of the same file for the walk to find, then activate
        // with the calibrated key. Clear PW_SELF (test-only): calibration
        // recorded this mm as the observer, but this cell proves cgroup
        // membership, not observer exclusion (P2-7 covers exclusion).
        let addr = unsafe {
            libc::mmap(
                std::ptr::null_mut(),
                4096,
                libc::PROT_READ,
                libc::MAP_PRIVATE,
                exe_fd,
                0,
            )
        };
        assert_ne!(addr, libc::MAP_FAILED);
        {
            use aya::maps::{Array, HashMap, MapData};
            let mut cfg_map: Array<&mut MapData, super::PwCfg> =
                Array::try_from(loaded.ebpf.map_mut("PW_CFG").expect("PW_CFG"))
                    .expect("typed PW_CFG");
            cfg_map
                .set(
                    0,
                    super::PwCfg {
                        active: 1,
                        scope_kind: 2,
                        target_tgid: 0,
                        calib_tid: 0,
                        cgroup_id: id,
                        calib_index: 0,
                        pad: 0,
                    },
                    0,
                )
                .expect("write cfg");
            let mut watched: HashMap<_, super::PwWatchedKey, u32> =
                HashMap::try_from(loaded.ebpf.map_mut("PW_WATCHED").expect("PW_WATCHED"))
                    .expect("typed PW_WATCHED");
            watched
                .insert(
                    super::PwWatchedKey {
                        s_dev: kdev,
                        i_ino: kino,
                    },
                    0u32,
                    0,
                )
                .expect("insert watched");
            // Clear the observer mark for this cell (test-only setup).
            let mut self_map: Array<&mut MapData, u64> = Array::try_from(
                loaded.ebpf.map_mut("PW_SELF").expect("PW_SELF"), // test-only
            )
            .expect("typed self");
            self_map.set(0, 0, 0).expect("clear self for test");
        }
        // Walk this process via pidfd.
        let pidfd_raw = unsafe { libc::syscall(libc::SYS_pidfd_open, std::process::id(), 0) };
        assert!(pidfd_raw >= 0, "pidfd_open self");
        let pidfd = unsafe { std::os::fd::OwnedFd::from_raw_fd(pidfd_raw as i32) };
        let prog_fd = loaded
            .ebpf
            .program(super::PROGRAM_WALK)
            .expect("walk program")
            .fd()
            .expect("walk fd")
            .as_fd()
            .try_clone_to_owned()
            .expect("clone walk fd");
        let link = crate::attach::identity_iter::link_create_task_vma(
            prog_fd.as_fd(),
            Some(pidfd.as_fd()),
        )
        .expect("walk link");
        let iter = crate::attach::identity_iter::iter_create(link.as_fd()).expect("iter");
        // The witness walk writes no bytes; drain to EOF (the END).
        let mut chunk = [0u8; 4096];
        loop {
            let got = unsafe {
                libc::read(
                    std::os::unix::io::AsRawFd::as_raw_fd(&iter),
                    chunk.as_mut_ptr().cast(),
                    chunk.len(),
                )
            };
            if got == 0 {
                break;
            }
            if got > 0 {
                continue;
            }
            let errno = std::io::Error::last_os_error().raw_os_error();
            if errno == Some(libc::EAGAIN) || errno == Some(libc::EINTR) {
                continue;
            }
            panic!("walk read failed: {errno:?}");
        }
        unsafe { libc::munmap(addr, 4096) };
        // FOUND proves membership, hence id equality.
        {
            use aya::maps::{Array, MapData};
            let state_map: Array<&MapData, super::PwState> =
                Array::try_from(loaded.ebpf.map("PW_STATE").expect("PW_STATE"))
                    .expect("typed state");
            let state = state_map.get(&0, 0).expect("read state");
            assert_eq!(state.walk_end, 1, "walk reached END");
            assert_eq!(
                state.found_slots, 1,
                "self mapping found as cgroup member (id {id})"
            );
        }
    }

    // P2-4 startup driver tests with a scripted backend.
    struct ScriptBackend {
        ops: Vec<String>,
        calib: super::PwCalibSlot,
        self_departs: u64,
        insert_err: bool,
        active_seen: bool,
    }

    impl ScriptBackend {
        fn new(calib: super::PwCalibSlot, self_departs: u64) -> Self {
            Self {
                ops: Vec::new(),
                calib,
                self_departs,
                insert_err: false,
                active_seen: false,
            }
        }
    }

    impl super::WitnessBackend for ScriptBackend {
        type Error = String;
        fn write_cfg(&mut self, cfg: &super::PwCfg) -> Result<(), String> {
            if cfg.active == 1 {
                self.active_seen = true;
                self.ops.push("active".into());
            } else {
                self.ops.push(format!("cfg calib={}", cfg.calib_index));
            }
            Ok(())
        }
        fn attach(
            &mut self,
            _family: super::DepartFamily,
            _need_migrate: bool,
        ) -> Result<(), String> {
            self.ops.push("attach".into());
            Ok(())
        }
        fn read_calib(&mut self, index: u32) -> Result<super::PwCalibSlot, String> {
            self.ops.push(format!("calib{index}"));
            Ok(self.calib)
        }
        fn read_self_departs(&mut self) -> Result<u64, String> {
            self.ops.push("departs".into());
            Ok(self.self_departs)
        }
        fn insert_watched(&mut self, _key: &super::PwWatchedKey, slot: u32) -> Result<(), String> {
            self.ops.push(format!("key{slot}"));
            if self.insert_err {
                return Err("insert failed".into());
            }
            Ok(())
        }
    }

    fn temp_prearm_file(name: &str) -> (tempfile::TempDir, std::path::PathBuf) {
        let dir = tempfile::tempdir().expect("tempdir");
        let path = dir.path().join(name);
        std::fs::write(&path, vec![0x7f, b'E', b'L', b'F', 0, 1, 2, 3]).expect("write");
        (dir, path)
    }

    fn calib_for(path: &std::path::Path) -> super::PwCalibSlot {
        // Mirror what the kernel would record for this temp file: the
        // map_files identity after an mmap. For the scripted backend the
        // test computes it the same way production reads it (fstat here
        // equals the kernel key on non-Btrfs TMPDIR).
        use std::os::unix::fs::MetadataExt as _;
        let meta = std::fs::metadata(path).expect("fstat");
        super::PwCalibSlot {
            hits: 1,
            s_dev: meta.dev(),
            i_ino: meta.ino(),
        }
    }

    #[test]
    fn start_calibration_failures_are_unavailable() {
        let (_dir, path) = temp_prearm_file("libx.so");
        let good = calib_for(&path);
        // hits 0.
        let backend = ScriptBackend::new(super::PwCalibSlot { hits: 0, ..good }, 1);
        assert!(
            super::start_with(
                std::slice::from_ref(&path),
                3,
                0,
                0,
                false,
                super::DepartFamily::Pair,
                backend,
                || 100,
                &mut crate::discovery::scan::CaptureWorkBudget::default(),
            )
            .is_err()
        );
        // hits 2.
        let backend = ScriptBackend::new(super::PwCalibSlot { hits: 2, ..good }, 1);
        assert!(
            super::start_with(
                std::slice::from_ref(&path),
                3,
                0,
                0,
                false,
                super::DepartFamily::Pair,
                backend,
                || 100,
                &mut crate::discovery::scan::CaptureWorkBudget::default(),
            )
            .is_err()
        );
        // inode 0.
        let backend = ScriptBackend::new(
            super::PwCalibSlot {
                hits: 1,
                s_dev: good.s_dev,
                i_ino: 0,
            },
            1,
        );
        assert!(
            super::start_with(
                std::slice::from_ref(&path),
                3,
                0,
                0,
                false,
                super::DepartFamily::Pair,
                backend,
                || 100,
                &mut crate::discovery::scan::CaptureWorkBudget::default(),
            )
            .is_err()
        );
        // identity mismatch (inode; s_dev is Btrfs-tolerant).
        let backend = ScriptBackend::new(
            super::PwCalibSlot {
                hits: 1,
                s_dev: good.s_dev,
                i_ino: good.i_ino.wrapping_add(1),
            },
            1,
        );
        assert!(
            super::start_with(
                std::slice::from_ref(&path),
                3,
                0,
                0,
                false,
                super::DepartFamily::Pair,
                backend,
                || 100,
                &mut crate::discovery::scan::CaptureWorkBudget::default(),
            )
            .is_err()
        );
    }

    /// One-row overlay table over `merged_root` with the given layers.
    fn overlay_table_for(
        merged_root: &std::path::Path,
        upper: &std::path::Path,
        lower: &std::path::Path,
    ) -> String {
        format!(
            "31 23 0:27 / {} rw,relatime - overlay overlay rw,lowerdir={},upperdir={}\n",
            merged_root.display(),
            lower.display(),
            upper.display(),
        )
    }

    fn backing_ino_of(path: &std::path::Path) -> u64 {
        use std::os::unix::fs::MetadataExt as _;
        std::fs::metadata(path).expect("layer file stat").ino()
    }

    #[test]
    fn backing_accepts_lower_candidate_on_xino_split() {
        // The BPF slot carries the lower backing inode while the
        // merged view carries a huge xino inode: backing vs backing
        // through the lower candidate must accept.
        let root = tempfile::tempdir().expect("tempdir");
        let (lower, upper, merged_root) = (
            root.path().join("lower"),
            root.path().join("upper"),
            root.path().join("merged"),
        );
        for dir in [&lower, &upper, &merged_root] {
            std::fs::create_dir(dir).expect("layer dir");
        }
        let layer_file = lower.join("lib.so");
        std::fs::write(&layer_file, [0xA1u8; 64]).expect("write");
        let table = overlay_table_for(&merged_root, &upper, &lower);
        assert!(
            super::calibration_backing_accepted(
                &merged_root.join("lib.so"),
                backing_ino_of(&layer_file),
                &table,
            ),
            "the lower backing inode must match the slot"
        );
    }

    #[test]
    fn backing_accepts_upper_candidate_after_copy_up() {
        // After copy-up the merged view keeps the stable overlay inode
        // while new mappings back onto the upper file: the upper
        // candidate must match the slot even though the lower file
        // (same remainder, different inode) does not.
        let root = tempfile::tempdir().expect("tempdir");
        let (lower, upper, merged_root) = (
            root.path().join("lower"),
            root.path().join("upper"),
            root.path().join("merged"),
        );
        for dir in [&lower, &upper, &merged_root] {
            std::fs::create_dir(dir).expect("layer dir");
        }
        std::fs::write(lower.join("lib.so"), [0xA2u8; 64]).expect("write");
        let upper_file = upper.join("lib.so");
        std::fs::write(&upper_file, [0xA3u8; 64]).expect("write");
        assert_ne!(
            backing_ino_of(&lower.join("lib.so")),
            backing_ino_of(&upper_file),
            "the twin needs distinct layer inodes"
        );
        let table = overlay_table_for(&merged_root, &upper, &lower);
        assert!(
            super::calibration_backing_accepted(
                &merged_root.join("lib.so"),
                backing_ino_of(&upper_file),
                &table,
            ),
            "the upper backing inode must match the slot"
        );
    }

    #[test]
    fn backing_refuses_different_backing_file_with_same_overlay_shape() {
        // Negative twin: the same merged path and table, but the slot
        // names another file's backing inode — never accepted, even
        // though the overlay view would render the same merged file.
        let root = tempfile::tempdir().expect("tempdir");
        let (lower, upper, merged_root) = (
            root.path().join("lower"),
            root.path().join("upper"),
            root.path().join("merged"),
        );
        for dir in [&lower, &upper, &merged_root] {
            std::fs::create_dir(dir).expect("layer dir");
        }
        let layer_file = lower.join("lib.so");
        std::fs::write(&layer_file, [0xA4u8; 64]).expect("write");
        let other = root.path().join("other.so");
        std::fs::write(&other, [0xA5u8; 64]).expect("write");
        let (layer_ino, other_ino) = (backing_ino_of(&layer_file), backing_ino_of(&other));
        assert_ne!(
            layer_ino, other_ino,
            "the twin needs two distinct backing inodes"
        );
        let table = overlay_table_for(&merged_root, &upper, &lower);
        assert!(
            !super::calibration_backing_accepted(&merged_root.join("lib.so"), other_ino, &table,),
            "a different backing inode must refuse"
        );
    }

    #[test]
    fn backing_refuses_without_cover_escapes_and_missing_layers() {
        let root = tempfile::tempdir().expect("tempdir");
        let (lower, upper, merged_root) = (
            root.path().join("lower"),
            root.path().join("upper"),
            root.path().join("merged"),
        );
        for dir in [&lower, &upper, &merged_root] {
            std::fs::create_dir(dir).expect("layer dir");
        }
        let layer_file = lower.join("lib.so");
        std::fs::write(&layer_file, [0xA6u8; 64]).expect("write");
        let slot = backing_ino_of(&layer_file);
        let table = overlay_table_for(&merged_root, &upper, &lower);
        // No table, no cover.
        assert!(
            !super::calibration_backing_accepted(&merged_root.join("lib.so"), slot, ""),
            "an empty table names no layer"
        );
        let plain = "10 1 8:1 / /var/tmp/x rw,relatime - ext4 /dev/sda3 rw\n".to_string();
        assert!(
            !super::calibration_backing_accepted(&merged_root.join("lib.so"), slot, &plain,),
            "a non-overlay table names no layer"
        );
        // A remainder escaping the mount never resolves.
        assert!(
            !super::calibration_backing_accepted(&merged_root.join("../evil.so"), slot, &table,),
            "an escaping remainder must refuse"
        );
        // A layer path that stats nothing (copied-up file whose lower
        // was cleaned, or a container-hidden host lowerdir) refuses.
        assert!(
            !super::calibration_backing_accepted(&merged_root.join("absent.so"), slot, &table,),
            "unstatable layer files must refuse"
        );
    }

    #[test]
    fn backing_accepts_symlinked_merged_path_via_canonical_form() {
        // The merged path may reach the mount through a symlink (a
        // symlinked TMPDIR or operator path): canonicalization must
        // still land the remainder under the table mountpoint.
        let root = tempfile::tempdir().expect("tempdir");
        let (lower, upper, merged_root) = (
            root.path().join("lower"),
            root.path().join("upper"),
            root.path().join("merged"),
        );
        for dir in [&lower, &upper, &merged_root] {
            std::fs::create_dir(dir).expect("layer dir");
        }
        let layer_file = lower.join("lib.so");
        std::fs::write(&layer_file, [0xA7u8; 64]).expect("write");
        // The merged view itself exists (as on a live mount), so the
        // symlinked path canonicalizes instead of falling back.
        std::fs::write(merged_root.join("lib.so"), [0xA7u8; 64]).expect("write");
        let link = root.path().join("link");
        std::os::unix::fs::symlink(&merged_root, &link).expect("symlink");
        let table = overlay_table_for(&merged_root, &upper, &lower);
        assert!(
            super::calibration_backing_accepted(
                &link.join("lib.so"),
                backing_ino_of(&layer_file),
                &table,
            ),
            "a symlinked merged path must resolve to its layers"
        );
    }

    #[test]
    fn backing_refuses_lower_slot_when_upper_copy_exists() {
        // The merged path now backs onto the upper copy: a slot carrying
        // the lower (pre-copy-up) inode is a different backing file under
        // the same overlay ino and must refuse, even though the lower
        // candidate still exists on its layer.
        let root = tempfile::tempdir().expect("tempdir");
        let (lower, upper, merged_root) = (
            root.path().join("lower"),
            root.path().join("upper"),
            root.path().join("merged"),
        );
        for dir in [&lower, &upper, &merged_root] {
            std::fs::create_dir(dir).expect("layer dir");
        }
        let lower_file = lower.join("lib.so");
        std::fs::write(&lower_file, [0xA8u8; 64]).expect("write");
        let upper_file = upper.join("lib.so");
        std::fs::write(&upper_file, [0xA9u8; 64]).expect("write");
        assert_ne!(
            backing_ino_of(&lower_file),
            backing_ino_of(&upper_file),
            "the twin needs distinct layer inodes"
        );
        let table = overlay_table_for(&merged_root, &upper, &lower);
        assert!(
            !super::calibration_backing_accepted(
                &merged_root.join("lib.so"),
                backing_ino_of(&lower_file),
                &table,
            ),
            "a lower slot under an existing upper copy must refuse"
        );
    }

    #[test]
    fn backing_lower_match_under_existing_upper_needs_metacopy() {
        // Only a metadata-only upper still backs reads from the lower
        // file: the lower slot is accepted with a metacopy upper and
        // refused without one.
        let root = tempfile::tempdir().expect("tempdir");
        let (lower, upper, merged_root) = (
            root.path().join("lower"),
            root.path().join("upper"),
            root.path().join("merged"),
        );
        for dir in [&lower, &upper, &merged_root] {
            std::fs::create_dir(dir).expect("layer dir");
        }
        let lower_file = lower.join("lib.so");
        std::fs::write(&lower_file, [0xAAu8; 64]).expect("write");
        let upper_file = upper.join("lib.so");
        std::fs::write(&upper_file, [0xABu8; 64]).expect("write");
        let table = overlay_table_for(&merged_root, &upper, &lower);
        let merged = merged_root.join("lib.so");
        let slot = backing_ino_of(&lower_file);
        assert!(
            super::calibration_backing_accepted_with(&merged, slot, &table, |_| true),
            "a lower slot under a metacopy upper must accept"
        );
        assert!(
            !super::calibration_backing_accepted_with(&merged, slot, &table, |_| false),
            "a lower slot under a full upper copy must refuse"
        );
    }

    #[test]
    fn backing_refuses_non_regular_upper_over_lower_file() {
        // The topmost existing entry selects the backing file: an upper
        // symlink (whiteouts and directories read the same way) over a
        // lower file refuses instead of falling through to the lower.
        let root = tempfile::tempdir().expect("tempdir");
        let (lower, upper, merged_root) = (
            root.path().join("lower"),
            root.path().join("upper"),
            root.path().join("merged"),
        );
        for dir in [&lower, &upper, &merged_root] {
            std::fs::create_dir(dir).expect("layer dir");
        }
        let lower_file = lower.join("lib.so");
        std::fs::write(&lower_file, [0xACu8; 64]).expect("write");
        let upper_link = upper.join("lib.so");
        std::os::unix::fs::symlink(&lower_file, &upper_link).expect("symlink");
        let table = overlay_table_for(&merged_root, &upper, &lower);
        let merged = merged_root.join("lib.so");
        assert!(
            !super::calibration_backing_accepted(&merged, backing_ino_of(&lower_file), &table,),
            "a symlinked upper over a lower file must refuse"
        );
        // A directory upper refuses the same way.
        std::fs::remove_file(&upper_link).expect("remove");
        std::fs::create_dir(&upper_link).expect("dir");
        assert!(
            !super::calibration_backing_accepted(&merged, backing_ino_of(&lower_file), &table,),
            "a directory upper over a lower file must refuse"
        );
    }

    #[test]
    fn backing_refuses_non_regular_higher_lower_over_deeper_file() {
        // A non-regular entry in a higher lower layer refuses instead of
        // being skipped for a deeper lower file.
        let root = tempfile::tempdir().expect("tempdir");
        let (lower1, lower2, upper, merged_root) = (
            root.path().join("lower1"),
            root.path().join("lower2"),
            root.path().join("upper"),
            root.path().join("merged"),
        );
        for dir in [&lower1, &lower2, &upper, &merged_root] {
            std::fs::create_dir(dir).expect("layer dir");
        }
        let deep_file = lower2.join("lib.so");
        std::fs::write(&deep_file, [0xADu8; 64]).expect("write");
        std::os::unix::fs::symlink(&deep_file, lower1.join("lib.so")).expect("symlink");
        let table = format!(
            "31 23 0:27 / {} rw,relatime - overlay overlay rw,lowerdir={}:{},upperdir={}\n",
            merged_root.display(),
            lower1.display(),
            lower2.display(),
            upper.display(),
        );
        assert!(
            !super::calibration_backing_accepted(
                &merged_root.join("lib.so"),
                backing_ino_of(&deep_file),
                &table,
            ),
            "a symlinked higher lower over a deeper file must refuse"
        );
    }

    #[test]
    fn upper_is_metacopy_false_for_ordinary_files() {
        // The live probe reads `trusted.overlay.metacopy`: ordinary
        // files (and missing paths) report false, fail closed.
        let root = tempfile::tempdir().expect("tempdir");
        let plain = root.path().join("plain.so");
        std::fs::write(&plain, [0xACu8; 64]).expect("write");
        assert!(!super::upper_is_metacopy(&plain));
        assert!(!super::upper_is_metacopy(&root.path().join("absent.so")));
    }

    #[test]
    fn upper_is_metacopy_accepts_any_present_value_size() {
        // The presence probe reports the value size: 0 for the empty
        // marker, 4-plus-digest with verity. Any non-negative size is a
        // metacopy; only a failed probe is not. (A fixed 16-byte value
        // read fails the verity form with ERANGE.)
        let root = tempfile::tempdir().expect("tempdir");
        let upper = root.path().join("upper.so");
        std::fs::write(&upper, [0xAEu8; 64]).expect("write");
        assert!(super::upper_is_metacopy_with(&upper, |_, _| 0));
        assert!(super::upper_is_metacopy_with(&upper, |_, _| 40));
        assert!(!super::upper_is_metacopy_with(&upper, |_, _| -1));
    }

    #[test]
    fn start_requires_departure_calibration_and_watched_keys() {
        let (_dir, path) = temp_prearm_file("liby.so");
        let good = calib_for(&path);
        // No self_departs.
        let backend = ScriptBackend::new(good, 0);
        assert!(
            super::start_with(
                std::slice::from_ref(&path),
                3,
                0,
                0,
                false,
                super::DepartFamily::Pair,
                backend,
                || 100,
                &mut crate::discovery::scan::CaptureWorkBudget::default(),
            )
            .is_err()
        );
        // Insert failure.
        let mut backend = ScriptBackend::new(good, 1);
        backend.insert_err = true;
        assert!(
            super::start_with(
                std::slice::from_ref(&path),
                3,
                0,
                0,
                false,
                super::DepartFamily::Pair,
                backend,
                || 100,
                &mut crate::discovery::scan::CaptureWorkBudget::default(),
            )
            .is_err()
        );
    }

    #[test]
    fn start_refuses_nonregular_and_unopenable_paths() {
        let dir = tempfile::tempdir().expect("tempdir");
        let backend = ScriptBackend::new(super::PwCalibSlot::default(), 1);
        // Directory (non-regular).
        assert!(
            super::start_with(
                std::slice::from_ref(&dir.path().to_path_buf()),
                3,
                0,
                0,
                false,
                super::DepartFamily::Pair,
                backend,
                || 100,
                &mut crate::discovery::scan::CaptureWorkBudget::default(),
            )
            .is_err()
        );
        // Unopenable.
        let backend = ScriptBackend::new(super::PwCalibSlot::default(), 1);
        assert!(
            super::start_with(
                &[dir.path().join("missing.so")],
                3,
                0,
                0,
                false,
                super::DepartFamily::Pair,
                backend,
                || 100,
                &mut crate::discovery::scan::CaptureWorkBudget::default(),
            )
            .is_err()
        );
    }

    #[test]
    fn start_orders_keys_before_active_and_ns_after_write() {
        let (_dir, path) = temp_prearm_file("libz.so");
        let good = calib_for(&path);
        let backend = ScriptBackend::new(good, 1);
        let witnessed = super::start_with(
            std::slice::from_ref(&path),
            3,
            0,
            0,
            false,
            super::DepartFamily::Pair,
            backend,
            || 12345,
            &mut crate::discovery::scan::CaptureWorkBudget::default(),
        )
        .expect("clean start succeeds");
        assert_eq!(witnessed.active_ns, 12345);
        assert_eq!(witnessed.files.len(), 1);
    }

    #[test]
    fn start_records_key_before_active_order() {
        let (_dir, path) = temp_prearm_file("libw.so");
        let good = calib_for(&path);
        let backend = ScriptBackend::new(good, 1);
        let witnessed = super::start_with(
            std::slice::from_ref(&path),
            3,
            0,
            0,
            false,
            super::DepartFamily::Pair,
            backend,
            || 7,
            &mut crate::discovery::scan::CaptureWorkBudget::default(),
        )
        .expect("clean start succeeds");
        let ops = &witnessed.backend.ops;
        let key_pos = ops.iter().position(|op| op == "key0").expect("key op");
        let active_pos = ops.iter().position(|op| op == "active").expect("active op");
        assert!(key_pos < active_pos, "keys before active: {ops:?}");
    }

    #[test]
    fn start_calibration_mismatch_reports_calibration_class() {
        // A file the witness cannot calibrate (here: nothing backs the
        // slot inode) refuses with the calibration class, not btf.
        let (_dir, path) = temp_prearm_file("libcal.so");
        let good = calib_for(&path);
        let backend = ScriptBackend::new(
            super::PwCalibSlot {
                hits: 1,
                s_dev: good.s_dev,
                i_ino: good.i_ino.wrapping_add(1),
            },
            1,
        );
        let err = match super::start_with(
            std::slice::from_ref(&path),
            3,
            0,
            0,
            false,
            super::DepartFamily::Pair,
            backend,
            || 7,
            &mut crate::discovery::scan::CaptureWorkBudget::default(),
        ) {
            Ok(_) => panic!("a calibration mismatch must refuse"),
            Err(err) => err,
        };
        assert_eq!(err.class(), "calibration");
    }

    #[test]
    fn start_departure_miss_reports_calibration_class() {
        // A missed departure calibration refuses with the calibration
        // class, not btf.
        let (_dir, path) = temp_prearm_file("libdep.so");
        let backend = ScriptBackend::new(calib_for(&path), 0);
        let err = match super::start_with(
            std::slice::from_ref(&path),
            3,
            0,
            0,
            false,
            super::DepartFamily::Pair,
            backend,
            || 7,
            &mut crate::discovery::scan::CaptureWorkBudget::default(),
        ) {
            Ok(_) => panic!("a missed departure calibration must refuse"),
            Err(err) => err,
        };
        assert_eq!(err.class(), "calibration");
    }

    #[test]
    fn start_records_open_time_pin_for_condition_4() {
        // Condition 4 joins the witness fd's open-time pin against the
        // pre-arm pin's held baseline: the recorded pin must equal the
        // file's pin at startup.
        let (_dir, path) = temp_prearm_file("libpin.so");
        let backend = ScriptBackend::new(calib_for(&path), 1);
        let witnessed = super::start_with(
            std::slice::from_ref(&path),
            3,
            0,
            0,
            false,
            super::DepartFamily::Pair,
            backend,
            || 7,
            &mut crate::discovery::scan::CaptureWorkBudget::default(),
        )
        .expect("clean start succeeds");
        assert_eq!(witnessed.files.len(), 1);
        let expected =
            crate::discovery::identity::pin_of(&std::fs::File::open(&path).expect("open"))
                .expect("pin");
        assert_eq!(witnessed.files[0].pin, expected);
    }

    #[test]
    fn start_refuses_when_file_changes_between_open_and_fstat() {
        // A copy-up landing between open() and the open-time pin must
        // refuse with the calibration class: the calibration mmap maps
        // the pre-copy-up file while the pin would read post-copy-up
        // state. The hook chmods the file in that window (a ctime-only
        // change, like a copy-up).
        let (_dir, path) = temp_prearm_file("libopenrace.so");
        let backend = ScriptBackend::new(calib_for(&path), 1);
        let err = match super::open_race_test::observe(
            |victim| {
                use std::os::unix::fs::PermissionsExt as _;
                let mode = std::fs::metadata(victim)
                    .expect("stat the victim")
                    .permissions()
                    .mode();
                std::fs::set_permissions(victim, std::fs::Permissions::from_mode(mode ^ 0o100))
                    .expect("chmod the victim");
            },
            || {
                super::start_with(
                    std::slice::from_ref(&path),
                    3,
                    0,
                    0,
                    false,
                    super::DepartFamily::Pair,
                    backend,
                    || 7,
                    &mut crate::discovery::scan::CaptureWorkBudget::default(),
                )
            },
        ) {
            Ok(_) => panic!("a change between open and fstat must refuse"),
            Err(err) => err,
        };
        assert_eq!(err.class(), "calibration");
    }

    #[test]
    fn start_open_failure_reports_calibration_class() {
        // An open failure inside the per-file loop refuses with the
        // calibration class, not btf: no BTF problem is involved. The
        // file stats (pre-open pin) but does not open (mode 000). Which
        // claim applies is decided by what this process can actually do
        // (root opens mode-000 files): both configurations assert.
        let (_dir, path) = temp_prearm_file("libopenfail.so");
        use std::os::unix::fs::PermissionsExt as _;
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o000)).expect("chmod");
        let denied = std::fs::File::open(&path).is_err();
        let backend = ScriptBackend::new(calib_for(&path), 1);
        let outcome = super::start_with(
            std::slice::from_ref(&path),
            3,
            0,
            0,
            false,
            super::DepartFamily::Pair,
            backend,
            || 7,
            &mut crate::discovery::scan::CaptureWorkBudget::default(),
        );
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o644)).expect("restore");
        if !denied {
            assert!(outcome.is_ok(), "an openable file starts");
            return;
        }
        let err = match outcome {
            Ok(_) => panic!("an unopenable path must refuse"),
            Err(err) => err,
        };
        assert_eq!(err.class(), "calibration");
    }

    #[test]
    fn start_reads_mountinfo_only_on_calibration_mismatch() {
        // Laziness: a direct-match calibration never touches the mount
        // table, so the budget records no table IO.
        let (_dir, path) = temp_prearm_file("liblazy.so");
        let backend = ScriptBackend::new(calib_for(&path), 1);
        let mut budget = crate::discovery::scan::CaptureWorkBudget::default();
        let witnessed = super::start_with(
            std::slice::from_ref(&path),
            3,
            0,
            0,
            false,
            super::DepartFamily::Pair,
            backend,
            || 7,
            &mut budget,
        )
        .expect("clean start succeeds");
        assert_eq!(witnessed.files.len(), 1);
        assert_eq!(
            budget.attempted_io_bytes(),
            0,
            "no table read without a mismatch"
        );
    }

    #[test]
    fn start_fallback_table_read_goes_through_the_budget() {
        // A direct mismatch reads the observer table through the bounded
        // reader: the budget records the table IO (and the non-overlay
        // temp file still refuses, fail closed).
        let (_dir, path) = temp_prearm_file("libcharged.so");
        let good = calib_for(&path);
        let backend = ScriptBackend::new(
            super::PwCalibSlot {
                hits: 1,
                s_dev: good.s_dev,
                i_ino: good.i_ino.wrapping_add(1),
            },
            1,
        );
        let mut budget = crate::discovery::scan::CaptureWorkBudget::default();
        let err = match super::start_with(
            std::slice::from_ref(&path),
            3,
            0,
            0,
            false,
            super::DepartFamily::Pair,
            backend,
            || 7,
            &mut budget,
        ) {
            Ok(_) => panic!("an unbacked slot must refuse"),
            Err(err) => err,
        };
        assert_eq!(err.class(), "calibration");
        assert!(
            budget.attempted_io_bytes() > 0,
            "the fallback read charges the budget"
        );
    }

    fn probe_softhsm_path() -> std::path::PathBuf {
        for candidate in [
            "/usr/lib/x86_64-linux-gnu/softhsm/libsofthsm2.so",
            "/usr/lib64/pkcs11/libsofthsm2.so",
        ] {
            let path = std::path::PathBuf::from(candidate);
            if path.is_file() {
                return path;
            }
        }
        // Fallback: first libsofthsm2.so under the known roots.
        for root in [
            "/usr/lib/x86_64-linux-gnu/softhsm",
            "/usr/lib64/pkcs11",
            "/usr/lib/softhsm",
        ] {
            if let Ok(entries) = std::fs::read_dir(root) {
                for entry in entries.flatten() {
                    let path = entry.path();
                    if path
                        .file_name()
                        .is_some_and(|name| name == "libsofthsm2.so")
                        && path.is_file()
                    {
                        return path;
                    }
                }
            }
        }
        panic!("SoftHSM not found under the probed provider paths");
    }

    /// Privileged twin: a live start on the host, then `active` read back.
    #[test]
    #[ignore = "privileged: live witness start on the host"]
    fn privileged_start_activates_on_host() {
        let path = probe_softhsm_path();
        let raw_btf = std::fs::read("/sys/kernel/btf/vmlinux").expect("host BTF bytes");
        let family = super::resolve_depart_family(&raw_btf).expect("depart family");
        super::check_target_protos(&raw_btf, false).expect("target protos");
        let btf = aya::Btf::from_sys_fs().expect("host BTF");
        let depart: &[&'static str] = match family {
            super::DepartFamily::Pair => &[super::PROGRAM_DEPART_EXIT, super::PROGRAM_DEPART_EXEC],
            super::DepartFamily::Single => &[super::PROGRAM_DEPART],
        };
        let loaded = super::load_witness_programs(&btf, depart, false).expect("witness loads");
        let backend = super::LiveBackend::from_loaded(loaded.ebpf);
        let witnessed = super::start_with(
            std::slice::from_ref(&path),
            3,
            0,
            0,
            false,
            family,
            backend,
            || crate::attach::monotonic_ns().expect("monotonic clock"),
            &mut crate::discovery::scan::CaptureWorkBudget::default(),
        )
        .expect("live start succeeds");
        assert_eq!(witnessed.backend.read_active().expect("read active"), 1);
        assert!(witnessed.active_ns > 0);
        assert_eq!(witnessed.files.len(), 1);
        eprintln!(
            "witness live start ok: active_ns={} key=({},{})",
            witnessed.active_ns, witnessed.files[0].key.s_dev, witnessed.files[0].key.i_ino
        );
    }

    // P2-5 finalize tests with a scripted backend.
    struct ScriptFinalize {
        ops: Vec<String>,
        walks: Vec<super::WalkOutcome>,
        state: super::PwState,
        busy_settles: bool,
        misses: u64,
        settle_max: Option<u32>,
        // Scripted close-error inputs (None takes the Ok path).
        misses_err: Option<String>,
        deactivate_err: Option<String>,
        read_err: Option<String>,
    }

    impl ScriptFinalize {
        fn clean() -> Self {
            let state = super::PwState {
                walk_end: 1,
                pending_in: 2,
                pending_out: 2,
                ..super::PwState::default()
            };
            Self {
                ops: Vec::new(),
                walks: vec![super::WalkOutcome::Done],
                state,
                busy_settles: true,
                misses: 0,
                settle_max: None,
                misses_err: None,
                deactivate_err: None,
                read_err: None,
            }
        }
    }

    impl super::FinalizeBackend for ScriptFinalize {
        type Error = String;
        fn run_walk(&mut self) -> Result<super::WalkOutcome, String> {
            self.ops.push("walk".into());
            Ok(self.walks.remove(0))
        }
        fn read_state(&mut self) -> Result<super::PwState, String> {
            self.ops.push("read".into());
            if let Some(error) = self.read_err.clone() {
                return Err(error);
            }
            Ok(self.state)
        }
        fn deactivate(&mut self) -> Result<(), String> {
            self.ops.push("deactivate".into());
            if let Some(error) = self.deactivate_err.clone() {
                return Err(error);
            }
            Ok(())
        }
        fn settle_busy(&mut self, max: u32) -> Result<bool, String> {
            self.ops.push("settle".into());
            self.settle_max = Some(max);
            Ok(self.busy_settles)
        }
        fn release(&mut self) -> Result<(), String> {
            self.ops.push("release".into());
            Ok(())
        }
        fn recursion_misses(&mut self, program: &str) -> Result<u64, String> {
            self.ops.push(format!("miss:{program}"));
            if let Some(error) = self.misses_err.clone() {
                return Err(error);
            }
            Ok(self.misses)
        }
    }

    #[test]
    fn finalize_clean_empty_clears() {
        let mut backend = ScriptFinalize::clean();
        let verdicts = super::finalize_with(&mut backend, 1, Some("1".into()));
        assert_eq!(verdicts, vec![super::FileVerdict::Clear]);
        // Close ordering: walk, deactivate, settle, read, release.
        let ops = backend.ops.join(",");
        let walk = ops.find("walk").unwrap();
        let deact = ops.find("deactivate").unwrap();
        let settle = ops.find("settle").unwrap();
        let read = ops.find("read").unwrap();
        let release = ops.find("release").unwrap();
        assert!(
            walk < deact && deact < settle && settle < read && read < release,
            "close order: {ops}"
        );
    }

    #[test]
    fn finalize_quiescence_and_walk_rules() {
        // Busy settles: one walk suffices (visited, no second walk).
        let mut backend = ScriptFinalize::clean();
        super::finalize_with(&mut backend, 1, Some("1".into()));
        assert_eq!(
            backend.ops.iter().filter(|op| *op == "walk").count(),
            1,
            "one walk on success: {:?}",
            backend.ops
        );
        // Fatal walk: `walk` after exactly one walk (no second walk:
        // an abandoned walk emits no END, so a retry could never satisfy
        // `walk_end == 1`; EAGAIN resumes inside the single walk).
        let mut backend = ScriptFinalize::clean();
        backend.walks = vec![super::WalkOutcome::Fatal("snapshot".into())];
        let verdicts = super::finalize_with(&mut backend, 1, Some("1".into()));
        assert_eq!(
            verdicts,
            vec![super::FileVerdict::Keep(super::KeepReason::Walk)]
        );
        assert_eq!(
            backend.ops.iter().filter(|op| *op == "walk").count(),
            1,
            "exactly one walk even on failure: {:?}",
            backend.ops
        );
        // Unsettled busy: `quiesce`.
        let mut backend = ScriptFinalize::clean();
        backend.busy_settles = false;
        let verdicts = super::finalize_with(&mut backend, 1, Some("1".into()));
        assert_eq!(
            verdicts,
            vec![super::FileVerdict::Keep(super::KeepReason::Quiesce)]
        );
    }

    #[test]
    fn finalize_pending_reads_state_once() {
        // Spec §4.6 step 4 reads PW_STATE once: pending is frozen after
        // deactivate + settle (later hooks return before touching it),
        // so re-reading cannot observe a change.
        let mut backend = ScriptFinalize::clean();
        backend.state.pending_in = 2;
        backend.state.pending_out = 1;
        let verdicts = super::finalize_with(&mut backend, 1, Some("1".into()));
        assert_eq!(
            verdicts,
            vec![super::FileVerdict::Keep(super::KeepReason::Pending)]
        );
        assert_eq!(
            backend.ops.iter().filter(|op| *op == "read").count(),
            1,
            "single state read: {:?}",
            backend.ops
        );
    }

    #[test]
    fn finalize_quiesce_bound_is_one_second() {
        // Spec §4.6 step 3: poll busy with a 1 s deadline. Each flip is
        // one 1 ms sleep plus a read, so 1000 flips ≈ 1 s.
        let mut backend = ScriptFinalize::clean();
        super::finalize_with(&mut backend, 1, Some("1".into()));
        assert_eq!(
            backend.settle_max,
            Some(1000),
            "quiesce deadline flips: {:?}",
            backend.settle_max
        );
    }

    #[test]
    fn finalize_verdict_boundaries_keep_windows() {
        use super::KeepReason;
        // Each boundary condition keeps the window with its exact reason
        // (P2-5 RED: each nonclean §8 group 3-5 input → that exact reason).
        type StateCase = (KeepReason, Box<dyn Fn(&mut super::PwState)>);
        let mut cases: Vec<StateCase> = vec![
            (KeepReason::Latched, Box::new(|s| s.latch_slots = 1)),
            (KeepReason::Torn, Box::new(|s| s.torn_slots = 1)),
            (KeepReason::Found, Box::new(|s| s.found_slots = 1)),
            (KeepReason::Migration, Box::new(|s| s.migrations = 1)),
            (KeepReason::Pending, Box::new(|s| s.pending_out = 1)),
            (KeepReason::Fault, Box::new(|s| s.faults = 1)),
            (KeepReason::Stuck, Box::new(|s| s.stuck = 1)),
            (KeepReason::Walk, Box::new(|s| s.walk_end = 2)),
        ];
        for (reason, mutate) in cases.drain(..) {
            let mut backend = ScriptFinalize::clean();
            mutate(&mut backend.state);
            let verdicts = super::finalize_with(&mut backend, 1, Some("1".into()));
            assert_eq!(
                verdicts,
                vec![super::FileVerdict::Keep(reason)],
                "{} keeps the window",
                reason.as_str(),
            );
        }
        // Recursion misses keep with `recursion`.
        let mut backend = ScriptFinalize::clean();
        backend.misses = 1;
        let verdicts = super::finalize_with(&mut backend, 1, Some("1".into()));
        assert_eq!(
            verdicts,
            vec![super::FileVerdict::Keep(KeepReason::Recursion)]
        );
        // ftrace not 1 keeps with `ftrace`.
        let mut backend = ScriptFinalize::clean();
        let verdicts = super::finalize_with(&mut backend, 1, Some("0".into()));
        assert_eq!(verdicts, vec![super::FileVerdict::Keep(KeepReason::Ftrace)]);
        // Second slot with a latch keeps only that slot (lattice row).
        let mut backend = ScriptFinalize::clean();
        backend.state.latch_slots = 0b10;
        let verdicts = super::finalize_with(&mut backend, 2, Some("1".into()));
        assert_eq!(
            verdicts,
            vec![
                super::FileVerdict::Clear,
                super::FileVerdict::Keep(KeepReason::Latched)
            ]
        );
        // Priority: found beats latch beats torn (the mprotect dance
        // latches spuriously while the mapping stays present).
        let mut backend = ScriptFinalize::clean();
        backend.state.latch_slots = 1;
        backend.state.torn_slots = 1;
        backend.state.found_slots = 1;
        let verdicts = super::finalize_with(&mut backend, 1, Some("1".into()));
        assert_eq!(verdicts, vec![super::FileVerdict::Keep(KeepReason::Found)]);
        let mut backend = ScriptFinalize::clean();
        backend.state.latch_slots = 1;
        backend.state.torn_slots = 1;
        let verdicts = super::finalize_with(&mut backend, 1, Some("1".into()));
        assert_eq!(
            verdicts,
            vec![super::FileVerdict::Keep(KeepReason::Latched)]
        );
    }

    #[test]
    fn finalize_recursion_misses_error_keeps_recursion() {
        // Spec §2 condition 7 needs the health fact verified, not
        // assumed: an unreadable recursion-miss count keeps windows.
        let mut backend = ScriptFinalize::clean();
        backend.misses_err = Some("prog info omits recursion misses".into());
        let verdicts = super::finalize_with(&mut backend, 1, Some("1".into()));
        assert_eq!(
            verdicts,
            vec![super::FileVerdict::Keep(super::KeepReason::Recursion)]
        );
    }

    #[test]
    fn finalize_deactivate_error_keeps_quiesce() {
        // A close that never proved its hooks quiet cannot trust the
        // state read; cleanup (settle, read, release) still runs.
        let mut backend = ScriptFinalize::clean();
        backend.deactivate_err = Some("cfg rewrite refused".into());
        let verdicts = super::finalize_with(&mut backend, 1, Some("1".into()));
        assert_eq!(
            verdicts,
            vec![super::FileVerdict::Keep(super::KeepReason::Quiesce)]
        );
        for op in ["walk", "deactivate", "settle", "read", "release"] {
            assert!(
                backend.ops.iter().any(|seen| seen == op),
                "cleanup still runs {op}: {:?}",
                backend.ops
            );
        }
    }

    #[test]
    fn finalize_read_state_error_keeps_fault() {
        // An unreadable close-time state is a fault, not evidence.
        let mut backend = ScriptFinalize::clean();
        backend.read_err = Some("PW_STATE unreadable".into());
        let verdicts = super::finalize_with(&mut backend, 1, Some("1".into()));
        assert_eq!(
            verdicts,
            vec![super::FileVerdict::Keep(super::KeepReason::Fault)]
        );
    }

    /// One-file started witness over a scripted clean backend, for the
    /// driver `finalize` twins. The dir outlives the witness: dropping it
    /// would unlink the file and rotate ctime, which the finalize pin
    /// re-check must (and does) flag.
    fn scripted_started_witness() -> (tempfile::TempDir, super::StartupWitness<ScriptFinalize>) {
        use std::os::unix::fs::MetadataExt as _;
        use std::os::unix::io::{FromRawFd as _, IntoRawFd as _};
        let dir = tempfile::tempdir().expect("tempdir");
        let path = dir.path().join("witness-assembly.so");
        std::fs::write(&path, [0x7fu8, b'E', b'L', b'F']).expect("write");
        let meta = std::fs::metadata(&path).expect("fstat");
        let file = std::fs::File::open(&path).expect("open");
        let pin = crate::discovery::identity::pin_of(&file).expect("pin");
        let raw = file.into_raw_fd();
        // SAFETY: owned fd from an open File.
        let fd = unsafe { std::os::fd::OwnedFd::from_raw_fd(raw) };
        let witnessed = super::StartupWitness {
            backend: ScriptFinalize::clean(),
            files: vec![super::WitnessFile {
                fd,
                dev: meta.dev(),
                ino: meta.ino(),
                pin,
                key: super::PwWatchedKey {
                    s_dev: meta.dev(),
                    i_ino: meta.ino(),
                },
            }],
            active_ns: 40,
            scope_start_ns: Some(50),
        };
        (dir, witnessed)
    }

    #[test]
    fn driver_finalize_owned_drops_without_verdict() {
        let (_dir, witnessed) = scripted_started_witness();
        assert_eq!(witnessed.finalize(true), None);
    }

    #[test]
    fn driver_finalize_assembles_verdict_from_clean_close() {
        let (_dir, witnessed) = scripted_started_witness();
        let (dev, ino) = (witnessed.files[0].dev, witnessed.files[0].ino);
        let verdict = witnessed.finalize(false).expect("clean close verdict");
        assert_eq!(verdict.active_ns, 40);
        assert_eq!(verdict.scope_start_ns, Some(50));
        assert!(verdict.walk_started_ns > 0, "walk clock stamped");
        assert_eq!(verdict.slots.len(), 1);
        assert_eq!(verdict.slots[0].verdict, super::FileVerdict::Clear);
        assert_eq!(verdict.slots[0].fd_dev, dev);
        assert_eq!(verdict.slots[0].fd_ino, ino);
    }

    /// One-file started witness over a live temp path (the dir outlives
    /// the witness), for the finalize re-check twin: the file must stay
    /// rewritable after startup.
    fn scripted_started_witness_live() -> (
        tempfile::TempDir,
        std::path::PathBuf,
        super::StartupWitness<ScriptFinalize>,
    ) {
        use std::os::unix::fs::MetadataExt as _;
        use std::os::unix::io::{FromRawFd as _, IntoRawFd as _};
        let dir = tempfile::tempdir().expect("tempdir");
        let path = dir.path().join("witness-recheck.so");
        std::fs::write(&path, [0x7fu8, b'E', b'L', b'F']).expect("write");
        let meta = std::fs::metadata(&path).expect("fstat");
        let file = std::fs::File::open(&path).expect("open");
        let pin = crate::discovery::identity::pin_of(&file).expect("pin");
        let raw = file.into_raw_fd();
        // SAFETY: owned fd from an open File.
        let fd = unsafe { std::os::fd::OwnedFd::from_raw_fd(raw) };
        let witnessed = super::StartupWitness {
            backend: ScriptFinalize::clean(),
            files: vec![super::WitnessFile {
                fd,
                dev: meta.dev(),
                ino: meta.ino(),
                pin,
                key: super::PwWatchedKey {
                    s_dev: meta.dev(),
                    i_ino: meta.ino(),
                },
            }],
            active_ns: 40,
            scope_start_ns: Some(50),
        };
        (dir, path, witnessed)
    }

    #[test]
    fn driver_finalize_changed_witness_fd_keeps_calibration() {
        // The witness fd's file changed between startup and finalize
        // (a copy-up rewrites ctime the same way; size is preserved):
        // the calibration-time key watches the old file, so the slot
        // must keep its window with the calibration reason even though
        // the walk was clean.
        let (_dir, path, witnessed) = scripted_started_witness_live();
        std::fs::write(&path, [0x7fu8, b'E', b'L', b'F', 1, 2, 3, 4]).expect("rewrite");
        let verdict = witnessed.finalize(false).expect("finalize verdict");
        assert_eq!(verdict.slots.len(), 1);
        assert_eq!(
            verdict.slots[0].verdict,
            super::FileVerdict::Keep(super::KeepReason::Calibration)
        );
    }

    #[test]
    fn keep_reasons_carry_exact_section_61_spellings() {
        let spelled: Vec<&str> = super::KeepReason::all()
            .iter()
            .map(|reason| reason.as_str())
            .collect();
        assert_eq!(
            spelled,
            [
                "latched",
                "torn",
                "found",
                "migration",
                "pending",
                "fault",
                "stuck",
                "recursion",
                "ftrace",
                "walk",
                "quiesce",
                "calibration",
            ]
        );
    }

    /// P2-5 contract: this module never names the four kernel-only maps
    /// (departed, visited, self, run) outside map-shape validation.
    /// Production code names none of them at all; test code names them
    /// only in the shape table, the map-cap enumeration, or a line marked
    /// `test-only` (one privileged cell setup). The names below are
    /// assembled from fragments so this test does not name them itself.
    #[test]
    fn witness_source_confines_kernel_only_map_names() {
        let source = std::fs::read_to_string(concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/src/attach/prearm_witness.rs"
        ))
        .expect("read own source");
        let marker = "#[cfg(test)]\nmod tests {";
        let tests_at = source.find(marker).expect("tests module marker");
        let names = [
            ["PW_", "DEPARTED"].concat(),
            ["PW_", "VISITED"].concat(),
            ["PW_", "SELF"].concat(),
            ["PW_", "RUN"].concat(),
        ];
        // The map-cap enumeration span (fmt-proof: whatever layout the
        // array body takes, it stays between its opener and `]`). The
        // opener match anchors at line start so these very lines (which
        // name the opener pattern) do not open a span themselves.
        let openers = source
            .lines()
            .filter(|line| line.trim_start().starts_with("for cap in ["))
            .count();
        assert_eq!(openers, 1, "exactly one map-cap enumeration");
        let mut in_caps = false;
        for (index, line) in source.lines().enumerate() {
            let number = index + 1;
            if line.trim_start().starts_with("for cap in [") {
                in_caps = true;
            }
            let in_enumeration = in_caps;
            if in_caps && line.contains(']') {
                in_caps = false;
            }
            if !names.iter().any(|name| line.contains(name)) {
                continue;
            }
            let offset: usize = source
                .lines()
                .take(index)
                .map(|prior| prior.len() + 1)
                .sum();
            if offset < tests_at {
                panic!("production line {number} names a kernel-only map: {line}");
            }
            let trimmed = line.trim_start();
            let allowed =
                trimmed.starts_with("(\"PW_") || in_enumeration || line.contains("test-only");
            assert!(
                allowed,
                "test line {number} names a kernel-only map outside shape validation: {line}"
            );
        }
    }

    /// Privileged twin: live start + two-walk finalize on the host.
    #[test]
    #[ignore = "privileged: live witness finalize on the host"]
    fn privileged_finalize_clears_clean_start() {
        use super::FinalizeBackend as _;
        // Private temp file: nothing else on the host maps it, so FOUND
        // stays clear (SoftHSM may be mapped by other processes).
        let dir = tempfile::tempdir().expect("tempdir");
        let path = dir.path().join("witness-clean.so");
        std::fs::write(&path, vec![0x7f, b'E', b'L', b'F', 0, 1, 2, 3]).expect("write");
        let raw_btf = std::fs::read("/sys/kernel/btf/vmlinux").expect("host BTF bytes");
        let family = super::resolve_depart_family(&raw_btf).expect("depart family");
        super::check_target_protos(&raw_btf, false).expect("target protos");
        let btf = aya::Btf::from_sys_fs().expect("host BTF");
        let depart: &[&'static str] = match family {
            super::DepartFamily::Pair => &[super::PROGRAM_DEPART_EXIT, super::PROGRAM_DEPART_EXEC],
            super::DepartFamily::Single => &[super::PROGRAM_DEPART],
        };
        let loaded = super::load_witness_programs(&btf, depart, false).expect("witness loads");
        let backend = super::LiveBackend::from_loaded(loaded.ebpf);
        let mut witnessed = super::start_with(
            std::slice::from_ref(&path),
            3,
            0,
            0,
            false,
            family,
            backend,
            || crate::attach::monotonic_ns().expect("clock"),
            &mut crate::discovery::scan::CaptureWorkBudget::default(),
        )
        .expect("live start succeeds");
        let ftrace = std::fs::read_to_string("/proc/sys/kernel/ftrace_enabled").ok();
        let verdicts = super::finalize_with(&mut witnessed.backend, 1, ftrace);
        if verdicts != vec![super::FileVerdict::Clear] {
            let state = witnessed.backend.read_state().expect("read state");
            eprintln!(
                "witness state: latch={:#x} torn={:#x} found={:#x} mig={} pin={} pout={} faults={} stuck={} wend={} wruns={} wvmas={} busy={}",
                state.latch_slots,
                state.torn_slots,
                state.found_slots,
                state.migrations,
                state.pending_in,
                state.pending_out,
                state.faults,
                state.stuck,
                state.walk_end,
                state.walk_runs,
                state.walk_vmas,
                state.busy
            );
        }
        assert_eq!(verdicts, vec![super::FileVerdict::Clear]);
        eprintln!("witness live finalize ok: Clear");
    }

    /// Privileged twin: quiesce settles under parallel maps churn.
    #[test]
    #[ignore = "privileged: witness quiesce under maps churn"]
    fn privileged_finalize_settles_under_churn() {
        let dir = tempfile::tempdir().expect("tempdir");
        let path = dir.path().join("witness-churn.so");
        std::fs::write(&path, vec![0x7f, b'E', b'L', b'F', 4, 5, 6, 7]).expect("write");
        let raw_btf = std::fs::read("/sys/kernel/btf/vmlinux").expect("host BTF bytes");
        let family = super::resolve_depart_family(&raw_btf).expect("depart family");
        super::check_target_protos(&raw_btf, false).expect("target protos");
        let btf = aya::Btf::from_sys_fs().expect("host BTF");
        let depart: &[&'static str] = match family {
            super::DepartFamily::Pair => &[super::PROGRAM_DEPART_EXIT, super::PROGRAM_DEPART_EXEC],
            super::DepartFamily::Single => &[super::PROGRAM_DEPART],
        };
        let loaded = super::load_witness_programs(&btf, depart, false).expect("witness loads");
        let backend = super::LiveBackend::from_loaded(loaded.ebpf);
        let mut witnessed = super::start_with(
            std::slice::from_ref(&path),
            3,
            0,
            0,
            false,
            family,
            backend,
            || crate::attach::monotonic_ns().expect("clock"),
            &mut crate::discovery::scan::CaptureWorkBudget::default(),
        )
        .expect("live start succeeds");
        // Churn an unwatched temp file mapping while finalizing.
        let churn_dir = tempfile::tempdir().expect("tempdir");
        let churn_path = churn_dir.path().join("churn.bin");
        std::fs::write(&churn_path, vec![0u8; 8192]).expect("write churn");
        let churn_file = std::fs::File::open(&churn_path).expect("open churn");
        use std::os::unix::io::AsRawFd as _;
        let churn_fd = churn_file.as_raw_fd();
        let stop = std::sync::Arc::new(std::sync::atomic::AtomicBool::new(false));
        let stop_clone = stop.clone();
        let churner = std::thread::spawn(move || {
            while !stop_clone.load(std::sync::atomic::Ordering::Relaxed) {
                // SAFETY: short-lived private mapping of an open file.
                let addr = unsafe {
                    libc::mmap(
                        std::ptr::null_mut(),
                        4096,
                        libc::PROT_READ,
                        libc::MAP_PRIVATE,
                        churn_fd,
                        0,
                    )
                };
                if addr != libc::MAP_FAILED {
                    unsafe { libc::munmap(addr, 4096) };
                }
            }
        });
        let ftrace = std::fs::read_to_string("/proc/sys/kernel/ftrace_enabled").ok();
        let verdicts = super::finalize_with(&mut witnessed.backend, 1, ftrace);
        stop.store(true, std::sync::atomic::Ordering::Relaxed);
        churner.join().expect("churner joins");
        // Unwatched churn must not latch or break quiescence.
        assert_eq!(verdicts, vec![super::FileVerdict::Clear]);
        eprintln!("witness quiesce under churn ok: Clear");
    }

    #[test]
    fn userspace_reads_only_state_and_calib() {
        // Contract (§4.0 rules): userspace map reads are PW_STATE/PW_CALIB
        // only. Fail on any other `.map("PW_...")` reader in this module.
        let source = std::fs::read_to_string(concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/src/attach/prearm_witness.rs"
        ))
        .expect("read own source");
        for (index, line) in source.lines().enumerate() {
            let line_no = index + 1;
            // Skip this contract test itself (it names the maps).
            if line.contains("PW_STATE/PW_CALIB") || line.contains(".map(\"PW_") {
                // Allow the two readers; fail on any other map name.
                for cap in [
                    "PW_CFG",
                    "PW_WATCHED",
                    "PW_DEPARTED",
                    "PW_VISITED",
                    "PW_SELF",
                    "PW_RUN",
                ] {
                    let probe = format!(".map(\"{cap}\"");
                    assert!(!line.contains(&probe), "line {line_no} reads {cap}: {line}");
                }
            }
        }
    }
}
