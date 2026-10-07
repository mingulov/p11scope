//! SPDX-License-Identifier: GPL-3.0-or-later
//! Stage 3 Wave D kernel-side identity (D2a+b): the aya loader, record
//! parser, run reader, and raw iterator syscalls for the `vma_identity` BPF
//! object (`crates/ebpf/native/vma_identity.c`).
//!
//! Standalone by construction: this file takes no `crate::` dependency, so
//! the W3-1 harness can include it by path until W3-2 wires it into
//! `attach.rs`. Every ABI constant mirrors `vma_identity.h`; the inline
//! tests pin the shared layout against that header.

use std::collections::{BTreeMap, BTreeSet};
use std::io;
use std::os::fd::{AsFd as _, AsRawFd as _, BorrowedFd, FromRawFd as _, OwnedFd};
use std::time::Instant;

// ---------------------------------------------------------------------------
// Record ABI (§5). Mirrors `vma_identity.h`; `c_header_records_match` pins it.
// ---------------------------------------------------------------------------

/// Record magic `0x4950` ("PI"), little-endian.
pub const RECORD_MAGIC: u16 = 0x4950;
/// Record layout version the parser accepts.
pub const RECORD_VERSION: u8 = 1;
/// Every record is exactly 32 bytes.
pub const RECORD_LEN: usize = 32;
/// `kind` of a target verdict record.
pub const KIND_VMA: u8 = 1;
/// `kind` of an anchor-installation record.
pub const KIND_ANCHOR: u8 = 2;
/// `kind` of the end-of-run record.
pub const KIND_END: u8 = 3;
/// VMA verdict for "other file": no anchor matched this VMA.
pub const VERDICT_NONE: u32 = 0xFFFF_FFFF;
/// Anchor verdict: the slot installed.
pub const ANCHOR_OK: u32 = 0;
/// Anchor verdict: the slot aliases another installed slot (`start` names it).
pub const ANCHOR_DUP: u32 = 1;
/// Anchor verdict: the anchor map refused the insert.
pub const ANCHOR_FULL: u32 = 2;
/// Anchor verdict: the arena VMA failed the shape check.
pub const ANCHOR_BAD_SHAPE: u32 = 3;
/// Anchor slots in the kernel maps.
pub const ANCHOR_SLOTS: u32 = 1024;
/// Words in the scope bitmap; covers `PID_MAX_LIMIT` (2^22).
pub const SCOPE_WORDS: usize = 65_536;
/// I6 kernel-pointer guard: no record address field may reach 2^56.
pub const POINTER_GUARD: u64 = 1 << 56;
/// Page granularity every VMA range must honor.
pub const PAGE_GRANULE: u64 = 4096;

// ---------------------------------------------------------------------------
// `config[0]` and the scope bitmap.
// ---------------------------------------------------------------------------

/// Userspace view of `struct p11_identity_config`: observer addresses and
/// counters only, never kernel pointers.
#[repr(C)]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct IdentityConfig {
    /// Pass generation; anchor entries and records must carry it (I2).
    pub generation: u64,
    /// Observer's anchor-arena base address.
    pub arena_base: u64,
    /// Observer's anchor-arena length in bytes.
    pub arena_len: u64,
    /// Slots installed this pass (`<= ANCHOR_SLOTS`).
    pub slots: u32,
    /// Reserved, always zero.
    pub pad: u32,
}

const _: () = assert!(size_of::<IdentityConfig>() == 32);
const _: () = assert!(std::mem::offset_of!(IdentityConfig, generation) == 0);
const _: () = assert!(std::mem::offset_of!(IdentityConfig, arena_base) == 8);
const _: () = assert!(std::mem::offset_of!(IdentityConfig, arena_len) == 16);
const _: () = assert!(std::mem::offset_of!(IdentityConfig, slots) == 24);

/// Value of an `anchors` entry, for documentation and tests. The kernel owns
/// these entries; userspace never reads them (I6).
#[repr(C)]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct AnchorEntry {
    pub slot: u32,
    pub pad: u32,
    pub generation: u64,
}

const _: () = assert!(size_of::<AnchorEntry>() == 16);
const _: () = assert!(std::mem::offset_of!(AnchorEntry, generation) == 8);

/// Bitmap cell for `tgid`: `(word, bit)`, or `None` past the bitmap (the
/// in-program bound check drops such tasks before they can emit).
pub fn scope_word_bit(tgid: u32) -> Option<(usize, u64)> {
    let word = (tgid >> 6) as usize;
    if word >= SCOPE_WORDS {
        return None;
    }
    Some((word, 1u64 << (tgid & 63)))
}

/// Set `tgid`'s bit in a scope bitmap slice. Returns false (without touching
/// the slice) when the tgid is past the bitmap or the slice is short.
pub fn scope_set_bit(bitmap: &mut [u64], tgid: u32) -> bool {
    let Some((word, bit)) = scope_word_bit(tgid) else {
        return false;
    };
    let Some(cell) = bitmap.get_mut(word) else {
        return false;
    };
    *cell |= bit;
    true
}

/// Test `tgid`'s bit. A short slice or an out-of-range tgid reads as absent.
pub fn scope_test_bit(bitmap: &[u64], tgid: u32) -> bool {
    let Some((word, bit)) = scope_word_bit(tgid) else {
        return false;
    };
    bitmap.get(word).is_some_and(|cell| cell & bit != 0)
}

// ---------------------------------------------------------------------------
// Parser (§5). Pure and unprivileged; every anomaly rejects the whole run.
// ---------------------------------------------------------------------------

/// Which program produced the stream.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum RunKind {
    /// `p11_identity_vma`: VMA verdicts plus one END.
    Target,
    /// `p11_anchor_vma`: anchor outcomes plus one END.
    Anchor,
}

/// How the iterator walked.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum RunMode {
    /// Whole-system walk: tgids arrive in ascending order (F2).
    WholeSystem,
    /// Per-pid walk: every record names one tgid.
    PerPid,
}

/// What the parser expects a run to prove. `scope` is exactly the pids whose
/// maps text userspace read and that need a verdict (I10).
pub struct Expect<'a> {
    /// Pass generation; every record must carry its low 32 bits.
    pub generation: u64,
    /// Slots installed this pass; bounds every non-`NONE` verdict.
    pub slots: u32,
    /// In-scope tgids.
    pub scope: &'a BTreeSet<u32>,
    /// Walk shape.
    pub mode: RunMode,
    /// Producing program.
    pub run: RunKind,
}

/// Per-range verdict of a target run: the matched anchor slot, or no match.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum TargetVerdict {
    Slot(u32),
    Unmatched,
}

/// Per-slot outcome of an anchor run.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum AnchorOutcome {
    Ok,
    /// Aliases the named installed slot.
    Dup(u32),
    Full,
    BadShape,
}

/// A parsed run: the exact-range join input plus anchor outcomes. Records
/// never supply keys, paths, permissions, or grouping (I8).
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Run {
    /// Target verdicts by `(tgid, (start, end))`.
    pub by_pid: BTreeMap<u32, BTreeMap<(u64, u64), TargetVerdict>>,
    /// Anchor outcomes by slot. A slot with conflicting repeats downgrades
    /// to `BadShape` (never installed): per-key fail-closed, not run failure.
    pub anchors: BTreeMap<u32, AnchorOutcome>,
    /// Pids whose exact-range duplicates conflicted (F5): that pid alone
    /// falls back to the userspace proof, and its records are dropped here so
    /// no consumer can use them.
    pub demoted_pids: BTreeSet<u32>,
}

/// Why a run was rejected. Every variant fails the whole run closed.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Invalid {
    /// Length is not a multiple of 32.
    Length,
    /// Bad magic.
    Magic,
    /// Bad version.
    Version,
    /// Unknown kind.
    Kind,
    /// Generation mismatch.
    Gen,
    /// No END record.
    MissingEnd,
    /// END is not the last record (this also covers a repeated END: the
    /// first END is then not last).
    EndNotLast,
    /// A VMA range has `start >= end`.
    RangeOrder,
    /// A VMA range is not 4 KiB aligned.
    RangeAlign,
    /// A record address field reached the 2^56 pointer guard (I6).
    PointerShape,
    /// A verdict is neither `NONE`/known-anchor-outcome nor below the slots.
    VerdictRange,
    /// A tgid is not in scope (I10).
    TgidScope,
    /// Whole-system tgids decreased.
    TgidOrder,
    /// An ANCHOR record in a target run, or VMA in an anchor run.
    WrongRunKind,
    /// A per-pid run named more than one tgid.
    MultiTgid,
    /// An END record carries a nonzero payload.
    EndPayload,
    /// An ANCHOR record carries a malformed payload.
    AnchorPayload,
}

fn u16_at(record: &[u8], at: usize) -> u16 {
    u16::from_le_bytes([record[at], record[at + 1]])
}

fn u32_at(record: &[u8], at: usize) -> u32 {
    u32::from_le_bytes([record[at], record[at + 1], record[at + 2], record[at + 3]])
}

fn u64_at(record: &[u8], at: usize) -> u64 {
    u64::from_le_bytes([
        record[at],
        record[at + 1],
        record[at + 2],
        record[at + 3],
        record[at + 4],
        record[at + 5],
        record[at + 6],
        record[at + 7],
    ])
}

/// Parse one run's bytes. Pure: no syscalls, no allocation past the output,
/// and no panic on any input (the byte-flip tests pin this).
pub fn parse(bytes: &[u8], expect: &Expect) -> Result<Run, Invalid> {
    if !bytes.len().is_multiple_of(RECORD_LEN) {
        return Err(Invalid::Length);
    }
    if bytes.is_empty() {
        return Err(Invalid::MissingEnd);
    }
    let records = bytes.len() / RECORD_LEN;
    let want_gen = expect.generation as u32;
    let mut run = Run::default();
    let mut last_tgid: Option<u32> = None;
    let mut only_tgid: Option<u32> = None;
    for index in 0..records {
        let record = &bytes[index * RECORD_LEN..(index + 1) * RECORD_LEN];
        let magic = u16_at(record, 0);
        let version = record[2];
        let kind = record[3];
        let a = u32_at(record, 4);
        let start = u64_at(record, 8);
        let end = u64_at(record, 16);
        let verdict = u32_at(record, 24);
        let generation = u32_at(record, 28);
        if magic != RECORD_MAGIC {
            return Err(Invalid::Magic);
        }
        if version != RECORD_VERSION {
            return Err(Invalid::Version);
        }
        if generation != want_gen {
            return Err(Invalid::Gen);
        }
        match kind {
            KIND_END => {
                if index != records - 1 {
                    return Err(Invalid::EndNotLast);
                }
                if a != 0 || start != 0 || end != 0 || verdict != 0 {
                    return Err(Invalid::EndPayload);
                }
            }
            KIND_VMA => {
                if !matches!(expect.run, RunKind::Target) {
                    return Err(Invalid::WrongRunKind);
                }
                if start >= end {
                    return Err(Invalid::RangeOrder);
                }
                if start & (PAGE_GRANULE - 1) != 0 || end & (PAGE_GRANULE - 1) != 0 {
                    return Err(Invalid::RangeAlign);
                }
                if start >= POINTER_GUARD || end >= POINTER_GUARD {
                    return Err(Invalid::PointerShape);
                }
                let parsed = if verdict == VERDICT_NONE {
                    TargetVerdict::Unmatched
                } else if verdict < expect.slots {
                    TargetVerdict::Slot(verdict)
                } else {
                    return Err(Invalid::VerdictRange);
                };
                if !expect.scope.contains(&a) {
                    return Err(Invalid::TgidScope);
                }
                match expect.mode {
                    RunMode::WholeSystem => {
                        if last_tgid.is_some_and(|last| a < last) {
                            return Err(Invalid::TgidOrder);
                        }
                        last_tgid = Some(a);
                    }
                    RunMode::PerPid => match only_tgid {
                        None => only_tgid = Some(a),
                        Some(first) if first == a => {}
                        Some(_) => return Err(Invalid::MultiTgid),
                    },
                }
                if run.demoted_pids.contains(&a) {
                    continue;
                }
                let conflicted = matches!(
                    run.by_pid.get(&a),
                    Some(previous) if matches!(previous.get(&(start, end)), Some(before) if *before != parsed)
                );
                if conflicted {
                    run.by_pid.remove(&a);
                    run.demoted_pids.insert(a);
                } else {
                    run.by_pid
                        .entry(a)
                        .or_default()
                        .insert((start, end), parsed);
                }
            }
            KIND_ANCHOR => {
                if !matches!(expect.run, RunKind::Anchor) {
                    return Err(Invalid::WrongRunKind);
                }
                if start >= POINTER_GUARD || end >= POINTER_GUARD {
                    return Err(Invalid::PointerShape);
                }
                let outcome = match verdict {
                    ANCHOR_OK => {
                        if start != 0 || end != 0 {
                            return Err(Invalid::AnchorPayload);
                        }
                        if a >= expect.slots {
                            return Err(Invalid::VerdictRange);
                        }
                        AnchorOutcome::Ok
                    }
                    ANCHOR_DUP => {
                        if end != 0 {
                            return Err(Invalid::AnchorPayload);
                        }
                        if a >= expect.slots || start >= u64::from(expect.slots) {
                            return Err(Invalid::VerdictRange);
                        }
                        AnchorOutcome::Dup(start as u32)
                    }
                    ANCHOR_FULL => {
                        if start != 0 || end != 0 {
                            return Err(Invalid::AnchorPayload);
                        }
                        if a >= expect.slots {
                            return Err(Invalid::VerdictRange);
                        }
                        AnchorOutcome::Full
                    }
                    ANCHOR_BAD_SHAPE => {
                        if start != 0 || end != 0 {
                            return Err(Invalid::AnchorPayload);
                        }
                        // Any slot value: a shape failure never installs.
                        AnchorOutcome::BadShape
                    }
                    _ => return Err(Invalid::VerdictRange),
                };
                match run.anchors.get(&a) {
                    None => {
                        run.anchors.insert(a, outcome);
                    }
                    Some(previous) if *previous == outcome => {}
                    Some(_) => {
                        run.anchors.insert(a, AnchorOutcome::BadShape);
                    }
                }
            }
            _ => return Err(Invalid::Kind),
        }
    }
    let tail = &bytes[(records - 1) * RECORD_LEN..records * RECORD_LEN];
    if tail[3] != KIND_END {
        return Err(Invalid::MissingEnd);
    }
    Ok(run)
}

// ---------------------------------------------------------------------------
// Reader (§5). Drains one iterator fd to EOF.
// ---------------------------------------------------------------------------

/// Iterator read buffer: 64 KiB, above the 32 KiB kernel buffer (F4).
pub const READ_BUF_LEN: usize = 64 * 1024;

/// Why a run could not be read. Any of these fails the run; none is valid
/// output.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ReadError {
    /// The deadline passed while retrying `EINTR`/`EAGAIN`.
    Deadline,
    /// The stream passed `max_bytes` without EOF.
    TooLarge,
    /// Any other errno from `read()`.
    Errno(i32),
}

/// Drain `fd` to EOF. Retries `EINTR` and `EAGAIN` (F4: a 1M-object read
/// with no output keeps the iterator state, so the next `read()` continues
/// the same walk), bounded by `deadline`, which is checked between reads.
/// Stops after the END record plus the EOF read; the parser then proves the
/// stream held exactly one END. `max_bytes` caps a runaway stream.
pub fn read_run(
    fd: BorrowedFd<'_>,
    deadline: Option<Instant>,
    max_bytes: usize,
) -> Result<Vec<u8>, ReadError> {
    let mut out = Vec::new();
    let mut chunk = [0u8; READ_BUF_LEN];
    loop {
        if deadline.is_some_and(|at| Instant::now() >= at) {
            return Err(ReadError::Deadline);
        }
        // SAFETY: `read()` writes at most `chunk.len()` bytes into `chunk`.
        let got = unsafe { libc::read(fd.as_raw_fd(), chunk.as_mut_ptr().cast(), chunk.len()) };
        if got < 0 {
            let errno = io::Error::last_os_error()
                .raw_os_error()
                .unwrap_or(libc::EIO);
            if errno == libc::EINTR || errno == libc::EAGAIN {
                continue;
            }
            return Err(ReadError::Errno(errno));
        }
        if got == 0 {
            return Ok(out);
        }
        let fresh = &chunk[..got as usize];
        if out.len() + fresh.len() > max_bytes {
            return Err(ReadError::TooLarge);
        }
        out.extend_from_slice(fresh);
    }
}

// ---------------------------------------------------------------------------
// Raw iterator syscalls (F6). aya's `Iter::attach` cannot pass `iter_info`,
// so per-pid runs (the anchor run, phase-D confirms) need raw link creation.
// Layouts verified against `include/uapi/linux/bpf.h` (6.1 and 7.2 caches)
// and cross-checked against aya's generated bindings by the harness.
// ---------------------------------------------------------------------------

/// `BPF_LINK_CREATE` command number.
pub const BPF_LINK_CREATE: u32 = 28;
/// `BPF_ITER_CREATE` command number.
pub const BPF_ITER_CREATE: u32 = 33;
/// `BPF_MAP_UPDATE_ELEM` command number.
pub const BPF_MAP_UPDATE_ELEM: u32 = 2;
/// `BPF_MAP_DELETE_ELEM` command number.
pub const BPF_MAP_DELETE_ELEM: u32 = 3;
/// `BPF_TRACE_ITER` attach type for `iter/task_vma` links.
pub const BPF_TRACE_ITER: u32 = 28;
/// `BPF_ANY`: create or update.
pub const BPF_ANY: u64 = 0;

/// `union bpf_iter_link_info` (16 bytes): the task member is
/// `{tid@0, pid@4, pid_fd@8}` plus 4 bytes of union padding.
#[repr(C)]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct IterLinkInfo {
    pub tid: u32,
    pub pid: u32,
    pub pid_fd: u32,
    pub reserved: u32,
}

const _: () = assert!(size_of::<IterLinkInfo>() == 16);
const _: () = assert!(std::mem::offset_of!(IterLinkInfo, tid) == 0);
const _: () = assert!(std::mem::offset_of!(IterLinkInfo, pid) == 4);
const _: () = assert!(std::mem::offset_of!(IterLinkInfo, pid_fd) == 8);

/// `BPF_LINK_CREATE` attr through `iter_info_len` (F6: `iter_info` at 16,
/// `iter_info_len` at 24). Trailing union members stay zero: whole-system
/// links pass a null `iter_info`, per-pid links point at an [`IterLinkInfo`].
#[repr(C)]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct LinkCreateAttr {
    pub prog_fd: u32,
    pub target_fd: u32,
    pub attach_type: u32,
    pub flags: u32,
    pub iter_info: u64,
    pub iter_info_len: u32,
    pub reserved: u32,
}

const _: () = assert!(size_of::<LinkCreateAttr>() == 32);
const _: () = assert!(std::mem::offset_of!(LinkCreateAttr, prog_fd) == 0);
const _: () = assert!(std::mem::offset_of!(LinkCreateAttr, attach_type) == 8);
const _: () = assert!(std::mem::offset_of!(LinkCreateAttr, flags) == 12);
const _: () = assert!(std::mem::offset_of!(LinkCreateAttr, iter_info) == 16);
const _: () = assert!(std::mem::offset_of!(LinkCreateAttr, iter_info_len) == 24);

/// `BPF_ITER_CREATE` attr: `{link_fd@0, flags@4}`.
#[repr(C)]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct IterCreateAttr {
    pub link_fd: u32,
    pub flags: u32,
}

const _: () = assert!(size_of::<IterCreateAttr>() == 8);

/// `BPF_MAP_*_ELEM` attr: `{map_fd@0, key@8, value@16, flags@24}`.
#[repr(C)]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct MapElemAttr {
    pub map_fd: u32,
    pub reserved: u32,
    pub key: u64,
    pub value: u64,
    pub flags: u64,
}

const _: () = assert!(size_of::<MapElemAttr>() == 32);
const _: () = assert!(std::mem::offset_of!(MapElemAttr, map_fd) == 0);
const _: () = assert!(std::mem::offset_of!(MapElemAttr, key) == 8);
const _: () = assert!(std::mem::offset_of!(MapElemAttr, value) == 16);
const _: () = assert!(std::mem::offset_of!(MapElemAttr, flags) == 24);

fn bpf(cmd: u32, attr: *mut std::ffi::c_void, size: usize) -> io::Result<i32> {
    // SAFETY: raw bpf() with a caller-sized attr; exactly what libbpf does.
    let ret = unsafe { libc::syscall(libc::SYS_bpf, cmd as libc::c_long, attr, size) };
    if ret < 0 {
        Err(io::Error::last_os_error())
    } else {
        Ok(ret as i32)
    }
}

/// Create a `task_vma` iterator link for `prog_fd`: whole-system with
/// `pid_fd = None`, or one process with `Some(pidfd)`. The pidfd names the
/// task only at attach (F2); generation proof stays the confirm pin's job.
pub fn link_create_task_vma(
    prog_fd: BorrowedFd<'_>,
    pid_fd: Option<BorrowedFd<'_>>,
) -> io::Result<OwnedFd> {
    let info = IterLinkInfo {
        tid: 0,
        pid: 0,
        pid_fd: pid_fd.map_or(0, |fd| fd.as_raw_fd() as u32),
        reserved: 0,
    };
    let attr = LinkCreateAttr {
        prog_fd: prog_fd.as_raw_fd() as u32,
        target_fd: 0,
        attach_type: BPF_TRACE_ITER,
        flags: 0,
        iter_info: if pid_fd.is_some() {
            std::ptr::addr_of!(info).addr() as u64
        } else {
            0
        },
        iter_info_len: if pid_fd.is_some() {
            size_of::<IterLinkInfo>() as u32
        } else {
            0
        },
        reserved: 0,
    };
    let mut attr = attr;
    let fd = bpf(
        BPF_LINK_CREATE,
        std::ptr::addr_of_mut!(attr).cast(),
        size_of::<LinkCreateAttr>(),
    )?;
    // SAFETY: the syscall returned a new owned fd.
    Ok(unsafe { OwnedFd::from_raw_fd(fd) })
}

/// Open the readable iterator file for a link. The reader drains this fd.
pub fn iter_create(link_fd: BorrowedFd<'_>) -> io::Result<OwnedFd> {
    let mut attr = IterCreateAttr {
        link_fd: link_fd.as_raw_fd() as u32,
        flags: 0,
    };
    let fd = bpf(
        BPF_ITER_CREATE,
        std::ptr::addr_of_mut!(attr).cast(),
        size_of::<IterCreateAttr>(),
    )?;
    // SAFETY: the syscall returned a new owned fd.
    Ok(unsafe { OwnedFd::from_raw_fd(fd) })
}

// ---------------------------------------------------------------------------
// Write-only anchor handle (I6). Deliberately no `Debug`, `Display`, or
// `Serialize`, and no read API: the fds cannot read by kernel enforcement,
// and this type cannot even ask.
// ---------------------------------------------------------------------------

/// Writer for the kernel-only anchor maps. Holds the two `WRONLY` fds;
/// exposes inserts and deletes only. There is intentionally no `get`,
/// `lookup`, `iter`, `keys`, or `Debug` implementation: inode addresses
/// enter the kernel here and never come back.
pub struct AnchorMaps {
    hash: OwnedFd,
    slots: OwnedFd,
}

impl AnchorMaps {
    /// Wrap the two anchor-map fds (cloned from the loaded object). No
    /// validation reads are possible: the fds refuse them with `EPERM`.
    pub fn new(hash: OwnedFd, slots: OwnedFd) -> Self {
        Self { hash, slots }
    }

    fn update(fd: BorrowedFd<'_>, key: &[u8], value: &[u8]) -> io::Result<()> {
        let attr = MapElemAttr {
            map_fd: fd.as_raw_fd() as u32,
            reserved: 0,
            key: key.as_ptr().addr() as u64,
            value: value.as_ptr().addr() as u64,
            flags: BPF_ANY,
        };
        let mut attr = attr;
        bpf(
            BPF_MAP_UPDATE_ELEM,
            std::ptr::addr_of_mut!(attr).cast(),
            size_of::<MapElemAttr>(),
        )?;
        Ok(())
    }

    fn delete(fd: BorrowedFd<'_>, key: &[u8]) -> io::Result<()> {
        let attr = MapElemAttr {
            map_fd: fd.as_raw_fd() as u32,
            reserved: 0,
            key: key.as_ptr().addr() as u64,
            value: 0,
            flags: 0,
        };
        let mut attr = attr;
        bpf(
            BPF_MAP_DELETE_ELEM,
            std::ptr::addr_of_mut!(attr).cast(),
            size_of::<MapElemAttr>(),
        )?;
        Ok(())
    }

    /// Insert `(addr -> (slot, generation))` into `anchors`. Used only to clear a
    /// slot the kernel reported `FULL` for, or to drop a torn-down anchor
    /// before its slot is reused; the anchor program itself installs entries.
    pub fn insert(&self, addr: u64, slot: u32, generation: u64) -> io::Result<()> {
        let entry = AnchorEntry {
            slot,
            pad: 0,
            generation,
        };
        Self::update(
            self.hash.as_fd(),
            &addr.to_ne_bytes(),
            // SAFETY: `AnchorEntry` is `#[repr(C)]` plain data.
            unsafe {
                std::slice::from_raw_parts(
                    std::ptr::addr_of!(entry).cast::<u8>(),
                    size_of::<AnchorEntry>(),
                )
            },
        )
    }

    /// Delete `addr` from `anchors`. Absent keys fail with `ENOENT`, which
    /// the caller treats as already clear.
    pub fn remove(&self, addr: u64) -> io::Result<()> {
        Self::delete(self.hash.as_fd(), &addr.to_ne_bytes())
    }

    /// Record `addr` as slot `slot`'s last-installed address. Mirrors the
    /// program's own bookkeeping for slots userspace tears down directly.
    pub fn set_slot(&self, slot: u32, addr: u64) -> io::Result<()> {
        Self::update(self.slots.as_fd(), &slot.to_ne_bytes(), &addr.to_ne_bytes())
    }
}

// ---------------------------------------------------------------------------
// aya loader (D2a route decision: the clang object loads as-is).
// ---------------------------------------------------------------------------

/// The clang-built identity object, embedded by `build.rs`. Alignment
/// matters: aya parses it as ELF in place.
pub static IDENTITY_OBJECT: &[u8] =
    aya::include_bytes_aligned!(concat!(env!("OUT_DIR"), "/p11scope-ebpf-identity"));

/// Anchor program name in the identity object.
pub const ANCHOR_PROGRAM: &str = "p11_anchor_vma";
/// Target program name in the identity object.
pub const TARGET_PROGRAM: &str = "p11_identity_vma";
/// Iterator type for [`aya::programs::Iter::load`].
pub const ITER_TYPE_TASK_VMA: &str = "task_vma";

/// Why the identity object failed to load.
#[derive(Debug)]
pub enum LoadError {
    /// Object, BTF, or map failure from aya's loader.
    Ebpf(aya::EbpfError),
    /// Program verification failure.
    Program(aya::programs::ProgramError),
    /// A program the object must contain is missing.
    MissingProgram(&'static str),
}

impl From<aya::EbpfError> for LoadError {
    fn from(error: aya::EbpfError) -> Self {
        Self::Ebpf(error)
    }
}

impl From<aya::programs::ProgramError> for LoadError {
    fn from(error: aya::programs::ProgramError) -> Self {
        Self::Program(error)
    }
}

impl std::fmt::Display for LoadError {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Ebpf(error) => write!(formatter, "{error:#}"),
            Self::Program(error) => write!(formatter, "{error:#}"),
            Self::MissingProgram(name) => write!(formatter, "program {name} missing from object"),
        }
    }
}

impl std::error::Error for LoadError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Ebpf(error) => Some(error),
            Self::Program(error) => Some(error),
            Self::MissingProgram(_) => None,
        }
    }
}

/// Load the identity object: maps plus both `iter/task_vma` programs, with
/// CO-RE relocated against `btf` (`None` disables relocation and leaves the
/// programs unverified). With BTF, a successful return means both programs
/// passed the verifier and the object is ready to attach. Attaching itself
/// is W3-2's probe.
pub fn load_identity_object(btf: Option<&aya::Btf>) -> Result<aya::Ebpf, LoadError> {
    let mut loader = aya::EbpfLoader::new();
    loader.btf(btf);
    let mut ebpf = loader.load(IDENTITY_OBJECT)?;
    if let Some(btf) = btf {
        for name in [ANCHOR_PROGRAM, TARGET_PROGRAM] {
            let program: &mut aya::programs::Iter = ebpf
                .program_mut(name)
                .ok_or(LoadError::MissingProgram(name))?
                .try_into()?;
            program.load(ITER_TYPE_TASK_VMA, btf)?;
        }
    }
    Ok(ebpf)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::Duration;

    fn record(
        kind: u8,
        a: u32,
        start: u64,
        end: u64,
        verdict: u32,
        generation: u32,
    ) -> [u8; RECORD_LEN] {
        let mut out = [0u8; RECORD_LEN];
        out[0..2].copy_from_slice(&RECORD_MAGIC.to_le_bytes());
        out[2] = RECORD_VERSION;
        out[3] = kind;
        out[4..8].copy_from_slice(&a.to_le_bytes());
        out[8..16].copy_from_slice(&start.to_le_bytes());
        out[16..24].copy_from_slice(&end.to_le_bytes());
        out[24..28].copy_from_slice(&verdict.to_le_bytes());
        out[28..32].copy_from_slice(&generation.to_le_bytes());
        out
    }

    fn end(generation: u32) -> [u8; RECORD_LEN] {
        record(KIND_END, 0, 0, 0, 0, generation)
    }

    fn target_expect(scope: &BTreeSet<u32>) -> Expect<'_> {
        Expect {
            generation: 7,
            slots: 4,
            scope,
            mode: RunMode::WholeSystem,
            run: RunKind::Target,
        }
    }

    fn anchor_expect(scope: &BTreeSet<u32>) -> Expect<'_> {
        Expect {
            generation: 7,
            slots: 4,
            scope,
            mode: RunMode::WholeSystem,
            run: RunKind::Anchor,
        }
    }

    #[test]
    fn target_run_parses_to_exact_range_map() {
        let scope: BTreeSet<u32> = [100, 200].into_iter().collect();
        let mut bytes = Vec::new();
        bytes.extend_from_slice(&record(KIND_VMA, 100, 0x1000, 0x2000, 3, 7));
        bytes.extend_from_slice(&record(KIND_VMA, 100, 0x3000, 0x4000, VERDICT_NONE, 7));
        bytes.extend_from_slice(&record(KIND_VMA, 200, 0x1000, 0x2000, 1, 7));
        bytes.extend_from_slice(&end(7));
        let run = parse(&bytes, &target_expect(&scope)).expect("valid target run");
        assert_eq!(run.demoted_pids, BTreeSet::new());
        assert!(run.anchors.is_empty());
        assert_eq!(
            run.by_pid
                .get(&100)
                .expect("pid 100")
                .get(&(0x1000, 0x2000)),
            Some(&TargetVerdict::Slot(3))
        );
        assert_eq!(
            run.by_pid
                .get(&100)
                .expect("pid 100")
                .get(&(0x3000, 0x4000)),
            Some(&TargetVerdict::Unmatched)
        );
        assert_eq!(
            run.by_pid
                .get(&200)
                .expect("pid 200")
                .get(&(0x1000, 0x2000)),
            Some(&TargetVerdict::Slot(1))
        );
    }

    #[test]
    fn anchor_run_parses_outcomes_and_aliases() {
        let scope = BTreeSet::new();
        let mut bytes = Vec::new();
        bytes.extend_from_slice(&record(KIND_ANCHOR, 0, 0, 0, ANCHOR_OK, 7));
        // DUP names the aliased slot in `start`; repeated identically.
        let mut dup = record(KIND_ANCHOR, 1, 0, 0, ANCHOR_DUP, 7);
        dup[8..16].copy_from_slice(&0u64.to_le_bytes());
        bytes.extend_from_slice(&dup);
        bytes.extend_from_slice(&dup);
        bytes.extend_from_slice(&record(KIND_ANCHOR, 2, 0, 0, ANCHOR_FULL, 7));
        bytes.extend_from_slice(&record(KIND_ANCHOR, 99, 0, 0, ANCHOR_BAD_SHAPE, 7));
        bytes.extend_from_slice(&end(7));
        let run = parse(&bytes, &anchor_expect(&scope)).expect("valid anchor run");
        // Slot 1 repeats (identical DUP): allowed, collapses to one outcome.
        assert_eq!(run.anchors.get(&0), Some(&AnchorOutcome::Ok));
        assert_eq!(run.anchors.get(&1), Some(&AnchorOutcome::Dup(0)));
        assert_eq!(run.anchors.get(&2), Some(&AnchorOutcome::Full));
        assert_eq!(run.anchors.get(&99), Some(&AnchorOutcome::BadShape));
        assert!(run.by_pid.is_empty());
    }

    #[test]
    fn parser_table_rejects_every_anomaly() {
        let scope: BTreeSet<u32> = [100].into_iter().collect();
        let good_vma = || record(KIND_VMA, 100, 0x1000, 0x2000, 3, 7);
        let anchor_ok = || record(KIND_ANCHOR, 0, 0, 0, ANCHOR_OK, 7);
        let cases: Vec<(&str, Vec<u8>, RunKind, RunMode, Invalid)> = vec![
            (
                "length",
                vec![0u8; 31],
                RunKind::Target,
                RunMode::WholeSystem,
                Invalid::Length,
            ),
            (
                "empty",
                vec![],
                RunKind::Target,
                RunMode::WholeSystem,
                Invalid::MissingEnd,
            ),
            (
                "missing-end",
                good_vma().to_vec(),
                RunKind::Target,
                RunMode::WholeSystem,
                Invalid::MissingEnd,
            ),
            (
                "end-not-last",
                [end(7).to_vec(), good_vma().to_vec(), end(7).to_vec()].concat(),
                RunKind::Target,
                RunMode::WholeSystem,
                Invalid::EndNotLast,
            ),
            (
                "two-ends",
                [end(7).to_vec(), end(7).to_vec()].concat(),
                RunKind::Target,
                RunMode::WholeSystem,
                Invalid::EndNotLast,
            ),
            (
                "end-payload",
                record(KIND_END, 1, 0, 0, 0, 7).to_vec(),
                RunKind::Target,
                RunMode::WholeSystem,
                Invalid::EndPayload,
            ),
        ];
        for (name, bytes, run, mode, want) in cases {
            let expect = Expect {
                generation: 7,
                slots: 4,
                scope: &scope,
                mode,
                run,
            };
            assert_eq!(parse(&bytes, &expect), Err(want), "{name}");
        }
        // Single-record corruptions of an otherwise valid two-record stream.
        let corrupt = |mut rec: [u8; RECORD_LEN], at: usize, value: u8| {
            rec[at] = value;
            [rec.to_vec(), end(7).to_vec()].concat()
        };
        let field_cases: Vec<(&str, Vec<u8>, Invalid)> = vec![
            ("magic-lo", corrupt(good_vma(), 0, 0x51), Invalid::Magic),
            ("magic-hi", corrupt(good_vma(), 1, 0x48), Invalid::Magic),
            ("version", corrupt(good_vma(), 2, 2), Invalid::Version),
            ("kind-unknown", corrupt(good_vma(), 3, 9), Invalid::Kind),
            (
                "kind-anchor-in-target",
                corrupt(good_vma(), 3, KIND_ANCHOR),
                Invalid::WrongRunKind,
            ),
            ("generation", corrupt(good_vma(), 28, 8), Invalid::Gen),
            (
                "start-gte-end",
                [
                    record(KIND_VMA, 100, 0x2000, 0x2000, 3, 7).to_vec(),
                    end(7).to_vec(),
                ]
                .concat(),
                Invalid::RangeOrder,
            ),
            (
                "start-unaligned",
                [
                    record(KIND_VMA, 100, 0x1001, 0x2000, 3, 7).to_vec(),
                    end(7).to_vec(),
                ]
                .concat(),
                Invalid::RangeAlign,
            ),
            (
                "end-unaligned",
                [
                    record(KIND_VMA, 100, 0x1000, 0x2001, 3, 7).to_vec(),
                    end(7).to_vec(),
                ]
                .concat(),
                Invalid::RangeAlign,
            ),
            (
                "pointer-start",
                [
                    record(
                        KIND_VMA,
                        100,
                        0xffff_8000_0000_0000,
                        0xffff_8000_0001_0000,
                        3,
                        7,
                    )
                    .to_vec(),
                    end(7).to_vec(),
                ]
                .concat(),
                Invalid::PointerShape,
            ),
            (
                "verdict-range",
                [
                    record(KIND_VMA, 100, 0x1000, 0x2000, 4, 7).to_vec(),
                    end(7).to_vec(),
                ]
                .concat(),
                Invalid::VerdictRange,
            ),
            (
                "tgid-scope",
                [
                    record(KIND_VMA, 101, 0x1000, 0x2000, 3, 7).to_vec(),
                    end(7).to_vec(),
                ]
                .concat(),
                Invalid::TgidScope,
            ),
        ];
        for (name, bytes, want) in field_cases {
            let expect = target_expect(&scope);
            assert_eq!(parse(&bytes, &expect), Err(want), "{name}");
        }
        // Order and mode rules need two VMA records.
        let pair = |first: u32, second: u32| {
            [
                record(KIND_VMA, first, 0x1000, 0x2000, 3, 7).to_vec(),
                record(KIND_VMA, second, 0x1000, 0x2000, 3, 7).to_vec(),
                end(7).to_vec(),
            ]
            .concat()
        };
        let wide: BTreeSet<u32> = [100, 200].into_iter().collect();
        let whole = Expect {
            generation: 7,
            slots: 4,
            scope: &wide,
            mode: RunMode::WholeSystem,
            run: RunKind::Target,
        };
        assert_eq!(parse(&pair(200, 100), &whole), Err(Invalid::TgidOrder));
        parse(&pair(100, 200), &whole).expect("ascending tgids parse");
        parse(&pair(100, 100), &whole).expect("same-tgid repeats parse");
        let per_pid = Expect {
            generation: 7,
            slots: 4,
            scope: &wide,
            mode: RunMode::PerPid,
            run: RunKind::Target,
        };
        assert_eq!(parse(&pair(100, 200), &per_pid), Err(Invalid::MultiTgid));
        parse(&pair(100, 100), &per_pid).expect("per-pid single tgid parses");
        // Anchor payload rules.
        let empty_scope = BTreeSet::new();
        let anchor = anchor_expect(&empty_scope);
        let bad_dup_other = {
            let mut rec = record(KIND_ANCHOR, 1, 0, 0, ANCHOR_DUP, 7);
            rec[8..16].copy_from_slice(&9u64.to_le_bytes());
            [rec.to_vec(), end(7).to_vec()].concat()
        };
        assert_eq!(parse(&bad_dup_other, &anchor), Err(Invalid::VerdictRange));
        let bad_dup_end = {
            let mut rec = record(KIND_ANCHOR, 1, 0, 0, ANCHOR_DUP, 7);
            rec[16..24].copy_from_slice(&1u64.to_le_bytes());
            [rec.to_vec(), end(7).to_vec()].concat()
        };
        assert_eq!(parse(&bad_dup_end, &anchor), Err(Invalid::AnchorPayload));
        let bad_ok_slot = [
            record(KIND_ANCHOR, 4, 0, 0, ANCHOR_OK, 7).to_vec(),
            end(7).to_vec(),
        ]
        .concat();
        assert_eq!(parse(&bad_ok_slot, &anchor), Err(Invalid::VerdictRange));
        let bad_verdict = [record(KIND_ANCHOR, 0, 0, 0, 9, 7).to_vec(), end(7).to_vec()].concat();
        assert_eq!(parse(&bad_verdict, &anchor), Err(Invalid::VerdictRange));
        let vma_in_anchor = [good_vma().to_vec(), end(7).to_vec()].concat();
        assert_eq!(parse(&vma_in_anchor, &anchor), Err(Invalid::WrongRunKind));
        let anchor_in_target = [anchor_ok().to_vec(), end(7).to_vec()].concat();
        assert_eq!(
            parse(&anchor_in_target, &target_expect(&scope)),
            Err(Invalid::WrongRunKind)
        );
    }

    #[test]
    fn conflicting_duplicates_demote_one_pid_not_the_run() {
        let scope: BTreeSet<u32> = [100, 200].into_iter().collect();
        let bytes = [
            record(KIND_VMA, 100, 0x1000, 0x2000, 3, 7).to_vec(),
            record(KIND_VMA, 100, 0x3000, 0x4000, 1, 7).to_vec(),
            record(KIND_VMA, 100, 0x1000, 0x2000, VERDICT_NONE, 7).to_vec(),
            record(KIND_VMA, 200, 0x1000, 0x2000, 2, 7).to_vec(),
            end(7).to_vec(),
        ]
        .concat();
        let run = parse(&bytes, &target_expect(&scope)).expect("demotion is not run failure");
        assert_eq!(run.demoted_pids, BTreeSet::from([100]));
        assert!(
            !run.by_pid.contains_key(&100),
            "demoted pid drops its records"
        );
        assert_eq!(
            run.by_pid
                .get(&200)
                .expect("pid 200")
                .get(&(0x1000, 0x2000)),
            Some(&TargetVerdict::Slot(2))
        );
    }

    #[test]
    fn identical_duplicates_are_accepted() {
        let scope: BTreeSet<u32> = [100].into_iter().collect();
        let bytes = [
            record(KIND_VMA, 100, 0x1000, 0x2000, 3, 7).to_vec(),
            record(KIND_VMA, 100, 0x1000, 0x2000, 3, 7).to_vec(),
            end(7).to_vec(),
        ]
        .concat();
        let run = parse(&bytes, &target_expect(&scope)).expect("identical duplicates parse");
        assert!(run.demoted_pids.is_empty());
        assert_eq!(run.by_pid.get(&100).expect("pid 100").len(), 1);
    }

    #[test]
    fn conflicting_anchor_repeats_downgrade_the_slot() {
        let empty_scope = BTreeSet::new();
        let anchor = anchor_expect(&empty_scope);
        let bytes = [
            record(KIND_ANCHOR, 0, 0, 0, ANCHOR_OK, 7).to_vec(),
            record(KIND_ANCHOR, 0, 0, 0, ANCHOR_FULL, 7).to_vec(),
            end(7).to_vec(),
        ]
        .concat();
        let run = parse(&bytes, &anchor).expect("anchor conflict is per-key, not run failure");
        assert_eq!(run.anchors.get(&0), Some(&AnchorOutcome::BadShape));
    }

    /// The design's byte-flip property, stated precisely. The literal "same
    /// `Run` or `Invalid`" holds for the END-only stream: it carries no
    /// payload byte whose flip stays valid, so this test pins all 32 × 255
    /// flips exhaustively. Payload streams cannot satisfy the literal form
    /// (an in-range verdict flip yields a *different* valid `Run`), so the
    /// companion test below pins no-panic plus determinism there instead.
    #[test]
    fn every_byte_flip_of_end_only_is_same_or_invalid() {
        let scope = BTreeSet::new();
        let expect = target_expect(&scope);
        let bytes = end(7).to_vec();
        let baseline = parse(&bytes, &expect).expect("END-only parses");
        let mut same = 0u32;
        let mut invalid = 0u32;
        for at in 0..bytes.len() {
            for value in 0..=255u8 {
                if value == bytes[at] {
                    continue;
                }
                let mut flipped = bytes.clone();
                flipped[at] = value;
                match parse(&flipped, &expect) {
                    Ok(run) => {
                        assert_eq!(
                            run, baseline,
                            "flip at {at} to {value:#x} must not change the run"
                        );
                        same += 1;
                    }
                    Err(_) => invalid += 1,
                }
            }
        }
        assert_eq!(same + invalid, 32 * 255);
        assert!(invalid > 0, "flips must invalidate sometimes");
    }

    /// Payload-stream flips never panic and parse deterministically: any two
    /// parses of the same flipped bytes agree.
    #[test]
    fn every_byte_flip_of_payload_streams_is_panic_free_and_deterministic() {
        let scope: BTreeSet<u32> = [100, 200].into_iter().collect();
        let target = target_expect(&scope);
        let target_bytes = [
            record(KIND_VMA, 100, 0x1000, 0x2000, 3, 7).to_vec(),
            record(KIND_VMA, 200, 0x5000, 0x6000, VERDICT_NONE, 7).to_vec(),
            end(7).to_vec(),
        ]
        .concat();
        let empty_scope = BTreeSet::new();
        let anchor = anchor_expect(&empty_scope);
        let anchor_bytes = [
            record(KIND_ANCHOR, 0, 0, 0, ANCHOR_OK, 7).to_vec(),
            record(KIND_ANCHOR, 3, 0, 0, ANCHOR_BAD_SHAPE, 7).to_vec(),
            end(7).to_vec(),
        ]
        .concat();
        for (bytes, expect) in [(&target_bytes, &target), (&anchor_bytes, &anchor)] {
            for at in 0..bytes.len() {
                for value in 0..=255u8 {
                    if value == bytes[at] {
                        continue;
                    }
                    let mut flipped = bytes.clone();
                    flipped[at] = value;
                    let first = parse(&flipped, expect);
                    let second = parse(&flipped, expect);
                    assert_eq!(
                        first, second,
                        "flip at {at} to {value:#x} parses deterministically"
                    );
                }
            }
        }
    }

    #[test]
    fn randomized_mutations_never_panic() {
        // Small xorshift; deterministic seed, no RNG dependency.
        let mut state = 0x243F_6A88_85A3_0B09u64;
        let mut next = move || {
            state ^= state << 13;
            state ^= state >> 7;
            state ^= state << 17;
            state
        };
        let scope: BTreeSet<u32> = [100].into_iter().collect();
        let expect = target_expect(&scope);
        let seed = [
            record(KIND_VMA, 100, 0x1000, 0x9000, 2, 7).to_vec(),
            record(KIND_VMA, 100, 0xA000, 0xB000, VERDICT_NONE, 7).to_vec(),
            end(7).to_vec(),
        ]
        .concat();
        for _ in 0..5_000 {
            let mut bytes = seed.clone();
            let flips = 1 + (next() % 5) as usize;
            for _ in 0..flips {
                let at = (next() % bytes.len() as u64) as usize;
                bytes[at] = (next() & 0xFF) as u8;
            }
            let _ = parse(&bytes, &expect);
        }
        // Truncated and overlong inputs too.
        for len in 0..seed.len() + 64 {
            let _ = parse(&seed[..len.min(seed.len())], &expect);
            let mut long = seed.clone();
            long.extend(std::iter::repeat_n(0xA5, len.saturating_sub(seed.len())));
            let _ = parse(&long, &expect);
        }
    }

    fn pipe() -> (OwnedFd, OwnedFd) {
        let mut fds = [0; 2];
        assert_eq!(unsafe { libc::pipe(fds.as_mut_ptr()) }, 0, "pipe()");
        // SAFETY: `pipe()` returned two new owned fds.
        unsafe { (OwnedFd::from_raw_fd(fds[0]), OwnedFd::from_raw_fd(fds[1])) }
    }

    fn write_all(fd: BorrowedFd<'_>, mut bytes: &[u8]) {
        while !bytes.is_empty() {
            // SAFETY: `write()` reads at most `bytes.len()` bytes from `bytes`.
            let wrote = unsafe { libc::write(fd.as_raw_fd(), bytes.as_ptr().cast(), bytes.len()) };
            assert!(wrote > 0, "pipe write");
            bytes = &bytes[wrote as usize..];
        }
    }

    #[test]
    fn reader_drains_chunks_to_eof() {
        let (read_end, write_end) = pipe();
        let payload = [
            record(KIND_VMA, 100, 0x1000, 0x2000, 3, 7).to_vec(),
            end(7).to_vec(),
        ]
        .concat();
        write_all(write_end.as_fd(), &payload[..40]);
        write_all(write_end.as_fd(), &payload[40..]);
        drop(write_end);
        let out = read_run(read_end.as_fd(), None, 1 << 20).expect("drain to EOF");
        assert_eq!(out, payload);
    }

    #[test]
    fn reader_treats_eagain_as_retry_not_eof() {
        let (read_end, write_end) = pipe();
        // Nonblocking read end: empty reads fail `EAGAIN` until the writer
        // delivers, then EOF when the writer closes.
        let flags = unsafe { libc::fcntl(read_end.as_raw_fd(), libc::F_GETFL) };
        assert!(flags >= 0, "getfl");
        assert_eq!(
            unsafe {
                libc::fcntl(
                    read_end.as_raw_fd(),
                    libc::F_SETFL,
                    flags | libc::O_NONBLOCK,
                )
            },
            0,
            "nonblock"
        );
        let payload = [
            record(KIND_VMA, 100, 0x1000, 0x2000, VERDICT_NONE, 7).to_vec(),
            end(7).to_vec(),
        ]
        .concat();
        let writer = std::thread::spawn(move || {
            std::thread::sleep(Duration::from_millis(20));
            write_all(write_end.as_fd(), &payload);
        });
        let out = read_run(
            read_end.as_fd(),
            Some(Instant::now() + Duration::from_secs(10)),
            1 << 20,
        )
        .expect("EAGAIN must retry until data, not return EOF early");
        writer.join().expect("writer thread");
        assert_eq!(out.len(), 2 * RECORD_LEN);
    }

    #[test]
    fn reader_deadline_and_cap_fail_closed() {
        let (read_end, write_end) = pipe();
        let flags = unsafe { libc::fcntl(read_end.as_raw_fd(), libc::F_GETFL) };
        assert_eq!(
            unsafe {
                libc::fcntl(
                    read_end.as_raw_fd(),
                    libc::F_SETFL,
                    flags | libc::O_NONBLOCK,
                )
            },
            0,
            "nonblock"
        );
        // No writer activity: EAGAIN spins until the (already past) deadline.
        let _held = write_end;
        assert_eq!(
            read_run(read_end.as_fd(), Some(Instant::now()), 1 << 20),
            Err(ReadError::Deadline)
        );
        // A stream past the cap fails even with a live deadline.
        let (read_end, write_end) = pipe();
        let payload = [end(7).to_vec(), end(7).to_vec()].concat();
        write_all(write_end.as_fd(), &payload);
        drop(write_end);
        assert_eq!(
            read_run(read_end.as_fd(), None, RECORD_LEN),
            Err(ReadError::TooLarge)
        );
    }

    #[test]
    fn uapi_layouts_match_f6() {
        use std::mem::offset_of;
        assert_eq!(size_of::<IterLinkInfo>(), 16);
        assert_eq!(offset_of!(IterLinkInfo, tid), 0);
        assert_eq!(offset_of!(IterLinkInfo, pid), 4);
        assert_eq!(offset_of!(IterLinkInfo, pid_fd), 8);
        assert_eq!(BPF_LINK_CREATE, 28);
        assert_eq!(BPF_ITER_CREATE, 33);
        assert_eq!(BPF_TRACE_ITER, 28);
        assert_eq!(size_of::<LinkCreateAttr>(), 32);
        assert_eq!(offset_of!(LinkCreateAttr, iter_info), 16);
        assert_eq!(offset_of!(LinkCreateAttr, iter_info_len), 24);
        assert_eq!(size_of::<IterCreateAttr>(), 8);
        assert_eq!(size_of::<MapElemAttr>(), 32);
        assert_eq!(offset_of!(MapElemAttr, key), 8);
        assert_eq!(offset_of!(MapElemAttr, value), 16);
        assert_eq!(offset_of!(MapElemAttr, flags), 24);
        // The syscall number comes from libc, not a hardcoded copy.
        assert_eq!(libc::SYS_bpf as u32, 321);
    }

    /// The Rust ABI constants must equal the `#define`s in
    /// `crates/ebpf/native/vma_identity.h`; the C compiler pins the struct
    /// shapes with `_Static_assert`, this test pins the shared scalars.
    #[test]
    fn c_header_records_match() {
        let root = std::path::Path::new(env!("CARGO_MANIFEST_DIR"));
        let header = std::fs::read_to_string(root.join("crates/ebpf/native/vma_identity.h"))
            .expect("read vma_identity.h");
        let define = |name: &str| -> String {
            header
                .lines()
                .find_map(|line| {
                    let rest = line.strip_prefix("#define")?.trim();
                    let (key, value) = rest.split_once(char::is_whitespace)?;
                    (key == name).then(|| value.trim().to_string())
                })
                .unwrap_or_else(|| panic!("{name} missing from vma_identity.h"))
        };
        let digits = |name: &str| {
            define(name)
                .trim_end_matches(['U', 'u', 'L', 'l'])
                .to_string()
        };
        let hex = |name: &str| {
            let value = digits(name);
            u64::from_str_radix(value.trim_start_matches("0x").trim_start_matches("0X"), 16)
                .unwrap_or_else(|_| panic!("{name}={value} is not hex"))
        };
        let dec = |name: &str| {
            let value = digits(name);
            value
                .parse::<u64>()
                .unwrap_or_else(|_| panic!("{name}={value} is not a number"))
        };
        assert_eq!(hex("P11_IDENT_MAGIC"), u64::from(RECORD_MAGIC));
        assert_eq!(dec("P11_IDENT_VERSION"), u64::from(RECORD_VERSION));
        assert_eq!(dec("P11_IDENT_RECORD_LEN"), RECORD_LEN as u64);
        assert_eq!(dec("P11_IDENT_KIND_VMA"), u64::from(KIND_VMA));
        assert_eq!(dec("P11_IDENT_KIND_ANCHOR"), u64::from(KIND_ANCHOR));
        assert_eq!(dec("P11_IDENT_KIND_END"), u64::from(KIND_END));
        assert_eq!(hex("P11_IDENT_NONE"), u64::from(VERDICT_NONE));
        assert_eq!(dec("P11_IDENT_ANCHOR_OK"), u64::from(ANCHOR_OK));
        assert_eq!(dec("P11_IDENT_ANCHOR_DUP"), u64::from(ANCHOR_DUP));
        assert_eq!(dec("P11_IDENT_ANCHOR_FULL"), u64::from(ANCHOR_FULL));
        assert_eq!(
            dec("P11_IDENT_ANCHOR_BAD_SHAPE"),
            u64::from(ANCHOR_BAD_SHAPE)
        );
        assert_eq!(dec("P11_IDENT_ANCHOR_SLOTS"), u64::from(ANCHOR_SLOTS));
        assert_eq!(dec("P11_IDENT_SCOPE_WORDS"), SCOPE_WORDS as u64);
        assert_eq!(dec("P11_IDENT_F_WRONLY"), 16);
        assert_eq!(dec("P11_IDENT_F_MMAPABLE"), 1024);
    }

    /// I6 grep test: the anchor handle exposes no read API and no `Debug`,
    /// and the kernel never receives an inode address in a record struct.
    #[test]
    fn anchor_handle_has_no_read_api_or_debug() {
        let root = std::path::Path::new(env!("CARGO_MANIFEST_DIR"));
        let rust =
            std::fs::read_to_string(root.join("src/attach/identity_iter.rs")).expect("read self");
        let handle = rust
            .split_once("Write-only anchor handle")
            .expect("AnchorMaps block")
            .1
            .split_once("// aya loader")
            .expect("handle block end")
            .0;
        for forbidden in [
            "derive(Debug)",
            "derive (Debug)",
            "fn get(",
            "fn lookup(",
            "fn iter(",
            "fn keys(",
        ] {
            assert!(
                !handle.contains(forbidden),
                "AnchorMaps must not contain {forbidden:?}"
            );
        }
        assert!(handle.contains("pub fn insert("), "write API present");
        assert!(handle.contains("pub fn remove("), "delete API present");
        assert!(handle.contains("pub fn set_slot("), "slot API present");
        for path in [
            "crates/ebpf/native/vma_identity.h",
            "crates/ebpf/native/vma_identity.c",
        ] {
            let c = std::fs::read_to_string(root.join(path)).expect("read C source");
            // Every `seq_write` call passes the ABI record struct, never a
            // raw inode address: a mutation smuggling `f_inode` out through
            // any other buffer fails here.
            for (number, line) in c.lines().enumerate() {
                // Call sites only (the helper declaration shares the name).
                if line.contains("seq_write(seq") {
                    assert!(
                        line.contains("&record"),
                        "{path}:{} seq_write must pass &record",
                        number + 1
                    );
                }
            }
        }
        // Stronger: the record struct's fields are exactly the ABI names.
        let header = std::fs::read_to_string(root.join("crates/ebpf/native/vma_identity.h"))
            .expect("header");
        let record = header
            .split_once("struct p11_vma_identity_record {")
            .expect("record struct")
            .1
            .split_once("};")
            .expect("record end")
            .0;
        assert!(
            !record.contains("inode"),
            "record struct must not mention inodes"
        );
    }

    /// Raw syscalls fail closed (not panic, not success) on invalid fds.
    /// Unprivileged: `/dev/null` is never a BPF object.
    #[test]
    fn raw_syscalls_fail_closed_on_invalid_fds() {
        let null = std::fs::File::open("/dev/null").expect("open /dev/null");
        let link = link_create_task_vma(null.as_fd(), None);
        assert!(link.is_err(), "link create on /dev/null must fail");
        let link_pid = link_create_task_vma(null.as_fd(), Some(null.as_fd()));
        assert!(
            link_pid.is_err(),
            "per-pid link create on /dev/null must fail"
        );
        let iter = iter_create(null.as_fd());
        assert!(iter.is_err(), "iter create on /dev/null must fail");
        let maps = AnchorMaps::new(
            null.as_fd().try_clone_to_owned().expect("clone"),
            null.as_fd().try_clone_to_owned().expect("clone"),
        );
        assert!(
            maps.insert(1, 0, 1).is_err(),
            "map insert on /dev/null must fail"
        );
        assert!(maps.remove(1).is_err(), "map delete on /dev/null must fail");
        assert!(
            maps.set_slot(0, 1).is_err(),
            "slot write on /dev/null must fail"
        );
    }

    #[test]
    fn scope_bitmap_helpers_set_and_test() {
        let mut bitmap = vec![0u64; SCOPE_WORDS];
        assert!(scope_set_bit(&mut bitmap, 1));
        assert!(scope_set_bit(&mut bitmap, 64));
        assert!(scope_set_bit(&mut bitmap, 4_194_303));
        assert!(!scope_set_bit(&mut bitmap, 4_194_304));
        assert!(scope_test_bit(&bitmap, 1));
        assert!(scope_test_bit(&bitmap, 64));
        assert!(scope_test_bit(&bitmap, 4_194_303));
        assert!(!scope_test_bit(&bitmap, 2));
        assert!(!scope_test_bit(&bitmap, 4_194_304));
        assert!(!scope_set_bit(&mut bitmap[..10], 4_194_303));
        assert!(!scope_test_bit(&bitmap[..10], 4_194_303));
    }
}
