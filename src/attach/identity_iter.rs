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
/// Anchor verdict: a current-generation slot changed inode mid-pass (a
/// wrong-scope second installer, or the anchor page remapped during the
/// walk). Contested, never installed — and never a second `OK`.
pub const ANCHOR_CONFLICT: u32 = 4;
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
/// counters only, never kernel pointers. The anchor run is always per-pid
/// on the observer: userspace installs its own tgid here and the anchor
/// program skips every other task, so a wrong-scope walk cannot install
/// foreign inodes under observer slots.
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
    /// Observer's tgid: the only task the anchor program installs for.
    pub observer_tgid: u32,
}

const _: () = assert!(size_of::<IdentityConfig>() == 32);
const _: () = assert!(std::mem::offset_of!(IdentityConfig, generation) == 0);
const _: () = assert!(std::mem::offset_of!(IdentityConfig, arena_base) == 8);
const _: () = assert!(std::mem::offset_of!(IdentityConfig, arena_len) == 16);
const _: () = assert!(std::mem::offset_of!(IdentityConfig, slots) == 24);
const _: () = assert!(std::mem::offset_of!(IdentityConfig, observer_tgid) == 28);

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
    /// The slot changed inode mid-pass (a wrong-scope second installer,
    /// or the anchor page remapped during the walk). Contested: never
    /// installed, and never confused with `Ok`.
    Conflict,
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
    /// The expected slot count exceeds `ANCHOR_SLOTS`: no kernel run can
    /// produce slots the maps cannot hold.
    ExpectSlots,
    /// The expected generation exceeds the u32 record field: distinct
    /// passes would accept identical records, so the run identity is
    /// ambiguous.
    ExpectGen,
    /// A `DUP` alias names a missing, failed, self, or cyclic destination:
    /// aliases must resolve to a valid installed (`OK`) root.
    Alias,
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

/// Follow `slot` through the collapsed alias graph to its installed
/// root. Only `Ok` slots are installed: `Full`, `BadShape`, and
/// `Conflict` destinations fail, as do missing slots, self-reference,
/// and cycles.
fn resolve_anchor_root(anchors: &BTreeMap<u32, AnchorOutcome>, slot: u32) -> Result<u32, Invalid> {
    let mut seen = BTreeSet::new();
    let mut at = slot;
    loop {
        if !seen.insert(at) {
            return Err(Invalid::Alias);
        }
        match anchors.get(&at) {
            Some(AnchorOutcome::Dup(next)) => {
                if *next == at {
                    return Err(Invalid::Alias);
                }
                at = *next;
            }
            Some(AnchorOutcome::Ok) => return Ok(at),
            _ => return Err(Invalid::Alias),
        }
    }
}

/// Parse one run's bytes. Pure: no syscalls, no allocation past the output,
/// and no panic on any input (the byte-flip tests pin this).
///
/// Structural decode, NOT authentication: an accepted `Run` is proven
/// well-formed against the contract, not proven genuine. Legal in-range
/// mutations — a single-bit `Slot(2)→Slot(3)` verdict flip, or
/// `FULL→OK` — yield a *different* valid `Run`; corruption detection
/// needs encoding help (checksums live outside this 32-byte ABI), and
/// hostile-kernel assertions need independent validation (a parser cannot
/// authenticate the stream it parses). What the parser does guarantee:
/// every structural anomaly fails the whole run closed.
pub fn parse(bytes: &[u8], expect: &Expect) -> Result<Run, Invalid> {
    // The expectation itself is validated first: an oversized slot count
    // would admit impossible kernel slots, and a generation wider than
    // the u32 record field would let distinct passes (7 vs 0x1_00000007)
    // accept identical records. The `as u32` below is lossless past this.
    if expect.slots > ANCHOR_SLOTS {
        return Err(Invalid::ExpectSlots);
    }
    if expect.generation > u64::from(u32::MAX) {
        return Err(Invalid::ExpectGen);
    }
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
                    ANCHOR_CONFLICT => {
                        if start != 0 || end != 0 {
                            return Err(Invalid::AnchorPayload);
                        }
                        if a >= expect.slots {
                            return Err(Invalid::VerdictRange);
                        }
                        AnchorOutcome::Conflict
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
    // Alias validation runs after ALL conflicts collapsed: a destination
    // downgraded by a later repeat must fail the aliases pointing at it.
    // Aliases are exposed resolved to their installed root, so consumers
    // never chase chains.
    let dup_slots: Vec<u32> = run
        .anchors
        .iter()
        .filter(|(_, outcome)| matches!(outcome, AnchorOutcome::Dup(_)))
        .map(|(slot, _)| *slot)
        .collect();
    for slot in dup_slots {
        let root = resolve_anchor_root(&run.anchors, slot)?;
        run.anchors.insert(slot, AnchorOutcome::Dup(root));
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
/// the same walk). Stops after the END record plus the EOF read; the parser
/// then proves the stream held exactly one END. `max_bytes` caps a runaway
/// stream.
///
/// The `deadline` is mandatory (a plain `Instant`, never optional): every
/// kernel run must bound its retries. It is checked before every read and
/// after every read returns, including EOF — a result that arrives after
/// expiry is rejected. This is a COOPERATIVE deadline only: a single
/// blocked `read()` cannot be interrupted, so the wait for one read is
/// unbounded; the guarantee is that overdue RESULTS are never accepted.
pub fn read_run(
    fd: BorrowedFd<'_>,
    deadline: Instant,
    max_bytes: usize,
) -> Result<Vec<u8>, ReadError> {
    let mut out = Vec::new();
    let mut chunk = [0u8; READ_BUF_LEN];
    loop {
        if Instant::now() >= deadline {
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
        // The read itself may have crossed the deadline (a blocked read is
        // uninterruptible): reject overdue results, EOF included.
        if Instant::now() >= deadline {
            return Err(ReadError::Deadline);
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

/// Encode the `iter_info` selector for a task_vma link: `None` is the
/// explicit whole-system walk (zero info, len 0); `Some(pidfd)` is the
/// per-pid walk (info carrying the pidfd, len 16). A pidfd numbered 0 is
/// rejected with `EINVAL`: the kernel narrows the task iterator only on
/// `pid_fd != 0`, so encoding fd 0 would silently select a whole-system
/// walk. Callers that close stdin must `F_DUPFD_CLOEXEC` the pidfd to ≥1
/// (retained through link creation) before calling.
fn encode_task_vma_selector(pid_fd: Option<BorrowedFd<'_>>) -> io::Result<(IterLinkInfo, u32)> {
    match pid_fd {
        None => Ok((
            IterLinkInfo {
                tid: 0,
                pid: 0,
                pid_fd: 0,
                reserved: 0,
            },
            0,
        )),
        Some(fd) => {
            let raw = fd.as_raw_fd();
            if raw == 0 {
                return Err(io::Error::from_raw_os_error(libc::EINVAL));
            }
            Ok((
                IterLinkInfo {
                    tid: 0,
                    pid: 0,
                    pid_fd: raw as u32,
                    reserved: 0,
                },
                size_of::<IterLinkInfo>() as u32,
            ))
        }
    }
}

/// Create a `task_vma` iterator link for `prog_fd`: whole-system with
/// `pid_fd = None`, or one process with `Some(pidfd)`. The pidfd names the
/// task only at attach (F2); generation proof stays the confirm pin's job.
/// A pidfd numbered 0 fails with `EINVAL` before any syscall (see
/// [`encode_task_vma_selector`]); it must never encode as `pid_fd: 0`.
pub fn link_create_task_vma(
    prog_fd: BorrowedFd<'_>,
    pid_fd: Option<BorrowedFd<'_>>,
) -> io::Result<OwnedFd> {
    let (info, len) = encode_task_vma_selector(pid_fd)?;
    let attr = LinkCreateAttr {
        prog_fd: prog_fd.as_raw_fd() as u32,
        target_fd: 0,
        attach_type: BPF_TRACE_ITER,
        flags: 0,
        iter_info: if len == 0 {
            0
        } else {
            std::ptr::addr_of!(info).addr() as u64
        },
        iter_info_len: len,
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
    /// A verified program fd could not be cloned for the strict receipt.
    FdClone(io::Error),
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

impl From<io::Error> for LoadError {
    fn from(error: io::Error) -> Self {
        Self::FdClone(error)
    }
}

impl std::fmt::Display for LoadError {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Ebpf(error) => write!(formatter, "{error:#}"),
            Self::Program(error) => write!(formatter, "{error:#}"),
            Self::MissingProgram(name) => write!(formatter, "program {name} missing from object"),
            Self::FdClone(error) => write!(formatter, "program fd clone failed: {error}"),
        }
    }
}

impl std::error::Error for LoadError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Ebpf(error) => Some(error),
            Self::Program(error) => Some(error),
            Self::MissingProgram(_) => None,
            Self::FdClone(error) => Some(error),
        }
    }
}

/// Extract the kernel verifier log carried by a loader failure, if any.
/// Program-load failures always carry one (even permission-looking
/// `EACCES`: verifier rejections arrive with that errno); object-side
/// failures carry none.
pub fn verifier_log_of(error: &LoadError) -> Option<String> {
    let program = match error {
        LoadError::Program(program) => program,
        LoadError::Ebpf(aya::EbpfError::ProgramError(program)) => program,
        _ => return None,
    };
    match program {
        aya::programs::ProgramError::LoadError { verifier_log, .. } => {
            Some(verifier_log.to_string())
        }
        _ => None,
    }
}

/// Unverified load: parse, CO-RE relocation, and map creation only.
/// `None` disables relocation and leaves the programs unloaded; even with
/// `Some`, this function never loads a program. It exists for the
/// explicitly-unprivileged smoke test, which proves parsing and syscall
/// reachability. It MUST never back a "verified" or "loaded" claim: use
/// [`load_identity_object_strict`], which requires readable BTF and both
/// verified program fds.
pub fn load_identity_object_unverified(btf: Option<&aya::Btf>) -> Result<aya::Ebpf, LoadError> {
    let mut loader = aya::EbpfLoader::new();
    loader.btf(btf);
    let ebpf = loader.load(IDENTITY_OBJECT)?;
    Ok(ebpf)
}

/// A verified identity object: both `iter/task_vma` programs passed the
/// kernel verifier, and their fds are retained here as the receipt.
pub struct StrictIdentity {
    /// The loaded object (maps + both verified programs).
    pub ebpf: aya::Ebpf,
    /// Cloned fd of the verified anchor program.
    pub anchor_fd: OwnedFd,
    /// Cloned fd of the verified target program.
    pub target_fd: OwnedFd,
}

/// Strict load: maps plus both `iter/task_vma` programs, with CO-RE
/// relocated against readable `btf`. A successful return means both
/// programs passed the verifier and both fds are retained. EVERY
/// program-load error fails here — callers must not classify any of them
/// as "unprivileged" (verifier rejections arrive as `EACCES`).
/// Attaching itself is W3-2's probe.
pub fn load_identity_object_strict(btf: &aya::Btf) -> Result<StrictIdentity, LoadError> {
    let mut loader = aya::EbpfLoader::new();
    loader.btf(Some(btf));
    let mut ebpf = loader.load(IDENTITY_OBJECT)?;
    for name in [ANCHOR_PROGRAM, TARGET_PROGRAM] {
        let program: &mut aya::programs::Iter = ebpf
            .program_mut(name)
            .ok_or(LoadError::MissingProgram(name))?
            .try_into()?;
        program.load(ITER_TYPE_TASK_VMA, btf)?;
    }
    let fd_of = |ebpf: &aya::Ebpf, name: &'static str| -> Result<OwnedFd, LoadError> {
        let program = ebpf.program(name).ok_or(LoadError::MissingProgram(name))?;
        Ok(program.fd()?.as_fd().try_clone_to_owned()?)
    };
    Ok(StrictIdentity {
        anchor_fd: fd_of(&ebpf, ANCHOR_PROGRAM)?,
        target_fd: fd_of(&ebpf, TARGET_PROGRAM)?,
        ebpf,
    })
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
        assert!(oracle_accepts(&bytes, &target_expect(&scope)));
        assert_run_matches_bytes(&bytes, &target_expect(&scope), &run);
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
        assert!(oracle_accepts(&bytes, &anchor_expect(&scope)));
        assert_run_matches_bytes(&bytes, &anchor_expect(&scope), &run);
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

    /// The parser must validate the expectation itself, not just the
    /// stream: `slots` past the kernel capacity admits impossible slots,
    /// and a generation wider than the u32 record field makes distinct
    /// passes accept identical records.
    #[test]
    fn parse_validates_expect_width_and_slots() {
        let scope: BTreeSet<u32> = [100].into_iter().collect();
        let bytes = [
            record(KIND_VMA, 100, 0x1000, 0x2000, 3, 7).to_vec(),
            end(7).to_vec(),
        ]
        .concat();
        let oversized = Expect {
            generation: 7,
            slots: ANCHOR_SLOTS + 1,
            scope: &scope,
            mode: RunMode::WholeSystem,
            run: RunKind::Target,
        };
        assert_eq!(
            parse(&bytes, &oversized),
            Err(Invalid::ExpectSlots),
            "slots past ANCHOR_SLOTS must reject the run"
        );
        let wide = Expect {
            generation: 0x1_0000_0007,
            slots: 4,
            scope: &scope,
            mode: RunMode::WholeSystem,
            run: RunKind::Target,
        };
        assert_eq!(
            parse(&bytes, &wide),
            Err(Invalid::ExpectGen),
            "a generation wider than u32 must reject the run"
        );
        // Boundary accepts: exactly the capacity, exactly u32::MAX, and
        // the zero-slot all-NONE target run stay valid.
        let full = Expect {
            generation: 7,
            slots: ANCHOR_SLOTS,
            scope: &scope,
            mode: RunMode::WholeSystem,
            run: RunKind::Target,
        };
        parse(&bytes, &full).expect("slots == ANCHOR_SLOTS parses");
        let gen_bytes = [
            record(KIND_VMA, 100, 0x1000, 0x2000, 3, u32::MAX).to_vec(),
            end(u32::MAX).to_vec(),
        ]
        .concat();
        let max_gen = Expect {
            generation: u64::from(u32::MAX),
            slots: 4,
            scope: &scope,
            mode: RunMode::WholeSystem,
            run: RunKind::Target,
        };
        parse(&gen_bytes, &max_gen).expect("generation == u32::MAX parses");
        let none_bytes = [
            record(KIND_VMA, 100, 0x1000, 0x2000, VERDICT_NONE, 7).to_vec(),
            end(7).to_vec(),
        ]
        .concat();
        let zero_slots = Expect {
            generation: 7,
            slots: 0,
            scope: &scope,
            mode: RunMode::WholeSystem,
            run: RunKind::Target,
        };
        parse(&none_bytes, &zero_slots).expect("zero slots admit NONE-only runs");
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

    /// A current-gen slot changing inode must surface as a distinct
    /// `Conflict` outcome — never a second `OK`.
    #[test]
    fn anchor_conflict_outcome_marks_slot_contested() {
        let empty_scope = BTreeSet::new();
        let anchor = anchor_expect(&empty_scope);
        let bytes = [
            record(KIND_ANCHOR, 0, 0, 0, ANCHOR_CONFLICT, 7).to_vec(),
            end(7).to_vec(),
        ]
        .concat();
        let run = parse(&bytes, &anchor).expect("CONFLICT must parse to a contested slot");
        assert_eq!(run.anchors.get(&0), Some(&AnchorOutcome::Conflict));
        // A contested slot never counts as installed, even beside an OK:
        // mixed repeats still downgrade the slot.
        let bytes = [
            record(KIND_ANCHOR, 1, 0, 0, ANCHOR_OK, 7).to_vec(),
            record(KIND_ANCHOR, 1, 0, 0, ANCHOR_CONFLICT, 7).to_vec(),
            end(7).to_vec(),
        ]
        .concat();
        let run = parse(&bytes, &anchor).expect("mixed repeats stay per-key");
        assert_eq!(run.anchors.get(&1), Some(&AnchorOutcome::BadShape));
        // Identical CONFLICT repeats collapse like any other outcome.
        let bytes = [
            record(KIND_ANCHOR, 2, 0, 0, ANCHOR_CONFLICT, 7).to_vec(),
            record(KIND_ANCHOR, 2, 0, 0, ANCHOR_CONFLICT, 7).to_vec(),
            end(7).to_vec(),
        ]
        .concat();
        let run = parse(&bytes, &anchor).expect("identical repeats collapse");
        assert_eq!(run.anchors.get(&2), Some(&AnchorOutcome::Conflict));
        // CONFLICT carries no payload and names a real slot.
        let mut dirty = record(KIND_ANCHOR, 0, 0, 0, ANCHOR_CONFLICT, 7);
        dirty[8] = 1;
        assert_eq!(
            parse(&[dirty.to_vec(), end(7).to_vec()].concat(), &anchor),
            Err(Invalid::AnchorPayload)
        );
        let wide = [
            record(KIND_ANCHOR, 4, 0, 0, ANCHOR_CONFLICT, 7).to_vec(),
            end(7).to_vec(),
        ]
        .concat();
        assert_eq!(parse(&wide, &anchor), Err(Invalid::VerdictRange));
    }

    /// Each address endpoint is guarded independently at exactly 2^56:
    /// `start` at the guard rejects even with a higher end, `end` at the
    /// guard rejects even with a lower start, and the highest fully
    /// below-guard range parses. (A coarser guard such as 2^57 would admit
    /// the contract-forbidden range between them.)
    #[test]
    fn pointer_guard_rejects_each_endpoint_at_2pow56() {
        let scope: BTreeSet<u32> = [100].into_iter().collect();
        let expect = target_expect(&scope);
        let guarded = POINTER_GUARD;
        // start exactly at the guard.
        let bytes = [
            record(KIND_VMA, 100, guarded, guarded + 0x1000, 3, 7).to_vec(),
            end(7).to_vec(),
        ]
        .concat();
        assert_eq!(parse(&bytes, &expect), Err(Invalid::PointerShape));
        // end exactly at the guard.
        let bytes = [
            record(KIND_VMA, 100, guarded - 0x1000, guarded, 3, 7).to_vec(),
            end(7).to_vec(),
        ]
        .concat();
        assert_eq!(parse(&bytes, &expect), Err(Invalid::PointerShape));
        // A forbidden range strictly between 2^56 and 2^57.
        let bytes = [
            record(KIND_VMA, 100, guarded + 0x1000, guarded + 0x2000, 3, 7).to_vec(),
            end(7).to_vec(),
        ]
        .concat();
        assert_eq!(parse(&bytes, &expect), Err(Invalid::PointerShape));
        // The highest fully below-guard range parses.
        let bytes = [
            record(KIND_VMA, 100, guarded - 0x2000, guarded - 0x1000, 3, 7).to_vec(),
            end(7).to_vec(),
        ]
        .concat();
        parse(&bytes, &expect).expect("below-guard range parses");
        // Anchor address fields get the same per-endpoint guard (checked
        // before payload shape, so the guard names the failure).
        let empty = BTreeSet::new();
        let anchor = anchor_expect(&empty);
        let mut start_guarded = record(KIND_ANCHOR, 0, 0, 0, ANCHOR_OK, 7);
        start_guarded[8..16].copy_from_slice(&guarded.to_le_bytes());
        assert_eq!(
            parse(&[start_guarded.to_vec(), end(7).to_vec()].concat(), &anchor),
            Err(Invalid::PointerShape)
        );
        let mut end_guarded = record(KIND_ANCHOR, 0, 0, 0, ANCHOR_OK, 7);
        end_guarded[16..24].copy_from_slice(&guarded.to_le_bytes());
        assert_eq!(
            parse(&[end_guarded.to_vec(), end(7).to_vec()].concat(), &anchor),
            Err(Invalid::PointerShape)
        );
    }

    /// Structural decode, pinned: legal single-bit flips yield *different*
    /// valid runs rather than rejections. `Slot(2)→Slot(3)` flips one bit
    /// of the verdict word; `FULL(2)→OK(0)` clears one bit. (By contrast
    /// `NONE→Slot` needs 30 bits.) This is the documented
    /// structural-decode-not-authentication property, not a gap.
    #[test]
    fn legal_single_bit_flips_yield_different_valid_runs() {
        let scope: BTreeSet<u32> = [100].into_iter().collect();
        let expect = target_expect(&scope);
        let mut vma = record(KIND_VMA, 100, 0x1000, 0x2000, 2, 7);
        assert_eq!(vma[24], 0x02);
        vma[24] = 0x03;
        let run = parse(&[vma.to_vec(), end(7).to_vec()].concat(), &expect)
            .expect("in-range verdict flip stays valid");
        assert_eq!(
            run.by_pid
                .get(&100)
                .and_then(|ranges| ranges.get(&(0x1000, 0x2000))),
            Some(&TargetVerdict::Slot(3))
        );
        let empty = BTreeSet::new();
        let anchor = anchor_expect(&empty);
        let mut full = record(KIND_ANCHOR, 0, 0, 0, ANCHOR_FULL, 7);
        assert_eq!(full[24], 0x02);
        full[24] = 0x00;
        let run = parse(&[full.to_vec(), end(7).to_vec()].concat(), &anchor)
            .expect("FULL->OK single-bit clear stays valid");
        assert_eq!(run.anchors.get(&0), Some(&AnchorOutcome::Ok));
    }

    /// `Dup` must alias an installed slot: self-reference, cycles, and
    /// missing/failed destinations all fail the run — bounds checks alone
    /// do not establish "aliases an installed slot".
    #[test]
    fn anchor_alias_graph_is_validated_after_conflicts() {
        let empty = BTreeSet::new();
        let anchor = anchor_expect(&empty);
        let dup = |slot: u32, dest: u32| {
            let mut rec = record(KIND_ANCHOR, slot, 0, 0, ANCHOR_DUP, 7);
            rec[8..16].copy_from_slice(&u64::from(dest).to_le_bytes());
            rec.to_vec()
        };
        // Self-DUP.
        let bytes = [dup(1, 1), end(7).to_vec()].concat();
        assert_eq!(parse(&bytes, &anchor), Err(Invalid::Alias));
        // Missing destination: {1: Dup(2)} with no slot 2.
        let bytes = [dup(1, 2), end(7).to_vec()].concat();
        assert_eq!(parse(&bytes, &anchor), Err(Invalid::Alias));
        // Reciprocal cycle.
        let bytes = [dup(1, 2), dup(2, 1), end(7).to_vec()].concat();
        assert_eq!(parse(&bytes, &anchor), Err(Invalid::Alias));
        // Longer cycle through an installed-looking chain.
        let bytes = [
            record(KIND_ANCHOR, 0, 0, 0, ANCHOR_OK, 7).to_vec(),
            dup(1, 2),
            dup(2, 3),
            dup(3, 1),
            end(7).to_vec(),
        ]
        .concat();
        assert_eq!(parse(&bytes, &anchor), Err(Invalid::Alias));
        // DUP to a failed destination.
        let bytes = [
            record(KIND_ANCHOR, 2, 0, 0, ANCHOR_FULL, 7).to_vec(),
            dup(1, 2),
            end(7).to_vec(),
        ]
        .concat();
        assert_eq!(parse(&bytes, &anchor), Err(Invalid::Alias));
        // DUP to a contested destination.
        let bytes = [
            record(KIND_ANCHOR, 2, 0, 0, ANCHOR_CONFLICT, 7).to_vec(),
            dup(1, 2),
            end(7).to_vec(),
        ]
        .concat();
        assert_eq!(parse(&bytes, &anchor), Err(Invalid::Alias));
        // DUP to a destination later downgraded by conflict.
        let bytes = [
            record(KIND_ANCHOR, 2, 0, 0, ANCHOR_OK, 7).to_vec(),
            record(KIND_ANCHOR, 2, 0, 0, ANCHOR_FULL, 7).to_vec(),
            dup(1, 2),
            end(7).to_vec(),
        ]
        .concat();
        assert_eq!(parse(&bytes, &anchor), Err(Invalid::Alias));
    }

    /// Valid aliases are exposed resolved to their installed root, so
    /// consumers never chase chains.
    #[test]
    fn anchor_aliases_resolve_to_installed_root() {
        let empty = BTreeSet::new();
        let anchor = anchor_expect(&empty);
        let dup = |slot: u32, dest: u32| {
            let mut rec = record(KIND_ANCHOR, slot, 0, 0, ANCHOR_DUP, 7);
            rec[8..16].copy_from_slice(&u64::from(dest).to_le_bytes());
            rec.to_vec()
        };
        let bytes = [
            record(KIND_ANCHOR, 0, 0, 0, ANCHOR_OK, 7).to_vec(),
            dup(2, 0),
            dup(1, 2),
            end(7).to_vec(),
        ]
        .concat();
        let run = parse(&bytes, &anchor).expect("rooted chains parse");
        assert_eq!(run.anchors.get(&0), Some(&AnchorOutcome::Ok));
        assert_eq!(run.anchors.get(&1), Some(&AnchorOutcome::Dup(0)));
        assert_eq!(run.anchors.get(&2), Some(&AnchorOutcome::Dup(0)));
        assert!(oracle_accepts(&bytes, &anchor));
        assert_run_matches_bytes(&bytes, &anchor, &run);
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

    /// Independent oracle: accept/reject re-derived from the contract,
    /// never by calling [`parse`]. Every byte-flip and randomized mutation
    /// below must agree with it — that turns "parse compares with itself"
    /// into "parse agrees with an independent decision procedure".
    /// (Kept in sync with `parse` by construction: any rule change must
    /// update both, and the agreement tests fail otherwise.)
    fn oracle_accepts(bytes: &[u8], expect: &Expect) -> bool {
        if expect.slots > ANCHOR_SLOTS {
            return false;
        }
        if expect.generation > u64::from(u32::MAX) {
            return false;
        }
        if !bytes.len().is_multiple_of(RECORD_LEN) || bytes.is_empty() {
            return false;
        }
        let records = bytes.len() / RECORD_LEN;
        // The tail must be a zero-payload END; any other END position dies
        // in the walk below.
        let tail = &bytes[(records - 1) * RECORD_LEN..records * RECORD_LEN];
        if tail[3] != KIND_END
            || u32_at(tail, 4) != 0
            || u64_at(tail, 8) != 0
            || u64_at(tail, 16) != 0
            || u32_at(tail, 24) != 0
        {
            return false;
        }
        let want_gen = expect.generation as u32;
        let mut last_tgid: Option<u32> = None;
        let mut only_tgid: Option<u32> = None;
        let mut raw_anchor: Vec<(u32, AnchorOutcome)> = Vec::new();
        for index in 0..records {
            let record = &bytes[index * RECORD_LEN..(index + 1) * RECORD_LEN];
            if u16_at(record, 0) != RECORD_MAGIC || record[2] != RECORD_VERSION {
                return false;
            }
            if u32_at(record, 28) != want_gen {
                return false;
            }
            let a = u32_at(record, 4);
            let start = u64_at(record, 8);
            let end = u64_at(record, 16);
            let verdict = u32_at(record, 24);
            match record[3] {
                KIND_END => {
                    if index != records - 1 {
                        return false;
                    }
                }
                KIND_VMA => {
                    if !matches!(expect.run, RunKind::Target) {
                        return false;
                    }
                    if start >= end
                        || start & (PAGE_GRANULE - 1) != 0
                        || end & (PAGE_GRANULE - 1) != 0
                    {
                        return false;
                    }
                    if start >= POINTER_GUARD || end >= POINTER_GUARD {
                        return false;
                    }
                    if verdict != VERDICT_NONE && verdict >= expect.slots {
                        return false;
                    }
                    if !expect.scope.contains(&a) {
                        return false;
                    }
                    match expect.mode {
                        RunMode::WholeSystem => {
                            if last_tgid.is_some_and(|last| a < last) {
                                return false;
                            }
                            last_tgid = Some(a);
                        }
                        RunMode::PerPid => match only_tgid {
                            None => only_tgid = Some(a),
                            Some(first) if first == a => {}
                            Some(_) => return false,
                        },
                    }
                }
                KIND_ANCHOR => {
                    if !matches!(expect.run, RunKind::Anchor) {
                        return false;
                    }
                    if start >= POINTER_GUARD || end >= POINTER_GUARD {
                        return false;
                    }
                    let outcome = match verdict {
                        ANCHOR_OK => (start == 0 && end == 0 && a < expect.slots)
                            .then_some(AnchorOutcome::Ok),
                        ANCHOR_DUP => {
                            (end == 0 && a < expect.slots && start < u64::from(expect.slots))
                                .then_some(AnchorOutcome::Dup(start as u32))
                        }
                        ANCHOR_FULL => (start == 0 && end == 0 && a < expect.slots)
                            .then_some(AnchorOutcome::Full),
                        ANCHOR_BAD_SHAPE => {
                            (start == 0 && end == 0).then_some(AnchorOutcome::BadShape)
                        }
                        ANCHOR_CONFLICT => (start == 0 && end == 0 && a < expect.slots)
                            .then_some(AnchorOutcome::Conflict),
                        _ => None,
                    };
                    match outcome {
                        Some(mapped) => raw_anchor.push((a, mapped)),
                        None => return false,
                    }
                }
                _ => return false,
            }
        }
        // Alias validation after all conflicts, mirroring `parse`.
        if matches!(expect.run, RunKind::Anchor) && oracle_collapsed_anchors(&raw_anchor).is_none()
        {
            return false;
        }
        true
    }

    /// Test-side alias collapse + resolution (shared by the oracle and
    /// the correspondence check; independent of `resolve_anchor_root`):
    /// collapse each slot's raw outcomes (mixed repeats downgrade), then
    /// resolve every `Dup` to its installed root. `None` rejects the run:
    /// self-reference, cycles, and missing/failed destinations.
    fn oracle_collapsed_anchors(
        raw: &[(u32, AnchorOutcome)],
    ) -> Option<BTreeMap<u32, AnchorOutcome>> {
        let mut per_slot: BTreeMap<u32, Vec<AnchorOutcome>> = BTreeMap::new();
        for (slot, outcome) in raw {
            per_slot.entry(*slot).or_default().push(*outcome);
        }
        let mut collapsed = BTreeMap::new();
        for (slot, outcomes) in &per_slot {
            let first = outcomes[0];
            if outcomes.iter().all(|one| *one == first) {
                collapsed.insert(*slot, first);
            } else {
                collapsed.insert(*slot, AnchorOutcome::BadShape);
            }
        }
        let slots: Vec<u32> = collapsed.keys().copied().collect();
        for slot in slots {
            if !matches!(collapsed[&slot], AnchorOutcome::Dup(_)) {
                continue;
            }
            let mut visited = Vec::new();
            let mut at = slot;
            let root = loop {
                if visited.contains(&at) || visited.len() > collapsed.len() {
                    return None;
                }
                visited.push(at);
                match collapsed.get(&at) {
                    Some(AnchorOutcome::Dup(next)) => {
                        if *next == at {
                            return None;
                        }
                        at = *next;
                    }
                    Some(AnchorOutcome::Ok) => break at,
                    _ => return None,
                }
            };
            collapsed.insert(slot, AnchorOutcome::Dup(root));
        }
        Some(collapsed)
    }

    /// Correspondence check: an accepted `Run` must match the raw bytes it
    /// was parsed from — every parsed entry traces to raw record(s) with
    /// the correctly-mapped verdict, demotions trace to genuine raw
    /// conflicts, and nothing is invented. Never calls [`parse`].
    fn assert_run_matches_bytes(bytes: &[u8], expect: &Expect, run: &Run) {
        let records = bytes.len() / RECORD_LEN;
        let mut raw_vma: Vec<(u32, u64, u64, TargetVerdict)> = Vec::new();
        let mut raw_anchor: Vec<(u32, AnchorOutcome)> = Vec::new();
        for index in 0..records {
            let record = &bytes[index * RECORD_LEN..(index + 1) * RECORD_LEN];
            let a = u32_at(record, 4);
            let start = u64_at(record, 8);
            let end = u64_at(record, 16);
            let verdict = u32_at(record, 24);
            match record[3] {
                KIND_VMA => {
                    let mapped = if verdict == VERDICT_NONE {
                        TargetVerdict::Unmatched
                    } else {
                        TargetVerdict::Slot(verdict)
                    };
                    raw_vma.push((a, start, end, mapped));
                }
                KIND_ANCHOR => {
                    let mapped = match verdict {
                        ANCHOR_OK => AnchorOutcome::Ok,
                        ANCHOR_DUP => AnchorOutcome::Dup(start as u32),
                        ANCHOR_FULL => AnchorOutcome::Full,
                        ANCHOR_BAD_SHAPE => AnchorOutcome::BadShape,
                        _ => AnchorOutcome::Conflict,
                    };
                    raw_anchor.push((a, mapped));
                }
                _ => {}
            }
        }
        match expect.run {
            RunKind::Target => {
                assert!(
                    run.anchors.is_empty(),
                    "target runs carry no anchor outcomes"
                );
                // Every parsed entry traces to identical raw record(s), and
                // no raw record for a kept pid disagrees with it.
                for (pid, ranges) in &run.by_pid {
                    assert!(
                        !run.demoted_pids.contains(pid),
                        "kept pid {pid} must not be demoted"
                    );
                    for (range, verdict) in ranges {
                        let mut sources = 0;
                        for (a, start, end, mapped) in &raw_vma {
                            if a == pid && (*start, *end) == *range {
                                assert_eq!(
                                    mapped, verdict,
                                    "parsed verdict for {pid}:{range:?} must match its raw records"
                                );
                                sources += 1;
                            }
                        }
                        assert!(sources > 0, "parsed {pid}:{range:?} invents no raw record");
                    }
                }
                // Every demotion traces to a genuine raw conflict, and every
                // raw record is either reflected or its pid demoted.
                for pid in &run.demoted_pids {
                    assert!(
                        !run.by_pid.contains_key(pid),
                        "demoted pid {pid} keeps no records"
                    );
                    let mut conflict = false;
                    for i in 0..raw_vma.len() {
                        for j in 0..raw_vma.len() {
                            if raw_vma[i].0 == *pid
                                && raw_vma[j].0 == *pid
                                && (raw_vma[i].1, raw_vma[i].2) == (raw_vma[j].1, raw_vma[j].2)
                                && raw_vma[i].3 != raw_vma[j].3
                            {
                                conflict = true;
                            }
                        }
                    }
                    assert!(conflict, "demoted pid {pid} needs a genuine raw conflict");
                }
                for (a, start, end, mapped) in &raw_vma {
                    if run.demoted_pids.contains(a) {
                        continue;
                    }
                    assert_eq!(
                        run.by_pid
                            .get(a)
                            .and_then(|ranges| ranges.get(&(*start, *end))),
                        Some(mapped),
                        "raw record {a}:({start}, {end}) must be reflected when kept"
                    );
                }
            }
            RunKind::Anchor => {
                assert!(
                    run.by_pid.is_empty(),
                    "anchor runs carry no target verdicts"
                );
                assert!(run.demoted_pids.is_empty(), "anchor runs demote nothing");
                let expected = oracle_collapsed_anchors(&raw_anchor)
                    .expect("accepted runs collapse and resolve");
                assert_eq!(
                    run.anchors, expected,
                    "parsed anchors must equal collapsed+resolved raw outcomes"
                );
            }
        }
    }

    /// The design's byte-flip property, stated precisely. The literal "same
    /// `Run` or `Invalid`" holds for the END-only stream: it carries no
    /// payload byte whose flip stays valid, so this test pins all 32 × 255
    /// flips exhaustively. Payload streams cannot satisfy the literal form
    /// (an in-range verdict flip yields a *different* valid `Run`), so the
    /// companion test below pins no-panic plus determinism there instead.
    /// Both tests additionally pin oracle agreement plus parsed-bytes
    /// correspondence on every flip.
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
                        assert!(
                            oracle_accepts(&flipped, &expect),
                            "oracle must agree: flip at {at} to {value:#x} accepted"
                        );
                        assert_run_matches_bytes(&flipped, &expect, &run);
                        same += 1;
                    }
                    Err(_) => {
                        assert!(
                            !oracle_accepts(&flipped, &expect),
                            "oracle must agree: flip at {at} to {value:#x} rejected"
                        );
                        invalid += 1;
                    }
                }
            }
        }
        assert_eq!(same + invalid, 32 * 255);
        assert!(invalid > 0, "flips must invalidate sometimes");
    }

    /// Payload-stream flips never panic and parse deterministically: any two
    /// parses of the same flipped bytes agree. Every flip additionally pins
    /// oracle agreement (rejection assertions for structural mutations via
    /// the independent decision procedure) plus parsed-bytes correspondence
    /// for accepted streams.
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
                    assert_eq!(
                        first.is_ok(),
                        oracle_accepts(&flipped, expect),
                        "flip at {at} to {value:#x} must agree with the oracle"
                    );
                    if let Ok(run) = first {
                        assert_run_matches_bytes(&flipped, expect, &run);
                    }
                }
            }
        }
    }

    /// Randomized mutations never panic, and every outcome agrees with
    /// the oracle (accepted streams additionally match their raw bytes).
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
            let parsed = parse(&bytes, &expect);
            assert_eq!(
                parsed.is_ok(),
                oracle_accepts(&bytes, &expect),
                "randomized mutation must agree with the oracle"
            );
            if let Ok(run) = parsed {
                assert_run_matches_bytes(&bytes, &expect, &run);
            }
        }
        // Truncated and overlong inputs too.
        for len in 0..seed.len() + 64 {
            let cut = &seed[..len.min(seed.len())];
            assert_eq!(
                parse(cut, &expect).is_ok(),
                oracle_accepts(cut, &expect),
                "truncation to {len} bytes must agree with the oracle"
            );
            let mut long = seed.clone();
            long.extend(std::iter::repeat_n(0xA5, len.saturating_sub(seed.len())));
            assert_eq!(
                parse(&long, &expect).is_ok(),
                oracle_accepts(&long, &expect),
                "extension to {} bytes must agree with the oracle",
                long.len()
            );
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
        let out = read_run(
            read_end.as_fd(),
            Instant::now() + Duration::from_secs(60),
            1 << 20,
        )
        .expect("drain to EOF");
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
            Instant::now() + Duration::from_secs(10),
            1 << 20,
        )
        .expect("EAGAIN must retry until data, not return EOF early");
        writer.join().expect("writer thread");
        assert_eq!(out.len(), 2 * RECORD_LEN);
    }

    /// EOF arriving after the deadline must fail, not succeed: the
    /// blocking read below sleeps past the deadline (uninterruptible) and
    /// then delivers EOF with no data. The reader must reject the
    /// overdue empty result instead of returning `Ok`.
    #[test]
    fn reader_eof_after_deadline_is_rejected() {
        let (read_end, write_end) = pipe();
        let deadline = Instant::now() + Duration::from_millis(50);
        let writer = std::thread::spawn(move || {
            std::thread::sleep(Duration::from_millis(300));
            drop(write_end);
        });
        assert_eq!(
            read_run(read_end.as_fd(), deadline, 1 << 20),
            Err(ReadError::Deadline),
            "EOF past the deadline must fail the run"
        );
        writer.join().expect("writer thread");
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
            read_run(read_end.as_fd(), Instant::now(), 1 << 20),
            Err(ReadError::Deadline)
        );
        // A future deadline is reached through repeated retries, not just
        // observed already-expired: the spin below must terminate at the
        // deadline with no data delivered.
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
        let _held = write_end;
        let before = Instant::now();
        assert_eq!(
            read_run(
                read_end.as_fd(),
                before + Duration::from_millis(100),
                1 << 20
            ),
            Err(ReadError::Deadline)
        );
        assert!(
            before.elapsed() >= Duration::from_millis(100),
            "the retry spin must last until the deadline"
        );
        // A stream past the cap fails even with a live deadline.
        let (read_end, write_end) = pipe();
        let payload = [end(7).to_vec(), end(7).to_vec()].concat();
        write_all(write_end.as_fd(), &payload);
        drop(write_end);
        assert_eq!(
            read_run(
                read_end.as_fd(),
                Instant::now() + Duration::from_secs(60),
                RECORD_LEN
            ),
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
        assert_eq!(dec("P11_IDENT_ANCHOR_CONFLICT"), u64::from(ANCHOR_CONFLICT));
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

    /// Selector encoding: a pidfd numbered 0 must be rejected, never
    /// encoded. The kernel narrows the task iterator only on `pid_fd != 0`,
    /// so encoding fd 0 with `iter_info_len = 16` silently selects a
    /// whole-system walk. `None` stays the only whole-system encoding.
    #[test]
    fn pidfd_zero_selector_is_rejected_not_whole_system() {
        // Borrowed, never owned or closed: fd 0 here stands in for a
        // caller's pidfd that landed on descriptor 0 (stdin closed).
        let zero = unsafe { BorrowedFd::borrow_raw(0) };
        let err = encode_task_vma_selector(Some(zero))
            .expect_err("pidfd 0 must be rejected, never encoded");
        assert_eq!(
            err.raw_os_error(),
            Some(libc::EINVAL),
            "fd-0 rejection must be EINVAL raised before any syscall"
        );
        // A nonzero pidfd still selects the per-pid walk.
        let null = std::fs::File::open("/dev/null").expect("open /dev/null");
        assert_ne!(null.as_raw_fd(), 0, "test needs a nonzero fd");
        let (info, len) = encode_task_vma_selector(Some(null.as_fd())).expect("nonzero encodes");
        assert_eq!(info.pid_fd, null.as_raw_fd() as u32);
        assert_eq!(info.tid, 0);
        assert_eq!(info.pid, 0);
        assert_eq!(len, size_of::<IterLinkInfo>() as u32);
        // `None` is the only whole-system encoding.
        let (info, len) = encode_task_vma_selector(None).expect("None encodes");
        assert_eq!(info.pid_fd, 0);
        assert_eq!(len, 0);
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
    fn verifier_log_extraction_reports_kernel_log() {
        let denial = LoadError::Program(aya::programs::ProgramError::LoadError {
            io_error: io::Error::from_raw_os_error(libc::EACCES),
            verifier_log: aya_obj::VerifierLog::new("R1 invalid mem access\n".to_string()),
        });
        assert_eq!(
            verifier_log_of(&denial).as_deref(),
            Some("R1 invalid mem access\n"),
            "a verifier EACCES must retain its log, never pass as unprivileged"
        );
        let nested = LoadError::Ebpf(aya::EbpfError::ProgramError(
            aya::programs::ProgramError::LoadError {
                io_error: io::Error::from_raw_os_error(libc::EACCES),
                verifier_log: aya_obj::VerifierLog::new("back-edge\n".to_string()),
            },
        ));
        assert_eq!(verifier_log_of(&nested).as_deref(), Some("back-edge\n"));
        assert_eq!(verifier_log_of(&LoadError::MissingProgram("x")), None);
        assert_eq!(
            verifier_log_of(&LoadError::FdClone(io::Error::from_raw_os_error(
                libc::EMFILE
            ))),
            None
        );
    }

    /// The anchor run is per-pid on the observer: `config[0]` carries
    /// the observer tgid the anchor program installs for (offset 28,
    /// layout pinned against the C header by the compile-time asserts).
    #[test]
    fn identity_config_binds_observer_tgid() {
        let config = IdentityConfig {
            generation: 7,
            arena_base: 0x1000,
            arena_len: 8192,
            slots: 1,
            observer_tgid: 4242,
        };
        assert_eq!(size_of::<IdentityConfig>(), 32);
        assert_eq!(std::mem::offset_of!(IdentityConfig, observer_tgid), 28);
        assert_eq!(config.observer_tgid, 4242);
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
