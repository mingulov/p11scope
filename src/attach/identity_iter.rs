//! SPDX-License-Identifier: GPL-3.0-or-later
//! Stage 3 Wave D kernel-side identity (D2a+b): the aya loader, record
//! parser, run reader, and raw iterator syscalls for the `vma_identity` BPF
//! object (`crates/ebpf/native/vma_identity.c`).
//!
//! Standalone by construction: this file takes no `crate::` dependency.
//! Wired into `attach.rs` (W3-2). Every ABI constant mirrors
//! `vma_identity.h`; the inline tests pin the shared layout against that
//! header.

use std::collections::{BTreeMap, BTreeSet};
use std::io;
use std::os::fd::{AsFd as _, AsRawFd as _, BorrowedFd, FromRawFd as _, OwnedFd};
use std::path::{Path, PathBuf};
use std::time::{Duration, Instant};

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
/// Slot arena stride in bytes: an anchor page plus its guard page (§3.3).
pub const ANCHOR_STRIDE: u64 = 8192;
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

/// Why an anchor-arena config was rejected before iteration.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ArenaConfigError {
    /// More slots than the kernel maps hold.
    TooManySlots,
    /// The arena reservation exceeds the full-capacity extent.
    ArenaTooLong,
    /// The arena base is not page-aligned, so stride math cannot work.
    BaseMisaligned,
    /// `base + len` wraps: the kernel's range filter would misbehave.
    RangeOverflow,
    /// A nonzero slot count with an empty arena installs nothing by
    /// construction — certainly a bug, rejected loudly.
    EmptyArena,
    /// The arena length is not page-aligned, so it cannot map whole pages.
    LenMisaligned,
    /// The arena is shorter than `slots * ANCHOR_STRIDE`: at least one
    /// slot's page would lie outside the reservation.
    ArenaTooShort,
}

/// Validate an anchor-arena config BEFORE writing it to `config[0]` and
/// iterating. An oversized arena lets the kernel's slot quotient exceed
/// the u32 record field (the truncation this gate exists to prevent); an
/// undersized or misaligned one admits VMAs the reservation cannot
/// contain; every other rejection is a nonsense config that would
/// silently install nothing or mis-filter. W3-2 calls this on every pass
/// setup. The reservation model: `slots` stride-spaced pages starting at
/// a page-aligned `arena_base`, so the length must be page-aligned and
/// cover at least `slots * ANCHOR_STRIDE` bytes.
pub fn validate_arena_config(config: &IdentityConfig) -> Result<(), ArenaConfigError> {
    if config.slots > ANCHOR_SLOTS {
        return Err(ArenaConfigError::TooManySlots);
    }
    if config.arena_len > u64::from(ANCHOR_SLOTS) * ANCHOR_STRIDE {
        return Err(ArenaConfigError::ArenaTooLong);
    }
    if config.arena_base & (PAGE_GRANULE - 1) != 0 {
        return Err(ArenaConfigError::BaseMisaligned);
    }
    if config.arena_base.checked_add(config.arena_len).is_none() {
        return Err(ArenaConfigError::RangeOverflow);
    }
    if config.slots > 0 && config.arena_len == 0 {
        return Err(ArenaConfigError::EmptyArena);
    }
    if config.arena_len & (PAGE_GRANULE - 1) != 0 {
        return Err(ArenaConfigError::LenMisaligned);
    }
    if config.arena_len < u64::from(config.slots) * ANCHOR_STRIDE {
        return Err(ArenaConfigError::ArenaTooShort);
    }
    Ok(())
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
    /// `BAD_SHAPE` diagnostics for slots outside the installed range:
    /// arena VMAs past `slots` (stale mappings from a wider pass), or
    /// saturated unrepresentable quotients. Never installed, never
    /// aliases — reported separately so they cannot poison a legitimate
    /// slot's outcome.
    pub outer_bad_shape: BTreeSet<u32>,
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
                // Out-of-range shape diagnostics never enter the slot
                // namespace: route them to the separate report set. (Only
                // BAD_SHAPE admits out-of-range `a`; every other outcome
                // bounds-checks below.)
                if verdict == ANCHOR_BAD_SHAPE && a >= expect.slots {
                    if start != 0 || end != 0 {
                        return Err(Invalid::AnchorPayload);
                    }
                    run.outer_bad_shape.insert(a);
                    continue;
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
                        // In-range here (out-of-range routed above): a shape
                        // failure downgrades its slot, never installs.
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
/// `BPF_MAP_CREATE` command number.
pub const BPF_MAP_CREATE: u32 = 0;
/// `BPF_MAP_UPDATE_ELEM` command number.
pub const BPF_MAP_UPDATE_ELEM: u32 = 2;
/// `BPF_MAP_DELETE_ELEM` command number.
pub const BPF_MAP_DELETE_ELEM: u32 = 3;
/// `BPF_MAP_LOOKUP_ELEM` command number (I6 read surface: tests only).
pub const BPF_MAP_LOOKUP_ELEM: u32 = 1;
/// `BPF_MAP_GET_NEXT_KEY` command number (I6 read surface: tests only).
pub const BPF_MAP_GET_NEXT_KEY: u32 = 4;
/// `BPF_MAP_LOOKUP_AND_DELETE_ELEM` command number (I6 read surface:
/// tests only).
pub const BPF_MAP_LOOKUP_AND_DELETE_ELEM: u32 = 21;
/// `BPF_MAP_LOOKUP_BATCH` command number (I6 read surface: tests only).
pub const BPF_MAP_LOOKUP_BATCH: u32 = 24;
/// `BPF_OBJ_GET_INFO_BY_FD` command number.
pub const BPF_OBJ_GET_INFO_BY_FD: u32 = 15;
/// `BPF_MAP_TYPE_HASH` map type.
pub const BPF_MAP_TYPE_HASH: u32 = 1;
/// `BPF_MAP_TYPE_ARRAY` map type.
pub const BPF_MAP_TYPE_ARRAY: u32 = 2;
/// `BPF_TRACE_ITER` attach type for `iter/task_vma` links.
pub const BPF_TRACE_ITER: u32 = 28;
/// `BPF_F_WRONLY` map flag: the kernel-only anchor maps.
pub const BPF_F_WRONLY: u32 = 16;
/// `BPF_F_MMAPABLE` map flag: the scope bitmap.
pub const BPF_F_MMAPABLE: u32 = 1024;
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

/// `BPF_MAP_*_BATCH` attr: `{in_batch@0, out_batch@8, keys@16,
/// values@24, count@32, map_fd@36, elem_flags@40, flags@48}` (56 bytes).
/// Test-only use (I6): production code never reads the anchor maps.
#[repr(C)]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct MapBatchAttr {
    pub in_batch: u64,
    pub out_batch: u64,
    pub keys: u64,
    pub values: u64,
    pub count: u32,
    pub map_fd: u32,
    pub elem_flags: u64,
    pub flags: u64,
}

const _: () = assert!(size_of::<MapBatchAttr>() == 56);
const _: () = assert!(std::mem::offset_of!(MapBatchAttr, in_batch) == 0);
const _: () = assert!(std::mem::offset_of!(MapBatchAttr, out_batch) == 8);
const _: () = assert!(std::mem::offset_of!(MapBatchAttr, keys) == 16);
const _: () = assert!(std::mem::offset_of!(MapBatchAttr, values) == 24);
const _: () = assert!(std::mem::offset_of!(MapBatchAttr, count) == 32);
const _: () = assert!(std::mem::offset_of!(MapBatchAttr, map_fd) == 36);
const _: () = assert!(std::mem::offset_of!(MapBatchAttr, elem_flags) == 40);
const _: () = assert!(std::mem::offset_of!(MapBatchAttr, flags) == 48);

/// `BPF_OBJ_GET_INFO_BY_FD` attr: `{bpf_fd@0, info_len@4, info@8}`.
#[repr(C)]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ObjGetInfoAttr {
    pub bpf_fd: u32,
    pub info_len: u32,
    pub info: u64,
}

const _: () = assert!(size_of::<ObjGetInfoAttr>() == 16);
const _: () = assert!(std::mem::offset_of!(ObjGetInfoAttr, bpf_fd) == 0);
const _: () = assert!(std::mem::offset_of!(ObjGetInfoAttr, info_len) == 4);
const _: () = assert!(std::mem::offset_of!(ObjGetInfoAttr, info) == 8);

/// Prefix of `struct bpf_map_info` the handle check reads: the kernel
/// fills what fits, so a short buffer is a supported query for exactly
/// these fields. Metadata only — keys and values are never read.
#[repr(C)]
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct MapInfoPrefix {
    pub map_type: u32,
    pub id: u32,
    pub key_size: u32,
    pub value_size: u32,
    pub max_entries: u32,
    pub map_flags: u32,
}

const _: () = assert!(size_of::<MapInfoPrefix>() == 24);
const _: () = assert!(std::mem::offset_of!(MapInfoPrefix, map_type) == 0);
const _: () = assert!(std::mem::offset_of!(MapInfoPrefix, key_size) == 8);
const _: () = assert!(std::mem::offset_of!(MapInfoPrefix, value_size) == 12);
const _: () = assert!(std::mem::offset_of!(MapInfoPrefix, max_entries) == 16);
const _: () = assert!(std::mem::offset_of!(MapInfoPrefix, map_flags) == 20);

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
/// production code constructs (validates) only. There is intentionally
/// no `get`, `lookup`, `iter`, `keys`, `insert`, or `Debug`
/// implementation: only the anchor program installs identity assertions.
/// Teardown lives behind `#[cfg(test)]` as an interim test-only
/// primitive — unrestricted bookkeeping has no place in the non-test API
/// (a stray `set_slot` could otherwise clear the slot cell the anchor
/// program's conflict guard reads); production teardown is W3-2's
/// kernel-side slot/generation command. Inode addresses enter the kernel
/// here and never come back.
///
/// The fields are intentionally never read (I6: no read API exists, and
/// the kernel refuses reads through these fds). The `dead_code` allow is
/// that invariant, not tidiness: any future read must go through a new
/// audited API, which the I6 exact-API test will flag.
#[allow(dead_code)]
pub struct AnchorMaps {
    hash: OwnedFd,
    slots: OwnedFd,
}

/// Check one anchor-map handle: a `WRONLY` fd (`EBADF` otherwise) for a
/// map with exactly the expected type, key/value sizes, and capacity
/// (`EINVAL` otherwise), via `BPF_OBJ_GET_INFO_BY_FD`. The creation-time
/// `WRONLY` map flag is NOT re-checked here: the kernel reports the live
/// shape in `map_info` but the write-only-ness on the fd itself (a
/// `WRONLY` map yields `O_WRONLY` fds, and reads through them fail with
/// `EPERM`). Metadata only — keys and values are never read.
fn validated_map_fd(
    fd: BorrowedFd<'_>,
    want_type: u32,
    want_key: u32,
    want_value: u32,
    want_max: u32,
) -> io::Result<()> {
    // SAFETY: `fcntl(F_GETFL)` on a live owned fd.
    let flags = unsafe { libc::fcntl(fd.as_raw_fd(), libc::F_GETFL) };
    if flags < 0 {
        return Err(io::Error::last_os_error());
    }
    if flags & libc::O_ACCMODE != libc::O_WRONLY {
        return Err(io::Error::from_raw_os_error(libc::EBADF));
    }
    let mut info = MapInfoPrefix::default();
    let mut attr = ObjGetInfoAttr {
        bpf_fd: fd.as_raw_fd() as u32,
        info_len: size_of::<MapInfoPrefix>() as u32,
        info: std::ptr::addr_of_mut!(info).addr() as u64,
    };
    bpf(
        BPF_OBJ_GET_INFO_BY_FD,
        std::ptr::addr_of_mut!(attr).cast(),
        size_of::<ObjGetInfoAttr>(),
    )?;
    if info.map_type != want_type
        || info.key_size != want_key
        || info.value_size != want_value
        || info.max_entries != want_max
    {
        return Err(io::Error::from_raw_os_error(libc::EINVAL));
    }
    Ok(())
}

impl AnchorMaps {
    /// Wrap the two anchor-map fds (cloned from the loaded object). The
    /// handles are validated: each must be a `WRONLY` fd for a map with
    /// exactly the expected type, key/value sizes, and capacity (checked
    /// via `BPF_OBJ_GET_INFO_BY_FD` plus the fd access mode) — otherwise
    /// a size-mismatched map would turn updates into kernel over-reads of
    /// caller memory. No validation reads of map CONTENTS are possible:
    /// the fds refuse them with `EPERM`.
    pub fn new(hash: OwnedFd, slots: OwnedFd) -> io::Result<Self> {
        validated_map_fd(hash.as_fd(), BPF_MAP_TYPE_HASH, 8, 16, ANCHOR_SLOTS)?;
        validated_map_fd(slots.as_fd(), BPF_MAP_TYPE_ARRAY, 4, 8, ANCHOR_SLOTS)?;
        Ok(Self { hash, slots })
    }

    #[cfg(test)]
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

    #[cfg(test)]
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

    /// Delete `addr` from `anchors`. Absent keys fail with `ENOENT`, which
    /// the caller treats as already clear. Deletion can only clear an
    /// assertion, never manufacture one the target program would trust.
    ///
    /// Test-only interim teardown primitive: the address must come from
    /// the caller's own bookkeeping (never from a kernel read — these fds
    /// refuse reads). W3-2 replaces address-keyed teardown with a
    /// kernel-side slot/generation command that removes the entry without
    /// userspace ever handling an inode address.
    #[cfg(test)]
    pub fn remove(&self, addr: u64) -> io::Result<()> {
        Self::delete(self.hash.as_fd(), &addr.to_ne_bytes())
    }

    /// Record `addr` as slot `slot`'s last-installed address. Mirrors the
    /// program's own bookkeeping for slots userspace tears down directly.
    /// Test-only interim alongside [`AnchorMaps::remove`]: same W3-2
    /// replacement. (Unrestricted bookkeeping must stay out of the
    /// non-test API: clearing a slot cell without clearing its hash
    /// assertion would blind the program's conflict guard to a reinstall.)
    #[cfg(test)]
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

// ---------------------------------------------------------------------------
// Kernel eligibility (D2c §6.1): the deny is a BTF member check of the
// named fix, never a version range. `uname -r` cannot express the floor
// (Debian 12 ships `6.1.0-NN` with a 6.1.1xx base, F0). This module
// therefore scans raw vmlinux BTF itself: aya's `Btf` answers existence
// by name and kind, but exposes no member list, so the `mm` check needs
// the wire format. Pure and unprivileged; every anomaly denies.
// ---------------------------------------------------------------------------

/// Where the running kernel exposes its raw BTF blob.
pub const VMLINUX_BTF_PATH: &str = "/sys/kernel/btf/vmlinux";

/// BTF type-kind numbers (uapi `struct btf_type`: kind in info bits
/// 24..29, vlen in bits 0..16, kind-flag in bit 31). Pinned against
/// `aya_obj::btf::BtfKind` by `btf_kind_consts_match_aya`.
pub const BTF_KIND_STRUCT: u32 = 4;
/// Union kind: named so the wrong-kind test reads as a uapi pin.
pub const BTF_KIND_UNION: u32 = 5;
/// Enum kind (the `pid_fd` fallback witness).
pub const BTF_KIND_ENUM: u32 = 6;
/// Func kind (the `pid_fd` primary witness).
pub const BTF_KIND_FUNC: u32 = 12;

/// The iterator seq-info struct that gained `mm` with the fix (F0).
pub const TASK_VMA_INFO_STRUCT: &str = "bpf_iter_seq_task_vma_info";
/// The member the fix adds: the iterator's own mm reference.
pub const TASK_VMA_INFO_MM_MEMBER: &str = "mm";
/// Parameterized task iterators (v6.1+, F0 row 2): either witness proves
/// `pid_fd` support, the second covering stripped-FUNC BTF.
pub const TASK_ITER_ATTACH_FUNC: &str = "bpf_iter_attach_task";
/// Enum witness for parameterized task iterators (§6.1 item 4).
pub const TASK_ITER_TYPE_ENUM: &str = "bpf_iter_task_type";

/// The named fix, quoted in every `kernel_fix_missing` diagnostic (§7).
pub const MM_FIX_TEXT: &str = "upstream 7ff94f276f8e \"bpf: keep a reference to the mm, in case the task is dead.\" (v6.2; 6.1.8+)";

/// Why raw BTF could not be scanned. Every variant denies (fail closed):
/// an unscannable blob is treated as fix-missing, never as eligible.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum BtfScanError {
    /// Fewer than the 24 header bytes.
    TooShort,
    /// Not a BTF blob (magic `0xE_B9F`).
    BadMagic,
    /// Wrong version, short header length, or incoherent offsets.
    BadHeader,
    /// A claimed region extends past the end of the bytes.
    Truncated,
    /// A name offset escapes the string section or lacks a NUL.
    BadString(u32),
    /// A type kind with no known record layout (carries the kind).
    UnknownKind(u32),
}

impl std::fmt::Display for BtfScanError {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::TooShort => write!(formatter, "BTF shorter than its header"),
            Self::BadMagic => write!(formatter, "not a BTF blob"),
            Self::BadHeader => write!(formatter, "bad BTF header"),
            Self::Truncated => write!(formatter, "BTF region past end of bytes"),
            Self::BadString(offset) => write!(formatter, "bad BTF string at {offset}"),
            Self::UnknownKind(kind) => write!(formatter, "unknown BTF kind {kind}"),
        }
    }
}

impl std::error::Error for BtfScanError {}

/// Selection-time deny reasons (§7). Labels are the published vocabulary;
/// D3d discloses them verbatim in `observation.identity.fallback`.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum KernelDeny {
    /// BTF lacks `bpf_iter_seq_task_vma_info.mm`: 5.15.y and 6.1.0–6.1.7.
    FixMissing,
    /// Neither `pid_fd` witness present: unparameterized task iterators.
    NoTaskIterPidfd,
    /// vmlinux BTF unreadable (carries the path and io error).
    NoBtf(String),
}

impl KernelDeny {
    /// The §7 reason label.
    pub fn label(&self) -> &'static str {
        match self {
            Self::FixMissing => "kernel_fix_missing",
            Self::NoTaskIterPidfd => "no_task_iter_pidfd",
            Self::NoBtf(_) => "no_btf",
        }
    }

    /// The full `"<label>: <detail>"` reason. The fix-missing text names
    /// the upstream commit; no reason mentions release strings.
    pub fn reason(&self) -> String {
        match self {
            Self::FixMissing => format!(
                "kernel_fix_missing: BTF struct {TASK_VMA_INFO_STRUCT} has no member `{TASK_VMA_INFO_MM_MEMBER}` ({MM_FIX_TEXT})"
            ),
            Self::NoTaskIterPidfd => format!(
                "no_task_iter_pidfd: BTF has neither FUNC {TASK_ITER_ATTACH_FUNC} nor ENUM {TASK_ITER_TYPE_ENUM}"
            ),
            Self::NoBtf(detail) => format!("no_btf: {detail}"),
        }
    }
}

impl std::fmt::Display for KernelDeny {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str(&self.reason())
    }
}

impl std::error::Error for KernelDeny {}

const BTF_MAGIC: u16 = 0xE_B9F;
const BTF_HEADER_LEN: usize = 24;

fn btf_u32_at(raw: &[u8], at: usize) -> u32 {
    u32::from_le_bytes(raw[at..at + 4].try_into().unwrap_or([0; 4]))
}

/// Split a raw BTF blob into its type and string sections. vmlinux BTF
/// matches host endianness; this observer is little-endian-only
/// (Linux x86-64-first), so a big-endian blob fails as `BadMagic`.
fn btf_sections(raw: &[u8]) -> Result<(&[u8], &[u8]), BtfScanError> {
    if raw.len() < BTF_HEADER_LEN {
        return Err(BtfScanError::TooShort);
    }
    if u16::from_le_bytes(raw[0..2].try_into().unwrap_or([0; 2])) != BTF_MAGIC {
        return Err(BtfScanError::BadMagic);
    }
    if raw[2] != 1 {
        return Err(BtfScanError::BadHeader);
    }
    let header_len = btf_u32_at(raw, 4) as usize;
    let type_off = btf_u32_at(raw, 8) as usize;
    let type_len = btf_u32_at(raw, 12) as usize;
    let str_off = btf_u32_at(raw, 16) as usize;
    let str_len = btf_u32_at(raw, 20) as usize;
    if header_len < BTF_HEADER_LEN {
        return Err(BtfScanError::BadHeader);
    }
    let types_at = header_len
        .checked_add(type_off)
        .ok_or(BtfScanError::BadHeader)?;
    let types_end = types_at
        .checked_add(type_len)
        .ok_or(BtfScanError::BadHeader)?;
    let strings_at = header_len
        .checked_add(str_off)
        .ok_or(BtfScanError::BadHeader)?;
    let strings_end = strings_at
        .checked_add(str_len)
        .ok_or(BtfScanError::BadHeader)?;
    if types_end > raw.len() || strings_end > raw.len() {
        return Err(BtfScanError::Truncated);
    }
    Ok((&raw[types_at..types_end], &raw[strings_at..strings_end]))
}

/// Resolve a BTF string offset. Offset 0 is the anonymous empty name.
fn btf_string(strings: &[u8], offset: u32) -> Result<&[u8], BtfScanError> {
    let offset = offset as usize;
    if offset >= strings.len() {
        return Err(BtfScanError::BadString(offset as u32));
    }
    let tail = &strings[offset..];
    let end = tail
        .iter()
        .position(|byte| *byte == 0)
        .ok_or(BtfScanError::BadString(offset as u32))?;
    Ok(&tail[..end])
}

/// Extra bytes after a type's 12-byte header, by kind and vlen (uapi
/// `struct btf_array` / `btf_member` / `btf_enum` / `btf_param` /
/// `btf_var` / `btf_var_secinfo` / `btf_enum64`, plus the single-word
/// tails of INT, VAR, and DECL_TAG).
/// Unknown kinds fail: their records cannot be skipped soundly, so the
/// blob cannot prove eligibility.
///
/// DECL_TAG counts 4, not 8: uapi's 8-byte `struct btf_decl_tag`
/// overlays `type` on the common header's third word, leaving only
/// `component_idx` as extra. (An 8-byte count desyncs the walk at the
/// first `bpf_fastcall` tag of a real vmlinux blob — caught by the
/// host-BTF test against an independent python walk.)
fn btf_extra_len(kind: u32, vlen: usize) -> Result<usize, BtfScanError> {
    let scaled = |size: usize| vlen.checked_mul(size).ok_or(BtfScanError::Truncated);
    match kind {
        0 | 2 | 7 | 8 | 9 | 10 | 11 | 12 | 16 | 18 => Ok(0),
        1 | 14 | 17 => Ok(4),
        3 => Ok(12),
        4 | 5 => scaled(12),
        6 => scaled(8),
        13 => scaled(8),
        15 => scaled(12),
        19 => scaled(12),
        unknown => Err(BtfScanError::UnknownKind(unknown)),
    }
}

/// Walk every type in a raw blob. The visitor sees `(kind, name, record,
/// strings)` and returns true to stop early with found.
fn btf_each_type(
    raw: &[u8],
    mut visit: impl FnMut(u32, &[u8], &[u8], &[u8]) -> Result<bool, BtfScanError>,
) -> Result<bool, BtfScanError> {
    let (types, strings) = btf_sections(raw)?;
    let mut at = 0usize;
    while at < types.len() {
        let rest = &types[at..];
        if rest.len() < 12 {
            return Err(BtfScanError::Truncated);
        }
        let name_off = btf_u32_at(rest, 0);
        let info = btf_u32_at(rest, 4);
        let kind = (info >> 24) & 0x1F;
        let vlen = (info & 0xFFFF) as usize;
        let record_len = 12usize
            .checked_add(btf_extra_len(kind, vlen)?)
            .ok_or(BtfScanError::Truncated)?;
        if rest.len() < record_len {
            return Err(BtfScanError::Truncated);
        }
        let name = btf_string(strings, name_off)?;
        if visit(kind, name, &rest[..record_len], strings)? {
            return Ok(true);
        }
        at += record_len;
    }
    Ok(false)
}

/// Whether any STRUCT `struct_name` in raw BTF carries `member`. True
/// only when at least one same-named struct exists AND every same-named
/// struct has the member: same-name distinct-layout types must not let
/// an unpatched shape pass on a patched twin's evidence. (vmlinux BTF is
/// deduplicated, so in practice exactly one struct answers.)
pub fn btf_has_struct_member(
    raw: &[u8],
    struct_name: &str,
    member: &str,
) -> Result<bool, BtfScanError> {
    let mut seen = false;
    let mut missing = false;
    btf_each_type(raw, |kind, name, record, strings| {
        if kind != BTF_KIND_STRUCT || name != struct_name.as_bytes() {
            return Ok(false);
        }
        seen = true;
        let vlen = (btf_u32_at(record, 4) & 0xFFFF) as usize;
        let mut found = false;
        for index in 0..vlen {
            let base = 12 + index * 12;
            let member_name = btf_string(strings, btf_u32_at(record, base))?;
            if member_name == member.as_bytes() {
                found = true;
                break;
            }
        }
        missing |= !found;
        Ok(false)
    })?;
    Ok(seen && !missing)
}

/// Whether any type of `kind` named `name` exists in raw BTF.
pub fn btf_has_named_type(raw: &[u8], kind: u32, name: &str) -> Result<bool, BtfScanError> {
    btf_each_type(raw, |found_kind, found_name, _, _| {
        Ok(found_kind == kind && found_name == name.as_bytes())
    })
}

/// Eligibility items 2–4 (§6.1) over raw BTF bytes: the `mm` fix must be
/// present, plus one `pid_fd` witness. Gated on BTF fields only — never
/// on release strings. An unscannable blob denies as fix-missing.
pub fn check_kernel_identity_btf(raw: &[u8]) -> Result<(), KernelDeny> {
    match btf_has_struct_member(raw, TASK_VMA_INFO_STRUCT, TASK_VMA_INFO_MM_MEMBER) {
        Ok(true) => {}
        Ok(false) | Err(_) => return Err(KernelDeny::FixMissing),
    }
    let attach = btf_has_named_type(raw, BTF_KIND_FUNC, TASK_ITER_ATTACH_FUNC).unwrap_or(false);
    let task_type = btf_has_named_type(raw, BTF_KIND_ENUM, TASK_ITER_TYPE_ENUM).unwrap_or(false);
    if attach || task_type {
        Ok(())
    } else {
        Err(KernelDeny::NoTaskIterPidfd)
    }
}

/// Read the running kernel's raw BTF. Unreadable BTF denies as `no_btf`.
pub fn read_vmlinux_btf() -> Result<Vec<u8>, KernelDeny> {
    std::fs::read(VMLINUX_BTF_PATH)
        .map_err(|error| KernelDeny::NoBtf(format!("{VMLINUX_BTF_PATH}: {error}")))
}

/// Deny before load: read vmlinux BTF and run the §6.1 items 2–4 checks.
/// Callers must run this before any loader or BPF call and refuse on
/// `Err` — the 5.15 guest cell proves the refusal happens with zero
/// `bpf()` syscalls issued. Returns the scanned bytes on success.
pub fn ensure_kernel_identity_btf() -> Result<Vec<u8>, KernelDeny> {
    let raw = read_vmlinux_btf()?;
    check_kernel_identity_btf(&raw)?;
    Ok(raw)
}

// ---------------------------------------------------------------------------
// Anchor arena (§3.3) and functional probe (§6.5).
// ---------------------------------------------------------------------------

/// A slot arena: a `PROT_NONE` anonymous reservation of `slots *
/// ANCHOR_STRIDE` bytes (8 MiB of address space at full cap, no RSS).
/// Slot `i` is the page at `base + i * ANCHOR_STRIDE`, mapped
/// `MAP_FIXED` `PROT_READ` from the held fd; its neighbours stay
/// anonymous `PROT_NONE`, so the anchor VMA can never merge and
/// `vm_start` identifies the slot exactly. `Drop` unmaps the reservation.
pub struct AnchorArena {
    base: u64,
    slots: u32,
}

impl AnchorArena {
    /// Reserve an arena for `slots` anchor pages. Rejects 0 and anything
    /// past `ANCHOR_SLOTS` with `EINVAL` before any mapping.
    pub fn reserve(slots: u32) -> io::Result<Self> {
        if slots == 0 || slots > ANCHOR_SLOTS {
            return Err(io::Error::from_raw_os_error(libc::EINVAL));
        }
        let len = u64::from(slots) * ANCHOR_STRIDE;
        // SAFETY: anonymous reservation (`MAP_NORESERVE`, no fd); `len >
        // 0` and page-aligned by construction.
        let base = unsafe {
            libc::mmap(
                std::ptr::null_mut(),
                len as usize,
                libc::PROT_NONE,
                libc::MAP_PRIVATE | libc::MAP_ANONYMOUS | libc::MAP_NORESERVE,
                -1,
                0,
            )
        };
        if base == libc::MAP_FAILED {
            return Err(io::Error::last_os_error());
        }
        Ok(Self {
            base: base.addr() as u64,
            slots,
        })
    }

    /// Reservation base address (page-aligned).
    pub fn base(&self) -> u64 {
        self.base
    }

    /// Reservation length in bytes (`slots * ANCHOR_STRIDE`).
    pub fn len(&self) -> u64 {
        u64::from(self.slots) * ANCHOR_STRIDE
    }

    /// Whether the arena holds no slots. Always false: `reserve` rejects
    /// 0, but the predicate keeps `len` honest for lints.
    pub fn is_empty(&self) -> bool {
        self.slots == 0
    }

    /// Slot `slot`'s page address, or `None` past the reservation.
    pub fn slot_page(&self, slot: u32) -> Option<u64> {
        if slot >= self.slots {
            return None;
        }
        Some(self.base + u64::from(slot) * ANCHOR_STRIDE)
    }

    /// Map one page `PROT_READ` (never `PROT_EXEC`) at slot `slot` from
    /// offset 0 of `file`, `MAP_FIXED` inside this reservation. Only the
    /// slot page is replaced; the guard neighbours are untouched. The
    /// caller must not assign slots to empty files (D3b policy): the
    /// mapping itself is unopinionated.
    pub fn map_slot(&self, slot: u32, file: BorrowedFd<'_>) -> io::Result<()> {
        let page = self
            .slot_page(slot)
            .ok_or_else(|| io::Error::from_raw_os_error(libc::EINVAL))?;
        // SAFETY: `MAP_FIXED` within our own reservation replaces exactly
        // the slot page; the fd is borrowed live.
        let at = unsafe {
            libc::mmap(
                page as *mut libc::c_void,
                PAGE_GRANULE as usize,
                libc::PROT_READ,
                libc::MAP_PRIVATE | libc::MAP_FIXED,
                file.as_raw_fd(),
                0,
            )
        };
        if at == libc::MAP_FAILED {
            return Err(io::Error::last_os_error());
        }
        Ok(())
    }

    /// Release slot `slot` back to anonymous `PROT_NONE`, rejoining the
    /// reservation. Ordering rule (I1): call only after the last run
    /// that used the slot has been read to END or abandoned.
    pub fn release_slot(&self, slot: u32) -> io::Result<()> {
        let page = self
            .slot_page(slot)
            .ok_or_else(|| io::Error::from_raw_os_error(libc::EINVAL))?;
        // SAFETY: like `map_slot`, restoring the reservation's own shape.
        let at = unsafe {
            libc::mmap(
                page as *mut libc::c_void,
                PAGE_GRANULE as usize,
                libc::PROT_NONE,
                libc::MAP_PRIVATE | libc::MAP_ANONYMOUS | libc::MAP_FIXED | libc::MAP_NORESERVE,
                -1,
                0,
            )
        };
        if at == libc::MAP_FAILED {
            return Err(io::Error::last_os_error());
        }
        Ok(())
    }

    /// The `config[0]` for a pass over this arena: `installed` slots of
    /// this reservation, observed by `observer_tgid`. Validate with
    /// [`validate_arena_config`] before writing (the probe does).
    pub fn config(&self, generation: u64, installed: u32, observer_tgid: u32) -> IdentityConfig {
        IdentityConfig {
            generation,
            arena_base: self.base,
            arena_len: self.len(),
            slots: installed,
            observer_tgid,
        }
    }
}

impl Drop for AnchorArena {
    fn drop(&mut self) {
        // SAFETY: the exact reservation this arena owns. Errors are
        // impossible here (a live private mapping) and ignored in `Drop`
        // by convention.
        unsafe {
            libc::munmap(self.base as *mut libc::c_void, self.len() as usize);
        }
    }
}

/// §6.5 probe files: two distinct files, a hard link to the first, and a
/// byte-identical copy of the first. All paths are canonicalized (the
/// child's maps text is matched against them verbatim).
pub struct ProbeFixture {
    /// First anchored file (slot 0).
    pub a: PathBuf,
    /// Second anchored file (slot 1).
    pub b: PathBuf,
    /// Hard link to `a`: must read back slot 0.
    pub hardlink: PathBuf,
    /// Byte-identical copy of `a` (distinct inode): must read NONE.
    pub copy: PathBuf,
}

/// Write the §6.5 fixture into `dir` (one page per file, deterministic
/// contents) and self-validate the discrimination the probe asserts:
/// the link shares `a`'s inode, the copy shares its bytes but not its
/// inode, and `b` differs in both. Stale `hardlink`/`copy` names from a
/// previous run over a surviving dir are unlinked first, so a rerun can
/// never see a previous run's inodes.
pub fn write_probe_fixture(dir: &Path) -> io::Result<ProbeFixture> {
    let dir = std::fs::canonicalize(dir)?;
    let a_bytes: Vec<u8> = (0..4096u32).map(|i| (i % 251) as u8).collect();
    let b_bytes: Vec<u8> = (0..4096u32).map(|i| ((i % 241) as u8) ^ 0x5A).collect();
    let a = dir.join("probe-a");
    let b = dir.join("probe-b");
    let hardlink = dir.join("probe-a-link");
    let copy = dir.join("probe-a-copy");
    std::fs::write(&a, &a_bytes)?;
    std::fs::write(&b, &b_bytes)?;
    for stale in [&hardlink, &copy] {
        let _ = std::fs::remove_file(stale);
    }
    std::fs::hard_link(&a, &hardlink)?;
    std::fs::write(&copy, &a_bytes)?;
    use std::os::unix::fs::MetadataExt as _;
    let ino = |path: &Path| std::fs::metadata(path).map(|meta| meta.ino());
    let (ino_a, ino_b, ino_link, ino_copy) = (ino(&a)?, ino(&b)?, ino(&hardlink)?, ino(&copy)?);
    let mismatch = |what: &str| io::Error::new(io::ErrorKind::InvalidData, what);
    if ino_a != ino_link {
        return Err(mismatch("probe fixture: hard link left a's inode"));
    }
    if ino_a == ino_b || ino_a == ino_copy {
        return Err(mismatch("probe fixture: distinct files share an inode"));
    }
    if std::fs::read(&copy)? != a_bytes {
        return Err(mismatch("probe fixture: copy diverged from a"));
    }
    if a_bytes == b_bytes {
        return Err(mismatch("probe fixture: a and b are byte-identical"));
    }
    Ok(ProbeFixture {
        a,
        b,
        hardlink,
        copy,
    })
}

/// A forked child that maps each of its paths `PROT_READ|PROT_EXEC`
/// `MAP_PRIVATE`, reports the mapping addresses over a pipe, then pauses
/// until reaped. `Drop` kills (`SIGKILL`) and reaps, so a probe that
/// bails early never leaks a child or a zombie.
pub struct MappedChild {
    pid: u32,
    addrs: Vec<u64>,
    reaped: bool,
}

impl MappedChild {
    /// The child's pid (a group leader in the observer's namespace).
    pub fn pid(&self) -> u32 {
        self.pid
    }

    /// The reported mapping addresses, in path order.
    pub fn addrs(&self) -> &[u64] {
        &self.addrs
    }

    /// Kill (`SIGKILL`) and reap the child. Idempotent; `Drop` calls this
    /// when a probe bails early.
    pub fn reap(&mut self) {
        if self.reaped {
            return;
        }
        self.reaped = true;
        // SAFETY: signal + `waitpid` on our own forked child; `waitpid`
        // retries `EINTR`, and every outcome (including `ECHILD`) ends here.
        unsafe {
            libc::kill(self.pid as libc::pid_t, libc::SIGKILL);
            let mut status = 0;
            loop {
                if libc::waitpid(self.pid as libc::pid_t, &mut status, 0) >= 0 {
                    break;
                }
                if io::Error::last_os_error().raw_os_error() != Some(libc::EINTR) {
                    break;
                }
            }
        }
    }
}

impl Drop for MappedChild {
    fn drop(&mut self) {
        self.reap();
    }
}

/// Fork a child that maps `paths` executable and reports the addresses.
///
/// Fork-safety: the child touches only async-signal-safe calls (`open`,
/// `mmap`, `close`, `write`, `pause`, `_exit`) and read-only inherited
/// memory (the pre-fork `CString`s); it never allocates, never touches a
/// Rust lock, and never returns into the test harness. Failure modes exit
/// 11 (`open`), 12 (`mmap`), or 13 (report), which the parent reads back
/// from the exit status on EOF. The parent reads exactly one address per
/// path: the child either reports all of them or dies first, so the read
/// cannot hang.
pub fn spawn_exec_mapping_child(paths: &[PathBuf]) -> io::Result<MappedChild> {
    if paths.is_empty() {
        return Err(io::Error::from_raw_os_error(libc::EINVAL));
    }
    let cpaths: Vec<std::ffi::CString> = paths
        .iter()
        .map(|path| {
            use std::os::unix::ffi::OsStrExt as _;
            std::ffi::CString::new(path.as_os_str().as_bytes())
                .map_err(|_| io::Error::from_raw_os_error(libc::EINVAL))
        })
        .collect::<Result<_, _>>()?;
    let mut pipe = [0; 2];
    // SAFETY: `pipe` writes two fresh fds on success.
    if unsafe { libc::pipe(pipe.as_mut_ptr()) } != 0 {
        return Err(io::Error::last_os_error());
    }
    // SAFETY: `fork` in a multithreaded parent is sound when the child
    // issues only async-signal-safe calls and `_exit`s (documented above).
    let pid = unsafe { libc::fork() };
    if pid < 0 {
        let error = io::Error::last_os_error();
        unsafe {
            libc::close(pipe[0]);
            libc::close(pipe[1]);
        }
        return Err(error);
    }
    if pid == 0 {
        unsafe {
            libc::close(pipe[0]);
            for cpath in &cpaths {
                // SAFETY: child-only, AS-safe (`open`, `mmap`, `close`).
                let fd = libc::open(cpath.as_ptr(), libc::O_RDONLY);
                if fd < 0 {
                    libc::_exit(11);
                }
                let at = libc::mmap(
                    std::ptr::null_mut(),
                    PAGE_GRANULE as usize,
                    libc::PROT_READ | libc::PROT_EXEC,
                    libc::MAP_PRIVATE,
                    fd,
                    0,
                );
                libc::close(fd);
                if at == libc::MAP_FAILED {
                    libc::_exit(12);
                }
                let bytes = (at.addr() as u64).to_le_bytes();
                let mut wrote = 0;
                while wrote < bytes.len() {
                    // SAFETY: `write` of the live stack bytes.
                    let got =
                        libc::write(pipe[1], bytes[wrote..].as_ptr().cast(), bytes.len() - wrote);
                    if got <= 0 {
                        libc::_exit(13);
                    }
                    wrote += got as usize;
                }
            }
            libc::close(pipe[1]);
            loop {
                libc::pause();
            }
        }
    }
    // SAFETY: parent: the write end belongs to the child now.
    unsafe {
        libc::close(pipe[1]);
    }
    let mut addrs = Vec::with_capacity(paths.len());
    for _ in paths {
        let mut word = [0u8; 8];
        let mut have = 0;
        while have < word.len() {
            // SAFETY: `read` into the live stack buffer.
            let got =
                unsafe { libc::read(pipe[0], word[have..].as_mut_ptr().cast(), word.len() - have) };
            if got == 0 {
                // EOF: the child died before reporting; its exit code
                // names the failed step (11/12/13).
                let mut status = 0;
                unsafe {
                    libc::close(pipe[0]);
                    libc::waitpid(pid, &mut status, 0);
                }
                return Err(io::Error::new(
                    io::ErrorKind::Other,
                    format!("probe child {pid} died before reporting (status {status})"),
                ));
            }
            if got < 0 {
                let error = io::Error::last_os_error();
                if error.raw_os_error() == Some(libc::EINTR) {
                    continue;
                }
                unsafe {
                    libc::close(pipe[0]);
                    libc::kill(pid, libc::SIGKILL);
                    let mut status = 0;
                    libc::waitpid(pid, &mut status, 0);
                }
                return Err(error);
            }
            have += got as usize;
        }
        addrs.push(u64::from_le_bytes(word));
    }
    unsafe {
        libc::close(pipe[0]);
    }
    Ok(MappedChild {
        pid: pid as u32,
        addrs,
        reaped: false,
    })
}

/// Why the functional probe failed: the stage plus the cause. Every stage
/// fails the probe loudly; there is no fallback inside §6.5 (selection
/// falls back to userspace on `probe_failed`, D3d's job).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ProbeError {
    /// Short stage tag (`fixture`, `child`, `arena-config`, `config-map`,
    /// `scope-map`, `link`, `iter`, `read`, `parse-anchor`, `parse-target`,
    /// `join`, ...).
    pub stage: &'static str,
    /// The underlying cause, rendered.
    pub detail: String,
}

impl std::fmt::Display for ProbeError {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            formatter,
            "functional probe {}: {}",
            self.stage, self.detail
        )
    }
}

impl std::error::Error for ProbeError {}

fn probe_io(stage: &'static str, error: io::Error) -> ProbeError {
    ProbeError {
        stage,
        detail: error.to_string(),
    }
}

// SAFETY: `repr(C)`, `Copy`, all-primitive fields: every bit pattern is a
// valid value, so aya may read and write it as map bytes.
unsafe impl aya::Pod for IdentityConfig {}

/// Write `config[0]` on a freshly loaded object.
fn write_probe_config(ebpf: &mut aya::Ebpf, config: &IdentityConfig) -> Result<(), ProbeError> {
    let map = ebpf.map_mut("config").ok_or_else(|| ProbeError {
        stage: "config-map",
        detail: "config map missing from the loaded object".to_owned(),
    })?;
    let mut array =
        aya::maps::Array::<_, IdentityConfig>::try_from(map).map_err(|error| ProbeError {
            stage: "config-cast",
            detail: error.to_string(),
        })?;
    array.set(0, config, 0).map_err(|error| ProbeError {
        stage: "config-write",
        detail: error.to_string(),
    })
}

/// Set exactly `tgids`' bits in the scope bitmap of a freshly loaded
/// object (zero-init, so set == OR). An out-of-bitmap tgid fails loudly:
/// silently dropping a target would forge a "no record" outcome.
fn write_probe_scope(ebpf: &mut aya::Ebpf, tgids: &[u32]) -> Result<(), ProbeError> {
    let mut words = BTreeMap::new();
    for tgid in tgids {
        let (word, bit) = scope_word_bit(*tgid).ok_or_else(|| ProbeError {
            stage: "scope-bit",
            detail: format!("tgid {tgid} past the scope bitmap"),
        })?;
        *words.entry(word as u32).or_insert(0u64) |= bit;
    }
    let map = ebpf.map_mut("scope_bitmap").ok_or_else(|| ProbeError {
        stage: "scope-map",
        detail: "scope_bitmap map missing from the loaded object".to_owned(),
    })?;
    let mut array = aya::maps::Array::<_, u64>::try_from(map).map_err(|error| ProbeError {
        stage: "scope-cast",
        detail: error.to_string(),
    })?;
    for (word, bits) in words {
        array.set(word, bits, 0).map_err(|error| ProbeError {
            stage: "scope-write",
            detail: error.to_string(),
        })?;
    }
    Ok(())
}

/// Open a pidfd for `pid`. A descriptor numbered 0 is re-numbered to ≥1
/// (`F_DUPFD_CLOEXEC`, restoring the closed-stdin state): the link
/// encoder rejects fd 0 rather than risk a silent whole-system walk.
pub fn open_pidfd(pid: u32) -> io::Result<OwnedFd> {
    // SAFETY: `pidfd_open(pid, 0)` returns a new owned fd or -1.
    let raw = unsafe { libc::syscall(libc::SYS_pidfd_open, pid, 0) };
    if raw < 0 {
        return Err(io::Error::last_os_error());
    }
    // SAFETY: the syscall returned a new owned fd.
    let owned = unsafe { OwnedFd::from_raw_fd(raw as i32) };
    if owned.as_raw_fd() != 0 {
        return Ok(owned);
    }
    // SAFETY: `F_DUPFD_CLOEXEC` a live fd to ≥1; `owned` (fd 0) then
    // drops, restoring the closed-stdin state.
    let duped = unsafe { libc::fcntl(0, libc::F_DUPFD_CLOEXEC, 1) };
    if duped < 0 {
        return Err(io::Error::last_os_error());
    }
    // SAFETY: `fcntl` returned a new owned fd.
    Ok(unsafe { OwnedFd::from_raw_fd(duped) })
}

/// Attach `prog_fd` (whole-system, or per-pid on `pid_fd`) and drain one
/// run to EOF under `deadline` and `max_bytes`. The link and iter fds
/// close on drop.
fn attach_and_read_run(
    prog_fd: BorrowedFd<'_>,
    pid_fd: Option<BorrowedFd<'_>>,
    deadline: Instant,
    max_bytes: usize,
) -> Result<Vec<u8>, ProbeError> {
    let link = link_create_task_vma(prog_fd, pid_fd).map_err(|error| probe_io("link", error))?;
    let iter = iter_create(link.as_fd()).map_err(|error| probe_io("iter", error))?;
    read_run(iter.as_fd(), deadline, max_bytes).map_err(|error| ProbeError {
        stage: "read",
        detail: format!("{error:?}"),
    })
}

/// The single executable file range for `path` in a maps text. Exactly
/// one must exist: zero means the mapping is gone (the child died),
/// several means an unexpected merge or split.
fn find_exec_range(maps: &str, path: &Path) -> Result<(u64, u64), ProbeError> {
    let want = path.to_string_lossy();
    let mut hits = Vec::new();
    for line in maps.lines() {
        let mut fields = line.split_whitespace();
        let range = fields.next().unwrap_or("");
        let perms = fields.next().unwrap_or("");
        let tail: Vec<&str> = fields.collect();
        if tail.last() == Some(&want.as_ref()) && perms.as_bytes().get(2) == Some(&b'x') {
            let (start, end) = range.split_once('-').ok_or_else(|| ProbeError {
                stage: "join",
                detail: format!("unparsable maps range for {want}"),
            })?;
            let parse = |hex: &str| {
                u64::from_str_radix(hex, 16).map_err(|_| ProbeError {
                    stage: "join",
                    detail: format!("unparsable maps range for {want}"),
                })
            };
            hits.push((parse(start)?, parse(end)?));
        }
    }
    if hits.len() != 1 {
        return Err(ProbeError {
            stage: "join",
            detail: format!(
                "expected exactly one exec VMA for {want}, found {}",
                hits.len()
            ),
        });
    }
    Ok(hits[0])
}

/// The §6.5 verdicts, as data: callers assert (tests) or print (the
/// `identity_probe` example) — this function never decides pass/fail
/// itself beyond failing loudly on malformed runs.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct FunctionalProbeReport {
    /// The probe child's pid (the only tgid that may emit).
    pub child_pid: u32,
    /// Anchor outcomes by slot, in slot order.
    pub anchor_outcomes: Vec<(u32, AnchorOutcome)>,
    /// Verdict at the hard link's range: `Slot(0)` on success.
    pub hardlink_verdict: TargetVerdict,
    /// Verdict at the second file's range: `Slot(1)` on success.
    pub second_verdict: TargetVerdict,
    /// Verdict at the byte-identical copy's range: `Unmatched` on success.
    pub copy_verdict: TargetVerdict,
    /// Records emitted for the child (3 probe + inherited exec VMAs).
    pub child_record_count: usize,
    /// Of those, the `Unmatched` ones (inherited VMAs + the copy).
    pub child_unmatched_count: usize,
    /// Tgids that emitted, sorted (must be exactly `[child_pid]`).
    pub pids_seen: Vec<u32>,
    /// Pids with conflicting exact-range duplicates (must be empty).
    pub demoted_pids: Vec<u32>,
    /// Whether the stale-generation phase read `Unmatched` at both
    /// anchored ranges (the `gen`-check probe).
    pub stale_unmatched: bool,
}

/// Run the §6.5 functional probe: fixture files, an executable-mapping
/// child, a 2-slot arena (A→0, B→1), a per-pid anchor run on the
/// observer, a whole-system target run over the child, and a
/// stale-generation target phase. `loaded` must be freshly strict-loaded
/// (zeroed maps); `generation` must be in `1..u32::MAX` (the stale phase
/// uses `generation + 1`, and the parser compares low 32 bits). Slots
/// release after the last run is consumed (I1 ordering).
pub fn run_functional_probe(
    dir: &Path,
    loaded: &mut StrictIdentity,
    generation: u64,
) -> Result<FunctionalProbeReport, ProbeError> {
    if generation == 0 || generation >= u64::from(u32::MAX) {
        return Err(ProbeError {
            stage: "generation",
            detail: format!("generation {generation} outside 1..u32::MAX"),
        });
    }
    let fixture = write_probe_fixture(dir).map_err(|error| probe_io("fixture", error))?;
    let mut child = spawn_exec_mapping_child(&[
        fixture.hardlink.clone(),
        fixture.b.clone(),
        fixture.copy.clone(),
    ])
    .map_err(|error| probe_io("child", error))?;
    // Ground truth from the child's maps (robust to merge/split): the
    // exact exec ranges the kernel must report for each probe file.
    let maps = std::fs::read_to_string(format!("/proc/{}/maps", child.pid()))
        .map_err(|error| probe_io("maps", error))?;
    let hardlink_range = find_exec_range(&maps, &fixture.hardlink)?;
    let second_range = find_exec_range(&maps, &fixture.b)?;
    let copy_range = find_exec_range(&maps, &fixture.copy)?;
    // The arena reserves AFTER the fork, so the child never inherits
    // anchor VMAs (they are non-exec and out of scope anyway; this keeps
    // the probe's VMA accounting exact).
    let arena = AnchorArena::reserve(2).map_err(|error| probe_io("arena", error))?;
    let file_a = std::fs::File::open(&fixture.a).map_err(|error| probe_io("anchor-open", error))?;
    let file_b = std::fs::File::open(&fixture.b).map_err(|error| probe_io("anchor-open", error))?;
    arena
        .map_slot(0, file_a.as_fd())
        .map_err(|error| probe_io("anchor-map", error))?;
    arena
        .map_slot(1, file_b.as_fd())
        .map_err(|error| probe_io("anchor-map", error))?;
    let observer = std::process::id();
    let config = arena.config(generation, 2, observer);
    validate_arena_config(&config).map_err(|error| ProbeError {
        stage: "arena-config",
        detail: format!("{error:?}"),
    })?;
    write_probe_config(&mut loaded.ebpf, &config)?;
    write_probe_scope(&mut loaded.ebpf, &[child.pid()])?;
    // Anchor run: ALWAYS per-pid on the observer.
    let pidfd = open_pidfd(observer).map_err(|error| probe_io("pidfd", error))?;
    let anchor_bytes = attach_and_read_run(
        loaded.anchor_fd.as_fd(),
        Some(pidfd.as_fd()),
        Instant::now() + Duration::from_secs(5),
        64 * 1024,
    )?;
    let anchor_run = parse(
        &anchor_bytes,
        &Expect {
            generation,
            slots: 2,
            scope: &BTreeSet::from([observer]),
            mode: RunMode::PerPid,
            run: RunKind::Anchor,
        },
    )
    .map_err(|error| ProbeError {
        stage: "parse-anchor",
        detail: format!("{error:?}"),
    })?;
    let mut anchor_outcomes: Vec<(u32, AnchorOutcome)> = anchor_run.anchors.into_iter().collect();
    anchor_outcomes.sort_by_key(|(slot, _)| *slot);
    // Target run: whole-system, only the child in scope.
    let target_bytes = attach_and_read_run(
        loaded.target_fd.as_fd(),
        None,
        Instant::now() + Duration::from_secs(5),
        64 * 1024,
    )?;
    let target_run = parse(
        &target_bytes,
        &Expect {
            generation,
            slots: 2,
            scope: &BTreeSet::from([child.pid()]),
            mode: RunMode::WholeSystem,
            run: RunKind::Target,
        },
    )
    .map_err(|error| ProbeError {
        stage: "parse-target",
        detail: format!("{error:?}"),
    })?;
    let child_ranges = target_run
        .by_pid
        .get(&child.pid())
        .ok_or_else(|| ProbeError {
            stage: "join",
            detail: format!("child {} emitted no records", child.pid()),
        })?;
    let verdict_at = |range: &(u64, u64)| {
        child_ranges.get(range).copied().ok_or_else(|| ProbeError {
            stage: "join",
            detail: format!("no record at {}-{}", range.0, range.1),
        })
    };
    let hardlink_verdict = verdict_at(&hardlink_range)?;
    let second_verdict = verdict_at(&second_range)?;
    let copy_verdict = verdict_at(&copy_range)?;
    let child_record_count = child_ranges.len();
    let child_unmatched_count = child_ranges
        .values()
        .filter(|verdict| **verdict == TargetVerdict::Unmatched)
        .count();
    let mut pids_seen: Vec<u32> = target_run.by_pid.keys().copied().collect();
    pids_seen.sort();
    let mut demoted_pids: Vec<u32> = target_run.demoted_pids.iter().copied().collect();
    demoted_pids.sort();
    // Stale phase: bump the generation without re-anchoring; every
    // verdict must flip to NONE (the `gen`-check probe).
    let stale_generation = generation + 1;
    write_probe_config(
        &mut loaded.ebpf,
        &IdentityConfig {
            generation: stale_generation,
            ..config
        },
    )?;
    let stale_bytes = attach_and_read_run(
        loaded.target_fd.as_fd(),
        None,
        Instant::now() + Duration::from_secs(5),
        64 * 1024,
    )?;
    let stale_run = parse(
        &stale_bytes,
        &Expect {
            generation: stale_generation,
            slots: 2,
            scope: &BTreeSet::from([child.pid()]),
            mode: RunMode::WholeSystem,
            run: RunKind::Target,
        },
    )
    .map_err(|error| ProbeError {
        stage: "parse-stale",
        detail: format!("{error:?}"),
    })?;
    let stale_ranges = stale_run
        .by_pid
        .get(&child.pid())
        .ok_or_else(|| ProbeError {
            stage: "join",
            detail: format!("child {} emitted no stale records", child.pid()),
        })?;
    let stale_unmatched = [hardlink_range, second_range]
        .iter()
        .all(|range| stale_ranges.get(range) == Some(&TargetVerdict::Unmatched));
    // Release AFTER the last run is consumed (I1 ordering rule).
    arena
        .release_slot(0)
        .map_err(|error| probe_io("anchor-release", error))?;
    arena
        .release_slot(1)
        .map_err(|error| probe_io("anchor-release", error))?;
    child.reap();
    Ok(FunctionalProbeReport {
        child_pid: child.pid(),
        anchor_outcomes,
        hardlink_verdict,
        second_verdict,
        copy_verdict,
        child_record_count,
        child_unmatched_count,
        pids_seen,
        demoted_pids,
        stale_unmatched,
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
        // Slot 99 is outside the 4 installed slots: reported separately.
        assert!(!run.anchors.contains_key(&99));
        assert_eq!(run.outer_bad_shape, BTreeSet::from([99]));
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
        let vma = record(KIND_VMA, 100, 0x1000, 0x2000, 2, 7);
        assert_eq!(vma[24], 0x02);
        let before = parse(&[vma.to_vec(), end(7).to_vec()].concat(), &expect)
            .expect("original verdict parses");
        assert_eq!(
            before
                .by_pid
                .get(&100)
                .and_then(|ranges| ranges.get(&(0x1000, 0x2000))),
            Some(&TargetVerdict::Slot(2))
        );
        let mut flipped = vma;
        flipped[24] = 0x03;
        let after = parse(&[flipped.to_vec(), end(7).to_vec()].concat(), &expect)
            .expect("in-range verdict flip stays valid");
        assert_eq!(
            after
                .by_pid
                .get(&100)
                .and_then(|ranges| ranges.get(&(0x1000, 0x2000))),
            Some(&TargetVerdict::Slot(3))
        );
        assert_ne!(
            before, after,
            "the flip must change the run, not merely stay valid"
        );
        let empty = BTreeSet::new();
        let anchor = anchor_expect(&empty);
        let full = record(KIND_ANCHOR, 0, 0, 0, ANCHOR_FULL, 7);
        assert_eq!(full[24], 0x02);
        let before = parse(&[full.to_vec(), end(7).to_vec()].concat(), &anchor)
            .expect("original FULL parses");
        assert_eq!(before.anchors.get(&0), Some(&AnchorOutcome::Full));
        let mut cleared = full;
        cleared[24] = 0x00;
        let after = parse(&[cleared.to_vec(), end(7).to_vec()].concat(), &anchor)
            .expect("FULL->OK single-bit clear stays valid");
        assert_eq!(after.anchors.get(&0), Some(&AnchorOutcome::Ok));
        assert_ne!(
            before, after,
            "the clear must change the run, not merely stay valid"
        );
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

    /// Out-of-range `BAD_SHAPE` diagnostics must not land in the
    /// valid-slot namespace: with 4 installed slots, a `BAD_SHAPE(99)`
    /// (stale mapping from a wider pass) and a saturated `BAD_SHAPE(MAX)`
    /// (unrepresentable quotient) report separately, and a legitimate
    /// `OK(2)` beside them stays `Ok`.
    #[test]
    fn outer_bad_shape_diagnostics_stay_out_of_slots() {
        let empty = BTreeSet::new();
        let anchor = anchor_expect(&empty);
        let bytes = [
            record(KIND_ANCHOR, 2, 0, 0, ANCHOR_OK, 7).to_vec(),
            record(KIND_ANCHOR, 99, 0, 0, ANCHOR_BAD_SHAPE, 7).to_vec(),
            record(KIND_ANCHOR, u32::MAX, 0, 0, ANCHOR_BAD_SHAPE, 7).to_vec(),
            end(7).to_vec(),
        ]
        .concat();
        let run = parse(&bytes, &anchor).expect("outer diagnostics never fail the run");
        assert_eq!(run.anchors.get(&2), Some(&AnchorOutcome::Ok));
        assert!(
            !run.anchors.contains_key(&99),
            "BAD_SHAPE(99) must not appear as a slot outcome"
        );
        assert!(
            !run.anchors.contains_key(&u32::MAX),
            "saturated diagnostics must not appear as slot outcomes"
        );
        assert_eq!(run.outer_bad_shape, BTreeSet::from([99, u32::MAX]));
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

    /// Independent little-endian decoders for the oracle and the
    /// correspondence check. Deliberately NOT shared with the production
    /// `u16_at`/`u32_at`/`u64_at` above (shift-OR instead of
    /// `from_le_bytes`): a byte-order defect in one implementation cannot
    /// hide inside agreement with the other, and the known-answer test
    /// below pins both against literals.
    fn oracle_u16_at(record: &[u8], at: usize) -> u16 {
        (record[at] as u16) | ((record[at + 1] as u16) << 8)
    }

    fn oracle_u32_at(record: &[u8], at: usize) -> u32 {
        (record[at] as u32)
            | ((record[at + 1] as u32) << 8)
            | ((record[at + 2] as u32) << 16)
            | ((record[at + 3] as u32) << 24)
    }

    fn oracle_u64_at(record: &[u8], at: usize) -> u64 {
        (record[at] as u64)
            | ((record[at + 1] as u64) << 8)
            | ((record[at + 2] as u64) << 16)
            | ((record[at + 3] as u64) << 24)
            | ((record[at + 4] as u64) << 32)
            | ((record[at + 5] as u64) << 40)
            | ((record[at + 6] as u64) << 48)
            | ((record[at + 7] as u64) << 56)
    }

    /// Both decoder implementations agree with known answers: byte order
    /// is pinned against literals, so a byte-swap defect in either one
    /// (the round-2 oracle finding) fails here instead of hiding inside
    /// oracle agreement.
    #[test]
    fn decoders_match_known_answers() {
        let bytes: Vec<u8> = (1u8..=32).collect();
        assert_eq!(u16_at(&bytes, 0), 0x0201);
        assert_eq!(oracle_u16_at(&bytes, 0), 0x0201);
        assert_eq!(u32_at(&bytes, 0), 0x0403_0201);
        assert_eq!(oracle_u32_at(&bytes, 0), 0x0403_0201);
        assert_eq!(u64_at(&bytes, 0), 0x0807_0605_0403_0201);
        assert_eq!(oracle_u64_at(&bytes, 0), 0x0807_0605_0403_0201);
        // The finding's distinguisher: bytes 4/5 (05 06 here) land in the
        // 0x0000_0605_0000_0000 position, never swapped.
        assert_eq!(u64_at(&bytes, 0) & 0xFFFF_0000_0000, 0x0605_0000_0000);
        assert_eq!(
            oracle_u64_at(&bytes, 0) & 0xFFFF_0000_0000,
            0x0605_0000_0000
        );
        // Unaligned offsets too.
        assert_eq!(u32_at(&bytes, 5), 0x0908_0706);
        assert_eq!(oracle_u32_at(&bytes, 5), 0x0908_0706);
        assert_eq!(u64_at(&bytes, 8), 0x100F_0E0D_0C0B_0A09);
        assert_eq!(oracle_u64_at(&bytes, 8), 0x100F_0E0D_0C0B_0A09);
    }

    /// The two decoder implementations agree on random inputs at every
    /// valid offset, so they cannot silently diverge.
    #[test]
    fn decoder_implementations_agree() {
        let mut state = 0x9E37_79B9_7F4A_7C15u64;
        let mut next = move || {
            state ^= state << 13;
            state ^= state >> 7;
            state ^= state << 17;
            state
        };
        for _ in 0..200 {
            let mut bytes = vec![0u8; 32];
            for slot in &mut bytes {
                *slot = (next() & 0xFF) as u8;
            }
            for at in 0..=30 {
                assert_eq!(u16_at(&bytes, at), oracle_u16_at(&bytes, at), "u16 at {at}");
            }
            for at in 0..=28 {
                assert_eq!(u32_at(&bytes, at), oracle_u32_at(&bytes, at), "u32 at {at}");
            }
            for at in 0..=24 {
                assert_eq!(u64_at(&bytes, at), oracle_u64_at(&bytes, at), "u64 at {at}");
            }
        }
    }

    /// Independent oracle: accept/reject re-derived from the contract,
    /// never by calling [`parse`], and decoded with the independent
    /// `oracle_*` readers above — never the production `u*_at` ones.
    /// Every byte-flip and randomized mutation below must agree with it —
    /// that turns "parse compares with itself" into "parse agrees with an
    /// independent decision procedure". (Kept in sync with `parse` by
    /// construction: any rule change must update both, and the agreement
    /// tests fail otherwise.)
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
            || oracle_u32_at(tail, 4) != 0
            || oracle_u64_at(tail, 8) != 0
            || oracle_u64_at(tail, 16) != 0
            || oracle_u32_at(tail, 24) != 0
        {
            return false;
        }
        let want_gen = expect.generation as u32;
        let mut last_tgid: Option<u32> = None;
        let mut only_tgid: Option<u32> = None;
        // In-range anchor outcomes collapse into `anchors`; out-of-range
        // BAD_SHAPE diagnostics report separately (mirrors `parse`).
        let mut raw_anchor: Vec<(u32, AnchorOutcome)> = Vec::new();
        for index in 0..records {
            let record = &bytes[index * RECORD_LEN..(index + 1) * RECORD_LEN];
            if oracle_u16_at(record, 0) != RECORD_MAGIC || record[2] != RECORD_VERSION {
                return false;
            }
            if oracle_u32_at(record, 28) != want_gen {
                return false;
            }
            let a = oracle_u32_at(record, 4);
            let start = oracle_u64_at(record, 8);
            let end = oracle_u64_at(record, 16);
            let verdict = oracle_u32_at(record, 24);
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
                        Some(mapped) => {
                            // Out-of-range shape diagnostics bypass the
                            // slot namespace exactly like `parse` routes.
                            if mapped != AnchorOutcome::BadShape || a < expect.slots {
                                raw_anchor.push((a, mapped));
                            }
                        }
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
    /// conflicts, and nothing is invented. Never calls [`parse`], and
    /// decodes with the independent `oracle_*` readers (so a production
    /// decoder defect shows up as parsed-vs-raw mismatch, not agreement).
    fn assert_run_matches_bytes(bytes: &[u8], expect: &Expect, run: &Run) {
        let records = bytes.len() / RECORD_LEN;
        let mut raw_vma: Vec<(u32, u64, u64, TargetVerdict)> = Vec::new();
        let mut raw_anchor: Vec<(u32, AnchorOutcome)> = Vec::new();
        for index in 0..records {
            let record = &bytes[index * RECORD_LEN..(index + 1) * RECORD_LEN];
            let a = oracle_u32_at(record, 4);
            let start = oracle_u64_at(record, 8);
            let end = oracle_u64_at(record, 16);
            let verdict = oracle_u32_at(record, 24);
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
                assert!(
                    run.outer_bad_shape.is_empty(),
                    "target runs carry no anchor diagnostics"
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
                let mut in_range = Vec::new();
                let mut outer = BTreeSet::new();
                for (slot, outcome) in &raw_anchor {
                    if *outcome == AnchorOutcome::BadShape && *slot >= expect.slots {
                        outer.insert(*slot);
                    } else {
                        in_range.push((*slot, *outcome));
                    }
                }
                let expected = oracle_collapsed_anchors(&in_range)
                    .expect("accepted runs collapse and resolve");
                assert_eq!(
                    run.anchors, expected,
                    "parsed anchors must equal collapsed+resolved raw outcomes"
                );
                assert_eq!(
                    run.outer_bad_shape, outer,
                    "parsed outer diagnostics must match out-of-range raw records"
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
        assert_eq!(BPF_MAP_CREATE, 0);
        assert_eq!(BPF_MAP_UPDATE_ELEM, 2);
        assert_eq!(BPF_MAP_DELETE_ELEM, 3);
        assert_eq!(BPF_OBJ_GET_INFO_BY_FD, 15);
        assert_eq!(BPF_MAP_TYPE_HASH, 1);
        assert_eq!(BPF_MAP_TYPE_ARRAY, 2);
        assert_eq!(BPF_TRACE_ITER, 28);
        assert_eq!(BPF_F_WRONLY, 16);
        assert_eq!(BPF_F_MMAPABLE, 1024);
        assert_eq!(size_of::<LinkCreateAttr>(), 32);
        assert_eq!(offset_of!(LinkCreateAttr, iter_info), 16);
        assert_eq!(offset_of!(LinkCreateAttr, iter_info_len), 24);
        assert_eq!(size_of::<IterCreateAttr>(), 8);
        assert_eq!(size_of::<MapElemAttr>(), 32);
        assert_eq!(offset_of!(MapElemAttr, key), 8);
        assert_eq!(offset_of!(MapElemAttr, value), 16);
        assert_eq!(offset_of!(MapElemAttr, flags), 24);
        assert_eq!(size_of::<ObjGetInfoAttr>(), 16);
        assert_eq!(offset_of!(ObjGetInfoAttr, bpf_fd), 0);
        assert_eq!(offset_of!(ObjGetInfoAttr, info_len), 4);
        assert_eq!(offset_of!(ObjGetInfoAttr, info), 8);
        assert_eq!(size_of::<MapInfoPrefix>(), 24);
        assert_eq!(offset_of!(MapInfoPrefix, key_size), 8);
        assert_eq!(offset_of!(MapInfoPrefix, value_size), 12);
        assert_eq!(offset_of!(MapInfoPrefix, max_entries), 16);
        assert_eq!(offset_of!(MapInfoPrefix, map_flags), 20);
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
        assert_eq!(dec("P11_IDENT_ANCHOR_STRIDE"), ANCHOR_STRIDE);
        assert_eq!(dec("P11_IDENT_PAGE"), PAGE_GRANULE);
        assert_eq!(dec("P11_IDENT_SCOPE_WORDS"), SCOPE_WORDS as u64);
        assert_eq!(dec("P11_IDENT_F_WRONLY"), 16);
        assert_eq!(dec("P11_IDENT_F_MMAPABLE"), 1024);
    }

    /// Structural I6: `AnchorMaps` implements no leak trait — no
    /// `Debug`, no `Display`, no `Serialize`, however derived, manual, or
    /// renamed. Ambiguity-based negative assertions: if the handle
    /// implemented the probed trait, both impls below would apply and this
    /// function would fail to compile. (Liveness is proven by experiment:
    /// adding any of these impls breaks the build; see the round-1 report.)
    #[test]
    fn anchor_maps_implements_no_leak_traits() {
        struct Probe;
        trait AmbiguousIfDebug<T> {
            fn probe() {}
        }
        impl<T: ?Sized> AmbiguousIfDebug<()> for T {}
        impl<T: ?Sized + std::fmt::Debug> AmbiguousIfDebug<Probe> for T {}
        <AnchorMaps as AmbiguousIfDebug<_>>::probe();

        trait AmbiguousIfDisplay<T> {
            fn probe() {}
        }
        impl<T: ?Sized> AmbiguousIfDisplay<()> for T {}
        impl<T: ?Sized + std::fmt::Display> AmbiguousIfDisplay<Probe> for T {}
        <AnchorMaps as AmbiguousIfDisplay<_>>::probe();

        trait AmbiguousIfSerialize<T> {
            fn probe() {}
        }
        impl<T: ?Sized> AmbiguousIfSerialize<()> for T {}
        impl<T: ?Sized + serde::Serialize> AmbiguousIfSerialize<Probe> for T {}
        <AnchorMaps as AmbiguousIfSerialize<_>>::probe();
    }

    /// Whether `text` mentions `word` as a whole C identifier — `addr`
    /// matches `addr` and `*addr`, never `my_addr`.
    fn mentions_word(text: &str, word: &str) -> bool {
        let mut rest = text;
        while let Some(found) = rest.find(word) {
            let boundary =
                |side: Option<char>| side.is_none_or(|c| !(c.is_alphanumeric() || c == '_'));
            let before = rest[..found].chars().next_back();
            let after = rest[found + word.len()..].chars().next();
            if boundary(before) && boundary(after) {
                return true;
            }
            rest = &rest[found + word.len()..];
        }
        false
    }

    /// Byte index of a plain or compound `=` assignment in `code` (`=`,
    /// `+=`, `<<=` … count; `==`, `!=`, `<=`, `>=` never do), or `None`.
    /// `<<=`/`>>=` assign (the `=` follows a second shift chevron);
    /// `<=`/`>=` compare.
    fn find_assignment(code: &str) -> Option<usize> {
        let bytes = code.as_bytes();
        let mut index = 0;
        while index < bytes.len() {
            if bytes[index] == b'=' {
                let prev = if index > 0 { bytes[index - 1] } else { b' ' };
                let prev_prev = if index > 1 { bytes[index - 2] } else { b' ' };
                let next = bytes.get(index + 1).copied().unwrap_or(b' ');
                if next == b'=' || prev == b'=' || prev == b'!' {
                    // `==`, `!=`: never an assignment.
                } else if prev == b'<' || prev == b'>' {
                    // `<<=` / `>>=` assign; `<=` / `>=` compare.
                    if prev_prev == prev {
                        return Some(index);
                    }
                } else {
                    return Some(index);
                }
            }
            index += 1;
        }
        None
    }

    /// Remove `&ident` (address-of) tokens from `expr`, never binary
    /// `&` (bitwise and) or `&&` (logical and):
    /// `p11_map_lookup(&anchors, &addr)` passes stack pointers as keys,
    /// not the inode address itself, so the result is not inode-derived
    /// — while `~0ULL & addr` computes with the address and stays
    /// tainted. A `&` is address-of only in unary position (expression
    /// start, or after `(`, `,`, `=`, or another operator — never after
    /// an operand: identifier, number, `)`, `]`, a second `&`, or a
    /// postfix `++`/`--`), with an identifier after it (whitespace
    /// allowed).
    fn strip_address_of(expr: &str) -> String {
        let chars: Vec<char> = expr.chars().collect();
        let mut out = String::with_capacity(expr.len());
        let mut index = 0;
        while index < chars.len() {
            if chars[index] == '&' && chars.get(index + 1) != Some(&'&') {
                let mut back = index;
                while back > 0 && chars[back - 1].is_whitespace() {
                    back -= 1;
                }
                let prev = if back > 0 {
                    Some(chars[back - 1])
                } else {
                    None
                };
                // A trailing `++`/`--` is a postfix operand (`mask-- &
                // addr` computes with the address), never a unary slot.
                let postfix = prev.is_some_and(|c| {
                    (c == '+' || c == '-')
                        && back
                            .checked_sub(2)
                            .and_then(|at| chars.get(at))
                            .is_some_and(|before| *before == c)
                });
                let unary = !postfix
                    && prev.is_none_or(|c| {
                        !(c.is_alphanumeric() || c == '_' || c == ')' || c == ']' || c == '&')
                    });
                let mut fwd = index + 1;
                while fwd < chars.len() && chars[fwd].is_whitespace() {
                    fwd += 1;
                }
                let next_ident = chars
                    .get(fwd)
                    .is_some_and(|c| c.is_alphabetic() || *c == '_');
                if unary && next_ident {
                    let mut end = fwd + 1;
                    while end < chars.len() && (chars[end].is_alphanumeric() || chars[end] == '_') {
                        end += 1;
                    }
                    index = end;
                    out.push(' ');
                    continue;
                }
            }
            out.push(chars[index]);
            index += 1;
        }
        out
    }

    fn expr_is_tainted(expr: &str, tainted: &BTreeSet<String>) -> bool {
        let value = strip_address_of(expr);
        tainted.iter().any(|var| mentions_word(&value, var))
    }

    /// Strip C block comments (`/*…*/`, multi-line aware), line comments
    /// (`//…`), and string/char literal contents from `text`, blanking
    /// them to spaces (newlines kept) so byte offsets and line numbers
    /// survive. What remains is code shape. A single lexer pass keeps
    /// comment markers inside strings (and vice versa) from confusing
    /// each other. C block comments do not nest. A char literal keeps a
    /// `0` placeholder operand (same length): without it `-'x' & addr`
    /// would blank into a false unary-`&` shape and lose its taint.
    /// Before all of that, translation phase 2 runs file-wide: a
    /// backslash immediately before a newline is deleted (operands,
    /// comments, and strings alike), so `mask-\<newline>-` reads as
    /// the `mask--` operand the compiler sees. Spliced lines merge --
    /// line numbers past a splice differ from the raw text, exactly as
    /// they do for the compiler.
    fn strip_c_noise(text: &str) -> String {
        let spliced = text.replace("\\\r\n", "").replace("\\\n", "");
        let bytes = spliced.as_bytes();
        let mut out = Vec::with_capacity(bytes.len());
        let mut index = 0;
        while index < bytes.len() {
            let byte = bytes[index];
            let next = bytes.get(index + 1).copied().unwrap_or(0);
            if byte == b'/' && next == b'/' {
                while index < bytes.len() && bytes[index] != b'\n' {
                    out.push(b' ');
                    index += 1;
                }
                continue;
            }
            if byte == b'/' && next == b'*' {
                out.push(b' ');
                out.push(b' ');
                index += 2;
                while index < bytes.len()
                    && !(bytes[index] == b'*' && bytes.get(index + 1) == Some(&b'/'))
                {
                    out.push(if bytes[index] == b'\n' { b'\n' } else { b' ' });
                    index += 1;
                }
                if index < bytes.len() {
                    out.push(b' ');
                    out.push(b' ');
                    index += 2;
                }
                continue;
            }
            if byte == b'"' || byte == b'\'' {
                let quote = byte;
                // A char literal is an operand: keep a `0` placeholder
                // so neighbors still read operand-shaped after blanking.
                out.push(if quote == b'\'' { b'0' } else { b' ' });
                index += 1;
                while index < bytes.len() && bytes[index] != quote {
                    if bytes[index] == b'\\' {
                        out.push(b' ');
                        index += 1;
                        if index < bytes.len() {
                            out.push(if bytes[index] == b'\n' { b'\n' } else { b' ' });
                            index += 1;
                        }
                        continue;
                    }
                    out.push(if bytes[index] == b'\n' { b'\n' } else { b' ' });
                    index += 1;
                }
                if index < bytes.len() {
                    out.push(b' ');
                    index += 1;
                }
                continue;
            }
            out.push(byte);
            index += 1;
        }
        String::from_utf8(out).expect("blanking keeps UTF-8 boundaries")
    }

    /// Whether `name` is a plain C variable name (no operators, no member
    /// access, no dereference).
    fn is_plain_c_var(name: &str) -> bool {
        !name.is_empty() && name.chars().all(|c| c.is_alphanumeric() || c == '_')
    }

    /// Strip one fully-wrapping paren pair from `text` (`(x)` → `x`,
    /// `((x))` → `(x)`), or return it unchanged. Only strips when the
    /// open paren at index 0 matches the final close — `(a) + (b)`
    /// stays put. Callers loop for nested pairs.
    fn strip_wrapping_parens(text: &str) -> &str {
        let bytes = text.as_bytes();
        if bytes.first() != Some(&b'(') || bytes.last() != Some(&b')') {
            return text;
        }
        let mut depth = 0i32;
        for (offset, byte) in bytes.iter().enumerate() {
            match byte {
                b'(' => depth += 1,
                b')' => {
                    depth -= 1;
                    if depth == 0 {
                        return if offset == bytes.len() - 1 {
                            &text[1..bytes.len() - 1]
                        } else {
                            text
                        };
                    }
                }
                _ => {}
            }
        }
        text
    }

    /// Audit one C function body: no `emit(...)` argument (checked at its
    /// call site, against the taint set at that point) carries an
    /// inode-derived value, and no `record.<field>` store takes one.
    /// Taint sources (sticky, never cleared): `addr` (the inode pointer),
    /// `old` (the slot cell's stored address), `f_inode` (the inode field
    /// itself). Transfers (assignments across intermediates, `P11_READ`
    /// as `dst = src`) and emit checks run in chunk-offset order over
    /// `;`-separated statements, so same-line (`start = addr;
    /// emit(...)`) and split-line (`start =` / `addr;`) layouts taint
    /// before the check; plain `=` with a clean rhs clears non-source
    /// variables, whose value was replaced, while compound `<op>=` keeps
    /// taint when either side is tainted (it reads the old value).
    /// Through-deref stores (`*p = …`, including paren-wrapped
    /// `(*p)` / `*(...)` and unbraced-control-prefixed `if (...) *p`
    /// spellings) of tainted values fail unless the statement is the
    /// exact bookkeeping allowlist (`*slot_cell = addr`); `record.*`
    /// stores (bare or paren-wrapped) feed `seq_write` and are
    /// checked; `p.f`, `p->f`, `a[i]` stores stay map/struct writes
    /// outside the envelope (with wrapper functions and
    /// inter-procedural flows -- all pin-backstopped; see the test
    /// docs).
    fn audit_c_chunk(chunk: &str, path: &str) -> Result<(), String> {
        const SOURCES: [&str; 3] = ["addr", "old", "f_inode"];
        // The only through-deref store of a tainted value the audit
        // allows, exactly: `*slot_cell = addr` installs the slot's
        // observed address into the kernel map (never into a record).
        // Compared on trimmed statement text — reformatting the line
        // fails loudly.
        const DEREF_ALLOWLIST: [&str; 1] = ["*slot_cell = addr"];
        let clean = strip_c_noise(chunk);
        let bytes = clean.as_bytes();
        // Every `emit(` call's byte range and argument text, balanced
        // across wrapped lines. (The `emit` definition itself matches
        // too; its parameter list carries no tainted value.)
        let mut calls: Vec<(usize, usize, String)> = Vec::new();
        let mut at = 0;
        while let Some(found) = clean[at..].find("emit(") {
            let start = at + found;
            let mut depth = 0usize;
            let mut end = None;
            for (offset, byte) in bytes[start..].iter().enumerate() {
                match byte {
                    b'(' => depth += 1,
                    b')' => {
                        depth -= 1;
                        if depth == 0 {
                            end = Some(start + offset);
                            break;
                        }
                    }
                    _ => {}
                }
            }
            let Some(close) = end else {
                return Err(format!("{path}: unbalanced emit( in chunk"));
            };
            calls.push((start, close, clean[start..=close].to_string()));
            at = close + 1;
        }
        let in_call = |offset: usize| calls.iter().any(|(s, e, _)| offset > *s && offset < *e);
        // Statements at paren-depth-0 `;` (a `for (;;)` header never
        // splits), each with its chunk offset.
        let mut statements: Vec<(usize, &str)> = Vec::new();
        let mut depth = 0i32;
        let mut stmt_start = 0;
        for (offset, byte) in bytes.iter().enumerate() {
            match byte {
                b'(' => depth += 1,
                b')' => depth = depth.saturating_sub(1),
                b';' if depth == 0 => {
                    statements.push((stmt_start, &clean[stmt_start..offset]));
                    stmt_start = offset + 1;
                }
                _ => {}
            }
        }
        statements.push((stmt_start, &clean[stmt_start..]));
        enum Event {
            Read {
                offset: usize,
                dst: String,
                src: String,
            },
            Assign {
                offset: usize,
                lhs: String,
                rhs: String,
                stmt: String,
            },
            Emit {
                offset: usize,
                args: String,
            },
        }
        let offset_of = |event: &Event| match event {
            Event::Read { offset, .. }
            | Event::Assign { offset, .. }
            | Event::Emit { offset, .. } => *offset,
        };
        let mut events: Vec<Event> = Vec::new();
        for (start, _, args) in &calls {
            events.push(Event::Emit {
                offset: *start,
                args: args.clone(),
            });
        }
        for (stmt_start, text) in &statements {
            let mut rest = *text;
            let mut rest_off = *stmt_start;
            while let Some(found) = rest.find("P11_READ(") {
                // Balance from the call's open paren; split dst/src at
                // the first top-level comma.
                let call_off = rest_off + found;
                let mut paren = 0i32;
                let mut comma = None;
                let mut close = None;
                for (offset, byte) in rest[found..].bytes().enumerate() {
                    match byte {
                        b'(' => paren += 1,
                        b',' if paren == 1 && comma.is_none() => comma = Some(found + offset),
                        b')' => {
                            paren -= 1;
                            if paren == 0 {
                                close = Some(found + offset);
                                break;
                            }
                        }
                        _ => {}
                    }
                }
                let (Some(comma), Some(close)) = (comma, close) else {
                    return Err(format!("{path}: unbalanced P11_READ( in chunk"));
                };
                if !in_call(call_off) {
                    events.push(Event::Read {
                        offset: call_off,
                        dst: rest[found + "P11_READ(".len()..comma].to_string(),
                        src: rest[comma + 1..close].to_string(),
                    });
                }
                rest = &rest[close + 1..];
                rest_off += close + 1;
            }
            // Assignments, first `=` per fragment (chained `x = y = …`
            // fragments recurse so every target transfers).
            let mut frag = *text;
            let mut frag_off = *stmt_start;
            while let Some(eq) = find_assignment(frag) {
                let (lhs, rhs) = frag.split_at(eq);
                let rhs = &rhs[1..];
                let eq_off = frag_off + eq;
                if !in_call(eq_off) {
                    events.push(Event::Assign {
                        offset: eq_off,
                        lhs: lhs.to_string(),
                        rhs: rhs.to_string(),
                        stmt: text.trim().to_string(),
                    });
                }
                frag = rhs;
                frag_off = eq_off + 1;
            }
        }
        events.sort_by_key(offset_of);
        let mut tainted: BTreeSet<String> = SOURCES.iter().map(|name| name.to_string()).collect();
        for event in events {
            match event {
                Event::Emit { args, .. } => {
                    for forbidden in ["addr", "inode"] {
                        if args.contains(forbidden) {
                            return Err(format!(
                                "{path}: emit(...) argument names {forbidden:?}: {args}"
                            ));
                        }
                    }
                    for var in &tainted {
                        if mentions_word(&args, var) {
                            return Err(format!(
                                "{path}: emit(...) argument carries tainted {var:?}: {args}"
                            ));
                        }
                    }
                }
                Event::Read { dst, src, .. } => {
                    let dst = dst.trim();
                    if !is_plain_c_var(dst) {
                        continue;
                    }
                    if expr_is_tainted(&src, &tainted) {
                        tainted.insert(dst.to_string());
                    } else if !SOURCES.contains(&dst) {
                        tainted.remove(dst);
                    }
                }
                Event::Assign { lhs, rhs, stmt, .. } => {
                    // The assignment target: text after the last
                    // structural character (a statement can open with
                    // `}`/`{` from control flow before its assignment,
                    // e.g. `}\n *slot_cell = addr`), with fully-wrapping
                    // paren pairs stripped — `(record.start)`,
                    // `(*pp)`, and `(start)` audit exactly like the
                    // bare spellings instead of vanishing into an
                    // empty target. Never split on parens: that
                    // erased every wrapped lhs before the sink
                    // checks.
                    // Split off control-flow/call prefixes: `{`, `}`, and
                    // `,` always cut; `(` cuts only when it never closes
                    // inside the lhs (`if (x = …`) — a balanced wrap
                    // (`(record.start)`) stays for unwrapping below.
                    let lhs_bytes = lhs.as_bytes();
                    let mut cut = 0;
                    let mut opens: Vec<usize> = Vec::new();
                    for (index, byte) in lhs_bytes.iter().enumerate() {
                        match byte {
                            b'{' | b'}' | b',' => {
                                cut = index + 1;
                                opens.clear();
                            }
                            b'(' => opens.push(index),
                            b')' => {
                                opens.pop();
                            }
                            _ => {}
                        }
                    }
                    if let Some(unmatched) = opens.last() {
                        cut = cut.max(unmatched + 1);
                    }
                    // A balanced `(...)` group that opens away from the cut
                    // after a condition/call suffix (`if (1)start`,
                    // `if (ok) *pp`) is a control-flow prefix, not the
                    // target: cut after its close, or the prefix either
                    // glues onto the name or trips the `*`-skip below and
                    // the store vanishes. Wraps (`(` AT the cut),
                    // deref operands (`(` after `*`), and anything else
                    // keep their existing handling.
                    // Whether the loop below cut a control-flow prefix:
                    // a store under unbraced `if` may never execute, so
                    // it propagates taint but never kills it (breaker
                    // micro-fix B3b). Braced kills cut at `{`/`}` above
                    // and never set this flag.
                    let mut prefix_cut = false;
                    loop {
                        let rest = &lhs[cut..];
                        let stripped = rest.trim_start();
                        let Some(first) = stripped.as_bytes().first() else {
                            break;
                        };
                        if *first == b'(' {
                            break;
                        }
                        let base = cut + (rest.len() - stripped.len());
                        let Some(rel) = lhs[base..].find('(') else {
                            break;
                        };
                        let open = base + rel;
                        let suffix = lhs[..open].trim_end().chars().next_back();
                        let is_suffix = suffix.is_some_and(|c| {
                            c.is_alphanumeric() || c == '_' || c == ']' || c == ')'
                        });
                        if !is_suffix {
                            break;
                        }
                        let mut depth = 1i32;
                        let mut close = None;
                        for (offset, byte) in lhs.as_bytes()[open + 1..].iter().enumerate() {
                            match byte {
                                b'(' => depth += 1,
                                b')' => {
                                    depth -= 1;
                                    if depth == 0 {
                                        close = Some(open + 1 + offset);
                                        break;
                                    }
                                }
                                _ => {}
                            }
                        }
                        let Some(close) = close else { break };
                        // A call-in-deref target (`*f() = addr`) ends at
                        // the close: only a control-flow prefix has a
                        // target after it, so cut only when non-whitespace
                        // follows (breaker micro-fix B1).
                        if lhs[close + 1..].trim_start().is_empty() {
                            break;
                        }
                        cut = close + 1;
                        prefix_cut = true;
                    }
                    let core = lhs[cut..].trim();
                    let mut unwrapped = strip_wrapping_parens(core);
                    loop {
                        let narrower = strip_wrapping_parens(unwrapped.trim());
                        if narrower.len() == unwrapped.trim().len() {
                            break;
                        }
                        unwrapped = narrower;
                    }
                    let deop = unwrapped
                        .trim_end_matches(['+', '-', '*', '/', '%', '&', '|', '^', '<', '>'])
                        .trim();
                    let compound = deop != unwrapped.trim();
                    // A compound operator sits outside the parens
                    // (`(x) += …`): unwrap once more past it.
                    let mut target = strip_wrapping_parens(deop);
                    loop {
                        let narrower = strip_wrapping_parens(target.trim());
                        if narrower.len() == target.trim().len() {
                            break;
                        }
                        target = narrower;
                    }
                    let target = target.trim();
                    if target.contains("record.") || target.contains("record->") {
                        if expr_is_tainted(&rhs, &tainted) {
                            return Err(format!(
                                "{path}: record field store of tainted value: {stmt}"
                            ));
                        }
                        continue;
                    }
                    if target.starts_with('*') {
                        let stmt_core = stmt.rsplit(['{', '}']).next().unwrap_or(&stmt).trim();
                        if expr_is_tainted(&rhs, &tainted) && !DEREF_ALLOWLIST.contains(&stmt_core)
                        {
                            return Err(format!(
                                "{path}: through-deref store of tainted value: {stmt}"
                            ));
                        }
                        continue;
                    }
                    if target.contains(['*', '.', '[']) || target.contains("->") {
                        continue;
                    }
                    let Some(name) = target.split_whitespace().next_back() else {
                        continue;
                    };
                    if !is_plain_c_var(name) {
                        continue;
                    }
                    let rhs_tainted = expr_is_tainted(&rhs, &tainted);
                    if compound {
                        if rhs_tainted || tainted.contains(name) {
                            tainted.insert(name.to_string());
                        } else if !SOURCES.contains(&name) {
                            tainted.remove(name);
                        }
                    } else if rhs_tainted {
                        tainted.insert(name.to_string());
                    } else if !SOURCES.contains(&name) && !prefix_cut {
                        tainted.remove(name);
                    }
                }
            }
        }
        Ok(())
    }

    /// Audit one identity C source for record-leak shape, per function:
    /// every `seq_write` call passes the ABI record struct, and no
    /// `emit(...)` argument carries an inode-derived value — tracked by a
    /// taint analysis over assignments ([`audit_c_chunk`]), so `start =
    /// addr` before an `emit(..., start, ...)` fails even though the
    /// argument text is clean. Returns the rejection reason instead of
    /// panicking so mutation proofs can assert rejection. The analysis is
    /// intra-procedural and alias-insensitive by design; the object digest
    /// pin stays as the complementary tripwire for anything it cannot see.
    fn audit_identity_c_source(source: &str, path: &str) -> Result<(), String> {
        // Comment/string-blind throughout: braces and `seq_write` tokens
        // inside comments or literals must shape neither the chunking
        // nor the checks.
        let clean = strip_c_noise(source);
        for (number, line) in clean.lines().enumerate() {
            if line.contains("seq_write(seq") && !line.contains("&record") {
                return Err(format!("{path}:{} seq_write must pass &record", number + 1));
            }
        }
        // Per-function chunks at top-level closing braces, so taint never
        // leaks across functions (C nests no functions; maps and structs
        // close with `};`).
        let mut chunks: Vec<String> = Vec::new();
        let mut current = String::new();
        for line in clean.lines() {
            current.push_str(line);
            current.push('\n');
            if line == "}" {
                chunks.push(std::mem::take(&mut current));
            }
        }
        chunks.push(current);
        for chunk in &chunks {
            audit_c_chunk(chunk, path)?;
        }
        Ok(())
    }

    /// The kernel never receives an inode address in a record struct
    /// through an audited flow: the record fields are exactly the ABI
    /// names, `seq_write` passes `&record`, and no `emit(...)` argument
    /// smuggles an inode-derived value into an existing record field —
    /// directly, renamed through an assignment (`start = addr`) the
    /// argument text hides, laundered through a compound assignment,
    /// laid out across a line break, computed with binary `&`, or
    /// stored through a dereference. Producer mutations (an inode
    /// address into `start`, into the DUP alias field, through a
    /// pre-emit assignment, through an intermediate, through each
    /// compound operator, same-line, split-line, binary-`&`, and
    /// through-deref) must fail the audit — proven by mutating the
    /// real sources in memory. Outside the envelope by design, and
    /// backstopped by the object digest pin instead (any such source
    /// change trips `identity_object_digest_pinned`): inter-procedural
    /// flows (wrapper functions), `p->f`/`p.f`/`a[i]` and
    /// pointer-declaration aliasing, `memcpy`-style block copies, and
    /// `&(`-forms.
    #[test]
    fn kernel_records_carry_no_inode_addresses_in_audited_flows() {
        let root = std::path::Path::new(env!("CARGO_MANIFEST_DIR"));
        for path in [
            "crates/ebpf/native/vma_identity.h",
            "crates/ebpf/native/vma_identity.c",
        ] {
            let source = std::fs::read_to_string(root.join(path)).expect("read C source");
            audit_identity_c_source(&source, path).expect("real sources pass the audit");
        }
        // The record struct's fields are exactly the ABI names.
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
        // Producer mutation 1: the inode address into `start`.
        let path = "crates/ebpf/native/vma_identity.c";
        let c = std::fs::read_to_string(root.join(path)).expect("read C source");
        let mutated = c.replacen(
            "emit(ctx, P11_IDENT_KIND_VMA, tgid_u, start, end, verdict,",
            "emit(ctx, P11_IDENT_KIND_VMA, tgid_u, addr, end, verdict,",
            1,
        );
        assert_ne!(mutated, c, "mutation 1 must apply");
        assert!(
            audit_identity_c_source(&mutated, path).is_err(),
            "mutation 1 (addr into start) must fail the audit"
        );
        // Producer mutation 2: the inode address into the DUP alias field.
        let mutated = c.replacen(
            "emit(ctx, P11_IDENT_KIND_ANCHOR, slot, found->slot, 0,",
            "emit(ctx, P11_IDENT_KIND_ANCHOR, slot, addr, 0,",
            1,
        );
        assert_ne!(mutated, c, "mutation 2 must apply");
        assert!(
            audit_identity_c_source(&mutated, path).is_err(),
            "mutation 2 (addr into DUP field) must fail the audit"
        );
        // Producer mutation 3: rename the leak through an assignment —
        // `start = addr` immediately before the existing target emit.
        // The argument text stays clean (`start`), so a lexical audit
        // survives this; the data-flow audit must fail it.
        let mutated = c.replacen(
            "    emit(ctx, P11_IDENT_KIND_VMA, tgid_u, start, end, verdict,",
            "    start = addr;\n    emit(ctx, P11_IDENT_KIND_VMA, tgid_u, start, end, verdict,",
            1,
        );
        assert_ne!(mutated, c, "mutation 3 must apply");
        assert!(
            audit_identity_c_source(&mutated, path).is_err(),
            "mutation 3 (start = addr before emit) must fail the audit"
        );
        // Producer mutation 4: the same leak through an intermediate —
        // taint must propagate across assignments.
        let mutated = c.replacen(
            "    emit(ctx, P11_IDENT_KIND_VMA, tgid_u, start, end, verdict,",
            "    u64 smuggled = addr;\n    start = smuggled;\n    emit(ctx, P11_IDENT_KIND_VMA, tgid_u, start, end, verdict,",
            1,
        );
        assert_ne!(mutated, c, "mutation 4 must apply");
        assert!(
            audit_identity_c_source(&mutated, path).is_err(),
            "mutation 4 (addr through an intermediate) must fail the audit"
        );
        // Producer mutation 5: launder taint through a compound
        // assignment — `+=` reads the tainted old value, so a clean rhs
        // must NOT clear it.
        for op in ["+=", "-=", "|=", "&=", "<<="] {
            let mutated = c.replacen(
                "    emit(ctx, P11_IDENT_KIND_VMA, tgid_u, start, end, verdict,",
                &format!(
                    "    start = addr;\n    start {op} 0;\n    emit(ctx, P11_IDENT_KIND_VMA, tgid_u, start, end, verdict,"
                ),
                1,
            );
            assert_ne!(mutated, c, "mutation 5 ({op}) must apply");
            assert!(
                audit_identity_c_source(&mutated, path).is_err(),
                "mutation 5 (launder through `{op}`) must fail the audit"
            );
        }
        // Producer mutation 6: same-line `start = addr; emit(...)` — the
        // emit check must see the assignment before it on its own line.
        let mutated = c.replacen(
            "    emit(ctx, P11_IDENT_KIND_VMA, tgid_u, start, end, verdict,",
            "    start = addr; emit(ctx, P11_IDENT_KIND_VMA, tgid_u, start, end, verdict,",
            1,
        );
        assert_ne!(mutated, c, "mutation 6 must apply");
        assert!(
            audit_identity_c_source(&mutated, path).is_err(),
            "mutation 6 (same-line start = addr; emit) must fail the audit"
        );
        // Producer mutation 7: split-line assignment — both the
        // before-`=` split (`start` / `= addr;`) and the brief-exact
        // after-`=` split (`start =` / `addr;`) must taint across the
        // line break, not clear on an empty-looking rhs.
        for stmt in ["    start\n    = addr;", "    start =\n    addr;"] {
            let mutated = c.replacen(
                "    emit(ctx, P11_IDENT_KIND_VMA, tgid_u, start, end, verdict,",
                &format!("{stmt}\n    emit(ctx, P11_IDENT_KIND_VMA, tgid_u, start, end, verdict,"),
                1,
            );
            assert_ne!(mutated, c, "mutation 7 ({stmt:?}) must apply");
            assert!(
                audit_identity_c_source(&mutated, path).is_err(),
                "mutation 7 (split-line assignment {stmt:?}) must fail the audit"
            );
        }
        // Producer mutation 8: binary `&` is not address-of —
        // `start = ~0ULL & addr` must taint, spaced or spaceless, and so
        // must `&` after a postfix operand (`mask-- & addr`, `p++ &
        // addr`) or a char-literal operand (`-'x' & addr`).
        for rhs in [
            "~0ULL & addr",
            "~0ULL&addr",
            "mask-- & addr",
            "p++ & addr",
            "-'x' & addr",
        ] {
            let mutated = c.replacen(
                "    emit(ctx, P11_IDENT_KIND_VMA, tgid_u, start, end, verdict,",
                &format!(
                    "    start = {rhs};\n    emit(ctx, P11_IDENT_KIND_VMA, tgid_u, start, end, verdict,"
                ),
                1,
            );
            assert_ne!(mutated, c, "mutation 8 ({rhs}) must apply");
            assert!(
                audit_identity_c_source(&mutated, path).is_err(),
                "mutation 8 (binary `&` in `{rhs}`) must fail the audit"
            );
        }
        // Producer mutation 9: a tainted through-deref store outside the
        // bookkeeping allowlist — `*pp = addr` must fail (the real
        // `*slot_cell = addr` line passes by exact-text allowlist, and a
        // reformatted twin fails loudly).
        for (from, to) in [
            ("    *slot_cell = addr;", "    *pp = addr;"),
            ("    *slot_cell = addr;", "    *slot_cell=addr;"),
        ] {
            let mutated = c.replacen(from, to, 1);
            assert_ne!(mutated, c, "mutation 9 ({to}) must apply");
            assert!(
                audit_identity_c_source(&mutated, path).is_err(),
                "mutation 9 (deref store `{to}`) must fail the audit"
            );
        }
        // Parenthesized assignment targets (fix round 4, item 08):
        // the record/deref checks run on the full lhs, so
        // paren-wrapped spellings fail exactly like the bare ones —
        // plus a plain `record.field` store, previously unproven.
        for stmt in [
            "(record.start) = addr;",
            "(*pp) = addr;",
            "*(&start) = addr;",
            "record.start = addr;",
        ] {
            assert!(
                audit_c_chunk(stmt, "chunk").is_err(),
                "record/deref store `{stmt}` must fail the audit"
            );
        }
        // `(start) = addr` must taint `start`, so a later emit of it
        // fails.
        assert!(
            audit_c_chunk(
                "    (start) = addr;\n    emit(ctx, 1, 2, start, 0, 0, 0);\n",
                "chunk"
            )
            .is_err(),
            "a parenthesized store must propagate taint to the emit"
        );
        // Control-flow-prefixed stores (fix round 5): an unbraced `if`
        // prefix must not hide a tainted store from the emit check, nor
        // a through-deref store from the deref check -- the balanced
        // condition is not the target.
        for stmt in [
            "    if (1)start = addr;\n    emit(ctx, 1, 2, start, 0, 0, 0);\n",
            "    if (*word_cell) start = addr;\n    emit(ctx, 1, 2, start, 0, 0, 0);\n",
        ] {
            assert!(
                audit_c_chunk(stmt, "chunk").is_err(),
                "control-flow-prefixed store must propagate taint: {stmt:?}"
            );
        }
        for stmt in ["    if (ok) *pp = addr;\n", "    if (1) *pp = addr;\n"] {
            assert!(
                audit_c_chunk(stmt, "chunk").is_err(),
                "control-flow-prefixed deref store must fail: {stmt:?}"
            );
        }
        // Call-in-deref targets (breaker micro-fix B1): in `*f() =
        // addr` the trailing `(` is a call suffix, not a
        // control-flow prefix, so the through-deref store must fail
        // loudly. Both spellings are clang-18-valid C.
        for stmt in ["    *getp() = addr;\n", "    *target() = addr;\n"] {
            assert!(
                audit_c_chunk(stmt, "chunk").is_err(),
                "call-in-deref store must fail the audit: {stmt:?}"
            );
        }
        // Conditional kills under unbraced `if` (breaker micro-fix
        // B3b): `if (0) start = 0` may never execute, so the kill
        // must not clear taint before the emit -- while a braced
        // kill still clears (pre-existing flow-insensitivity,
        // unchanged).
        assert!(
            audit_c_chunk(
                "    start = addr;\n    if (0) start = 0;\n    emit(ctx, 1, 2, start, 0, 0, 0);\n",
                "chunk"
            )
            .is_err(),
            "an unbraced-`if` kill must not clear taint"
        );
        audit_c_chunk(
            "    start = addr;\n    if (c) { start = 0; }\n    emit(ctx, 1, 2, start, 0, 0, 0);\n",
            "chunk",
        )
        .expect("a braced kill still clears taint");
        // No-regression control: a compound operator outside parens
        // (`(x) += ...`) still tracks taint on the unwrapped target.
        assert!(
            audit_c_chunk(
                "    start = addr;\n    (start) += 0;\n    emit(ctx, 1, 2, start, 0, 0, 0);\n",
                "chunk"
            )
            .is_err(),
            "`(x) += ...` must keep taint on the unwrapped target"
        );
        // Line-spliced postfix (fix round 5): C translation phase 2
        // joins `mask-\<newline>-` into `mask--` before anything else,
        // so the audit must see the operand too -- `& addr` stays binary
        // and taints.
        assert!(
            audit_c_chunk(
                "    start = mask-\\\n- & addr;\n    emit(ctx, 1, 2, start, 0, 0, 0);\n",
                "chunk"
            )
            .is_err(),
            "a line-spliced postfix operand must keep binary-`&` taint"
        );
        // A splice inside a line comment continues it (phase 2 precedes
        // comment stripping): the emit below is commented out, so the
        // chunk passes for a different reason than the live-emit case.
        audit_c_chunk(
            "    start = addr; // trailing \\\n    emit(ctx, 1, 2, start, 0, 0, 0);\n",
            "chunk",
        )
        .expect("a spliced line comment must swallow the emit");
        // Legitimate address-of uses stay untainted: `&addr` as a lookup
        // key never taints the result — while binary `&` does.
        audit_c_chunk(
            "    x = f(&addr);\n    emit(ctx, 1, 2, x, 0, 0, 0);\n",
            "chunk",
        )
        .expect("address-of must not taint");
        assert!(
            audit_c_chunk(
                "    x = y & addr;\n    emit(ctx, 1, 2, x, 0, 0, 0);\n",
                "chunk"
            )
            .is_err(),
            "binary `&` must taint"
        );
    }

    /// Blank Rust noise length-preservingly (every byte becomes a space
    /// or stays, newlines kept): block comments `/*…*/` (nesting, as Rust
    /// allows), line comments `//…`, and string/char literal contents
    /// (normal, raw `r#*"…"*#`, and byte forms). The lexer is aware of
    /// each form so markers inside one never open another (`/*` in a
    /// string, `//` in a block comment, `"` in a comment); `'` opens a
    /// char literal only for `'x'`/`'\…'` shapes, never for lifetimes
    /// (`'a`, `'static`). What remains is code shape at identical byte
    /// offsets. An unterminated block comment blanks through EOF — the
    /// audited code compiles, so that only bites player-made mutations,
    /// which then fail loudly (hidden methods break the exact sets).
    fn blank_rust_noise(code: &str) -> String {
        let bytes = code.as_bytes();
        let mut out = Vec::with_capacity(bytes.len());
        let mut index = 0;
        // Copy the byte verbatim (code shape); blank it (noise).
        while index < bytes.len() {
            let byte = bytes[index];
            let next = bytes.get(index + 1).copied().unwrap_or(0);
            // Line comment: pass through to (and including) the newline
            // — its contents are never code, but it ends there.
            if byte == b'/' && next == b'/' {
                out.push(b' ');
                out.push(b' ');
                index += 2;
                while index < bytes.len() && bytes[index] != b'\n' {
                    out.push(b' ');
                    index += 1;
                }
                continue;
            }
            // Block comment, nesting.
            if byte == b'/' && next == b'*' {
                let mut depth = 0i32;
                while index < bytes.len() {
                    let pair = (bytes[index], bytes.get(index + 1).copied().unwrap_or(0));
                    if pair == (b'/', b'*') {
                        depth += 1;
                        out.push(b' ');
                        out.push(b' ');
                        index += 2;
                    } else if pair == (b'*', b'/') {
                        depth -= 1;
                        out.push(b' ');
                        out.push(b' ');
                        index += 2;
                        if depth == 0 {
                            break;
                        }
                    } else {
                        out.push(if bytes[index] == b'\n' { b'\n' } else { b' ' });
                        index += 1;
                    }
                }
                continue;
            }
            // Raw string `r"…"`, `r#"…"#`, … (optionally `br`-prefixed):
            // copy the opener, blank the contents, copy the closer.
            let raw_opener = |at: usize| -> Option<(usize, usize)> {
                let mut hashes = 0;
                let mut cursor = at;
                if bytes.get(cursor) == Some(&b'b') {
                    cursor += 1;
                }
                if bytes.get(cursor) != Some(&b'r') {
                    return None;
                }
                cursor += 1;
                while bytes.get(cursor) == Some(&b'#') {
                    hashes += 1;
                    cursor += 1;
                }
                if bytes.get(cursor) != Some(&b'"') {
                    return None;
                }
                Some((cursor + 1, hashes))
            };
            if let Some((contents, hashes)) = raw_opener(index) {
                for byte in &bytes[index..contents] {
                    out.push(*byte);
                }
                index = contents;
                // Blank to the closing quote plus the same hashes.
                loop {
                    if index < bytes.len() && bytes[index] == b'"' {
                        let mut cursor = index + 1;
                        let mut seen = 0;
                        while seen < hashes && bytes.get(cursor) == Some(&b'#') {
                            seen += 1;
                            cursor += 1;
                        }
                        if seen == hashes {
                            out.push(b'"');
                            out.extend(std::iter::repeat_n(b'#', hashes));
                            index = cursor;
                            break;
                        }
                    }
                    if index >= bytes.len() {
                        break;
                    }
                    out.push(if bytes[index] == b'\n' { b'\n' } else { b' ' });
                    index += 1;
                }
                continue;
            }
            // Normal or byte string: copy the quotes/prefix, blank the
            // contents (`\"` and `\\` escapes respected).
            if byte == b'"' || (byte == b'b' && next == b'"') {
                if byte == b'b' {
                    out.push(b'b');
                    index += 1;
                }
                out.push(b'"');
                index += 1;
                while index < bytes.len() && bytes[index] != b'"' {
                    if bytes[index] == b'\\' {
                        out.push(b' ');
                        index += 1;
                        if index < bytes.len() {
                            out.push(if bytes[index] == b'\n' { b'\n' } else { b' ' });
                            index += 1;
                        }
                        continue;
                    }
                    // A newline ends a normal (non-raw) string in valid
                    // code; blank it as newline regardless.
                    out.push(if bytes[index] == b'\n' { b'\n' } else { b' ' });
                    index += 1;
                }
                if index < bytes.len() {
                    out.push(b'"');
                    index += 1;
                }
                continue;
            }
            // Char literal vs lifetime: `'x'` / `'\…'` copy through (with
            // blanked contents); `'a` / `'static` are lifetimes — the
            // quote is code shape, pass it through untouched.
            if byte == b'\'' {
                let is_char =
                    (next == b'\\') || bytes.get(index + 2).is_some_and(|third| *third == b'\'');
                if is_char {
                    out.push(b'\'');
                    index += 1;
                    while index < bytes.len() && bytes[index] != b'\'' {
                        if bytes[index] == b'\\' {
                            out.push(b' ');
                            index += 1;
                            if index < bytes.len() {
                                out.push(b' ');
                                index += 1;
                            }
                            continue;
                        }
                        out.push(b' ');
                        index += 1;
                    }
                    if index < bytes.len() {
                        out.push(b'\'');
                        index += 1;
                    }
                } else {
                    out.push(byte);
                    index += 1;
                }
                continue;
            }
            out.push(byte);
            index += 1;
        }
        String::from_utf8(out).expect("blanking keeps UTF-8 boundaries")
    }

    /// The Rust noise blanker is lexically sound: nested block
    /// comments blank fully, markers inside strings/chars/comments never
    /// open a comment, lifetimes never open a char literal, and every
    /// output is byte-identical in length (offsets survive).
    #[test]
    fn rust_noise_blanker_is_lexically_sound() {
        for (input, expected) in [
            ("a /* x /* y */ z */ b", "a                   b"),
            ("let s = \"/* no */\";", "let s = \"        \";"),
            ("// /* \ncode();", "      \ncode();"),
            ("fn f(x: &'a str) {}", "fn f(x: &'a str) {}"),
            ("let c = '{';", "let c = ' ';"),
            ("r#\"a\"b\"#;", "r#\"   \"#;"),
            ("b\"byte\";", "b\"    \";"),
        ] {
            let blanked = blank_rust_noise(input);
            assert_eq!(blanked, expected, "blanker input {input:?}");
            assert_eq!(blanked.len(), input.len(), "length preserved");
        }
        // A brace hidden in a block comment cannot truncate matching;
        // one in code still counts.
        assert_eq!(blank_rust_noise("/* } */ {}").matches('{').count(), 1);
    }

    /// Strip `//` comments and `"..."` string literals (with `\"`
    /// escapes) from one line: what remains is code shape (braces, item
    /// keywords). Single-quote char literals are passed through — the
    /// audited block holds none with braces.
    fn strip_line_noise(line: &str) -> String {
        let mut out = String::with_capacity(line.len());
        let mut chars = line.chars().peekable();
        let mut in_string = false;
        while let Some(ch) = chars.next() {
            if in_string {
                if ch == '\\' {
                    chars.next();
                } else if ch == '"' {
                    in_string = false;
                }
                continue;
            }
            if ch == '"' {
                in_string = true;
                continue;
            }
            if ch == '/' && chars.peek() == Some(&'/') {
                break;
            }
            out.push(ch);
        }
        out
    }

    /// Parse one `impl AnchorMaps` method (logical) line: `Some((name,
    /// public, same_line_gate))` for any visibility/modifier spelling
    /// (`fn`, `pub fn`, `pub(crate) fn`, `pub (crate) fn`, `pub const
    /// fn`, `const unsafe fn`, ...), `None` otherwise. The caller joins
    /// newline-split signatures before calling, so a logical line may
    /// span physical lines. Leading same-line attributes
    /// (`#[inline] pub fn …`, including spaced `# [inline]` — comments
    /// blank to spaces upstream) are scanned past to the item start,
    /// and a same-line `#[cfg(test)]` gate is reported. Only lines that
    /// START an item match — a method body cannot start with these
    /// qualifiers, so `let f: fn(u32)` inside a body never matches —
    /// and `fn` must be followed by a name plus `(` or `<`.
    fn parse_impl_method(line: &str) -> Option<(String, bool, bool)> {
        let code = strip_line_noise(line);
        let mut rest = code.trim_start();
        let mut same_line_gate = false;
        loop {
            let probe = rest.trim_start();
            // An attribute opener: `#`, optional whitespace (a spaced
            // `# [attr]` compiles; comments blank to spaces upstream),
            // then `[`. Anything else starts the item.
            let bracketed = probe
                .strip_prefix('#')
                .map(|tail| tail.trim_start())
                .filter(|tail| tail.starts_with('['));
            let Some(bracketed) = bracketed else {
                rest = probe;
                break;
            };
            // Strip one balanced `[…]` span (string-aware, for
            // `#[doc = "…[…]…"]`).
            let bytes = bracketed.as_bytes();
            let mut depth = 0i32;
            let mut end = None;
            let mut in_string = false;
            let mut escaped = false;
            for (offset, byte) in bytes.iter().enumerate() {
                if in_string {
                    if escaped {
                        escaped = false;
                    } else if *byte == b'\\' {
                        escaped = true;
                    } else if *byte == b'"' {
                        in_string = false;
                    }
                    continue;
                }
                match byte {
                    b'"' => in_string = true,
                    b'[' => depth += 1,
                    b']' => {
                        depth -= 1;
                        if depth == 0 {
                            end = Some(offset);
                            break;
                        }
                    }
                    _ => {}
                }
            }
            let end = end?;
            let flat: String = std::iter::once('#')
                .chain(bracketed[..=end].chars())
                .filter(|c| !c.is_whitespace())
                .collect();
            if flat == "#[cfg(test)]" {
                same_line_gate = true;
            }
            rest = &bracketed[end + 1..];
        }
        let trimmed = rest;
        if !(trimmed.starts_with("fn ")
            || trimmed.starts_with("pub")
            || trimmed.starts_with("const ")
            || trimmed.starts_with("unsafe ")
            || trimmed.starts_with("async "))
        {
            return None;
        }
        let (before, after) = trimmed.split_once("fn ")?;
        // `before` must be qualifiers only: strip one balanced `pub(…)`
        // span (whitespace-tolerant: `pub (crate)` compiles), then every
        // remaining token must be a plain qualifier.
        let mut qualifiers = before.to_string();
        let mut search = 0;
        let mut span = None;
        while let Some(rel) = qualifiers[search..].find("pub") {
            let at = search + rel;
            let bytes = qualifiers.as_bytes();
            let boundary =
                |side: Option<u8>| side.is_none_or(|b| !(b.is_ascii_alphanumeric() || b == b'_'));
            let before_ok = boundary(at.checked_sub(1).and_then(|i| bytes.get(i).copied()));
            let after_pub = &qualifiers[at + 3..];
            let gap = after_pub.len() - after_pub.trim_start().len();
            if before_ok
                && boundary(after_pub.as_bytes().first().copied())
                && after_pub[gap..].starts_with('(')
            {
                span = Some((at, gap));
                break;
            }
            search = at + 3;
        }
        if let Some((start, gap)) = span {
            let tail = &qualifiers[start + 3 + gap..];
            let mut depth = 0;
            let mut end = None;
            for (offset, ch) in tail.char_indices() {
                match ch {
                    '(' => depth += 1,
                    ')' => {
                        depth -= 1;
                        if depth == 0 {
                            end = Some(offset + 1);
                            break;
                        }
                    }
                    _ => {}
                }
            }
            qualifiers.replace_range(start..start + 3 + gap + end?, " ");
        }
        if !qualifiers
            .split_whitespace()
            .all(|token| matches!(token, "pub" | "const" | "unsafe" | "async"))
        {
            return None;
        }
        let name: String = after
            .chars()
            .take_while(|ch| ch.is_alphanumeric() || *ch == '_')
            .collect();
        if name.is_empty() {
            return None;
        }
        let rest = after[name.len()..].trim_start();
        if !(rest.starts_with('(') || rest.starts_with('<')) {
            return None;
        }
        Some((name, before.contains("pub"), same_line_gate))
    }

    /// Whether `word` occurs in `text` as a whole Rust identifier.
    fn contains_rust_word(text: &str, word: &str) -> bool {
        let mut rest = text;
        while let Some(found) = rest.find(word) {
            let boundary =
                |side: Option<char>| side.is_none_or(|c| !(c.is_alphanumeric() || c == '_'));
            let before = rest[..found].chars().next_back();
            let after = rest[found + word.len()..].chars().next();
            if boundary(before) && boundary(after) {
                return true;
            }
            rest = &rest[found + word.len()..];
        }
        false
    }

    /// Strip one whole-word keyword from the front of `text`.
    fn strip_rust_word<'a>(text: &'a str, word: &str) -> Option<&'a str> {
        let tail = text.strip_prefix(word)?;
        if tail
            .chars()
            .next()
            .is_some_and(|c| c.is_alphanumeric() || c == '_')
        {
            return None;
        }
        Some(tail)
    }

    /// Read a Rust path (`ident`, `self::x::Y`, `::x::Y`) from the front
    /// of `text`: the path plus the remainder, or `None`. Gaps around
    /// `::` compile (`self :: Y`, comments blank to spaces upstream),
    /// so segment joints skip whitespace -- but only across a real
    /// `::`, never between bare tokens. A `r#`-quoted segment
    /// (`r#AnchorMaps`) denotes its bare name.
    fn read_rust_path(text: &str) -> Option<(String, &str)> {
        let mut rest = text.strip_prefix("::").map(str::trim_start).unwrap_or(text);
        let mut path = String::new();
        loop {
            // Raw identifier: `r#` (adjacent -- a gap is the ident `r`
            // followed by an attribute) plus the quoted name, which
            // denotes the bare ident.
            if rest.starts_with('r') && rest[1..].starts_with('#') {
                rest = &rest[1..];
                while rest.starts_with('#') {
                    rest = &rest[1..];
                }
            }
            let name: String = rest
                .chars()
                .take_while(|c| c.is_alphanumeric() || *c == '_')
                .collect();
            if name.is_empty() || name.chars().next().is_some_and(|c| c.is_numeric()) {
                return None;
            }
            path.push_str(&name);
            rest = &rest[name.len()..];
            let joint = rest.trim_start();
            if let Some(tail) = joint.strip_prefix("::") {
                path.push_str("::");
                rest = tail.trim_start();
            } else {
                return Some((path, rest));
            }
        }
    }

    /// Skip one balanced `<…>` span (generic params) from the front of
    /// `text`: the remainder, or `None` when unbalanced.
    fn skip_rust_generics(text: &str) -> Option<&str> {
        let mut depth = 0i32;
        for (offset, byte) in text.bytes().enumerate() {
            match byte {
                b'<' => depth += 1,
                b'>' => {
                    depth -= 1;
                    if depth == 0 {
                        return Some(&text[offset + 1..]);
                    }
                }
                _ => {}
            }
        }
        None
    }

    /// Classify one `impl` header (the text after the `impl` keyword):
    /// (counts-as-inherent-`AnchorMaps`, is-trait-impl-for-`AnchorMaps`).
    /// Headers that defeat the strict parse fall back to a conservative
    /// substring heuristic — never to silence.
    fn classify_impl_header(rest: &str) -> (bool, bool) {
        let fallback = |rest: &str| {
            let head = rest.split('{').next().unwrap_or(rest);
            let head = &head[..head.len().min(300)];
            // Generic arguments are not the impl subject: `impl
            // Wrapper<AnchorMaps>` is an unrelated inherent block, so
            // blank balanced `<...>` spans before the substring
            // heuristic -- a name occurring only inside them reads as
            // neither. Unbalanced input keeps the loud heuristic.
            let mut spans = String::with_capacity(head.len());
            let mut depth = 0i32;
            let mut balanced = true;
            for ch in head.chars() {
                match ch {
                    '<' => {
                        depth += 1;
                        spans.push(' ');
                    }
                    '>' if depth > 0 => {
                        depth -= 1;
                        spans.push(' ');
                    }
                    _ if depth > 0 => spans.push(' '),
                    _ => spans.push(ch),
                }
            }
            if depth != 0 {
                balanced = false;
            }
            let head: &str = if balanced { &spans } else { head };
            if !contains_rust_word(head, "AnchorMaps") {
                return (false, false);
            }
            let before = head.split("AnchorMaps").next().unwrap_or("");
            // `for` ahead of the name reads as a trait impl; anything
            // else reads as an inherent block. Either fails the exact
            // counts loudly.
            let is_trait = contains_rust_word(before, "for");
            (!is_trait, is_trait)
        };
        let mut text = rest.trim_start();
        // Unstable `impl const Trait` (parsed defensively; stable code
        // has none).
        if let Some(tail) = strip_rust_word(text, "const") {
            text = tail.trim_start();
        }
        if text.starts_with('<') {
            let Some(tail) = skip_rust_generics(text) else {
                return fallback(rest);
            };
            text = tail.trim_start();
        }
        // Unstable negative impls (`impl !Send`).
        if let Some(tail) = text.strip_prefix('!') {
            text = tail.trim_start();
        }
        let Some((path, tail)) = read_rust_path(text) else {
            return fallback(rest);
        };
        let mut tail = tail.trim_start();
        // Generic trait arguments (`impl AsRef<OwnedFd> for AnchorMaps`):
        // skip one balanced `<…>` span after the trait path before
        // matching `for`, or the header misreads as inherent silence.
        if tail.starts_with('<') {
            let Some(after) = skip_rust_generics(tail) else {
                return fallback(rest);
            };
            tail = after.trim_start();
        }
        if let Some(tail) = strip_rust_word(tail, "for") {
            let tail = tail.trim_start();
            let Some((subject, _)) = read_rust_path(tail) else {
                return (false, true);
            };
            let last = subject.rsplit("::").next().unwrap_or(&subject);
            return (false, last == "AnchorMaps");
        }
        let last = path.rsplit("::").next().unwrap_or(&path);
        if last == "AnchorMaps" {
            return (true, false);
        }
        // A strict miss that still names whole-word `for` + `AnchorMaps`
        // defeated the shape above — fall back loudly, never to silence.
        fallback(rest)
    }

    /// Every `impl` block touching `AnchorMaps` in noise-blanked
    /// production `code`: (byte offset of the `impl` keyword,
    /// is-trait-impl). `unsafe`/`default` qualifiers ahead of `impl`
    /// need no handling — the scan keys on the keyword itself.
    fn anchor_impls(code: &str) -> Vec<(usize, bool)> {
        let bytes = code.as_bytes();
        let mut found = Vec::new();
        let mut index = 0;
        while index + 4 <= bytes.len() {
            let Some(rel) = code[index..].find("impl") else {
                break;
            };
            let at = index + rel;
            let prev_ok =
                at == 0 || !(bytes[at - 1].is_ascii_alphanumeric() || bytes[at - 1] == b'_');
            let next_ok = bytes
                .get(at + 4)
                .is_none_or(|b| !(b.is_ascii_alphanumeric() || *b == b'_'));
            if prev_ok && next_ok {
                let (inherent, is_trait) = classify_impl_header(&code[at + 4..]);
                found.push((at, inherent, is_trait));
            }
            index = at + 4;
        }
        found
            .into_iter()
            .filter_map(|(at, inherent, is_trait)| {
                if inherent || is_trait {
                    Some((at, is_trait))
                } else {
                    None
                }
            })
            .collect()
    }

    /// Fail loudly when noise-blanked audit input carries non-ASCII
    /// bytes: the scanners below are ASCII-shape based (`trim_start`,
    /// `split_whitespace`, `is_ascii_whitespace`), while `rustc`
    /// accepts non-ASCII inter-token gaps (U+200E, U+0085) and
    /// non-ASCII idents those tests cannot see -- so any non-ASCII in
    /// the audited regions rejects instead of risking silence. Real
    /// production code blanks to pure ASCII (its non-ASCII lives in
    /// comments and strings), so this only bites smuggled spellings.
    fn require_ascii_audit_input(text: &str, what: &str) -> Result<(), String> {
        if text.is_ascii() {
            return Ok(());
        }
        let (offset, found) = text
            .char_indices()
            .find(|(_, ch)| !ch.is_ascii())
            .expect("a non-ASCII char exists");
        Err(format!(
            "{what} must be ASCII after blanking: found {found:?} (U+{:04X}) at byte {offset}",
            u32::from(found)
        ))
    }

    /// Scan production code for `impl` blocks touching `AnchorMaps`:
    /// (inherent-block count, any-trait-impl). Matches trait impls on
    /// `for` + optional path + `AnchorMaps` (`for self::AnchorMaps`,
    /// `for crate::x::AnchorMaps`), and inherent blocks under any
    /// qualifier/generic spelling. Exotic headers that defeat the
    /// strict parse fall back to a conservative substring heuristic —
    /// never to silence. Non-ASCII bytes fail loudly: the scanners are
    /// ASCII-shape based, and `rustc` accepts non-ASCII inter-token
    /// gaps (U+200E, U+0085) the ASCII tests cannot see.
    fn scan_anchor_impls(code: &str) -> Result<(usize, bool), String> {
        require_ascii_audit_input(code, "impl scan input")?;
        let mut inherent = 0;
        let mut trait_impl = false;
        for (_, is_trait) in anchor_impls(code) {
            if is_trait {
                trait_impl = true;
            } else {
                inherent += 1;
            }
        }
        Ok((inherent, trait_impl))
    }

    /// Byte offset of the inherent `impl AnchorMaps` keyword in
    /// noise-blanked production `code`, or `None`.
    fn find_inherent_anchor_impl(code: &str) -> Option<usize> {
        anchor_impls(code)
            .into_iter()
            .find_map(|(at, is_trait)| (!is_trait).then_some(at))
    }

    /// Whether `name` is a Rust strict or reserved keyword (`if`,
    /// `return`, ...): keywords can never name a macro, so `!` after one
    /// is unary negation, never an invocation. A `r#`-quoted ident
    /// still counts as an invocation (syntactically one); the caller
    /// checks the `#`.
    fn is_rust_keyword(name: &str) -> bool {
        matches!(
            name,
            "as" | "break"
                | "const"
                | "continue"
                | "crate"
                | "else"
                | "enum"
                | "extern"
                | "false"
                | "fn"
                | "for"
                | "if"
                | "impl"
                | "in"
                | "let"
                | "loop"
                | "match"
                | "mod"
                | "move"
                | "mut"
                | "pub"
                | "ref"
                | "return"
                | "self"
                | "Self"
                | "static"
                | "struct"
                | "super"
                | "trait"
                | "true"
                | "type"
                | "unsafe"
                | "use"
                | "where"
                | "while"
                | "async"
                | "await"
                | "dyn"
                | "gen"
                | "abstract"
                | "become"
                | "box"
                | "do"
                | "final"
                | "macro"
                | "override"
                | "priv"
                | "typeof"
                | "unsized"
                | "virtual"
                | "yield"
                | "try"
        )
    }

    /// Forbid macros in the handle region: no `macro_rules` in
    /// production code at all, and no macro invocations inside the
    /// `impl AnchorMaps` block except the two allowlisted
    /// `std::ptr::addr_of_mut!` call sites (pinned by count). An
    /// invocation is `!` preceded (across whitespace) by an identifier
    /// char and followed (across whitespace) by `(`, `[`, or `{` — a
    /// spaced `mac ! ()` compiles, and comments blank to spaces
    /// upstream, so adjacency is not required. `!=` never matches, and
    /// neither does unary `!` after a strict keyword (`if !(...)`,
    /// `return !(...)`): keywords can never name a macro. Non-ASCII
    /// bytes fail loudly (the gap/ident scans are ASCII-shape based).
    /// An external `#[macro_use]` definition needs no in-file search:
    /// whatever defines the macro, invoking it in the region fails
    /// this scan. Returns the rejection reason instead of panicking so
    /// proofs can assert rejection.
    fn check_handle_region_has_no_macros(code: &str) -> Result<(), String> {
        require_ascii_audit_input(code, "macro forbid input")?;
        if code.contains("macro_rules") {
            return Err("production code must not define macro_rules".to_string());
        }
        let offset = find_inherent_anchor_impl(code)
            .ok_or_else(|| "no inherent impl AnchorMaps".to_string())?;
        let end = offset + impl_block_end(&code[offset..]);
        let region = &code[offset..end];
        let bytes = region.as_bytes();
        let mut allowlisted = 0;
        let mut index = 0;
        while index < bytes.len() {
            if bytes[index] == b'!' {
                let mut back = index;
                while back > 0 && bytes[back - 1].is_ascii_whitespace() {
                    back -= 1;
                }
                let prev = back
                    .checked_sub(1)
                    .and_then(|at| bytes.get(at).copied())
                    .unwrap_or(b' ');
                let mut fwd = index + 1;
                while fwd < bytes.len() && bytes[fwd].is_ascii_whitespace() {
                    fwd += 1;
                }
                let next = bytes.get(fwd).copied().unwrap_or(b' ');
                let prev_ident = prev.is_ascii_alphanumeric() || prev == b'_';
                let next_delim = next == b'(' || next == b'[' || next == b'{';
                if prev_ident && next_delim {
                    let mut start = back;
                    while start > 0
                        && (bytes[start - 1].is_ascii_alphanumeric()
                            || bytes[start - 1] == b'_'
                            || bytes[start - 1] == b':')
                    {
                        start -= 1;
                    }
                    let name = &region[start..back];
                    // A strict keyword ahead of `!` is unary negation
                    // (`if !(...)`), never an invocation -- unless the
                    // ident is `r#`-quoted, which still reads as one.
                    let raw = start > 0 && bytes[start - 1] == b'#';
                    if !raw && is_rust_keyword(name) {
                        index += 1;
                        continue;
                    }
                    if name == "std::ptr::addr_of_mut" {
                        allowlisted += 1;
                    } else {
                        return Err(format!("macro invocation in the handle region: {name}!"));
                    }
                }
            }
            index += 1;
        }
        if allowlisted != 2 {
            return Err(format!(
                "expected exactly 2 allowlisted addr_of_mut! sites, found {allowlisted}"
            ));
        }
        Ok(())
    }

    /// Enumerate the methods of an `impl AnchorMaps` block (the text
    /// after `impl AnchorMaps`): (public, private, `#[cfg(test)]`-gated)
    /// name sets. The block range comes from brace matching (immune to a
    /// body brace dedented to column 0, which would truncate a
    /// first-`}` scan and hide later methods); method lines parse with
    /// [`parse_impl_method`], any visibility/modifier spelling. Shared by
    /// the exact-API test and the bypass-mutation proofs below.
    /// Byte offset just past the `impl` block's closing brace in
    /// `block` (the text from the `impl` keyword): brace matching from
    /// the first `{`, immune to a body brace dedented to column 0.
    fn impl_block_end(block: &str) -> usize {
        let mut depth = 0i32;
        let mut started = false;
        let mut offset = 0;
        for line in block.split_inclusive('\n') {
            for ch in strip_line_noise(line).chars() {
                match ch {
                    '{' => {
                        depth += 1;
                        started = true;
                    }
                    '}' => depth -= 1,
                    _ => {}
                }
            }
            offset += line.len();
            if started && depth == 0 {
                return offset;
            }
        }
        panic!("impl block end");
    }

    /// Whether a stripped, still-unparsed candidate could be an
    /// incomplete method signature whose remainder follows on the next
    /// line: optional complete attributes, `pub` (plus an optionally
    /// still-open `(...)` group), qualifier words, then `fn` plus at
    /// most a bare name (or a still-open `<...>` group). Anything else
    /// never continues: bodies (`unsafe {`), associated items
    /// (`const X: ...`, `type ...`), bare `#` lines (split attributes
    /// stay out of scope), and complete trailing tokens.
    fn signature_prefix_open(candidate: &str) -> bool {
        let mut text = candidate.trim_start();
        // Leading complete `# [...]` spans (string-aware, as in the
        // method parser); a trailing bare `#` never continues.
        loop {
            let probe = text.trim_start();
            let Some(bracketed) = probe
                .strip_prefix('#')
                .map(str::trim_start)
                .filter(|tail| tail.starts_with('['))
            else {
                text = probe;
                break;
            };
            let mut depth = 0i32;
            let mut end = None;
            let mut in_string = false;
            let mut escaped = false;
            for (offset, byte) in bracketed.bytes().enumerate() {
                if in_string {
                    if escaped {
                        escaped = false;
                    } else if byte == b'\\' {
                        escaped = true;
                    } else if byte == b'"' {
                        in_string = false;
                    }
                    continue;
                }
                match byte {
                    b'"' => in_string = true,
                    b'[' => depth += 1,
                    b']' => {
                        depth -= 1;
                        if depth == 0 {
                            end = Some(offset);
                            break;
                        }
                    }
                    _ => {}
                }
            }
            let Some(close) = end else {
                return false;
            };
            text = bracketed[close + 1..].trim_start();
        }
        // An attribute-only line gates from above (the `previous`
        // path), it never continues a signature.
        if text.is_empty() || text.starts_with('#') {
            return false;
        }
        if let Some(tail) = strip_rust_word(text, "pub") {
            text = tail.trim_start();
            if text.starts_with('(') {
                let mut depth = 0i32;
                let mut closed = None;
                for (offset, ch) in text.char_indices() {
                    match ch {
                        '(' => depth += 1,
                        ')' => {
                            depth -= 1;
                            if depth == 0 {
                                closed = Some(offset);
                                break;
                            }
                        }
                        _ => {}
                    }
                }
                // A still-open visibility group continues on the next
                // line.
                let Some(close) = closed else {
                    return true;
                };
                text = text[close + 1..].trim_start();
            }
        }
        // Qualifier words (order-insensitive here: complete lines
        // parse before this check ever runs).
        loop {
            let mut advanced = false;
            for word in ["const", "unsafe", "async"] {
                if let Some(tail) = strip_rust_word(text, word) {
                    text = tail.trim_start();
                    advanced = true;
                    break;
                }
            }
            if !advanced {
                break;
            }
        }
        if text.is_empty() {
            // Bare qualifiers (`pub`, `pub const`) continue.
            return true;
        }
        let Some(tail) = strip_rust_word(text, "fn") else {
            return false;
        };
        let tail = tail.trim_start();
        let name: String = tail
            .chars()
            .take_while(|c| c.is_alphanumeric() || *c == '_')
            .collect();
        if name.is_empty() || name.chars().next().is_some_and(|c| c.is_numeric()) {
            // `fn` alone continues; anything else non-name closes.
            return tail.is_empty();
        }
        let after = tail[name.len()..].trim_start();
        if after.is_empty() {
            return true;
        }
        // A still-open generic group continues; anything else closes.
        if after.starts_with('<') {
            let mut depth = 0i32;
            for ch in after.chars() {
                match ch {
                    '<' => depth += 1,
                    '>' => depth -= 1,
                    _ => {}
                }
            }
            return depth > 0;
        }
        false
    }

    /// Enumerated `impl AnchorMaps` API: (public, private,
    /// `#[cfg(test)]`-gated) name sets.
    type AnchorApiSets = (BTreeSet<String>, BTreeSet<String>, BTreeSet<String>);

    fn anchor_maps_api(block: &str) -> Result<AnchorApiSets, String> {
        require_ascii_audit_input(block, "API enumeration input")?;
        let end = impl_block_end(block);
        let mut public = BTreeSet::new();
        let mut private = BTreeSet::new();
        let mut gated = BTreeSet::new();
        let mut previous = String::new();
        // A signature broken across lines (`pub` / `(crate) fn ...`,
        // `pub fn name` / `(...)`) still enumerates: an unparsed
        // candidate that is a strict signature prefix continues on the
        // next line. A pending prefix that derails -- or dangles at the
        // block end -- fails loudly instead of vanishing.
        let mut pending = String::new();
        for line in block[..end].lines() {
            // Strip each physical line BEFORE joining: a trailing `//`
            // comment ends at its own newline, never swallowing the
            // continuation line (re-stripping inside the method parser
            // is idempotent on valid code).
            let clean = strip_line_noise(line);
            let candidate = if pending.is_empty() {
                clean
            } else {
                format!("{pending}\n{clean}")
            };
            // The gate attribute sits immediately above its method — or
            // on the same line ahead of it. Whitespace-insensitive: a
            // spaced `# [cfg(test)]` line gates exactly like the tight
            // spelling.
            let prev_flat: String = previous.chars().filter(|c| !c.is_whitespace()).collect();
            let prev_gated = prev_flat == "#[cfg(test)]";
            if let Some((name, is_public, same_line_gate)) = parse_impl_method(&candidate) {
                if prev_gated || same_line_gate {
                    gated.insert(name.clone());
                }
                if is_public {
                    public.insert(name);
                } else {
                    private.insert(name);
                }
                previous = candidate;
                pending.clear();
            } else if signature_prefix_open(&candidate) {
                pending = candidate;
            } else if pending.is_empty() {
                previous = candidate;
            } else {
                return Err(format!(
                    "unclassifiable method-like text in the AnchorMaps impl: {candidate:?}"
                ));
            }
        }
        if !pending.is_empty() {
            return Err(format!(
                "dangling signature prefix at the end of the AnchorMaps impl: {pending:?}"
            ));
        }
        Ok((public, private, gated))
    }

    /// The API enumeration sees through visibility and modifier bypasses:
    /// a `pub(crate) fn` fd accessor and a `pub const fn` reader, added to
    /// a copy of the real sources in memory, must both show up in the
    /// public set (where the exact-set assertion would then fail).
    #[test]
    fn anchor_api_enumeration_catches_bypass_signatures() {
        let root = std::path::Path::new(env!("CARGO_MANIFEST_DIR"));
        let rust =
            std::fs::read_to_string(root.join("src/attach/identity_iter.rs")).expect("read self");
        let code = rust.split_once("mod tests").expect("test module").0;
        let api_of = |code: &str| {
            // Re-blank inside: bypass mutations land after any outer
            // blanking, so the enumeration must see through them here.
            let blanked = blank_rust_noise(code);
            let offset = find_inherent_anchor_impl(&blanked).expect("impl block");
            anchor_maps_api(&blanked[offset..])
        };
        for smuggled in [
            "    pub(crate) fn raw_hash_fd(&self) -> i32 { 0 }\n",
            "    pub const fn fd_accessor(&self) -> i32 { 0 }\n",
        ] {
            let mutated =
                code.replacen("    pub fn new(", &format!("{smuggled}    pub fn new("), 1);
            assert_ne!(mutated, code, "mutation must apply");
            let (public, _, _) = api_of(&mutated).expect("bypass api scans");
            let name = smuggled
                .split("fn ")
                .nth(1)
                .expect("fn name")
                .split('(')
                .next()
                .expect("name end");
            assert!(
                public.contains(name),
                "enumeration must catch the bypass signature {name}"
            );
        }
        // Block-comment-hidden method (astra N2a): a `/* } */` line ends
        // a naive brace scan early, hiding the live method after it.
        let hidden = code.replacen(
            "        Self::update(self.slots.as_fd(), &slot.to_ne_bytes(), &addr.to_ne_bytes())\n    }\n}",
            "        Self::update(self.slots.as_fd(), &slot.to_ne_bytes(), &addr.to_ne_bytes())\n    }\n    /* } */\n    pub fn smuggled_block(&self) -> i32 { 0 }\n}",
            1,
        );
        assert_ne!(hidden, code, "comment-hiding mutation must apply");
        let (public, _, _) = api_of(&hidden).expect("hidden api scans");
        assert!(
            public.contains("smuggled_block"),
            "enumeration must see through block comments"
        );
        // Same-line-attributed method (astra N3): the line starts with
        // `#`, not a qualifier.
        let attributed = code.replacen(
            "    pub fn new(",
            "    #[inline] pub fn smuggled_attr(&self) -> i32 { 0 }\n    pub fn new(",
            1,
        );
        assert_ne!(attributed, code, "attribute mutation must apply");
        let (public, _, _) = api_of(&attributed).expect("attributed api scans");
        assert!(
            public.contains("smuggled_attr"),
            "enumeration must parse fn after same-line attributes"
        );
        // Spaced attributes and visibility (fix round 4, item 05):
        // `# [inline]`, `# /*gap*/ [inline]`, and `pub (crate) fn`
        // all compile — each smuggled accessor must still enumerate.
        for (smuggled, name) in [
            (
                "    # [inline] pub fn smuggled_spaced_attr(&self) -> i32 { 0 }\n",
                "smuggled_spaced_attr",
            ),
            (
                "    # /*gap*/ [inline] pub fn smuggled_gap_attr(&self) -> i32 { 0 }\n",
                "smuggled_gap_attr",
            ),
            (
                "    pub (crate) fn smuggled_spaced_vis(&self) -> i32 { 0 }\n",
                "smuggled_spaced_vis",
            ),
        ] {
            let mutated =
                code.replacen("    pub fn new(", &format!("{smuggled}    pub fn new("), 1);
            assert_ne!(mutated, code, "spacing mutation {name} must apply");
            let (public, _, _) = api_of(&mutated).expect("spaced api scans");
            assert!(
                public.contains(name),
                "enumeration must catch the spaced spelling {name}"
            );
        }
        // Non-ASCII inter-token gaps (fix round 5): `rustc` accepts
        // U+200E and U+0085 where the ASCII spacing checks look
        // (`pub`/`(crate)`, `#`/`[`), so each smuggled spelling must
        // fail the audit loudly instead of vanishing. Fixtures are
        // byte-built (`char::from_u32`, never literal non-ASCII) and
        // byte-asserted.
        let lrm = char::from_u32(0x200E).expect("U+200E exists");
        let nel = char::from_u32(0x0085).expect("U+0085 exists");
        let unicode: [(String, &[u8]); 4] = [
            (
                format!("    pub{lrm}(crate) fn smuggled_unicode_vis(&self) -> i32 {{ 0 }}\n"),
                &[0xE2, 0x80, 0x8E],
            ),
            (
                format!("    #{lrm}[inline] pub fn smuggled_unicode_attr(&self) -> i32 {{ 0 }}\n"),
                &[0xE2, 0x80, 0x8E],
            ),
            (
                format!("    pub{nel}(crate) fn smuggled_unicode_nel(&self) -> i32 {{ 0 }}\n"),
                &[0xC2, 0x85],
            ),
            (
                format!(
                    "    #{nel}[inline] pub fn smuggled_unicode_attr_nel(&self) -> i32 {{ 0 }}\n"
                ),
                &[0xC2, 0x85],
            ),
        ];
        for (smuggled, utf8) in unicode {
            assert!(
                smuggled.as_bytes().windows(utf8.len()).any(|w| w == utf8),
                "fixture must carry the {utf8:02X?} bytes"
            );
            let mutated =
                code.replacen("    pub fn new(", &format!("{smuggled}    pub fn new("), 1);
            assert_ne!(mutated, code, "unicode mutation must apply");
            assert!(
                api_of(&mutated).is_err(),
                "enumeration must fail loudly on non-ASCII gaps: {smuggled:?}"
            );
        }
        // Newline-split signatures (fix round 5): `rustc` accepts a
        // method signature broken across lines, so each smuggled
        // spelling must still enumerate.
        for (smuggled, name) in [
            (
                "    pub\n    (crate) fn smuggled_split_vis(&self) -> i32 { 0 }\n",
                "smuggled_split_vis",
            ),
            (
                "    pub fn smuggled_split_params\n    (&self) -> i32 { 0 }\n",
                "smuggled_split_params",
            ),
        ] {
            let mutated =
                code.replacen("    pub fn new(", &format!("{smuggled}    pub fn new("), 1);
            assert_ne!(mutated, code, "split mutation {name} must apply");
            let (public, _, _) = api_of(&mutated).expect("split api scans");
            assert!(
                public.contains(name),
                "enumeration must catch the split spelling {name}"
            );
        }
    }

    /// The impl-block predicates see through comments and paths: a
    /// trait impl for `self::AnchorMaps` (sol F1/S5), a commented
    /// `for` (astra N2b), and a commented inherent header (a second
    /// inherent block must count) — each proven by appending the
    /// bypass to a copy of the real production code in memory.
    #[test]
    fn anchor_impl_predicates_catch_comment_and_path_bypasses() {
        let root = std::path::Path::new(env!("CARGO_MANIFEST_DIR"));
        let rust =
            std::fs::read_to_string(root.join("src/attach/identity_iter.rs")).expect("read self");
        let blanked = blank_rust_noise(&rust);
        let code = blanked.split_once("mod tests").expect("test module").0;
        assert_eq!(
            scan_anchor_impls(code).expect("real code scans"),
            (1, false),
            "real code: exactly one inherent block, no trait impl"
        );
        let slf = format!("{code}\nimpl std::fmt::Debug for self::AnchorMaps {{}}\n");
        assert!(
            scan_anchor_impls(&blank_rust_noise(&slf))
                .expect("path bypass scans")
                .1,
            "`for self::AnchorMaps` must read as a trait impl"
        );
        let commented = format!("{code}\nimpl Foo for /*x*/ AnchorMaps {{}}\n");
        assert!(
            scan_anchor_impls(&blank_rust_noise(&commented))
                .expect("commented bypass scans")
                .1,
            "commented `for` impl must read as a trait impl"
        );
        let second = format!("{code}\nimpl /*x*/ AnchorMaps {{}}\n");
        assert_eq!(
            scan_anchor_impls(&blank_rust_noise(&second))
                .expect("second inherent scans")
                .0,
            2,
            "commented inherent impl must count"
        );
        // Generic trait arguments on the trait path (fix round 4, item
        // 04): the trait name parses, then a balanced `<…>` span, then
        // `for AnchorMaps` — each must read as a trait impl, never
        // silence (the `AsRef<OwnedFd>` spelling is a working fd leak
        // via `as_ref`).
        for header in [
            "impl<T> Evil<T> for AnchorMaps {}",
            "impl Evil2<T> for AnchorMaps {}",
            "impl AsRef<OwnedFd> for AnchorMaps {}",
        ] {
            let mutated = format!("{code}\n{header}\n");
            assert!(
                scan_anchor_impls(&blank_rust_noise(&mutated))
                    .expect("generic header scans")
                    .1,
                "`{header}` must read as a trait impl"
            );
        }
        // Spaced qualified subject paths (fix round 5): gaps around
        // `::` compile (`for self :: AnchorMaps`, comment-separated --
        // blanked to spaces upstream -- and leading `:: AnchorMaps`),
        // so each must read as a trait impl, never silence.
        for header in [
            "impl Evil for self :: AnchorMaps {}",
            "impl AsRef<OwnedFd> for self /*gap*/ :: AnchorMaps {}",
            "impl Evil for :: AnchorMaps {}",
            "impl Evil for crate :: AnchorMaps {}",
        ] {
            let mutated = format!("{code}\n{header}\n");
            assert!(
                scan_anchor_impls(&blank_rust_noise(&mutated))
                    .expect("spaced header scans")
                    .1,
                "`{header}` must read as a trait impl"
            );
        }
        // Raw-identifier subjects (fix round 5): `r#AnchorMaps` denotes
        // the same type, so a trait impl for it must read as a trait
        // impl -- and a bare `impl r#AnchorMaps` as a second inherent
        // block, never silence.
        for header in [
            "impl AsRef<OwnedFd> for r#AnchorMaps {}",
            "impl std::fmt::Debug for r#AnchorMaps {}",
        ] {
            let mutated = format!("{code}\n{header}\n");
            assert!(
                scan_anchor_impls(&blank_rust_noise(&mutated))
                    .expect("raw-ident header scans")
                    .1,
                "`{header}` must read as a trait impl"
            );
        }
        let inherent = format!("{code}\nimpl r#AnchorMaps {{}}\n");
        assert_eq!(
            scan_anchor_impls(&blank_rust_noise(&inherent)).expect("inherent raw scans"),
            (2, false),
            "`impl r#AnchorMaps` must read as a second inherent block"
        );
        // Generic-nested names (fix round 5): `impl Wrapper<AnchorMaps>`
        // is an unrelated inherent block -- `AnchorMaps` occurs only
        // inside `<...>` -- so the scan must stay `(1, false)`.
        let wrapped = format!("{code}\nimpl Wrapper<AnchorMaps> {{}}\n");
        assert_eq!(
            scan_anchor_impls(&blank_rust_noise(&wrapped)).expect("wrapped header scans"),
            (1, false),
            "`impl Wrapper<AnchorMaps>` must not count as an AnchorMaps block"
        );
        // Non-ASCII in an impl header (fix round 5): a U+200E or
        // U+0085 gap between `for` and the subject must fail the
        // scan loudly. Byte-built (`char::from_u32`, never literal
        // non-ASCII) and byte-asserted.
        let lrm = char::from_u32(0x200E).expect("U+200E exists");
        let nel = char::from_u32(0x0085).expect("U+0085 exists");
        let non_ascii: [(String, &[u8]); 2] = [
            (
                format!("impl Evil for{lrm}AnchorMaps {{}}"),
                &[0xE2, 0x80, 0x8E],
            ),
            (format!("impl Evil for{nel}AnchorMaps {{}}"), &[0xC2, 0x85]),
        ];
        for (header, utf8) in non_ascii {
            assert!(
                header.as_bytes().windows(utf8.len()).any(|w| w == utf8),
                "fixture must carry the {utf8:02X?} bytes"
            );
            let mutated = format!("{code}\n{header}\n");
            assert!(
                scan_anchor_impls(&blank_rust_noise(&mutated)).is_err(),
                "scan must fail loudly on non-ASCII: {header:?}"
            );
        }
    }

    /// Macros cannot smuggle handle methods (astra N5, design decision
    /// (i)): text enumeration is blind to macro-generated methods, so
    /// macros are forbidden instead — no `macro_rules!` in production
    /// code, and no invocations in the `impl AnchorMaps` region except
    /// the two allowlisted `std::ptr::addr_of_mut!` call sites the map
    /// syscalls need. (`rustc`-based enumeration was the alternative;
    /// the forbid is proportionate: the handle region legitimately
    /// contains no macros but those two call sites.)
    #[test]
    fn anchor_impl_region_forbids_macros() {
        let root = std::path::Path::new(env!("CARGO_MANIFEST_DIR"));
        let rust =
            std::fs::read_to_string(root.join("src/attach/identity_iter.rs")).expect("read self");
        let blanked = blank_rust_noise(&rust);
        let code = blanked.split_once("mod tests").expect("test module").0;
        // The blind spot this closes: a macro-generated read method is
        // invisible to text enumeration AND trips no other pin — the
        // enumeration still reports the pinned sets under the mutation.
        let mutated = code.replacen(
            "    pub fn new(",
            "    macro_rules! smuggled_method { () => { pub fn smuggled_macro(&self) -> i32 { 0 } } }\n    smuggled_method!();\n    pub fn new(",
            1,
        );
        assert_ne!(mutated, code, "macro mutation must apply");
        let blanked_mut = blank_rust_noise(&mutated);
        let offset = find_inherent_anchor_impl(&blanked_mut).expect("impl block");
        let (public, private, _) = anchor_maps_api(&blanked_mut[offset..]).expect("hole demo api");
        assert_eq!(
            public,
            BTreeSet::from([
                "new".to_string(),
                "remove".to_string(),
                "set_slot".to_string()
            ]),
            "hole demo: enumeration misses macro-generated methods"
        );
        assert_eq!(
            private,
            BTreeSet::from(["update".to_string(), "delete".to_string()]),
            "hole demo: private set also blind to macro methods"
        );
        assert_eq!(
            scan_anchor_impls(&blanked_mut).expect("hole demo scans"),
            (1, false),
            "hole demo: impl predicates miss macro methods"
        );
        // The close: real code passes the forbid, every macro mutation
        // fails it.
        check_handle_region_has_no_macros(code).expect("real code passes the macro forbid");
        assert!(
            check_handle_region_has_no_macros(&blanked_mut).is_err(),
            "forbid must reject the macro-generated method"
        );
        // Invocation-only proof (the definition lives outside the
        // region — the invocation still fails).
        let invoked = code.replacen("    pub fn new(", "    smuggled!();\n    pub fn new(", 1);
        assert_ne!(invoked, code, "invocation mutation must apply");
        assert!(
            check_handle_region_has_no_macros(&blank_rust_noise(&invoked)).is_err(),
            "forbid must reject a bare macro invocation in the region"
        );
        // Definition-only proof (outside the region, still forbidden).
        let defined = format!("{code}\nmacro_rules! evil {{ () => {{}} }}\n");
        assert!(
            check_handle_region_has_no_macros(&blank_rust_noise(&defined)).is_err(),
            "forbid must reject macro_rules in production code"
        );
        // Spacing bypasses (fix round 4, item 07): `mac! ()`,
        // `mac ! ()`, and comment-separated equivalents all compile,
        // as does a spaced `include!` — every spelling must fail the
        // forbid (comments blank to spaces upstream, like whitespace).
        for invocation in [
            "    smuggled ! ();\n",
            "    smuggled! ();\n",
            "    mkacc! ();\n",
            "    mkacc ! ();\n",
            "    include! (\"extra_methods.rs\");\n",
            "    smuggled /*c*/ ! /*c*/ ();\n",
        ] {
            let mutated = code.replacen(
                "    pub fn new(",
                &format!("{invocation}    pub fn new("),
                1,
            );
            assert_ne!(mutated, code, "spacing mutation {invocation:?} must apply");
            assert!(
                check_handle_region_has_no_macros(&blank_rust_noise(&mutated)).is_err(),
                "forbid must reject the spaced invocation {invocation:?}"
            );
        }
        // Keyword-led unary `!` (fix round 5): `if !(...)` and `return
        // !(...)` are ordinary negation -- a strict keyword can never name
        // a macro, spaced or tight -- so each must pass the forbid.
        for stmt in [
            "    if !(ready) { return; }\n",
            "    if!(ready) { return; }\n",
            "    return !(ready);\n",
        ] {
            let mutated = code.replacen("    pub fn new(", &format!("{stmt}    pub fn new("), 1);
            assert_ne!(mutated, code, "unary mutation {stmt:?} must apply");
            check_handle_region_has_no_macros(&blank_rust_noise(&mutated))
                .expect("forbid must accept keyword-led unary `!`");
        }
        // Non-ASCII macro gaps and idents (fix round 5): `mm!` plus a
        // U+0085/U+200E gap, and a non-ASCII invocation (U+00E9
        // `!()`), all compile -- each must fail the forbid loudly.
        // Fixtures are byte-built (`char::from_u32`, never literal
        // non-ASCII) and byte-asserted.
        let lrm = char::from_u32(0x200E).expect("U+200E exists");
        let nel = char::from_u32(0x0085).expect("U+0085 exists");
        let eacute = char::from_u32(0xE9).expect("U+00E9 exists");
        let unicode: [(String, &[u8]); 3] = [
            (format!("    mm!{nel}();\n"), &[0xC2, 0x85]),
            (format!("    mm!{lrm}();\n"), &[0xE2, 0x80, 0x8E]),
            (format!("    {eacute}!();\n"), &[0xC3, 0xA9]),
        ];
        for (invocation, utf8) in unicode {
            assert!(
                invocation.as_bytes().windows(utf8.len()).any(|w| w == utf8),
                "fixture must carry the {utf8:02X?} bytes"
            );
            let mutated = code.replacen(
                "    pub fn new(",
                &format!("{invocation}    pub fn new("),
                1,
            );
            assert_ne!(mutated, code, "unicode mutation {invocation:?} must apply");
            assert!(
                check_handle_region_has_no_macros(&blank_rust_noise(&mutated)).is_err(),
                "forbid must fail loudly on non-ASCII: {invocation:?}"
            );
        }
    }

    /// Structural I6: the anchor handle exposes exactly its write-only
    /// API — no read method under any name, no second impl block, no
    /// trait impl anywhere in the file. Renamed reads (`get_slot`,
    /// `lookup_raw`, `AsRawFd`, manual `Debug`) all fail here, where the
    /// old exact-name grep passed. The interim teardown primitives
    /// (`remove`/`set_slot` plus their `update`/`delete` helpers) must be
    /// `#[cfg(test)]`-gated: unrestricted bookkeeping has no place in the
    /// non-test API (production teardown is W3-2's kernel-side
    /// slot/generation command). The literal `derive(Debug)` mutation
    /// test is kept below as well.
    #[test]
    fn anchor_handle_exposes_exact_write_api() {
        let root = std::path::Path::new(env!("CARGO_MANIFEST_DIR"));
        let rust =
            std::fs::read_to_string(root.join("src/attach/identity_iter.rs")).expect("read self");
        // Production code only: this test's own needles live in `mod tests`.
        // Noise-blanked throughout, so comments and strings shape neither
        // the predicates nor the enumeration.
        let blanked = blank_rust_noise(&rust);
        let code = blanked.split_once("mod tests").expect("test module").0;
        // Exactly one inherent impl, and no trait impl for the handle
        // anywhere in production code (manual `Debug`/`Display`/`AsRawFd`/
        // `Deref` included; `anchor_maps_implements_no_leak_traits`
        // backs this structurally for the whole crate). The scan sees
        // through comments and paths (`impl /*x*/ AnchorMaps`,
        // `for self::AnchorMaps`).
        assert_eq!(
            scan_anchor_impls(code).expect("real code scans"),
            (1, false),
            "exactly one inherent impl AnchorMaps block, no trait impl for it"
        );
        // The block's method names, exactly: any added method — read,
        // write, or otherwise — fails here.
        let offset = find_inherent_anchor_impl(code).expect("impl block");
        let (public, private, gated) = anchor_maps_api(&code[offset..]).expect("real code api");
        assert_eq!(
            public,
            BTreeSet::from([
                "new".to_string(),
                "remove".to_string(),
                "set_slot".to_string()
            ]),
            "public AnchorMaps API must stay exactly the write-only set"
        );
        assert_eq!(
            private,
            BTreeSet::from(["update".to_string(), "delete".to_string()]),
            "private AnchorMaps helpers must stay exactly update/delete"
        );
        assert_eq!(
            gated,
            BTreeSet::from([
                "remove".to_string(),
                "set_slot".to_string(),
                "update".to_string(),
                "delete".to_string()
            ]),
            "interim teardown must be #[cfg(test)]-gated out of the non-test API"
        );
        // Kept: the literal `Debug`-derive mutation test (M4), on the
        // blanked handle region (a `derive` in a comment cannot trip it).
        let handle = blank_rust_noise(
            rust.split_once("Write-only anchor handle")
                .expect("AnchorMaps block")
                .1
                .split_once("// aya loader")
                .expect("handle block end")
                .0,
        );
        for forbidden in ["derive(Debug)", "derive (Debug)"] {
            assert!(
                !handle.contains(forbidden),
                "AnchorMaps must not contain {forbidden:?}"
            );
        }
    }

    /// The pointer guard is exactly 2^56 and the page granule exactly
    /// 4 KiB: value pins so a guard-coarsening mutation (2^57 admits
    /// contract-forbidden addresses) fails structurally. Behavioral
    /// endpoints (start/end at exactly 2^56, the mid-range case, the
    /// below-guard accept) live in
    /// `pointer_guard_rejects_each_endpoint_at_2pow56`.
    #[test]
    fn pointer_guard_constant_is_exact() {
        assert_eq!(POINTER_GUARD, 1u64 << 56);
        assert_eq!(PAGE_GRANULE, 4096);
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
        // The constructor rejects non-map fds outright now; the raw
        // update/delete paths below still fail closed at the syscall.
        assert!(
            AnchorMaps::new(
                null.as_fd().try_clone_to_owned().expect("clone"),
                null.as_fd().try_clone_to_owned().expect("clone"),
            )
            .is_err(),
            "AnchorMaps::new on /dev/null must fail"
        );
        assert!(
            AnchorMaps::update(null.as_fd(), &1u64.to_ne_bytes(), &[0u8; 16]).is_err(),
            "map update on /dev/null must fail"
        );
        assert!(
            AnchorMaps::delete(null.as_fd(), &1u64.to_ne_bytes()).is_err(),
            "map delete on /dev/null must fail"
        );
    }

    /// `AnchorMaps::new` validates handles, not just ownership: a
    /// read-mode fd and a write-mode non-map fd must both fail — the
    /// first at the access-mode check, the second at `GET_INFO`.
    #[test]
    fn anchor_maps_reject_invalid_handles() {
        let null_ro = std::fs::File::open("/dev/null").expect("open /dev/null");
        // (`AnchorMaps` has no `Debug` by design, so `expect_err` is
        // unavailable: match explicitly instead.)
        let err = match AnchorMaps::new(
            null_ro.as_fd().try_clone_to_owned().expect("clone"),
            null_ro.as_fd().try_clone_to_owned().expect("clone"),
        ) {
            Ok(_) => panic!("read-mode fds must fail the WRONLY check"),
            Err(err) => err,
        };
        assert_eq!(err.raw_os_error(), Some(libc::EBADF));
        let null_wo = std::fs::OpenOptions::new()
            .write(true)
            .open("/dev/null")
            .expect("open /dev/null O_WRONLY");
        assert_ne!(
            unsafe { libc::fcntl(null_wo.as_raw_fd(), libc::F_GETFL) } & libc::O_ACCMODE,
            libc::O_RDONLY,
            "test needs a write-mode fd"
        );
        assert!(
            AnchorMaps::new(
                null_wo.as_fd().try_clone_to_owned().expect("clone"),
                null_wo.as_fd().try_clone_to_owned().expect("clone"),
            )
            .is_err(),
            "a write-mode non-map fd must fail GET_INFO validation"
        );
    }

    /// Test-only raw map creation (`BPF_MAP_CREATE` prefix
    /// `{type@0,key@4,value@8,max@12,flags@16}` per `linux/bpf.h`).
    fn test_create_map(
        map_type: u32,
        key_size: u32,
        value_size: u32,
        max_entries: u32,
        map_flags: u32,
    ) -> io::Result<OwnedFd> {
        #[repr(C)]
        struct CreateAttr {
            map_type: u32,
            key_size: u32,
            value_size: u32,
            max_entries: u32,
            map_flags: u32,
            reserved: [u64; 8],
        }
        let mut attr = CreateAttr {
            map_type,
            key_size,
            value_size,
            max_entries,
            map_flags,
            reserved: [0; 8],
        };
        let fd = bpf(
            BPF_MAP_CREATE,
            std::ptr::addr_of_mut!(attr).cast(),
            size_of::<CreateAttr>(),
        )?;
        // SAFETY: the syscall returned a new owned fd.
        Ok(unsafe { OwnedFd::from_raw_fd(fd) })
    }

    /// Privileged: the constructor accepts genuine `WRONLY` anchor maps
    /// and rejects every wrong handle — swapped roles, a size-mismatched
    /// map (the over-read shape: ARRAY 4/16 as `slots`), a readable map,
    /// and a non-map fd. Run as root with `--ignored`.
    #[test]
    #[ignore = "privileged: creates real BPF maps for handle validation"]
    fn anchor_maps_validate_real_handles() {
        // Genuine pair first: must construct.
        let hash = test_create_map(BPF_MAP_TYPE_HASH, 8, 16, ANCHOR_SLOTS, BPF_F_WRONLY)
            .expect("create WRONLY hash (run as root)");
        let slots = test_create_map(BPF_MAP_TYPE_ARRAY, 4, 8, ANCHOR_SLOTS, BPF_F_WRONLY)
            .expect("create WRONLY array (run as root)");
        let maps = AnchorMaps::new(
            hash.as_fd().try_clone_to_owned().expect("clone"),
            slots.as_fd().try_clone_to_owned().expect("clone"),
        )
        .expect("genuine WRONLY anchor maps construct");
        // Teardown primitives work on the real maps: slot bookkeeping
        // writes, and deleting an absent key fails ENOENT (already clear).
        maps.set_slot(0, 0x1234_5678)
            .expect("slot write on a real slots map");
        let err = maps
            .remove(0x1234_5678)
            .expect_err("absent key deletes fail");
        assert_eq!(err.raw_os_error(), Some(libc::ENOENT));
        // Swapped roles: the hash is no ARRAY and the slots no HASH.
        // (No `Debug` on `AnchorMaps`, so no `expect_err`: match instead.)
        let err = match AnchorMaps::new(
            slots.as_fd().try_clone_to_owned().expect("clone"),
            hash.as_fd().try_clone_to_owned().expect("clone"),
        ) {
            Ok(_) => panic!("swapped map roles must fail"),
            Err(err) => err,
        };
        assert_eq!(err.raw_os_error(), Some(libc::EINVAL));
        // Size-mismatched map as `slots`: ARRAY key 4 value 16. Without
        // validation, `set_slot` would hand the kernel an 8-byte buffer
        // for a 16-byte value — a stack over-read into the map.
        let wide = test_create_map(BPF_MAP_TYPE_ARRAY, 4, 16, ANCHOR_SLOTS, BPF_F_WRONLY)
            .expect("create WRONLY wide array");
        let err = match AnchorMaps::new(
            hash.as_fd().try_clone_to_owned().expect("clone"),
            wide.as_fd().try_clone_to_owned().expect("clone"),
        ) {
            Ok(_) => panic!("a value-16 map as slots must fail"),
            Err(err) => err,
        };
        assert_eq!(err.raw_os_error(), Some(libc::EINVAL));
        // Readable (non-WRONLY) maps: same shape, wrong access mode.
        let hash_rd = test_create_map(BPF_MAP_TYPE_HASH, 8, 16, ANCHOR_SLOTS, 0)
            .expect("create readable hash");
        let err = match AnchorMaps::new(
            hash_rd.as_fd().try_clone_to_owned().expect("clone"),
            slots.as_fd().try_clone_to_owned().expect("clone"),
        ) {
            Ok(_) => panic!("a readable hash fd must fail the WRONLY check"),
            Err(err) => err,
        };
        assert_eq!(err.raw_os_error(), Some(libc::EBADF));
        // Wrong capacity.
        let short = test_create_map(BPF_MAP_TYPE_ARRAY, 4, 8, 512, BPF_F_WRONLY)
            .expect("create short array");
        let err = match AnchorMaps::new(
            hash.as_fd().try_clone_to_owned().expect("clone"),
            short.as_fd().try_clone_to_owned().expect("clone"),
        ) {
            Ok(_) => panic!("a short slots map must fail"),
            Err(err) => err,
        };
        assert_eq!(err.raw_os_error(), Some(libc::EINVAL));
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

    /// The anchor program detects a mid-pass slot change — the anchor page
    /// remapped during the walk, or an overflow-discarded `DUP` followed by
    /// a replay carrying a new inode. A per-slot observed-generation marker
    /// distinguishes a current-pass change (contested: `CONFLICT`, installs
    /// nothing) from stale previous-pass bookkeeping (a legitimate
    /// between-passes reinstall). Structural pin on the C source: the guard
    /// must consult the observed map before installation. Behavioral
    /// C-logic coverage lives in the host harness
    /// (`anchor_host_harness_replay_and_arena_behavior`); live
    /// overflow-replay coverage needs attach + arena control (W3-2).
    #[test]
    fn anchor_program_guards_mid_pass_slot_changes() {
        let root = std::path::Path::new(env!("CARGO_MANIFEST_DIR"));
        let c = std::fs::read_to_string(root.join("crates/ebpf/native/vma_identity.c"))
            .expect("read C source");
        for needle in [
            "anchor_observed",
            "observed_cell == gen + 1",
            "old != addr",
            "*observed_cell = gen + 1",
        ] {
            assert!(
                c.contains(needle),
                "anchor C must contain the mid-pass guard piece {needle:?}"
            );
        }
        let guard = c.find("observed_cell == gen").expect("guard");
        let install = c.find("p11_map_update(&anchors").expect("install");
        assert!(
            guard < install,
            "the mid-pass guard must precede installation"
        );
    }

    /// Arena configs are validated before iteration: oversized slot
    /// counts, over-long arenas (the truncation shape), misaligned bases,
    /// wrapping ranges, and empty arenas with live slots all fail loudly.
    #[test]
    fn validate_arena_config_rejects_nonsense() {
        let good = IdentityConfig {
            generation: 7,
            arena_base: 0x7f00_0000_0000,
            arena_len: 4 * ANCHOR_STRIDE,
            slots: 4,
            observer_tgid: 4242,
        };
        assert_eq!(validate_arena_config(&good), Ok(()));
        // Full capacity is fine.
        let full = IdentityConfig {
            slots: ANCHOR_SLOTS,
            arena_len: u64::from(ANCHOR_SLOTS) * ANCHOR_STRIDE,
            ..good
        };
        assert_eq!(validate_arena_config(&full), Ok(()));
        // Zero slots with an empty arena is coherent (installs nothing).
        let idle = IdentityConfig {
            slots: 0,
            arena_len: 0,
            ..good
        };
        assert_eq!(validate_arena_config(&idle), Ok(()));
        let bad_slots = IdentityConfig {
            slots: ANCHOR_SLOTS + 1,
            ..good
        };
        assert_eq!(
            validate_arena_config(&bad_slots),
            Err(ArenaConfigError::TooManySlots)
        );
        let bad_len = IdentityConfig {
            arena_len: u64::from(ANCHOR_SLOTS) * ANCHOR_STRIDE + 1,
            ..good
        };
        assert_eq!(
            validate_arena_config(&bad_len),
            Err(ArenaConfigError::ArenaTooLong)
        );
        // The finding's trigger shape: an arena big enough for the slot
        // quotient to exceed u32.
        let huge = IdentityConfig {
            arena_len: (u64::from(u32::MAX) + 2) * ANCHOR_STRIDE,
            ..good
        };
        assert_eq!(
            validate_arena_config(&huge),
            Err(ArenaConfigError::ArenaTooLong)
        );
        let bad_base = IdentityConfig {
            arena_base: good.arena_base + 1,
            ..good
        };
        assert_eq!(
            validate_arena_config(&bad_base),
            Err(ArenaConfigError::BaseMisaligned)
        );
        let wrapped = IdentityConfig {
            arena_base: u64::MAX - 0x1000 + 1,
            arena_len: 0x2000,
            ..good
        };
        assert_eq!(
            validate_arena_config(&wrapped),
            Err(ArenaConfigError::RangeOverflow)
        );
        let empty = IdentityConfig {
            arena_len: 0,
            slots: 4,
            ..good
        };
        assert_eq!(
            validate_arena_config(&empty),
            Err(ArenaConfigError::EmptyArena)
        );
        // The round-2 finding's shape: a 1-byte arena cannot contain any
        // page VMA, yet the start-address filter alone would admit one.
        let sliver = IdentityConfig {
            arena_base: 0x1000,
            arena_len: 1,
            slots: 1,
            ..good
        };
        assert_eq!(
            validate_arena_config(&sliver),
            Err(ArenaConfigError::LenMisaligned)
        );
        // A single page cannot hold a stride-spaced slot either.
        let short = IdentityConfig {
            arena_len: PAGE_GRANULE,
            slots: 1,
            ..good
        };
        assert_eq!(
            validate_arena_config(&short),
            Err(ArenaConfigError::ArenaTooShort)
        );
        // Three strides cannot hold four slots.
        let narrow = IdentityConfig {
            arena_len: 3 * ANCHOR_STRIDE,
            slots: 4,
            ..good
        };
        assert_eq!(
            validate_arena_config(&narrow),
            Err(ArenaConfigError::ArenaTooShort)
        );
        // A larger-than-needed reservation stays coherent: extra strides
        // simply never install (their quotients miss the slot range).
        let roomy = IdentityConfig {
            arena_len: 5 * ANCHOR_STRIDE,
            slots: 4,
            ..good
        };
        assert_eq!(validate_arena_config(&roomy), Ok(()));
    }

    /// The anchor program enforces full VMA containment in the arena, not
    /// just the start address: a VMA starting inside the reservation but
    /// extending past its end is a shape failure, never an install.
    /// Structural pin (behavioral C-logic cases live in the host
    /// harness; live containment coverage needs attach, W3-2).
    #[test]
    fn anchor_program_enforces_vma_containment() {
        let root = std::path::Path::new(env!("CARGO_MANIFEST_DIR"));
        let c = std::fs::read_to_string(root.join("crates/ebpf/native/vma_identity.c"))
            .expect("read C source");
        assert!(
            c.contains("end > base + len"),
            "anchor C must check VMA end containment against the arena"
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

    // -- D2c BTF deny (RED-first) -------------------------------------------

    /// Byte-constructed minimal BTF blob: types appended in id order
    /// (1-based), strings NUL-terminated from offset 1 (offset 0 is the
    /// anonymous empty name). Pure ASCII fixtures; no real kernel bytes.
    struct BtfFixture {
        types: Vec<u8>,
        strings: Vec<u8>,
    }

    impl BtfFixture {
        fn new() -> Self {
            Self {
                types: Vec::new(),
                strings: vec![0],
            }
        }

        fn intern(&mut self, text: &str) -> u32 {
            let offset = self.strings.len() as u32;
            self.strings.extend_from_slice(text.as_bytes());
            self.strings.push(0);
            offset
        }

        fn header(&mut self, name_off: u32, kind: u32, vlen: u32, size_or_type: u32) {
            let info = (kind << 24) | (vlen & 0xFFFF);
            self.types.extend_from_slice(&name_off.to_le_bytes());
            self.types.extend_from_slice(&info.to_le_bytes());
            self.types.extend_from_slice(&size_or_type.to_le_bytes());
        }

        fn int(&mut self, name: &str) {
            let name_off = self.intern(name);
            self.header(name_off, 1, 0, 4);
            self.types.extend_from_slice(&0x0100_0020u32.to_le_bytes());
        }

        fn struct_with(&mut self, name: &str, members: &[(&str, u32, u32)]) {
            let name_off = self.intern(name);
            self.header(name_off, 4, members.len() as u32, 16);
            for (member, type_id, offset) in members {
                let member_off = self.intern(member);
                self.types.extend_from_slice(&member_off.to_le_bytes());
                self.types.extend_from_slice(&type_id.to_le_bytes());
                self.types.extend_from_slice(&offset.to_le_bytes());
            }
        }

        fn union_with(&mut self, name: &str, members: &[(&str, u32, u32)]) {
            let name_off = self.intern(name);
            self.header(name_off, 5, members.len() as u32, 8);
            for (member, type_id, offset) in members {
                let member_off = self.intern(member);
                self.types.extend_from_slice(&member_off.to_le_bytes());
                self.types.extend_from_slice(&type_id.to_le_bytes());
                self.types.extend_from_slice(&offset.to_le_bytes());
            }
        }

        fn func(&mut self, name: &str) {
            let name_off = self.intern(name);
            self.header(name_off, 12, 0, 1);
        }

        fn enum_with(&mut self, name: &str, values: &[(&str, u32)]) {
            let name_off = self.intern(name);
            self.header(name_off, 6, values.len() as u32, 4);
            for (value, number) in values {
                let value_off = self.intern(value);
                self.types.extend_from_slice(&value_off.to_le_bytes());
                self.types.extend_from_slice(&number.to_le_bytes());
            }
        }

        fn decl_tag(&mut self, name: &str, target: u32) {
            let name_off = self.intern(name);
            self.header(name_off, 17, 0, target);
            self.types.extend_from_slice(&0u32.to_le_bytes());
        }

        fn finish(&self) -> Vec<u8> {
            let mut out = Vec::new();
            out.extend_from_slice(&0xE_B9Fu16.to_le_bytes());
            out.push(0x01);
            out.push(0x00);
            out.extend_from_slice(&24u32.to_le_bytes());
            out.extend_from_slice(&0u32.to_le_bytes());
            out.extend_from_slice(&(self.types.len() as u32).to_le_bytes());
            out.extend_from_slice(&(self.types.len() as u32).to_le_bytes());
            out.extend_from_slice(&(self.strings.len() as u32).to_le_bytes());
            out.extend_from_slice(&self.types);
            out.extend_from_slice(&self.strings);
            out
        }
    }

    /// A vmlinux-shaped fixture: an INT (id 1), the task_vma seq struct
    /// (id 2, with or without `mm`), and the pid_fd witnesses.
    fn seq_info_fixture(with_mm: bool, with_func: bool, with_enum: bool) -> Vec<u8> {
        let mut fixture = BtfFixture::new();
        fixture.int("unsigned int");
        let mut members = vec![("task", 1, 0)];
        if with_mm {
            members.push(("mm", 1, 64));
        }
        fixture.struct_with(TASK_VMA_INFO_STRUCT, &members);
        if with_func {
            fixture.func(TASK_ITER_ATTACH_FUNC);
        }
        if with_enum {
            fixture.enum_with(TASK_ITER_TYPE_ENUM, &[("PID", 0)]);
        }
        fixture.finish()
    }

    #[test]
    fn btf_kind_consts_match_aya() {
        assert_eq!(
            BTF_KIND_STRUCT,
            aya_obj::btf::BtfKind::Struct as u32,
            "struct kind pins uapi"
        );
        assert_eq!(
            BTF_KIND_UNION,
            aya_obj::btf::BtfKind::Union as u32,
            "union kind pins uapi"
        );
        assert_eq!(
            BTF_KIND_ENUM,
            aya_obj::btf::BtfKind::Enum as u32,
            "enum kind pins uapi"
        );
        assert_eq!(
            BTF_KIND_FUNC,
            aya_obj::btf::BtfKind::Func as u32,
            "func kind pins uapi"
        );
    }

    #[test]
    fn btf_struct_member_matches_exactly() {
        let with = seq_info_fixture(true, true, false);
        assert!(
            btf_has_struct_member(&with, TASK_VMA_INFO_STRUCT, TASK_VMA_INFO_MM_MEMBER)
                .expect("valid fixture scans"),
            "the mm member must be found"
        );
        let without = seq_info_fixture(false, true, false);
        assert!(
            !btf_has_struct_member(&without, TASK_VMA_INFO_STRUCT, TASK_VMA_INFO_MM_MEMBER)
                .expect("valid fixture scans"),
            "a task-only struct must miss"
        );
        assert!(
            !btf_has_struct_member(&with, TASK_VMA_INFO_STRUCT, "task_struct")
                .expect("valid fixture scans"),
            "a wrong member must miss"
        );
        assert!(
            !btf_has_struct_member(&with, "bpf_iter_seq_task_info", TASK_VMA_INFO_MM_MEMBER)
                .expect("valid fixture scans"),
            "a wrong struct must miss"
        );
    }

    #[test]
    fn btf_struct_member_rejects_wrong_kind() {
        let mut fixture = BtfFixture::new();
        fixture.int("unsigned int");
        fixture.union_with(TASK_VMA_INFO_STRUCT, &[("mm", 1, 0)]);
        let blob = fixture.finish();
        assert!(
            !btf_has_struct_member(&blob, TASK_VMA_INFO_STRUCT, TASK_VMA_INFO_MM_MEMBER)
                .expect("valid fixture scans"),
            "a union is not the struct: deny direction"
        );
    }

    #[test]
    fn btf_walk_survives_decl_tag_records() {
        // A DECL_TAG between the INT and the struct: only the 4-byte
        // tail keeps the walk in sync (an 8-byte count desyncs here,
        // exactly as on real vmlinux at the first `bpf_fastcall` tag).
        let mut fixture = BtfFixture::new();
        fixture.int("unsigned int");
        fixture.decl_tag("bpf_fastcall", 1);
        fixture.struct_with(TASK_VMA_INFO_STRUCT, &[("task", 1, 0), ("mm", 1, 64)]);
        let blob = fixture.finish();
        assert!(
            btf_has_struct_member(&blob, TASK_VMA_INFO_STRUCT, TASK_VMA_INFO_MM_MEMBER)
                .expect("valid fixture scans"),
            "the struct past the tag must be found"
        );
    }

    #[test]
    fn btf_named_type_finds_func_and_enum() {
        let blob = seq_info_fixture(true, true, true);
        assert!(
            btf_has_named_type(&blob, BTF_KIND_FUNC, TASK_ITER_ATTACH_FUNC)
                .expect("valid fixture scans"),
        );
        assert!(
            btf_has_named_type(&blob, BTF_KIND_ENUM, TASK_ITER_TYPE_ENUM)
                .expect("valid fixture scans"),
        );
        assert!(
            !btf_has_named_type(&blob, BTF_KIND_FUNC, TASK_ITER_TYPE_ENUM)
                .expect("valid fixture scans"),
            "kind is part of the match"
        );
        let bare = seq_info_fixture(true, false, false);
        assert!(
            !btf_has_named_type(&bare, BTF_KIND_FUNC, TASK_ITER_ATTACH_FUNC)
                .expect("valid fixture scans"),
        );
    }

    #[test]
    fn btf_scan_rejects_malformed_blobs() {
        let good = seq_info_fixture(true, true, false);
        let mut bad_magic = good.clone();
        bad_magic[0] = 0x00;
        assert!(matches!(
            btf_has_struct_member(&bad_magic, TASK_VMA_INFO_STRUCT, "mm"),
            Err(BtfScanError::BadMagic)
        ));
        assert!(matches!(
            btf_has_struct_member(&good[..10], TASK_VMA_INFO_STRUCT, "mm"),
            Err(BtfScanError::TooShort)
        ));
        let mut bad_version = good.clone();
        bad_version[2] = 0x09;
        assert!(matches!(
            btf_has_struct_member(&bad_version, TASK_VMA_INFO_STRUCT, "mm"),
            Err(BtfScanError::BadHeader)
        ));
        let truncated = &good[..good.len() - 8];
        assert!(matches!(
            btf_has_struct_member(truncated, TASK_VMA_INFO_STRUCT, "mm"),
            Err(BtfScanError::Truncated | BtfScanError::BadString(_))
        ));
        let mut bad_kind = good.clone();
        // The struct header info word sits 4 bytes into the type
        // section (after the INT's 16 bytes): force an unknown kind.
        let info_at = 24 + 16 + 4;
        bad_kind[info_at + 3] = 0x1F;
        assert!(matches!(
            btf_has_struct_member(&bad_kind, TASK_VMA_INFO_STRUCT, "mm"),
            Err(BtfScanError::UnknownKind(31))
        ));
    }

    #[test]
    fn kernel_deny_labels_match_section_7() {
        assert_eq!(KernelDeny::FixMissing.label(), "kernel_fix_missing");
        assert_eq!(KernelDeny::NoTaskIterPidfd.label(), "no_task_iter_pidfd");
        assert_eq!(KernelDeny::NoBtf("gone".to_owned()).label(), "no_btf");
        let reason = KernelDeny::FixMissing.reason();
        assert!(
            reason.contains("kernel_fix_missing") && reason.contains("7ff94f276f8e"),
            "the fix text names the upstream commit, got {reason:?}"
        );
        assert!(
            !reason.contains("uname"),
            "the deny vocabulary never mentions uname, got {reason:?}"
        );
    }

    #[test]
    fn kernel_deny_gate_matrix() {
        assert!(
            check_kernel_identity_btf(&seq_info_fixture(true, true, false)).is_ok(),
            "mm + attach func allows"
        );
        assert!(
            check_kernel_identity_btf(&seq_info_fixture(true, false, true)).is_ok(),
            "mm + task-type enum allows (pid_fd fallback witness)"
        );
        assert!(
            matches!(
                check_kernel_identity_btf(&seq_info_fixture(false, true, false)),
                Err(KernelDeny::FixMissing)
            ),
            "task-only struct denies even with the attach func"
        );
        assert!(
            matches!(
                check_kernel_identity_btf(&seq_info_fixture(true, false, false)),
                Err(KernelDeny::NoTaskIterPidfd)
            ),
            "mm without any pid_fd witness denies"
        );
        assert!(
            matches!(
                check_kernel_identity_btf(&[0u8; 64]),
                Err(KernelDeny::FixMissing)
            ),
            "an unscannable blob denies as fix-missing (fail closed)"
        );
    }

    #[test]
    fn kernel_deny_never_consults_uname() {
        let root = std::path::Path::new(env!("CARGO_MANIFEST_DIR"));
        let source = std::fs::read_to_string(root.join("src/attach/identity_iter.rs"))
            .expect("read own source");
        // Split spellings: the token list itself must not contain the
        // tokens it forbids.
        let tokens = [
            concat!("libc::", "uname"),
            concat!("uts", "name"),
            concat!("Uts", "Name"),
            concat!("gethost", "name"),
            concat!("/proc/", "version"),
        ];
        for token in tokens {
            assert!(
                !source.contains(token),
                "the deny path must never consult {token:?}"
            );
        }
    }

    #[test]
    fn kernel_deny_host_btf_is_eligible() {
        match std::fs::read(VMLINUX_BTF_PATH) {
            Ok(bytes) => assert!(
                check_kernel_identity_btf(&bytes).is_ok(),
                "gate hosts (6.1.8+/6.2+) carry the mm fix; deny paths are pinned by fixtures and guest cells"
            ),
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
                assert!(
                    matches!(read_vmlinux_btf(), Err(KernelDeny::NoBtf(_))),
                    "missing BTF denies as no_btf"
                );
            }
            Err(error) => panic!("host BTF unreadable: {error}"),
        }
    }

    // -- D2c EPERM on WRONLY fds (RED-first) ----------------------------------

    /// Borrow a loaded identity map's fd. Panics loudly on a missing map
    /// or an unexpected variant: the object contract pins both.
    #[cfg(test)]
    fn loaded_map_fd<'a>(ebpf: &'a aya::Ebpf, name: &str) -> BorrowedFd<'a> {
        let map = ebpf
            .map(name)
            .unwrap_or_else(|| panic!("{name} map missing from the loaded object"));
        let data = match map {
            aya::maps::Map::HashMap(data) | aya::maps::Map::Array(data) => data,
            _ => panic!("{name} map has an unexpected variant"),
        };
        data.fd().as_fd()
    }

    /// Raw `BPF_MAP_LOOKUP_ELEM` through `fd`. Test-only: production code
    /// must never read the anchor maps (I6).
    #[cfg(test)]
    fn raw_map_lookup(fd: BorrowedFd<'_>, key: &[u8], value: &mut [u8]) -> io::Result<()> {
        let mut attr = MapElemAttr {
            map_fd: fd.as_raw_fd() as u32,
            reserved: 0,
            key: key.as_ptr().addr() as u64,
            value: value.as_mut_ptr().addr() as u64,
            flags: 0,
        };
        bpf(
            BPF_MAP_LOOKUP_ELEM,
            std::ptr::addr_of_mut!(attr).cast(),
            size_of::<MapElemAttr>(),
        )?;
        Ok(())
    }

    /// Raw `BPF_MAP_GET_NEXT_KEY` through `fd`: `None` asks for the first
    /// key. Test-only (I6).
    #[cfg(test)]
    fn raw_map_next_key(fd: BorrowedFd<'_>, key: Option<&[u8]>, next: &mut [u8]) -> io::Result<()> {
        let mut attr = MapElemAttr {
            map_fd: fd.as_raw_fd() as u32,
            reserved: 0,
            key: key.map_or(0, |key| key.as_ptr().addr() as u64),
            value: next.as_mut_ptr().addr() as u64,
            flags: 0,
        };
        bpf(
            BPF_MAP_GET_NEXT_KEY,
            std::ptr::addr_of_mut!(attr).cast(),
            size_of::<MapElemAttr>(),
        )?;
        Ok(())
    }

    /// Raw `BPF_MAP_LOOKUP_AND_DELETE_ELEM` through `fd`. Test-only (I6).
    /// On a WRONLY fd the permission check fires before any map-type
    /// dispatch, so nothing is ever deleted here.
    #[cfg(test)]
    fn raw_map_lookup_and_delete(
        fd: BorrowedFd<'_>,
        key: &[u8],
        value: &mut [u8],
    ) -> io::Result<()> {
        let mut attr = MapElemAttr {
            map_fd: fd.as_raw_fd() as u32,
            reserved: 0,
            key: key.as_ptr().addr() as u64,
            value: value.as_mut_ptr().addr() as u64,
            flags: 0,
        };
        bpf(
            BPF_MAP_LOOKUP_AND_DELETE_ELEM,
            std::ptr::addr_of_mut!(attr).cast(),
            size_of::<MapElemAttr>(),
        )?;
        Ok(())
    }

    /// Raw single-element `BPF_MAP_LOOKUP_BATCH` through `fd`, starting
    /// from the beginning. Returns the filled count. Test-only (I6).
    #[cfg(test)]
    fn raw_map_lookup_batch(
        fd: BorrowedFd<'_>,
        keys: &mut [u8],
        values: &mut [u8],
    ) -> io::Result<u32> {
        let mut out_batch = [0u8; 8];
        let mut attr = MapBatchAttr {
            in_batch: 0,
            out_batch: out_batch.as_mut_ptr().addr() as u64,
            keys: keys.as_mut_ptr().addr() as u64,
            values: values.as_mut_ptr().addr() as u64,
            count: 1,
            map_fd: fd.as_raw_fd() as u32,
            elem_flags: 0,
            flags: 0,
        };
        bpf(
            BPF_MAP_LOOKUP_BATCH,
            std::ptr::addr_of_mut!(attr).cast(),
            size_of::<MapBatchAttr>(),
        )?;
        Ok(attr.count)
    }

    #[cfg(test)]
    fn assert_eperm(result: io::Result<()>, operation: &str, map: &str) {
        match result {
            Ok(()) => panic!("{operation} on WRONLY map {map} unexpectedly succeeded"),
            Err(error) => assert_eq!(
                error.raw_os_error(),
                Some(libc::EPERM),
                "{operation} on WRONLY map {map} must fail EPERM"
            ),
        }
    }

    /// D2c/I6: every syscall read through the loaded object's WRONLY
    /// anchor-map fds fails with `EPERM` (F3): lookup, get-next-key,
    /// lookup-and-delete, and batch lookup, on all three WRONLY maps
    /// (`anchors`, `anchor_slots`, `anchor_observed`). The readable
    /// `config` map is the non-vacuity control: the same syscalls there
    /// succeed, proving the test issues well-formed calls. Run as root
    /// with `--ignored`: the strict load fails loudly without privileges
    /// and the test never passes vacuously.
    #[test]
    #[ignore = "privileged: WRONLY anchor fds refuse all syscall reads with EPERM"]
    fn wronly_anchor_fds_refuse_reads_with_eperm() {
        let btf = aya::Btf::from_sys_fs().expect("EPERM gate requires readable host BTF");
        let loaded =
            load_identity_object_strict(&btf).expect("EPERM gate requires the strict load");
        // (name, key bytes, value bytes) per WRONLY map, from the object
        // contract (`identity_object_has_two_iter_programs_and_five_maps`).
        for (name, key_len, value_len) in [
            ("anchors", 8usize, 16usize),
            ("anchor_slots", 4, 8),
            ("anchor_observed", 4, 8),
        ] {
            let fd = loaded_map_fd(&loaded.ebpf, name);
            let key = vec![0u8; key_len];
            let mut value = vec![0u8; value_len];
            assert_eperm(raw_map_lookup(fd, &key, &mut value), "lookup", name);
            let mut next = vec![0u8; key_len];
            assert_eperm(raw_map_next_key(fd, None, &mut next), "get_next_key", name);
            assert_eperm(
                raw_map_lookup_and_delete(fd, &key, &mut value),
                "lookup_and_delete",
                name,
            );
            let mut batch_keys = vec![0u8; key_len];
            let mut batch_values = vec![0u8; value_len];
            match raw_map_lookup_batch(fd, &mut batch_keys, &mut batch_values) {
                Ok(count) => panic!("batch lookup on WRONLY map {name} filled {count}"),
                Err(error) => assert_eq!(
                    error.raw_os_error(),
                    Some(libc::EPERM),
                    "batch lookup on WRONLY map {name} must fail EPERM"
                ),
            }
        }
        // Non-vacuity control: the readable `config` ARRAY (key 4, value
        // 32, one entry) answers the same calls.
        let config = loaded_map_fd(&loaded.ebpf, "config");
        let key = [0u8; 4];
        let mut value = [0u8; 32];
        raw_map_lookup(config, &key, &mut value).expect("readable-map lookup succeeds");
        let mut next = [0xFFu8; 4];
        raw_map_next_key(config, None, &mut next).expect("readable-map next-key succeeds");
        assert_eq!(next, [0, 0, 0, 0], "the first (only) config key is 0");
        let mut batch_keys = [0u8; 4];
        let mut batch_values = [0u8; 32];
        let filled = raw_map_lookup_batch(config, &mut batch_keys, &mut batch_values)
            .expect("readable-map batch lookup succeeds");
        assert_eq!(filled, 1, "the one config entry is returned");
    }

    // -- D2c arena + functional probe (RED-first) ------------------------------

    #[cfg(test)]
    fn probe_tempdir() -> tempfile::TempDir {
        let dir = tempfile::tempdir().expect("probe tempdir");
        std::fs::set_permissions(
            dir.path(),
            std::os::unix::fs::PermissionsExt::from_mode(0o700),
        )
        .expect("chmod 0700");
        dir
    }

    /// Own-VMA shapes overlapping `[base, base + len)`: `(start, end,
    /// perms, path)` per line, in maps order.
    #[cfg(test)]
    fn own_reservation_shape(base: u64, len: u64) -> Vec<(u64, u64, String, String)> {
        let maps = std::fs::read_to_string("/proc/self/maps").expect("read own maps");
        let mut shape = Vec::new();
        for line in maps.lines() {
            let mut fields = line.split_whitespace();
            let range = fields.next().unwrap_or("");
            let perms = fields.next().unwrap_or("").to_owned();
            let (start, end) = range.split_once('-').unwrap_or(("0", "0"));
            let start = u64::from_str_radix(start, 16).unwrap_or(0);
            let end = u64::from_str_radix(end, 16).unwrap_or(0);
            if start < base + len && end > base {
                let path = fields.nth(3).unwrap_or("").to_owned();
                shape.push((start, end, perms, path));
            }
        }
        shape
    }

    #[test]
    fn anchor_arena_maps_and_releases_slots() {
        let dir = probe_tempdir();
        let file = dir.path().join("anchor-a");
        let content: Vec<u8> = (0..4096u32).map(|i| (i % 251) as u8).collect();
        std::fs::write(&file, &content).expect("write anchor file");
        let arena = AnchorArena::reserve(4).expect("reserve 4 slots");
        assert_eq!(arena.base() & (PAGE_GRANULE - 1), 0, "page-aligned base");
        assert_eq!(arena.len(), 4 * ANCHOR_STRIDE);
        assert_eq!(arena.slot_page(1), Some(arena.base() + ANCHOR_STRIDE));
        assert_eq!(arena.slot_page(4), None);
        let opened = std::fs::File::open(&file).expect("open anchor file");
        arena.map_slot(1, opened.as_fd()).expect("map slot 1");
        // The mapped bytes are readable at the slot page.
        let slot = arena.slot_page(1).expect("slot 1 page");
        let bytes = unsafe { std::slice::from_raw_parts(slot as *const u8, 4096) };
        assert_eq!(bytes, content.as_slice(), "the slot page shows the file");
        // The no-merge shape: guard pair, file page, rest.
        let shape = own_reservation_shape(arena.base(), arena.len());
        assert_eq!(shape.len(), 3, "one split triple, got {shape:?}");
        assert_eq!(
            (shape[0].0, shape[0].1),
            (arena.base(), arena.base() + 8192)
        );
        assert_eq!(shape[0].2, "---p");
        assert_eq!(
            (shape[1].0, shape[1].1),
            (arena.base() + 8192, arena.base() + 12288)
        );
        assert_eq!(shape[1].2, "r--p");
        assert_eq!(shape[1].3, file.to_string_lossy());
        assert_eq!(
            (shape[2].0, shape[2].1),
            (arena.base() + 12288, arena.base() + 32768)
        );
        assert_eq!(shape[2].2, "---p");
        // The arena's config validates for a 2-slot pass.
        let config = arena.config(7, 2, 1234);
        assert_eq!(config.generation, 7);
        assert_eq!(config.arena_base, arena.base());
        assert_eq!(config.slots, 2);
        assert_eq!(config.observer_tgid, 1234);
        validate_arena_config(&config).expect("arena config validates");
        arena.release_slot(1).expect("release slot 1");
        let merged = own_reservation_shape(arena.base(), arena.len());
        assert_eq!(
            merged.len(),
            1,
            "release rejoins the reservation, got {merged:?}"
        );
        assert_eq!(
            (merged[0].0, merged[0].1),
            (arena.base(), arena.base() + 32768)
        );
        assert_eq!(merged[0].2, "---p");
    }

    #[test]
    fn anchor_arena_rejects_bad_shapes() {
        assert!(AnchorArena::reserve(0).is_err(), "zero slots rejects");
        assert!(
            AnchorArena::reserve(ANCHOR_SLOTS + 1).is_err(),
            "over-cap rejects"
        );
        let full = AnchorArena::reserve(ANCHOR_SLOTS).expect("full reserve");
        assert!(full.slot_page(ANCHOR_SLOTS - 1).is_some());
        assert_eq!(full.slot_page(ANCHOR_SLOTS), None);
        let arena = AnchorArena::reserve(2).expect("reserve 2");
        let dir = probe_tempdir();
        let file = dir.path().join("f");
        std::fs::write(&file, [7u8; 64]).expect("write");
        let opened = std::fs::File::open(&file).expect("open");
        assert!(
            arena.map_slot(2, opened.as_fd()).is_err(),
            "slot == slots rejects"
        );
        assert!(
            arena.release_slot(2).is_err(),
            "release past the end rejects"
        );
        assert_eq!(arena.slot_page(2), None);
    }

    /// The child's reported addresses must be the starts of its three
    /// `r-xp` probe-file ranges (validates the address-report channel the
    /// privileged probe joins on). Unprivileged.
    #[test]
    fn probe_child_maps_probe_files_executable() {
        let dir = probe_tempdir();
        let fixture = write_probe_fixture(dir.path()).expect("fixture");
        let paths = [&fixture.hardlink, &fixture.b, &fixture.copy];
        let mut child =
            spawn_exec_mapping_child(&paths.map(std::path::PathBuf::from)).expect("spawn child");
        assert_eq!(child.addrs().len(), 3, "one address per mapping");
        let mut seen = std::collections::BTreeSet::new();
        for addr in child.addrs() {
            assert_eq!(addr & (PAGE_GRANULE - 1), 0, "page-aligned mapping");
            assert!(seen.insert(addr), "distinct mappings");
        }
        let maps = std::fs::read_to_string(format!("/proc/{}/maps", child.pid()))
            .expect("read child maps");
        for (path, addr) in paths.iter().zip(child.addrs().iter()) {
            let mut hits = 0;
            for line in maps.lines() {
                let mut fields = line.split_whitespace();
                let range = fields.next().unwrap_or("");
                let perms = fields.next().unwrap_or("");
                let tail: Vec<&str> = fields.collect();
                if tail.last() == Some(&path.to_string_lossy().as_ref()) && perms.contains('x') {
                    let (start, _) = range.split_once('-').expect("maps range");
                    let start = u64::from_str_radix(start, 16).expect("maps start");
                    assert_eq!(&start, addr, "reported address starts the VMA");
                    hits += 1;
                }
            }
            assert_eq!(hits, 1, "exactly one exec VMA for {}", path.display());
        }
        child.reap();
    }

    /// §6.5 on the host: a hard link to an anchored file reads back its
    /// slot, a byte-identical copy reads NONE, and a stale generation
    /// reads NONE everywhere (the `gen`-check probe). Run as root with
    /// `--ignored`.
    #[test]
    #[ignore = "privileged: functional probe proves hardlink-match vs copy-NONE"]
    fn functional_probe_proves_hardlink_match_and_copy_none() {
        ensure_kernel_identity_btf().expect("the probe needs an eligible kernel");
        let btf = aya::Btf::from_sys_fs().expect("readable host BTF");
        let mut loaded = load_identity_object_strict(&btf).expect("strict load");
        let dir = probe_tempdir();
        let report = run_functional_probe(dir.path(), &mut loaded, 1).expect("probe runs");
        assert_eq!(
            report.anchor_outcomes,
            vec![(0, AnchorOutcome::Ok), (1, AnchorOutcome::Ok)],
            "both slots install exactly once"
        );
        assert_eq!(report.hardlink_verdict, TargetVerdict::Slot(0));
        assert_eq!(report.second_verdict, TargetVerdict::Slot(1));
        assert_eq!(report.copy_verdict, TargetVerdict::Unmatched);
        assert_eq!(
            report.pids_seen,
            vec![report.child_pid],
            "only the child emits"
        );
        assert_eq!(
            report.child_unmatched_count + 2,
            report.child_record_count,
            "only the two anchored ranges match; every inherited VMA is NONE"
        );
        assert!(report.demoted_pids.is_empty(), "no conflicting duplicates");
        assert!(report.stale_unmatched, "the stale generation reads NONE");
        eprintln!(
            "W3-2 functional probe: child {} emitted {} records ({} NONE), \
             hardlink=slot0 second=slot1 copy=NONE stale=all-NONE",
            report.child_pid, report.child_record_count, report.child_unmatched_count,
        );
    }
}
