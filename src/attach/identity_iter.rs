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
    /// an operand: identifier, number, `)`, `]`, or a second `&`), with
    /// an identifier after it (whitespace allowed).
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
                let unary = prev.is_none_or(|c| {
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
    /// each other. C block comments do not nest.
    fn strip_c_noise(text: &str) -> String {
        let bytes = text.as_bytes();
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
                out.push(b' ');
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
    /// Through-deref stores (`*p = …`) of tainted values fail unless the
    /// statement is the exact bookkeeping allowlist (`*slot_cell =
    /// addr`); `record.*` stores feed `seq_write` and are checked;
    /// `p.f`, `p->f`, `a[i]` stores stay map/struct writes outside the
    /// envelope (with wrapper functions and inter-procedural flows —
    /// all pin-backstopped; see the test docs).
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
                    // `}`/`{`/`)` from control flow before its
                    // assignment, e.g. `}\n *slot_cell = addr`).
                    let core = lhs
                        .rsplit(['{', '}', '(', ')', ','])
                        .next()
                        .unwrap_or(&lhs)
                        .trim();
                    let target = core
                        .trim_end_matches(['+', '-', '*', '/', '%', '&', '|', '^', '<', '>'])
                        .trim();
                    let compound = target != core;
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
                    } else if !SOURCES.contains(&name) {
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

    /// The kernel never receives an inode address in a record struct: the
    /// record fields are exactly the ABI names, `seq_write` passes
    /// `&record`, and no `emit(...)` argument smuggles an inode-derived
    /// value into an existing record field — directly, or renamed through
    /// an assignment (`start = addr`) the argument text hides. Producer
    /// mutations (an inode address into `start`, into the DUP alias
    /// field, through a pre-emit assignment, through an intermediate)
    /// must fail the audit — proven by mutating the real sources in
    /// memory.
    #[test]
    fn kernel_records_carry_no_inode_addresses() {
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
        // Producer mutation 7: split-line assignment — `start =` /
        // `addr;` must taint across the line break, not clear on an
        // empty-looking rhs.
        let mutated = c.replacen(
            "    emit(ctx, P11_IDENT_KIND_VMA, tgid_u, start, end, verdict,",
            "    start\n    = addr;\n    emit(ctx, P11_IDENT_KIND_VMA, tgid_u, start, end, verdict,",
            1,
        );
        assert_ne!(mutated, c, "mutation 7 must apply");
        assert!(
            audit_identity_c_source(&mutated, path).is_err(),
            "mutation 7 (split-line assignment) must fail the audit"
        );
        // Producer mutation 8: binary `&` is not address-of —
        // `start = ~0ULL & addr` must taint, spaced or spaceless.
        for rhs in ["~0ULL & addr", "~0ULL&addr"] {
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
            let raw_hashes = |at: usize| -> Option<(usize, usize)> {
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
                Some((at, cursor + 1))
            };
            if let Some((start, contents)) = raw_hashes(index) {
                for byte in &bytes[start..contents] {
                    out.push(*byte);
                }
                let mut hashes = 0;
                let mut probe = start + usize::from(bytes[start] == b'b') + 1;
                while bytes.get(probe) == Some(&b'#') {
                    hashes += 1;
                    probe += 1;
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
                            for _ in 0..hashes {
                                out.push(b'#');
                            }
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

    /// Parse one `impl AnchorMaps` method line: `Some((name, public,
    /// same_line_gate))` for any visibility/modifier spelling (`fn`, `pub
    /// fn`, `pub(crate) fn`, `pub const fn`, `const unsafe fn`, ...),
    /// `None` otherwise. Leading same-line attributes (`#[inline] pub
    /// fn …`) are scanned past to the item start, and a same-line
    /// `#[cfg(test)]` gate is reported. Only lines that START an item
    /// match — a method body cannot start with these qualifiers, so `let
    /// f: fn(u32)` inside a body never matches — and `fn` must be
    /// followed by a name plus `(` or `<`.
    fn parse_impl_method(line: &str) -> Option<(String, bool, bool)> {
        let code = strip_line_noise(line);
        let mut rest = code.trim_start();
        let mut same_line_gate = false;
        loop {
            let probe = rest.trim_start();
            if !probe.starts_with("#[") {
                rest = probe;
                break;
            }
            // Strip one balanced `#[…]` span (string-aware, for
            // `#[doc = "…[…]…"]`).
            let bytes = probe.as_bytes();
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
            let Some(end) = end else {
                return None;
            };
            let flat: String = probe[..=end]
                .chars()
                .filter(|c| !c.is_whitespace())
                .collect();
            if flat == "#[cfg(test)]" {
                same_line_gate = true;
            }
            rest = &probe[end + 1..];
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
        // `before` must be qualifiers only: strip one balanced `pub(...)`
        // span, then every remaining token must be a plain qualifier.
        let mut qualifiers = before.to_string();
        if let Some(start) = qualifiers.find("pub(") {
            let tail = &qualifiers[start..];
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
            qualifiers.replace_range(start..start + end?, " ");
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
    /// of `text`: the path plus the remainder, or `None`.
    fn read_rust_path(text: &str) -> Option<(String, &str)> {
        let mut rest = text.strip_prefix("::").unwrap_or(text);
        let mut path = String::new();
        loop {
            let name: String = rest
                .chars()
                .take_while(|c| c.is_alphanumeric() || *c == '_')
                .collect();
            if name.is_empty() || name.chars().next().is_some_and(|c| c.is_numeric()) {
                return None;
            }
            path.push_str(&name);
            rest = &rest[name.len()..];
            if let Some(tail) = rest.strip_prefix("::") {
                path.push_str("::");
                rest = tail;
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
        let tail = tail.trim_start();
        if let Some(tail) = strip_rust_word(tail, "for") {
            let tail = tail.trim_start();
            let Some((subject, _)) = read_rust_path(tail) else {
                return (false, true);
            };
            let last = subject.rsplit("::").next().unwrap_or(&subject);
            return (false, last == "AnchorMaps");
        }
        let last = path.rsplit("::").next().unwrap_or(&path);
        (last == "AnchorMaps", false)
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

    /// Scan production code for `impl` blocks touching `AnchorMaps`:
    /// (inherent-block count, any-trait-impl). Matches trait impls on
    /// `for` + optional path + `AnchorMaps` (`for self::AnchorMaps`,
    /// `for crate::x::AnchorMaps`), and inherent blocks under any
    /// qualifier/generic spelling. Exotic headers that defeat the
    /// strict parse fall back to a conservative substring heuristic —
    /// never to silence.
    fn scan_anchor_impls(code: &str) -> (usize, bool) {
        let mut inherent = 0;
        let mut trait_impl = false;
        for (_, is_trait) in anchor_impls(code) {
            if is_trait {
                trait_impl = true;
            } else {
                inherent += 1;
            }
        }
        (inherent, trait_impl)
    }

    /// Byte offset of the inherent `impl AnchorMaps` keyword in
    /// noise-blanked production `code`, or `None`.
    fn find_inherent_anchor_impl(code: &str) -> Option<usize> {
        anchor_impls(code)
            .into_iter()
            .find_map(|(at, is_trait)| (!is_trait).then_some(at))
    }

    /// Forbid macros in the handle region: no `macro_rules` in
    /// production code at all, and no macro invocations inside the
    /// `impl AnchorMaps` block except the two allowlisted
    /// `std::ptr::addr_of_mut!` call sites (pinned by count). An
    /// invocation is `!` preceded by an identifier char and followed by
    /// `(`, `[`, or `{` — `!=` and unary `!` never match. Returns the
    /// rejection reason instead of panicking so proofs can assert
    /// rejection.
    fn check_handle_region_has_no_macros(code: &str) -> Result<(), String> {
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
                let prev = bytes.get(index.wrapping_sub(1)).copied().unwrap_or(b' ');
                let next = bytes.get(index + 1).copied().unwrap_or(b' ');
                let prev_ident = prev.is_ascii_alphanumeric() || prev == b'_';
                let next_delim = next == b'(' || next == b'[' || next == b'{';
                if prev_ident && next_delim {
                    let mut start = index;
                    while start > 0
                        && (bytes[start - 1].is_ascii_alphanumeric()
                            || bytes[start - 1] == b'_'
                            || bytes[start - 1] == b':')
                    {
                        start -= 1;
                    }
                    if &region[start..index] == "std::ptr::addr_of_mut" {
                        allowlisted += 1;
                    } else {
                        return Err(format!(
                            "macro invocation in the handle region: {}!",
                            &region[start..index]
                        ));
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

    fn anchor_maps_api(block: &str) -> (BTreeSet<String>, BTreeSet<String>, BTreeSet<String>) {
        let end = impl_block_end(block);
        let mut public = BTreeSet::new();
        let mut private = BTreeSet::new();
        let mut gated = BTreeSet::new();
        let mut previous = String::new();
        for line in block[..end].lines() {
            // The gate attribute sits immediately above its method — or
            // on the same line ahead of it.
            let prev_gated = previous.trim_start() == "#[cfg(test)]";
            if let Some((name, is_public, same_line_gate)) = parse_impl_method(line) {
                if prev_gated || same_line_gate {
                    gated.insert(name.clone());
                }
                if is_public {
                    public.insert(name);
                } else {
                    private.insert(name);
                }
            }
            previous = strip_line_noise(line);
        }
        (public, private, gated)
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
            let (public, _, _) = api_of(&mutated);
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
        let (public, _, _) = api_of(&hidden);
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
        let (public, _, _) = api_of(&attributed);
        assert!(
            public.contains("smuggled_attr"),
            "enumeration must parse fn after same-line attributes"
        );
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
            scan_anchor_impls(code),
            (1, false),
            "real code: exactly one inherent block, no trait impl"
        );
        let slf = format!("{code}\nimpl std::fmt::Debug for self::AnchorMaps {{}}\n");
        assert!(
            scan_anchor_impls(&blank_rust_noise(&slf)).1,
            "`for self::AnchorMaps` must read as a trait impl"
        );
        let commented = format!("{code}\nimpl Foo for /*x*/ AnchorMaps {{}}\n");
        assert!(
            scan_anchor_impls(&blank_rust_noise(&commented)).1,
            "commented `for` impl must read as a trait impl"
        );
        let second = format!("{code}\nimpl /*x*/ AnchorMaps {{}}\n");
        assert_eq!(
            scan_anchor_impls(&blank_rust_noise(&second)).0,
            2,
            "commented inherent impl must count"
        );
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
        let (public, private, _) = anchor_maps_api(&blanked_mut[offset..]);
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
            scan_anchor_impls(&blanked_mut),
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
            scan_anchor_impls(code),
            (1, false),
            "exactly one inherent impl AnchorMaps block, no trait impl for it"
        );
        // The block's method names, exactly: any added method — read,
        // write, or otherwise — fails here.
        let offset = find_inherent_anchor_impl(code).expect("impl block");
        let (public, private, gated) = anchor_maps_api(&code[offset..]);
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
}
