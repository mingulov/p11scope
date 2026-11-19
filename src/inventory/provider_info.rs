//! SPDX-License-Identifier: GPL-3.0-or-later
//! SPDX-FileCopyrightText: 2026 Denis Mingulov <denis@mingulov.com>
//! Userspace half of v0.8.0 keymeta Task 7 (spec §17): 176-byte INFO
//! record decode, padded-string parsing, the (module, caller,
//! slot[, mechanism]) join and the section-version-8 projection
//! (`modules[].provider_info` plus the top-level
//! `provider_observations` section).
//!
//! TODO(Task 7 BPF half, attach + session): the `INFO_START` / `INFO` /
//! `INFO_KIND` / `INFO_EVIDENCE` maps, the inventory program list
//! 12→15, the per-group info returns with EMFILE deferral, and the
//! INFO drain in the inventory session land after the Task 2 merge.
//! The drain feeds [`decode_info_record`] + [`InfoJoin::ingest`]
//! (resolving endpoint → module and the header identity → caller
//! incarnation itself) and calls [`InfoJoin::note_aliased_endpoint`] /
//! [`InfoJoin::note_return_deferred`] for the attach-side gaps. The
//! shared adapters, read lists and wire codes live in
//! `p11scope_ebpf_common::inventory_info` / `object_flow`; the
//! root-crate LP64 cross-check pins them against cryptoki-sys. Until
//! the drain lands, this module's decode/join surface is test-driven
//! only.

#![allow(dead_code)] // TODO(Task 7 BPF half): remove once the INFO drain feeds the join.

use crate::discovery::caller_registry::instance_input::RegistryInstanceId;
use crate::discovery::caller_registry::{CallerId, ModuleId};
use p11scope_ebpf_common::inventory_info::{
    INFO_HEADER_LEN, INFO_KIND_MECHANISM, INFO_KIND_PROVIDER, INFO_KIND_TOKEN, INFO_LAYOUT_ILP32,
    INFO_LAYOUT_LP64, INFO_PAYLOAD_MAX, INFO_RECORD_LEN, INFO_STATUS_OK, INFO_STATUS_UNAVAILABLE,
    INFO_VERSION, InfoTrailer,
};
use std::collections::{BTreeMap, BTreeSet, VecDeque};
/// Named reason on a padded string refused for non-UTF8 bytes.
pub(crate) const INFO_STRING_NON_UTF8: &str = "non_utf8_bytes";
/// Departed-INFO rows retired per fold call (spec §17.5, INV-2):
/// one bounded slice per call, resumable across calls, so a single
/// caller can never stall a pass no matter how many rows it owns.
pub(crate) const INFO_FOLD_ROWS_PER_CALL: usize = 64;
/// Mechanism rows kept per (module, caller, slot); extras refuse.
pub(crate) const INFO_MAX_MECHANISMS_PER_SLOT: usize = 128;
/// Token rows kept run-wide; new rows past this refuse with the
/// named `info_token_rows_refused` gap. Mirrors the retained-table
/// caller/module bound (`DEFAULT_MAX_CALLERS`).
pub(crate) const INFO_MAX_TOKEN_ROWS: usize = 4096;
/// Mechanism rows kept run-wide beside the per-slot cap; new rows
/// past this refuse with the named `info_mechanism_rows_refused`
/// gap. Mirrors the retained-table edge bound (`DEFAULT_MAX_EDGES`).
pub(crate) const INFO_MAX_MECHANISM_ROWS: usize = 32768;
/// Section version of the Task 7 projection (spec §10.1 allocator).
pub(crate) const PROVIDER_OBSERVATIONS_VERSION: u8 = 8;

/// Exact payload bytes per (kind, layout) (spec §17.1).
fn info_payload_len(kind: u8, layout: u8) -> Option<u8> {
    match (kind, layout) {
        (INFO_KIND_PROVIDER, INFO_LAYOUT_LP64) => Some(76),
        (INFO_KIND_PROVIDER, INFO_LAYOUT_ILP32) => Some(72),
        (INFO_KIND_TOKEN, INFO_LAYOUT_LP64) => Some(76),
        (INFO_KIND_TOKEN, INFO_LAYOUT_ILP32) => Some(64),
        (INFO_KIND_MECHANISM, INFO_LAYOUT_LP64) => Some(24),
        (INFO_KIND_MECHANISM, INFO_LAYOUT_ILP32) => Some(12),
        _ => None,
    }
}

/// One decoded 176-byte info record (spec §17.4).
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct InfoRecord {
    pub endpoint: u32,
    pub kind: u8,
    pub layout: u8,
    pub host_tgid: u32,
    pub task_cookie: u64,
    pub exec_id: u64,
    pub slot: u64,
    pub mechanism: u64,
    pub status: u8,
    pub payload_len: u8,
    pub payload: [u8; INFO_PAYLOAD_MAX],
}

fn le_u16(bytes: &[u8], off: usize) -> u16 {
    u16::from_le_bytes([bytes[off], bytes[off + 1]])
}

fn le_u32(bytes: &[u8], off: usize) -> u32 {
    u32::from_le_bytes([bytes[off], bytes[off + 1], bytes[off + 2], bytes[off + 3]])
}

fn le_u64(bytes: &[u8], off: usize) -> u64 {
    u64::from_le_bytes([
        bytes[off],
        bytes[off + 1],
        bytes[off + 2],
        bytes[off + 3],
        bytes[off + 4],
        bytes[off + 5],
        bytes[off + 6],
        bytes[off + 7],
    ])
}

/// Decode + validate one 176-byte record: exact length, known
/// header kind/layout with zero reserved, the slot/mechanism
/// placement rules, then trailer version, kind/layout agreement,
/// known status, exact payload length, zero reserved and zero
/// trailer slack past `payload_len` (spec §17.4). Refusals carry
/// named reasons. Endpoint resolution (known endpoint → module) is
/// the drain's job.
pub(crate) fn decode_info_record(bytes: &[u8]) -> Result<InfoRecord, &'static str> {
    if bytes.len() != INFO_RECORD_LEN {
        return Err("bad_length");
    }
    let kind = bytes[4];
    if !matches!(
        kind,
        INFO_KIND_PROVIDER | INFO_KIND_TOKEN | INFO_KIND_MECHANISM
    ) {
        return Err("unknown_kind");
    }
    let layout = bytes[5];
    if layout != INFO_LAYOUT_LP64 && layout != INFO_LAYOUT_ILP32 {
        return Err("unknown_layout");
    }
    if bytes[6..8] != [0, 0] || bytes[12..16] != [0, 0, 0, 0] {
        return Err("nonzero_reserved");
    }
    // Slot/mechanism placement (spec §17.4): slot is 0 for
    // C_GetInfo, mechanism is 0 for C_GetInfo/C_GetTokenInfo.
    let slot = le_u64(bytes, 32);
    let mechanism = le_u64(bytes, 40);
    if kind == INFO_KIND_PROVIDER && slot != 0 {
        return Err("nonzero_slot");
    }
    if kind != INFO_KIND_MECHANISM && mechanism != 0 {
        return Err("nonzero_mechanism");
    }
    // Trailer field positions come from the shared InfoTrailer
    // layout, never from copied numbers.
    let trailer = INFO_HEADER_LEN;
    let version_at = trailer + core::mem::offset_of!(InfoTrailer, version);
    let kind_at = trailer + core::mem::offset_of!(InfoTrailer, kind);
    let status_at = trailer + core::mem::offset_of!(InfoTrailer, status);
    let layout_at = trailer + core::mem::offset_of!(InfoTrailer, layout);
    let payload_len_at = trailer + core::mem::offset_of!(InfoTrailer, payload_len);
    let reserved_at = trailer + core::mem::offset_of!(InfoTrailer, reserved);
    let payload_at = trailer + core::mem::offset_of!(InfoTrailer, payload);
    debug_assert_eq!(payload_at + INFO_PAYLOAD_MAX, INFO_RECORD_LEN);
    if le_u16(bytes, version_at) != INFO_VERSION {
        return Err("unknown_version");
    }
    if bytes[kind_at] != kind {
        return Err("kind_mismatch");
    }
    if bytes[layout_at] != layout {
        return Err("layout_mismatch");
    }
    let status = bytes[status_at];
    if status != INFO_STATUS_OK && status != INFO_STATUS_UNAVAILABLE {
        return Err("unknown_status");
    }
    if bytes[reserved_at..reserved_at + 2] != [0, 0] {
        return Err("nonzero_reserved");
    }
    let payload_len = bytes[payload_len_at];
    if Some(payload_len) != info_payload_len(kind, layout) {
        return Err("bad_payload_len");
    }
    // Trailer slack past payload_len is zero-filled by the writer;
    // nonzero bytes are a writer bug and refuse (spec §17.4).
    let payload_end = payload_at + INFO_PAYLOAD_MAX;
    if bytes[payload_at + usize::from(payload_len)..payload_end]
        .iter()
        .any(|byte| *byte != 0)
    {
        return Err("nonzero_trailer_slack");
    }
    // Status 1 (unavailable) carries a zero payload over the whole
    // window: the return adapter zeroes it before emitting, so any
    // nonzero byte inside the declared prefix refuses (spec §17.1).
    if status == INFO_STATUS_UNAVAILABLE
        && bytes[payload_at..payload_at + usize::from(payload_len)]
            .iter()
            .any(|byte| *byte != 0)
    {
        return Err("nonzero_unavailable_payload");
    }
    let mut payload = [0u8; INFO_PAYLOAD_MAX];
    payload.copy_from_slice(&bytes[payload_at..payload_end]);
    Ok(InfoRecord {
        endpoint: le_u32(bytes, 0),
        kind,
        layout,
        host_tgid: le_u32(bytes, 8),
        task_cookie: le_u64(bytes, 16),
        exec_id: le_u64(bytes, 24),
        slot,
        mechanism,
        status,
        payload_len,
        payload,
    })
}

/// Trim one space-padded fixed-width string: truncate at the first
/// embedded NUL, trim trailing spaces; all-spaces publishes as the
/// empty string. Non-UTF8 refuses the field (spec §17.1).
pub(crate) fn trim_padded(bytes: &[u8]) -> Result<String, &'static str> {
    let end = bytes
        .iter()
        .position(|byte| *byte == 0)
        .unwrap_or(bytes.len());
    let mut text = &bytes[..end];
    while text.last() == Some(&b' ') {
        text = &text[..text.len() - 1];
    }
    std::str::from_utf8(text)
        .map(str::to_string)
        .map_err(|_| INFO_STRING_NON_UTF8)
}

/// Parsed `CK_INFO` payload: versions, padded strings, flags.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct CkInfoValues {
    pub cryptoki_major: u8,
    pub cryptoki_minor: u8,
    pub manufacturer: Result<String, &'static str>,
    pub flags: u64,
    pub description: Result<String, &'static str>,
    pub library_major: u8,
    pub library_minor: u8,
}

/// Parsed `CK_TOKEN_INFO` ranges: manufacturer, model, flags (whole
/// word, incl. PIN-state bits), PIN lengths, versions. No other
/// token byte exists in this struct (spec §17.2).
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct TokenValues {
    pub manufacturer: Result<String, &'static str>,
    pub model: Result<String, &'static str>,
    pub flags: u64,
    pub pin_min_len: u64,
    pub pin_max_len: u64,
    pub hardware_major: u8,
    pub hardware_minor: u8,
    pub firmware_major: u8,
    pub firmware_minor: u8,
}

/// Parsed `CK_MECHANISM_INFO`: raw mechanism-dependent numbers.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct MechanismValues {
    pub min_key_size: u64,
    pub max_key_size: u64,
    pub flags: u64,
}

/// Parsed payload by record kind.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum InfoValues {
    Provider(CkInfoValues),
    Token(TokenValues),
    Mechanism(MechanismValues),
}

fn parse_ck_info(payload: &[u8], layout: u8) -> CkInfoValues {
    let word = layout == INFO_LAYOUT_LP64;
    let flags = if word {
        le_u64(payload, 34)
    } else {
        u64::from(le_u32(payload, 34))
    };
    let (description, library) = if word {
        (&payload[42..74], &payload[74..76])
    } else {
        (&payload[38..70], &payload[70..72])
    };
    CkInfoValues {
        cryptoki_major: payload[0],
        cryptoki_minor: payload[1],
        manufacturer: trim_padded(&payload[2..34]),
        flags,
        description: trim_padded(description),
        library_major: library[0],
        library_minor: library[1],
    }
}

fn parse_token(payload: &[u8], layout: u8) -> TokenValues {
    // The PIN window packs ulMaxPinLen before ulMinPinLen (struct
    // address order, spec §17.1): LP64 payload+56 is struct
    // ulMaxPinLen@136 and payload+64 is ulMinPinLen@144; ia32
    // payload+52 is struct ulMaxPinLen@116 and payload+56 is
    // ulMinPinLen@120.
    let word = layout == INFO_LAYOUT_LP64;
    let (flags, pin_max_len, pin_min_len, versions) = if word {
        (
            le_u64(payload, 48),
            le_u64(payload, 56),
            le_u64(payload, 64),
            &payload[72..76],
        )
    } else {
        (
            u64::from(le_u32(payload, 48)),
            u64::from(le_u32(payload, 52)),
            u64::from(le_u32(payload, 56)),
            &payload[60..64],
        )
    };
    TokenValues {
        manufacturer: trim_padded(&payload[0..32]),
        model: trim_padded(&payload[32..48]),
        flags,
        pin_min_len,
        pin_max_len,
        hardware_major: versions[0],
        hardware_minor: versions[1],
        firmware_major: versions[2],
        firmware_minor: versions[3],
    }
}

fn parse_mechanism(payload: &[u8], layout: u8) -> MechanismValues {
    if layout == INFO_LAYOUT_LP64 {
        MechanismValues {
            min_key_size: le_u64(payload, 0),
            max_key_size: le_u64(payload, 8),
            flags: le_u64(payload, 16),
        }
    } else {
        MechanismValues {
            min_key_size: u64::from(le_u32(payload, 0)),
            max_key_size: u64::from(le_u32(payload, 4)),
            flags: u64::from(le_u32(payload, 8)),
        }
    }
}

/// Parse a decoded record's payload (§17.1 ranges). Lengths are
/// exact by construction; strings refuse per field, never the row.
pub(crate) fn parse_info_payload(record: &InfoRecord) -> InfoValues {
    let payload = &record.payload[..usize::from(record.payload_len)];
    match record.kind {
        INFO_KIND_PROVIDER => InfoValues::Provider(parse_ck_info(payload, record.layout)),
        INFO_KIND_TOKEN => InfoValues::Token(parse_token(payload, record.layout)),
        _ => InfoValues::Mechanism(parse_mechanism(payload, record.layout)),
    }
}

/// Per-module provider facts (rides `modules[].provider_info`).
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct ProviderInfo {
    pub cryptoki_major: u8,
    pub cryptoki_minor: u8,
    pub manufacturer: Option<String>,
    pub manufacturer_reason: Option<&'static str>,
    pub description: Option<String>,
    pub description_reason: Option<&'static str>,
    pub flags: u64,
    pub library_major: u8,
    pub library_minor: u8,
}

/// One (module, caller, slot) token row.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct TokenRow {
    pub module: ModuleId,
    pub caller: CallerId,
    pub slot: u64,
    pub manufacturer: Option<String>,
    pub manufacturer_reason: Option<&'static str>,
    pub model: Option<String>,
    pub model_reason: Option<&'static str>,
    pub hardware_major: u8,
    pub hardware_minor: u8,
    pub firmware_major: u8,
    pub firmware_minor: u8,
    pub flags: u64,
    pub pin_min_len: u64,
    pub pin_max_len: u64,
    pub completions: u64,
    pub changes: u64,
    pub instance: Option<RegistryInstanceId>,
}

/// One (module, caller, slot, mechanism) mechanism row.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct MechanismRow {
    pub module: ModuleId,
    pub caller: CallerId,
    pub slot: u64,
    pub mechanism: u64,
    pub min_key_size: u64,
    pub max_key_size: u64,
    pub flags: u64,
    pub completions: u64,
    pub changes: u64,
    pub instance: Option<RegistryInstanceId>,
}

/// Named section gaps, all counted (spec §17.5).
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub(crate) struct ProviderGaps {
    pub aliased: u64,
    pub return_deferred: u64,
    pub return_refused_hazard: u64,
    pub caller_unavailable: u64,
    pub mechanism_refused: u64,
    pub tokens_refused: u64,
    pub mechanisms_refused: u64,
    pub tokens_departed: u64,
    pub mechanisms_departed: u64,
}

/// The joined Task 7 projection (top-level section content).
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub(crate) struct ProviderObservations {
    pub tokens: Vec<TokenRow>,
    pub mechanisms: Vec<MechanismRow>,
    pub gaps: ProviderGaps,
}

impl ProviderObservations {
    pub(crate) fn is_empty(&self) -> bool {
        self.tokens.is_empty() && self.mechanisms.is_empty() && self.gaps == ProviderGaps::default()
    }
}

fn split_string(parsed: Result<String, &'static str>) -> (Option<String>, Option<&'static str>) {
    match parsed {
        Ok(text) => (Some(text), None),
        Err(reason) => (None, Some(reason)),
    }
}

/// The (module, caller, slot[, mechanism]) join (spec §17.5):
/// last-wins repeats with completions/changes, per-process slot
/// separation, the 128-mechanism per-slot cap, the run-wide row
/// caps, departed-caller folding and the named gaps.
pub(crate) struct InfoJoin {
    providers: BTreeMap<ModuleId, ProviderInfo>,
    /// Caller-leading keys: a departed caller's rows retire as one
    /// bounded range instead of scanning the whole table. Snapshots
    /// sort back to module-leading order.
    tokens: BTreeMap<(CallerId, ModuleId, u64), TokenRow>,
    mechanisms: BTreeMap<(CallerId, ModuleId, u64, u64), MechanismRow>,
    gaps: ProviderGaps,
    /// Rows examined by departed-caller folds (work pin: each fold
    /// touches only its caller's slice, never the whole table).
    fold_visits: u64,
    /// Departed callers awaiting fold, in retire order.
    fold_queue: VecDeque<CallerId>,
    /// The in-progress departed fold and its resume position.
    fold_cursor: Option<InfoFoldCursor>,
    /// Queued plus in-progress departed callers: indexed enqueue
    /// membership, and the departed set the snapshots omit — a
    /// queued caller's rows read departed from enqueue time, before
    /// any fold slice reclaims them.
    fold_pending: BTreeSet<CallerId>,
    /// Live (token + mechanism) rows per caller, maintained at
    /// every insert and fold: the stop discloses deferred folds
    /// from these, never a pending scan.
    caller_rows: BTreeMap<CallerId, u64>,
    /// Rows still queued-but-unfolded over `fold_pending`,
    /// maintained with it: enqueue adds the caller's rows, folds
    /// subtract what they retire, and rows that land for a queued
    /// caller add on ingest.
    pending_rows: u64,
}

/// One departed caller's in-progress fold (spec §17.5): token rows
/// first, then mechanism rows, each as a resumable caller-bounded
/// range. `after` is the last retired key (exclusive resume
/// point), or `None` before the phase's first key.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct InfoFoldCursor {
    caller: CallerId,
    phase: InfoFoldPhase,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum InfoFoldPhase {
    Tokens {
        after: Option<(CallerId, ModuleId, u64)>,
    },
    Mechanisms {
        after: Option<(CallerId, ModuleId, u64, u64)>,
    },
}

impl InfoJoin {
    pub(crate) fn new() -> Self {
        Self {
            providers: BTreeMap::new(),
            tokens: BTreeMap::new(),
            mechanisms: BTreeMap::new(),
            gaps: ProviderGaps::default(),
            fold_visits: 0,
            fold_queue: VecDeque::new(),
            fold_cursor: None,
            fold_pending: BTreeSet::new(),
            caller_rows: BTreeMap::new(),
            pending_rows: 0,
        }
    }

    /// One info endpoint whose slot set is not exactly one info
    /// function keeps its usage entry (attach-side count).
    pub(crate) fn note_aliased_endpoint(&mut self) {
        self.gaps.aliased = self.gaps.aliased.saturating_add(1);
    }

    /// One endpoint/group whose info return link deferred on EMFILE
    /// (attach-side count).
    pub(crate) fn note_return_deferred(&mut self) {
        self.gaps.return_deferred = self.gaps.return_deferred.saturating_add(1);
    }

    /// One info endpoint downgraded to usage-only by the
    /// uretprobe-vs-seccomp refusal (spec §17.4).
    pub(crate) fn note_return_refused_hazard(&mut self) {
        self.gaps.return_refused_hazard = self.gaps.return_refused_hazard.saturating_add(1);
    }

    /// Queue one departed caller's rows for folding, like the
    /// caller registry folds departed edges into `departed_use`.
    /// Idempotent: a caller already queued or folding queues once
    /// (indexed membership, never a queue scan). The caller's rows
    /// read departed from here on, before any fold slice runs.
    pub(crate) fn enqueue_fold(&mut self, caller: CallerId) {
        if !self.fold_pending.insert(caller) {
            return;
        }
        self.pending_rows = self
            .pending_rows
            .saturating_add(self.caller_rows.get(&caller).copied().unwrap_or(0));
        self.fold_queue.push_back(caller);
    }

    /// One fresh token/mechanism row for `caller`: the per-caller
    /// count and, for a queued departure, the pending total grow by
    /// one. Repeats of an existing row never reach here.
    fn note_row_added(&mut self, caller: CallerId) {
        self.caller_rows
            .entry(caller)
            .and_modify(|count| *count = count.saturating_add(1))
            .or_insert(1);
        if self.fold_pending.contains(&caller) {
            self.pending_rows = self.pending_rows.saturating_add(1);
        }
    }

    /// `retired` rows of `caller` folded away: the per-caller count
    /// and the pending total shrink by as much.
    fn note_rows_folded(&mut self, caller: CallerId, retired: u64) {
        if let Some(count) = self.caller_rows.get_mut(&caller) {
            *count = count.saturating_sub(retired);
        }
        self.pending_rows = self.pending_rows.saturating_sub(retired);
    }

    /// Retire up to `bound` queued departed rows through the
    /// resumable per-caller range cursor, oldest caller first.
    /// Returns whether more rows remain queued. Rows retire with
    /// their counts landing in the named departed gaps; rows of
    /// live callers never merge (slot ids are per-process), so
    /// values leave with the row and only the folded row counts
    /// survive. Missing callers fold nothing and count nothing, but
    /// every phase probe still charges one credit even when it finds
    /// no rows, so an empty-caller queue drains bounded prefixes,
    /// never the whole queue in one step. Snapshots omit queued
    /// callers' rows throughout; folds complete over subsequent
    /// calls.
    pub(crate) fn fold_step(&mut self, bound: usize) -> bool {
        use std::ops::Bound::{Excluded, Included};
        let mut remaining = bound;
        while remaining > 0 {
            if self.fold_cursor.is_none() {
                let Some(caller) = self.fold_queue.pop_front() else {
                    return false;
                };
                self.fold_cursor = Some(InfoFoldCursor {
                    caller,
                    phase: InfoFoldPhase::Tokens { after: None },
                });
            }
            let Some(cursor) = self.fold_cursor else {
                return !self.fold_queue.is_empty();
            };
            // A phase that yields fewer keys than the remaining
            // allowance is exhausted (an empty take included) and
            // the cursor advances; a full take spends the allowance
            // and keeps the resume point after the last key taken.
            // An empty probe still charges one credit for the range
            // scan itself.
            let quota = remaining;
            match cursor.phase {
                InfoFoldPhase::Tokens { after } => {
                    let start = match after {
                        None => Included((cursor.caller, ModuleId(u32::MIN), u64::MIN)),
                        Some(key) => Excluded(key),
                    };
                    let end = Included((cursor.caller, ModuleId(u32::MAX), u64::MAX));
                    let keys: Vec<(CallerId, ModuleId, u64)> = self
                        .tokens
                        .range((start, end))
                        .take(quota)
                        .map(|(key, _)| *key)
                        .collect();
                    let took = keys.len();
                    self.fold_visits = self.fold_visits.saturating_add(took as u64);
                    for key in &keys {
                        self.tokens.remove(key);
                    }
                    self.gaps.tokens_departed =
                        self.gaps.tokens_departed.saturating_add(took as u64);
                    self.note_rows_folded(cursor.caller, took as u64);
                    remaining -= took.max(1);
                    if took < quota {
                        self.fold_cursor = Some(InfoFoldCursor {
                            caller: cursor.caller,
                            phase: InfoFoldPhase::Mechanisms { after: None },
                        });
                    } else if let Some(last) = keys.last() {
                        self.fold_cursor = Some(InfoFoldCursor {
                            caller: cursor.caller,
                            phase: InfoFoldPhase::Tokens { after: Some(*last) },
                        });
                    }
                }
                InfoFoldPhase::Mechanisms { after } => {
                    let start = match after {
                        None => Included((cursor.caller, ModuleId(u32::MIN), u64::MIN, u64::MIN)),
                        Some(key) => Excluded(key),
                    };
                    let end = Included((cursor.caller, ModuleId(u32::MAX), u64::MAX, u64::MAX));
                    let keys: Vec<(CallerId, ModuleId, u64, u64)> = self
                        .mechanisms
                        .range((start, end))
                        .take(quota)
                        .map(|(key, _)| *key)
                        .collect();
                    let took = keys.len();
                    self.fold_visits = self.fold_visits.saturating_add(took as u64);
                    for key in &keys {
                        self.mechanisms.remove(key);
                    }
                    self.gaps.mechanisms_departed =
                        self.gaps.mechanisms_departed.saturating_add(took as u64);
                    self.note_rows_folded(cursor.caller, took as u64);
                    remaining -= took.max(1);
                    if took < quota {
                        self.fold_pending.remove(&cursor.caller);
                        self.fold_cursor = None;
                        // Rows that landed for this caller after its
                        // ranges passed stay live and keep their
                        // per-caller count; only the pending total
                        // drops them with the caller.
                        let live = self.caller_rows.get(&cursor.caller).copied().unwrap_or(0);
                        self.pending_rows = self.pending_rows.saturating_sub(live);
                        if live == 0 {
                            self.caller_rows.remove(&cursor.caller);
                        }
                    } else if let Some(last) = keys.last() {
                        self.fold_cursor = Some(InfoFoldCursor {
                            caller: cursor.caller,
                            phase: InfoFoldPhase::Mechanisms { after: Some(*last) },
                        });
                    }
                }
            }
        }
        self.fold_cursor.is_some() || !self.fold_queue.is_empty()
    }

    /// Queued-but-unfolded departed folds: how many callers still
    /// pend and how many of their rows the stop has not reclaimed.
    /// The stop discloses this once instead of silently understating
    /// the departed counts — from the maintained per-caller counts,
    /// with no range probe even over thousands of empty callers.
    pub(crate) fn fold_deferred(&self) -> (u64, u64) {
        (self.fold_pending.len() as u64, self.pending_rows)
    }

    /// Fold one decoded record (with drain-resolved module,
    /// optionally resolved caller incarnation, and optional proved
    /// instance) into the join. Unavailable records publish nothing.
    /// Provider facts publish regardless of caller resolution;
    /// token and mechanism rows require a bound caller and refuse
    /// with the named counted `info_caller_unavailable` gap without
    /// one (unresolved or zero identity alike).
    pub(crate) fn ingest(
        &mut self,
        record: &InfoRecord,
        module: ModuleId,
        caller: Option<CallerId>,
        instance: Option<RegistryInstanceId>,
    ) {
        if record.status == INFO_STATUS_UNAVAILABLE {
            return;
        }
        match parse_info_payload(record) {
            InfoValues::Provider(values) => {
                let (manufacturer, manufacturer_reason) = split_string(values.manufacturer);
                let (description, description_reason) = split_string(values.description);
                self.providers.insert(
                    module,
                    ProviderInfo {
                        cryptoki_major: values.cryptoki_major,
                        cryptoki_minor: values.cryptoki_minor,
                        manufacturer,
                        manufacturer_reason,
                        description,
                        description_reason,
                        flags: values.flags,
                        library_major: values.library_major,
                        library_minor: values.library_minor,
                    },
                );
            }
            InfoValues::Token(values) => {
                let Some(caller) = caller else {
                    self.gaps.caller_unavailable = self.gaps.caller_unavailable.saturating_add(1);
                    return;
                };
                if record.task_cookie == 0 || record.exec_id == 0 {
                    self.gaps.caller_unavailable = self.gaps.caller_unavailable.saturating_add(1);
                    return;
                }
                let key = (caller, module, record.slot);
                let fresh = !self.tokens.contains_key(&key);
                if fresh && self.tokens.len() >= INFO_MAX_TOKEN_ROWS {
                    self.gaps.tokens_refused = self.gaps.tokens_refused.saturating_add(1);
                    return;
                }
                let (manufacturer, manufacturer_reason) = split_string(values.manufacturer);
                let (model, model_reason) = split_string(values.model);
                if fresh {
                    self.note_row_added(caller);
                }
                let row = self.tokens.entry(key).or_insert_with(|| TokenRow {
                    module,
                    caller,
                    slot: record.slot,
                    manufacturer: None,
                    manufacturer_reason: None,
                    model: None,
                    model_reason: None,
                    hardware_major: 0,
                    hardware_minor: 0,
                    firmware_major: 0,
                    firmware_minor: 0,
                    flags: 0,
                    pin_min_len: 0,
                    pin_max_len: 0,
                    completions: 0,
                    changes: 0,
                    instance: None,
                });
                row.completions = row.completions.saturating_add(1);
                let changed = row.manufacturer != manufacturer
                    || row.manufacturer_reason != manufacturer_reason
                    || row.model != model
                    || row.model_reason != model_reason
                    || row.hardware_major != values.hardware_major
                    || row.hardware_minor != values.hardware_minor
                    || row.firmware_major != values.firmware_major
                    || row.firmware_minor != values.firmware_minor
                    || row.flags != values.flags
                    || row.pin_min_len != values.pin_min_len
                    || row.pin_max_len != values.pin_max_len;
                // First observation sets the value (changes 0): a
                // fresh row has completions 1 here.
                if changed && row.completions > 1 {
                    row.changes = row.changes.saturating_add(1);
                }
                row.manufacturer = manufacturer;
                row.manufacturer_reason = manufacturer_reason;
                row.model = model;
                row.model_reason = model_reason;
                row.hardware_major = values.hardware_major;
                row.hardware_minor = values.hardware_minor;
                row.firmware_major = values.firmware_major;
                row.firmware_minor = values.firmware_minor;
                row.flags = values.flags;
                row.pin_min_len = values.pin_min_len;
                row.pin_max_len = values.pin_max_len;
                // Attribution sticks once proved: a later unproven
                // poll never clears it.
                if instance.is_some() {
                    row.instance = instance;
                }
            }
            InfoValues::Mechanism(values) => {
                let Some(caller) = caller else {
                    self.gaps.caller_unavailable = self.gaps.caller_unavailable.saturating_add(1);
                    return;
                };
                if record.task_cookie == 0 || record.exec_id == 0 {
                    self.gaps.caller_unavailable = self.gaps.caller_unavailable.saturating_add(1);
                    return;
                }
                let key = (caller, module, record.slot, record.mechanism);
                let fresh = !self.mechanisms.contains_key(&key);
                if fresh {
                    let slot_reporters = self
                        .mechanisms
                        .range(
                            (caller, module, record.slot, u64::MIN)
                                ..=(caller, module, record.slot, u64::MAX),
                        )
                        .count();
                    if slot_reporters >= INFO_MAX_MECHANISMS_PER_SLOT {
                        self.gaps.mechanism_refused = self.gaps.mechanism_refused.saturating_add(1);
                        return;
                    }
                    if self.mechanisms.len() >= INFO_MAX_MECHANISM_ROWS {
                        self.gaps.mechanisms_refused =
                            self.gaps.mechanisms_refused.saturating_add(1);
                        return;
                    }
                }
                if fresh {
                    self.note_row_added(caller);
                }
                let row = self.mechanisms.entry(key).or_insert_with(|| MechanismRow {
                    module,
                    caller,
                    slot: record.slot,
                    mechanism: record.mechanism,
                    min_key_size: 0,
                    max_key_size: 0,
                    flags: 0,
                    completions: 0,
                    changes: 0,
                    instance: None,
                });
                row.completions = row.completions.saturating_add(1);
                let changed = row.min_key_size != values.min_key_size
                    || row.max_key_size != values.max_key_size
                    || row.flags != values.flags;
                if changed && row.completions > 1 {
                    row.changes = row.changes.saturating_add(1);
                }
                row.min_key_size = values.min_key_size;
                row.max_key_size = values.max_key_size;
                row.flags = values.flags;
                if instance.is_some() {
                    row.instance = instance;
                }
            }
        }
    }

    pub(crate) fn finish(self) -> (BTreeMap<ModuleId, ProviderInfo>, ProviderObservations) {
        self.snapshot()
    }

    /// A non-destructive projection: the per-module provider facts
    /// plus the run-wide token/mechanism rows and gaps. The session
    /// renders streaming views from snapshots while the capture
    /// still runs; the terminal view finishes the join. Rows of
    /// queued-but-unfolded departed callers read departed, never
    /// live, from enqueue time — a stop right after retirement
    /// cannot publish them.
    pub(crate) fn snapshot(&self) -> (BTreeMap<ModuleId, ProviderInfo>, ProviderObservations) {
        // Caller-leading storage, module-leading output: restore the
        // deterministic (module, caller, slot[, mechanism]) order.
        let mut tokens: Vec<TokenRow> = self
            .tokens
            .values()
            .filter(|row| !self.fold_pending.contains(&row.caller))
            .cloned()
            .collect();
        tokens.sort_by_key(|row| (row.module, row.caller, row.slot));
        let mut mechanisms: Vec<MechanismRow> = self
            .mechanisms
            .values()
            .filter(|row| !self.fold_pending.contains(&row.caller))
            .cloned()
            .collect();
        mechanisms.sort_by_key(|row| (row.module, row.caller, row.slot, row.mechanism));
        (
            self.providers.clone(),
            ProviderObservations {
                tokens,
                mechanisms,
                gaps: self.gaps.clone(),
            },
        )
    }
}

fn refused_string_json(
    map: &mut serde_json::Map<String, serde_json::Value>,
    key: &str,
    value: &Option<String>,
    reason: &Option<&'static str>,
) {
    map.insert(
        key.to_string(),
        value
            .clone()
            .map(serde_json::Value::from)
            .unwrap_or(serde_json::Value::Null),
    );
    if let Some(reason) = reason {
        map.insert(
            format!("{key}_reason"),
            serde_json::Value::String((*reason).to_string()),
        );
    }
}

/// `modules[].provider_info` JSON (section version 8).
pub(crate) fn provider_info_json(info: &ProviderInfo) -> serde_json::Value {
    let mut map = serde_json::Map::new();
    map.insert(
        "cryptoki_major".to_string(),
        serde_json::Value::from(info.cryptoki_major),
    );
    map.insert(
        "cryptoki_minor".to_string(),
        serde_json::Value::from(info.cryptoki_minor),
    );
    refused_string_json(
        &mut map,
        "manufacturer",
        &info.manufacturer,
        &info.manufacturer_reason,
    );
    refused_string_json(
        &mut map,
        "description",
        &info.description,
        &info.description_reason,
    );
    map.insert("flags".to_string(), serde_json::Value::from(info.flags));
    map.insert(
        "library_major".to_string(),
        serde_json::Value::from(info.library_major),
    );
    map.insert(
        "library_minor".to_string(),
        serde_json::Value::from(info.library_minor),
    );
    serde_json::Value::Object(map)
}

fn token_row_json(row: &TokenRow) -> serde_json::Value {
    let mut map = serde_json::Map::new();
    map.insert(
        "module".to_string(),
        serde_json::Value::from(row.module.label()),
    );
    map.insert(
        "caller".to_string(),
        serde_json::Value::from(row.caller.label()),
    );
    map.insert("slot".to_string(), serde_json::Value::from(row.slot));
    refused_string_json(
        &mut map,
        "manufacturer",
        &row.manufacturer,
        &row.manufacturer_reason,
    );
    refused_string_json(&mut map, "model", &row.model, &row.model_reason);
    map.insert(
        "hardware_major".to_string(),
        serde_json::Value::from(row.hardware_major),
    );
    map.insert(
        "hardware_minor".to_string(),
        serde_json::Value::from(row.hardware_minor),
    );
    map.insert(
        "firmware_major".to_string(),
        serde_json::Value::from(row.firmware_major),
    );
    map.insert(
        "firmware_minor".to_string(),
        serde_json::Value::from(row.firmware_minor),
    );
    map.insert("flags".to_string(), serde_json::Value::from(row.flags));
    map.insert(
        "pin_min_len".to_string(),
        serde_json::Value::from(row.pin_min_len),
    );
    map.insert(
        "pin_max_len".to_string(),
        serde_json::Value::from(row.pin_max_len),
    );
    map.insert(
        "completions".to_string(),
        serde_json::Value::from(row.completions),
    );
    map.insert("changes".to_string(), serde_json::Value::from(row.changes));
    if let Some(instance) = row.instance {
        map.insert(
            "instance".to_string(),
            serde_json::Value::from(instance.label()),
        );
    }
    serde_json::Value::Object(map)
}

fn mechanism_row_json(row: &MechanismRow) -> serde_json::Value {
    let mut map = serde_json::Map::new();
    map.insert(
        "module".to_string(),
        serde_json::Value::from(row.module.label()),
    );
    map.insert(
        "caller".to_string(),
        serde_json::Value::from(row.caller.label()),
    );
    map.insert("slot".to_string(), serde_json::Value::from(row.slot));
    map.insert(
        "mechanism".to_string(),
        serde_json::Value::from(row.mechanism),
    );
    map.insert(
        "min_key_size".to_string(),
        serde_json::Value::from(row.min_key_size),
    );
    map.insert(
        "max_key_size".to_string(),
        serde_json::Value::from(row.max_key_size),
    );
    map.insert("flags".to_string(), serde_json::Value::from(row.flags));
    map.insert(
        "completions".to_string(),
        serde_json::Value::from(row.completions),
    );
    map.insert("changes".to_string(), serde_json::Value::from(row.changes));
    if let Some(instance) = row.instance {
        map.insert(
            "instance".to_string(),
            serde_json::Value::from(instance.label()),
        );
    }
    serde_json::Value::Object(map)
}

/// Top-level `provider_observations` JSON (section version 8).
pub(crate) fn provider_observations_json(observations: &ProviderObservations) -> serde_json::Value {
    let mut gaps = Vec::new();
    for (reason, count) in [
        ("info_aliased_endpoint", observations.gaps.aliased),
        ("info_return_deferred", observations.gaps.return_deferred),
        (
            "info_return_refused_hazard",
            observations.gaps.return_refused_hazard,
        ),
        (
            "info_caller_unavailable",
            observations.gaps.caller_unavailable,
        ),
        (
            "mechanism_info_refused",
            observations.gaps.mechanism_refused,
        ),
        ("info_token_rows_refused", observations.gaps.tokens_refused),
        (
            "info_mechanism_rows_refused",
            observations.gaps.mechanisms_refused,
        ),
        (
            "info_token_departed_folded",
            observations.gaps.tokens_departed,
        ),
        (
            "info_mechanism_departed_folded",
            observations.gaps.mechanisms_departed,
        ),
    ] {
        if count > 0 {
            gaps.push(serde_json::json!({"reason": reason, "count": count}));
        }
    }
    serde_json::json!({
        "version": PROVIDER_OBSERVATIONS_VERSION,
        "tokens": observations.tokens.iter().map(token_row_json).collect::<Vec<_>>(),
        "mechanisms": observations.mechanisms.iter().map(mechanism_row_json).collect::<Vec<_>>(),
        "gaps": gaps,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    use crate::discovery::caller_registry::instance_input::RegistryInstanceId;
    use crate::discovery::caller_registry::{CallerId, ModuleId};

    // Spec §17.1 oracles: struct spans and read ranges. These numbers
    // are transcribed from the design, NOT from the implementation
    // consts below — if the implementation drifts, these twins fail.
    const CK_INFO_SPAN: [(u8, usize); 2] = [(INFO_LAYOUT_LP64, 88), (INFO_LAYOUT_ILP32, 76)];
    const CK_INFO_RANGES_LP64: [(usize, usize); 2] = [(0, 34), (40, 42)];
    const CK_INFO_RANGES_ILP32: [(usize, usize); 2] = [(0, 34), (36, 38)];
    const TOKEN_SPAN: [(u8, usize); 2] = [(INFO_LAYOUT_LP64, 208), (INFO_LAYOUT_ILP32, 160)];
    const TOKEN_RANGES_LP64: [(usize, usize); 4] = [(32, 48), (96, 8), (136, 16), (184, 4)];
    const TOKEN_RANGES_ILP32: [(usize, usize); 4] = [(32, 48), (96, 4), (116, 8), (140, 4)];
    const MECH_SPAN: [(u8, usize); 2] = [(INFO_LAYOUT_LP64, 24), (INFO_LAYOUT_ILP32, 12)];

    fn padded(text: &[u8], len: usize) -> Vec<u8> {
        let mut out = vec![b' '; len];
        let take = text.len().min(len);
        out[..take].copy_from_slice(&text[..take]);
        out
    }

    fn full_ck_info_lp64() -> [u8; 88] {
        let mut info = [0xAAu8; 88];
        info[0..2].copy_from_slice(&[3, 1]);
        info[2..34].copy_from_slice(&padded(b"SoftHSM", 32));
        info[34..40].fill(0xAA); // pad: never fetched
        info[40..48].copy_from_slice(&0u64.to_le_bytes());
        info[48..80].copy_from_slice(&padded(b"SoftHSM v2", 32));
        info[80..82].copy_from_slice(&[2, 6]);
        info[82..88].fill(0xAA); // tail pad: never fetched
        info
    }

    fn full_ck_info_ilp32() -> [u8; 76] {
        let mut info = [0xAAu8; 76];
        info[0..2].copy_from_slice(&[3, 1]);
        info[2..34].copy_from_slice(&padded(b"SoftHSM", 32));
        // Pad [34..36) stays sentinel: never fetched.
        info[36..40].copy_from_slice(&0u32.to_le_bytes());
        info[40..72].copy_from_slice(&padded(b"SoftHSM v2", 32));
        info[72..74].copy_from_slice(&[2, 6]);
        // Tail pad [74..76) stays sentinel: never fetched.
        info
    }

    fn full_token_lp64() -> [u8; 208] {
        let mut token = [0xAAu8; 208];
        // Excluded §17.2 bytes stay sentinel: label, serial, session
        // counts, memory sizes, utcTime must never reach the output.
        token[32..64].copy_from_slice(&padded(b"TokenMfr", 32));
        token[64..80].copy_from_slice(&padded(b"Model-X", 16));
        token[96..104].copy_from_slice(&0x06u64.to_le_bytes());
        // Realistic asymmetric PIN policy: ulMaxPinLen @136, then
        // ulMinPinLen @144 (spec §17.1; max > min, so a min/max
        // swap fails the exact asserts below).
        token[136..144].copy_from_slice(&255u64.to_le_bytes());
        token[144..152].copy_from_slice(&4u64.to_le_bytes());
        token[184..186].copy_from_slice(&[2, 6]);
        token[186..188].copy_from_slice(&[2, 7]);
        token
    }

    fn full_mech_lp64() -> [u8; 24] {
        let mut mech = [0u8; 24];
        mech[0..8].copy_from_slice(&1024u64.to_le_bytes());
        mech[8..16].copy_from_slice(&4096u64.to_le_bytes());
        mech[16..24].copy_from_slice(&1u64.to_le_bytes());
        mech
    }

    fn full_token_ilp32() -> [u8; 160] {
        let mut token = [0xAAu8; 160];
        token[32..64].copy_from_slice(&padded(b"TokenMfr", 32));
        token[64..80].copy_from_slice(&padded(b"Model-X", 16));
        token[96..100].copy_from_slice(&0x06u32.to_le_bytes());
        // ia32 mirrors LP64: ulMaxPinLen @116, ulMinPinLen @120.
        token[116..120].copy_from_slice(&255u32.to_le_bytes());
        token[120..124].copy_from_slice(&4u32.to_le_bytes());
        token[140..142].copy_from_slice(&[2, 6]);
        token[142..144].copy_from_slice(&[2, 7]);
        token
    }

    fn payload_of(full: &[u8], ranges: &[(usize, usize)]) -> Vec<u8> {
        let mut payload = Vec::new();
        for (off, len) in ranges {
            payload.extend_from_slice(&full[*off..*off + *len]);
        }
        payload
    }

    fn record_bytes(
        kind: u8,
        layout: u8,
        payload: &[u8],
        slot: u64,
        mechanism: u64,
        cookie: u64,
    ) -> Vec<u8> {
        let mut record = vec![0u8; INFO_RECORD_LEN];
        record[0..4].copy_from_slice(&7u32.to_le_bytes());
        record[4] = kind;
        record[5] = layout;
        record[8..12].copy_from_slice(&4242u32.to_le_bytes());
        record[16..24].copy_from_slice(&cookie.to_le_bytes());
        record[24..32].copy_from_slice(&9u64.to_le_bytes());
        record[32..40].copy_from_slice(&slot.to_le_bytes());
        record[40..48].copy_from_slice(&mechanism.to_le_bytes());
        record[48..50].copy_from_slice(&INFO_VERSION.to_le_bytes());
        record[50] = kind;
        record[51] = INFO_STATUS_OK;
        record[52] = layout;
        record[53] = payload.len() as u8;
        record[56..56 + payload.len()].copy_from_slice(payload);
        record
    }

    fn provider_record() -> Vec<u8> {
        let full = full_ck_info_lp64();
        let payload = payload_of(&full, &CK_INFO_RANGES_LP64);
        assert_eq!(payload.len(), 76);
        record_bytes(INFO_KIND_PROVIDER, INFO_LAYOUT_LP64, &payload, 0, 0, 11)
    }

    fn provider_record_ilp32() -> Vec<u8> {
        let full = full_ck_info_ilp32();
        let payload = payload_of(&full, &CK_INFO_RANGES_ILP32);
        assert_eq!(payload.len(), 72);
        record_bytes(INFO_KIND_PROVIDER, INFO_LAYOUT_ILP32, &payload, 0, 0, 11)
    }

    fn token_record_ilp32() -> Vec<u8> {
        let full = full_token_ilp32();
        let payload = payload_of(&full, &TOKEN_RANGES_ILP32);
        assert_eq!(payload.len(), 64);
        record_bytes(INFO_KIND_TOKEN, INFO_LAYOUT_ILP32, &payload, 3, 0, 11)
    }

    #[test]
    fn info_wire_codes_are_frozen() {
        assert_eq!(INFO_RECORD_LEN, 176);
        assert_eq!(INFO_VERSION, 1);
        assert_eq!(INFO_KIND_PROVIDER, 1);
        assert_eq!(INFO_KIND_TOKEN, 2);
        assert_eq!(INFO_KIND_MECHANISM, 3);
        assert_eq!(INFO_LAYOUT_LP64, 1);
        assert_eq!(INFO_LAYOUT_ILP32, 2);
        assert_eq!(INFO_STATUS_OK, 0);
        assert_eq!(INFO_STATUS_UNAVAILABLE, 1);
        assert_eq!(INFO_MAX_MECHANISMS_PER_SLOT, 128);
        assert_eq!(PROVIDER_OBSERVATIONS_VERSION, 8);
    }

    #[test]
    fn info_decode_accepts_provider_lp64_with_exact_fields() {
        let bytes = provider_record();
        let record = decode_info_record(&bytes).expect("provider record decodes");
        assert_eq!(record.endpoint, 7);
        assert_eq!(record.kind, INFO_KIND_PROVIDER);
        assert_eq!(record.layout, INFO_LAYOUT_LP64);
        assert_eq!(record.host_tgid, 4242);
        assert_eq!(record.task_cookie, 11);
        assert_eq!(record.exec_id, 9);
        let InfoValues::Provider(values) = parse_info_payload(&record) else {
            panic!("provider kind parses provider values");
        };
        assert_eq!((values.cryptoki_major, values.cryptoki_minor), (3, 1));
        assert_eq!(values.manufacturer, Ok("SoftHSM".to_string()));
        assert_eq!(values.flags, 0);
        assert_eq!(values.description, Ok("SoftHSM v2".to_string()));
        assert_eq!((values.library_major, values.library_minor), (2, 6));
    }

    #[test]
    fn info_decode_accepts_provider_ia32_with_exact_fields() {
        let bytes = provider_record_ilp32();
        let record = decode_info_record(&bytes).expect("ia32 provider record decodes");
        assert_eq!(record.kind, INFO_KIND_PROVIDER);
        assert_eq!(record.layout, INFO_LAYOUT_ILP32);
        assert_eq!(record.payload_len, 72);
        let InfoValues::Provider(values) = parse_info_payload(&record) else {
            panic!("provider kind parses provider values");
        };
        assert_eq!((values.cryptoki_major, values.cryptoki_minor), (3, 1));
        assert_eq!(values.manufacturer, Ok("SoftHSM".to_string()));
        assert_eq!(values.flags, 0);
        assert_eq!(values.description, Ok("SoftHSM v2".to_string()));
        assert_eq!((values.library_major, values.library_minor), (2, 6));
    }

    #[test]
    fn info_decode_accepts_token_ia32_with_exact_fields() {
        let bytes = token_record_ilp32();
        let record = decode_info_record(&bytes).expect("ia32 token record decodes");
        assert_eq!(record.kind, INFO_KIND_TOKEN);
        assert_eq!(record.layout, INFO_LAYOUT_ILP32);
        assert_eq!(record.slot, 3);
        let InfoValues::Token(values) = parse_info_payload(&record) else {
            panic!("token kind parses token values");
        };
        assert_eq!(values.manufacturer, Ok("TokenMfr".to_string()));
        assert_eq!(values.model, Ok("Model-X".to_string()));
        assert_eq!(values.flags, 0x06);
        assert_eq!(values.pin_min_len, 4);
        assert_eq!(values.pin_max_len, 255);
        assert_eq!((values.hardware_major, values.hardware_minor), (2, 6));
        assert_eq!((values.firmware_major, values.firmware_minor), (2, 7));
    }

    #[test]
    fn info_decode_accepts_mechanism_on_both_layouts() {
        let full = full_mech_lp64();
        let record = decode_info_record(&record_bytes(
            INFO_KIND_MECHANISM,
            INFO_LAYOUT_LP64,
            &full,
            5,
            1082,
            11,
        ))
        .expect("LP64 mechanism record decodes");
        let InfoValues::Mechanism(values) = parse_info_payload(&record) else {
            panic!("mechanism kind parses mechanism values");
        };
        assert_eq!(values.min_key_size, 1024);
        assert_eq!(values.max_key_size, 4096);
        assert_eq!(values.flags, 1);

        let mut ia32 = [0u8; 12];
        ia32[0..4].copy_from_slice(&512u32.to_le_bytes());
        ia32[4..8].copy_from_slice(&1024u32.to_le_bytes());
        ia32[8..12].copy_from_slice(&3u32.to_le_bytes());
        let record = decode_info_record(&record_bytes(
            INFO_KIND_MECHANISM,
            INFO_LAYOUT_ILP32,
            &ia32,
            5,
            1082,
            11,
        ))
        .expect("ia32 mechanism record decodes");
        let InfoValues::Mechanism(values) = parse_info_payload(&record) else {
            panic!("ia32 mechanism kind parses mechanism values");
        };
        assert_eq!(values.min_key_size, 512);
        assert_eq!(values.max_key_size, 1024);
        assert_eq!(values.flags, 3);
    }

    #[test]
    fn info_decode_refuses_malformed_records_with_named_reasons() {
        let good = provider_record();
        let mut cases: Vec<(&str, Vec<u8>, &str)> = Vec::new();
        cases.push(("short", good[..175].to_vec(), "bad_length"));
        let mut long = good.clone();
        long.push(0);
        cases.push(("long", long, "bad_length"));
        let mut version = good.clone();
        version[48..50].copy_from_slice(&2u16.to_le_bytes());
        cases.push(("version", version, "unknown_version"));
        let mut kind = good.clone();
        kind[4] = 4;
        kind[50] = 4;
        cases.push(("kind", kind, "unknown_kind"));
        let mut kind_zero = good.clone();
        kind_zero[4] = 0;
        kind_zero[50] = 0;
        cases.push(("kind-zero", kind_zero, "unknown_kind"));
        let mut layout = good.clone();
        layout[5] = 3;
        layout[52] = 3;
        cases.push(("layout", layout, "unknown_layout"));
        let mut mismatch = good.clone();
        mismatch[50] = INFO_KIND_TOKEN;
        cases.push(("kind-mismatch", mismatch, "kind_mismatch"));
        let mut layout_mismatch = good.clone();
        layout_mismatch[52] = INFO_LAYOUT_ILP32;
        cases.push(("layout-mismatch", layout_mismatch, "layout_mismatch"));
        let mut payload_len = good.clone();
        payload_len[53] = 75;
        cases.push(("payload-len", payload_len, "bad_payload_len"));
        let mut reserved = good.clone();
        reserved[6] = 1;
        cases.push(("header-reserved", reserved, "nonzero_reserved"));
        let mut reserved_high = good.clone();
        reserved_high[12] = 1;
        cases.push(("header-reserved-high", reserved_high, "nonzero_reserved"));
        let mut trailer_reserved = good.clone();
        trailer_reserved[55] = 1;
        cases.push(("trailer-reserved", trailer_reserved, "nonzero_reserved"));
        let mut status = good.clone();
        status[51] = 2;
        cases.push(("status", status, "unknown_status"));
        assert_eq!(cases.len(), 13);
        for (name, bytes, reason) in cases {
            assert_eq!(
                decode_info_record(&bytes),
                Err(reason),
                "case {name} refuses with {reason}"
            );
        }
    }

    #[test]
    fn info_decode_refuses_nonzero_trailer_slack() {
        // Spec §17.4: trailer bytes past payload_len are zero; the
        // writer zero-fills the 120-byte payload window.
        let good = provider_record();
        // First slack byte (payload_len 76, slack starts at 56 + 76).
        let mut first = good.clone();
        first[56 + 76] = 1;
        assert_eq!(
            decode_info_record(&first),
            Err("nonzero_trailer_slack"),
            "nonzero first slack byte refuses"
        );
        // Last trailer byte.
        let mut last = good.clone();
        last[175] = 0xFF;
        assert_eq!(
            decode_info_record(&last),
            Err("nonzero_trailer_slack"),
            "nonzero last slack byte refuses"
        );
        // Short-payload kind (mechanism LP64, payload_len 24): slack
        // starts at 56 + 24.
        let mech = full_mech_lp64();
        let short = record_bytes(INFO_KIND_MECHANISM, INFO_LAYOUT_LP64, &mech, 5, 1082, 11);
        let mut slacked = short.clone();
        slacked[56 + 24] = 1;
        assert_eq!(
            decode_info_record(&slacked),
            Err("nonzero_trailer_slack"),
            "nonzero slack on a short payload refuses"
        );
        // Zero slack still decodes.
        decode_info_record(&good).expect("zero-slack record decodes");
    }

    #[test]
    fn info_decode_refuses_nonzero_slot_for_provider_kind() {
        // Spec §17.4: slot is 0 for C_GetInfo records.
        let mut bytes = provider_record();
        bytes[32..40].copy_from_slice(&5u64.to_le_bytes());
        assert_eq!(
            decode_info_record(&bytes),
            Err("nonzero_slot"),
            "provider record with nonzero slot refuses"
        );
        // Token rows may carry a slot (healthy control).
        let full = full_token_lp64();
        let payload = payload_of(&full, &TOKEN_RANGES_LP64);
        let token = record_bytes(INFO_KIND_TOKEN, INFO_LAYOUT_LP64, &payload, 3, 0, 11);
        decode_info_record(&token).expect("token record with a slot decodes");
    }

    #[test]
    fn info_decode_refuses_nonzero_mechanism_for_provider_and_token() {
        // Spec §17.4: mechanism is 0 for C_GetInfo and C_GetTokenInfo.
        let mut provider = provider_record();
        provider[40..48].copy_from_slice(&7u64.to_le_bytes());
        assert_eq!(
            decode_info_record(&provider),
            Err("nonzero_mechanism"),
            "provider record with nonzero mechanism refuses"
        );
        let full = full_token_lp64();
        let payload = payload_of(&full, &TOKEN_RANGES_LP64);
        let token = record_bytes(INFO_KIND_TOKEN, INFO_LAYOUT_LP64, &payload, 3, 7, 11);
        assert_eq!(
            decode_info_record(&token),
            Err("nonzero_mechanism"),
            "token record with nonzero mechanism refuses"
        );
        // Mechanism rows carry a mechanism id (healthy control).
        let mech = full_mech_lp64();
        let row = record_bytes(INFO_KIND_MECHANISM, INFO_LAYOUT_LP64, &mech, 5, 1082, 11);
        decode_info_record(&row).expect("mechanism record with an id decodes");
    }

    #[test]
    fn info_trim_trims_padded_strings_and_refuses_non_utf8() {
        assert_eq!(trim_padded(b"SoftHSM   "), Ok("SoftHSM".to_string()));
        assert_eq!(trim_padded(b"A\0B      "), Ok("A".to_string()));
        assert_eq!(
            trim_padded(b"                                "),
            Ok(String::new())
        );
        assert_eq!(trim_padded(b"A B  "), Ok("A B".to_string()));
        assert_eq!(trim_padded(b"\xff\xfe      "), Err(INFO_STRING_NON_UTF8));
        assert_eq!(INFO_STRING_NON_UTF8, "non_utf8_bytes");
    }

    #[test]
    fn info_payload_never_touches_excluded_ranges() {
        // Every excluded §17.2 byte and every struct pad holds 0xAA
        // above; exact parsed output proves the parser never reads
        // them (0xAA is non-UTF8, so any contact would refuse or
        // corrupt a field).
        let full = full_token_lp64();
        let payload = payload_of(&full, &TOKEN_RANGES_LP64);
        assert_eq!(payload.len(), 76);
        let record = decode_info_record(&record_bytes(
            INFO_KIND_TOKEN,
            INFO_LAYOUT_LP64,
            &payload,
            0,
            0,
            11,
        ))
        .expect("token record decodes");
        let InfoValues::Token(values) = parse_info_payload(&record) else {
            panic!("token kind parses token values");
        };
        assert_eq!(values.manufacturer, Ok("TokenMfr".to_string()));
        assert_eq!(values.model, Ok("Model-X".to_string()));
        assert_eq!(values.flags, 0x06);
        assert_eq!(values.pin_min_len, 4);
        assert_eq!(values.pin_max_len, 255);

        // Trailer slack past payload_len refuses: nonzero slack
        // is a writer bug, never silently ignored (spec §17.4).
        let mut slacked = provider_record();
        slacked[56 + 76..].fill(0xFF);
        assert_eq!(
            decode_info_record(&slacked),
            Err("nonzero_trailer_slack"),
            "0xFF trailer slack refuses"
        );
    }

    #[test]
    fn info_token_pin_policy_publishes_exact() {
        let mut full = full_token_lp64();
        full[96..104].copy_from_slice(&0xA5A5u64.to_le_bytes());
        let payload = payload_of(&full, &TOKEN_RANGES_LP64);
        let record = decode_info_record(&record_bytes(
            INFO_KIND_TOKEN,
            INFO_LAYOUT_LP64,
            &payload,
            0,
            0,
            11,
        ))
        .expect("token record decodes");
        let InfoValues::Token(values) = parse_info_payload(&record) else {
            panic!("token kind parses token values");
        };
        assert_eq!(values.flags, 0xA5A5);
        assert_eq!(values.pin_min_len, 4);
        assert_eq!(values.pin_max_len, 255);
    }

    #[test]
    fn info_token_pin_lens_match_cryptoki_sys_field_assignment() {
        // Oracle-connected twin: the PIN lengths are assigned by
        // cryptoki-sys field name (never by numeric offset), so a
        // parser min/max swap cannot hide behind a mirrored fixture
        // the way hand-placed bytes once did.
        use cryptoki_sys::CK_TOKEN_INFO;
        use std::mem::{offset_of, size_of};

        assert_eq!(offset_of!(CK_TOKEN_INFO, ulMaxPinLen), 136);
        assert_eq!(offset_of!(CK_TOKEN_INFO, ulMinPinLen), 144);
        let mut token: CK_TOKEN_INFO = unsafe { std::mem::zeroed() };
        token.ulMaxPinLen = 255;
        token.ulMinPinLen = 4;
        token.flags = 0x06;
        let raw = unsafe {
            std::slice::from_raw_parts(
                std::ptr::from_ref(&token).cast::<u8>(),
                size_of::<CK_TOKEN_INFO>(),
            )
        };
        let payload = payload_of(raw, &TOKEN_RANGES_LP64);
        assert_eq!(payload.len(), 76);
        let record = decode_info_record(&record_bytes(
            INFO_KIND_TOKEN,
            INFO_LAYOUT_LP64,
            &payload,
            0,
            0,
            11,
        ))
        .expect("token record decodes");
        let InfoValues::Token(values) = parse_info_payload(&record) else {
            panic!("token kind parses token values");
        };
        assert_eq!(values.pin_min_len, 4);
        assert_eq!(values.pin_max_len, 255);
        assert_eq!(values.flags, 0x06);
    }

    #[test]
    fn info_lp64_struct_layout_matches_cryptoki_sys() {
        use cryptoki_sys::{CK_INFO, CK_MECHANISM_INFO, CK_TOKEN_INFO};
        use std::mem::{offset_of, size_of};

        assert_eq!(size_of::<CK_INFO>(), 88);
        assert_eq!(offset_of!(CK_INFO, cryptokiVersion), 0);
        assert_eq!(offset_of!(CK_INFO, manufacturerID), 2);
        assert_eq!(offset_of!(CK_INFO, flags), 40);
        assert_eq!(offset_of!(CK_INFO, libraryDescription), 48);
        assert_eq!(offset_of!(CK_INFO, libraryVersion), 80);

        assert_eq!(size_of::<CK_TOKEN_INFO>(), 208);
        assert_eq!(offset_of!(CK_TOKEN_INFO, label), 0);
        assert_eq!(offset_of!(CK_TOKEN_INFO, manufacturerID), 32);
        assert_eq!(offset_of!(CK_TOKEN_INFO, model), 64);
        assert_eq!(offset_of!(CK_TOKEN_INFO, serialNumber), 80);
        assert_eq!(offset_of!(CK_TOKEN_INFO, flags), 96);
        assert_eq!(offset_of!(CK_TOKEN_INFO, ulMaxPinLen), 136);
        assert_eq!(offset_of!(CK_TOKEN_INFO, ulMinPinLen), 144);
        assert_eq!(offset_of!(CK_TOKEN_INFO, hardwareVersion), 184);
        assert_eq!(offset_of!(CK_TOKEN_INFO, firmwareVersion), 186);
        assert_eq!(offset_of!(CK_TOKEN_INFO, utcTime), 188);

        assert_eq!(size_of::<CK_MECHANISM_INFO>(), 24);
        assert_eq!(offset_of!(CK_MECHANISM_INFO, ulMinKeySize), 0);
        assert_eq!(offset_of!(CK_MECHANISM_INFO, ulMaxKeySize), 8);
        assert_eq!(offset_of!(CK_MECHANISM_INFO, flags), 16);

        // The §17.1 spans the entry guard enforces.
        assert_eq!(
            CK_INFO_SPAN,
            [(INFO_LAYOUT_LP64, 88), (INFO_LAYOUT_ILP32, 76)]
        );
        assert_eq!(
            TOKEN_SPAN,
            [(INFO_LAYOUT_LP64, 208), (INFO_LAYOUT_ILP32, 160)]
        );
        assert_eq!(MECH_SPAN, [(INFO_LAYOUT_LP64, 24), (INFO_LAYOUT_ILP32, 12)]);
    }

    fn ingest_token(join: &mut InfoJoin, slot: u64, caller: u32) {
        let full = full_token_lp64();
        let payload = payload_of(&full, &TOKEN_RANGES_LP64);
        let record = decode_info_record(&record_bytes(
            INFO_KIND_TOKEN,
            INFO_LAYOUT_LP64,
            &payload,
            slot,
            0,
            100 + u64::from(caller),
        ))
        .expect("token record decodes");
        join.ingest(&record, ModuleId(0), Some(CallerId(caller)), None);
    }

    #[test]
    fn info_join_repeats_bump_completions_and_changes() {
        let mut join = InfoJoin::new();
        ingest_token(&mut join, 0, 0);
        ingest_token(&mut join, 0, 0);
        let (_, observations) = join.finish();
        assert_eq!(observations.tokens.len(), 1);
        assert_eq!(observations.tokens[0].completions, 2);
        assert_eq!(observations.tokens[0].changes, 0);

        // Changed flags: completions and changes both bump, one row.
        let mut join = InfoJoin::new();
        ingest_token(&mut join, 0, 0);
        let mut full = full_token_lp64();
        full[96..104].copy_from_slice(&0x07u64.to_le_bytes());
        let payload = payload_of(&full, &TOKEN_RANGES_LP64);
        let record = decode_info_record(&record_bytes(
            INFO_KIND_TOKEN,
            INFO_LAYOUT_LP64,
            &payload,
            0,
            0,
            100,
        ))
        .expect("token record decodes");
        join.ingest(&record, ModuleId(0), Some(CallerId(0)), None);
        let (_, observations) = join.finish();
        assert_eq!(observations.tokens.len(), 1);
        assert_eq!(observations.tokens[0].completions, 2);
        assert_eq!(observations.tokens[0].changes, 1);
        assert_eq!(observations.tokens[0].flags, 0x07);

        // Swapped token: last-wins, single entry, changes bump.
        let mut full = full_token_lp64();
        full[64..80].copy_from_slice(&padded(b"Model-Y", 16));
        let payload = payload_of(&full, &TOKEN_RANGES_LP64);
        let record = decode_info_record(&record_bytes(
            INFO_KIND_TOKEN,
            INFO_LAYOUT_LP64,
            &payload,
            0,
            0,
            100,
        ))
        .expect("token record decodes");
        let mut join = InfoJoin::new();
        ingest_token(&mut join, 0, 0);
        join.ingest(&record, ModuleId(0), Some(CallerId(0)), None);
        let (_, observations) = join.finish();
        assert_eq!(observations.tokens.len(), 1);
        assert_eq!(observations.tokens[0].model.as_deref(), Some("Model-Y"));
        assert_eq!(observations.tokens[0].completions, 2);
        assert_eq!(observations.tokens[0].changes, 1);
    }

    #[test]
    fn info_join_caps_mechanisms_at_128_per_slot() {
        let mut join = InfoJoin::new();
        for mechanism in 0..129u64 {
            let full = full_mech_lp64();
            let record = decode_info_record(&record_bytes(
                INFO_KIND_MECHANISM,
                INFO_LAYOUT_LP64,
                &full,
                0,
                mechanism,
                100,
            ))
            .expect("mechanism record decodes");
            join.ingest(&record, ModuleId(0), Some(CallerId(0)), None);
        }
        let (_, observations) = join.finish();
        assert_eq!(observations.mechanisms.len(), 128);
        assert_eq!(observations.gaps.mechanism_refused, 1);
        assert!(
            observations
                .mechanisms
                .iter()
                .all(|row| row.mechanism < 128),
            "first 128 reporters stand"
        );

        // Re-polling a capped reporter completes without consuming
        // new cap or refusing.
        let mut join = InfoJoin::new();
        for mechanism in 0..128u64 {
            let full = full_mech_lp64();
            let record = decode_info_record(&record_bytes(
                INFO_KIND_MECHANISM,
                INFO_LAYOUT_LP64,
                &full,
                0,
                mechanism,
                100,
            ))
            .expect("mechanism record decodes");
            join.ingest(&record, ModuleId(0), Some(CallerId(0)), None);
        }
        let full = full_mech_lp64();
        let record = decode_info_record(&record_bytes(
            INFO_KIND_MECHANISM,
            INFO_LAYOUT_LP64,
            &full,
            0,
            7,
            100,
        ))
        .expect("mechanism record decodes");
        join.ingest(&record, ModuleId(0), Some(CallerId(0)), None);
        let (_, observations) = join.finish();
        assert_eq!(observations.mechanisms.len(), 128);
        assert_eq!(observations.gaps.mechanism_refused, 0);
        let row = observations
            .mechanisms
            .iter()
            .find(|row| row.mechanism == 7)
            .expect("reporter 7 stands");
        assert_eq!(row.completions, 2);
    }

    #[test]
    fn info_join_separates_slots_per_process() {
        let mut join = InfoJoin::new();
        ingest_token(&mut join, 0, 0);
        ingest_token(&mut join, 0, 1);
        ingest_token(&mut join, 1, 0);
        let (_, observations) = join.finish();
        assert_eq!(observations.tokens.len(), 3);
        let keys: Vec<(u32, u32, u64)> = observations
            .tokens
            .iter()
            .map(|row| (row.module.0, row.caller.0, row.slot))
            .collect();
        assert_eq!(keys, vec![(0, 0, 0), (0, 0, 1), (0, 1, 0)]);
    }

    #[test]
    fn info_join_attaches_instance_only_when_proven() {
        let full = full_token_lp64();
        let payload = payload_of(&full, &TOKEN_RANGES_LP64);
        let record = decode_info_record(&record_bytes(
            INFO_KIND_TOKEN,
            INFO_LAYOUT_LP64,
            &payload,
            0,
            0,
            100,
        ))
        .expect("token record decodes");
        let mut join = InfoJoin::new();
        join.ingest(
            &record,
            ModuleId(0),
            Some(CallerId(0)),
            Some(RegistryInstanceId::from_raw(7)),
        );
        ingest_token(&mut join, 1, 0);
        let (_, observations) = join.finish();
        assert_eq!(
            observations.tokens[0].instance,
            Some(RegistryInstanceId::from_raw(7))
        );
        assert_eq!(observations.tokens[1].instance, None);
    }

    #[test]
    fn info_join_repoll_without_instance_keeps_proved_instance() {
        // Attribution sticks once proved: re-polling the SAME row
        // without an instance never clears it (token and mechanism).
        let full = full_token_lp64();
        let payload = payload_of(&full, &TOKEN_RANGES_LP64);
        let record = decode_info_record(&record_bytes(
            INFO_KIND_TOKEN,
            INFO_LAYOUT_LP64,
            &payload,
            0,
            0,
            100,
        ))
        .expect("token record decodes");
        let mut join = InfoJoin::new();
        join.ingest(
            &record,
            ModuleId(0),
            Some(CallerId(0)),
            Some(RegistryInstanceId::from_raw(7)),
        );
        join.ingest(&record, ModuleId(0), Some(CallerId(0)), None);
        let mech = full_mech_lp64();
        let record = decode_info_record(&record_bytes(
            INFO_KIND_MECHANISM,
            INFO_LAYOUT_LP64,
            &mech,
            0,
            1082,
            100,
        ))
        .expect("mechanism record decodes");
        join.ingest(
            &record,
            ModuleId(0),
            Some(CallerId(0)),
            Some(RegistryInstanceId::from_raw(9)),
        );
        join.ingest(&record, ModuleId(0), Some(CallerId(0)), None);
        let (_, observations) = join.finish();
        assert_eq!(observations.tokens.len(), 1);
        assert_eq!(observations.tokens[0].completions, 2);
        assert_eq!(
            observations.tokens[0].instance,
            Some(RegistryInstanceId::from_raw(7))
        );
        assert_eq!(observations.mechanisms.len(), 1);
        assert_eq!(observations.mechanisms[0].completions, 2);
        assert_eq!(
            observations.mechanisms[0].instance,
            Some(RegistryInstanceId::from_raw(9))
        );
    }

    #[test]
    fn info_join_zero_identity_refuses_rows_with_named_gap() {
        // Zero caller identity: provider_info still publishes, but
        // token/mechanism rows are refused (never keyed under a
        // shared zero caller).
        let mut join = InfoJoin::new();
        let provider = decode_info_record(&provider_record()).expect("provider record decodes");
        join.ingest(&provider, ModuleId(0), Some(CallerId(0)), None);
        let full = full_token_lp64();
        let payload = payload_of(&full, &TOKEN_RANGES_LP64);
        let mut zero = record_bytes(INFO_KIND_TOKEN, INFO_LAYOUT_LP64, &payload, 0, 0, 0);
        zero[24..32].copy_from_slice(&0u64.to_le_bytes());
        let token = decode_info_record(&zero).expect("zero-identity record decodes");
        join.ingest(&token, ModuleId(0), Some(CallerId(0)), None);
        let mech = full_mech_lp64();
        let mut zero_mech = record_bytes(INFO_KIND_MECHANISM, INFO_LAYOUT_LP64, &mech, 0, 1082, 0);
        zero_mech[24..32].copy_from_slice(&0u64.to_le_bytes());
        let mechanism = decode_info_record(&zero_mech).expect("zero-identity record decodes");
        join.ingest(&mechanism, ModuleId(0), Some(CallerId(0)), None);
        let (providers, observations) = join.finish();
        assert_eq!(providers.len(), 1);
        assert!(observations.tokens.is_empty());
        assert!(observations.mechanisms.is_empty());
        assert_eq!(observations.gaps.caller_unavailable, 2);
    }

    #[test]
    fn info_join_unavailable_records_publish_nothing() {
        let mut bytes = provider_record();
        bytes[51] = INFO_STATUS_UNAVAILABLE;
        // Wire-valid unavailable bytes: the whole payload window is
        // zero (a populated prefix refuses at decode).
        let len = usize::from(bytes[53]);
        bytes[56..56 + len].fill(0);
        let record = decode_info_record(&bytes).expect("unavailable record decodes");
        assert_eq!(record.status, INFO_STATUS_UNAVAILABLE);
        let mut join = InfoJoin::new();
        join.ingest(&record, ModuleId(0), Some(CallerId(0)), None);
        let (providers, observations) = join.finish();
        assert!(providers.is_empty());
        assert!(observations.is_empty());
    }

    #[test]
    fn info_status_unavailable_refuses_nonzero_payload_prefix() {
        // Status 1 carries a zero payload over the whole 120-byte
        // window (the writer zeroes it): any nonzero byte inside the
        // declared prefix refuses, not just slack past it.
        let mut bytes = provider_record();
        bytes[51] = INFO_STATUS_UNAVAILABLE;
        assert_eq!(
            decode_info_record(&bytes),
            Err("nonzero_unavailable_payload"),
            "populated payload with status 1 refuses"
        );
        // Single-byte mutants inside the declared prefix of an
        // otherwise wire-valid unavailable record (first and last
        // prefix bytes).
        let mut valid = record_bytes(INFO_KIND_PROVIDER, INFO_LAYOUT_LP64, &[0u8; 76], 0, 0, 11);
        valid[51] = INFO_STATUS_UNAVAILABLE;
        decode_info_record(&valid).expect("zero-payload unavailable decodes");
        valid[56] = 1;
        assert_eq!(
            decode_info_record(&valid),
            Err("nonzero_unavailable_payload"),
            "nonzero first prefix byte refuses"
        );
        valid[56] = 0;
        valid[56 + 75] = 0xFF;
        assert_eq!(
            decode_info_record(&valid),
            Err("nonzero_unavailable_payload"),
            "nonzero last prefix byte refuses"
        );
    }

    #[test]
    fn info_join_provider_last_wins_without_counters() {
        let mut join = InfoJoin::new();
        let first = decode_info_record(&provider_record()).expect("provider record decodes");
        join.ingest(&first, ModuleId(0), Some(CallerId(0)), None);
        let mut info = full_ck_info_lp64();
        info[48..80].copy_from_slice(&padded(b"SoftHSM v3", 32));
        let payload = payload_of(&info, &CK_INFO_RANGES_LP64);
        let second = decode_info_record(&record_bytes(
            INFO_KIND_PROVIDER,
            INFO_LAYOUT_LP64,
            &payload,
            0,
            0,
            100,
        ))
        .expect("provider record decodes");
        join.ingest(&second, ModuleId(0), Some(CallerId(0)), None);
        let (providers, observations) = join.finish();
        assert_eq!(providers.len(), 1);
        let rendered = provider_info_json(&providers[&ModuleId(0)]);
        assert_eq!(rendered["description"], "SoftHSM v3");
        assert!(rendered.get("completions").is_none());
        assert!(rendered.get("changes").is_none());
        assert!(observations.tokens.is_empty());
    }

    #[test]
    fn info_projection_is_deterministic() {
        let build = || {
            let mut join = InfoJoin::new();
            ingest_token(&mut join, 1, 1);
            ingest_token(&mut join, 0, 1);
            ingest_token(&mut join, 0, 0);
            let full = full_mech_lp64();
            for mechanism in [1082u64, 4231] {
                let record = decode_info_record(&record_bytes(
                    INFO_KIND_MECHANISM,
                    INFO_LAYOUT_LP64,
                    &full,
                    0,
                    mechanism,
                    100,
                ))
                .expect("mechanism record decodes");
                join.ingest(&record, ModuleId(0), Some(CallerId(0)), None);
            }
            let (providers, observations) = join.finish();
            let provider = decode_info_record(&provider_record()).expect("provider record decodes");
            let mut join = InfoJoin::new();
            join.ingest(&provider, ModuleId(0), Some(CallerId(0)), None);
            let (providers2, _) = join.finish();
            let _ = providers;
            (
                provider_observations_json(&observations),
                provider_info_json(&providers2[&ModuleId(0)]),
            )
        };
        let (first_obs, first_info) = build();
        let (second_obs, second_info) = build();
        assert_eq!(
            serde_json::to_string(&first_obs).expect("serialize"),
            serde_json::to_string(&second_obs).expect("serialize")
        );
        assert_eq!(
            serde_json::to_string(&first_info).expect("serialize"),
            serde_json::to_string(&second_info).expect("serialize")
        );
    }

    #[test]
    fn info_schema_v8_pins_task7_section_contract() {
        let mut join = InfoJoin::new();
        ingest_token(&mut join, 0, 0);
        let full = full_mech_lp64();
        let record = decode_info_record(&record_bytes(
            INFO_KIND_MECHANISM,
            INFO_LAYOUT_LP64,
            &full,
            0,
            1082,
            100,
        ))
        .expect("mechanism record decodes");
        join.ingest(
            &record,
            ModuleId(0),
            Some(CallerId(0)),
            Some(RegistryInstanceId::from_raw(9)),
        );
        join.note_aliased_endpoint();
        join.note_return_deferred();
        let provider = decode_info_record(&provider_record()).expect("provider record decodes");
        join.ingest(&provider, ModuleId(0), Some(CallerId(0)), None);
        let (providers, observations) = join.finish();
        let section = provider_observations_json(&observations);
        assert_eq!(section["version"], 8);
        let mut keys: Vec<&str> = section
            .as_object()
            .expect("section object")
            .keys()
            .map(String::as_str)
            .collect();
        keys.sort_unstable();
        assert_eq!(keys, vec!["gaps", "mechanisms", "tokens", "version"]);
        let token = &section["tokens"][0];
        let mut token_keys: Vec<&str> = token
            .as_object()
            .expect("token object")
            .keys()
            .map(String::as_str)
            .collect();
        token_keys.sort_unstable();
        assert_eq!(
            token_keys,
            vec![
                "caller",
                "changes",
                "completions",
                "firmware_major",
                "firmware_minor",
                "flags",
                "hardware_major",
                "hardware_minor",
                "manufacturer",
                "model",
                "module",
                "pin_max_len",
                "pin_min_len",
                "slot",
            ]
        );
        assert_eq!(token["module"], "m0");
        assert_eq!(token["caller"], "c0");
        assert!(token["slot"].is_u64());
        assert!(token["flags"].is_u64());
        let mechanism = &section["mechanisms"][0];
        assert_eq!(mechanism["instance"], "i9");
        assert!(mechanism["min_key_size"].is_u64());
        assert!(mechanism["max_key_size"].is_u64());
        let mut mechanism_keys: Vec<&str> = mechanism
            .as_object()
            .expect("mechanism object")
            .keys()
            .map(String::as_str)
            .collect();
        mechanism_keys.sort_unstable();
        assert_eq!(
            mechanism_keys,
            vec![
                "caller",
                "changes",
                "completions",
                "flags",
                "instance",
                "max_key_size",
                "mechanism",
                "min_key_size",
                "module",
                "slot",
            ]
        );
        let info = provider_info_json(&providers[&ModuleId(0)]);
        let mut info_keys: Vec<&str> = info
            .as_object()
            .expect("provider info object")
            .keys()
            .map(String::as_str)
            .collect();
        info_keys.sort_unstable();
        assert_eq!(
            info_keys,
            vec![
                "cryptoki_major",
                "cryptoki_minor",
                "description",
                "flags",
                "library_major",
                "library_minor",
                "manufacturer",
            ]
        );
        // The exact key sets above pin the producer output itself: a
        // `serial` (or label/session/memory/clock) key injected into
        // any Task 7 renderer fails this test, not just the schema or
        // golden twins.
        fn walk_keys(value: &serde_json::Value, found: &mut Vec<String>) {
            match value {
                serde_json::Value::Object(map) => {
                    for (key, child) in map {
                        found.push(key.clone());
                        walk_keys(child, found);
                    }
                }
                serde_json::Value::Array(items) => {
                    for child in items {
                        walk_keys(child, found);
                    }
                }
                _ => {}
            }
        }
        let mut found = Vec::new();
        walk_keys(&section, &mut found);
        walk_keys(&info, &mut found);
        for key in &found {
            let lowered = key.to_lowercase();
            for forbidden in [
                "serial",
                "label",
                "utctime",
                "sessioncount",
                "session_count",
                "memory",
                "password",
            ] {
                assert!(
                    !lowered.contains(forbidden),
                    "excluded key {key:?} in producer output"
                );
            }
            if lowered.contains("pin") {
                assert!(
                    ["pin_min_len", "pin_max_len"].contains(&lowered.as_str()),
                    "unexpected pin key {key:?} in producer output"
                );
            }
        }
        let gaps = section["gaps"].as_array().expect("gaps array");
        let reasons: Vec<&str> = gaps
            .iter()
            .map(|gap| gap["reason"].as_str().expect("gap reason"))
            .collect();
        assert_eq!(
            reasons,
            vec!["info_aliased_endpoint", "info_return_deferred"]
        );
    }

    #[test]
    fn info_join_refuses_token_rows_past_the_run_wide_cap() {
        // Spec §17.5: tokens are bounded run-wide; overflow refuses
        // new rows with a named counted gap while re-polls of kept
        // rows still complete.
        assert_eq!(INFO_MAX_TOKEN_ROWS, 4096);
        let mut join = InfoJoin::new();
        for slot in 0..INFO_MAX_TOKEN_ROWS as u64 {
            ingest_token(&mut join, slot, 0);
        }
        ingest_token(&mut join, INFO_MAX_TOKEN_ROWS as u64, 0);
        ingest_token(&mut join, 0, 0);
        let (_, observations) = join.finish();
        assert_eq!(observations.tokens.len(), INFO_MAX_TOKEN_ROWS);
        assert_eq!(observations.gaps.tokens_refused, 1);
        let row = observations
            .tokens
            .iter()
            .find(|row| row.slot == 0)
            .expect("slot 0 stands");
        assert_eq!(row.completions, 2);
    }

    #[test]
    fn info_join_refuses_mechanism_rows_past_the_run_wide_cap() {
        // Spec §17.5: mechanisms are bounded run-wide beside the
        // 128-per-slot cap; overflow refuses new rows with a named
        // counted gap while re-polls of kept rows still complete.
        assert_eq!(INFO_MAX_MECHANISM_ROWS, 32768);
        let mut join = InfoJoin::new();
        let full = full_mech_lp64();
        let mut rows = 0u64;
        for slot in 0..256u64 {
            for mechanism in 0..128u64 {
                let record = decode_info_record(&record_bytes(
                    INFO_KIND_MECHANISM,
                    INFO_LAYOUT_LP64,
                    &full,
                    slot,
                    mechanism,
                    100,
                ))
                .expect("mechanism record decodes");
                join.ingest(&record, ModuleId(0), Some(CallerId(0)), None);
                rows += 1;
            }
        }
        assert_eq!(rows, INFO_MAX_MECHANISM_ROWS as u64);
        let record = decode_info_record(&record_bytes(
            INFO_KIND_MECHANISM,
            INFO_LAYOUT_LP64,
            &full,
            256,
            0,
            100,
        ))
        .expect("mechanism record decodes");
        join.ingest(&record, ModuleId(0), Some(CallerId(0)), None);
        let record = decode_info_record(&record_bytes(
            INFO_KIND_MECHANISM,
            INFO_LAYOUT_LP64,
            &full,
            0,
            7,
            100,
        ))
        .expect("mechanism record decodes");
        join.ingest(&record, ModuleId(0), Some(CallerId(0)), None);
        let (_, observations) = join.finish();
        assert_eq!(observations.mechanisms.len(), INFO_MAX_MECHANISM_ROWS);
        assert_eq!(observations.gaps.mechanisms_refused, 1);
        assert_eq!(observations.gaps.mechanism_refused, 0);
        let row = observations
            .mechanisms
            .iter()
            .find(|row| row.slot == 0 && row.mechanism == 7)
            .expect("reporter 7 stands");
        assert_eq!(row.completions, 2);
    }

    #[test]
    fn info_join_folds_departed_caller_rows_with_counts() {
        // Spec §17.5: folding a departed caller retires its rows and
        // counts them; live callers stand untouched.
        let mut join = InfoJoin::new();
        ingest_token(&mut join, 0, 0);
        ingest_token(&mut join, 0, 1);
        ingest_token(&mut join, 1, 1);
        let full = full_mech_lp64();
        for (caller, slot) in [(0u32, 0u64), (1, 0), (1, 1)] {
            let record = decode_info_record(&record_bytes(
                INFO_KIND_MECHANISM,
                INFO_LAYOUT_LP64,
                &full,
                slot,
                1082,
                100 + u64::from(caller),
            ))
            .expect("mechanism record decodes");
            join.ingest(&record, ModuleId(0), Some(CallerId(caller)), None);
        }
        join.enqueue_fold(CallerId(9));
        join.enqueue_fold(CallerId(1));
        while join.fold_step(INFO_FOLD_ROWS_PER_CALL) {}
        let (_, observations) = join.finish();
        assert_eq!(observations.tokens.len(), 1);
        assert_eq!(observations.tokens[0].caller, CallerId(0));
        assert_eq!(observations.mechanisms.len(), 1);
        assert_eq!(observations.mechanisms[0].caller, CallerId(0));
        assert_eq!(observations.gaps.tokens_departed, 2);
        assert_eq!(observations.gaps.mechanisms_departed, 2);
    }

    #[test]
    fn fold_departed_caller_touches_only_its_own_rows() {
        // Scale fixture: a large unrelated live population (1000
        // token + 1000 mechanism rows) plus 2+2 rows for the
        // departing caller. The fold must touch the departing
        // slice, never scan the whole table.
        let mut join = InfoJoin::new();
        let full = full_mech_lp64();
        for slot in 0..1000u64 {
            ingest_token(&mut join, slot, 0);
            let record = decode_info_record(&record_bytes(
                INFO_KIND_MECHANISM,
                INFO_LAYOUT_LP64,
                &full,
                slot,
                0x1082,
                100,
            ))
            .expect("mechanism record decodes");
            join.ingest(&record, ModuleId(0), Some(CallerId(0)), None);
        }
        ingest_token(&mut join, 0, 9);
        ingest_token(&mut join, 1, 9);
        for mechanism in [0x1082u64, 0x1083] {
            let record = decode_info_record(&record_bytes(
                INFO_KIND_MECHANISM,
                INFO_LAYOUT_LP64,
                &full,
                0,
                mechanism,
                109,
            ))
            .expect("mechanism record decodes");
            join.ingest(&record, ModuleId(0), Some(CallerId(9)), None);
        }
        assert_eq!(join.tokens.len(), 1002);
        assert_eq!(join.mechanisms.len(), 1002);
        let visits_before = join.fold_visits;
        join.enqueue_fold(CallerId(9));
        assert!(
            !join.fold_step(INFO_FOLD_ROWS_PER_CALL),
            "four rows fold in one bounded step"
        );
        let visits = join.fold_visits - visits_before;
        assert!(
            visits <= 16,
            "fold touches the departing slice, not the table: {visits}"
        );
        assert_eq!(join.tokens.len(), 1000);
        assert_eq!(join.mechanisms.len(), 1000);
        let (_, observations) = join.finish();
        assert_eq!(observations.gaps.tokens_departed, 2);
        assert_eq!(observations.gaps.mechanisms_departed, 2);
    }

    /// Keymeta Task 7 departed fold (spec §17.5, INV-2): one caller
    /// can own hundreds of rows, and each fold call retires only a
    /// bounded slice of them through the resumable cursor — never
    /// the caller's whole table in one synchronous pass. Steps
    /// complete over subsequent calls with exact departed counts.
    #[test]
    fn fold_many_row_caller_retires_a_bounded_slice_per_call() {
        let mut join = InfoJoin::new();
        let full = full_mech_lp64();
        for slot in 0..500u64 {
            ingest_token(&mut join, slot, 9);
            let record = decode_info_record(&record_bytes(
                INFO_KIND_MECHANISM,
                INFO_LAYOUT_LP64,
                &full,
                slot,
                0x1082,
                100 + slot,
            ))
            .expect("mechanism record decodes");
            join.ingest(&record, ModuleId(0), Some(CallerId(9)), None);
        }
        assert_eq!(join.tokens.len(), 500);
        assert_eq!(join.mechanisms.len(), 500);
        join.enqueue_fold(CallerId(9));
        join.enqueue_fold(CallerId(9));
        let mut steps = 0u32;
        let mut visits_before = join.fold_visits;
        while join.fold_step(INFO_FOLD_ROWS_PER_CALL) {
            steps += 1;
            let visits = join.fold_visits - visits_before;
            assert!(
                visits <= INFO_FOLD_ROWS_PER_CALL as u64,
                "step {steps} retires a bounded slice: {visits}"
            );
            visits_before = join.fold_visits;
            assert!(steps <= 20, "1000 rows fold in bounded steps");
        }
        let visits = join.fold_visits - visits_before;
        assert!(
            visits <= INFO_FOLD_ROWS_PER_CALL as u64,
            "the final step stays bounded: {visits}"
        );
        assert_eq!(
            join.fold_visits, 1000,
            "every row retires exactly once across the steps"
        );
        assert_eq!(join.tokens.len(), 0);
        assert_eq!(join.mechanisms.len(), 0);
        let (_, observations) = join.finish();
        assert_eq!(observations.gaps.tokens_departed, 500);
        assert_eq!(observations.gaps.mechanisms_departed, 500);
    }

    /// Keymeta Task 7 departed fold (spec §17.5): a 65-row caller
    /// retires 64 rows in one bounded slice, and the unfolded
    /// remainder must not read as live — the queued departure is
    /// visible to the snapshot before the fold completes, so a stop
    /// right after the slice cannot publish a departed row.
    #[test]
    fn fold_step_over_65_rows_hides_the_unfolded_remainder_from_snapshots() {
        let mut join = InfoJoin::new();
        for slot in 0..65u64 {
            ingest_token(&mut join, slot, 9);
        }
        join.enqueue_fold(CallerId(9));
        assert!(
            join.fold_step(INFO_FOLD_ROWS_PER_CALL),
            "one row still pends after the first 64-row slice"
        );
        let (_, observations) = join.snapshot();
        assert_eq!(
            observations.gaps.tokens_departed, 64,
            "the first slice retires 64 rows"
        );
        assert!(
            observations.tokens.is_empty(),
            "the unfolded remainder of a queued caller reads departed, never live: {:?}",
            observations
                .tokens
                .iter()
                .map(|row| (row.caller, row.slot))
                .collect::<Vec<_>>()
        );
    }

    /// Keymeta Task 7 departed fold (spec §17.5, INV-2): empty
    /// callers still cost probe work — one fold step over 4096
    /// queued callers with no rows must retire a bounded prefix,
    /// never drain the whole queue for zero visits.
    #[test]
    fn fold_step_charges_empty_caller_probes() {
        let mut join = InfoJoin::new();
        for caller in 0..4096u32 {
            join.enqueue_fold(CallerId(caller));
        }
        let visits_before = join.fold_visits;
        assert!(
            join.fold_step(INFO_FOLD_ROWS_PER_CALL),
            "one step retires a bounded prefix of the empty-caller queue"
        );
        assert_eq!(
            join.fold_visits - visits_before,
            0,
            "no rows retire from empty callers"
        );
        assert_eq!(
            join.fold_queue.len(),
            4096 - 32,
            "each empty caller costs its two phase probes against the 64-credit slice"
        );
    }

    /// Keymeta Task 7 departed fold (spec §17.5, INV-2): the Finish
    /// disclosure over queued-but-unfolded callers reads maintained
    /// counts, never table scans — 4096 empty pending callers disclose
    /// with zero unfolded rows, and live rows keep their counts even
    /// when the tables disagree (a pending scan would read zero).
    #[test]
    fn finish_disclosure_spends_no_probes_over_empty_callers() {
        let mut join = InfoJoin::new();
        for caller in 0..4096u32 {
            join.enqueue_fold(CallerId(caller));
        }
        assert_eq!(
            join.fold_deferred(),
            (4096, 0),
            "the pending count discloses with zero unfolded rows"
        );
        let mut join = InfoJoin::new();
        for slot in 0..3u64 {
            ingest_token(&mut join, slot, 7);
        }
        ingest_token(&mut join, 0, 9);
        join.enqueue_fold(CallerId(7));
        join.enqueue_fold(CallerId(9));
        assert_eq!(
            join.fold_deferred(),
            (2, 4),
            "three plus one rows pend before the tables disagree"
        );
        join.tokens.clear();
        join.mechanisms.clear();
        assert_eq!(
            join.fold_deferred(),
            (2, 4),
            "the disclosure reads maintained counts, never table scans"
        );
    }

    /// Keymeta Task 7 departed fold (spec §17.5): the maintained
    /// disclosure counts stay exact across ingest, repeats,
    /// queueing and partial folds — repeats add no rows, a bounded
    /// slice decrements the pending total, rows that land for a
    /// queued caller count while queued, and draining the queue
    /// clears both counts with no per-caller residue.
    #[test]
    fn finish_disclosure_counts_stay_exact_across_folds() {
        let mut join = InfoJoin::new();
        // Caller 7: three token rows; a repeat adds no row.
        for slot in 0..3u64 {
            ingest_token(&mut join, slot, 7);
        }
        ingest_token(&mut join, 0, 7);
        // Caller 9: one token row and two mechanism rows.
        ingest_token(&mut join, 0, 9);
        let full = full_mech_lp64();
        for mechanism in [0x1082u64, 0x1083] {
            let record = decode_info_record(&record_bytes(
                INFO_KIND_MECHANISM,
                INFO_LAYOUT_LP64,
                &full,
                0,
                mechanism,
                109,
            ))
            .expect("mechanism record decodes");
            join.ingest(&record, ModuleId(0), Some(CallerId(9)), None);
        }
        assert_eq!(join.fold_deferred(), (0, 0), "nothing pends yet");
        join.enqueue_fold(CallerId(7));
        join.enqueue_fold(CallerId(9));
        assert_eq!(
            join.fold_deferred(),
            (2, 6),
            "three token rows plus one token and two mechanism rows"
        );
        // A bounded slice retires two of caller 7's token rows.
        assert!(
            join.fold_step(2),
            "four rows still pend after the first slice"
        );
        assert_eq!(join.fold_deferred(), (2, 4));
        // Rows that land for a queued caller count while queued.
        ingest_token(&mut join, 9, 7);
        assert_eq!(join.fold_deferred(), (2, 5));
        // Draining the queue clears both counts.
        while join.fold_step(INFO_FOLD_ROWS_PER_CALL) {}
        assert_eq!(join.fold_deferred(), (0, 0));
        assert!(
            join.caller_rows.is_empty(),
            "no per-caller count survives its fold: {:?}",
            join.caller_rows
        );
    }

    #[test]
    fn info_gaps_render_new_reasons_in_fixed_order() {
        let observations = ProviderObservations {
            tokens: Vec::new(),
            mechanisms: Vec::new(),
            gaps: ProviderGaps {
                aliased: 1,
                return_deferred: 2,
                return_refused_hazard: 9,
                caller_unavailable: 3,
                mechanism_refused: 4,
                tokens_refused: 5,
                mechanisms_refused: 6,
                tokens_departed: 7,
                mechanisms_departed: 8,
            },
        };
        let section = provider_observations_json(&observations);
        let gaps = section["gaps"].as_array().expect("gaps array");
        let reasons: Vec<&str> = gaps
            .iter()
            .map(|gap| gap["reason"].as_str().expect("gap reason"))
            .collect();
        assert_eq!(
            reasons,
            vec![
                "info_aliased_endpoint",
                "info_return_deferred",
                "info_return_refused_hazard",
                "info_caller_unavailable",
                "mechanism_info_refused",
                "info_token_rows_refused",
                "info_mechanism_rows_refused",
                "info_token_departed_folded",
                "info_mechanism_departed_folded",
            ]
        );
        let counts: Vec<u64> = gaps
            .iter()
            .map(|gap| gap["count"].as_u64().expect("gap count"))
            .collect();
        assert_eq!(counts, vec![1, 2, 9, 3, 4, 5, 6, 7, 8]);
    }

    /// Root-crate LP64 cross-check (spec §17.1 layer 3): the shared
    /// read lists cover exactly the read fields of the cryptoki-sys
    /// 0.5.0 bindgen types — every read field's
    /// `size_of`/`offset_of` sits inside the ranges, and every
    /// excluded §17.2 byte (label, serial, session counts, memory
    /// sizes, utcTime) plus every struct pad sits outside them. A pin
    /// bump that moves any field fails here. The ia32 literals are
    /// pinned by the byte-exact round-trip buffers below.
    #[test]
    fn info_read_lists_match_cryptoki_sys_lp64() {
        use core::mem::{offset_of, size_of};
        use cryptoki_sys::{CK_INFO, CK_MECHANISM_INFO, CK_TOKEN_INFO, CK_ULONG, CK_VERSION};
        use p11scope_ebpf_common::LinuxLayout::Lp64;
        use p11scope_ebpf_common::inventory_info::{
            info_payload_len, info_read_ranges, info_span_size,
        };
        // This host is LP64: the bindgen word is 8 bytes.
        assert_eq!(size_of::<CK_ULONG>(), 8);
        assert_eq!(size_of::<CK_VERSION>(), 2);
        // (kind, bindgen span, read fields as (offset, width),
        // excluded fields as (offset, width)).
        type FieldCase<'a> = (u8, usize, &'a [(usize, usize)], &'a [(usize, usize)]);
        let cases: [FieldCase<'_>; 3] = [
            (
                INFO_KIND_PROVIDER,
                size_of::<CK_INFO>(),
                &[
                    (
                        offset_of!(CK_INFO, cryptokiVersion),
                        size_of::<CK_VERSION>(),
                    ),
                    (offset_of!(CK_INFO, manufacturerID), 32),
                    (offset_of!(CK_INFO, flags), size_of::<CK_ULONG>()),
                    (offset_of!(CK_INFO, libraryDescription), 32),
                    (offset_of!(CK_INFO, libraryVersion), size_of::<CK_VERSION>()),
                ],
                &[],
            ),
            (
                INFO_KIND_TOKEN,
                size_of::<CK_TOKEN_INFO>(),
                &[
                    (offset_of!(CK_TOKEN_INFO, manufacturerID), 32),
                    (offset_of!(CK_TOKEN_INFO, model), 16),
                    (offset_of!(CK_TOKEN_INFO, flags), size_of::<CK_ULONG>()),
                    (
                        offset_of!(CK_TOKEN_INFO, ulMaxPinLen),
                        size_of::<CK_ULONG>(),
                    ),
                    (
                        offset_of!(CK_TOKEN_INFO, ulMinPinLen),
                        size_of::<CK_ULONG>(),
                    ),
                    (
                        offset_of!(CK_TOKEN_INFO, hardwareVersion),
                        size_of::<CK_VERSION>(),
                    ),
                    (
                        offset_of!(CK_TOKEN_INFO, firmwareVersion),
                        size_of::<CK_VERSION>(),
                    ),
                ],
                &[
                    (offset_of!(CK_TOKEN_INFO, label), 32),
                    (offset_of!(CK_TOKEN_INFO, serialNumber), 16),
                    (
                        offset_of!(CK_TOKEN_INFO, ulMaxSessionCount),
                        size_of::<CK_ULONG>(),
                    ),
                    (
                        offset_of!(CK_TOKEN_INFO, ulSessionCount),
                        size_of::<CK_ULONG>(),
                    ),
                    (
                        offset_of!(CK_TOKEN_INFO, ulMaxRwSessionCount),
                        size_of::<CK_ULONG>(),
                    ),
                    (
                        offset_of!(CK_TOKEN_INFO, ulRwSessionCount),
                        size_of::<CK_ULONG>(),
                    ),
                    (
                        offset_of!(CK_TOKEN_INFO, ulTotalPublicMemory),
                        size_of::<CK_ULONG>(),
                    ),
                    (
                        offset_of!(CK_TOKEN_INFO, ulFreePublicMemory),
                        size_of::<CK_ULONG>(),
                    ),
                    (
                        offset_of!(CK_TOKEN_INFO, ulTotalPrivateMemory),
                        size_of::<CK_ULONG>(),
                    ),
                    (
                        offset_of!(CK_TOKEN_INFO, ulFreePrivateMemory),
                        size_of::<CK_ULONG>(),
                    ),
                    (offset_of!(CK_TOKEN_INFO, utcTime), 16),
                ],
            ),
            (
                INFO_KIND_MECHANISM,
                size_of::<CK_MECHANISM_INFO>(),
                &[
                    (
                        offset_of!(CK_MECHANISM_INFO, ulMinKeySize),
                        size_of::<CK_ULONG>(),
                    ),
                    (
                        offset_of!(CK_MECHANISM_INFO, ulMaxKeySize),
                        size_of::<CK_ULONG>(),
                    ),
                    (offset_of!(CK_MECHANISM_INFO, flags), size_of::<CK_ULONG>()),
                ],
                &[],
            ),
        ];
        for (kind, bindgen_span, read_fields, excluded) in cases {
            let span = usize::from(info_span_size(kind, Lp64).expect("span"));
            assert_eq!(span, bindgen_span, "kind {kind}: span is the bindgen size");
            let list = info_read_ranges(kind, Lp64).expect("ranges");
            let live = &list.ranges[..usize::from(list.count)];
            let mut covered = vec![false; span];
            let mut sum = 0usize;
            for (off, len) in live {
                let (off, len) = (usize::from(*off), usize::from(*len));
                for byte in &mut covered[off..off + len] {
                    assert!(!*byte, "kind {kind}: ranges are disjoint");
                    *byte = true;
                }
                sum += len;
            }
            assert_eq!(
                sum,
                usize::from(info_payload_len(kind, Lp64).expect("payload len")),
                "kind {kind}: bytes sum"
            );
            for (off, len) in read_fields {
                assert!(
                    covered[*off..off + len].iter().all(|byte| *byte),
                    "kind {kind}: read field [{off}..{}) covered",
                    off + len
                );
            }
            for (off, len) in excluded {
                assert!(
                    covered[*off..off + len].iter().all(|byte| !*byte),
                    "kind {kind}: excluded field [{off}..{}) never read",
                    off + len
                );
            }
            // No read byte is unaccounted: every covered byte belongs
            // to a read field.
            for (index, byte) in covered.iter().enumerate() {
                if *byte {
                    assert!(
                        read_fields
                            .iter()
                            .any(|(off, len)| index >= *off && index < *off + *len),
                        "kind {kind}: byte {index} belongs to a read field"
                    );
                }
            }
        }
    }

    fn full_mech_ilp32() -> [u8; 12] {
        let mut mech = [0u8; 12];
        mech[0..4].copy_from_slice(&128u32.to_le_bytes());
        mech[4..8].copy_from_slice(&256u32.to_le_bytes());
        mech[8..12].copy_from_slice(&3u32.to_le_bytes());
        mech
    }

    /// One writer→decoder round trip through the production path:
    /// the return adapter packs the struct bytes, the shared encoder
    /// emits the 176-byte record, and the decoder accepts exactly
    /// those bytes. Struct buffers are built at the transcribed
    /// §17.1 offsets (the ia32 oracle, cited to the i686 bindgen
    /// asserts); LP64 additionally cross-checks against bindgen
    /// above.
    fn round_trip_via_writer(
        kind: u8,
        layout_code: u8,
        struct_bytes: &[u8],
        slot: u64,
        mechanism: u64,
    ) -> Vec<u8> {
        use p11scope_ebpf_common::LinuxLayout;
        use p11scope_ebpf_common::inventory_info::{InfoHeader, encode_info_record};
        use p11scope_ebpf_common::object_flow::{
            InfoReturnVerdict, InfoStart, adapter_info_return,
        };
        let layout = match layout_code {
            INFO_LAYOUT_LP64 => LinuxLayout::Lp64,
            _ => LinuxLayout::Ilp32,
        };
        let base = 0x4000u64;
        let stash = InfoStart {
            info_ptr: base,
            slot,
            mechanism,
            kind,
            layout: layout_code,
            reserved: [0; 6],
        };
        let mut reader = p11scope_ebpf_common::FnByteReader(
            |address: u64, _layout: LinuxLayout, out: &mut [u8]| {
                let start = usize::try_from(address.wrapping_sub(base)).map_err(|_| ())?;
                let end = start.checked_add(out.len()).ok_or(())?;
                out.copy_from_slice(struct_bytes.get(start..end).ok_or(())?);
                Ok(())
            },
        );
        let mut payload = [0xCCu8; INFO_PAYLOAD_MAX];
        let verdict = adapter_info_return(&stash, 0, layout, &mut payload, &mut reader);
        let InfoReturnVerdict::Emit(len) = verdict else {
            panic!("kind {kind}: CKR_OK packs, got {verdict:?}");
        };
        assert!(
            payload[len as usize..].iter().all(|byte| *byte == 0),
            "kind {kind}: slack past {len} is zero"
        );
        let header = InfoHeader {
            endpoint: 7,
            kind,
            layout: layout_code,
            reserved0: 0,
            host_tgid: 4242,
            reserved1: 0,
            task_cookie: 11,
            exec_id: 9,
            slot,
            mechanism,
        };
        let mut out = [0xCCu8; INFO_RECORD_LEN];
        assert!(encode_info_record(
            &mut out,
            &header,
            INFO_STATUS_OK,
            &payload
        ));
        out.to_vec()
    }

    #[test]
    fn info_round_trip_provider_lp64() {
        let full = full_ck_info_lp64();
        let bytes = round_trip_via_writer(INFO_KIND_PROVIDER, INFO_LAYOUT_LP64, &full, 0, 0);
        assert!(!bytes.contains(&0xAA), "no pad byte reaches the record");
        let record = decode_info_record(&bytes).expect("the writer output decodes");
        assert_eq!(record.kind, INFO_KIND_PROVIDER);
        assert_eq!(record.layout, INFO_LAYOUT_LP64);
        assert_eq!(record.payload_len, 76);
        let InfoValues::Provider(values) = parse_info_payload(&record) else {
            panic!("provider kind parses as provider");
        };
        assert_eq!((values.cryptoki_major, values.cryptoki_minor), (3, 1));
        assert_eq!(values.manufacturer.as_deref(), Ok("SoftHSM"));
        assert_eq!(values.flags, 0);
        assert_eq!(values.description.as_deref(), Ok("SoftHSM v2"));
        assert_eq!((values.library_major, values.library_minor), (2, 6));
    }

    #[test]
    fn info_round_trip_provider_ilp32() {
        let full = full_ck_info_ilp32();
        let bytes = round_trip_via_writer(INFO_KIND_PROVIDER, INFO_LAYOUT_ILP32, &full, 0, 0);
        assert!(!bytes.contains(&0xAA), "no pad byte reaches the record");
        let record = decode_info_record(&bytes).expect("the writer output decodes");
        assert_eq!(record.kind, INFO_KIND_PROVIDER);
        assert_eq!(record.layout, INFO_LAYOUT_ILP32);
        assert_eq!(record.payload_len, 72);
        let InfoValues::Provider(values) = parse_info_payload(&record) else {
            panic!("provider kind parses as provider");
        };
        assert_eq!((values.cryptoki_major, values.cryptoki_minor), (3, 1));
        assert_eq!(values.manufacturer.as_deref(), Ok("SoftHSM"));
        assert_eq!(values.flags, 0);
        assert_eq!(values.description.as_deref(), Ok("SoftHSM v2"));
        assert_eq!((values.library_major, values.library_minor), (2, 6));
    }

    #[test]
    fn info_round_trip_token_lp64() {
        let full = full_token_lp64();
        let bytes = round_trip_via_writer(INFO_KIND_TOKEN, INFO_LAYOUT_LP64, &full, 3, 0);
        assert!(
            !bytes.contains(&0xAA),
            "no excluded byte reaches the record"
        );
        let record = decode_info_record(&bytes).expect("the writer output decodes");
        assert_eq!(record.kind, INFO_KIND_TOKEN);
        assert_eq!(record.layout, INFO_LAYOUT_LP64);
        assert_eq!(record.payload_len, 76);
        assert_eq!(record.slot, 3);
        let InfoValues::Token(values) = parse_info_payload(&record) else {
            panic!("token kind parses as token");
        };
        assert_eq!(values.manufacturer.as_deref(), Ok("TokenMfr"));
        assert_eq!(values.model.as_deref(), Ok("Model-X"));
        assert_eq!(values.flags, 0x06);
        assert_eq!(values.pin_min_len, 4);
        assert_eq!(values.pin_max_len, 255);
        assert_eq!((values.hardware_major, values.hardware_minor), (2, 6));
        assert_eq!((values.firmware_major, values.firmware_minor), (2, 7));
    }

    #[test]
    fn info_round_trip_token_ilp32() {
        let full = full_token_ilp32();
        let bytes = round_trip_via_writer(INFO_KIND_TOKEN, INFO_LAYOUT_ILP32, &full, 3, 0);
        assert!(
            !bytes.contains(&0xAA),
            "no excluded byte reaches the record"
        );
        let record = decode_info_record(&bytes).expect("the writer output decodes");
        assert_eq!(record.kind, INFO_KIND_TOKEN);
        assert_eq!(record.layout, INFO_LAYOUT_ILP32);
        assert_eq!(record.payload_len, 64);
        assert_eq!(record.slot, 3);
        let InfoValues::Token(values) = parse_info_payload(&record) else {
            panic!("token kind parses as token");
        };
        assert_eq!(values.manufacturer.as_deref(), Ok("TokenMfr"));
        assert_eq!(values.model.as_deref(), Ok("Model-X"));
        assert_eq!(values.flags, 0x06);
        assert_eq!(values.pin_min_len, 4);
        assert_eq!(values.pin_max_len, 255);
        assert_eq!((values.hardware_major, values.hardware_minor), (2, 6));
        assert_eq!((values.firmware_major, values.firmware_minor), (2, 7));
    }

    #[test]
    fn info_round_trip_mechanism_lp64() {
        let full = full_mech_lp64();
        let bytes = round_trip_via_writer(INFO_KIND_MECHANISM, INFO_LAYOUT_LP64, &full, 3, 0x1082);
        let record = decode_info_record(&bytes).expect("the writer output decodes");
        assert_eq!(record.kind, INFO_KIND_MECHANISM);
        assert_eq!(record.layout, INFO_LAYOUT_LP64);
        assert_eq!(record.payload_len, 24);
        assert_eq!(record.slot, 3);
        assert_eq!(record.mechanism, 0x1082);
        let InfoValues::Mechanism(values) = parse_info_payload(&record) else {
            panic!("mechanism kind parses as mechanism");
        };
        assert_eq!(values.min_key_size, 1024);
        assert_eq!(values.max_key_size, 4096);
        assert_eq!(values.flags, 1);
    }

    #[test]
    fn info_round_trip_mechanism_ilp32() {
        let full = full_mech_ilp32();
        let bytes = round_trip_via_writer(INFO_KIND_MECHANISM, INFO_LAYOUT_ILP32, &full, 3, 0x1082);
        let record = decode_info_record(&bytes).expect("the writer output decodes");
        assert_eq!(record.kind, INFO_KIND_MECHANISM);
        assert_eq!(record.layout, INFO_LAYOUT_ILP32);
        assert_eq!(record.payload_len, 12);
        assert_eq!(record.slot, 3);
        assert_eq!(record.mechanism, 0x1082);
        let InfoValues::Mechanism(values) = parse_info_payload(&record) else {
            panic!("mechanism kind parses as mechanism");
        };
        assert_eq!(values.min_key_size, 128);
        assert_eq!(values.max_key_size, 256);
        assert_eq!(values.flags, 3);
    }

    /// An unreadable struct at return still yields a valid record:
    /// status UNAVAILABLE with a zero payload decodes, and the join
    /// publishes nothing from it.
    #[test]
    fn info_round_trip_unavailable_joins_to_nothing() {
        use p11scope_ebpf_common::LinuxLayout;
        use p11scope_ebpf_common::inventory_info::{InfoHeader, encode_info_record};
        use p11scope_ebpf_common::object_flow::{
            InfoReturnVerdict, InfoStart, adapter_info_return,
        };
        let stash = InfoStart {
            info_ptr: 0x4000,
            slot: 3,
            mechanism: 0,
            kind: INFO_KIND_TOKEN,
            layout: INFO_LAYOUT_LP64,
            reserved: [0; 6],
        };
        let mut reader = p11scope_ebpf_common::FnByteReader(
            |_address: u64, _layout: LinuxLayout, _out: &mut [u8]| Err(()),
        );
        let mut payload = [0xCCu8; INFO_PAYLOAD_MAX];
        let verdict = adapter_info_return(&stash, 0, LinuxLayout::Lp64, &mut payload, &mut reader);
        assert_eq!(verdict, InfoReturnVerdict::Unavailable);
        assert_eq!(payload, [0u8; INFO_PAYLOAD_MAX]);
        let header = InfoHeader {
            endpoint: 7,
            kind: INFO_KIND_TOKEN,
            layout: INFO_LAYOUT_LP64,
            reserved0: 0,
            host_tgid: 4242,
            reserved1: 0,
            task_cookie: 11,
            exec_id: 9,
            slot: 3,
            mechanism: 0,
        };
        let mut out = [0xCCu8; INFO_RECORD_LEN];
        assert!(encode_info_record(
            &mut out,
            &header,
            INFO_STATUS_UNAVAILABLE,
            &payload
        ));
        let record = decode_info_record(&out).expect("unavailable decodes");
        assert_eq!(record.status, INFO_STATUS_UNAVAILABLE);
        let mut join = InfoJoin::new();
        join.ingest(&record, ModuleId(1), Some(CallerId(11)), None);
        let (providers, observations) = join.finish();
        assert!(providers.is_empty());
        assert!(observations.is_empty());
    }
}
