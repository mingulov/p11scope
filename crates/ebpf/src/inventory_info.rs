//! SPDX-License-Identifier: GPL-2.0-only
//! SPDX-FileCopyrightText: 2026 Denis Mingulov <denis@mingulov.com>
//! Inventory info pair (v0.8.0 keymeta Task 7, spec §17.4). FULL
//! inventory flavors only: per-ABI entry probes running the unchanged
//! `usage_entry` body first, then a scope-gated stash; one return
//! probe emitting the 176-byte info record on the dedicated `INFO`
//! ring. The P0 inventory flavor omits this module (exact
//! 12-program list), so P0 acquires no info bytes.
use super::*;
use core::ffi::c_void;
use p11scope_ebpf_common::inventory_info::{
    INFO_LAYOUT_ILP32, INFO_LAYOUT_LP64, INFO_PAYLOAD_MAX, INFO_RECORD_LEN, INFO_STATUS_OK,
    INFO_STATUS_UNAVAILABLE, InfoHeader, encode_info_record, info_kind_valid, info_uses_arg,
};
use p11scope_ebpf_common::object_capture::validate_target_span;
use p11scope_ebpf_common::object_flow::{
    InfoReturnVerdict, InfoStart, adapter_info_entry, adapter_info_return,
};
use p11scope_ebpf_common::{
    EVIDENCE_ABI_REFUSALS, INFO_EVIDENCE_CELLS, INFO_EVIDENCE_INSERT_FAILURES,
    INFO_EVIDENCE_NESTED_OVERWRITES, INFO_EVIDENCE_RING_LOSS, INFO_EVIDENCE_STASH_MISMATCHES,
    INFO_EVIDENCE_UNMATCHED_RETURNS, INVENTORY_INFO_BYTES, ImageIdentity, InfoByteReader,
    LinuxLayout, PRODUCED_INFO, StartKey, inventory_cookie_endpoint,
};

/// In-flight info-call stash (spec §17.4): one 32-byte row per
/// in-flight call at an info endpoint, keyed by (`pid_tgid`,
/// endpoint) — the endpoint leg is required because the p11-kit
/// proxy nests info calls on the same thread across endpoints.
/// Cold in-flight calls only: 1024 rows.
#[map]
static INFO_START: HashMap<StartKey, InfoStart> = HashMap::with_max_entries(1024, 0);

/// The dedicated INFO ring (spec §17.4): 64 KiB of cold traffic,
/// drained in the inventory session alongside DISCOVERY.
#[map]
static INFO: RingBuf = RingBuf::with_byte_size(INVENTORY_INFO_BYTES, 0);

/// Endpoint→kind publication (spec §17.4, fix9 R1): the kind in the
/// low byte, written once per endpoint after its return link exists
/// and read back. Placeholder only: the loader must set the approved
/// nonzero N before load. Never frozen: endpoints are admitted
/// during capture extends, after preparation loaded the programs.
#[map]
static INFO_KIND: Array<u64> = Array::with_max_entries(1, BPF_F_RDONLY_PROG);

/// Info evidence cells (spec §17.4): insert failures, unmatched
/// returns, nested overwrites, stash mismatches and INFO ring
/// losses — never silent, never folded into `EVIDENCE`.
#[map]
static INFO_EVIDENCE: PerCpuArray<u64> =
    PerCpuArray::with_max_entries(INFO_EVIDENCE_CELLS, 0);

fn bump_info_evidence(index: u32) {
    if let Some(value) = INFO_EVIDENCE.get_ptr_mut(index) {
        counter_add(value, 1);
    }
}

struct BpfInfoReader;

impl InfoByteReader for BpfInfoReader {
    #[inline(always)]
    #[allow(clippy::result_unit_err)]
    fn read_bytes(&mut self, addr: u64, layout: LinuxLayout, out: &mut [u8]) -> Result<(), ()> {
        validate_target_span(addr, out.len() as u64, layout).ok_or(())?;
        unsafe { helpers::bpf_probe_read_user_buf(addr as *const u8, out) }.map_err(|_| ())
    }
}

#[uprobe]
pub fn p11_info_entry_lp64(ctx: ProbeContext) -> u32 {
    keep_endpoint_stack(&ctx);
    info_entry(ctx, LinuxLayout::Lp64)
}

#[uprobe]
pub fn p11_info_entry_ia32(ctx: ProbeContext) -> u32 {
    keep_endpoint_stack(&ctx);
    info_entry(ctx, LinuxLayout::Ilp32)
}

/// The info entry: the UNCHANGED `usage_entry` body first (so the
/// usage witness — Global bitmap or Callers `CALLER_USE` row — still
/// records), then the re-evaluated admit gates and the stash.
/// `usage_entry` returns 0 on every path, so its return value cannot
/// gate the stash (fix9 R3): without re-evaluation, processes
/// outside the operator's scope would have their info captured.
#[inline(always)]
fn info_entry(ctx: ProbeContext, declared_layout: LinuxLayout) -> u32 {
    // Rebuilt below for the stash after the shared entry consumes
    // `ctx` (ProbeContext is move-only): the regs pointer stays valid
    // for the whole probe invocation.
    let regs = ctx.regs as *mut c_void;
    super::inventory::usage_entry(ctx, declared_layout);
    let ctx = ProbeContext::new(regs);
    if scope_auth().is_none() {
        return 0;
    }
    if probe_layout(&ctx) != Some(declared_layout) {
        bump_evidence(EVIDENCE_ABI_REFUSALS);
        return 0;
    }
    let Some(config) = super::inventory::USAGE_CONFIG
        .get(0)
        .copied()
        .filter(|config| config.is_valid())
    else {
        super::inventory::bump_usage_evidence(
            p11scope_ebpf_common::USAGE_EVIDENCE_INVALID_CONFIG,
        );
        return 0;
    };
    let Some(endpoint) = inventory_cookie_endpoint(cookie_of(&ctx), config.endpoint_capacity)
    else {
        super::inventory::bump_usage_evidence(
            p11scope_ebpf_common::USAGE_EVIDENCE_INVALID_COOKIE,
        );
        return 0;
    };
    let kind = INFO_KIND.get(endpoint).copied().unwrap_or(0) as u8;
    if !info_kind_valid(kind) {
        // Usage-only, return-deferred or revoked endpoint (kind 0,
        // or a value userspace never publishes): the usage witness
        // above still recorded, and nothing stashes.
        return 0;
    }
    stash_info_entry(&ctx, endpoint, kind, declared_layout);
    0
}

/// Run the info entry adapter and bind the stash row: insert on
/// retention (overwrite, counting the nested overwrite), delete on
/// unavailable (a stale row is never trusted), count full-map insert
/// failures. Outlined (not inlined): the 32-byte row, the pre-fetched
/// argument array and the adapter spills stay out of the root frame.
#[inline(never)]
fn stash_info_entry(ctx: &ProbeContext, endpoint: u32, kind: u8, layout: LinuxLayout) {
    let mut row = InfoStart::default();
    // Pre-fetch every info argument slot with a compile-time-constant
    // index (spec §17.1: indices ≤ 2). A dynamic index into `arg_u64`
    // becomes register-offset pt_regs arithmetic, which the verifier
    // rejects; words start zeroed beside a validity mask (the length
    // stash precedent). The fetch closure only indexes these arrays,
    // never `arg_u64`.
    let mut words = [0u64; 3];
    let mut present: u8 = 0;
    // Kind-gated loads (spec §17.1, allowlist-v3 named positions):
    // each constant-index site reads only when the kind authorizes
    // that position, so ia32 stack words outside the function
    // signature are never touched.
    if info_uses_arg(kind, 0) {
        if let Ok(word) = arg_u64(ctx, 0, layout) {
            words[0] = word;
            present |= 0x01;
        }
    }
    if info_uses_arg(kind, 1) {
        if let Ok(word) = arg_u64(ctx, 1, layout) {
            words[1] = word;
            present |= 0x02;
        }
    }
    if info_uses_arg(kind, 2) {
        if let Ok(word) = arg_u64(ctx, 2, layout) {
            words[2] = word;
            present |= 0x04;
        }
    }
    let mut fetch = |index: u8| {
        if index < 3 && present & (1 << index) != 0 {
            Some(words[index as usize])
        } else {
            None
        }
    };
    let key = StartKey {
        pid_tgid: helpers::bpf_get_current_pid_tgid(),
        slot: endpoint,
        _pad: 0,
    };
    if !adapter_info_entry(&mut row, kind, layout, &mut fetch) {
        let _ = INFO_START.remove(&key);
        return;
    }
    if INFO_START.get_ptr(&key).is_some() {
        bump_info_evidence(INFO_EVIDENCE_NESTED_OVERWRITES);
    }
    if INFO_START.insert(&key, &row, 0).is_err() {
        bump_info_evidence(INFO_EVIDENCE_INSERT_FAILURES);
    }
}

/// The info return: enforce the endpoint's LIVE kind, then copy
/// the stash row and delete it unconditionally (every return
/// deletes), then resolve the return adapter (RV + owned layout).
/// Out-of-scope returns delete silently and count nothing (their
/// entries never stashed). A revoked or unknown live kind deletes
/// silently too — the entry stashed nothing there, a valid stash
/// racing the revocation loses INFO authority here with its pointer
/// never read, and later in-scope invocations after revocation
/// count nothing. A missing row on an eligible call counts the
/// named unmatched return and emits nothing; a stash/live kind
/// skew or layout skew counts the named mismatch; a non-OK RV
/// emits nothing (fix9 R5 — a failed return such as
/// `CKR_TOKEN_NOT_PRESENT` on a polled empty slot must not leave its
/// row behind); `CKR_OK` emits the 176-byte record, status-1 with a
/// zero payload when the bytes are unreadable.
#[uretprobe]
pub fn p11_info_return(ctx: RetProbeContext) -> u32 {
    keep_endpoint_stack(&ctx);
    let pid_tgid = helpers::bpf_get_current_pid_tgid();
    let Some(config) = super::inventory::USAGE_CONFIG
        .get(0)
        .copied()
        .filter(|config| config.is_valid())
    else {
        super::inventory::bump_usage_evidence(
            p11scope_ebpf_common::USAGE_EVIDENCE_INVALID_CONFIG,
        );
        return 0;
    };
    let Some(endpoint) = inventory_cookie_endpoint(cookie_of(&ctx), config.endpoint_capacity)
    else {
        super::inventory::bump_usage_evidence(
            p11scope_ebpf_common::USAGE_EVIDENCE_INVALID_COOKIE,
        );
        return 0;
    };
    let key = StartKey {
        pid_tgid,
        slot: endpoint,
        _pad: 0,
    };
    if scope_auth().is_none() {
        // Out-of-scope returns never stashed (the entry refuses
        // them): delete any row silently and count nothing, so the
        // unmatched diagnostic counts only eligible calls.
        let _ = INFO_START.remove(&key);
        return 0;
    }
    // Revocation authority (spec §17.4): the zero-write read-back is
    // the boundary. Past it, the live cell reads 0 (or an unknown
    // value userspace never publishes): the entry stashed nothing,
    // so the return deletes any racing row silently and counts
    // nothing — no saved-pointer read, no unmatched count.
    let live_kind = INFO_KIND.get(endpoint).copied().unwrap_or(0) as u8;
    if !info_kind_valid(live_kind) {
        let _ = INFO_START.remove(&key);
        return 0;
    }
    let stash = INFO_START.get_ptr(&key).map(|row| unsafe { *row });
    let _ = INFO_START.remove(&key);
    let Some(stash) = stash else {
        bump_info_evidence(INFO_EVIDENCE_UNMATCHED_RETURNS);
        return 0;
    };
    // Kinds only ever clear to zero (never N1→N2), so a live/stash
    // skew fails noisy, never silent — and never reads.
    if stash.kind != live_kind {
        bump_info_evidence(INFO_EVIDENCE_STASH_MISMATCHES);
        return 0;
    }
    let Some(layout) = ret_probe_layout(&ctx) else {
        bump_info_evidence(INFO_EVIDENCE_STASH_MISMATCHES);
        return 0;
    };
    let rv = normalize_target_word(ctx.ret(), layout);
    let mut payload = [0u8; INFO_PAYLOAD_MAX];
    match adapter_info_return(&stash, rv, layout, &mut payload, &mut BpfInfoReader) {
        InfoReturnVerdict::Emit(_) => {
            emit_info_record(endpoint, &stash, layout, INFO_STATUS_OK, &payload, pid_tgid)
        }
        InfoReturnVerdict::Unavailable => emit_info_record(
            endpoint,
            &stash,
            layout,
            INFO_STATUS_UNAVAILABLE,
            &payload,
            pid_tgid,
        ),
        InfoReturnVerdict::Silent => 0,
        InfoReturnVerdict::StashMismatch => {
            bump_info_evidence(INFO_EVIDENCE_STASH_MISMATCHES);
            0
        }
    }
}

/// Build the record header (identity via `p11_link_current_identity`
/// in the Callers flavor, zero in the Global flavor) and emit the
/// shared encoding on the INFO ring. A failed reservation counts
/// the INFO ring loss in its own evidence cell (never the shared
/// discovery ring loss); a submitted record bumps `PRODUCED_INFO`,
/// the kernel half of the drain cross-check.
#[inline(always)]
fn emit_info_record(
    endpoint: u32,
    stash: &InfoStart,
    layout: LinuxLayout,
    status: u8,
    payload: &[u8; INFO_PAYLOAD_MAX],
    pid_tgid: u64,
) -> u32 {
    #[cfg(feature = "inventory-callers")]
    let image = {
        let mut image = ImageIdentity::default();
        if unsafe { p11_link_current_identity(&mut image) } != 1 || image.task_cookie == 0 {
            ImageIdentity::default()
        } else {
            image
        }
    };
    #[cfg(not(feature = "inventory-callers"))]
    let image = ImageIdentity::default();
    let header = InfoHeader {
        endpoint,
        kind: stash.kind,
        layout: match layout {
            LinuxLayout::Lp64 => INFO_LAYOUT_LP64,
            LinuxLayout::Ilp32 => INFO_LAYOUT_ILP32,
        },
        reserved0: 0,
        host_tgid: (pid_tgid >> 32) as u32,
        reserved1: 0,
        task_cookie: image.task_cookie,
        exec_id: image.exec_id,
        slot: stash.slot,
        mechanism: stash.mechanism,
    };
    let Some(mut entry) = INFO.reserve::<[u8; INFO_RECORD_LEN]>(0) else {
        bump_info_evidence(INFO_EVIDENCE_RING_LOSS);
        return 0;
    };
    let raw = entry.as_mut_ptr();
    // SAFETY: the reservation owns exactly one aligned 176-byte
    // record; the shared encoder fills every byte or fails closed.
    if !encode_info_record(unsafe { &mut *raw }, &header, status, payload) {
        entry.discard(0);
        bump_info_evidence(INFO_EVIDENCE_STASH_MISMATCHES);
        return 0;
    }
    entry.submit(0);
    bump_produced(PRODUCED_INFO);
    0
}
