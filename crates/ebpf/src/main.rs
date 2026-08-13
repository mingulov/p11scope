//! p11scope BPF programs. A lightweight or template-aware entry program
//! plus one return program serve every attach point. The attach cookie
//! carries the slot index, so 68+ probes share a small fixed program set
//! rather than per-function copies. Cookies need kernel >= 5.15.
#![no_std]
#![no_main]

use aya_ebpf::macros::{map, tracepoint, uprobe, uretprobe};
use aya_ebpf::bindings::BPF_F_RDONLY_PROG;
use aya_ebpf::maps::{
    Array, CgroupArray, HashMap, PerCpuArray, PerCpuHashMap, ProgramArray, RingBuf,
};
use aya_ebpf::programs::{ProbeContext, RetProbeContext, TracePointContext};
use aya_ebpf::helpers;
use core::mem::MaybeUninit;
use p11scope_ebpf_common::{
    ARG_NONE, CFG_FLAGS, CallStart, EVIDENCE_CELLS, EVIDENCE_CGROUP_SCOPE_FAILURES,
    EVIDENCE_RING_LOSS, EVIDENCE_RV_UPDATE_FAILURES, EVIDENCE_SEMANTIC_CAPTURE_FAILURES,
    EVIDENCE_START_INSERT_FAILURES, EVIDENCE_TEMPLATE_TAIL_FAILURES,
    EVIDENCE_UNMATCHED_RETURNS, Event, FLAG_CGROUP_FILTER, FLAG_PID_FILTER,
    FUNCTION_HASH_OFFSET, FUNCTION_NAME_MAX_BYTES, FUNCTION_NONE, MAX_ATTRS, MAX_MECH_SHAPES,
    MAX_SLOTS, MECH_NONE, RING_BYTES, RV_ENTRIES, RvKey, SESSION_NONE, START_ENTRIES,
    SlotSemantics, SlotStats, StartKey, USER_TYPE_NONE, bucket_of, capture, event_type,
    function_hash_step, lifecycle, shape, valid_config,
};

#[map]
static CONFIG: Array<u64> = Array::with_max_entries(1, BPF_F_RDONLY_PROG);

#[map]
static PID_FILTER: HashMap<u32, u8> = HashMap::with_max_entries(1024, BPF_F_RDONLY_PROG);

#[map]
static CGROUP_FILTER: CgroupArray = CgroupArray::with_max_entries(1, 0);

#[map]
static STATS: PerCpuArray<SlotStats> = PerCpuArray::with_max_entries(MAX_SLOTS, 0);

#[map]
static START: HashMap<StartKey, CallStart> = HashMap::with_max_entries(START_ENTRIES, 0);

#[map]
static RV_COUNTS: PerCpuHashMap<RvKey, u64> = PerCpuHashMap::with_max_entries(RV_ENTRIES, 0);

#[map]
static SLOT_SEMANTICS: Array<SlotSemantics> =
    Array::with_max_entries(MAX_SLOTS, BPF_F_RDONLY_PROG);

/// Mechanism id -> parameter shape code, published by userspace from
/// proxy-ng's registry. An unknown mechanism id looks up empty and is
/// treated as `shape::NONE`.
#[map]
static MECH_SHAPE: HashMap<u64, u32> =
    HashMap::with_max_entries(MAX_MECH_SHAPES, BPF_F_RDONLY_PROG);

/// Attribute type -> allowlisted boolean mask. Keeping the catalog in a map
/// avoids multiplying verifier states by eleven match arms for every one of
/// the bounded template entries.
#[map]
static ATTR_BOOL_BITS: HashMap<u32, u32> = HashMap::with_max_entries(16, BPF_F_RDONLY_PROG);

#[map]
static TEMPLATE_TAIL: ProgramArray = ProgramArray::with_max_entries(1, 0);

/// FNV hash of an exact standard function name -> stable shared-table id.
/// Raw `pFunctionName` bytes never leave the BPF stack.
#[map]
static ASYNC_FUNCTIONS: HashMap<u64, u32> = HashMap::with_max_entries(128, BPF_F_RDONLY_PROG);

#[map]
static EVENTS: RingBuf = RingBuf::with_byte_size(RING_BYTES, 0);

#[map]
static EVIDENCE: PerCpuArray<u64> = PerCpuArray::with_max_entries(EVIDENCE_CELLS, 0);

/// Does this call belong to the capture scope? With no filter configured
/// nothing is observed — scope is always explicit (design spec: no
/// magical system-wide capture).
fn bump_evidence(index: u32) {
    if let Some(value) = EVIDENCE.get_ptr_mut(index) {
        unsafe { *value += 1 };
    }
}

fn in_scope() -> bool {
    let flags = CONFIG.get(CFG_FLAGS).copied().unwrap_or(0);
    if !valid_config(flags) {
        return false;
    }
    if flags & FLAG_PID_FILTER != 0 {
        let tgid = (helpers::bpf_get_current_pid_tgid() >> 32) as u32;
        if unsafe { PID_FILTER.get(&tgid) }.is_some() {
            return true;
        }
    }
    if flags & FLAG_CGROUP_FILTER != 0 {
        match CGROUP_FILTER.current_task_under_cgroup(0) {
            Ok(matches) => return matches,
            Err(_) => {
                bump_evidence(EVIDENCE_CGROUP_SCOPE_FAILURES);
                return false;
            }
        }
    }
    false
}

fn slot_of<C>(ctx: &C) -> u32
where
    C: aya_ebpf::EbpfContext,
{
    (unsafe { helpers::bpf_get_attach_cookie(ctx.as_ptr()) }) as u32
}

/// Decode allowlisted `CK_MECHANISM` parameters for `shape` at `pmech`,
/// writing the result into `start.shape/p0/p1/p2`. Anything unexpected —
/// an `ulParameterLen` that matches no known layout, null `pParameter`, or
/// any failed read — leaves `start.shape` at its `shape::NONE` default and
/// `p0/p1/p2` untouched (they are already zeroed by the caller): partial
/// decodes are never emitted, and an unrecognized length is never guessed
/// at.
///
/// PKCS#11 has two incompatible `CK_GCM_PARAMS` layouts in the wild: the
/// legacy v2.20 one (40 bytes) and the current v2.40/OASIS one (48 bytes,
/// which inserts `ulIvBits` at offset 16 and pushes the rest out). Reusing
/// the legacy offsets against a modern 48-byte struct — as this function
/// used to, guarding only `ulParameterLen >= 40` — reads `CK_GCM_PARAMS.pAAD`
/// (a userspace pointer) into what the caller believes is `ulAADLen`. The
/// match below is deliberately an *exact* length match per layout, never
/// `>=`: a length that fits neither known layout means the field offsets
/// are unknown, and guessing is exactly what caused that disclosure.
///
/// Reads exactly two `CK_MECHANISM` fields (`ulParameterLen` at offset 16,
/// `pParameter` at offset 8) plus three shape-specific `u64` scalars at
/// fixed offsets from `pParameter`. For GCM, `pIv`/`pAAD` — pointers, at
/// offset 0 always and offset 16 or 24 depending on layout — are never
/// read; only the three length/count scalars are.
fn decode_params(pmech: u64, sh: u32, start: &mut CallStart) {
    // CK_MECHANISM.ulParameterLen is the third CK_ULONG (offset 16). Read
    // first: which offsets (if any) apply depends on it.
    let Some(param_len_addr) = pmech.checked_add(16) else {
        capture_failure(start);
        return;
    };
    let Ok(param_len) = (unsafe { helpers::bpf_probe_read_user(param_len_addr as *const u64) })
    else {
        capture_failure(start);
        return;
    };
    let (o0, o1, o2, out_shape) = match (sh, param_len) {
        // CK_RSA_PKCS_PSS_PARAMS { hashAlg, mgf, sLen } — three CK_ULONGs,
        // 24 bytes, one layout.
        (shape::RSA_PKCS_PSS, 24) => (0u64, 8u64, 16u64, shape::RSA_PKCS_PSS),
        // CK_GCM_PARAMS, legacy v2.20 layout (40 bytes):
        // { pIv, ulIvLen, pAAD, ulAADLen, ulTagBits }.
        (shape::GCM, 40) => (8u64, 24u64, 32u64, shape::GCM_V220),
        // CK_GCM_PARAMS, v2.40/OASIS layout (48 bytes):
        // { pIv, ulIvLen, ulIvBits, pAAD, ulAADLen, ulTagBits }.
        (shape::GCM, 48) => (8u64, 32u64, 40u64, shape::GCM_V240),
        _ => return,
    };
    // CK_MECHANISM.pParameter is the second CK_ULONG (offset 8).
    let Some(pparam_addr) = pmech.checked_add(8) else {
        capture_failure(start);
        return;
    };
    let Ok(pparam) = (unsafe { helpers::bpf_probe_read_user(pparam_addr as *const u64) }) else {
        capture_failure(start);
        return;
    };
    if pparam == 0 {
        return;
    }
    let (Some(a0), Some(a1), Some(a2)) = (
        pparam.checked_add(o0),
        pparam.checked_add(o1),
        pparam.checked_add(o2),
    ) else {
        capture_failure(start);
        return;
    };
    let r0 = unsafe { helpers::bpf_probe_read_user(a0 as *const u64) };
    let r1 = unsafe { helpers::bpf_probe_read_user(a1 as *const u64) };
    let r2 = unsafe { helpers::bpf_probe_read_user(a2 as *const u64) };
    if let (Ok(a), Ok(b), Ok(c)) = (r0, r1, r2) {
        start.shape = out_shape;
        start.p0 = a;
        start.p1 = b;
        start.p2 = c;
    } else {
        capture_failure(start);
    }
}

/// Walk at most `MAX_ATTRS` entries of `pTemplate`, recording each entry's
/// *type* only into `start.attr_types` — `pValue` is never read except for
/// the policy-boolean allowlist under the `ulValueLen == 1` gate below.
/// `attr_total` is always set from `count`, so a template longer than the
/// cap (or one abandoned early by a read failure) stays visible as
/// truncation evidence rather than being silently trimmed.
///
/// The loop bound is the constant `MAX_ATTRS`, not `count`, so the
/// verifier can prove termination; the `i >= count` check inside just
/// stops early for shorter templates. Any read failure for an entry —
/// including a bad `pTemplate` itself — stops the walk immediately;
/// entries already captured are kept, nothing is skipped ahead or guessed.
#[inline(never)]
fn walk_template<const TYPES_ONLY: bool, const SECOND: bool>(
    ptemplate: u64,
    count: u64,
    start: &mut CallStart,
) {
    let total = count.min(u32::MAX as u64) as u32;
    if SECOND {
        start.attr_total1 = total;
    } else {
        start.attr_total = total;
    }
    for i in 0..MAX_ATTRS {
        if (i as u64) >= count {
            break;
        }
        // CK_ATTRIBUTE { CK_ATTRIBUTE_TYPE type; CK_VOID_PTR pValue;
        // CK_ULONG ulValueLen; } — 24 bytes; all three fields are
        // CK_ULONG-sized (8 bytes) on LP64. `type` is read first and is
        // the only field ever read for a non-allowlisted attribute.
        let Some(base) = ptemplate.checked_add((i as u64) * 24) else {
            capture_failure(start);
            break;
        };
        let Ok(t) = (unsafe { helpers::bpf_probe_read_user(base as *const u64) }) else {
            capture_failure(start);
            break;
        };
        let attr_type = t;
        if SECOND {
            start.attr_types1[i] = attr_type;
            start.attr_count1 += 1;
        } else {
            start.attr_types[i] = attr_type;
            start.attr_count += 1;
        }

        // Policy-boolean allowlist only: read ulValueLen (offset 16) next,
        // and only when it is exactly 1 read the single CK_BBOOL byte at
        // pValue (offset 8). This length gate is load-bearing: it is what
        // keeps a CKA_VALUE or CKA_LABEL from ever being read even if a
        // type were mis-listed on the allowlist. Type checked first, then
        // length, then the single byte — in that order, always.
        if TYPES_ONLY {
            continue;
        }
        // CK_ATTRIBUTE_TYPE is full-width on LP64 and remains so in the
        // event. Only standard low-width values can enter the boolean
        // allowlist; a vendor type with matching low bits must not alias it.
        if attr_type > u32::MAX as u64 {
            continue;
        }
        let bool_type = attr_type as u32;
        let Some(mask) = (unsafe { ATTR_BOOL_BITS.get(&bool_type) }).copied() else { continue };
        // Read the two remaining CK_ATTRIBUTE fields together only after
        // the type allowlist matched. This preserves the privacy order while
        // keeping the verifier from exploring two independent read failures.
        let Some(value_addr) = base.checked_add(8) else {
            capture_failure(start);
            break;
        };
        let Ok([pvalue, len]) =
            (unsafe { helpers::bpf_probe_read_user(value_addr as *const [u64; 2]) })
        else {
            capture_failure(start);
            break;
        };
        if len != 1 {
            continue;
        }
        let Ok(b) = (unsafe { helpers::bpf_probe_read_user(pvalue as *const u8) }) else {
            capture_failure(start);
            break;
        };
        if SECOND {
            start.attr_bools_seen1 |= mask;
            if b != 0 {
                start.attr_bools1 |= mask;
            }
        } else {
            start.attr_bools_seen |= mask;
            if b != 0 {
                start.attr_bools |= mask;
            }
        }
    }
}

fn arg_u64(ctx: &ProbeContext, index: u8) -> Result<u64, ()> {
    match index {
        // Keep every register index a compile-time constant. A dynamic
        // `ctx.arg(index)` becomes variable pointer arithmetic on pt_regs,
        // which the kernel verifier correctly rejects.
        0 => ctx.arg::<u64>(0).ok_or(()),
        1 => ctx.arg::<u64>(1).ok_or(()),
        2 => ctx.arg::<u64>(2).ok_or(()),
        3 => ctx.arg::<u64>(3).ok_or(()),
        4 => ctx.arg::<u64>(4).ok_or(()),
        5 => ctx.arg::<u64>(5).ok_or(()),
        6 => {
            let rsp = unsafe { (*ctx.regs).rsp as u64 };
            let Some(address) = rsp.checked_add(8) else { return Err(()) };
            match unsafe { helpers::bpf_probe_read_user(address as *const u64) } {
                Ok(value) => Ok(value),
                Err(_) => Err(()),
            }
        }
        _ => Err(()),
    }
}

fn capture_failure(start: &mut CallStart) {
    start.capture |= capture::ARG_READ_FAILURE;
    bump_evidence(EVIDENCE_SEMANTIC_CAPTURE_FAILURES);
}

fn capture_scalar(ctx: &ProbeContext, index: u8, start: &mut CallStart) -> Option<u64> {
    if index == ARG_NONE {
        return None;
    }
    match arg_u64(ctx, index) {
        Ok(value) => Some(value),
        Err(()) => {
            capture_failure(start);
            None
        }
    }
}

fn capture_async_target(ctx: &ProbeContext, index: u8, start: &mut CallStart) {
    let Some(pointer) = capture_scalar(ctx, index, start) else { return };
    if pointer == 0 {
        capture_failure(start);
        return;
    }
    // One helper call bounds and NUL-terminates the snapshot. `MaybeUninit`
    // avoids a verifier-expensive 29-byte memset. Only the bytes covered by
    // the helper's returned length are read below.
    let mut name = MaybeUninit::<[u8; FUNCTION_NAME_MAX_BYTES + 2]>::uninit();
    let read = unsafe {
        helpers::generated::bpf_probe_read_user_str(
            name.as_mut_ptr().cast(),
            (FUNCTION_NAME_MAX_BYTES + 2) as u32,
            pointer as *const core::ffi::c_void,
        )
    };
    if read <= 1 || read > (FUNCTION_NAME_MAX_BYTES + 1) as _ {
        capture_failure(start);
        return;
    }
    let len = (read - 1) as usize;
    let name = name.as_ptr().cast::<u8>();
    let mut hash = FUNCTION_HASH_OFFSET;
    for offset in 0..FUNCTION_NAME_MAX_BYTES {
        if offset >= len {
            break;
        }
        hash = function_hash_step(hash, unsafe { name.add(offset).read() });
    }
    hash = function_hash_step(hash, len as u8);
    match unsafe { ASYNC_FUNCTIONS.get(&hash) }.copied() {
        Some(id) => start.target_function = id,
        None => capture_failure(start),
    }
}

#[uprobe]
pub fn p11_entry(ctx: ProbeContext) -> u32 {
    p11_entry_impl::<0>(ctx)
}

#[uprobe]
pub fn p11_entry_template(ctx: ProbeContext) -> u32 {
    p11_entry_impl::<1>(ctx)
}

#[uprobe]
pub fn p11_entry_template_types(ctx: ProbeContext) -> u32 {
    p11_entry_impl::<2>(ctx)
}

#[uprobe]
pub fn p11_entry_template_pair(ctx: ProbeContext) -> u32 {
    p11_entry_impl::<3>(ctx)
}

#[uprobe]
pub fn p11_entry_template_second(ctx: ProbeContext) -> u32 {
    let slot = slot_of(&ctx);
    if slot >= MAX_SLOTS {
        return 0;
    }
    let key = StartKey {
        pid_tgid: helpers::bpf_get_current_pid_tgid(),
        slot,
        _pad: 0,
    };
    let Some(start) = START.get_ptr_mut(&key) else {
        bump_evidence(EVIDENCE_TEMPLATE_TAIL_FAILURES);
        return 0;
    };
    let semantics = SLOT_SEMANTICS
        .get(slot)
        .copied()
        .unwrap_or(SlotSemantics::COUNT_ONLY);
    // SAFETY: START owns this per-thread/per-slot value until the return
    // probe removes it; the primary entry program has already inserted it.
    let start = unsafe { &mut *start };
    if let Some(template) = capture_scalar(&ctx, semantics.template1_arg, start) {
        if let Some(count) = capture_scalar(&ctx, semantics.template_count1_arg, start) {
            walk_template::<false, true>(template, count, start);
        }
    }
    0
}

#[inline(always)]
fn p11_entry_impl<const TEMPLATE_MODE: u8>(ctx: ProbeContext) -> u32 {
    let slot = slot_of(&ctx);
    if slot >= MAX_SLOTS || !in_scope() {
        return 0;
    }
    if let Some(stats) = STATS.get_ptr_mut(slot) {
        // SAFETY: PerCpuArray gives this CPU exclusive access to its own
        // copy; there is no cross-CPU aliasing to race with.
        unsafe { (*stats).entered += 1 };
    }
    let key = StartKey { pid_tgid: helpers::bpf_get_current_pid_tgid(), slot, _pad: 0 };
    let semantics = SLOT_SEMANTICS.get(slot).copied().unwrap_or(SlotSemantics::COUNT_ONLY);
    let mut start = CallStart {
        ts_ns: unsafe { helpers::bpf_ktime_get_ns() },
        session: SESSION_NONE,
        slot_id: 0,
        mechanism: MECH_NONE,
        mechanism_ptr: 0,
        flags: 0,
        out_ptr: 0,
        user_type: USER_TYPE_NONE,
        shape: shape::NONE,
        p0: 0,
        p1: 0,
        p2: 0,
        async_value: 0,
        attr_types: [0; MAX_ATTRS],
        attr_count: 0,
        attr_total: 0,
        attr_bools: 0,
        attr_bools_seen: 0,
        attr_types1: [0; MAX_ATTRS],
        attr_count1: 0,
        attr_total1: 0,
        attr_bools1: 0,
        attr_bools_seen1: 0,
        capture: capture::MECHANISM_NONE | capture::OUTPUT_NONE,
        target_function: FUNCTION_NONE,
        _pad: 0,
    };

    if let Some(value) = capture_scalar(&ctx, semantics.session_arg, &mut start) {
        start.session = value;
    }
    if let Some(value) = capture_scalar(&ctx, semantics.slot_arg, &mut start) {
        start.slot_id = value;
    }
    if let Some(value) = capture_scalar(&ctx, semantics.flags_arg, &mut start) {
        start.flags = value;
        if semantics.lifecycle == lifecycle::OPEN_SESSION && value & 0x8 != 0 {
            start.capture |= capture::ASYNC_SESSION;
        }
    }
    if let Some(value) = capture_scalar(&ctx, semantics.user_type_arg, &mut start) {
        start.user_type = value as u32;
    }

    if semantics.mechanism_arg != ARG_NONE {
        match capture_scalar(&ctx, semantics.mechanism_arg, &mut start) {
            None => {
                start.capture =
                    (start.capture & !capture::MECHANISM_MASK) | capture::MECHANISM_UNREADABLE;
            }
            Some(0) => {
                start.capture =
                    (start.capture & !capture::MECHANISM_MASK) | capture::MECHANISM_NULL;
            }
            Some(pointer) => match unsafe {
                helpers::bpf_probe_read_user(pointer as *const u64)
            } {
                Ok(mechanism) => {
                    start.mechanism = mechanism;
                    start.capture =
                        (start.capture & !capture::MECHANISM_MASK) | capture::MECHANISM_VALUE;
                    let parameter_shape =
                        unsafe { MECH_SHAPE.get(&mechanism) }.copied().unwrap_or(shape::NONE);
                    if parameter_shape != shape::NONE {
                        decode_params(pointer, parameter_shape, &mut start);
                    }
                }
                Err(_) => {
                    start.capture = (start.capture & !capture::MECHANISM_MASK)
                        | capture::MECHANISM_UNREADABLE;
                    capture_failure(&mut start);
                }
            },
        }
    }

    if semantics.output_arg != ARG_NONE {
        match capture_scalar(&ctx, semantics.output_arg, &mut start) {
            None => {
                start.capture =
                    (start.capture & !capture::OUTPUT_MASK) | capture::OUTPUT_UNREADABLE;
            }
            Some(pointer) => {
                start.capture = (start.capture & !capture::OUTPUT_MASK)
                    | if pointer == 0 { capture::OUTPUT_NULL } else { capture::OUTPUT_NON_NULL };
                if semantics.lifecycle == lifecycle::OPEN_SESSION {
                    start.out_ptr = pointer;
                }
            }
        }
    }

    if TEMPLATE_MODE != 0 {
        if semantics.template0_arg != ARG_NONE {
            // Keep the reads nested. Holding two Option payloads across the
            // second helper call makes LLVM spill an uninitialized `None`
            // payload, which the BPF verifier rejects even though Rust would
            // test both discriminants before use.
            if let Some(template) = capture_scalar(&ctx, semantics.template0_arg, &mut start) {
                if let Some(count) =
                    capture_scalar(&ctx, semantics.template_count0_arg, &mut start)
                {
                    if TEMPLATE_MODE == 2 {
                        walk_template::<true, false>(template, count, &mut start);
                    } else {
                        walk_template::<false, false>(template, count, &mut start);
                    }
                }
            }
        }
    }
    if TEMPLATE_MODE == 0 && semantics.async_name_arg != ARG_NONE {
        capture_async_target(&ctx, semantics.async_name_arg, &mut start);
        match semantics.lifecycle {
            lifecycle::ASYNC_JOIN => {
                if let Some(value) = capture_scalar(&ctx, semantics.async_value_arg, &mut start) {
                    start.async_value = value;
                }
            }
            lifecycle::ASYNC_GET_ID => {
                if let Some(pointer) = capture_scalar(&ctx, semantics.async_value_arg, &mut start) {
                    start.out_ptr = pointer;
                }
            }
            _ => {}
        }
    }

    if START
        .insert(&key, &start, aya_ebpf::bindings::BPF_NOEXIST as u64)
        .is_err()
    {
        // A same-thread/same-slot ambiguous nested call makes both returns
        // untrustworthy. Invalidate the outer record so neither return can
        // combine entry state from one invocation with the other.
        let _ = START.remove(&key);
        bump_evidence(EVIDENCE_START_INSERT_FAILURES);
        return 0;
    }
    if TEMPLATE_MODE == 3 {
        // Success never returns. Failure leaves template0 as usable partial
        // evidence and is independently disclosed below.
        unsafe { TEMPLATE_TAIL.tail_call(&ctx, 0) };
        bump_evidence(EVIDENCE_TEMPLATE_TAIL_FAILURES);
    }
    0
}

#[uretprobe]
pub fn p11_return(ctx: RetProbeContext) -> u32 {
    let slot = slot_of(&ctx);
    if slot >= MAX_SLOTS {
        return 0;
    }
    let key = StartKey { pid_tgid: helpers::bpf_get_current_pid_tgid(), slot, _pad: 0 };
    if !in_scope() {
        // Entry-time scope owns this pairing record. If a task migrates out
        // of a selected cgroup mid-call, clean it up without emitting an
        // out-of-scope event and disclose the lost completion.
        if START.remove(&key).is_ok() {
            bump_evidence(EVIDENCE_UNMATCHED_RETURNS);
        }
        return 0;
    }
    // No start entry means the entry probe filtered this call out (or the
    // process was already inside the function at attach time). Either way
    // there is nothing to attribute.
    let Some(&start) = (unsafe { START.get(&key) }) else {
        return 0;
    };
    if START.remove(&key).is_err() {
        bump_evidence(EVIDENCE_UNMATCHED_RETURNS);
        return 0;
    }

    let now = unsafe { helpers::bpf_ktime_get_ns() };
    let delta = now.saturating_sub(start.ts_ns);
    let rv: u64 = ctx.ret();

    if let Some(stats) = STATS.get_ptr_mut(slot) {
        // SAFETY: as in p11_entry — per-CPU storage, no aliasing.
        unsafe {
            (*stats).returned += 1;
            (*stats).total_ns += delta;
            if delta > (*stats).max_ns {
                (*stats).max_ns = delta;
            }
            let b = bucket_of(delta) as usize;
            if b < (*stats).buckets.len() {
                (*stats).buckets[b] += 1;
            }
            if rv != 0 && rv != 0x204 {
                (*stats).errors += 1;
            }
        }
    }

    let rk = RvKey { slot, _pad: 0, rv };
    let prev = unsafe { RV_COUNTS.get(&rk) }.copied().unwrap_or(0);
    if RV_COUNTS.insert(&rk, &(prev + 1), 0).is_err() {
        bump_evidence(EVIDENCE_RV_UPDATE_FAILURES);
    }

    let semantics = SLOT_SEMANTICS.get(slot).copied().unwrap_or(SlotSemantics::COUNT_ONLY);
    let mut session = start.session;
    if semantics.lifecycle == lifecycle::OPEN_SESSION && start.out_ptr != 0 && (rv == 0 || rv == 0x204) {
        // C_OpenSession wrote the handle by now. Only trust it on success.
        match unsafe { helpers::bpf_probe_read_user(start.out_ptr as *const u64) } {
            Ok(value) => session = value,
            Err(_) => bump_evidence(EVIDENCE_SEMANTIC_CAPTURE_FAILURES),
        }
    }
    let mut async_value = start.async_value;
    let mut capture_flags = start.capture;
    if rv == 0 && start.out_ptr != 0 && semantics.lifecycle == lifecycle::ASYNC_GET_ID {
        match unsafe { helpers::bpf_probe_read_user(start.out_ptr as *const u64) } {
            Ok(value) => async_value = value,
            Err(_) => {
                capture_flags |= capture::ASYNC_VALUE_UNREADABLE;
                bump_evidence(EVIDENCE_SEMANTIC_CAPTURE_FAILURES);
            }
        }
    }

    let ev = Event {
        ts_ns: now,
        duration_ns: delta,
        pid_tgid: helpers::bpf_get_current_pid_tgid(),
        cgroup_id: unsafe { helpers::bpf_get_current_cgroup_id() },
        session,
        slot_id: start.slot_id,
        mechanism: start.mechanism,
        flags: start.flags,
        rv,
        p0: start.p0,
        p1: start.p1,
        p2: start.p2,
        async_value,
        slot,
        target_function: start.target_function,
        user_type: start.user_type,
        shape: start.shape,
        attr_types: start.attr_types,
        attr_count: start.attr_count,
        attr_total: start.attr_total,
        attr_bools: start.attr_bools,
        attr_bools_seen: start.attr_bools_seen,
        attr_types1: start.attr_types1,
        attr_count1: start.attr_count1,
        attr_total1: start.attr_total1,
        attr_bools1: start.attr_bools1,
        attr_bools_seen1: start.attr_bools_seen1,
        capture: capture_flags,
        event_type: event_type::CALL,
    };
    match EVENTS.reserve::<Event>(0) {
        Some(mut e) => {
            e.write(ev);
            e.submit(0);
        }
        None => {
            bump_evidence(EVIDENCE_RING_LOSS);
        }
    }
    0
}

#[tracepoint(category = "sched", name = "sched_process_fork")]
pub fn sched_process_fork(ctx: TracePointContext) -> u32 {
    if !in_scope() {
        return 0;
    }
    // Linux sched_process_fork format: common fields (8), parent_comm
    // (16), parent_pid (4), child_comm (16), child_pid (4).
    // SAFETY: offsets are fixed by the sched_process_fork tracepoint ABI
    // described above and each read stays within that record.
    let Ok(parent) = (unsafe { ctx.read_at::<u32>(24) }) else { return 0 };
    let Ok(child) = (unsafe { ctx.read_at::<u32>(44) }) else { return 0 };
    let ev = Event {
        pid_tgid: (parent as u64) << 32,
        session: child as u64,
        event_type: event_type::FORK,
        ..Event::default()
    };
    match EVENTS.reserve::<Event>(0) {
        Some(mut event) => {
            event.write(ev);
            event.submit(0);
        }
        None => bump_evidence(EVIDENCE_RING_LOSS),
    }
    0
}

#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    loop {}
}
