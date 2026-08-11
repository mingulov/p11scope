//! p11scope BPF programs. Two programs serve every attach point: the
//! attach cookie carries the slot index, so 68+ probes need two programs
//! rather than 68 copies. Cookies need kernel >= 5.15, which is the
//! project's floor.
#![no_std]
#![no_main]

use aya_ebpf::macros::{map, uprobe, uretprobe};
use aya_ebpf::maps::{Array, HashMap, PerCpuArray, PerCpuHashMap, RingBuf};
use aya_ebpf::programs::{ProbeContext, RetProbeContext};
use aya_ebpf::{EbpfContext as _, helpers};
use p11scope_ebpf_common::{
    CFG_FLAGS, CallStart, Event, FLAG_CGROUP_FILTER, FLAG_PID_FILTER, MAX_ATTRS, MAX_MECH_SHAPES,
    MAX_SLOTS, MECH_NONE, RING_BYTES, RvKey, SESSION_NONE, SlotStats, StartKey, USER_TYPE_NONE,
    attr_bool, bucket_of, fnkind, shape,
};

#[map]
static CONFIG: Array<u64> = Array::with_max_entries(4, 0);

#[map]
static PID_FILTER: HashMap<u32, u8> = HashMap::with_max_entries(1024, 0);

#[map]
static CGROUP_FILTER: HashMap<u64, u8> = HashMap::with_max_entries(1024, 0);

#[map]
static STATS: PerCpuArray<SlotStats> = PerCpuArray::with_max_entries(MAX_SLOTS, 0);

#[map]
static START: HashMap<StartKey, CallStart> = HashMap::with_max_entries(16384, 0);

#[map]
static RV_COUNTS: PerCpuHashMap<RvKey, u64> = PerCpuHashMap::with_max_entries(4096, 0);

/// Slot -> semantic function kind, published by userspace (Task 4). An
/// unknown slot degrades to `fnkind::OTHER`, i.e. "capture nothing" — never
/// UB, never a guess.
#[map]
static SLOT_KIND: Array<u32> = Array::with_max_entries(MAX_SLOTS, 0);

/// Mechanism id -> parameter shape code, published by userspace from
/// proxy-ng's registry (Task 1). Not consumed yet — Task 3 adds the
/// in-kernel decode that switches on it. An unknown mechanism id looks
/// up empty, which callers must treat as `shape::NONE`.
#[map]
static MECH_SHAPE: HashMap<u64, u32> = HashMap::with_max_entries(MAX_MECH_SHAPES, 0);

#[map]
static EVENTS: RingBuf = RingBuf::with_byte_size(RING_BYTES, 0);

/// Events that could not be reserved. A capture that dropped events must
/// never read COMPLETE, so this is reported, not swallowed.
#[map]
static LOST: PerCpuArray<u64> = PerCpuArray::with_max_entries(1, 0);

/// Does this call belong to the capture scope? With no filter configured
/// nothing is observed — scope is always explicit (design spec: no
/// magical system-wide capture).
fn in_scope(ctx: &ProbeContext) -> bool {
    let flags = CONFIG.get(CFG_FLAGS).copied().unwrap_or(0);
    if flags & FLAG_PID_FILTER != 0 {
        let tgid = ctx.tgid();
        if unsafe { PID_FILTER.get(&tgid) }.is_some() {
            return true;
        }
    }
    if flags & FLAG_CGROUP_FILTER != 0 {
        let cgid = unsafe { helpers::bpf_get_current_cgroup_id() };
        if unsafe { CGROUP_FILTER.get(&cgid) }.is_some() {
            return true;
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
/// short `ulParameterLen`, null `pParameter`, or any failed read — leaves
/// `start.shape` at its `shape::NONE` default and `p0/p1/p2` untouched
/// (they are already zeroed by the caller): partial decodes are never
/// emitted.
///
/// Reads exactly two `CK_MECHANISM` fields (`ulParameterLen` at offset 16,
/// `pParameter` at offset 8) plus three shape-specific `u64` scalars at
/// fixed offsets from `pParameter`. For `GCM`, offsets 0 and 16 of
/// `CK_GCM_PARAMS` are `pIv`/`pAAD` — pointers — and are never read; only
/// `ulIvLen` (8), `ulAADLen` (24), `ulTagBits` (32) are.
fn decode_params(pmech: u64, sh: u32, start: &mut CallStart) {
    let (needed, o0, o1, o2) = match sh {
        // CK_RSA_PKCS_PSS_PARAMS { hashAlg, mgf, sLen } — three CK_ULONGs.
        shape::RSA_PKCS_PSS => (24u64, 0u64, 8u64, 16u64),
        // CK_GCM_PARAMS { pIv, ulIvLen, pAAD, ulAADLen, ulTagBits }.
        shape::GCM => (40u64, 8u64, 24u64, 32u64),
        _ => return,
    };
    // CK_MECHANISM.ulParameterLen is the third CK_ULONG (offset 16). Guard
    // first: a provider passing a short buffer must never cause a read
    // past its end.
    let Ok(param_len) = (unsafe { helpers::bpf_probe_read_user((pmech + 16) as *const u64) })
    else {
        return;
    };
    if param_len < needed {
        return;
    }
    // CK_MECHANISM.pParameter is the second CK_ULONG (offset 8).
    let Ok(pparam) = (unsafe { helpers::bpf_probe_read_user((pmech + 8) as *const u64) }) else {
        return;
    };
    if pparam == 0 {
        return;
    }
    let r0 = unsafe { helpers::bpf_probe_read_user((pparam + o0) as *const u64) };
    let r1 = unsafe { helpers::bpf_probe_read_user((pparam + o1) as *const u64) };
    let r2 = unsafe { helpers::bpf_probe_read_user((pparam + o2) as *const u64) };
    if let (Ok(a), Ok(b), Ok(c)) = (r0, r1, r2) {
        start.shape = sh;
        start.p0 = a;
        start.p1 = b;
        start.p2 = c;
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
fn walk_template(ptemplate: u64, count: u64, start: &mut CallStart) {
    start.attr_total = count as u32;
    for i in 0..MAX_ATTRS {
        if (i as u64) >= count {
            break;
        }
        // CK_ATTRIBUTE { CK_ATTRIBUTE_TYPE type; CK_VOID_PTR pValue;
        // CK_ULONG ulValueLen; } — 24 bytes; all three fields are
        // CK_ULONG-sized (8 bytes) on LP64. `type` is read first and is
        // the only field ever read for a non-allowlisted attribute.
        let base = ptemplate + (i as u64) * 24;
        let Ok(t) = (unsafe { helpers::bpf_probe_read_user(base as *const u64) }) else {
            break;
        };
        let attr_type = t as u32;
        start.attr_types[i] = attr_type;
        start.attr_count += 1;

        // Policy-boolean allowlist only: read ulValueLen (offset 16) next,
        // and only when it is exactly 1 read the single CK_BBOOL byte at
        // pValue (offset 8). This length gate is load-bearing: it is what
        // keeps a CKA_VALUE or CKA_LABEL from ever being read even if a
        // type were mis-listed on the allowlist. Type checked first, then
        // length, then the single byte — in that order, always.
        let Some(bit) = attr_bool::bit_for_attr_type(attr_type) else {
            continue;
        };
        let Ok(len) = (unsafe { helpers::bpf_probe_read_user((base + 16) as *const u64) })
        else {
            break;
        };
        if len != 1 {
            continue;
        }
        let Ok(pvalue) = (unsafe { helpers::bpf_probe_read_user((base + 8) as *const u64) })
        else {
            break;
        };
        let Ok(b) = (unsafe { helpers::bpf_probe_read_user(pvalue as *const u8) }) else {
            break;
        };
        start.attr_bools_seen |= 1 << bit;
        if b != 0 {
            start.attr_bools |= 1 << bit;
        }
    }
}

#[uprobe]
pub fn p11_entry(ctx: ProbeContext) -> u32 {
    let slot = slot_of(&ctx);
    if slot >= MAX_SLOTS || !in_scope(&ctx) {
        return 0;
    }
    if let Some(stats) = STATS.get_ptr_mut(slot) {
        // SAFETY: PerCpuArray gives this CPU exclusive access to its own
        // copy; there is no cross-CPU aliasing to race with.
        unsafe { (*stats).entered += 1 };
    }
    let key = StartKey { pid_tgid: helpers::bpf_get_current_pid_tgid(), slot, _pad: 0 };
    // A re-entrant call overwrites its own start: the outer call then
    // measures short. Recorded rather than dropped; PKCS#11 entry points
    // are not re-entrant in practice.
    let kind = SLOT_KIND.get(slot).copied().unwrap_or(fnkind::OTHER);
    let mut start = CallStart {
        ts_ns: unsafe { helpers::bpf_ktime_get_ns() },
        session: SESSION_NONE,
        mechanism: MECH_NONE,
        out_ptr: 0,
        user_type: USER_TYPE_NONE,
        shape: shape::NONE,
        p0: 0,
        p1: 0,
        p2: 0,
        attr_types: [0; MAX_ATTRS],
        attr_count: 0,
        attr_total: 0,
        attr_bools: 0,
        attr_bools_seen: 0,
    };
    match kind {
        fnkind::INIT_WITH_MECH => {
            // (hSession, pMechanism, [hKey]) — mechanism TYPE, then (Phase
            // 3) allowlisted parameters for registry-published shapes only.
            if let Some(sess) = ctx.arg::<u64>(0) {
                start.session = sess;
            }
            if let Some(pmech) = ctx.arg::<u64>(1) {
                if pmech != 0 {
                    // CK_MECHANISM.mechanism is the first CK_ULONG.
                    if let Ok(m) = unsafe { helpers::bpf_probe_read_user(pmech as *const u64) } {
                        start.mechanism = m;
                        let sh = unsafe { MECH_SHAPE.get(&m) }.copied().unwrap_or(shape::NONE);
                        if sh != shape::NONE {
                            decode_params(pmech, sh, &mut start);
                        }
                    }
                }
            }
        }
        fnkind::OPEN_SESSION => {
            // phSession is arg4 and is only written by the time the call
            // returns; stash the pointer, read it at return.
            if let Some(p) = ctx.arg::<u64>(4) {
                start.out_ptr = p;
            }
        }
        fnkind::SESSION_ARG0 => {
            if let Some(sess) = ctx.arg::<u64>(0) {
                start.session = sess;
            }
        }
        fnkind::TEMPLATE_ARG1 => {
            // (hSession, pTemplate, ulCount, ...) — C_FindObjectsInit,
            // C_CreateObject. This kind moved out of SESSION_ARG0, so
            // session capture happens here too, not just the walk.
            if let Some(sess) = ctx.arg::<u64>(0) {
                start.session = sess;
            }
            if let (Some(pt), Some(count)) = (ctx.arg::<u64>(1), ctx.arg::<u64>(2)) {
                walk_template(pt, count, &mut start);
            }
        }
        fnkind::TEMPLATE_ARG2 => {
            // (hSession, pMechanism, pTemplate, ulCount, ...) —
            // C_GenerateKey. Mechanism type/shape decode is not done here
            // (that's INIT_WITH_MECH's job for *Init calls); this kind
            // only needs session + template.
            if let Some(sess) = ctx.arg::<u64>(0) {
                start.session = sess;
            }
            if let (Some(pt), Some(count)) = (ctx.arg::<u64>(2), ctx.arg::<u64>(3)) {
                walk_template(pt, count, &mut start);
            }
        }
        fnkind::LOGIN => {
            if let Some(sess) = ctx.arg::<u64>(0) {
                start.session = sess;
            }
            // userType only. pPin (arg2) and ulPinLen (arg3) are never read.
            if let Some(ut) = ctx.arg::<u64>(1) {
                start.user_type = ut as u32;
            }
        }
        _ => {}
    }
    let _ = START.insert(&key, &start, 0);
    0
}

#[uretprobe]
pub fn p11_return(ctx: RetProbeContext) -> u32 {
    let slot = slot_of(&ctx);
    if slot >= MAX_SLOTS {
        return 0;
    }
    let key = StartKey { pid_tgid: helpers::bpf_get_current_pid_tgid(), slot, _pad: 0 };
    // No start entry means the entry probe filtered this call out (or the
    // process was already inside the function at attach time). Either way
    // there is nothing to attribute.
    let Some(&start) = (unsafe { START.get(&key) }) else {
        return 0;
    };
    let _ = START.remove(&key);

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
            if rv != 0 {
                (*stats).errors += 1;
            }
        }
    }

    // CK_RV is CK_ULONG (u64 on LP64) but RvKey.rv is u32, so this narrows.
    // `errors` above already compares the full u64, so only a pathological
    // vendor rv > 2^32 could alias in the RV_COUNTS distribution. Left as
    // u32 to avoid churning the shared kernel/userspace ABI this late;
    // Phase 2 should widen this key when it reshapes events.
    let rk = RvKey { slot, rv: rv as u32 };
    let prev = unsafe { RV_COUNTS.get(&rk) }.copied().unwrap_or(0);
    let _ = RV_COUNTS.insert(&rk, &(prev + 1), 0);

    let mut session = start.session;
    if start.out_ptr != 0 && rv == 0 {
        // C_OpenSession wrote the handle by now. Only trust it on success.
        if let Ok(s) = unsafe { helpers::bpf_probe_read_user(start.out_ptr as *const u64) } {
            session = s;
        }
    }

    let ev = Event {
        ts_ns: now,
        duration_ns: delta,
        pid_tgid: helpers::bpf_get_current_pid_tgid(),
        cgroup_id: unsafe { helpers::bpf_get_current_cgroup_id() },
        session,
        mechanism: start.mechanism,
        rv,
        p0: start.p0,
        p1: start.p1,
        p2: start.p2,
        slot,
        kind: SLOT_KIND.get(slot).copied().unwrap_or(fnkind::OTHER),
        user_type: start.user_type,
        shape: start.shape,
        attr_types: start.attr_types,
        attr_count: start.attr_count,
        attr_total: start.attr_total,
        attr_bools: start.attr_bools,
        attr_bools_seen: start.attr_bools_seen,
    };
    match EVENTS.reserve::<Event>(0) {
        Some(mut e) => {
            e.write(ev);
            e.submit(0);
        }
        None => {
            if let Some(l) = LOST.get_ptr_mut(0) {
                // SAFETY: per-CPU storage, no cross-CPU aliasing.
                unsafe { *l += 1 };
            }
        }
    }
    0
}

#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    loop {}
}
