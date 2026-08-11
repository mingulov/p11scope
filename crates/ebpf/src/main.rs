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
    CFG_FLAGS, CallStart, Event, FLAG_CGROUP_FILTER, FLAG_PID_FILTER, MAX_SLOTS, MECH_NONE,
    RING_BYTES, RvKey, SESSION_NONE, SlotStats, StartKey, USER_TYPE_NONE, bucket_of, fnkind,
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
        _pad: 0,
    };
    match kind {
        fnkind::INIT_WITH_MECH => {
            // (hSession, pMechanism, [hKey]) — mechanism TYPE only. The
            // params pointer inside CK_MECHANISM is deliberately not read;
            // parameter decoding is Phase 3, behind the allowlist.
            if let Some(sess) = ctx.arg::<u64>(0) {
                start.session = sess;
            }
            if let Some(pmech) = ctx.arg::<u64>(1) {
                if pmech != 0 {
                    // CK_MECHANISM.mechanism is the first CK_ULONG.
                    if let Ok(m) = unsafe { helpers::bpf_probe_read_user(pmech as *const u64) } {
                        start.mechanism = m;
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
        slot,
        kind: SLOT_KIND.get(slot).copied().unwrap_or(fnkind::OTHER),
        user_type: start.user_type,
        _pad: 0,
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
