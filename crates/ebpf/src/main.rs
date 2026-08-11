//! p11scope BPF programs. Two programs serve every attach point: the
//! attach cookie carries the slot index, so 68+ probes need two programs
//! rather than 68 copies. Cookies need kernel >= 5.15, which is the
//! project's floor.
#![no_std]
#![no_main]

use aya_ebpf::macros::{map, uprobe, uretprobe};
use aya_ebpf::maps::{Array, HashMap, PerCpuArray, PerCpuHashMap};
use aya_ebpf::programs::{ProbeContext, RetProbeContext};
use aya_ebpf::{EbpfContext as _, helpers};
use p11scope_ebpf_common::{
    CFG_FLAGS, FLAG_CGROUP_FILTER, FLAG_PID_FILTER, MAX_SLOTS, RvKey, SlotStats, StartKey,
    bucket_of,
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
static START: HashMap<StartKey, u64> = HashMap::with_max_entries(16384, 0);

#[map]
static RV_COUNTS: PerCpuHashMap<RvKey, u64> = PerCpuHashMap::with_max_entries(4096, 0);

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
    let now = unsafe { helpers::bpf_ktime_get_ns() };
    // A re-entrant call overwrites its own start: the outer call then
    // measures short. Recorded rather than dropped; PKCS#11 entry points
    // are not re-entrant in practice.
    let _ = START.insert(&key, &now, 0);
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
    let delta = now.saturating_sub(start);
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
    0
}

#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    loop {}
}
