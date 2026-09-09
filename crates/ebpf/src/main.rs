//! p11scope BPF programs. A lightweight or template-aware entry program
//! plus one return program serve every attach point. The attach cookie
//! carries the slot and descriptor indices, so 68+ probes share a small fixed program set
//! rather than per-function copies. Cookies need kernel >= 5.15.
#![no_std]
#![no_main]
#![feature(core_intrinsics)]
#![allow(internal_features)]

use aya_ebpf::bindings::BPF_F_RDONLY_PROG;
use aya_ebpf::macros::{map, raw_tracepoint, uprobe, uretprobe};
use aya_ebpf::maps::ProgramArray;
use aya_ebpf::maps::ring_buf::RingBufEntry;
use aya_ebpf::maps::{Array, CgroupArray, HashMap, PerCpuArray, PerCpuHashMap, RingBuf};
use aya_ebpf::programs::{ProbeContext, RawTracePointContext, RetProbeContext};
use aya_ebpf::{EbpfContext as _, helpers};
use core::mem::MaybeUninit;
use p11scope_ebpf_common::{
    ARG_NONE, CFG_FLAGS, COALESCED_NO_HELPER_RC, CallStart, DISCOVERY_BYTES,
    DISCOVERY_COUNTER_CELLS, DISCOVERY_COUNTER_EXPORT_BOUNDED_READ_FAILURES,
    DISCOVERY_COUNTER_EXPORT_STATE_FAILURES, DISCOVERY_COUNTER_LOADER_HITS,
    DISCOVERY_COUNTER_LOADER_STATE_READ_FAILURES, DISCOVERY_COUNTER_RING_LOSS,
    DISCOVERY_INTERFACES, DISCOVERY_KIND_EXEC, DISCOVERY_KIND_FUNCTION_LIST_RETURN,
    DISCOVERY_KIND_INTERFACE_LIST_ELEMENT_RETURN, DISCOVERY_KIND_INTERFACE_RETURN,
    DISCOVERY_KIND_LEADER_EXIT, DISCOVERY_KIND_LOADER, DISCOVERY_NAME_EXACT_STANDARD,
    DISCOVERY_NAME_NA, DISCOVERY_NAME_NULL, DISCOVERY_NAME_OTHER, DISCOVERY_NAME_UNREADABLE,
    DISCOVERY_STATUS_COALESCED_NO_HELPER, DISCOVERY_STATUS_LOADER_CONTEXT_INVALID,
    DISCOVERY_STATUS_READ_FAILURE, DISCOVERY_VERSION_NULL, DISCOVERY_VERSION_UNREADABLE,
    DISCOVERY_VERSION_V3_0, DISCOVERY_VERSION_V3_1, DISCOVERY_VERSION_V3_2, DiscoveryRecord,
    EVIDENCE_ABI_REFUSALS, EVIDENCE_CELLS, EVIDENCE_CGROUP_SCOPE_FAILURES, EVIDENCE_RING_LOSS,
    EVIDENCE_RV_UPDATE_FAILURES, EVIDENCE_SEMANTIC_CAPTURE_FAILURES,
    EVIDENCE_START_INSERT_FAILURES, EVIDENCE_UNMATCHED_RETURNS, EVIDENCE_UNREGISTERED_MECHANISMS,
    Event, FLAG_CGROUP_FILTER, FLAG_PID_FILTER, FLAG_POLICY_AGGREGATE, FLAG_POLICY_ALLOWLISTED,
    FUNCTION_NAME_MAX_BYTES, FUNCTION_NONE, FunctionNameKey, ImageIdentity, LOADER_STATE_PRESENT,
    LinuxLayout, MAX_DESCRIPTORS, MAX_MECH_SHAPES, MAX_SLOTS, MECH_NONE, PAUSE_ARMED,
    PAUSE_REQUESTED, PauseKey, RING_BYTES, RV_ENTRIES, RvKey, SESSION_NONE, START_ENTRIES,
    STATE_DOMAIN_EXPORT, STATE_DOMAIN_SELECTION, SlotSemantics, SlotStats, StartKey, StartState,
    StateKey, TAIL_CALLS_INTERFACE_WORKER_SLOT, USER_TYPE_NONE, bucket_of, capture,
    classify_task_newtask, cookie_descriptor, cookie_slot, decode_export_attach_cookie,
    discovery_pause_coalesced, discovery_pause_enabled, discovery_state_take_failed,
    discovery_state_take_scope_lost, discovery_table_slots, discovery_usable_prefix,
    discovery_version_class, event_type, image_pair_matches, interface_continuation_next,
    interface_continuation_pack, interface_continuation_unpack, lifecycle, normalize_target_word,
    return_allows_mechanism, shape, target_layout_from_cs, target_stack_arg_address,
    target_word_end, valid_config, valid_loader_cookie,
};
#[cfg(feature = "unsafe-unvalidated-metadata")]
use p11scope_ebpf_common::{
    EVIDENCE_TEMPLATE_TAIL_FAILURES, FLAG_POLICY_UNSAFE_UNVALIDATED_METADATA, MAX_ATTRS,
    TAIL_CALLS_TEMPLATE_SECOND_SLOT,
};

#[map]
static CONFIG: Array<u64> = Array::with_max_entries(2, BPF_F_RDONLY_PROG);

#[map]
static PID_FILTER: HashMap<u32, u64> = HashMap::with_max_entries(1024, BPF_F_RDONLY_PROG);

#[map]
static CGROUP_FILTER: CgroupArray = CgroupArray::with_max_entries(1, 0);

#[map]
static STATS: PerCpuArray<SlotStats> = PerCpuArray::with_max_entries(MAX_SLOTS, 0);

#[map]
static START: HashMap<StartKey, CallStart> = HashMap::with_max_entries(START_ENTRIES, 0);

#[map]
static RV_COUNTS: PerCpuHashMap<RvKey, u64> = PerCpuHashMap::with_max_entries(RV_ENTRIES, 0);

#[map]
static DESCRIPTORS: Array<SlotSemantics> =
    Array::with_max_entries(MAX_DESCRIPTORS, BPF_F_RDONLY_PROG);

/// Mechanism id -> parameter shape code, published by userspace from
/// proxy-ng's registry. An unknown mechanism id looks up empty and is
/// treated as `shape::NONE`.
#[map]
static MECH_SHAPE: HashMap<u64, u32> =
    HashMap::with_max_entries(MAX_MECH_SHAPES, BPF_F_RDONLY_PROG);

/// Attribute type -> allowlisted boolean mask. Keeping the catalog in a map
/// avoids multiplying verifier states by eleven match arms for every one of
/// the bounded template entries.
#[cfg(feature = "unsafe-unvalidated-metadata")]
#[map]
static ATTR_BOOL_BITS: HashMap<u32, u32> = HashMap::with_max_entries(16, BPF_F_RDONLY_PROG);

#[map]
static TAIL_CALLS: ProgramArray = ProgramArray::with_max_entries(2, 0);

/// Exact bounded standard function name -> stable shared-table id. Raw
/// `pFunctionName` bytes never leave the BPF stack.
#[map]
static ASYNC_FUNCTIONS: HashMap<FunctionNameKey, u32> =
    HashMap::with_max_entries(128, BPF_F_RDONLY_PROG);

#[map]
static EVENTS: RingBuf = RingBuf::with_byte_size(RING_BYTES, 0);

#[map]
static EVIDENCE: PerCpuArray<u64> = PerCpuArray::with_max_entries(EVIDENCE_CELLS, 0);

#[map]
static DISCOVERY: RingBuf = RingBuf::with_byte_size(DISCOVERY_BYTES, 0);

#[map]
static DISCOVERY_STATE: HashMap<StateKey, StartState> = HashMap::with_max_entries(64, 0);

#[map]
static COUNTERS: PerCpuArray<u64> = PerCpuArray::with_max_entries(DISCOVERY_COUNTER_CELLS, 0);

#[map]
static PAUSE_PIDS: HashMap<PauseKey, u64> = HashMap::with_max_entries(1, 0);

/// Does this call belong to the capture scope? With no filter configured
/// nothing is observed — scope is always explicit (design spec: no
/// magical system-wide capture).
fn bump_evidence(index: u32) {
    if let Some(value) = EVIDENCE.get_ptr_mut(index) {
        unsafe { *value += 1 };
    }
}

#[inline(always)]
fn probe_layout(ctx: &ProbeContext) -> Option<LinuxLayout> {
    target_layout_from_cs(unsafe { (*ctx.regs).cs as u64 })
}

#[inline(always)]
fn ret_probe_layout(ctx: &RetProbeContext) -> Option<LinuxLayout> {
    target_layout_from_cs(unsafe { (*ctx.regs).cs as u64 })
}

#[inline(always)]
fn read_word(address: u64, layout: LinuxLayout) -> Result<u64, ()> {
    target_word_end(address, layout).ok_or(())?;
    match layout {
        LinuxLayout::Lp64 => {
            unsafe { helpers::bpf_probe_read_user(address as *const u64) }.map_err(|_| ())
        }
        LinuxLayout::Ilp32 => unsafe { helpers::bpf_probe_read_user(address as *const u32) }
            .map(u64::from)
            .map_err(|_| ()),
    }
}

#[inline(always)]
fn read_interface(address: u64, layout: LinuxLayout) -> Result<[u64; 3], ()> {
    let last = address
        .checked_add(layout.word_bytes() as u64 * 2)
        .ok_or(())?;
    target_word_end(last, layout).ok_or(())?;
    match layout {
        LinuxLayout::Lp64 => {
            unsafe { helpers::bpf_probe_read_user(address as *const [u64; 3]) }.map_err(|_| ())
        }
        LinuxLayout::Ilp32 => unsafe { helpers::bpf_probe_read_user(address as *const [u32; 3]) }
            .map(|words| words.map(u64::from))
            .map_err(|_| ()),
    }
}

#[cfg(feature = "unsafe-unvalidated-metadata")]
#[inline(always)]
fn read_word_pair(address: u64, layout: LinuxLayout) -> Result<[u64; 2], ()> {
    let second = address.checked_add(layout.word_bytes() as u64).ok_or(())?;
    target_word_end(second, layout).ok_or(())?;
    match layout {
        LinuxLayout::Lp64 => {
            unsafe { helpers::bpf_probe_read_user(address as *const [u64; 2]) }.map_err(|_| ())
        }
        LinuxLayout::Ilp32 => unsafe { helpers::bpf_probe_read_user(address as *const [u32; 2]) }
            .map(|words| words.map(u64::from))
            .map_err(|_| ()),
    }
}

const _: [(); 288] = [(); core::mem::size_of::<CallStart>()];

#[inline(always)]
fn zero_call_start(start: &mut MaybeUninit<CallStart>) {
    let words = start.as_mut_ptr().cast::<u64>();
    // Keep this straight-line, as with DiscoveryRecord: LLVM otherwise lowers
    // the full initialization to verifier-hostile memset/memcpy backtracking.
    unsafe {
        // CALL_START_INITIALIZER_BEGIN
        core::ptr::write_volatile(words.add(0), 0u64);
        core::ptr::write_volatile(words.add(1), 0u64);
        core::ptr::write_volatile(words.add(2), 0u64);
        core::ptr::write_volatile(words.add(3), 0u64);
        core::ptr::write_volatile(words.add(4), 0u64);
        core::ptr::write_volatile(words.add(5), 0u64);
        core::ptr::write_volatile(words.add(6), 0u64);
        core::ptr::write_volatile(words.add(7), 0u64);
        core::ptr::write_volatile(words.add(8), 0u64);
        core::ptr::write_volatile(words.add(9), 0u64);
        core::ptr::write_volatile(words.add(10), 0u64);
        core::ptr::write_volatile(words.add(11), 0u64);
        core::ptr::write_volatile(words.add(12), 0u64);
        core::ptr::write_volatile(words.add(13), 0u64);
        core::ptr::write_volatile(words.add(14), 0u64);
        core::ptr::write_volatile(words.add(15), 0u64);
        core::ptr::write_volatile(words.add(16), 0u64);
        core::ptr::write_volatile(words.add(17), 0u64);
        core::ptr::write_volatile(words.add(18), 0u64);
        core::ptr::write_volatile(words.add(19), 0u64);
        core::ptr::write_volatile(words.add(20), 0u64);
        core::ptr::write_volatile(words.add(21), 0u64);
        core::ptr::write_volatile(words.add(22), 0u64);
        core::ptr::write_volatile(words.add(23), 0u64);
        core::ptr::write_volatile(words.add(24), 0u64);
        core::ptr::write_volatile(words.add(25), 0u64);
        core::ptr::write_volatile(words.add(26), 0u64);
        core::ptr::write_volatile(words.add(27), 0u64);
        core::ptr::write_volatile(words.add(28), 0u64);
        core::ptr::write_volatile(words.add(29), 0u64);
        core::ptr::write_volatile(words.add(30), 0u64);
        core::ptr::write_volatile(words.add(31), 0u64);
        core::ptr::write_volatile(words.add(32), 0u64);
        core::ptr::write_volatile(words.add(33), 0u64);
        core::ptr::write_volatile(words.add(34), 0u64);
        core::ptr::write_volatile(words.add(35), 0u64);
        // CALL_START_INITIALIZER_END
    }
}

#[derive(Clone, Copy)]
#[repr(C)]
struct ScopeAuth {
    flags: u64,
    tgid: u32,
    _pad: u32,
    generation_token: u64,
}

const _: [(); 24] = [(); core::mem::size_of::<ScopeAuth>()];
const _: [(); 0] = [(); core::mem::offset_of!(ScopeAuth, flags)];
const _: [(); 8] = [(); core::mem::offset_of!(ScopeAuth, tgid)];
const _: [(); 12] = [(); core::mem::offset_of!(ScopeAuth, _pad)];
const _: [(); 16] = [(); core::mem::offset_of!(ScopeAuth, generation_token)];

fn scope_auth() -> Option<ScopeAuth> {
    if unsafe { p11_owner_healthy() } == 0 {
        return None;
    }
    let flags = CONFIG.get(CFG_FLAGS).copied().unwrap_or(0);
    if !valid_config(flags) {
        return None;
    }
    let pid_tgid = helpers::bpf_get_current_pid_tgid();
    let tgid = (pid_tgid >> 32) as u32;
    if flags & FLAG_PID_FILTER != 0 {
        let token = unsafe { PID_FILTER.get(&tgid) }.copied().unwrap_or(0);
        if token != 0 {
            return Some(ScopeAuth {
                flags,
                tgid,
                _pad: 0,
                generation_token: token,
            });
        }
    }
    if flags & FLAG_CGROUP_FILTER != 0 {
        match CGROUP_FILTER.current_task_under_cgroup(0) {
            Ok(true) => {
                return Some(ScopeAuth {
                    flags,
                    tgid,
                    _pad: 0,
                    generation_token: 0,
                });
            }
            Ok(false) => return None,
            Err(_) => {
                bump_evidence(EVIDENCE_CGROUP_SCOPE_FAILURES);
                return None;
            }
        }
    }
    None
}

fn scope_flags() -> Option<u64> {
    scope_auth().map(|scope| scope.flags)
}

fn bump_discovery_counter(index: u32) {
    if let Some(value) = COUNTERS.get_ptr_mut(index) {
        // SAFETY: PerCpuArray gives this CPU exclusive access to its cell.
        unsafe { *value += 1 };
    }
}

/// One source-bounded reservation/initializer path for every private
/// discovery record. The object checker proves that this always-inlined region
/// becomes 115 aligned u64 zero stores before any field use or submit.
#[inline(always)]
fn reserve_discovery() -> Option<RingBufEntry<DiscoveryRecord>> {
    let Some(mut entry) = DISCOVERY.reserve::<DiscoveryRecord>(0) else {
        bump_discovery_counter(DISCOVERY_COUNTER_RING_LOSS);
        return None;
    };
    let raw = entry.as_mut_ptr();
    let words = raw.cast::<u64>();
    // SAFETY: the reservation owns exactly one aligned 920-byte record. These
    // straight-line volatile stores cover word indices 0..=114 exactly once.
    unsafe {
        // TASK5_DISCOVERY_INITIALIZER_BEGIN
        core::ptr::write_volatile(words.add(0), 0u64);
        core::ptr::write_volatile(words.add(1), 0u64);
        core::ptr::write_volatile(words.add(2), 0u64);
        core::ptr::write_volatile(words.add(3), 0u64);
        core::ptr::write_volatile(words.add(4), 0u64);
        core::ptr::write_volatile(words.add(5), 0u64);
        core::ptr::write_volatile(words.add(6), 0u64);
        core::ptr::write_volatile(words.add(7), 0u64);
        core::ptr::write_volatile(words.add(8), 0u64);
        core::ptr::write_volatile(words.add(9), 0u64);
        core::ptr::write_volatile(words.add(10), 0u64);
        core::ptr::write_volatile(words.add(11), 0u64);
        core::ptr::write_volatile(words.add(12), 0u64);
        core::ptr::write_volatile(words.add(13), 0u64);
        core::ptr::write_volatile(words.add(14), 0u64);
        core::ptr::write_volatile(words.add(15), 0u64);
        core::ptr::write_volatile(words.add(16), 0u64);
        core::ptr::write_volatile(words.add(17), 0u64);
        core::ptr::write_volatile(words.add(18), 0u64);
        core::ptr::write_volatile(words.add(19), 0u64);
        core::ptr::write_volatile(words.add(20), 0u64);
        core::ptr::write_volatile(words.add(21), 0u64);
        core::ptr::write_volatile(words.add(22), 0u64);
        core::ptr::write_volatile(words.add(23), 0u64);
        core::ptr::write_volatile(words.add(24), 0u64);
        core::ptr::write_volatile(words.add(25), 0u64);
        core::ptr::write_volatile(words.add(26), 0u64);
        core::ptr::write_volatile(words.add(27), 0u64);
        core::ptr::write_volatile(words.add(28), 0u64);
        core::ptr::write_volatile(words.add(29), 0u64);
        core::ptr::write_volatile(words.add(30), 0u64);
        core::ptr::write_volatile(words.add(31), 0u64);
        core::ptr::write_volatile(words.add(32), 0u64);
        core::ptr::write_volatile(words.add(33), 0u64);
        core::ptr::write_volatile(words.add(34), 0u64);
        core::ptr::write_volatile(words.add(35), 0u64);
        core::ptr::write_volatile(words.add(36), 0u64);
        core::ptr::write_volatile(words.add(37), 0u64);
        core::ptr::write_volatile(words.add(38), 0u64);
        core::ptr::write_volatile(words.add(39), 0u64);
        core::ptr::write_volatile(words.add(40), 0u64);
        core::ptr::write_volatile(words.add(41), 0u64);
        core::ptr::write_volatile(words.add(42), 0u64);
        core::ptr::write_volatile(words.add(43), 0u64);
        core::ptr::write_volatile(words.add(44), 0u64);
        core::ptr::write_volatile(words.add(45), 0u64);
        core::ptr::write_volatile(words.add(46), 0u64);
        core::ptr::write_volatile(words.add(47), 0u64);
        core::ptr::write_volatile(words.add(48), 0u64);
        core::ptr::write_volatile(words.add(49), 0u64);
        core::ptr::write_volatile(words.add(50), 0u64);
        core::ptr::write_volatile(words.add(51), 0u64);
        core::ptr::write_volatile(words.add(52), 0u64);
        core::ptr::write_volatile(words.add(53), 0u64);
        core::ptr::write_volatile(words.add(54), 0u64);
        core::ptr::write_volatile(words.add(55), 0u64);
        core::ptr::write_volatile(words.add(56), 0u64);
        core::ptr::write_volatile(words.add(57), 0u64);
        core::ptr::write_volatile(words.add(58), 0u64);
        core::ptr::write_volatile(words.add(59), 0u64);
        core::ptr::write_volatile(words.add(60), 0u64);
        core::ptr::write_volatile(words.add(61), 0u64);
        core::ptr::write_volatile(words.add(62), 0u64);
        core::ptr::write_volatile(words.add(63), 0u64);
        core::ptr::write_volatile(words.add(64), 0u64);
        core::ptr::write_volatile(words.add(65), 0u64);
        core::ptr::write_volatile(words.add(66), 0u64);
        core::ptr::write_volatile(words.add(67), 0u64);
        core::ptr::write_volatile(words.add(68), 0u64);
        core::ptr::write_volatile(words.add(69), 0u64);
        core::ptr::write_volatile(words.add(70), 0u64);
        core::ptr::write_volatile(words.add(71), 0u64);
        core::ptr::write_volatile(words.add(72), 0u64);
        core::ptr::write_volatile(words.add(73), 0u64);
        core::ptr::write_volatile(words.add(74), 0u64);
        core::ptr::write_volatile(words.add(75), 0u64);
        core::ptr::write_volatile(words.add(76), 0u64);
        core::ptr::write_volatile(words.add(77), 0u64);
        core::ptr::write_volatile(words.add(78), 0u64);
        core::ptr::write_volatile(words.add(79), 0u64);
        core::ptr::write_volatile(words.add(80), 0u64);
        core::ptr::write_volatile(words.add(81), 0u64);
        core::ptr::write_volatile(words.add(82), 0u64);
        core::ptr::write_volatile(words.add(83), 0u64);
        core::ptr::write_volatile(words.add(84), 0u64);
        core::ptr::write_volatile(words.add(85), 0u64);
        core::ptr::write_volatile(words.add(86), 0u64);
        core::ptr::write_volatile(words.add(87), 0u64);
        core::ptr::write_volatile(words.add(88), 0u64);
        core::ptr::write_volatile(words.add(89), 0u64);
        core::ptr::write_volatile(words.add(90), 0u64);
        core::ptr::write_volatile(words.add(91), 0u64);
        core::ptr::write_volatile(words.add(92), 0u64);
        core::ptr::write_volatile(words.add(93), 0u64);
        core::ptr::write_volatile(words.add(94), 0u64);
        core::ptr::write_volatile(words.add(95), 0u64);
        core::ptr::write_volatile(words.add(96), 0u64);
        core::ptr::write_volatile(words.add(97), 0u64);
        core::ptr::write_volatile(words.add(98), 0u64);
        core::ptr::write_volatile(words.add(99), 0u64);
        core::ptr::write_volatile(words.add(100), 0u64);
        core::ptr::write_volatile(words.add(101), 0u64);
        core::ptr::write_volatile(words.add(102), 0u64);
        core::ptr::write_volatile(words.add(103), 0u64);
        core::ptr::write_volatile(words.add(104), 0u64);
        core::ptr::write_volatile(words.add(105), 0u64);
        core::ptr::write_volatile(words.add(106), 0u64);
        core::ptr::write_volatile(words.add(107), 0u64);
        core::ptr::write_volatile(words.add(108), 0u64);
        core::ptr::write_volatile(words.add(109), 0u64);
        core::ptr::write_volatile(words.add(110), 0u64);
        core::ptr::write_volatile(words.add(111), 0u64);
        core::ptr::write_volatile(words.add(112), 0u64);
        core::ptr::write_volatile(words.add(113), 0u64);
        core::ptr::write_volatile(words.add(114), 0u64);
        // TASK5_DISCOVERY_INITIALIZER_END
    }
    Some(entry)
}

#[inline(always)]
// TASK5_PAUSE_WRITER_BEGIN
fn finish_discovery_record(
    mut entry: RingBufEntry<DiscoveryRecord>,
    scope: ScopeAuth,
    eligible: bool,
    pid_tgid: u64,
    mut status_flags: u8,
) {
    let raw = entry.as_mut_ptr();
    let (hook_ts_ns, send_signal_rc) =
        if discovery_pause_enabled(eligible, scope.flags, scope.generation_token) {
            let key = PauseKey {
                tgid: scope.tgid,
                pad: 0,
                generation_token: scope.generation_token,
            };
            if let Some(value) = PAUSE_PIDS.get_ptr_mut(&key) {
                // SAFETY: the pointer is the exact live map value for the full
                // generation key; this is the only kernel writer.
                let (previous, won) = unsafe {
                    core::intrinsics::atomic_cxchg::<
                        u64,
                        { core::intrinsics::AtomicOrdering::AcqRel },
                        { core::intrinsics::AtomicOrdering::Acquire },
                    >(value, PAUSE_ARMED, PAUSE_REQUESTED)
                };
                if won {
                    // SAFETY: the causal timestamp is immediately before the one
                    // finite SIGSTOP request and both helpers take scalar inputs.
                    let hook_ts_ns = unsafe { helpers::bpf_ktime_get_ns() };
                    let send_signal_rc = unsafe { helpers::bpf_send_signal(19) } as i64;
                    (hook_ts_ns, send_signal_rc)
                } else if discovery_pause_coalesced(previous, won) {
                    status_flags |= DISCOVERY_STATUS_COALESCED_NO_HELPER;
                    (
                        unsafe { helpers::bpf_ktime_get_ns() },
                        COALESCED_NO_HELPER_RC,
                    )
                } else {
                    (unsafe { helpers::bpf_ktime_get_ns() }, 0)
                }
            } else {
                (unsafe { helpers::bpf_ktime_get_ns() }, 0)
            }
        } else {
            (unsafe { helpers::bpf_ktime_get_ns() }, 0)
        };
    // SAFETY: the shared initializer and all producer-specific writes finish
    // before this terminal timestamp/result sequence.
    unsafe {
        core::ptr::write_volatile(core::ptr::addr_of_mut!((*raw).hook_ts_ns), hook_ts_ns);
        core::ptr::write_volatile(core::ptr::addr_of_mut!((*raw).pid_tgid), pid_tgid);
        core::ptr::write_volatile(core::ptr::addr_of_mut!((*raw).status_flags), status_flags);
        core::ptr::write_volatile(
            core::ptr::addr_of_mut!((*raw).send_signal_rc),
            send_signal_rc,
        );
    }
    entry.submit(0);
}
// TASK5_PAUSE_WRITER_END

struct ExportArgs {
    kind: u8,
    interface_index: u8,
    symbol_id: u32,
    announced_count: u32,
    address: u64,
}

/// Laid out by hand, with the tail padding named.
///
/// This struct is copied whole onto the BPF stack. Under `repr(Rust)` the
/// compiler ordered it with five trailing padding bytes that nothing wrote,
/// and LLVM widened the copy to 8-byte loads that span them. Verifiers before
/// ~6.5 refuse to read a stack byte that is neither MISC nor ZERO, so the copy
/// was rejected with `invalid read from stack off -72+3 size 8` and
/// `BPF_PROG_LOAD` returned EACCES -- on 5.15 and 6.2, while 6.5 and newer
/// accepted the very same object. Naming the padding and initialising it makes
/// the whole 32 bytes written, which every verifier accepts.
#[derive(Clone, Copy)]
#[repr(C)]
struct SelectionTransport {
    request_flags: u64,
    binding_id: u64,
    return_rv: u64,
    request_name_class: u8,
    request_version_class: u8,
    pause_eligible: bool,
    word_bytes: u8,
    _pad: [u8; 4],
}

// Three u64 (24) + four single bytes + four named pad bytes = 32, with no
// implicit padding left for a verifier to reject. Naming `_pad` in the
// assertion is the point: deleting it, reordering the fields or dropping
// `repr(C)` stops this compiling, instead of failing on somebody's 5.15
// kernel. A size check alone would not -- implicit padding keeps the size at
// 32 while leaving those bytes unwritten, which is exactly the bug.
const _: () = assert!(core::mem::offset_of!(SelectionTransport, word_bytes) == 27);
const _: () = assert!(core::mem::offset_of!(SelectionTransport, _pad) == 28);
const _: () = assert!(core::mem::size_of::<SelectionTransport>() == 32);

fn no_selection(layout: LinuxLayout) -> SelectionTransport {
    SelectionTransport {
        _pad: [0; 4],
        request_name_class: DISCOVERY_NAME_NA,
        request_version_class: DISCOVERY_VERSION_NULL,
        request_flags: 0,
        binding_id: 0,
        return_rv: 0,
        pause_eligible: true,
        word_bytes: layout.word_bytes() as u8,
    }
}

fn selection_layout(selection: &SelectionTransport) -> Option<LinuxLayout> {
    match selection.word_bytes {
        4 => Some(LinuxLayout::Ilp32),
        8 => Some(LinuxLayout::Lp64),
        _ => None,
    }
}

struct ExportPayload {
    record_meta: u64,
    announced_count: u32,
    table_ptr: u64,
    interface_flags: u64,
    selection: SelectionTransport,
}

#[inline(never)]
fn classify_direct_interface(
    mut record_meta: u64,
    announced_count: u32,
    address: u64,
    scope: &ScopeAuth,
    selection: &SelectionTransport,
) {
    let Some(layout) = selection_layout(selection) else {
        bump_discovery_counter(DISCOVERY_COUNTER_EXPORT_BOUNDED_READ_FAILURES);
        return;
    };
    let mut read_failed = false;
    let mut interface_unreadable = false;
    let mut table_ptr = 0u64;
    let mut interface_flags = 0u64;
    let mut name_class = DISCOVERY_NAME_NA;

    if address == 0 {
        name_class = DISCOVERY_NAME_UNREADABLE;
        read_failed = true;
        interface_unreadable = true;
    } else {
        match read_interface(address, layout) {
            Ok([name, table, flags]) => {
                table_ptr = table;
                interface_flags = flags;
                if name == 0 {
                    name_class = DISCOVERY_NAME_NULL;
                } else {
                    let mut bytes = [0u8; 9];
                    let read = unsafe {
                        helpers::generated::bpf_probe_read_user_str(
                            bytes.as_mut_ptr().cast(),
                            bytes.len() as u32,
                            name as *const core::ffi::c_void,
                        )
                    };
                    if read < 0 {
                        name_class = DISCOVERY_NAME_UNREADABLE;
                        read_failed = true;
                    } else if read == 8 && bytes[..8] == *b"PKCS 11\0" {
                        name_class = DISCOVERY_NAME_EXACT_STANDARD;
                    } else {
                        name_class = DISCOVERY_NAME_OTHER;
                    }
                }
            }
            Err(_) => {
                name_class = DISCOVERY_NAME_UNREADABLE;
                read_failed = true;
                interface_unreadable = true;
            }
        }
    }

    record_meta = (record_meta & !(0xff00_0000u64 | 0x00ff_0000u64 | 1u64 << 25))
        | ((name_class as u64) << 16)
        | ((read_failed as u64) << 24)
        | ((interface_unreadable as u64) << 25);
    emit_export(
        &ExportPayload {
            record_meta,
            announced_count,
            table_ptr,
            interface_flags,
            selection: *selection,
        },
        scope,
    );
}

#[inline(never)]
fn classify_indirect_interface(
    record_meta: u64,
    announced_count: u32,
    pp_interface: u64,
    scope: &ScopeAuth,
    selection: &SelectionTransport,
) {
    let Some(layout) = selection_layout(selection) else {
        bump_discovery_counter(DISCOVERY_COUNTER_EXPORT_BOUNDED_READ_FAILURES);
        return;
    };
    let interface_address = if pp_interface == 0 {
        0
    } else {
        let address = pp_interface;
        match read_word(address, layout) {
            Ok(pointer) => pointer,
            Err(_) => 0,
        }
    };
    classify_direct_interface(
        record_meta,
        announced_count,
        interface_address,
        scope,
        selection,
    );
}

#[inline(never)]
fn emit_export(payload: &ExportPayload, scope: &ScopeAuth) {
    let Some(layout) = selection_layout(&payload.selection) else {
        bump_discovery_counter(DISCOVERY_COUNTER_EXPORT_BOUNDED_READ_FAILURES);
        return;
    };
    let Some(mut entry) = reserve_discovery() else {
        return;
    };
    let raw = entry.as_mut_ptr();
    let kind = payload.record_meta as u8;
    let interface_index = (payload.record_meta >> 8) as u8;
    let name_class = (payload.record_meta >> 16) as u8;
    let mut read_failed = (payload.record_meta >> 24) & 1 != 0;
    let interface_unreadable = (payload.record_meta >> 25) & 1 != 0;
    let symbol_id = (payload.record_meta >> 32) as u32;
    let selection = payload.selection;
    let read_table = name_class == DISCOVERY_NAME_NA || name_class == DISCOVERY_NAME_EXACT_STANDARD;
    let mut version_major = 0u8;
    let mut version_minor = 0u8;
    let mut selection_version_class = DISCOVERY_VERSION_NULL;
    let mut attempted = 0u8;
    let mut completed = 0u8;
    let mut walk_slots = 0u8;
    let mut read_version = false;
    if selection.return_rv != 0 {
        read_failed = false;
    } else if selection.binding_id != 0 {
        if interface_unreadable {
            selection_version_class = DISCOVERY_VERSION_UNREADABLE;
        } else if payload.table_ptr == 0 {
            read_failed = true;
        } else {
            read_version = true;
        }
    } else if read_table && !read_failed {
        read_version = true;
    }
    if read_version {
        match unsafe { helpers::bpf_probe_read_user(payload.table_ptr as *const [u8; 2]) } {
            Ok(version) => {
                if selection.binding_id != 0 {
                    selection_version_class = discovery_version_class(version[0], version[1]);
                    if name_class == DISCOVERY_NAME_EXACT_STANDARD
                        && matches!(
                            selection_version_class,
                            DISCOVERY_VERSION_V3_0
                                | DISCOVERY_VERSION_V3_1
                                | DISCOVERY_VERSION_V3_2
                        )
                    {
                        walk_slots = discovery_table_slots(version[0], version[1]);
                    }
                } else {
                    version_major = version[0];
                    version_minor = version[1];
                    walk_slots = discovery_table_slots(version_major, version_minor);
                }
            }
            Err(_) => {
                if selection.binding_id != 0 {
                    selection_version_class = DISCOVERY_VERSION_UNREADABLE;
                }
                read_failed = true;
            }
        }
    }
    let mut pointer_index = 0usize;
    while pointer_index < 104 {
        if pointer_index >= walk_slots as usize {
            break;
        }
        attempted += 1;
        let Some(address) = payload
            .table_ptr
            .checked_add(layout.word_bytes() as u64)
            .and_then(|base| base.checked_add(pointer_index as u64 * layout.word_bytes() as u64))
        else {
            read_failed = true;
            break;
        };
        match read_word(address, layout) {
            Ok(pointer) => {
                // SAFETY: pointer_index is statically bounded below
                // DISCOVERY_POINTERS and the record is initialized.
                unsafe {
                    core::ptr::write_volatile(
                        core::ptr::addr_of_mut!((*raw).pointers[pointer_index]),
                        pointer,
                    );
                }
                completed += 1;
            }
            Err(_) => {
                read_failed = true;
                break;
            }
        }
        pointer_index += 1;
    }
    if read_failed {
        bump_discovery_counter(DISCOVERY_COUNTER_EXPORT_BOUNDED_READ_FAILURES);
    }
    let usable = discovery_usable_prefix(read_failed, completed);

    let status = if read_failed {
        DISCOVERY_STATUS_READ_FAILURE
    } else {
        0
    };
    // SAFETY: the shared initializer completed before every field write.
    unsafe {
        core::ptr::write_volatile(core::ptr::addr_of_mut!((*raw).table_ptr), payload.table_ptr);
        core::ptr::write_volatile(
            core::ptr::addr_of_mut!((*raw).interface_flags),
            payload.interface_flags,
        );
        core::ptr::write_volatile(core::ptr::addr_of_mut!((*raw).kind), kind);
        if selection.binding_id != 0 {
            core::ptr::write_volatile(
                core::ptr::addr_of_mut!((*raw).case_id),
                selection.request_name_class,
            );
            core::ptr::write_volatile(
                core::ptr::addr_of_mut!((*raw).interface_index),
                selection.request_version_class,
            );
            core::ptr::write_volatile(
                core::ptr::addr_of_mut!((*raw).return_rv),
                selection.return_rv,
            );
            core::ptr::write_volatile(
                core::ptr::addr_of_mut!((*raw).request_flags),
                selection.request_flags,
            );
            core::ptr::write_volatile(
                core::ptr::addr_of_mut!((*raw).binding_id),
                selection.binding_id,
            );
        }
        if selection.binding_id == 0 {
            core::ptr::write_volatile(
                core::ptr::addr_of_mut!((*raw).interface_index),
                interface_index,
            );
        }
        core::ptr::write_volatile(core::ptr::addr_of_mut!((*raw).name_class), name_class);
        core::ptr::write_volatile(core::ptr::addr_of_mut!((*raw).usable_n), usable);
        core::ptr::write_volatile(
            core::ptr::addr_of_mut!((*raw).pointers_attempted),
            attempted,
        );
        core::ptr::write_volatile(core::ptr::addr_of_mut!((*raw).completed_prefix), completed);
        core::ptr::write_volatile(core::ptr::addr_of_mut!((*raw).version_major), version_major);
        core::ptr::write_volatile(core::ptr::addr_of_mut!((*raw).version_minor), version_minor);
        core::ptr::write_volatile(
            core::ptr::addr_of_mut!((*raw).selection_version_class),
            if selection.binding_id != 0 {
                selection_version_class
            } else {
                0
            },
        );
        core::ptr::write_volatile(core::ptr::addr_of_mut!((*raw).symbol_id), symbol_id);
        core::ptr::write_volatile(
            core::ptr::addr_of_mut!((*raw).announced_count),
            payload.announced_count,
        );
    }
    let pid_tgid = helpers::bpf_get_current_pid_tgid();
    let pause_eligible = selection.pause_eligible;
    finish_discovery_record(entry, *scope, pause_eligible, pid_tgid, status);
}

#[inline(always)]
fn classify_export(args: &ExportArgs, scope: &ScopeAuth, layout: LinuxLayout) {
    let record_meta =
        args.kind as u64 | ((args.interface_index as u64) << 8) | ((args.symbol_id as u64) << 32);
    let mut read_failed = false;
    let table_ptr = match read_word(args.address, layout) {
        Ok(pointer) if pointer != 0 => pointer,
        _ => {
            read_failed = true;
            0
        }
    };
    emit_export(
        &ExportPayload {
            record_meta: record_meta | ((read_failed as u64) << 24),
            announced_count: args.announced_count,
            table_ptr,
            interface_flags: 0,
            selection: no_selection(layout),
        },
        scope,
    );
}

fn export_symbol_id(cookie: u64) -> Option<u32> {
    let (_, _, symbol_id) = decode_export_attach_cookie(cookie)?;
    Some(symbol_id)
}

fn export_state_key<C: aya_ebpf::EbpfContext>(ctx: &C) -> Option<StateKey> {
    let attach_cookie = unsafe { helpers::bpf_get_attach_cookie(ctx.as_ptr()) };
    export_symbol_id(attach_cookie)?;
    Some(StateKey {
        pid_tgid: helpers::bpf_get_current_pid_tgid(),
        attach_cookie,
        domain: STATE_DOMAIN_EXPORT,
    })
}

fn insert_export_state(ctx: &ProbeContext, state: StartState) {
    if scope_auth().is_none() {
        return;
    }
    let Some(key) = export_state_key(ctx) else {
        return;
    };
    if owned_discovery_insert(&key, &state, aya_ebpf::bindings::BPF_NOEXIST as u64).is_err() {
        bump_discovery_counter(DISCOVERY_COUNTER_EXPORT_STATE_FAILURES);
    }
}

fn take_export_state(ctx: &RetProbeContext, scoped: bool) -> Option<(StateKey, StartState)> {
    let key = export_state_key(ctx)?;
    let state = owned_discovery_get(&key, false).copied();
    let state_present = state.is_some();
    let removed = owned_discovery_remove(&key, state_present).is_ok();
    if discovery_state_take_failed(state_present, removed) {
        if scoped {
            bump_discovery_counter(DISCOVERY_COUNTER_EXPORT_STATE_FAILURES);
        }
        return None;
    }
    if discovery_state_take_scope_lost(state_present, removed, scoped) {
        bump_discovery_counter(DISCOVERY_COUNTER_EXPORT_STATE_FAILURES);
        return None;
    }
    state.map(|state| (key, state))
}

fn discard_export_state(key: &StateKey) {
    let _ = owned_discovery_remove(key, false);
}

fn fail_export_state(key: &StateKey) {
    let _ = owned_discovery_remove(key, true);
    bump_discovery_counter(DISCOVERY_COUNTER_EXPORT_STATE_FAILURES);
}

fn finish_export_state(key: &StateKey) {
    if owned_discovery_remove(key, true).is_err() {
        bump_discovery_counter(DISCOVERY_COUNTER_EXPORT_STATE_FAILURES);
    }
}

#[inline(always)]
fn selection_state_key<C: aya_ebpf::EbpfContext>(ctx: &C) -> Option<StateKey> {
    let attach_cookie = unsafe { helpers::bpf_get_attach_cookie(ctx.as_ptr()) };
    (attach_cookie != 0).then_some(StateKey {
        pid_tgid: helpers::bpf_get_current_pid_tgid(),
        attach_cookie,
        domain: STATE_DOMAIN_SELECTION,
    })
}

fn classify_selection_name(pointer: u64) -> u8 {
    if pointer == 0 {
        return DISCOVERY_NAME_NULL;
    }
    let mut bytes = [0u8; 9];
    let read = unsafe {
        helpers::generated::bpf_probe_read_user_str(
            bytes.as_mut_ptr().cast(),
            bytes.len() as u32,
            pointer as *const core::ffi::c_void,
        )
    };
    if read < 0 {
        bump_discovery_counter(DISCOVERY_COUNTER_EXPORT_BOUNDED_READ_FAILURES);
        DISCOVERY_NAME_UNREADABLE
    } else if read == 8 && bytes[..8] == *b"PKCS 11\0" {
        DISCOVERY_NAME_EXACT_STANDARD
    } else {
        DISCOVERY_NAME_OTHER
    }
}

fn classify_selection_version(pointer: u64) -> u8 {
    if pointer == 0 {
        return DISCOVERY_VERSION_NULL;
    }
    match unsafe { helpers::bpf_probe_read_user(pointer as *const [u8; 2]) } {
        Ok([major, minor]) => discovery_version_class(major, minor),
        Err(_) => {
            bump_discovery_counter(DISCOVERY_COUNTER_EXPORT_BOUNDED_READ_FAILURES);
            DISCOVERY_VERSION_UNREADABLE
        }
    }
}

fn selection_request_word(name_class: u8, version_class: u8) -> u64 {
    u64::from(name_class) | (u64::from(version_class) << 8)
}

fn insert_selection_state(ctx: &ProbeContext, state: StartState) {
    let Some(key) = selection_state_key(ctx) else {
        return;
    };
    if owned_discovery_insert(&key, &state, aya_ebpf::bindings::BPF_NOEXIST as u64).is_err() {
        bump_discovery_counter(DISCOVERY_COUNTER_EXPORT_STATE_FAILURES);
    }
}

fn take_selection_state(ctx: &RetProbeContext, scoped: bool) -> Option<(StateKey, StartState)> {
    let key = selection_state_key(ctx)?;
    let state = owned_discovery_get(&key, false).copied();
    let state_present = state.is_some();
    let removed = owned_discovery_remove(&key, state_present).is_ok();
    if discovery_state_take_failed(state_present, removed) {
        if scoped {
            bump_discovery_counter(DISCOVERY_COUNTER_EXPORT_STATE_FAILURES);
        }
        return None;
    }
    if discovery_state_take_scope_lost(state_present, removed, scoped) {
        bump_discovery_counter(DISCOVERY_COUNTER_EXPORT_STATE_FAILURES);
        return None;
    }
    state.map(|state| (key, state))
}

#[uprobe]
pub fn function_list_entry(ctx: ProbeContext) -> u32 {
    if scope_auth().is_none() {
        return 0;
    }
    let Some(layout) = probe_layout(&ctx) else {
        if let Some(key) = export_state_key(&ctx) {
            discard_export_state(&key);
        }
        bump_evidence(EVIDENCE_ABI_REFUSALS);
        return 0;
    };
    let Ok(arg0) = arg_u64(&ctx, 0, layout) else {
        if let Some(key) = export_state_key(&ctx) {
            discard_export_state(&key);
        }
        bump_discovery_counter(DISCOVERY_COUNTER_EXPORT_BOUNDED_READ_FAILURES);
        return 0;
    };
    insert_export_state(
        &ctx,
        StartState {
            arg0,
            arg1: 0,
            arg2: 0,
        },
    );
    0
}

#[uretprobe]
pub fn function_list_return(ctx: RetProbeContext) -> u32 {
    let scope = scope_auth();
    if scope.is_none() {
        let _ = take_export_state(&ctx, false);
        return 0;
    }
    let Some(layout) = ret_probe_layout(&ctx) else {
        if let Some(key) = export_state_key(&ctx) {
            discard_export_state(&key);
        }
        bump_evidence(EVIDENCE_ABI_REFUSALS);
        return 0;
    };
    let Some((key, state)) = take_export_state(&ctx, scope.is_some()) else {
        return 0;
    };
    let Some(scope) = scope else {
        return 0;
    };
    let rv = normalize_target_word(ctx.ret(), layout);
    if rv == 0 {
        let Some(symbol_id) = export_symbol_id(key.attach_cookie) else {
            bump_discovery_counter(DISCOVERY_COUNTER_EXPORT_STATE_FAILURES);
            return 0;
        };
        classify_export(
            &ExportArgs {
                kind: DISCOVERY_KIND_FUNCTION_LIST_RETURN,
                interface_index: 0,
                symbol_id,
                announced_count: 0,
                address: state.arg0,
            },
            &scope,
            layout,
        );
    }
    0
}

#[uprobe]
pub fn interface_list_entry(ctx: ProbeContext) -> u32 {
    if scope_auth().is_none() {
        return 0;
    }
    let Some(layout) = probe_layout(&ctx) else {
        if let Some(key) = export_state_key(&ctx) {
            discard_export_state(&key);
        }
        bump_evidence(EVIDENCE_ABI_REFUSALS);
        return 0;
    };
    let (Ok(arg0), Ok(arg1)) = (arg_u64(&ctx, 0, layout), arg_u64(&ctx, 1, layout)) else {
        if let Some(key) = export_state_key(&ctx) {
            discard_export_state(&key);
        }
        bump_discovery_counter(DISCOVERY_COUNTER_EXPORT_BOUNDED_READ_FAILURES);
        return 0;
    };
    insert_export_state(
        &ctx,
        StartState {
            arg0,
            arg1,
            arg2: 0,
        },
    );
    0
}

#[uretprobe]
pub fn interface_list_return(ctx: RetProbeContext) -> u32 {
    let scope = scope_auth();
    if scope.is_none() {
        let _ = take_export_state(&ctx, false);
        return 0;
    }
    let Some(layout) = ret_probe_layout(&ctx) else {
        if let Some(key) = export_state_key(&ctx) {
            discard_export_state(&key);
        }
        bump_evidence(EVIDENCE_ABI_REFUSALS);
        return 0;
    };
    let Some((entry_key, state)) = take_export_state(&ctx, scope.is_some()) else {
        return 0;
    };
    let Some(_scope) = scope else {
        return 0;
    };
    let rv = normalize_target_word(ctx.ret(), layout);
    if rv != 0 {
        return 0;
    }
    let Ok(count) = read_word(state.arg1, layout) else {
        bump_discovery_counter(DISCOVERY_COUNTER_EXPORT_BOUNDED_READ_FAILURES);
        return 0;
    };
    let active_count = count.min(u64::from(DISCOVERY_INTERFACES));
    if active_count == 0 {
        return 0;
    }
    if state.arg0 == 0 {
        return 0;
    }
    if state
        .arg0
        .checked_add((active_count - 1) * layout.interface().stride as u64)
        .and_then(|address| {
            address.checked_add(layout.interface().stride as u64 - layout.word_bytes() as u64)
        })
        .and_then(|address| target_word_end(address, layout))
        .is_none()
    {
        bump_discovery_counter(DISCOVERY_COUNTER_EXPORT_BOUNDED_READ_FAILURES);
        return 0;
    }
    let Some(symbol_id) = export_symbol_id(entry_key.attach_cookie) else {
        bump_discovery_counter(DISCOVERY_COUNTER_EXPORT_STATE_FAILURES);
        return 0;
    };
    let Some(packed) = interface_continuation_pack(count, 0, symbol_id) else {
        bump_discovery_counter(DISCOVERY_COUNTER_EXPORT_STATE_FAILURES);
        return 0;
    };
    let key = StateKey {
        pid_tgid: entry_key.pid_tgid,
        attach_cookie: 0,
        domain: STATE_DOMAIN_EXPORT,
    };
    let continuation = StartState {
        arg0: state.arg0,
        arg1: packed,
        arg2: 0,
    };
    if owned_discovery_insert(&key, &continuation, aya_ebpf::bindings::BPF_NOEXIST as u64).is_err()
    {
        bump_discovery_counter(DISCOVERY_COUNTER_EXPORT_STATE_FAILURES);
        return 0;
    }
    unsafe { TAIL_CALLS.tail_call(&ctx, TAIL_CALLS_INTERFACE_WORKER_SLOT) };
    fail_export_state(&key);
    0
}

#[uretprobe]
pub fn interface_list_worker(ctx: RetProbeContext) -> u32 {
    let key = StateKey {
        pid_tgid: helpers::bpf_get_current_pid_tgid(),
        attach_cookie: 0,
        domain: STATE_DOMAIN_EXPORT,
    };
    let Some(scope) = scope_auth() else {
        let _ = owned_discovery_remove(&key, true);
        return 0;
    };
    let Some(layout) = ret_probe_layout(&ctx) else {
        let _ = owned_discovery_remove(&key, true);
        bump_evidence(EVIDENCE_ABI_REFUSALS);
        return 0;
    };
    let Some(state) = (owned_discovery_get(&key, true)).copied() else {
        fail_export_state(&key);
        return 0;
    };
    if state.arg0 == 0 {
        fail_export_state(&key);
        return 0;
    }
    let Some((announced_count, interface_index, symbol_id)) =
        interface_continuation_unpack(state.arg1)
    else {
        fail_export_state(&key);
        return 0;
    };
    let active_count = u64::from(if announced_count < DISCOVERY_INTERFACES as u32 {
        announced_count
    } else {
        DISCOVERY_INTERFACES as u32
    });
    if active_count == 0 {
        fail_export_state(&key);
        return 0;
    }
    let Some(last_offset) = active_count
        .checked_sub(1)
        .and_then(|index| index.checked_mul(layout.interface().stride as u64))
    else {
        fail_export_state(&key);
        return 0;
    };
    if state
        .arg0
        .checked_add(last_offset)
        .and_then(|address| {
            address.checked_add(layout.interface().stride as u64 - layout.word_bytes() as u64)
        })
        .and_then(|address| target_word_end(address, layout))
        .is_none()
    {
        fail_export_state(&key);
        return 0;
    }
    let Some(interface_offset) =
        u64::from(interface_index).checked_mul(layout.interface().stride as u64)
    else {
        fail_export_state(&key);
        return 0;
    };
    let Some(address) = state.arg0.checked_add(interface_offset) else {
        fail_export_state(&key);
        return 0;
    };
    classify_direct_interface(
        DISCOVERY_KIND_INTERFACE_LIST_ELEMENT_RETURN as u64
            | (u64::from(interface_index) << 8)
            | (u64::from(symbol_id) << 32),
        announced_count,
        address,
        &scope,
        &no_selection(layout),
    );

    let Some(next) = interface_continuation_next(state.arg1) else {
        finish_export_state(&key);
        return 0;
    };
    let continuation = StartState {
        arg0: state.arg0,
        arg1: next,
        arg2: 0,
    };
    if owned_discovery_insert(&key, &continuation, aya_ebpf::bindings::BPF_EXIST as u64).is_err() {
        fail_export_state(&key);
        return 0;
    }
    unsafe { TAIL_CALLS.tail_call(&ctx, TAIL_CALLS_INTERFACE_WORKER_SLOT) };
    fail_export_state(&key);
    0
}

#[uprobe]
pub fn interface_entry(ctx: ProbeContext) -> u32 {
    let Some(scope) = scope_auth() else {
        return 0;
    };
    let Some(layout) = probe_layout(&ctx) else {
        if let Some(key) = selection_state_key(&ctx) {
            discard_export_state(&key);
        }
        bump_evidence(EVIDENCE_ABI_REFUSALS);
        return 0;
    };
    if scope.flags & FLAG_POLICY_AGGREGATE != 0 {
        return 0;
    }
    let (Ok(name), Ok(version), Ok(pp_interface), Ok(flags)) = (
        arg_u64(&ctx, 0, layout),
        arg_u64(&ctx, 1, layout),
        arg_u64(&ctx, 2, layout),
        arg_u64(&ctx, 3, layout),
    ) else {
        if let Some(key) = selection_state_key(&ctx) {
            discard_export_state(&key);
        }
        bump_discovery_counter(DISCOVERY_COUNTER_EXPORT_BOUNDED_READ_FAILURES);
        return 0;
    };
    let request_name_class = classify_selection_name(name);
    let request_version_class = classify_selection_version(version);
    insert_selection_state(
        &ctx,
        StartState {
            arg0: pp_interface,
            arg1: selection_request_word(request_name_class, request_version_class),
            arg2: flags,
        },
    );
    0
}

#[uretprobe]
pub fn interface_return(ctx: RetProbeContext) -> u32 {
    let scope = scope_auth();
    if scope.is_none() {
        let _ = take_selection_state(&ctx, false);
        return 0;
    }
    let Some(layout) = ret_probe_layout(&ctx) else {
        if let Some(key) = selection_state_key(&ctx) {
            discard_export_state(&key);
        }
        bump_evidence(EVIDENCE_ABI_REFUSALS);
        return 0;
    };
    if scope
        .as_ref()
        .is_some_and(|scope| scope.flags & FLAG_POLICY_AGGREGATE != 0)
    {
        return 0;
    }
    let Some((key, state)) = take_selection_state(&ctx, scope.is_some()) else {
        return 0;
    };
    let Some(scope) = scope else {
        return 0;
    };
    let rv = normalize_target_word(ctx.ret(), layout);
    let selection = SelectionTransport {
        _pad: [0; 4],
        request_name_class: state.arg1 as u8,
        request_version_class: (state.arg1 >> 8) as u8,
        request_flags: state.arg2,
        binding_id: key.attach_cookie,
        return_rv: rv,
        pause_eligible: rv == 0,
        word_bytes: layout.word_bytes() as u8,
    };
    if rv != 0 {
        emit_export(
            &ExportPayload {
                record_meta: DISCOVERY_KIND_INTERFACE_RETURN as u64,
                announced_count: 0,
                table_ptr: 0,
                interface_flags: 0,
                selection,
            },
            &scope,
        );
    } else {
        classify_indirect_interface(
            DISCOVERY_KIND_INTERFACE_RETURN as u64,
            0,
            state.arg0,
            &scope,
            &selection,
        );
    }
    0
}

fn loader_cookie_of(ctx: &ProbeContext) -> u64 {
    unsafe { helpers::bpf_get_attach_cookie(ctx.as_ptr()) }
}

fn loader_runtime_ip(ctx: &ProbeContext) -> u64 {
    let helper_ip = unsafe { helpers::bpf_get_func_ip(ctx.as_ptr()) };
    if helper_ip != 0 {
        helper_ip
    } else {
        // Linux x86-64 uprobe pt_regs contains the adjusted runtime IP.
        unsafe { (*ctx.regs).rip as u64 }
    }
}

#[uprobe]
pub fn dl_debug_state(ctx: ProbeContext) -> u32 {
    let Some(scope) = scope_auth() else {
        return 0;
    };
    let Some(layout) = probe_layout(&ctx) else {
        bump_evidence(EVIDENCE_ABI_REFUSALS);
        return 0;
    };
    bump_discovery_counter(DISCOVERY_COUNTER_LOADER_HITS);
    let Some(mut entry) = reserve_discovery() else {
        return 0;
    };
    let raw = entry.as_mut_ptr();
    let pid_tgid = helpers::bpf_get_current_pid_tgid();
    let cookie = loader_cookie_of(&ctx);
    let state_present = cookie & LOADER_STATE_PRESENT != 0;
    if !valid_loader_cookie(cookie) {
        // SAFETY: invalid-cookie records stay zero outside these finite fields.
        unsafe {
            core::ptr::write_volatile(core::ptr::addr_of_mut!((*raw).kind), DISCOVERY_KIND_LOADER);
        }
        finish_discovery_record(
            entry,
            scope,
            false,
            pid_tgid,
            DISCOVERY_STATUS_LOADER_CONTEXT_INVALID,
        );
        return 0;
    }

    let hook_ip = normalize_target_word(loader_runtime_ip(&ctx), layout);
    if hook_ip == 0 {
        bump_discovery_counter(DISCOVERY_COUNTER_LOADER_STATE_READ_FAILURES);
        entry.discard(0);
        return 0;
    }
    let mut r_state = 0u32;
    if state_present {
        let delta = (cookie as i64) >> 9;
        let r_state_address = if delta >= 0 {
            hook_ip.checked_add(delta as u64)
        } else {
            hook_ip.checked_sub(delta.unsigned_abs())
        };
        match r_state_address.filter(|address| {
            layout == LinuxLayout::Lp64
                || address
                    .checked_add(core::mem::size_of::<u32>() as u64 - 1)
                    .is_some_and(|end| end <= u32::MAX as u64)
        }) {
            Some(address) => match unsafe { helpers::bpf_probe_read_user(address as *const u32) } {
                Ok(value) => r_state = value,
                Err(_) => bump_discovery_counter(DISCOVERY_COUNTER_LOADER_STATE_READ_FAILURES),
            },
            None => bump_discovery_counter(DISCOVERY_COUNTER_LOADER_STATE_READ_FAILURES),
        }
    }
    // SAFETY: the shared initializer completed before every field write.
    unsafe {
        core::ptr::write_volatile(core::ptr::addr_of_mut!((*raw).table_ptr), hook_ip);
        core::ptr::write_volatile(core::ptr::addr_of_mut!((*raw).kind), DISCOVERY_KIND_LOADER);
        core::ptr::write_volatile(
            core::ptr::addr_of_mut!((*raw).case_id),
            (cookie & 0xff) as u8,
        );
        core::ptr::write_volatile(core::ptr::addr_of_mut!((*raw).announced_count), r_state);
    }
    finish_discovery_record(entry, scope, true, pid_tgid, 0);
    0
}

#[inline(never)]
fn emit_lifecycle(kind: u8, scope: ScopeAuth, pause_eligible: bool) {
    let Some(mut entry) = reserve_discovery() else {
        return;
    };
    let raw = entry.as_mut_ptr();
    // SAFETY: the shared initializer completed before every field write.
    unsafe {
        core::ptr::write_volatile(core::ptr::addr_of_mut!((*raw).kind), kind);
    }
    let pid_tgid = helpers::bpf_get_current_pid_tgid();
    finish_discovery_record(entry, scope, pause_eligible, pid_tgid, 0);
}

#[raw_tracepoint(tracepoint = "sched_process_exec")]
pub fn sched_process_exec(_ctx: RawTracePointContext) -> u32 {
    // Mandatory current-physical-task cleanup precedes all capture filters.
    unsafe { p11_owner_cleanup() };
    if let Some(scope) = scope_auth() {
        emit_lifecycle(DISCOVERY_KIND_EXEC, scope, true);
    }
    0
}

#[raw_tracepoint(tracepoint = "sched_process_exit")]
pub fn sched_process_exit(_ctx: RawTracePointContext) -> u32 {
    // Retained original keys also cover fatal nonleader post-de_thread exit.
    unsafe { p11_owner_cleanup() };
    unsafe { p11_root_current_exit() };
    let pid_tgid = helpers::bpf_get_current_pid_tgid();
    if pid_tgid as u32 != (pid_tgid >> 32) as u32 {
        return 0;
    }
    if let Some(scope) = scope_auth() {
        emit_lifecycle(DISCOVERY_KIND_LEADER_EXIT, scope, false);
    }
    0
}

fn cookie_of<C>(ctx: &C) -> u64
where
    C: aya_ebpf::EbpfContext,
{
    unsafe { helpers::bpf_get_attach_cookie(ctx.as_ptr()) }
}

fn slot_of<C>(ctx: &C) -> u32
where
    C: aya_ebpf::EbpfContext,
{
    cookie_slot(cookie_of(ctx))
}

fn semantics_of<C>(ctx: &C) -> SlotSemantics
where
    C: aya_ebpf::EbpfContext,
{
    DESCRIPTORS
        .get(cookie_descriptor(cookie_of(ctx)))
        .copied()
        .unwrap_or(SlotSemantics::COUNT_ONLY)
}

/// Decode allowlisted `CK_MECHANISM` parameters for `shape` at `pmech`,
/// writing the result into `output.p0/p1/p2`. Anything unexpected —
/// an `ulParameterLen` that matches no known layout, null `pParameter`, or
/// any failed read — leaves `p0/p1/p2` untouched (they are already zeroed by
/// the caller): partial decodes are never emitted, and an unrecognized length
/// is never guessed at. The return value is the decoded shape, `shape::NONE`
/// when no exact supported parameter layout applies, or
/// `PARAMS_DECODE_FAILURE` when a required read or boundary check fails.
///
/// PKCS#11 has two incompatible `CK_GCM_PARAMS` layouts in the wild: the
/// legacy v2.20 one (five target words) and the current v2.40/OASIS one (six
/// target words, which inserts `ulIvBits`). Reusing the legacy offsets against
/// a modern struct — as this function
/// used to, guarding only `ulParameterLen >= 40` — reads `CK_GCM_PARAMS.pAAD`
/// (a userspace pointer) into what the caller believes is `ulAADLen`. The
/// match below is deliberately an *exact* length match per layout, never
/// `>=`: a length that fits neither known layout means the field offsets
/// are unknown, and guessing is exactly what caused that disclosure.
///
/// Reads exactly two `CK_MECHANISM` fields (`ulParameterLen` at word 2,
/// `pParameter` at word 1) plus three shape-specific target-width scalars at
/// fixed offsets from `pParameter`. For GCM, `pIv`/`pAAD` — pointers, at
/// offset 0 always and offset 16 or 24 depending on layout — are never
/// read; only the three length/count scalars are.
#[cfg(feature = "unsafe-unvalidated-metadata")]
#[repr(C)]
struct ParamsOutput {
    p0: u64,
    p1: u64,
    p2: u64,
}

#[cfg(feature = "unsafe-unvalidated-metadata")]
const PARAMS_DECODE_FAILURE: u32 = u32::MAX;

#[cfg(feature = "unsafe-unvalidated-metadata")]
const _: [(); 24] = [(); core::mem::size_of::<ParamsOutput>()];
#[cfg(feature = "unsafe-unvalidated-metadata")]
const _: () = assert!(core::mem::align_of::<ParamsOutput>() == core::mem::align_of::<u64>());
#[cfg(feature = "unsafe-unvalidated-metadata")]
const _: () = assert!(core::mem::offset_of!(ParamsOutput, p0) == 0);
#[cfg(feature = "unsafe-unvalidated-metadata")]
const _: () = assert!(core::mem::offset_of!(ParamsOutput, p1) == 8);
#[cfg(feature = "unsafe-unvalidated-metadata")]
const _: () = assert!(core::mem::offset_of!(ParamsOutput, p2) == 16);
#[cfg(feature = "unsafe-unvalidated-metadata")]
const _: () =
    assert!(core::mem::offset_of!(CallStart, p1) == core::mem::offset_of!(CallStart, p0) + 8);
#[cfg(feature = "unsafe-unvalidated-metadata")]
const _: () =
    assert!(core::mem::offset_of!(CallStart, p2) == core::mem::offset_of!(CallStart, p0) + 16);

#[cfg(feature = "unsafe-unvalidated-metadata")]
#[unsafe(no_mangle)]
#[inline(never)]
#[allow(private_interfaces)]
pub unsafe extern "C" fn p11_decode_params(
    pmech: u64,
    sh: u32,
    word_bytes: u32,
    output: *mut ParamsOutput,
) -> u32 {
    if output.is_null() {
        return PARAMS_DECODE_FAILURE;
    }
    let is_ilp32 = match word_bytes {
        4 => true,
        8 => false,
        _ => return PARAMS_DECODE_FAILURE,
    };
    // SAFETY: null was rejected above; the caller owns this contiguous
    // three-word output region for the duration of the global function call.
    let output = unsafe { &mut *output };
    if is_ilp32 {
        decode_params_impl::<true>(pmech, sh, output)
    } else {
        decode_params_impl::<false>(pmech, sh, output)
    }
}

#[cfg(feature = "unsafe-unvalidated-metadata")]
#[inline(never)]
fn decode_params_impl<const IS_ILP32: bool>(pmech: u64, sh: u32, output: &mut ParamsOutput) -> u32 {
    let layout = if IS_ILP32 {
        LinuxLayout::Ilp32
    } else {
        LinuxLayout::Lp64
    };
    let width = layout.word_bytes() as u64;
    // CK_MECHANISM.ulParameterLen is the third target word. Read
    // first: which offsets (if any) apply depends on it.
    let Some(param_len_addr) = pmech.checked_add(width * 2) else {
        return PARAMS_DECODE_FAILURE;
    };
    let Ok(param_len) = read_word(param_len_addr, layout) else {
        return PARAMS_DECODE_FAILURE;
    };
    let (o0, o1, o2, out_shape) = match (sh, param_len) {
        // CK_RSA_PKCS_PSS_PARAMS { hashAlg, mgf, sLen }.
        (shape::RSA_PKCS_PSS, len) if len == width * 3 => {
            (0, width, width * 2, shape::RSA_PKCS_PSS)
        }
        // CK_GCM_PARAMS, legacy v2.20 layout (20/40 bytes):
        // { pIv, ulIvLen, pAAD, ulAADLen, ulTagBits }.
        (shape::GCM, len) if len == width * 5 => (width, width * 3, width * 4, shape::GCM_V220),
        // CK_GCM_PARAMS, v2.40/OASIS layout (24/48 bytes):
        // { pIv, ulIvLen, ulIvBits, pAAD, ulAADLen, ulTagBits }.
        (shape::GCM, len) if len == width * 6 => (width, width * 4, width * 5, shape::GCM_V240),
        _ => return shape::NONE,
    };
    // CK_MECHANISM.pParameter is the second target word.
    let Some(pparam_addr) = pmech.checked_add(width) else {
        return PARAMS_DECODE_FAILURE;
    };
    let Ok(pparam) = read_word(pparam_addr, layout) else {
        return PARAMS_DECODE_FAILURE;
    };
    if pparam == 0 {
        return shape::NONE;
    }
    let (Some(a0), Some(a1), Some(a2)) = (
        pparam.checked_add(o0),
        pparam.checked_add(o1),
        pparam.checked_add(o2),
    ) else {
        return PARAMS_DECODE_FAILURE;
    };
    let r0 = read_word(a0, layout);
    let r1 = read_word(a1, layout);
    let r2 = read_word(a2, layout);
    if let (Ok(a), Ok(b), Ok(c)) = (r0, r1, r2) {
        output.p0 = a;
        output.p1 = b;
        output.p2 = c;
        out_shape
    } else {
        PARAMS_DECODE_FAILURE
    }
}

#[cfg(feature = "unsafe-unvalidated-metadata")]
#[repr(C)]
struct TemplateOutput {
    types: [u64; MAX_ATTRS],
    count: u32,
    total: u32,
    bools: u32,
    seen: u32,
}

#[cfg(feature = "unsafe-unvalidated-metadata")]
const TEMPLATE_WALK_FAILURE: u32 = 1;

#[cfg(feature = "unsafe-unvalidated-metadata")]
const _: () = assert!(core::mem::size_of::<TemplateOutput>() == 80);
#[cfg(feature = "unsafe-unvalidated-metadata")]
const _: () = assert!(core::mem::align_of::<TemplateOutput>() == core::mem::align_of::<u64>());
#[cfg(feature = "unsafe-unvalidated-metadata")]
const _: () = assert!(core::mem::offset_of!(TemplateOutput, types) == 0);
#[cfg(feature = "unsafe-unvalidated-metadata")]
const _: () = assert!(core::mem::offset_of!(TemplateOutput, count) == 64);
#[cfg(feature = "unsafe-unvalidated-metadata")]
const _: () = assert!(core::mem::offset_of!(TemplateOutput, total) == 68);
#[cfg(feature = "unsafe-unvalidated-metadata")]
const _: () = assert!(core::mem::offset_of!(TemplateOutput, bools) == 72);
#[cfg(feature = "unsafe-unvalidated-metadata")]
const _: () = assert!(core::mem::offset_of!(TemplateOutput, seen) == 76);
#[cfg(feature = "unsafe-unvalidated-metadata")]
const _: () = assert!(core::mem::offset_of!(CallStart, attr_types) == 96);
#[cfg(feature = "unsafe-unvalidated-metadata")]
const _: () = assert!(core::mem::offset_of!(CallStart, attr_count) == 160);
#[cfg(feature = "unsafe-unvalidated-metadata")]
const _: () = assert!(core::mem::offset_of!(CallStart, attr_total) == 164);
#[cfg(feature = "unsafe-unvalidated-metadata")]
const _: () = assert!(core::mem::offset_of!(CallStart, attr_bools) == 168);
#[cfg(feature = "unsafe-unvalidated-metadata")]
const _: () = assert!(core::mem::offset_of!(CallStart, attr_bools_seen) == 172);
#[cfg(feature = "unsafe-unvalidated-metadata")]
const _: () = assert!(core::mem::offset_of!(CallStart, attr_types1) == 176);
#[cfg(feature = "unsafe-unvalidated-metadata")]
const _: () = assert!(core::mem::offset_of!(CallStart, attr_count1) == 240);
#[cfg(feature = "unsafe-unvalidated-metadata")]
const _: () = assert!(core::mem::offset_of!(CallStart, attr_total1) == 244);
#[cfg(feature = "unsafe-unvalidated-metadata")]
const _: () = assert!(core::mem::offset_of!(CallStart, attr_bools1) == 248);
#[cfg(feature = "unsafe-unvalidated-metadata")]
const _: () = assert!(core::mem::offset_of!(CallStart, attr_bools_seen1) == 252);
#[cfg(feature = "unsafe-unvalidated-metadata")]
const _: () = assert!(core::mem::offset_of!(CallStart, capture) == 256);

#[cfg(feature = "unsafe-unvalidated-metadata")]
#[unsafe(no_mangle)]
#[inline(never)]
#[allow(private_interfaces)]
pub unsafe extern "C" fn p11_walk_template(
    ptemplate: u64,
    count: u64,
    word_bytes: u32,
    output: *mut TemplateOutput,
) -> u32 {
    if output.is_null() {
        return TEMPLATE_WALK_FAILURE;
    }
    let is_ilp32 = match word_bytes {
        4 => true,
        8 => false,
        _ => return TEMPLATE_WALK_FAILURE,
    };
    // SAFETY: null was rejected above. The caller owns exactly one contiguous
    // template-output region for the duration of this global call.
    let output = unsafe { &mut *output };
    if is_ilp32 {
        walk_template_impl::<true>(ptemplate, count, output)
    } else {
        walk_template_impl::<false>(ptemplate, count, output)
    }
}

/// Walk at most `MAX_ATTRS` entries of `pTemplate`, recording each entry's
/// *type* only into `output.types` — `pValue` is never read except for
/// the policy-boolean allowlist under the `ulValueLen == 1` gate below.
/// `output.total` is always set from `count`, so a template longer than the
/// cap (or one abandoned early by a read failure) stays visible as
/// truncation evidence rather than being silently trimmed.
///
/// The loop bound is the constant `MAX_ATTRS`, not `count`, so the
/// verifier can prove termination; the `i >= count` check inside just
/// stops early for shorter templates. Any read failure for an entry —
/// including a bad `pTemplate` itself — stops the walk immediately;
/// entries already captured are kept, nothing is skipped ahead or guessed.
#[cfg(feature = "unsafe-unvalidated-metadata")]
#[inline(always)]
fn walk_template<const TYPES_ONLY: bool, const SECOND: bool>(
    ptemplate: u64,
    count: u64,
    layout: LinuxLayout,
    start: &mut CallStart,
) {
    const {
        assert!(!TYPES_ONLY || !SECOND);
    }
    if TYPES_ONLY {
        match layout {
            LinuxLayout::Ilp32 => walk_template_types::<true>(ptemplate, count, start),
            LinuxLayout::Lp64 => walk_template_types::<false>(ptemplate, count, start),
        }
        return;
    }
    let offset = if SECOND {
        core::mem::offset_of!(CallStart, attr_types1)
    } else {
        core::mem::offset_of!(CallStart, attr_types)
    };
    let output = unsafe {
        (start as *mut CallStart)
            .cast::<u8>()
            .add(offset)
            .cast::<TemplateOutput>()
    };
    let status = unsafe { p11_walk_template(ptemplate, count, layout.word_bytes() as u32, output) };
    if status != 0 {
        capture_failure(start);
    }
}

#[cfg(feature = "unsafe-unvalidated-metadata")]
#[inline(never)]
fn walk_template_types<const IS_ILP32: bool>(ptemplate: u64, count: u64, start: &mut CallStart) {
    let layout = if IS_ILP32 {
        LinuxLayout::Ilp32
    } else {
        LinuxLayout::Lp64
    };
    let total = count.min(u32::MAX as u64) as u32;
    start.attr_total = total;
    for i in 0..MAX_ATTRS {
        if (i as u64) >= count {
            break;
        }
        let width = layout.word_bytes() as u64;
        let Some(base) = ptemplate.checked_add((i as u64) * width * 3) else {
            capture_failure(start);
            break;
        };
        let Ok(attr_type) = read_word(base, layout) else {
            capture_failure(start);
            break;
        };
        start.attr_types[i] = attr_type;
        start.attr_count += 1;
    }
}

#[cfg(feature = "unsafe-unvalidated-metadata")]
#[inline(never)]
fn walk_template_impl<const IS_ILP32: bool>(
    ptemplate: u64,
    count: u64,
    output: &mut TemplateOutput,
) -> u32 {
    let layout = if IS_ILP32 {
        LinuxLayout::Ilp32
    } else {
        LinuxLayout::Lp64
    };
    let total = count.min(u32::MAX as u64) as u32;
    output.total = total;
    for i in 0..MAX_ATTRS {
        if (i as u64) >= count {
            break;
        }
        // CK_ATTRIBUTE { CK_ATTRIBUTE_TYPE type; CK_VOID_PTR pValue;
        // CK_ULONG ulValueLen; } — three target words. `type` is read first and is
        // the only field ever read for a non-allowlisted attribute.
        let width = layout.word_bytes() as u64;
        let Some(base) = ptemplate.checked_add((i as u64) * width * 3) else {
            return TEMPLATE_WALK_FAILURE;
        };
        let Ok(t) = read_word(base, layout) else {
            return TEMPLATE_WALK_FAILURE;
        };
        let attr_type = t;
        output.types[i] = attr_type;
        output.count += 1;

        // Policy-boolean allowlist only: read ulValueLen (word 2) next,
        // and only when it is exactly 1 read the single CK_BBOOL byte at
        // pValue (word 1). This length gate is load-bearing: it is what
        // keeps a CKA_VALUE or CKA_LABEL from ever being read even if a
        // type were mis-listed on the allowlist. Type checked first, then
        // length, then the single byte — in that order, always.
        // CK_ATTRIBUTE_TYPE is full-width on LP64 and remains so in the
        // event. Only standard low-width values can enter the boolean
        // allowlist; a vendor type with matching low bits must not alias it.
        if attr_type > u32::MAX as u64 {
            continue;
        }
        let bool_type = attr_type as u32;
        let Some(mask) = (unsafe { ATTR_BOOL_BITS.get(&bool_type) }).copied() else {
            continue;
        };
        // Read the two remaining CK_ATTRIBUTE fields together only after
        // the type allowlist matched. This preserves the privacy order while
        // keeping the verifier from exploring two independent read failures.
        let Some(value_addr) = base.checked_add(width) else {
            return TEMPLATE_WALK_FAILURE;
        };
        let Ok([pvalue, len]) = read_word_pair(value_addr, layout) else {
            return TEMPLATE_WALK_FAILURE;
        };
        if len != 1 {
            continue;
        }
        let Ok(b) = (unsafe { helpers::bpf_probe_read_user(pvalue as *const u8) }) else {
            return TEMPLATE_WALK_FAILURE;
        };
        output.seen |= mask;
        if b != 0 {
            output.bools |= mask;
        }
    }
    0
}

fn arg_u64(ctx: &ProbeContext, index: u8, layout: LinuxLayout) -> Result<u64, ()> {
    if layout == LinuxLayout::Ilp32 {
        let rsp = unsafe { (*ctx.regs).rsp as u64 };
        let value = p11_read_ia32_arg(rsp, index as u32);
        return (value <= u32::MAX as u64).then_some(value).ok_or(());
    }
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
            let address = target_stack_arg_address(rsp, index, layout).ok_or(())?;
            read_word(address, layout)
        }
        _ => Err(()),
    }
}

const IA32_ARG_READ_FAILURE: u64 = 1u64 << 32;

#[unsafe(no_mangle)]
#[inline(never)]
pub extern "C" fn p11_read_ia32_arg(stack_pointer: u64, index: u32) -> u64 {
    if index > 6 {
        return IA32_ARG_READ_FAILURE;
    }
    let stack_pointer = stack_pointer & u32::MAX as u64;
    let offset = (u64::from(index) + 1) * 4;
    let Some(address) = stack_pointer.checked_add(offset) else {
        return IA32_ARG_READ_FAILURE;
    };
    let Some(end) = address.checked_add(3) else {
        return IA32_ARG_READ_FAILURE;
    };
    if end > u32::MAX as u64 {
        return IA32_ARG_READ_FAILURE;
    }
    match unsafe { helpers::bpf_probe_read_user(address as *const u32) } {
        Ok(value) => u64::from(value),
        Err(_) => IA32_ARG_READ_FAILURE,
    }
}

fn capture_failure(start: &mut CallStart) {
    start.capture |= capture::ARG_READ_FAILURE;
    bump_evidence(EVIDENCE_SEMANTIC_CAPTURE_FAILURES);
}

fn capture_scalar(
    ctx: &ProbeContext,
    index: u8,
    layout: LinuxLayout,
    start: &mut CallStart,
) -> Option<u64> {
    if index == ARG_NONE {
        return None;
    }
    match arg_u64(ctx, index, layout) {
        Ok(value) => Some(value),
        Err(()) => {
            capture_failure(start);
            None
        }
    }
}

const _: [(); 32] = [(); core::mem::size_of::<FunctionNameKey>()];
const _: () = assert!(core::mem::align_of::<FunctionNameKey>() >= 4);

#[inline(always)]
fn zero_function_name_key(key: &mut MaybeUninit<FunctionNameKey>) {
    let words = key.as_mut_ptr().cast::<u32>();
    unsafe {
        // ASYNC_KEY_INITIALIZER_BEGIN
        core::ptr::write_volatile(words.add(0), 0u32);
        core::ptr::write_volatile(words.add(1), 0u32);
        core::ptr::write_volatile(words.add(2), 0u32);
        core::ptr::write_volatile(words.add(3), 0u32);
        core::ptr::write_volatile(words.add(4), 0u32);
        core::ptr::write_volatile(words.add(5), 0u32);
        core::ptr::write_volatile(words.add(6), 0u32);
        core::ptr::write_volatile(words.add(7), 0u32);
        // ASYNC_KEY_INITIALIZER_END
    }
}

fn capture_async_target(ctx: &ProbeContext, index: u8, layout: LinuxLayout, start: &mut CallStart) {
    let Some(pointer) = capture_scalar(ctx, index, layout, start) else {
        return;
    };
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
    if read <= 0 || read > (FUNCTION_NAME_MAX_BYTES + 1) as _ {
        capture_failure(start);
        return;
    }
    let len = (read - 1) as usize;
    let name = name.as_ptr().cast::<u8>();
    let mut key_storage = MaybeUninit::<FunctionNameKey>::uninit();
    zero_function_name_key(&mut key_storage);
    // SAFETY: zero_function_name_key initialized every byte of the key.
    let key = unsafe { key_storage.assume_init_mut() };
    key.len = len as u32;
    // Keep every condition and address offset constant. Volatile accesses
    // prevent LLVM from recovering a variable-length memcpy, while each
    // source byte remains guarded by the helper-initialized `len`.
    macro_rules! copy_name_byte {
        ($offset:literal) => {
            if $offset < len {
                let byte = unsafe { core::ptr::read_volatile(name.add($offset)) };
                unsafe {
                    core::ptr::write_volatile(key.bytes.as_mut_ptr().add($offset), byte);
                }
            }
        };
    }
    copy_name_byte!(0);
    copy_name_byte!(1);
    copy_name_byte!(2);
    copy_name_byte!(3);
    copy_name_byte!(4);
    copy_name_byte!(5);
    copy_name_byte!(6);
    copy_name_byte!(7);
    copy_name_byte!(8);
    copy_name_byte!(9);
    copy_name_byte!(10);
    copy_name_byte!(11);
    copy_name_byte!(12);
    copy_name_byte!(13);
    copy_name_byte!(14);
    copy_name_byte!(15);
    copy_name_byte!(16);
    copy_name_byte!(17);
    copy_name_byte!(18);
    copy_name_byte!(19);
    copy_name_byte!(20);
    copy_name_byte!(21);
    copy_name_byte!(22);
    copy_name_byte!(23);
    copy_name_byte!(24);
    copy_name_byte!(25);
    copy_name_byte!(26);
    match unsafe { ASYNC_FUNCTIONS.get(key) }.copied() {
        Some(id) => start.target_function = id,
        None => capture_failure(start),
    }
}

const ENTRY_ABI_MIXED: u8 = 0;
const ENTRY_ABI_LP64: u8 = 1;
const ENTRY_ABI_ILP32: u8 = 2;

#[uprobe]
pub fn p11_entry(ctx: ProbeContext) -> u32 {
    #[cfg(not(feature = "unsafe-unvalidated-metadata"))]
    return p11_entry_impl::<0, ENTRY_ABI_MIXED>(ctx);
    #[cfg(feature = "unsafe-unvalidated-metadata")]
    return p11_entry_impl::<0, ENTRY_ABI_LP64>(ctx);
}

#[cfg(feature = "unsafe-unvalidated-metadata")]
#[uprobe]
pub fn p11_entry_ia32(ctx: ProbeContext) -> u32 {
    p11_entry_impl::<0, ENTRY_ABI_ILP32>(ctx)
}

#[cfg(feature = "unsafe-unvalidated-metadata")]
#[uprobe]
pub fn p11_entry_template(ctx: ProbeContext) -> u32 {
    p11_entry_impl::<1, ENTRY_ABI_MIXED>(ctx)
}

#[cfg(feature = "unsafe-unvalidated-metadata")]
#[uprobe]
pub fn p11_entry_template_types(ctx: ProbeContext) -> u32 {
    p11_entry_impl::<2, ENTRY_ABI_MIXED>(ctx)
}

#[cfg(feature = "unsafe-unvalidated-metadata")]
#[uprobe]
pub fn p11_entry_template_pair(ctx: ProbeContext) -> u32 {
    p11_entry_impl::<3, ENTRY_ABI_MIXED>(ctx)
}

#[cfg(feature = "unsafe-unvalidated-metadata")]
#[uprobe]
pub fn p11_entry_template_second(ctx: ProbeContext) -> u32 {
    let slot = slot_of(&ctx);
    let Some(flags) = scope_flags() else {
        return 0;
    };
    if slot >= MAX_SLOTS || flags & FLAG_POLICY_UNSAFE_UNVALIDATED_METADATA == 0 {
        return 0;
    }
    let key = StartKey {
        pid_tgid: helpers::bpf_get_current_pid_tgid(),
        slot,
        _pad: 0,
    };
    let Some(layout) = probe_layout(&ctx) else {
        let _ = owned_start_remove(&key, false);
        bump_evidence(EVIDENCE_ABI_REFUSALS);
        return 0;
    };
    let Some(start) = owned_start_mut(&key) else {
        bump_evidence(EVIDENCE_TEMPLATE_TAIL_FAILURES);
        return 0;
    };
    let semantics = semantics_of(&ctx);
    // SAFETY: START owns this per-thread/per-slot value until the return
    // probe removes it; the primary entry program has already inserted it.
    let start = unsafe { &mut *start };
    if let Some(template) = capture_scalar(&ctx, semantics.template1_arg, layout, start) {
        if let Some(count) = capture_scalar(&ctx, semantics.template_count1_arg, layout, start) {
            walk_template::<false, true>(template, count, layout, start);
        }
    }
    0
}

unsafe extern "C" {
    fn p11_root_current_tag() -> u64;
    fn p11_root_current_exit();
    fn p11_link_current_identity(out: *mut ImageIdentity) -> u32;
    fn p11_owner_healthy() -> u32;
    fn p11_owner_cleanup();
    fn p11_owner_start_get(key: *const StartKey, required: u32) -> *mut CallStart;
    fn p11_owner_start_insert(key: *const StartKey, value: *const CallStart) -> i64;
    fn p11_owner_start_remove(key: *const StartKey, required: u32) -> i64;
    fn p11_owner_discovery_get(key: *const StateKey, required: u32) -> *mut StartState;
    fn p11_owner_discovery_insert(
        key: *const StateKey,
        value: *const StartState,
        flags: u64,
    ) -> i64;
    fn p11_owner_discovery_remove(key: *const StateKey, required: u32) -> i64;
}

// All pairing map access is mediated by the native current-task owner. These
// thin wrappers retain the existing callers' success/failure behavior.
#[inline(always)]
fn owned_start_get(key: &StartKey) -> Option<&'static CallStart> {
    unsafe { p11_owner_start_get(key, 0).as_ref() }
}

#[cfg(feature = "unsafe-unvalidated-metadata")]
#[inline(always)]
fn owned_start_mut(key: &StartKey) -> Option<*mut CallStart> {
    let pointer = unsafe { p11_owner_start_get(key, 1) };
    (!pointer.is_null()).then_some(pointer)
}

#[inline(always)]
fn owned_start_remove(key: &StartKey, required: bool) -> Result<(), ()> {
    (unsafe { p11_owner_start_remove(key, u32::from(required)) } == 0)
        .then_some(())
        .ok_or(())
}

#[inline(always)]
fn owned_discovery_get(key: &StateKey, required: bool) -> Option<&'static StartState> {
    unsafe { p11_owner_discovery_get(key, u32::from(required)).as_ref() }
}

#[inline(always)]
fn owned_discovery_insert(key: &StateKey, state: &StartState, flags: u64) -> Result<(), ()> {
    (unsafe { p11_owner_discovery_insert(key, state, flags) } == 0)
        .then_some(())
        .ok_or(())
}

#[inline(always)]
fn owned_discovery_remove(key: &StateKey, required: bool) -> Result<(), ()> {
    (unsafe { p11_owner_discovery_remove(key, u32::from(required)) } == 0)
        .then_some(())
        .ok_or(())
}

#[inline(always)]
fn store_start(key: &StartKey, start: &CallStart) -> bool {
    if unsafe { p11_owner_start_insert(key, start) } == 0 {
        return true;
    }
    // Native NOEXIST handling invalidates the ambiguous invocation and settles
    // its count/index before reporting failure. Never delete by numeric key here.
    bump_evidence(EVIDENCE_START_INSERT_FAILURES);
    false
}

#[inline(always)]
fn record_aggregate_start(key: &StartKey) {
    let mut storage = MaybeUninit::<CallStart>::uninit();
    zero_call_start(&mut storage);
    // SAFETY: zero_call_start initialized every byte, including padding.
    let start = unsafe { storage.assume_init_mut() };
    start.ts_ns = unsafe { helpers::bpf_ktime_get_ns() };
    let _ = store_start(key, start);
}

#[inline(always)]
fn p11_entry_impl<const TEMPLATE_MODE: u8, const ENTRY_ABI: u8>(ctx: ProbeContext) -> u32 {
    let slot = slot_of(&ctx);
    if slot >= MAX_SLOTS {
        return 0;
    }
    let Some(flags) = scope_flags() else {
        return 0;
    };
    let key = StartKey {
        pid_tgid: helpers::bpf_get_current_pid_tgid(),
        slot,
        _pad: 0,
    };
    let Some(actual_layout) = probe_layout(&ctx) else {
        let _ = owned_start_remove(&key, false);
        bump_evidence(EVIDENCE_ABI_REFUSALS);
        return 0;
    };
    let layout = if ENTRY_ABI == ENTRY_ABI_LP64 {
        if !matches!(actual_layout, LinuxLayout::Lp64) {
            let _ = owned_start_remove(&key, false);
            bump_evidence(EVIDENCE_ABI_REFUSALS);
            return 0;
        }
        LinuxLayout::Lp64
    } else if ENTRY_ABI == ENTRY_ABI_ILP32 {
        if !matches!(actual_layout, LinuxLayout::Ilp32) {
            let _ = owned_start_remove(&key, false);
            bump_evidence(EVIDENCE_ABI_REFUSALS);
            return 0;
        }
        LinuxLayout::Ilp32
    } else {
        actual_layout
    };
    if let Some(stats) = STATS.get_ptr_mut(slot) {
        // SAFETY: PerCpuArray gives this CPU exclusive access to its own
        // copy; there is no cross-CPU aliasing to race with.
        unsafe { (*stats).entered += 1 };
    }
    if flags & FLAG_POLICY_AGGREGATE != 0 {
        record_aggregate_start(&key);
        return 0;
    }
    let semantics = semantics_of(&ctx);
    let mut storage = MaybeUninit::<CallStart>::uninit();
    zero_call_start(&mut storage);
    // SAFETY: zero_call_start initialized every byte, including padding.
    let start = unsafe { storage.assume_init_mut() };
    start.ts_ns = unsafe { helpers::bpf_ktime_get_ns() };
    // Write into caller-owned initialized storage: a second live identity
    // temporary would increase diagnostic entry call-chain stack usage.
    if unsafe { p11_link_current_identity(&mut start.image) } != 1 || start.image.task_cookie == 0 {
        let _ = owned_start_remove(&key, false);
        bump_evidence(EVIDENCE_SEMANTIC_CAPTURE_FAILURES);
        return 0;
    }
    start.session = SESSION_NONE;
    start.mechanism = MECH_NONE;
    start.user_type = USER_TYPE_NONE;
    start.shape = shape::NONE;
    start.capture = capture::MECHANISM_NONE | capture::OUTPUT_NONE;
    start.target_function = FUNCTION_NONE;

    if let Some(value) = capture_scalar(&ctx, semantics.session_arg, layout, start) {
        start.session = value;
    }
    if let Some(value) = capture_scalar(&ctx, semantics.slot_arg, layout, start) {
        start.slot_id = value;
    }
    if let Some(value) = capture_scalar(&ctx, semantics.flags_arg, layout, start) {
        start.flags = value;
        if semantics.lifecycle == lifecycle::OPEN_SESSION && value & 0x8 != 0 {
            start.capture |= capture::ASYNC_SESSION;
        }
    }
    if let Some(value) = capture_scalar(&ctx, semantics.user_type_arg, layout, start) {
        start.user_type = value as u32;
    }

    if semantics.mechanism_arg != ARG_NONE {
        match capture_scalar(&ctx, semantics.mechanism_arg, layout, start) {
            None => {
                start.capture =
                    (start.capture & !capture::MECHANISM_MASK) | capture::MECHANISM_UNREADABLE;
            }
            Some(0) => {
                start.capture =
                    (start.capture & !capture::MECHANISM_MASK) | capture::MECHANISM_NULL;
            }
            Some(pointer) => {
                start.mechanism_ptr = pointer;
                #[cfg(feature = "unsafe-unvalidated-metadata")]
                if flags & FLAG_POLICY_UNSAFE_UNVALIDATED_METADATA != 0 {
                    match read_word(pointer, layout) {
                        Ok(mechanism) => {
                            start.mechanism = mechanism;
                            start.capture = (start.capture & !capture::MECHANISM_MASK)
                                | capture::MECHANISM_VALUE;
                            let parameter_shape = unsafe { MECH_SHAPE.get(&mechanism) }
                                .copied()
                                .unwrap_or(shape::NONE);
                            if parameter_shape != shape::NONE {
                                // Project the narrow output from the whole
                                // CallStart pointer. No additional stack object
                                // is introduced, and the global helper's BTF
                                // contract covers only p0/p1/p2.
                                let output = unsafe {
                                    (start as *mut CallStart)
                                        .cast::<u8>()
                                        .add(core::mem::offset_of!(CallStart, p0))
                                        .cast::<ParamsOutput>()
                                };
                                let decoded_shape = unsafe {
                                    p11_decode_params(
                                        pointer,
                                        parameter_shape,
                                        layout.word_bytes() as u32,
                                        output,
                                    )
                                };
                                match decoded_shape {
                                    shape::RSA_PKCS_PSS | shape::GCM_V220 | shape::GCM_V240 => {
                                        start.shape = decoded_shape;
                                    }
                                    shape::NONE => {}
                                    _ => capture_failure(start),
                                }
                            }
                        }
                        Err(_) => {
                            start.capture = (start.capture & !capture::MECHANISM_MASK)
                                | capture::MECHANISM_UNREADABLE;
                            capture_failure(start);
                        }
                    }
                }
            }
        }
    }

    if semantics.output_arg != ARG_NONE {
        match capture_scalar(&ctx, semantics.output_arg, layout, start) {
            None => {
                start.capture =
                    (start.capture & !capture::OUTPUT_MASK) | capture::OUTPUT_UNREADABLE;
            }
            Some(pointer) => {
                start.capture = (start.capture & !capture::OUTPUT_MASK)
                    | if pointer == 0 {
                        capture::OUTPUT_NULL
                    } else {
                        capture::OUTPUT_NON_NULL
                    };
                if semantics.lifecycle == lifecycle::OPEN_SESSION {
                    start.out_ptr = pointer;
                }
            }
        }
    }

    #[cfg(feature = "unsafe-unvalidated-metadata")]
    if flags & FLAG_POLICY_UNSAFE_UNVALIDATED_METADATA != 0 && TEMPLATE_MODE != 0 {
        if semantics.template0_arg != ARG_NONE {
            // Keep the reads nested. Holding two Option payloads across the
            // second helper call makes LLVM spill an uninitialized `None`
            // payload, which the BPF verifier rejects even though Rust would
            // test both discriminants before use.
            if let Some(template) = capture_scalar(&ctx, semantics.template0_arg, layout, start) {
                if let Some(count) =
                    capture_scalar(&ctx, semantics.template_count0_arg, layout, start)
                {
                    if TEMPLATE_MODE == 2 {
                        walk_template::<true, false>(template, count, layout, start);
                    } else {
                        walk_template::<false, false>(template, count, layout, start);
                    }
                }
            }
        }
    }
    if TEMPLATE_MODE == 0 && semantics.async_name_arg != ARG_NONE {
        capture_async_target(&ctx, semantics.async_name_arg, layout, start);
        match semantics.lifecycle {
            lifecycle::ASYNC_JOIN => {
                if let Some(value) = capture_scalar(&ctx, semantics.async_value_arg, layout, start)
                {
                    start.async_value = value;
                }
            }
            lifecycle::ASYNC_GET_ID => {
                if let Some(pointer) =
                    capture_scalar(&ctx, semantics.async_value_arg, layout, start)
                {
                    start.out_ptr = pointer;
                }
            }
            _ => {}
        }
    }

    if !store_start(&key, start) {
        return 0;
    }
    #[cfg(feature = "unsafe-unvalidated-metadata")]
    if TEMPLATE_MODE == 3 {
        // Success never returns. Failure leaves template0 as usable partial
        // evidence and is independently disclosed below.
        unsafe { TAIL_CALLS.tail_call(&ctx, TAIL_CALLS_TEMPLATE_SECOND_SLOT) };
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
    let key = StartKey {
        pid_tgid: helpers::bpf_get_current_pid_tgid(),
        slot,
        _pad: 0,
    };
    let Some(flags) = scope_flags() else {
        // Entry-time scope owns this pairing record. If a task migrates out
        // of a selected cgroup mid-call, clean it up without emitting an
        // out-of-scope event and disclose the lost completion.
        if owned_start_remove(&key, false).is_ok() {
            bump_evidence(EVIDENCE_UNMATCHED_RETURNS);
        }
        return 0;
    };
    let Some(layout) = ret_probe_layout(&ctx) else {
        let _ = owned_start_remove(&key, false);
        bump_evidence(EVIDENCE_ABI_REFUSALS);
        return 0;
    };
    // No start entry means the entry probe filtered this call out (or the
    // process was already inside the function at attach time). Either way
    // there is nothing to attribute.
    let Some(&start) = owned_start_get(&key) else {
        return 0;
    };
    if owned_start_remove(&key, true).is_err() {
        bump_evidence(EVIDENCE_UNMATCHED_RETURNS);
        return 0;
    }

    let now = unsafe { helpers::bpf_ktime_get_ns() };
    let delta = now.saturating_sub(start.ts_ns);
    let rv = normalize_target_word(ctx.ret(), layout);

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

    if flags & FLAG_POLICY_AGGREGATE != 0 {
        return 0;
    }

    // Physical ownership and successful settlement above guard aggregate pairing.
    // Image equality additionally guards retained semantic pointer reads.
    let mut image = ImageIdentity::default();
    if unsafe { p11_link_current_identity(&mut image) } != 1
        || !image_pair_matches(start.image, image)
    {
        bump_evidence(EVIDENCE_SEMANTIC_CAPTURE_FAILURES);
        return 0;
    }

    let semantics = semantics_of(&ctx);
    let mut mechanism = start.mechanism;
    let mut capture_flags = start.capture;
    if flags & FLAG_POLICY_ALLOWLISTED != 0
        && return_allows_mechanism(rv)
        && start.mechanism_ptr != 0
    {
        match read_word(start.mechanism_ptr, layout) {
            Ok(value) if unsafe { MECH_SHAPE.get(&value) }.is_some() => {
                mechanism = value;
                capture_flags =
                    (capture_flags & !capture::MECHANISM_MASK) | capture::MECHANISM_VALUE;
            }
            Ok(_) => bump_evidence(EVIDENCE_UNREGISTERED_MECHANISMS),
            Err(_) => {
                capture_flags = (capture_flags & !capture::MECHANISM_MASK)
                    | capture::MECHANISM_UNREADABLE
                    | capture::ARG_READ_FAILURE;
                bump_evidence(EVIDENCE_SEMANTIC_CAPTURE_FAILURES);
            }
        }
    }
    let mut session = start.session;
    if semantics.lifecycle == lifecycle::OPEN_SESSION
        && start.out_ptr != 0
        && (rv == 0 || rv == 0x204)
    {
        // C_OpenSession wrote the handle by now. Only trust it on success.
        match read_word(start.out_ptr, layout) {
            Ok(value) => session = value,
            Err(_) => bump_evidence(EVIDENCE_SEMANTIC_CAPTURE_FAILURES),
        }
    }
    let mut async_value = start.async_value;
    if rv == 0 && start.out_ptr != 0 && semantics.lifecycle == lifecycle::ASYNC_GET_ID {
        match read_word(start.out_ptr, layout) {
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
        mechanism,
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
        image: start.image,
        child_image: ImageIdentity::default(),
        root_affiliation: unsafe { p11_root_current_tag() },
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

#[unsafe(no_mangle)]
#[inline(never)]
pub extern "C" fn p11_link_fork_allowed() -> u32 {
    let Some(scope) = scope_auth() else {
        return 0;
    };
    if scope.flags & FLAG_CGROUP_FILTER == 0 {
        return 0;
    }
    u32::from(scope.flags & FLAG_POLICY_AGGREGATE == 0)
}

#[unsafe(no_mangle)]
#[inline(never)]
pub unsafe extern "C" fn p11_link_emit_fork(
    child_pid: u32,
    clone_flags: u64,
    parent: *const ImageIdentity,
    child: *const ImageIdentity,
) -> u32 {
    // C calls synchronously with initialized stack pairs; no pointer escapes.
    if parent.is_null() || child.is_null() {
        return 0;
    }
    let image = unsafe { *parent };
    let child_image = unsafe { *child };
    if image.task_cookie == 0 || child_image.task_cookie == 0 {
        return 0;
    }
    let Some(event_type) = classify_task_newtask(clone_flags) else {
        return 0;
    };
    if child_pid == 0 {
        return 0;
    }
    let creator_tgid = helpers::bpf_get_current_pid_tgid() >> 32;
    let ev = Event {
        image,
        child_image,
        root_affiliation: unsafe { p11_root_current_tag() },
        pid_tgid: creator_tgid << 32,
        session: child_pid as u64,
        event_type,
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
