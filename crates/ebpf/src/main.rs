//! SPDX-License-Identifier: GPL-2.0-only
//! p11scope BPF programs. A lightweight or template-aware entry program
//! plus one return program serve every attach point. The attach cookie
//! carries the slot and descriptor indices, so 68+ probes share a small fixed program set
//! rather than per-function copies. Cookies need kernel >= 5.15.
#![no_std]
#![no_main]
#![feature(core_intrinsics)]
#![allow(internal_features)]

#[cfg(all(feature = "inventory-only", feature = "unsafe-unvalidated-metadata"))]
compile_error!("inventory-only cannot be combined with unsafe-unvalidated-metadata");

#[cfg(feature = "inventory-only")]
mod inventory;
#[cfg(feature = "inventory-callers")]
mod inventory_callers;

use aya_ebpf::bindings::{BPF_F_MMAPABLE, BPF_F_RDONLY_PROG};
use aya_ebpf::macros::{map, raw_tracepoint, uprobe, uretprobe};
#[cfg(not(feature = "inventory-only"))]
use aya_ebpf::maps::PerCpuHashMap;
use aya_ebpf::maps::ProgramArray;
use aya_ebpf::maps::ring_buf::RingBufEntry;
use aya_ebpf::maps::{Array, CgroupArray, HashMap, PerCpuArray, RingBuf};
use aya_ebpf::programs::{ProbeContext, RawTracePointContext, RetProbeContext};
use aya_ebpf::{EbpfContext as _, helpers};
#[cfg(not(feature = "inventory-only"))]
use core::mem::MaybeUninit;
#[cfg(feature = "inventory-only")]
use p11scope_ebpf_common::INVENTORY_DISCOVERY_BYTES;
#[cfg(not(feature = "inventory-only"))]
use p11scope_ebpf_common::instance::stamp_joinable;
#[cfg(not(feature = "inventory-only"))]
use p11scope_ebpf_common::object_capture::{
    DeriveEntry, authorize_derive_return, capture_derive_entry, classify_derive_mechanism,
    find_flag, handle_status, object_flag, spans_overlap, validate_target_span,
};
#[cfg(not(feature = "inventory-only"))]
use p11scope_ebpf_common::object_policy::ScalarDeriveMechanism;
#[cfg(not(feature = "inventory-only"))]
use p11scope_ebpf_common::object_wire::{
    OBJECT_ACTION_DERIVE, OBJECT_ACTION_FIND, OBJECT_ACTION_GET, OBJECT_ACTION_IMPORT,
    OBJECT_ACTION_MAX, OBJECT_ACTION_NONE, OBJECT_ATTR_LIST_UNINSPECTED, OBJECT_GUARD_NONE,
    OBJECT_GUARD_SCALAR_DERIVE, OBJECT_LAYOUT_ILP32, OBJECT_LAYOUT_LP64, ObjectCallWire,
    ObjectDescriptorWire, ObjectEventRecord, ObjectStart, object_result_arg7_address,
};
#[cfg_attr(feature = "inventory-only", allow(unused_imports))]
use p11scope_ebpf_common::{
    ARG_NONE, CFG_FLAGS, COALESCED_NO_HELPER_RC, CallStart, DISCOVERY_BYTES,
    DISCOVERY_COUNTER_CELLS, DISCOVERY_COUNTER_EXPORT_BOUNDED_READ_FAILURES,
    DISCOVERY_COUNTER_EXPORT_STATE_FAILURES, DISCOVERY_COUNTER_LOADER_HITS,
    DISCOVERY_COUNTER_LOADER_STATE_READ_FAILURES, DISCOVERY_COUNTER_RING_LOSS,
    DISCOVERY_EXEC_SAME_TASK_CANDIDATE, DISCOVERY_EXEC_UNKNOWN, DISCOVERY_INTERFACES,
    DISCOVERY_KIND_EXEC, DISCOVERY_KIND_FUNCTION_LIST_RETURN,
    DISCOVERY_KIND_INTERFACE_LIST_ELEMENT_RETURN, DISCOVERY_KIND_INTERFACE_RETURN,
    DISCOVERY_KIND_LEADER_EXIT, DISCOVERY_KIND_LOADER, DISCOVERY_NAME_EXACT_STANDARD,
    DISCOVERY_NAME_NA, DISCOVERY_NAME_NULL, DISCOVERY_NAME_OTHER, DISCOVERY_NAME_UNREADABLE,
    DISCOVERY_STATUS_COALESCED_NO_HELPER, DISCOVERY_STATUS_LOADER_CONTEXT_INVALID,
    DISCOVERY_STATUS_READ_FAILURE, DISCOVERY_VERSION_NULL, DISCOVERY_VERSION_UNREADABLE,
    DISCOVERY_VERSION_V3_0, DISCOVERY_VERSION_V3_1, DISCOVERY_VERSION_V3_2, DiscoveryRecord,
    EVIDENCE_ABI_REFUSALS, EVIDENCE_CELLS, EVIDENCE_CGROUP_SCOPE_FAILURES, EVIDENCE_RING_LOSS,
    EVIDENCE_RV_UPDATE_FAILURES, EVIDENCE_SEMANTIC_CAPTURE_FAILURES,
    EVIDENCE_START_INSERT_FAILURES, EVIDENCE_UNMATCHED_RETURNS, EVIDENCE_UNREGISTERED_MECHANISMS,
    Event, EventRecord, FLAG_CGROUP_FILTER, FLAG_PID_FILTER, FLAG_POLICY_AGGREGATE,
    FLAG_POLICY_ALLOWLISTED, FLAG_SYSTEM_FILTER, FUNCTION_NAME_MAX_BYTES, FUNCTION_NONE,
    FunctionNameKey, ImageIdentity, InstanceContinuity, LOADER_STATE_PRESENT, LinuxLayout,
    MAX_DESCRIPTORS, MAX_MECH_SHAPES, MAX_SLOTS, MECH_NONE, NATIVE_OWNER_SLOT_BOUND, PAUSE_ARMED,
    PAUSE_REQUESTED, PauseKey, RING_BYTES, RV_ENTRIES, RvKey, SESSION_NONE, STACK_GUARD_ENTRIES,
    START_ENTRIES, STATE_DOMAIN_EXPORT, STATE_DOMAIN_SELECTION, SlotSemantics, SlotStats, StartKey,
    StartState, StateKey, TAIL_CALLS_ENTRIES, TAIL_CALLS_INTERFACE_WORKER_SLOT,
    TAIL_CALLS_NO_PRIVATE_STACK_INDEX, USER_TYPE_NONE, bucket_of, capture, classify_exec_task,
    classify_task_newtask, cookie_descriptor, cookie_slot, decode_export_attach_cookie,
    discovery_pause_coalesced, discovery_pause_enabled, discovery_state_take_failed,
    discovery_state_take_scope_lost, discovery_table_slots, discovery_usable_prefix,
    discovery_version_class, event_type, image_pair_matches, interface_continuation_next,
    interface_continuation_pack, interface_continuation_unpack, interface_flags_class, lifecycle,
    normalize_target_word, read_ia32_arg_with, return_allows_mechanism, semantic_flags, shape,
    stop_gate_admit_with, target_layout_from_cs, target_stack_arg_address, target_word_end,
    valid_config, valid_loader_cookie,
};
#[cfg(feature = "unsafe-unvalidated-metadata")]
use p11scope_ebpf_common::{
    EVIDENCE_TEMPLATE_TAIL_FAILURES, FLAG_POLICY_UNSAFE_UNVALIDATED_METADATA, MAX_ATTRS,
    PAIR_CALLS_ENTRIES, PAIR_CALLS_SECOND_SLOT,
};

// Package G: the BPF slot universe and the native task-owner bound are one
// literal. Changing either without the other corrupts START ownership.
const _: () = assert!(MAX_SLOTS == NATIVE_OWNER_SLOT_BOUND);

#[map]
static CONFIG: Array<u64> = Array::with_max_entries(2, BPF_F_RDONLY_PROG);

#[map]
static PID_FILTER: HashMap<u32, u64> = HashMap::with_max_entries(1024, BPF_F_RDONLY_PROG);

#[map]
static CGROUP_FILTER: CgroupArray = CgroupArray::with_max_entries(1, 0);

#[cfg(not(feature = "inventory-only"))]
#[map]
static STATS: PerCpuArray<SlotStats> = PerCpuArray::with_max_entries(MAX_SLOTS, 0);

#[cfg(not(feature = "inventory-only"))]
#[map]
static START: HashMap<StartKey, CallStart> = HashMap::with_max_entries(START_ENTRIES, 0);

// H7 slice B subordinate custody: one 432-byte row per required object call
// keyed by the START key, a loader-published frozen descriptor table, and a
// loader-verified zero template the native owner copies from (no 432-byte
// stack temporary anywhere on the insert path).
#[cfg(not(feature = "inventory-only"))]
#[map]
static OBJECT_START: HashMap<StartKey, ObjectStart> = HashMap::with_max_entries(START_ENTRIES, 0);

#[cfg(not(feature = "inventory-only"))]
#[map]
static OBJECT_DESCRIPTORS: Array<ObjectDescriptorWire> =
    Array::with_max_entries(MAX_DESCRIPTORS, BPF_F_RDONLY_PROG);

#[cfg(not(feature = "inventory-only"))]
#[map]
static OBJECT_ZERO: Array<ObjectStart> = Array::with_max_entries(1, BPF_F_RDONLY_PROG);

#[cfg(not(feature = "inventory-only"))]
#[map]
static RV_COUNTS: PerCpuHashMap<RvKey, u64> = PerCpuHashMap::with_max_entries(RV_ENTRIES, 0);

#[cfg(not(feature = "inventory-only"))]
#[map]
static DESCRIPTORS: Array<SlotSemantics> =
    Array::with_max_entries(MAX_DESCRIPTORS, BPF_F_RDONLY_PROG);

/// Mechanism id -> parameter shape code, published by userspace from
/// pkcs11-types' registry. An unknown mechanism id looks up empty and is
/// treated as `shape::NONE`.
#[cfg(not(feature = "inventory-only"))]
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
static TAIL_CALLS: ProgramArray = ProgramArray::with_max_entries(TAIL_CALLS_ENTRIES, 0);

/// Never populated: the kernel-stack opt-out for the static endpoint
/// programs, which load with `expected_attach_type = BPF_TRACE_UPROBE_MULTI`
/// under the multi backend. Since CVE-2025-40123 (upstream 4540aed51b12,
/// backported to the stable series) a program array accepts only programs
/// with its owner's expected attach type, so these programs must not
/// reference TAIL_CALLS, whose owner is the plainly loaded interface
/// programs and worker. Userspace freezes it empty before any load.
#[map]
static STACK_GUARD: ProgramArray = ProgramArray::with_max_entries(STACK_GUARD_ENTRIES, 0);

/// The template-pair continuation: the pair program tail-calls slot 0 into
/// `p11_entry_template_second`. The pair loads for uprobe-multi under the
/// multi backend, so this array cannot be TAIL_CALLS (owned by the plainly
/// loaded programs since CVE-2025-40123): it is feature-only, referenced only
/// by the pair, and populated only with the continuation, which userspace
/// loads with the same expected attach type as the pair in each backend.
/// Userspace publishes the slot after the programs load, verifies the exact
/// read-back, then freezes the array.
#[cfg(feature = "unsafe-unvalidated-metadata")]
#[map]
static PAIR_CALLS: ProgramArray = ProgramArray::with_max_entries(PAIR_CALLS_ENTRIES, 0);

/// Keep this uprobe program on the task's own kernel stack.
///
/// From Linux 6.13 the x86 JIT runs a KPROBE-type program whose frame is at
/// least 64 bytes on a per-CPU *private stack*. Uprobe programs (classic and
/// multi) run preemptible (migrate-disabled only) and without a recursion
/// guard, so a second task running the same program on that CPU while the
/// first is preempted overwrites the first invocation's frame: keys, copied
/// START records, event bodies (live on 7.0: a return probe read another
/// thread's START key and the owner refused it as `start_key_mismatch`). The
/// verifier keeps the kernel stack for any program that contains a tail call,
/// so every uprobe program issues this one first. Its index is past the end of
/// the array, so the kernel never jumps and execution continues here; on
/// kernels without private stacks it is an equally harmless no-op.
///
/// Programs that always load plainly use TAIL_CALLS
/// ([`keep_kernel_stack`]); the programs userspace may load for uprobe-multi
/// under the multi backend (the static endpoints plus the template-second
/// continuation, which loads with its caller's attach type) use the empty
/// STACK_GUARD ([`keep_endpoint_stack`]), so each program array keeps one
/// expected attach type.
#[inline(always)]
fn keep_kernel_stack<C: aya_ebpf::EbpfContext>(ctx: &C) {
    // SAFETY: an out-of-range index makes bpf_tail_call return immediately.
    let _ = unsafe { TAIL_CALLS.tail_call(ctx, TAIL_CALLS_NO_PRIVATE_STACK_INDEX) };
}

/// [`keep_kernel_stack`] for the programs userspace may load with
/// `expected_attach_type = BPF_TRACE_UPROBE_MULTI`.
#[inline(always)]
fn keep_endpoint_stack<C: aya_ebpf::EbpfContext>(ctx: &C) {
    // SAFETY: STACK_GUARD is never populated and the index is out of range,
    // so bpf_tail_call returns immediately.
    let _ = unsafe { STACK_GUARD.tail_call(ctx, TAIL_CALLS_NO_PRIVATE_STACK_INDEX) };
}

/// Exact bounded standard function name -> stable shared-table id. Raw
/// `pFunctionName` bytes never leave the BPF stack.
#[cfg(not(feature = "inventory-only"))]
#[map]
static ASYNC_FUNCTIONS: HashMap<FunctionNameKey, u32> =
    HashMap::with_max_entries(128, BPF_F_RDONLY_PROG);

#[cfg(not(feature = "inventory-only"))]
#[map]
static EVENTS: RingBuf = RingBuf::with_byte_size(RING_BYTES, 0);

#[map]
static EVIDENCE: PerCpuArray<u64> = PerCpuArray::with_max_entries(EVIDENCE_CELLS, 0);

#[cfg(feature = "inventory-only")]
#[map]
static DISCOVERY: RingBuf = RingBuf::with_byte_size(INVENTORY_DISCOVERY_BYTES, 0);

#[cfg(not(feature = "inventory-only"))]
#[map]
static DISCOVERY: RingBuf = RingBuf::with_byte_size(DISCOVERY_BYTES, 0);

#[map]
static DISCOVERY_STATE: HashMap<StateKey, StartState> = HashMap::with_max_entries(64, 0);

#[map]
static COUNTERS: PerCpuArray<u64> = PerCpuArray::with_max_entries(DISCOVERY_COUNTER_CELLS, 0);

#[cfg(not(feature = "inventory-only"))]
#[map]
static PAUSE_PIDS: HashMap<PauseKey, u64> = HashMap::with_max_entries(1, 0);

/// Stop gate: bit 63 is the stop request, the low 63 bits count admitted
/// bodies. Userspace mmaps the single cell, so the map stays unfrozen and
/// Detailed-only.
#[cfg(not(feature = "inventory-only"))]
#[map]
static STOP_GATE: Array<u64> = Array::with_max_entries(1, BPF_F_MMAPABLE);

/// Stop-gate admission for the static Detailed programs. Reads the shared
/// word with a compare-exchange against (0, 0) and counts with a non-fetch
/// atomic add whose result is never consumed; the object checker proves the
/// fetch-free lowering in the built object. Returns true when the caller is
/// admitted and MUST call [`stop_gate_leave`] exactly once when its guarded
/// body has finished all capture accesses.
#[cfg(not(feature = "inventory-only"))]
#[inline(always)]
fn stop_gate_enter() -> bool {
    let Some(cell) = STOP_GATE.get_ptr_mut(0) else {
        return false;
    };
    // SAFETY: the pointer is the live STOP_GATE cell for the whole program.
    // Compare-exchange against (0, 0) only reads the shared word, and the
    // deliberately unused fetch-add result selects the non-fetch BPF ATOMIC
    // ADD form, which the object checker verifies per program.
    stop_gate_admit_with(
        || unsafe {
            core::intrinsics::atomic_cxchg::<
                u64,
                { core::intrinsics::AtomicOrdering::AcqRel },
                { core::intrinsics::AtomicOrdering::Acquire },
            >(cell, 0, 0)
            .0
        },
        |delta| unsafe {
            let _ = core::intrinsics::atomic_xadd::<
                u64,
                u64,
                { core::intrinsics::AtomicOrdering::AcqRel },
            >(cell, delta as u64);
        },
    )
}

/// Release one [`stop_gate_enter`] admission. Key 0 of the one-entry
/// STOP_GATE Array resolves in practice, but the lookup CAN miss per the
/// verifier (map_value_or_null): the 5.15 verifier rejects an unchecked
/// dereference, so a null lookup skips the decrement. That path is
/// unreachable in practice — enter already resolved the same cell — and
/// balancing stays exact: the object checker proves a decrement on every
/// exit path.
#[cfg(not(feature = "inventory-only"))]
#[inline(always)]
fn stop_gate_leave() {
    let Some(cell) = STOP_GATE.get_ptr_mut(0) else {
        return;
    };
    // SAFETY: the pointer is the live STOP_GATE cell; the unused result
    // lowers to a non-fetch BPF ATOMIC ADD, object-checked as in enter.
    let _ = unsafe {
        core::intrinsics::atomic_xadd::<u64, u64, { core::intrinsics::AtomicOrdering::AcqRel }>(
            cell,
            u64::MAX,
        )
    };
}

/// Inventory builds have no STOP_GATE map and no stop protocol: the shared
/// discovery and lifecycle wrappers below admit unconditionally so both
/// flavors compile from one source. The no-op inlines away.
#[cfg(feature = "inventory-only")]
#[inline(always)]
fn stop_gate_enter() -> bool {
    true
}

/// Inventory release side of the no-op admission above.
#[cfg(feature = "inventory-only")]
#[inline(always)]
fn stop_gate_leave() {}

/// Does this call belong to the capture scope? With no filter configured
/// nothing is observed — scope is always explicit, and system-wide capture
/// requires the explicit system scope bit (never a missing filter).
/// Add to one per-CPU counter cell with a non-fetch atomic add. From Linux
/// 6.1 uprobe programs run migrate-disabled but preemptible, so another
/// program can run on this CPU between a plain load and store of the same
/// per-CPU cell and its increment is lost. The result is deliberately unused:
/// only the non-fetch BPF ATOMIC ADD lowers on this toolchain (a consumed
/// fetch-add does not), and the object checker rejects any other counter write.
#[inline(always)]
fn counter_add(cell: *mut u64, delta: u64) {
    // SAFETY: `cell` is a live map-value pointer for this program run.
    let _ = unsafe {
        core::intrinsics::atomic_xadd::<u64, u64, { core::intrinsics::AtomicOrdering::AcqRel }>(
            cell, delta,
        )
    };
}

fn bump_evidence(index: u32) {
    if let Some(value) = EVIDENCE.get_ptr_mut(index) {
        counter_add(value, 1);
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

#[cfg(not(feature = "inventory-only"))]
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
    #[cfg(not(feature = "inventory-only"))]
    let valid = valid_config(flags);
    #[cfg(feature = "inventory-only")]
    let valid = p11scope_ebpf_common::valid_inventory_config(flags);
    if !valid {
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
    // `valid_config` above guarantees exactly one scope bit, so reaching here
    // with the system bit set means PID and cgroup bits are both clear: every
    // task passes after the owner-health and config gates. No pause token —
    // pause stays PID-scoped (`valid_config` refuses the combination).
    if flags & FLAG_SYSTEM_FILTER != 0 {
        return Some(ScopeAuth {
            flags,
            tgid,
            _pad: 0,
            generation_token: 0,
        });
    }
    None
}

#[cfg(not(feature = "inventory-only"))]
fn scope_flags() -> Option<u64> {
    scope_auth().map(|scope| scope.flags)
}

fn bump_discovery_counter(index: u32) {
    if let Some(value) = COUNTERS.get_ptr_mut(index) {
        counter_add(value, 1);
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
        // DISCOVERY_INITIALIZER_BEGIN
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
        // DISCOVERY_INITIALIZER_END
    }
    Some(entry)
}

#[inline(always)]
// PAUSE_WRITER_BEGIN
fn finish_discovery_record(
    mut entry: RingBufEntry<DiscoveryRecord>,
    scope: ScopeAuth,
    eligible: bool,
    pid_tgid: u64,
    #[allow(unused_mut)] mut status_flags: u8,
) {
    let raw = entry.as_mut_ptr();
    #[cfg(not(feature = "inventory-only"))]
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
    #[cfg(feature = "inventory-only")]
    let (hook_ts_ns, send_signal_rc) = {
        let _ = (scope, eligible);
        (unsafe { helpers::bpf_ktime_get_ns() }, 0i64)
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
// PAUSE_WRITER_END

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
                // The word behind a caller-writable pointer leaves this probe
                // only as a finite class, never verbatim.
                interface_flags = interface_flags_class(flags);
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
    keep_kernel_stack(&ctx);
    if !stop_gate_enter() {
        return 0;
    }
    let rc = function_list_entry_impl(ctx);
    stop_gate_leave();
    rc
}

#[inline(always)]
fn function_list_entry_impl(ctx: ProbeContext) -> u32 {
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
    keep_kernel_stack(&ctx);
    if !stop_gate_enter() {
        return 0;
    }
    let rc = function_list_return_impl(ctx);
    stop_gate_leave();
    rc
}

#[inline(always)]
fn function_list_return_impl(ctx: RetProbeContext) -> u32 {
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
    keep_kernel_stack(&ctx);
    if !stop_gate_enter() {
        return 0;
    }
    let rc = interface_list_entry_impl(ctx);
    stop_gate_leave();
    rc
}

#[inline(always)]
fn interface_list_entry_impl(ctx: ProbeContext) -> u32 {
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
    // Admission is carried across the tail call into interface_list_worker
    // (slot 0): a successful tail call never returns here, so no leave runs
    // before it; the worker releases the carried admission, and
    // fall-through runs fail_export_state, then leaves below.
    if !stop_gate_enter() {
        return 0;
    }
    let rc = interface_list_return_impl(ctx);
    stop_gate_leave();
    rc
}

#[inline(always)]
fn interface_list_return_impl(ctx: RetProbeContext) -> u32 {
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
    // Carried admission: interface_list_return entered before the tail call
    // (or the previous worker segment did) and did not leave, so this
    // continuation must not re-check the gate. Each segment either
    // tail-calls itself with the admission carried or finishes and leaves;
    // a failed tail call runs fail_export_state, then leaves below.
    let rc = interface_list_worker_impl(ctx);
    stop_gate_leave();
    rc
}

#[inline(always)]
fn interface_list_worker_impl(ctx: RetProbeContext) -> u32 {
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
    keep_kernel_stack(&ctx);
    if !stop_gate_enter() {
        return 0;
    }
    let rc = interface_entry_impl(ctx);
    stop_gate_leave();
    rc
}

#[inline(always)]
fn interface_entry_impl(ctx: ProbeContext) -> u32 {
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
    keep_kernel_stack(&ctx);
    if !stop_gate_enter() {
        return 0;
    }
    let rc = interface_return_impl(ctx);
    stop_gate_leave();
    rc
}

#[inline(always)]
fn interface_return_impl(ctx: RetProbeContext) -> u32 {
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
    keep_kernel_stack(&ctx);
    if !stop_gate_enter() {
        return 0;
    }
    let rc = dl_debug_state_impl(ctx);
    stop_gate_leave();
    rc
}

#[inline(always)]
fn dl_debug_state_impl(ctx: ProbeContext) -> u32 {
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
fn emit_lifecycle(kind: u8, case_id: u8, scope: ScopeAuth, pause_eligible: bool) {
    let Some(mut entry) = reserve_discovery() else {
        return;
    };
    let raw = entry.as_mut_ptr();
    // SAFETY: the shared initializer completed before every field write.
    unsafe {
        core::ptr::write_volatile(core::ptr::addr_of_mut!((*raw).kind), kind);
        core::ptr::write_volatile(core::ptr::addr_of_mut!((*raw).case_id), case_id);
    }
    let pid_tgid = helpers::bpf_get_current_pid_tgid();
    finish_discovery_record(entry, scope, pause_eligible, pid_tgid, 0);
}

#[raw_tracepoint(tracepoint = "sched_process_exec")]
pub fn sched_process_exec(_ctx: RawTracePointContext) -> u32 {
    if !stop_gate_enter() {
        return 0;
    }
    let rc = sched_process_exec_impl(_ctx);
    stop_gate_leave();
    rc
}

#[inline(always)]
fn sched_process_exec_impl(_ctx: RawTracePointContext) -> u32 {
    // Mandatory current-physical-task cleanup precedes all capture filters.
    // A failed custody settlement is capture loss: invalidate the audit
    // before lifecycle bookkeeping, then continue mandatorily.
    #[cfg(not(feature = "inventory-only"))]
    if unsafe { p11_owner_cleanup() } != 0 {
        unsafe { p11_object_fault() };
    }
    #[cfg(feature = "inventory-only")]
    let _ = unsafe { p11_owner_cleanup() };
    // Task 3 Stage A: a new mm ends CLONE_VM sharing for this process.
    #[cfg(not(feature = "inventory-only"))]
    unsafe {
        p11_instance_exec()
    };
    if let Some(scope) = scope_auth() {
        let old_pid = _ctx.arg::<u64>(1);
        let pid_tgid = helpers::bpf_get_current_pid_tgid();
        // Replacement/invalid IDs need no kernel dumpability read. Equal
        // leader IDs still require the checked current-kernel predicate.
        let mut class = classify_exec_task(old_pid, pid_tgid, 1);
        if class == DISCOVERY_EXEC_SAME_TASK_CANDIDATE {
            class = classify_exec_task(old_pid, pid_tgid, unsafe { p11_exec_dumpability() });
        }
        emit_lifecycle(DISCOVERY_KIND_EXEC, class, scope, true);
    }
    0
}

#[raw_tracepoint(tracepoint = "sched_process_exit")]
pub fn sched_process_exit(_ctx: RawTracePointContext) -> u32 {
    if !stop_gate_enter() {
        return 0;
    }
    let rc = sched_process_exit_impl(_ctx);
    stop_gate_leave();
    rc
}

#[inline(always)]
fn sched_process_exit_impl(_ctx: RawTracePointContext) -> u32 {
    // Retained original keys also cover fatal nonleader post-de_thread exit.
    // A failed custody settlement is capture loss: invalidate the audit
    // before lifecycle bookkeeping, then continue mandatorily.
    #[cfg(not(feature = "inventory-only"))]
    if unsafe { p11_owner_cleanup() } != 0 {
        unsafe { p11_object_fault() };
    }
    #[cfg(feature = "inventory-only")]
    let _ = unsafe { p11_owner_cleanup() };
    #[cfg(not(feature = "inventory-only"))]
    unsafe {
        p11_root_current_exit()
    };
    let pid_tgid = helpers::bpf_get_current_pid_tgid();
    if pid_tgid as u32 != (pid_tgid >> 32) as u32 {
        return 0;
    }
    if let Some(scope) = scope_auth() {
        emit_lifecycle(
            DISCOVERY_KIND_LEADER_EXIT,
            DISCOVERY_EXEC_UNKNOWN,
            scope,
            false,
        );
    }
    0
}

fn cookie_of<C>(ctx: &C) -> u64
where
    C: aya_ebpf::EbpfContext,
{
    unsafe { helpers::bpf_get_attach_cookie(ctx.as_ptr()) }
}

#[cfg(not(feature = "inventory-only"))]
fn slot_of<C>(ctx: &C) -> u32
where
    C: aya_ebpf::EbpfContext,
{
    cookie_slot(cookie_of(ctx))
}

#[cfg(not(feature = "inventory-only"))]
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

/// The types-only walk behind the same global boundary as
/// [`p11_walk_template`]: attribute *types* only, never values, written into
/// the caller's template-output region. A separate global rather than a mode
/// flag, so the full walker's verification is untouched. Older verifiers
/// verify a global once; the previous direct local calls made the types entry
/// program re-explore the walk per caller state and exceed the 1,000,000
/// instruction budget on Ubuntu 5.15.
#[cfg(feature = "unsafe-unvalidated-metadata")]
#[unsafe(no_mangle)]
#[inline(never)]
#[allow(private_interfaces)]
pub unsafe extern "C" fn p11_walk_template_types(
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
        walk_template_types::<true>(ptemplate, count, output)
    } else {
        walk_template_types::<false>(ptemplate, count, output)
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
        // The types-only entry program reaches the walk through its own
        // global, exactly like the full walk below: the layout dispatch lives
        // inside the global, which older verifiers explore once.
        let output = unsafe {
            (start as *mut CallStart)
                .cast::<u8>()
                .add(core::mem::offset_of!(CallStart, attr_types))
                .cast::<TemplateOutput>()
        };
        let status = unsafe {
            p11_walk_template_types(ptemplate, count, layout.word_bytes() as u32, output)
        };
        if status != 0 {
            capture_failure(start);
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
fn walk_template_types<const IS_ILP32: bool>(
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
        let width = layout.word_bytes() as u64;
        let Some(base) = ptemplate.checked_add((i as u64) * width * 3) else {
            return TEMPLATE_WALK_FAILURE;
        };
        let Ok(attr_type) = read_word(base, layout) else {
            return TEMPLATE_WALK_FAILURE;
        };
        output.types[i] = attr_type;
        output.count += 1;
    }
    0
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

#[unsafe(no_mangle)]
#[inline(never)]
pub extern "C" fn p11_read_ia32_arg(stack_pointer: u64, index: u32) -> u64 {
    read_ia32_arg_with(stack_pointer, index, |address| unsafe {
        helpers::bpf_probe_read_user(address as *const u32).map_err(|_| ())
    })
}

#[cfg(not(feature = "inventory-only"))]
fn capture_failure(start: &mut CallStart) {
    start.capture |= capture::ARG_READ_FAILURE;
    bump_evidence(EVIDENCE_SEMANTIC_CAPTURE_FAILURES);
}

#[cfg(not(feature = "inventory-only"))]
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

#[cfg(not(feature = "inventory-only"))]
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

#[cfg(not(feature = "inventory-only"))]
fn capture_async_target(pointer: u64, start: &mut CallStart) {
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

#[cfg(not(feature = "inventory-only"))]
const ENTRY_ABI_MIXED: u8 = 0;
#[cfg(not(feature = "inventory-only"))]
const ENTRY_ABI_LP64: u8 = 1;
#[cfg(not(feature = "inventory-only"))]
const ENTRY_ABI_ILP32: u8 = 2;

#[cfg(not(feature = "inventory-only"))]
#[uprobe]
pub fn p11_entry(ctx: ProbeContext) -> u32 {
    keep_endpoint_stack(&ctx);
    if !stop_gate_enter() {
        return 0;
    }
    #[cfg(not(feature = "unsafe-unvalidated-metadata"))]
    let rc = p11_entry_impl::<0, ENTRY_ABI_MIXED>(ctx);
    #[cfg(feature = "unsafe-unvalidated-metadata")]
    let rc = p11_entry_impl::<0, ENTRY_ABI_LP64>(ctx);
    stop_gate_leave();
    rc
}

#[cfg(feature = "unsafe-unvalidated-metadata")]
#[uprobe]
pub fn p11_entry_ia32(ctx: ProbeContext) -> u32 {
    keep_endpoint_stack(&ctx);
    if !stop_gate_enter() {
        return 0;
    }
    let rc = p11_entry_impl::<0, ENTRY_ABI_ILP32>(ctx);
    stop_gate_leave();
    rc
}

#[cfg(feature = "unsafe-unvalidated-metadata")]
#[uprobe]
pub fn p11_entry_template(ctx: ProbeContext) -> u32 {
    keep_endpoint_stack(&ctx);
    if !stop_gate_enter() {
        return 0;
    }
    let rc = p11_entry_impl::<1, ENTRY_ABI_MIXED>(ctx);
    stop_gate_leave();
    rc
}

#[cfg(feature = "unsafe-unvalidated-metadata")]
#[uprobe]
pub fn p11_entry_template_types(ctx: ProbeContext) -> u32 {
    keep_endpoint_stack(&ctx);
    if !stop_gate_enter() {
        return 0;
    }
    let rc = p11_entry_impl::<2, ENTRY_ABI_MIXED>(ctx);
    stop_gate_leave();
    rc
}

#[cfg(feature = "unsafe-unvalidated-metadata")]
#[uprobe]
pub fn p11_entry_template_pair(ctx: ProbeContext) -> u32 {
    // Admission is carried across the tail call: a successful tail call
    // never returns here, so no leave runs before it; the continuation
    // releases the carried admission, and fall-through leaves below.
    if !stop_gate_enter() {
        return 0;
    }
    let rc = p11_entry_impl::<3, ENTRY_ABI_MIXED>(ctx);
    stop_gate_leave();
    rc
}

#[cfg(feature = "unsafe-unvalidated-metadata")]
#[uprobe]
pub fn p11_entry_template_second(ctx: ProbeContext) -> u32 {
    // This continuation loads with its caller's expected attach type (multi
    // under the multi backend), so its opt-out goes through STACK_GUARD, not
    // TAIL_CALLS. The opt-out is still required: a tail-called program runs
    // its own prologue in the same preemptible uprobe context, so without a
    // tail call of its own it would take the shared per-CPU private stack.
    keep_endpoint_stack(&ctx);
    // Carried admission: the pair program entered before the tail call and
    // did not leave, so this continuation must not re-check the gate. It
    // releases the carried admission on every exit instead.
    let rc = p11_entry_template_second_impl(ctx);
    stop_gate_leave();
    rc
}

#[cfg(feature = "unsafe-unvalidated-metadata")]
#[inline(always)]
fn p11_entry_template_second_impl(ctx: ProbeContext) -> u32 {
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
        owned_start_discard(&key);
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
    fn p11_exec_dumpability() -> u32;
    #[cfg(not(feature = "inventory-only"))]
    fn p11_root_current_tag() -> u64;
    #[cfg(not(feature = "inventory-only"))]
    fn p11_root_current_exit();
    #[cfg(any(not(feature = "inventory-only"), feature = "inventory-callers"))]
    fn p11_link_current_identity(out: *mut ImageIdentity) -> u32;
    /// Task 3 Stage A continuity halves (native instance_epoch.c): the entry
    /// half records the private probed address and entry stamp under the
    /// call's START key; the return half fills an `EventRecord`'s private
    /// tail in place. Both own their stack frames, so no probe frame grows.
    #[cfg(not(feature = "inventory-only"))]
    fn p11_instance_entry(key: *const StartKey, ip: u64, cookie: u64, exec_id: u64) -> u32;
    #[cfg(not(feature = "inventory-only"))]
    fn p11_instance_return(key: *const StartKey, out: *mut InstanceContinuity) -> u32;
    #[cfg(not(feature = "inventory-only"))]
    fn p11_instance_exec() -> u32;
    fn p11_owner_healthy() -> u32;
    fn p11_owner_cleanup() -> u32;
    /// H7 slice B subordinate custody (native task_owner.c): the query row
    /// hands a validated live side row to the return terminal drain (which
    /// checks agreement, then retires through the ordinary removal) and to
    /// return-phase fill; only ready authorizes reads.
    #[cfg(not(feature = "inventory-only"))]
    fn p11_object_side_get(
        key: *const StartKey,
        descriptor: u32,
        required: u32,
    ) -> *mut ObjectStart;
    /// H7 slice B fault leaf (native instance_epoch.c): advances the
    /// existing checked fault cell. Probe roots call it sequentially after
    /// an owner/custody failure, never nested inside an owner helper.
    #[cfg(not(feature = "inventory-only"))]
    fn p11_object_fault();
    #[cfg(not(feature = "inventory-only"))]
    fn p11_owner_start_get(key: *const StartKey, required: u32) -> *mut CallStart;
    #[cfg(not(feature = "inventory-only"))]
    fn p11_owner_start_insert(key: *const StartKey, value: *const CallStart) -> i64;
    #[cfg(not(feature = "inventory-only"))]
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
#[cfg(not(feature = "inventory-only"))]
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

#[cfg(not(feature = "inventory-only"))]
#[inline(always)]
fn owned_start_remove(key: &StartKey, required: bool) -> Result<(), ()> {
    (unsafe { p11_owner_start_remove(key, u32::from(required)) } == 0)
        .then_some(())
        .ok_or(())
}

// Raw removal result for terminal drains: 0 retired, -2 healthy absence,
// anything else a custody failure the caller must fault on.
#[cfg(not(feature = "inventory-only"))]
#[inline(always)]
fn owned_start_remove_rc(key: &StartKey, required: bool) -> i64 {
    unsafe { p11_owner_start_remove(key, u32::from(required)) }
}

// Required-object marker for this attachment cookie: the frozen descriptor
// row must be an exact non-NONE object row for the attached descriptor,
// else the call stays ordinary. Mirrors object_wire::validate_start_marker.
// Out of line on purpose: entry has no frame to spare, and this helper
// only makes map-helper calls (which consume no BPF frame), so its level
// costs the chain a single rounding quantum.
#[cfg(not(feature = "inventory-only"))]
#[inline(never)]
fn object_marker_for(cookie: u64) -> u64 {
    let descriptor = cookie_descriptor(cookie);
    if descriptor == 0 || descriptor >= MAX_DESCRIPTORS {
        return 0;
    }
    let Some(row) = OBJECT_DESCRIPTORS.get(descriptor) else {
        return 0;
    };
    if row.function != descriptor - 1
        || row.action == OBJECT_ACTION_NONE
        || row.action > OBJECT_ACTION_MAX
        || row.guard == OBJECT_GUARD_NONE
        || row.guard > OBJECT_GUARD_SCALAR_DERIVE
    {
        return 0;
    }
    u64::from(descriptor) + 1
}

// Record the entry ABI on the subordinate row through the query row:
// return requires it unset or equal to the return layout. Out of line on
// purpose: entry has no frame to spare, and this level only queries (its
// chain costs a single rounding quantum). The caller abandons the
// invocation loudly on false.
#[cfg(not(feature = "inventory-only"))]
#[inline(never)]
fn object_record_entry_abi(key: &StartKey, descriptor: u32, layout: LinuxLayout) -> bool {
    let side = unsafe { p11_object_side_get(key, descriptor, 0).as_mut() };
    match side {
        // SAFETY: a validated live map row; the layout byte is ours.
        Some(side) => unsafe {
            core::ptr::addr_of_mut!((*side).layout).write(match layout {
                LinuxLayout::Lp64 => OBJECT_LAYOUT_LP64,
                LinuxLayout::Ilp32 => OBJECT_LAYOUT_ILP32,
            });
            true
        },
        None => false,
    }
}

// H7 adapters tail: entry-fill advances ENTRY to READY after writing the
// entry verdicts; return-fill advances READY to RETURNING after the
// return-phase reads. Both are outlined like the marker/ABI helpers so the
// hot roots keep their frames. The caller abandons (entry) or drains
// (return) loudly on false.
#[cfg(not(feature = "inventory-only"))]
#[inline(never)]
fn object_fill_entry(
    ctx: &ProbeContext,
    side: Option<&mut ObjectStart>,
    layout: LinuxLayout,
    null_cancel: bool,
) -> bool {
    let Some(side) = side else {
        return false;
    };
    let descriptor = side.descriptor_index;
    let Some(row) = OBJECT_DESCRIPTORS.get(descriptor) else {
        return false;
    };
    if row.function != descriptor.wrapping_sub(1)
        || row.action == OBJECT_ACTION_NONE
        || row.action > OBJECT_ACTION_MAX
        || row.guard == OBJECT_GUARD_NONE
        || row.guard > OBJECT_GUARD_SCALAR_DERIVE
    {
        return false;
    }
    // Entry input handles as data, applying the `capture_entry_inputs`
    // rules against the frozen map row directly. The core entry takes a
    // function ordinal through the name table (which would carry .rodata
    // string tables the BPF object forbids); the map row is already the
    // validated descriptor, so the same pure rules run without the lookup.
    // Written per input straight into the side row: holding both verdicts
    // across the argument reads costs a frame quantum the 512-byte chain
    // cannot spare.
    let import = row.action == OBJECT_ACTION_IMPORT;
    let input0 = row.input_args[0];
    let input1 = row.input_args[1];
    let mut flags = 0u32;
    let mut i = 0;
    while i < 2 {
        let arg = if i == 0 { input0 } else { input1 };
        let (status, word) = if arg == ARG_NONE {
            (handle_status::ABSENT, 0)
        } else {
            match arg_u64(ctx, arg, layout).ok() {
                None => {
                    flags |= object_flag::ARG_READ_FAILURE;
                    (handle_status::UNREADABLE, 0)
                }
                Some(0) if import => (handle_status::ABSENT, 0),
                Some(0) => (handle_status::INVALID_ZERO, 0),
                Some(word) => {
                    if layout == LinuxLayout::Ilp32 && word > u64::from(u32::MAX) {
                        (handle_status::INVALID_SPAN, 0)
                    } else {
                        (handle_status::VALUE, word)
                    }
                }
            }
        };
        // SAFETY: a validated live map row; these cells are ours.
        unsafe {
            core::ptr::addr_of_mut!((*side).inputs[i]).write(word);
            core::ptr::addr_of_mut!((*side).input_statuses[i]).write(status);
        }
        i += 1;
    }
    // Null-mechanism cancel, mirroring `apply_null_mechanism_cancel`: value
    // inputs already written above are suppressed in place.
    if null_cancel {
        let mut j = 0;
        while j < 2 {
            // SAFETY: a validated live map row; these cells are ours.
            let status = unsafe { core::ptr::addr_of!((*side).input_statuses[j]).read() };
            if status == handle_status::VALUE {
                unsafe {
                    core::ptr::addr_of_mut!((*side).input_statuses[j])
                        .write(handle_status::SUPPRESSED);
                    core::ptr::addr_of_mut!((*side).inputs[j]).write(0);
                }
            }
            j += 1;
        }
        flags |= object_flag::NULL_MECHANISM_CANCEL;
    }
    // SAFETY: a validated live map row; these fields are ours.
    unsafe {
        let old = core::ptr::addr_of!((*side).flags).read();
        core::ptr::addr_of_mut!((*side).flags).write(old | flags as u16);
        core::ptr::addr_of_mut!((*side).phase).write(2);
    }
    true
}

// H7 adapters tail: derive entry guard. Only the Derive family retains a
// result pointer here (after the single mechanism-word check); other
// families succeed trivially. Outlined separately: the inputs helper above
// already fills its 32-byte quantum.
#[cfg(not(feature = "inventory-only"))]
#[inline(never)]
fn object_entry_derive(
    ctx: &ProbeContext,
    side: Option<&mut ObjectStart>,
    layout: LinuxLayout,
) -> bool {
    let Some(side) = side else {
        return false;
    };
    let descriptor = side.descriptor_index;
    let Some(row) = OBJECT_DESCRIPTORS.get(descriptor) else {
        return false;
    };
    if row.function != descriptor.wrapping_sub(1)
        || row.action == OBJECT_ACTION_NONE
        || row.action > OBJECT_ACTION_MAX
        || row.guard == OBJECT_GUARD_NONE
        || row.guard > OBJECT_GUARD_SCALAR_DERIVE
    {
        return false;
    }
    if row.action != OBJECT_ACTION_DERIVE {
        return true;
    }
    // C_DeriveKey(hSession, pMechanism, hBaseKey, pTemplate, ulCount, phKey):
    // mechanism at arg 1, result pointer at arg 5. The ordinals below
    // duplicate the Derive row; refuse loudly if the frozen row disagrees
    // rather than reading the wrong arguments. Unreadable arguments retain
    // zero, which the return core maps to unreadable.
    if row.result_args != [5, ARG_NONE] {
        return false;
    }
    // H7-E3: membership before acquisition. The mechanism word is read
    // and classified first; the arg-5 result pointer is acquired only for
    // the accepted mechanisms, so refused calls never read arg 5 (on
    // ia32, never read its stack word).
    let mechanism_ptr = arg_u64(ctx, 1, layout).ok().unwrap_or(0);
    let derive = classify_derive_mechanism(mechanism_ptr, layout, |addr| read_word(addr, layout));
    let retained = match derive {
        DeriveEntry::Accepted(_) => arg_u64(ctx, 5, layout).ok(),
        DeriveEntry::Unavailable => None,
    };
    // SAFETY: a validated live map row; these fields are ours.
    unsafe {
        core::ptr::addr_of_mut!((*side).derive).write(derive.code());
        core::ptr::addr_of_mut!((*side).result_ptrs[0]).write(retained.unwrap_or(0));
        core::ptr::addr_of_mut!((*side).result_ptrs[1]).write(0);
    }
    true
}

// H7 adapters tail: result-pointer retention for non-Derive families.
// Derive retains through its mechanism guard above and skips here, so the
// guard cannot be bypassed by a raw argument read. Arg 7 (pair second,
// unwrap) lives on the userspace stack via the frozen helper.
#[cfg(not(feature = "inventory-only"))]
#[inline(never)]
fn object_entry_results(
    ctx: &ProbeContext,
    side: Option<&mut ObjectStart>,
    layout: LinuxLayout,
) -> bool {
    let Some(side) = side else {
        return false;
    };
    let descriptor = side.descriptor_index;
    let Some(row) = OBJECT_DESCRIPTORS.get(descriptor) else {
        return false;
    };
    if row.function != descriptor.wrapping_sub(1)
        || row.action == OBJECT_ACTION_NONE
        || row.action > OBJECT_ACTION_MAX
        || row.guard == OBJECT_GUARD_NONE
        || row.guard > OBJECT_GUARD_SCALAR_DERIVE
    {
        return false;
    }
    if row.action == OBJECT_ACTION_DERIVE {
        return true;
    }
    let arg0 = row.result_args[0];
    let arg1 = row.result_args[1];
    let mut i = 0;
    while i < 2 {
        let arg = if i == 0 { arg0 } else { arg1 };
        let ptr = if arg == ARG_NONE {
            0
        } else if arg == 7 {
            let rsp = unsafe { (*ctx.regs).rsp as u64 };
            match object_result_arg7_address(row, rsp, layout) {
                Some(addr) => read_word(addr, layout).ok().unwrap_or(0),
                None => return false,
            }
        } else {
            arg_u64(ctx, arg, layout).ok().unwrap_or(0)
        };
        // SAFETY: a validated live map row; this cell is ours.
        unsafe {
            core::ptr::addr_of_mut!((*side).result_ptrs[i]).write(ptr);
        }
        i += 1;
    }
    true
}

// H7 adapters tail: Find scalar retention (capacity value plus count
// pointer). Only the Find family retains here; others succeed trivially.
#[cfg(not(feature = "inventory-only"))]
#[inline(never)]
fn object_entry_find(
    ctx: &ProbeContext,
    side: Option<&mut ObjectStart>,
    layout: LinuxLayout,
) -> bool {
    let Some(side) = side else {
        return false;
    };
    let descriptor = side.descriptor_index;
    let Some(row) = OBJECT_DESCRIPTORS.get(descriptor) else {
        return false;
    };
    if row.function != descriptor.wrapping_sub(1)
        || row.action == OBJECT_ACTION_NONE
        || row.action > OBJECT_ACTION_MAX
        || row.guard == OBJECT_GUARD_NONE
        || row.guard > OBJECT_GUARD_SCALAR_DERIVE
    {
        return false;
    }
    if row.action != OBJECT_ACTION_FIND {
        return true;
    }
    let capacity = if row.find_capacity_arg == ARG_NONE {
        0
    } else {
        arg_u64(ctx, row.find_capacity_arg, layout).ok().unwrap_or(0)
    };
    let count_ptr = if row.find_count_arg == ARG_NONE {
        0
    } else {
        arg_u64(ctx, row.find_count_arg, layout).ok().unwrap_or(0)
    };
    // SAFETY: a validated live map row; these fields are ours.
    unsafe {
        core::ptr::addr_of_mut!((*side).find_capacity).write(capacity);
        core::ptr::addr_of_mut!((*side).find_count_ptr).write(count_ptr);
    }
    true
}

// Per-slot return gates for the unrolled fill below. Always inlined
// with value semantics: taking `&mut` of the slot scalars would pin
// them to stack addresses and spill past the 64-byte helper frame.
#[cfg(not(feature = "inventory-only"))]
#[inline(always)]
fn slot_gate(arg: u8, action: u8, derive_ok: bool) -> (bool, u8) {
    if arg == ARG_NONE {
        (false, handle_status::ABSENT)
    } else if action == OBJECT_ACTION_DERIVE && !derive_ok {
        (false, handle_status::PROTOCOL_UNAVAILABLE)
    } else {
        (true, handle_status::ABSENT)
    }
}

#[cfg(not(feature = "inventory-only"))]
#[inline(always)]
fn slot_span(ptr: u64, layout: LinuxLayout) -> (bool, u8) {
    if ptr == 0 {
        (false, handle_status::UNREADABLE)
    } else if target_word_end(ptr, layout).is_none() {
        (false, handle_status::INVALID_SPAN)
    } else {
        (true, handle_status::ABSENT)
    }
}

#[cfg(not(feature = "inventory-only"))]
#[inline(always)]
fn slot_word(ptr: u64, layout: LinuxLayout) -> (u8, u64) {
    match read_word(ptr, layout) {
        Err(()) => (handle_status::UNREADABLE, 0),
        Ok(0) => (handle_status::INVALID_ZERO, 0),
        Ok(observed) => {
            if layout == LinuxLayout::Ilp32 && observed > u64::from(u32::MAX) {
                (handle_status::INVALID_SPAN, 0)
            } else {
                (handle_status::VALUE, observed)
            }
        }
    }
}

// H7 adapters tail: return-fill reads both result handles at their
// retained pointers and advances READY to RETURNING, mirroring
// `capture_return_handles`. Find carries its facts in the Find section
// (emission reads the retained array base, never a handle) and skips
// here; families without results keep absent cells. The required=1
// query already proved ready custody, so only CKR_OK (0) gates reads.
// Slice D: slot-0 VALUE is pre-cross-check until the pair
// alias/duplicate/partial rules below recompute both slots from the
// retained pointers; emission never trusts slot-0 as final.
#[cfg(not(feature = "inventory-only"))]
#[inline(never)]
fn object_fill_return(
    ctx: &RetProbeContext,
    side: Option<&mut ObjectStart>,
    layout: LinuxLayout,
    mech_status: u32,
    mech: u64,
) -> bool {
    let Some(side) = side else {
        return false;
    };
    if side.phase != 2 {
        return false;
    }
    let descriptor = side.descriptor_index;
    let Some(row) = OBJECT_DESCRIPTORS.get(descriptor) else {
        return false;
    };
    if row.function != descriptor.wrapping_sub(1)
        || row.action == OBJECT_ACTION_NONE
        || row.action > OBJECT_ACTION_MAX
        || row.guard == OBJECT_GUARD_NONE
        || row.guard > OBJECT_GUARD_SCALAR_DERIVE
    {
        return false;
    }
    if row.action != OBJECT_ACTION_FIND {
        let rv = normalize_target_word(ctx.ret(), layout);
        // Derive return authorization is the full S1 match: accepted
        // entry evidence, CKR_OK, and existing MECHANISM_VALUE return
        // evidence exactly equal to the entry code. Entry-nonzero alone
        // never authorizes the phKey read.
        let derive_entry = match side.derive {
            1 => DeriveEntry::Accepted(ScalarDeriveMechanism::DhPkcs),
            2 => DeriveEntry::Accepted(ScalarDeriveMechanism::Sha256),
            3 => DeriveEntry::Accepted(ScalarDeriveMechanism::Ecdh1),
            4 => DeriveEntry::Accepted(ScalarDeriveMechanism::Ecdh1Cofactor),
            _ => DeriveEntry::Unavailable,
        };
        let derive_ok = row.action != OBJECT_ACTION_DERIVE
            || authorize_derive_return(derive_entry, rv, mech_status, mech);
        // Unrolled two-slot protocol: arrays and loop-carried indices
        // spill past the 64-byte helper frame, while straight-line
        // scalars stay in registers. Both retained pointers are
        // validated before either read; the alias rule consumes them
        // before the observed words overwrite them below.
        let mut flags = 0u32;
        let (gated0, mut status0) = slot_gate(row.result_args[0], row.action, derive_ok);
        if row.action == OBJECT_ACTION_DERIVE && !derive_ok && row.result_args[0] != ARG_NONE {
            flags |= object_flag::UNAVAILABLE_RESULT;
        }
        let (gated1, mut status1) = slot_gate(row.result_args[1], row.action, derive_ok);
        if row.action == OBJECT_ACTION_DERIVE && !derive_ok && row.result_args[1] != ARG_NONE {
            flags |= object_flag::UNAVAILABLE_RESULT;
        }
        let (mut word0, mut word1) = (0u64, 0u64);
        if gated0 || gated1 {
            if rv != 0 {
                if gated0 {
                    status0 = handle_status::PROTOCOL_UNAVAILABLE;
                }
                if gated1 {
                    status1 = handle_status::PROTOCOL_UNAVAILABLE;
                }
            } else {
                let ptr0 = side.result_ptrs[0];
                let ptr1 = side.result_ptrs[1];
                let mut readable0 = false;
                let mut readable1 = false;
                if gated0 {
                    let (ok, span) = slot_span(ptr0, layout);
                    readable0 = ok;
                    if !ok {
                        status0 = span;
                    }
                }
                if gated1 {
                    let (ok, span) = slot_span(ptr1, layout);
                    readable1 = ok;
                    if !ok {
                        status1 = span;
                    }
                }
                let w = layout.word_bytes() as u64;
                if readable0 && readable1 && spans_overlap(ptr0, w, ptr1, w) {
                    status0 = handle_status::ALIAS;
                    status1 = handle_status::ALIAS;
                    flags |= object_flag::ALIAS;
                } else {
                    if readable0 {
                        let (status, word) = slot_word(ptr0, layout);
                        status0 = status;
                        word0 = word;
                    }
                    if readable1 {
                        let (status, word) = slot_word(ptr1, layout);
                        status1 = status;
                        word1 = word;
                    }
                    if status0 == handle_status::VALUE
                        && status1 == handle_status::VALUE
                        && word0 == word1
                    {
                        status0 = handle_status::DUPLICATE;
                        status1 = handle_status::DUPLICATE;
                        word0 = 0;
                        word1 = 0;
                        flags |= object_flag::DUPLICATE_RESULT;
                    }
                    if gated0
                        && gated1
                        && u32::from(status0 == handle_status::VALUE)
                            + u32::from(status1 == handle_status::VALUE)
                            == 1
                    {
                        flags |= object_flag::PARTIAL_RESULT;
                    }
                }
            }
        }
        // SAFETY: a validated live map row; these fields are ours. The
        // retained pointers are overwritten with the observed handle
        // words (zero for non-value statuses), which emission reads;
        // the cross-checks above already consumed the retained pointers.
        unsafe {
            core::ptr::addr_of_mut!((*side).result_ptrs).write([word0, word1]);
            core::ptr::addr_of_mut!((*side).result_statuses).write([status0, status1]);
            let old = core::ptr::addr_of!((*side).flags).read();
            core::ptr::addr_of_mut!((*side).flags).write(old | flags as u16);
        }
    }
    // SAFETY: a validated live map row; the phase byte is ours.
    unsafe {
        core::ptr::addr_of_mut!((*side).phase).write(3);
    }
    true
}

// Slice D emission: fill the reserved 240-byte object tail in place
// from the RETURNING side row. Zeroes the whole tail first (every
// reserved word, the Find section and the result list stay zero unless
// their family helper fills them), then copies header, handles and
// statuses and marks never-inspected request lists honestly. Outlined:
// the return root has no frame to spare, and this level costs one
// rounding quantum. False only on custody failure, never on a finite
// per-field status.
#[cfg(not(feature = "inventory-only"))]
#[inline(never)]
fn object_tail_fill(
    tail: *mut ObjectCallWire,
    side: Option<&ObjectStart>,
    descriptor: u32,
) -> bool {
    if tail.is_null() {
        return false;
    }
    let Some(side) = side else {
        return false;
    };
    if side.phase != 3 || side.descriptor_index != descriptor {
        return false;
    }
    let Some(row) = OBJECT_DESCRIPTORS.get(descriptor) else {
        return false;
    };
    if row.function != descriptor.wrapping_sub(1)
        || row.action == OBJECT_ACTION_NONE
        || row.action > OBJECT_ACTION_MAX
        || row.guard == OBJECT_GUARD_NONE
        || row.guard > OBJECT_GUARD_SCALAR_DERIVE
    {
        return false;
    }
    // SAFETY: `tail` is the exclusively owned reserved tail; `side` is a
    // validated live map row whose fields are ours to read.
    //
    // Unrolled volatile stores on purpose: any optimizable zeroing
    // sequence (a loop, or even straight-line stores) lowers to memset
    // calls, and the kernel floors every subprogram on the call path at
    // 32 bytes (check_max_stack_depth), so each call level costs budget
    // this helper does not have. Volatile keeps it leaf-flat.
    unsafe {
        let words = tail.cast::<u64>();
        words.add(0).write_volatile(0);
        words.add(1).write_volatile(0);
        words.add(2).write_volatile(0);
        words.add(3).write_volatile(0);
        words.add(4).write_volatile(0);
        words.add(5).write_volatile(0);
        words.add(6).write_volatile(0);
        words.add(7).write_volatile(0);
        words.add(8).write_volatile(0);
        words.add(9).write_volatile(0);
        words.add(10).write_volatile(0);
        words.add(11).write_volatile(0);
        words.add(12).write_volatile(0);
        words.add(13).write_volatile(0);
        words.add(14).write_volatile(0);
        words.add(15).write_volatile(0);
        words.add(16).write_volatile(0);
        words.add(17).write_volatile(0);
        words.add(18).write_volatile(0);
        words.add(19).write_volatile(0);
        words.add(20).write_volatile(0);
        words.add(21).write_volatile(0);
        words.add(22).write_volatile(0);
        words.add(23).write_volatile(0);
        words.add(24).write_volatile(0);
        words.add(25).write_volatile(0);
        words.add(26).write_volatile(0);
        words.add(27).write_volatile(0);
        words.add(28).write_volatile(0);
        words.add(29).write_volatile(0);
        core::ptr::addr_of_mut!((*tail).version).write(1);
        core::ptr::addr_of_mut!((*tail).bytes).write(240);
        core::ptr::addr_of_mut!((*tail).descriptor_index).write(descriptor);
        core::ptr::addr_of_mut!((*tail).flags).write(u32::from(side.flags));
        core::ptr::addr_of_mut!((*tail).layout).write(side.layout);
        core::ptr::addr_of_mut!((*tail).action).write(row.action);
        core::ptr::addr_of_mut!((*tail).entry_derive).write(side.derive);
        core::ptr::addr_of_mut!((*tail).input_handles).write(side.inputs);
        core::ptr::addr_of_mut!((*tail).input_status).write(side.input_statuses);
        if row.action == OBJECT_ACTION_FIND {
            // Precondition (b): Find result_ptrs[0] holds the array base,
            // never a handle. The single-handle result cell is pinned to
            // the constant unavailable cell; Find facts live in the Find
            // section that object_emit_find fills next.
            core::ptr::addr_of_mut!((*tail).result_handles).write([0, 0]);
            core::ptr::addr_of_mut!((*tail).result_status)
                .write([handle_status::PROTOCOL_UNAVAILABLE, handle_status::ABSENT]);
        } else {
            core::ptr::addr_of_mut!((*tail).result_handles).write(side.result_ptrs);
            core::ptr::addr_of_mut!((*tail).result_status).write(side.result_statuses);
        }
    }
    // Requested lists: BPF performs no entry template inspection (no
    // chain budget for it), so present pairs carry the honest
    // uninspected marker; absent pairs stay all-zero.
    let mut p = 0;
    while p < 2 {
        let present =
            row.template_args[2 * p] != ARG_NONE && row.template_args[2 * p + 1] != ARG_NONE;
        if present {
            // SAFETY: `tail` is ours; `side` is a validated live map row.
            unsafe {
                let dst = core::ptr::addr_of_mut!((*tail).requested[p]);
                dst.write(side.requested[p]);
                core::ptr::addr_of_mut!((*dst).flags).write(OBJECT_ATTR_LIST_UNINSPECTED);
            }
        }
        p += 1;
    }
    // Get result lists are return-inspected only; slice D runs no Get
    // protocol in BPF, so a Get tail marks its result list uninspected
    // rather than claiming an inspected-empty result.
    if row.action == OBJECT_ACTION_GET {
        // SAFETY: `tail` is the exclusively owned reserved tail.
        unsafe {
            let dst = core::ptr::addr_of_mut!((*tail).result_attributes);
            core::ptr::addr_of_mut!((*dst).flags).write(OBJECT_ATTR_LIST_UNINSPECTED);
        }
    }
    true
}

// Slice D emission: stream the bounded Find protocol straight into the
// reserved tail, mirroring `capture_find_return` without its 8-word
// stack array. Non-Find families succeed trivially. Every refusal
// leaves the zeroed section with only its flag byte set; a changed
// count re-zeroes the streamed cells. Outlined like the tail fill.
#[cfg(not(feature = "inventory-only"))]
#[inline(never)]
fn object_emit_find(
    tail: *mut ObjectCallWire,
    side: Option<&ObjectStart>,
    descriptor: u32,
    layout: LinuxLayout,
    rv: u64,
) -> bool {
    if tail.is_null() {
        return false;
    }
    let Some(side) = side else {
        return false;
    };
    if side.phase != 3 || side.descriptor_index != descriptor {
        return false;
    }
    let Some(row) = OBJECT_DESCRIPTORS.get(descriptor) else {
        return false;
    };
    if row.function != descriptor.wrapping_sub(1) {
        return false;
    }
    if row.action != OBJECT_ACTION_FIND {
        return true;
    }
    if rv != 0 {
        return true;
    }
    let count_ptr = side.find_count_ptr;
    if count_ptr == 0 || target_word_end(count_ptr, layout).is_none() {
        // SAFETY: `tail` is the exclusively owned reserved tail.
        unsafe {
            core::ptr::addr_of_mut!((*tail).find_flags).write(find_flag::INVALID_COUNT);
        }
        return true;
    }
    let count = match read_word(count_ptr, layout) {
        Ok(count) => count,
        Err(()) => {
            // SAFETY: `tail` is the exclusively owned reserved tail.
            unsafe {
                core::ptr::addr_of_mut!((*tail).find_flags).write(find_flag::INVALID_COUNT);
            }
            return true;
        }
    };
    if layout == LinuxLayout::Ilp32 && count > u64::from(u32::MAX) {
        // SAFETY: `tail` is the exclusively owned reserved tail.
        unsafe {
            core::ptr::addr_of_mut!((*tail).find_flags).write(find_flag::INVALID_COUNT);
        }
        return true;
    }
    if count > side.find_capacity {
        // SAFETY: `tail` is the exclusively owned reserved tail.
        unsafe {
            core::ptr::addr_of_mut!((*tail).find_flags).write(find_flag::INVALID_COUNT);
        }
        return true;
    }
    // `count * W` with overflow refusal. A checked 64-bit multiply
    // lowers to a widening multiply BPF cannot link (`__multi3`), so
    // shift: the target word is 8 (LP64) or 4 (ILP32) bytes wide.
    let shift: u32 = match layout {
        LinuxLayout::Lp64 => 3,
        LinuxLayout::Ilp32 => 2,
    };
    let array_ptr = side.result_ptrs[0];
    if count > (u64::MAX >> shift) {
        // SAFETY: `tail` is the exclusively owned reserved tail.
        unsafe {
            core::ptr::addr_of_mut!((*tail).find_flags).write(find_flag::INVALID_SPAN);
        }
        return true;
    }
    let array_len = count << shift;
    if validate_target_span(array_ptr, array_len, layout).is_none() {
        // SAFETY: `tail` is the exclusively owned reserved tail.
        unsafe {
            core::ptr::addr_of_mut!((*tail).find_flags).write(find_flag::INVALID_SPAN);
        }
        return true;
    }
    if spans_overlap(array_ptr, array_len, count_ptr, 1u64 << shift) {
        // SAFETY: `tail` is the exclusively owned reserved tail.
        unsafe {
            core::ptr::addr_of_mut!((*tail).find_flags).write(find_flag::COUNT_ALIAS);
        }
        return true;
    }
    let take = if count > 8 { 8u64 } else { count };
    let mut flags = 0u8;
    if count > 8 {
        flags |= find_flag::TRUNCATED;
    }
    let mut i = 0u64;
    while i < take {
        let Some(addr) = array_ptr.checked_add(i << shift) else {
            // SAFETY: `tail` is ours; zero the streamed prefix, keep flags.
            unsafe {
                zero_find_cells(tail);
                core::ptr::addr_of_mut!((*tail).find_flags).write(find_flag::INVALID_SPAN);
            }
            return true;
        };
        // SAFETY: `tail` is the exclusively owned reserved tail; `i` is
        // bounded by `take <= 8`.
        unsafe {
            match read_word(addr, layout) {
                Err(()) => {
                    core::ptr::addr_of_mut!((*tail).find_status[i as usize])
                        .write(handle_status::UNREADABLE);
                    flags |= find_flag::UNREADABLE_ELEMENT;
                }
                Ok(0) => {
                    core::ptr::addr_of_mut!((*tail).find_status[i as usize])
                        .write(handle_status::INVALID_ZERO);
                }
                Ok(word) => {
                    if layout == LinuxLayout::Ilp32 && word > u64::from(u32::MAX) {
                        core::ptr::addr_of_mut!((*tail).find_status[i as usize])
                            .write(handle_status::INVALID_SPAN);
                    } else {
                        core::ptr::addr_of_mut!((*tail).find_status[i as usize])
                            .write(handle_status::VALUE);
                        core::ptr::addr_of_mut!((*tail).find_handles[i as usize]).write(word);
                    }
                }
            }
        }
        i += 1;
    }
    match read_word(count_ptr, layout) {
        Ok(stable) if stable == count => (),
        _ => {
            // SAFETY: `tail` is ours; the changed count discards the batch.
            unsafe {
                zero_find_cells(tail);
                core::ptr::addr_of_mut!((*tail).find_flags).write(find_flag::CHANGED_COUNT);
            }
            return true;
        }
    }
    // SAFETY: `tail` is the exclusively owned reserved tail.
    unsafe {
        core::ptr::addr_of_mut!((*tail).find_len).write(take as u8);
        core::ptr::addr_of_mut!((*tail).find_flags).write(flags);
        core::ptr::addr_of_mut!((*tail).find_valid).write(1);
    }
    true
}

// Zero the streamed Find cells after a late refusal (changed count or
// address overflow): the section keeps only its flag byte. Always
// inlined: it must not cost the return chain another level.
#[cfg(not(feature = "inventory-only"))]
#[inline(always)]
unsafe fn zero_find_cells(tail: *mut ObjectCallWire) {
    // SAFETY: the caller holds the exclusively owned reserved tail.
    //
    // Unrolled volatile stores like the tail zeroing above: any
    // optimizable zeroing here lowers to memset calls that cost the
    // return call chain a 32-byte level each, and this helper's caller
    // has no budget for it.
    unsafe {
        core::ptr::addr_of_mut!((*tail).find_handles[0]).write_volatile(0);
        core::ptr::addr_of_mut!((*tail).find_handles[1]).write_volatile(0);
        core::ptr::addr_of_mut!((*tail).find_handles[2]).write_volatile(0);
        core::ptr::addr_of_mut!((*tail).find_handles[3]).write_volatile(0);
        core::ptr::addr_of_mut!((*tail).find_handles[4]).write_volatile(0);
        core::ptr::addr_of_mut!((*tail).find_handles[5]).write_volatile(0);
        core::ptr::addr_of_mut!((*tail).find_handles[6]).write_volatile(0);
        core::ptr::addr_of_mut!((*tail).find_handles[7]).write_volatile(0);
        core::ptr::addr_of_mut!((*tail).find_status[0]).write_volatile(0);
        core::ptr::addr_of_mut!((*tail).find_status[1]).write_volatile(0);
        core::ptr::addr_of_mut!((*tail).find_status[2]).write_volatile(0);
        core::ptr::addr_of_mut!((*tail).find_status[3]).write_volatile(0);
        core::ptr::addr_of_mut!((*tail).find_status[4]).write_volatile(0);
        core::ptr::addr_of_mut!((*tail).find_status[5]).write_volatile(0);
        core::ptr::addr_of_mut!((*tail).find_status[6]).write_volatile(0);
        core::ptr::addr_of_mut!((*tail).find_status[7]).write_volatile(0);
        core::ptr::addr_of_mut!((*tail).find_len).write_volatile(0);
        core::ptr::addr_of_mut!((*tail).find_valid).write_volatile(0);
    }
}

// Discard a possibly stale START row on a refusal path; a failed discard
// is capture loss and faults.
#[cfg(not(feature = "inventory-only"))]
#[inline(always)]
fn owned_start_discard(key: &StartKey) {
    if !matches!(owned_start_remove_rc(key, false), 0 | -2) {
        unsafe { p11_object_fault() };
    }
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

#[cfg(not(feature = "inventory-only"))]
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

#[cfg(not(feature = "inventory-only"))]
#[inline(always)]
fn record_aggregate_start(key: &StartKey) {
    let mut storage = MaybeUninit::<CallStart>::uninit();
    zero_call_start(&mut storage);
    // SAFETY: zero_call_start initialized every byte, including padding.
    let start = unsafe { storage.assume_init_mut() };
    start.ts_ns = unsafe { helpers::bpf_ktime_get_ns() };
    let _ = store_start(key, start);
}

/// The probed runtime address: the uprobe `pt_regs` IP is `bp_vaddr`
/// (kernel `handle_swbp`), normalized to the target width. Private routing
/// input only (proposed allowlist-v3); never emitted to any renderer.
#[cfg(not(feature = "inventory-only"))]
#[inline(always)]
fn entry_ip(ctx: &ProbeContext, layout: LinuxLayout) -> u64 {
    normalize_target_word(unsafe { (*ctx.regs).rip as u64 }, layout)
}

#[cfg(not(feature = "inventory-only"))]
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
        // SAFETY: a live per-CPU cell; only the field address is taken. The
        // add is atomic because a preempting program can share this CPU.
        counter_add(unsafe { core::ptr::addr_of_mut!((*stats).entered) }, 1);
    }
    if flags & FLAG_POLICY_AGGREGATE != 0 {
        record_aggregate_start(&key);
        return 0;
    }
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
    // Task 3 Stage A: the call's private probed address and entry stamp,
    // recorded natively under its START key (its own frame: this frame does
    // not grow). A failure leaves no entry, which the return half reports as
    // an invalid, never-joining stamp. An entry orphaned by a later refusal
    // is overwritten by the key's next call or reclaimed by the LRU.
    let _ = unsafe {
        p11_instance_entry(
            &key,
            entry_ip(&ctx, layout),
            start.image.task_cookie,
            start.image.exec_id,
        )
    };
    start.session = SESSION_NONE;
    start.mechanism = MECH_NONE;
    start.user_type = USER_TYPE_NONE;
    start.shape = shape::NONE;
    start.capture = capture::MECHANISM_NONE | capture::OUTPUT_NONE;
    start.target_function = FUNCTION_NONE;

    // H7 slice B custody: bind the required-object marker after
    // descriptor/attachment admission, before native NOEXIST insertion. The
    // native transaction establishes the subordinate row and its immutable
    // binding; a zero marker keeps the ordinary path. Placed before the
    // capture sequences on purpose: entry has no frame to spare, and the
    // marker computation is independent of every captured field.
    if flags & FLAG_POLICY_ALLOWLISTED != 0 {
        start.object_required = object_marker_for(cookie_of(&ctx));
    }

    // Materialized late on purpose: its fields stay out of entry's live set
    // across the marker call above. The descriptor table is frozen, so this
    // reads the same row it would have read earlier.
    let semantics = semantics_of(&ctx);
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
        if let Some(pointer) = capture_scalar(&ctx, semantics.async_name_arg, layout, start) {
            capture_async_target(pointer, start);
        }
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
    if start.object_required != 0 {
        // Record the entry ABI on the subordinate row through the query
        // row: return requires it unset or equal to the return layout. The
        // marker is descriptor-plus-one by construction, so the query
        // descriptor derives from it without another cookie read. A
        // missing row here contradicts the just-committed transaction, so
        // abandon the invocation loudly instead of running half-bound.
        let recorded =
            object_record_entry_abi(&key, (start.object_required - 1) as u32, layout);
        if !recorded {
            let _ = owned_start_remove(&key, true);
            unsafe { p11_object_fault() };
            bump_evidence(EVIDENCE_START_INSERT_FAILURES);
            return 0;
        }
        // H7 adapters tail: entry-fill after the ABI record.
        let null_cancel = semantics_of(&ctx).semantic_flags
            & semantic_flags::NULL_MECHANISM_CANCEL
            != 0
            && start.capture & capture::MECHANISM_MASK == capture::MECHANISM_NULL;
        let fill_side =
            unsafe { p11_object_side_get(&key, (start.object_required - 1) as u32, 0).as_mut() };
        if !object_fill_entry(&ctx, fill_side, layout, null_cancel) {
            let _ = owned_start_remove(&key, true);
            unsafe { p11_object_fault() };
            bump_evidence(EVIDENCE_START_INSERT_FAILURES);
            return 0;
        }
        let derive_side =
            unsafe { p11_object_side_get(&key, (start.object_required - 1) as u32, 0).as_mut() };
        if !object_entry_derive(&ctx, derive_side, layout) {
            let _ = owned_start_remove(&key, true);
            unsafe { p11_object_fault() };
            bump_evidence(EVIDENCE_START_INSERT_FAILURES);
            return 0;
        }
        let results_side =
            unsafe { p11_object_side_get(&key, (start.object_required - 1) as u32, 0).as_mut() };
        if !object_entry_results(&ctx, results_side, layout) {
            let _ = owned_start_remove(&key, true);
            unsafe { p11_object_fault() };
            bump_evidence(EVIDENCE_START_INSERT_FAILURES);
            return 0;
        }
        let find_side =
            unsafe { p11_object_side_get(&key, (start.object_required - 1) as u32, 0).as_mut() };
        if !object_entry_find(&ctx, find_side, layout) {
            let _ = owned_start_remove(&key, true);
            unsafe { p11_object_fault() };
            bump_evidence(EVIDENCE_START_INSERT_FAILURES);
            return 0;
        }
    }
    #[cfg(feature = "unsafe-unvalidated-metadata")]
    if TEMPLATE_MODE == 3 {
        // Success never returns. Failure leaves template0 as usable partial
        // evidence and is independently disclosed below.
        unsafe { PAIR_CALLS.tail_call(&ctx, PAIR_CALLS_SECOND_SLOT) };
        bump_evidence(EVIDENCE_TEMPLATE_TAIL_FAILURES);
    }
    0
}

/// Count one completion under its CK_RV. An existing row is updated in place
/// with an atomic add; a missing row is created with BPF_NOEXIST, so a row
/// another program created meanwhile (on this CPU or another) is never
/// overwritten with a stale count, and that race falls back to the in-place
/// add. Only a full map or a failed update reports loss.
#[cfg(not(feature = "inventory-only"))]
#[inline(always)]
fn rv_count_add(key: &RvKey) -> bool {
    if let Some(cell) = RV_COUNTS.get_ptr_mut(key) {
        counter_add(cell, 1);
        return true;
    }
    // The initial count lives on the stack: a reference to a literal would be
    // placed in a .rodata literal pool, which loads as one more global-data map.
    let mut one = 0u64;
    // SAFETY: a plain local; the volatile store only keeps it off .rodata.
    unsafe { core::ptr::write_volatile(&mut one, 1) };
    if RV_COUNTS
        .insert(key, &one, aya_ebpf::bindings::BPF_NOEXIST as u64)
        .is_ok()
    {
        return true;
    }
    match RV_COUNTS.get_ptr_mut(key) {
        Some(cell) => {
            counter_add(cell, 1);
            true
        }
        None => false,
    }
}

#[cfg(not(feature = "inventory-only"))]
#[uretprobe]
pub fn p11_return(ctx: RetProbeContext) -> u32 {
    keep_endpoint_stack(&ctx);
    if !stop_gate_enter() {
        return 0;
    }
    let rc = p11_return_impl(ctx);
    stop_gate_leave();
    rc
}

#[cfg(not(feature = "inventory-only"))]
#[inline(always)]
fn p11_return_impl(ctx: RetProbeContext) -> u32 {
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
        match owned_start_remove_rc(&key, false) {
            0 => bump_evidence(EVIDENCE_UNMATCHED_RETURNS),
            -2 => {}
            _ => {
                unsafe { p11_object_fault() };
                bump_evidence(EVIDENCE_UNMATCHED_RETURNS);
            }
        }
        return 0;
    };
    let Some(layout) = ret_probe_layout(&ctx) else {
        owned_start_discard(&key);
        bump_evidence(EVIDENCE_ABI_REFUSALS);
        return 0;
    };
    // No start entry means the entry probe filtered this call out (or the
    // process was already inside the function at attach time). Either way
    // there is nothing to attribute. The row is copied: the drain below
    // deletes it, and the event is built from the copy afterwards.
    let Some(&start) = owned_start_get(&key) else {
        return 0;
    };
    if start.object_required == 0 {
        if owned_start_remove(&key, true).is_err() {
            // Removal failure is capture loss (a contradicted subordinate
            // row fails here too): disclose it and invalidate the audit.
            unsafe { p11_object_fault() };
            bump_evidence(EVIDENCE_UNMATCHED_RETURNS);
            return 0;
        }
    } else {
        // Slice D activation: query the validated side row and require
        // ready phase, attached-descriptor and retained-ABI agreement.
        // The drain retire moves after emission below: the side row must
        // stay alive while the 608-byte record is reserved and filled.
        // Query plus retire stays the drain (a monolithic native drain
        // nests too deep for return's 512-byte call-chain budget; see
        // object_producer_compiled_frames_are_bounded). Any failure
        // discards the record: no ring reservation, no facts.
        let layout_code = match layout {
            LinuxLayout::Lp64 => u32::from(OBJECT_LAYOUT_LP64),
            LinuxLayout::Ilp32 => u32::from(OBJECT_LAYOUT_ILP32),
        };
        let descriptor = cookie_descriptor(cookie_of(&ctx));
        let ready = unsafe { p11_object_side_get(&key, descriptor, 1).as_ref() };
        if ready.is_none() {
            // H7-E2: every refusal retires identifiable owned state
            // through the checked removal before returning; the fault
            // below fires whether or not the retire settles.
            let _ = owned_start_remove(&key, true);
            unsafe { p11_object_fault() };
            bump_evidence(EVIDENCE_UNMATCHED_RETURNS);
            return 0;
        }
        let side = unsafe { p11_object_side_get(&key, descriptor, 0).as_ref() };
        let agreed = side.is_some_and(|row| {
            row.descriptor_index == descriptor
                && (row.layout == 0 || u32::from(row.layout) == layout_code)
        });
        if !agreed {
            // H7-E2: retire before returning, as on every refusal arm.
            let _ = owned_start_remove(&key, true);
            unsafe { p11_object_fault() };
            bump_evidence(EVIDENCE_UNMATCHED_RETURNS);
            return 0;
        }
    }

    let now = unsafe { helpers::bpf_ktime_get_ns() };
    let delta = now.saturating_sub(start.ts_ns);
    let rv = normalize_target_word(ctx.ret(), layout);

    if let Some(stats) = STATS.get_ptr_mut(slot) {
        // SAFETY: a live per-CPU cell; only field addresses are taken. Every
        // sum is an atomic add (a preempting program can share this CPU).
        // `max_ns` stays a plain best-effort maximum: a lost update can only
        // keep a smaller maximum, never add or drop a counted call.
        unsafe {
            counter_add(core::ptr::addr_of_mut!((*stats).returned), 1);
            counter_add(core::ptr::addr_of_mut!((*stats).total_ns), delta);
            if delta > (*stats).max_ns {
                (*stats).max_ns = delta;
            }
            let b = bucket_of(delta) as usize;
            if b < (*stats).buckets.len() {
                counter_add(core::ptr::addr_of_mut!((*stats).buckets[b]), 1);
            }
            if rv != 0 && rv != 0x204 {
                counter_add(core::ptr::addr_of_mut!((*stats).errors), 1);
            }
        }
    }

    let rk = RvKey { slot, _pad: 0, rv };
    if !rv_count_add(&rk) {
        bump_evidence(EVIDENCE_RV_UPDATE_FAILURES);
    }

    if flags & FLAG_POLICY_AGGREGATE != 0 {
        // Aggregate records nothing: retire the object side row (its
        // retire moved after emission) before the early return.
        if start.object_required != 0 && owned_start_remove(&key, true).is_err() {
            unsafe { p11_object_fault() };
            bump_evidence(EVIDENCE_UNMATCHED_RETURNS);
        }
        return 0;
    }

    // Physical ownership and successful settlement above guard aggregate pairing.
    // Image equality additionally guards retained semantic pointer reads.
    let mut image = ImageIdentity::default();
    if unsafe { p11_link_current_identity(&mut image) } != 1
        || !image_pair_matches(start.image, image)
    {
        // H7-E2: image refusal retires held object calls with a fault;
        // ordinary calls were already retired above and keep their
        // accounting-only refusal.
        if start.object_required != 0 {
            let _ = owned_start_remove(&key, true);
            unsafe { p11_object_fault() };
        }
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
    if start.object_required != 0 {
        // Slice D emission: reserve the complete 608-byte record BEFORE
        // any result/attribute read. Reservation failure performs no new
        // reads: disclose loss, clean ownership, keep the aggregate
        // return/RV accounting recorded above, and return.
        let descriptor = cookie_descriptor(cookie_of(&ctx));
        let rv = normalize_target_word(ctx.ret(), layout);
        let Some(mut entry) = EVENTS.reserve::<ObjectEventRecord>(0) else {
            if owned_start_remove(&key, true).is_err() {
                unsafe { p11_object_fault() };
            }
            bump_evidence(EVIDENCE_RING_LOSS);
            return 0;
        };
        // Populate in place under ownership: the base event and its
        // continuity land in the reserved record FIRST, then the join
        // gate runs before any object result read, then (with the S1
        // return-time mechanism evidence the return body just captured)
        // the result fills and tail sections. Any refusal discards: no
        // facts. A found continuity entry is not a join: only the full
        // stamp predicate authorizes result/Find/attribute reads.
        let raw = entry.as_mut_ptr();
        unsafe {
            core::ptr::write(core::ptr::addr_of_mut!((*raw).base.event), ev);
            let _ = p11_instance_return(&key, core::ptr::addr_of_mut!((*raw).base.continuity));
        }
        let joined = unsafe {
            stamp_joinable(
                core::ptr::addr_of!((*raw).base.continuity.entry_stamp).read(),
                core::ptr::addr_of!((*raw).base.continuity.return_stamp).read(),
            )
        };
        if !joined {
            let _ = owned_start_remove(&key, true);
            entry.discard(0);
            unsafe { p11_object_fault() };
            bump_evidence(EVIDENCE_UNMATCHED_RETURNS);
            return 0;
        }
        let tail = unsafe { core::ptr::addr_of_mut!((*raw).object) };
        let ready = unsafe { p11_object_side_get(&key, descriptor, 1).as_mut() };
        let filled = object_fill_return(
            &ctx,
            ready,
            layout,
            capture_flags & capture::MECHANISM_MASK,
            mechanism,
        );
        // Each emission level re-queries its side row like the entry
        // adapters: the helpers stay leaf-flat (no nested native query)
        // so their 64-byte frames fit the 512-byte return chain.
        let tail_side = unsafe { p11_object_side_get(&key, descriptor, 0).as_ref() };
        let tailed = filled && object_tail_fill(tail, tail_side, descriptor);
        let find_side = unsafe { p11_object_side_get(&key, descriptor, 0).as_ref() };
        let emitted = tailed && object_emit_find(tail, find_side, descriptor, layout, rv);
        // Submit the completed ring record only after successful
        // removal; otherwise discard it and fault. H7-E2: the retirement
        // is evaluated independently of emission success, so a failed
        // fill/emission still retires owned state and no read runs after
        // either failure.
        let retired = owned_start_remove(&key, true).is_ok();
        if !emitted || !retired {
            entry.discard(0);
            unsafe { p11_object_fault() };
            bump_evidence(EVIDENCE_UNMATCHED_RETURNS);
            return 0;
        }
        entry.submit(0);
        return 0;
    }
    match EVENTS.reserve::<EventRecord>(0) {
        Some(mut e) => {
            let raw = e.as_mut_ptr();
            // SAFETY: `raw` is the reserved, exclusively owned record. The
            // event is written as before; the native return half then fills
            // every byte of the private continuity tail in place.
            unsafe {
                core::ptr::write(core::ptr::addr_of_mut!((*raw).event), ev);
                let _ = p11_instance_return(&key, core::ptr::addr_of_mut!((*raw).continuity));
            }
            e.submit(0);
        }
        None => {
            bump_evidence(EVIDENCE_RING_LOSS);
        }
    }
    0
}

#[cfg(not(feature = "inventory-only"))]
#[unsafe(no_mangle)]
#[inline(never)]
pub extern "C" fn p11_link_fork_allowed() -> u32 {
    let Some(scope) = scope_auth() else {
        return 0;
    };
    // Fork birth records flow under cgroup and system scope alike; PID scope
    // tracks a single process and never needs them.
    if scope.flags & (FLAG_CGROUP_FILTER | FLAG_SYSTEM_FILTER) == 0 {
        return 0;
    }
    u32::from(scope.flags & FLAG_POLICY_AGGREGATE == 0)
}

#[cfg(not(feature = "inventory-only"))]
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
    // Every EVENTS record is an `EventRecord`; a FORK carries no call, so
    // its continuity tail is all zero (an invalid stamp).
    match EVENTS.reserve::<EventRecord>(0) {
        Some(mut event) => {
            event.write(EventRecord {
                event: ev,
                continuity: InstanceContinuity::default(),
            });
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
