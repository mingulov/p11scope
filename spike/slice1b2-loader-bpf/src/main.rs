#![no_std]
#![no_main]
#![feature(core_intrinsics)]
#![allow(internal_features)]

#[allow(dead_code)]
#[path = "../common.rs"]
mod common;

use aya_ebpf::helpers;
use aya_ebpf::macros::{map, uprobe};
use aya_ebpf::maps::{Array, HashMap, RingBuf};
use aya_ebpf::programs::ProbeContext;
use aya_ebpf::EbpfContext as _;
use common::{DiscoveryRecord, StartState, StateKey};
use common::{COOKIE_ID_MASK, COOKIE_PAYLOAD_SHIFT, COOKIE_STATE_PRESENT, PAUSE_ARMED, PAUSE_REQUESTED};

const RING_LOSS: u32 = 0;
const STATE_FAILURES: u32 = 1;
const LOADER_HITS: u32 = 2;
const STATE_READ_FAILURES: u32 = 3;
/// Diagnostic: hits whose attach cookie was the zero cookie (§7.3 negative).
const COOKIE_ZERO_HITS: u32 = 4;
/// Diagnostic: hits where the primary helper returned zero and the x86-64
/// probe-register fallback was used.
const FUNC_IP_ZERO_HITS: u32 = 5;
/// Corrective design §7.3: loader event records reuse the existing 896-byte
/// DiscoveryRecord with `kind = LOADER = 3`.
const LOADER: u8 = 3;
/// §7.3: existing internal `status_flags` bit 0x02 = coalesced_no_helper (the
/// §5.3 pause loser status), bit 0x04 = loader_context_invalid.
const STATUS_COALESCED: u8 = 0x02;
const STATUS_CONTEXT_INVALID: u8 = 0x04;
/// Frozen x86-64 `struct r_debug` layout: `r_state` sits at byte offset 24.
const R_STATE_OFFSET: u64 = 24;

#[map]
static DISCOVERY: RingBuf = RingBuf::with_byte_size(65_536, 0);

#[map]
static START: HashMap<StateKey, StartState> = HashMap::with_max_entries(64, 0);

#[map]
static COUNTERS: Array<u64> = Array::with_max_entries(6, 0);

fn increment_counter(index: u32) {
    if let Some(value) = COUNTERS.get_ptr_mut(index) {
        // SAFETY: the loader event source serializes one process's loader path;
        // concurrent BPF writers of one counter cell do not exist in the spike lanes.
        unsafe { *value += 1 };
    }
}

/// Corrective design §4.1/§4.4: exactly 112 straight-line
/// `write_volatile(words.add(K), 0u64)` calls, K = 0..=111, each once. The shape
/// guard `check-init-shape.py` scopes the function named `emit_discovery`, so
/// this artifact's emitter keeps that name.
macro_rules! zero_words {
    ($words:expr; $($k:literal),* $(,)?) => { $( core::ptr::write_volatile($words.add($k), 0u64); )* };
}

/// §5.2 group key: tgid in the high half, zero low half, cookie u64::MAX.
fn pause_owner_key() -> StateKey {
    StateKey {
        pid_tgid: (helpers::bpf_get_current_pid_tgid() >> 32) << 32,
        attach_cookie: u64::MAX,
    }
}

/// `bpf_get_func_ip` is the stable primary source, but Ubuntu's 5.15 uprobe
/// path returns zero. The x86-64 uprobe handler presents the adjusted probe
/// address in `pt_regs.rip`, so use that field only when the helper is empty.
#[inline(always)]
fn uprobe_runtime_ip(ctx: &ProbeContext) -> u64 {
    // SAFETY: the probe context is the kernel-provided context for this attachment.
    let helper_ip = unsafe { helpers::bpf_get_func_ip(ctx.as_ptr()) };
    if helper_ip != 0 {
        return helper_ip;
    }
    increment_counter(FUNC_IP_ZERO_HITS);
    // SAFETY: this spike is Linux x86-64-only and ProbeContext owns a valid pt_regs pointer.
    unsafe { (*ctx.regs).rip as u64 }
}

struct LoaderArgs {
    pid_tgid: u64,
    cookie: u64,
}

/// The loader every-hit record: reserve the 896-byte DiscoveryRecord, apply the
/// 112 guarded flat zero stores, then the §7.3 cookie path (invalid → bit 0x04,
/// submit, return; valid → hook IP + optional one 4-byte r_state read) and the
/// §5.3 pause path (owner CAS ARMED→REQUESTED, single winner bpf_send_signal,
/// loser sets bit 0x02), then fields and submit. `table_ptr` carries the private
/// `hook_ip` (§7.3: never serialized by userspace). The hook calls no
/// loader/provider code.
#[inline(never)]
fn emit_discovery(ctx: &ProbeContext, args: &LoaderArgs) {
    // 1. every hit counts before reservation (§7.1)
    increment_counter(LOADER_HITS);
    // 2. reserve before any authorization is consumed; loss submits nothing
    let Some(mut entry) = DISCOVERY.reserve::<DiscoveryRecord>(0) else {
        increment_counter(RING_LOSS);
        return;
    };
    let raw = entry.as_mut_ptr();
    let words = raw.cast::<u64>();
    // 3. helper-independent initialization (112 flat volatile zero stores)
    // SAFETY: reserve owns one writable 896-byte entry; DiscoveryRecord is repr(C),
    // aligned to 8, 112 u64 writes cover it exactly, and no reference/read/submit
    // occurs before initialization.
    unsafe {
        zero_words!(words;
            0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15,
            16, 17, 18, 19, 20, 21, 22, 23, 24, 25, 26, 27, 28, 29, 30, 31,
            32, 33, 34, 35, 36, 37, 38, 39, 40, 41, 42, 43, 44, 45, 46, 47,
            48, 49, 50, 51, 52, 53, 54, 55, 56, 57, 58, 59, 60, 61, 62, 63,
            64, 65, 66, 67, 68, 69, 70, 71, 72, 73, 74, 75, 76, 77, 78, 79,
            80, 81, 82, 83, 84, 85, 86, 87, 88, 89, 90, 91, 92, 93, 94, 95,
            96, 97, 98, 99, 100, 101, 102, 103, 104, 105, 106, 107, 108, 109, 110, 111,
        );
    }
    // 4. §7.3 cookie validation: zero cookie, or absent state with a payload
    //    other than sentinel 1, is loader_context_invalid — no ID extraction, no
    //    IP/delta arithmetic, no state read, no pause.
    let zero_cookie = args.cookie == 0;
    if zero_cookie {
        increment_counter(COOKIE_ZERO_HITS);
    }
    let state_present = args.cookie & COOKIE_STATE_PRESENT != 0;
    let invalid_absent = !state_present && args.cookie >> COOKIE_PAYLOAD_SHIFT != 1;
    let invalid = zero_cookie || invalid_absent;
    // SAFETY: the cookie is a scalar validated above; the shift mirrors the
    // §7.3 signed 55-bit two's-complement decode.
    let delta: i64 = (args.cookie as i64) >> COOKIE_PAYLOAD_SHIFT;
    let mut status: u8 = 0;
    let mut hook_ip: u64 = 0;
    let mut r_state: u32 = 0;
    // SAFETY: this helper takes no pointers and has no preconditions.
    let mut hook_ts_ns = unsafe { helpers::bpf_ktime_get_ns() };
    if !invalid {
        // 5. §7.3 valid path: hook IP (reject zero), then only when state is
        //    present apply the checked signed delta and make exactly one
        //    4-byte r_state read; overflow/helper failure never drops the record.
        hook_ip = uprobe_runtime_ip(ctx);
        if hook_ip == 0 {
            status |= STATUS_CONTEXT_INVALID;
        } else if state_present {
            // §7.3: checked signed delta, then checked-add exactly 24. Overflow is a
            // state-address failure (STATE_READ_FAILURES), never a dropped record.
            let state_address = hook_ip
                .checked_add_signed(delta)
                .and_then(|r_debug| r_debug.checked_add(R_STATE_OFFSET));
            match state_address {
                Some(address) => {
                    // SAFETY: one bounded 4-byte user read at the frozen r_state offset.
                    match unsafe { helpers::bpf_probe_read_user(address as *const u32) } {
                        Ok(state) => r_state = state,
                        Err(_) => increment_counter(STATE_READ_FAILURES),
                    }
                }
                None => increment_counter(STATE_READ_FAILURES),
            }
        }
    } else {
        status |= STATUS_CONTEXT_INVALID;
    }
    // 6. §5.3 pause path — only for a validated context: the owner CAS decides
    //    the single signal helper caller; the loser records bit 0x02.
    //    `core::sync::atomic::AtomicU64::compare_exchange` does not exist on
    //    bpfel-unknown-none; the core intrinsic lowers to BPF_CMPXCHG.
    if status & STATUS_CONTEXT_INVALID == 0 {
        let won = match START.get_ptr_mut(&pause_owner_key()) {
            // SAFETY: the pointer addresses a live map value; this CAS is the only BPF writer of arg0.
            Some(state) => unsafe {
                core::intrinsics::atomic_cxchg::<
                    u64,
                    { core::intrinsics::AtomicOrdering::AcqRel },
                    { core::intrinsics::AtomicOrdering::Acquire },
                >(core::ptr::addr_of_mut!((*state).arg0), PAUSE_ARMED, PAUSE_REQUESTED)
                    .1
            },
            None => false,
        };
        if won {
            // The causal timestamp is sampled immediately before the one signal request.
            // SAFETY: these helpers take no pointers and SIGSTOP is a valid scalar signal.
            hook_ts_ns = unsafe { helpers::bpf_ktime_get_ns() };
            let _ = unsafe { helpers::bpf_send_signal(19) };
        } else {
            status |= STATUS_COALESCED;
        }
    }
    // 7. finish initialization and submit the every-hit record
    // SAFETY: same reserved entry; all fields written after the zero stores.
    unsafe {
        core::ptr::write(core::ptr::addr_of_mut!((*raw).hook_ts_ns), hook_ts_ns);
        core::ptr::write(core::ptr::addr_of_mut!((*raw).pid_tgid), args.pid_tgid);
        core::ptr::write(core::ptr::addr_of_mut!((*raw).table_ptr), hook_ip);
        core::ptr::write(core::ptr::addr_of_mut!((*raw).kind), LOADER);
        if !invalid {
            // §7.3: the context ID byte is copied into case_id only after validation.
            core::ptr::write(
                core::ptr::addr_of_mut!((*raw).case_id),
                (args.cookie & COOKIE_ID_MASK) as u8,
            );
        }
        core::ptr::write(core::ptr::addr_of_mut!((*raw).status_flags), status);
        core::ptr::write(core::ptr::addr_of_mut!((*raw).announced_count), r_state);
    }
    entry.submit(0);
}

/// §7.3 loader event source. Scope is enforced by the one-process attachment
/// (no loader-context BPF map exists; §7.3 forbids one), so the program itself
/// needs no pid comparison.
#[uprobe]
pub fn dl_debug_state(ctx: ProbeContext) -> u32 {
    // SAFETY: the probe context is the kernel-provided context for this attachment.
    let cookie = unsafe { helpers::bpf_get_attach_cookie(ctx.as_ptr()) };
    emit_discovery(
        &ctx,
        &LoaderArgs {
            pid_tgid: helpers::bpf_get_current_pid_tgid(),
            cookie,
        },
    );
    0
}

#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    loop {}
}
