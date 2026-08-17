#![no_std]
#![no_main]

#[allow(dead_code)]
#[path = "../../common.rs"]
mod common;

use aya_ebpf::helpers;
use aya_ebpf::macros::{map, uprobe, uretprobe};
use aya_ebpf::maps::{Array, HashMap, RingBuf};
use aya_ebpf::programs::{ProbeContext, RetProbeContext};
use common::{DiscoveryRecord, StartState, StateKey};

const RING_LOSS: u32 = 0;
const READ_FAILURES: u32 = 1;
const STATE_FAILURES: u32 = 2;
const TRUNCATED: u32 = 3;
const FUNCTION_LIST: u8 = 1;
const INTERFACE: u8 = 2;
const EXACT_STANDARD: u8 = 1;
const OTHER: u8 = 2;
const NULL: u8 = 3;
const UNREADABLE: u8 = 4;

#[map]
static EVENTS: RingBuf = RingBuf::with_byte_size(262_144, 0);

#[map]
static DISCOVERY: RingBuf = RingBuf::with_byte_size(65_536, 0);

#[map]
static START: HashMap<StateKey, StartState> = HashMap::with_max_entries(64, 0);

#[map]
static COUNTERS: Array<u64> = Array::with_max_entries(5, 0);

fn increment_counter(index: u32) {
    if let Some(value) = COUNTERS.get_ptr_mut(index) {
        // SAFETY: Gate A serializes fixture calls, so no two probes update a cell concurrently.
        unsafe { *value += 1 };
    }
}

fn state_key<C: aya_ebpf::EbpfContext>(ctx: &C) -> StateKey {
    StateKey {
        pid_tgid: helpers::bpf_get_current_pid_tgid(),
        // SAFETY: the probe context is the kernel-provided context for this attachment.
        attach_cookie: unsafe { helpers::bpf_get_attach_cookie(ctx.as_ptr()) },
    }
}

fn insert_start(key: StateKey, state: StartState) {
    let inserted = START.insert(&key, &state, aya_ebpf::bindings::BPF_NOEXIST as u64);
    if inserted.is_err() {
        increment_counter(STATE_FAILURES);
    }
}

fn take_start<C: aya_ebpf::EbpfContext>(ctx: &C) -> Option<(StateKey, StartState)> {
    let key = state_key(ctx);
    let Some(state) = START.get_ptr(&key) else {
        increment_counter(STATE_FAILURES);
        return None;
    };
    // SAFETY: the map value remains live until the immediately following remove.
    let state = unsafe { core::ptr::read(state) };
    if START.remove(&key).is_err() {
        increment_counter(STATE_FAILURES);
        return None;
    }
    Some((key, state))
}

struct EmitArgs {
    kind: u8,
    case_id: u8,
    interface_index: u8,
    name_class: u8,
    interface_flags: u64,
    table_ptr: u64,
    announced_count: u32,
    read_table: bool,
}

fn emit_discovery(args: &EmitArgs) {
    let Some(mut entry) = DISCOVERY.reserve::<DiscoveryRecord>(0) else {
        increment_counter(RING_LOSS);
        return;
    };
    let raw = entry.as_mut_ptr();
    let words = raw.cast::<u64>();
    let mut read_failed = false;
    let mut attempted = 0u8;
    let mut completed = 0u8;
    let mut version_major = 0u8;
    let mut version_minor = 0u8;
    // SAFETY: reserve owns one writable 896-byte entry; DiscoveryRecord is repr(C), aligned to 8,
    // 112 u64 writes cover it exactly, and no reference/read/submit occurs before initialization.
    unsafe {
        let mut word = 0usize;
        while word < 112 {
            core::ptr::write(words.add(word), 0);
            word += 1;
        }
        if args.read_table {
            match helpers::bpf_probe_read_user(args.table_ptr as *const [u8; 2]) {
                Ok(version) => {
                    version_major = version[0];
                    version_minor = version[1];
                    if version == [3, 2] {
                        let mut pointer_index = 0usize;
                        while pointer_index < 104 {
                            attempted += 1;
                            let address = args.table_ptr + 8 + pointer_index as u64 * 8;
                            match helpers::bpf_probe_read_user(address as *const u64) {
                                Ok(pointer) => {
                                    core::ptr::write(
                                        core::ptr::addr_of_mut!((*raw).pointers[pointer_index]),
                                        pointer,
                                    );
                                    completed += 1;
                                }
                                Err(_) => {
                                    read_failed = true;
                                    break;
                                }
                            }
                            pointer_index += 1;
                        }
                    }
                }
                Err(_) => read_failed = true,
            }
        }
        core::ptr::write(
            core::ptr::addr_of_mut!((*raw).hook_ts_ns),
            helpers::bpf_ktime_get_ns(),
        );
        core::ptr::write(
            core::ptr::addr_of_mut!((*raw).pid_tgid),
            helpers::bpf_get_current_pid_tgid(),
        );
        core::ptr::write(core::ptr::addr_of_mut!((*raw).table_ptr), args.table_ptr);
        core::ptr::write(
            core::ptr::addr_of_mut!((*raw).interface_flags),
            args.interface_flags,
        );
        core::ptr::write(core::ptr::addr_of_mut!((*raw).kind), args.kind);
        core::ptr::write(core::ptr::addr_of_mut!((*raw).case_id), args.case_id);
        core::ptr::write(
            core::ptr::addr_of_mut!((*raw).interface_index),
            args.interface_index,
        );
        core::ptr::write(core::ptr::addr_of_mut!((*raw).name_class), args.name_class);
        core::ptr::write(
            core::ptr::addr_of_mut!((*raw).status_flags),
            u8::from(read_failed),
        );
        core::ptr::write(
            core::ptr::addr_of_mut!((*raw).usable_n),
            if read_failed { 0 } else { completed },
        );
        core::ptr::write(
            core::ptr::addr_of_mut!((*raw).pointers_attempted),
            attempted,
        );
        core::ptr::write(core::ptr::addr_of_mut!((*raw).completed_prefix), completed);
        core::ptr::write(core::ptr::addr_of_mut!((*raw).version_major), version_major);
        core::ptr::write(core::ptr::addr_of_mut!((*raw).version_minor), version_minor);
        core::ptr::write(
            core::ptr::addr_of_mut!((*raw).announced_count),
            args.announced_count,
        );
    }
    if read_failed {
        increment_counter(READ_FAILURES);
    }
    entry.submit(0);
}

#[inline(never)]
fn emit_interface(
    base: u64,
    case_id: u8,
    interface_index: usize,
    announced_count: u32,
) -> bool {
    let address = base + interface_index as u64 * 24;
    // SAFETY: each bounded address names one live fixture CK_INTERFACE value.
    let Ok([name, table, flags]) =
        (unsafe { helpers::bpf_probe_read_user(address as *const [u64; 3]) })
    else {
        increment_counter(READ_FAILURES);
        return false;
    };
    let name_class = if name == 0 {
        NULL
    } else {
        let mut bytes = [0u8; 8];
        // SAFETY: the helper bounds the read to the private stack buffer.
        let read = unsafe {
            helpers::generated::bpf_probe_read_user_str(
                bytes.as_mut_ptr().cast(),
                bytes.len() as u32,
                name as *const core::ffi::c_void,
            )
        };
        if read < 0 {
            increment_counter(READ_FAILURES);
            UNREADABLE
        } else if read == 8 && bytes == *b"PKCS 11\0" {
            EXACT_STANDARD
        } else {
            OTHER
        }
    };
    emit_discovery(&EmitArgs {
        kind: INTERFACE,
        case_id,
        interface_index: interface_index as u8,
        name_class,
        interface_flags: flags,
        table_ptr: table,
        announced_count,
        read_table: name_class == EXACT_STANDARD,
    });
    true
}

#[uprobe]
pub fn function_list_entry(ctx: ProbeContext) -> u32 {
    let key = state_key(&ctx);
    insert_start(
        key,
        StartState {
            arg0: ctx.arg::<u64>(0).unwrap_or(0),
            arg1: 0,
        },
    );
    0
}

#[uretprobe]
pub fn function_list_return(ctx: RetProbeContext) -> u32 {
    let Some((key, state)) = take_start(&ctx) else {
        return 0;
    };
    // SAFETY: the pointer is the live first argument captured by the matching entry probe.
    match unsafe { helpers::bpf_probe_read_user(state.arg0 as *const u64) } {
        Ok(table_ptr) => emit_discovery(&EmitArgs {
            kind: FUNCTION_LIST,
            case_id: key.attach_cookie as u8,
            interface_index: 0,
            name_class: 0,
            interface_flags: 0,
            table_ptr,
            announced_count: 0,
            read_table: true,
        }),
        Err(_) => {
            increment_counter(READ_FAILURES);
            emit_discovery(&EmitArgs {
                kind: FUNCTION_LIST,
                case_id: key.attach_cookie as u8,
                interface_index: 0,
                name_class: 0,
                interface_flags: 0,
                table_ptr: 0,
                announced_count: 0,
                read_table: false,
            });
        }
    }
    0
}

#[uprobe]
pub fn interface_list_entry(ctx: ProbeContext) -> u32 {
    let key = state_key(&ctx);
    insert_start(
        key,
        StartState {
            arg0: ctx.arg::<u64>(0).unwrap_or(0),
            arg1: ctx.arg::<u64>(1).unwrap_or(0),
        },
    );
    0
}

#[uretprobe]
pub fn interface_list_return(ctx: RetProbeContext) -> u32 {
    let Some((key, state)) = take_start(&ctx) else {
        return 0;
    };
    // SAFETY: the pointer is the live count argument captured by the matching entry probe.
    let Ok(count) = (unsafe { helpers::bpf_probe_read_user(state.arg1 as *const u64) }) else {
        increment_counter(READ_FAILURES);
        return 0;
    };
    if count > 16 {
        increment_counter(TRUNCATED);
    }
    let announced_count = count.min(u32::MAX as u64) as u32;
    let mut interface_index = 0usize;
    while interface_index < 16 {
        if interface_index as u64 >= count {
            break;
        }
        if !emit_interface(
            state.arg0,
            key.attach_cookie as u8,
            interface_index,
            announced_count,
        ) {
            break;
        }
        interface_index += 1;
    }
    0
}

#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    loop {}
}
