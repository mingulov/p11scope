//! Types shared verbatim between the BPF programs and userspace. Every
//! type is `#[repr(C)]` with no padding surprises: both sides read the
//! same bytes out of the same map.
#![no_std]

/// Attach slots. One slot per unique {object, file_offset} target, not
/// per function name — aliased names share a slot by construction.
/// 512 covers the 104-entry 3.2 table several times over.
pub const MAX_SLOTS: u32 = 512;

/// Fixed static policy descriptors: count-only plus the 104 canonical
/// PKCS#11 function-table entries.
pub const MAX_DESCRIPTORS: u32 = 105;

/// Encode one static-slot attachment cookie. The low word remains the slot so
/// STATS, RV_COUNTS, START, and Event.slot keep their existing ABI.
pub const fn attach_cookie(slot: u32, descriptor: u32) -> u64 {
    slot as u64 | ((descriptor as u64) << 32)
}

/// Decode the aggregate slot from a static-slot attachment cookie.
pub const fn cookie_slot(cookie: u64) -> u32 {
    cookie as u32
}

/// Decode the fixed descriptor index from a static-slot attachment cookie.
pub const fn cookie_descriptor(cookie: u64) -> u32 {
    (cookie >> 32) as u32
}

/// No argument is captured for this descriptor field.
pub const ARG_NONE: u8 = u8::MAX;

/// Per-slot capture and state-machine description. Every byte is fixed
/// userspace policy; BPF only follows these allowlisted indices.
#[repr(C)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SlotSemantics {
    pub operations: u16,
    pub transition: u8,
    pub lifecycle: u8,
    pub direct: u8,
    pub semantic_flags: u8,
    pub session_arg: u8,
    pub slot_arg: u8,
    pub mechanism_arg: u8,
    pub output_arg: u8,
    pub flags_arg: u8,
    pub user_type_arg: u8,
    pub template0_arg: u8,
    pub template_count0_arg: u8,
    pub template1_arg: u8,
    pub template_count1_arg: u8,
    pub async_name_arg: u8,
    pub async_value_arg: u8,
}

impl SlotSemantics {
    pub const COUNT_ONLY: Self = Self {
        operations: 0,
        transition: transition::NONE,
        lifecycle: lifecycle::NONE,
        direct: direct::NONE,
        semantic_flags: 0,
        session_arg: ARG_NONE,
        slot_arg: ARG_NONE,
        mechanism_arg: ARG_NONE,
        output_arg: ARG_NONE,
        flags_arg: ARG_NONE,
        user_type_arg: ARG_NONE,
        template0_arg: ARG_NONE,
        template_count0_arg: ARG_NONE,
        template1_arg: ARG_NONE,
        template_count1_arg: ARG_NONE,
        async_name_arg: ARG_NONE,
        async_value_arg: ARG_NONE,
    };

    #[cfg(feature = "user")]
    pub fn argument_indices(&self) -> impl Iterator<Item = u8> {
        [
            self.session_arg,
            self.slot_arg,
            self.mechanism_arg,
            self.output_arg,
            self.flags_arg,
            self.user_type_arg,
            self.template0_arg,
            self.template_count0_arg,
            self.template1_arg,
            self.template_count1_arg,
            self.async_name_arg,
            self.async_value_arg,
        ]
        .into_iter()
        .filter(|index| *index != ARG_NONE)
    }
}

pub mod operation {
    pub const DIGEST: u16 = 1 << 0;
    pub const SIGN: u16 = 1 << 1;
    pub const VERIFY: u16 = 1 << 2;
    pub const ENCRYPT: u16 = 1 << 3;
    pub const DECRYPT: u16 = 1 << 4;
    pub const SIGN_RECOVER: u16 = 1 << 5;
    pub const VERIFY_RECOVER: u16 = 1 << 6;
    pub const MESSAGE_ENCRYPT: u16 = 1 << 7;
    pub const MESSAGE_DECRYPT: u16 = 1 << 8;
    pub const MESSAGE_SIGN: u16 = 1 << 9;
    pub const MESSAGE_VERIFY: u16 = 1 << 10;
}

pub mod transition {
    pub const NONE: u8 = 0;
    pub const INITIALIZE: u8 = 1;
    pub const CONTINUE: u8 = 2;
    pub const UPDATE_WITH_OUTPUT: u8 = 3;
    pub const FINISH_WITH_OUTPUT: u8 = 4;
    pub const FINISH_ALWAYS: u8 = 5;
    pub const RETAIN_ALWAYS: u8 = 6;
    pub const FINISH_ON_SUCCESS: u8 = 7;
}

pub mod lifecycle {
    pub const NONE: u8 = 0;
    pub const OPEN_SESSION: u8 = 1;
    pub const CLOSE_SESSION: u8 = 2;
    pub const CLOSE_ALL_SESSIONS: u8 = 3;
    pub const FINALIZE: u8 = 4;
    pub const LOGIN: u8 = 5;
    pub const LOGOUT: u8 = 6;
    pub const FIND_INIT: u8 = 7;
    pub const FIND_FINAL: u8 = 8;
    pub const SESSION_CANCEL: u8 = 9;
    pub const SET_OPERATION_STATE: u8 = 10;
    pub const ASYNC_COMPLETE: u8 = 11;
    pub const ASYNC_GET_ID: u8 = 12;
    pub const ASYNC_JOIN: u8 = 13;
    /// C_FindObjects while a search is active; success keeps it active.
    pub const FIND_OPERATION: u8 = 14;
}

pub mod direct {
    pub const NONE: u8 = 0;
    pub const GENERATE_KEY: u8 = 1;
    pub const GENERATE_KEY_PAIR: u8 = 2;
    pub const WRAP: u8 = 3;
    pub const UNWRAP: u8 = 4;
    pub const DERIVE: u8 = 5;
    pub const ENCAPSULATE: u8 = 6;
    pub const DECAPSULATE: u8 = 7;
    pub const WRAP_AUTHENTICATED: u8 = 8;
    pub const UNWRAP_AUTHENTICATED: u8 = 9;
}

pub mod semantic_flags {
    /// A successful NULL pMechanism cancels the named operation.
    pub const NULL_MECHANISM_CANCEL: u8 = 1 << 0;
    /// Template values are outputs; capture attribute types only.
    pub const TEMPLATE0_TYPES_ONLY: u8 = 1 << 1;
}

/// Log2 latency buckets: bucket i holds durations in [2^(i-1), 2^i) ns,
/// bucket 0 holds 0ns, bucket 31 is a catch-all for >= 2^30 ns (~1.07s).
pub const LATENCY_BUCKETS: usize = 32;

/// CONFIG map indices.
pub const CFG_FLAGS: u32 = 0;
/// Packed `sched_process_fork` field offsets, present only for cgroup event
/// capture. The low CONFIG cell remains the sole scope/policy owner.
pub const CFG_FORK_OFFSETS: u32 = 1;
/// Bit shift of the packed parent PID field offset.
pub const CFG_FORK_PARENT_OFFSET: u32 = 0;
/// Bit shift of the packed child PID field offset.
pub const CFG_FORK_CHILD_OFFSET: u32 = 16;
const CFG_FORK_OFFSET_MASK: u64 = u16::MAX as u64;
const CFG_FORK_OFFSETS_VALID: u64 = 1 << 32;
const CFG_FORK_OFFSETS_KNOWN: u64 = CFG_FORK_OFFSETS_VALID
    | (CFG_FORK_OFFSET_MASK << CFG_FORK_PARENT_OFFSET)
    | (CFG_FORK_OFFSET_MASK << CFG_FORK_CHILD_OFFSET);

/// Pack checked tracepoint offsets into the second CONFIG cell.
pub const fn pack_fork_offsets(parent: u16, child: u16) -> u64 {
    CFG_FORK_OFFSETS_VALID
        | ((parent as u64) << CFG_FORK_PARENT_OFFSET)
        | ((child as u64) << CFG_FORK_CHILD_OFFSET)
}

/// Decode a packed fork-offset cell, rejecting absence and unknown bits.
pub const fn unpack_fork_offsets(value: u64) -> Option<(usize, usize)> {
    if value & CFG_FORK_OFFSETS_VALID == 0 || value & !CFG_FORK_OFFSETS_KNOWN != 0 {
        return None;
    }
    Some((
        ((value >> CFG_FORK_PARENT_OFFSET) & CFG_FORK_OFFSET_MASK) as usize,
        ((value >> CFG_FORK_CHILD_OFFSET) & CFG_FORK_OFFSET_MASK) as usize,
    ))
}

/// CONFIG flag bits.
pub const FLAG_PID_FILTER: u64 = 1 << 0;
pub const FLAG_CGROUP_FILTER: u64 = 1 << 1;
pub const FLAG_POLICY_ALLOWLISTED: u64 = 1 << 2;
pub const FLAG_POLICY_UNSAFE_UNVALIDATED_METADATA: u64 = 1 << 3;
pub const FLAG_POLICY_AGGREGATE: u64 = 1 << 4;
pub const FLAG_PAUSE_ENABLED: u64 = 1 << 5;

/// A loaded program may observe only an explicitly selected scope under one
/// immutable capture policy. Unknown and multi-bit configurations fail closed.
pub const fn valid_config(flags: u64) -> bool {
    let scope = flags & (FLAG_PID_FILTER | FLAG_CGROUP_FILTER);
    let policy = flags
        & (FLAG_POLICY_ALLOWLISTED
            | FLAG_POLICY_UNSAFE_UNVALIDATED_METADATA
            | FLAG_POLICY_AGGREGATE);
    let known = FLAG_PID_FILTER
        | FLAG_CGROUP_FILTER
        | FLAG_POLICY_ALLOWLISTED
        | FLAG_POLICY_UNSAFE_UNVALIDATED_METADATA
        | FLAG_POLICY_AGGREGATE
        | FLAG_PAUSE_ENABLED;
    matches!(scope, FLAG_PID_FILTER | FLAG_CGROUP_FILTER)
        && matches!(
            policy,
            FLAG_POLICY_ALLOWLISTED
                | FLAG_POLICY_UNSAFE_UNVALIDATED_METADATA
                | FLAG_POLICY_AGGREGATE
        )
        && flags & !known == 0
        && (flags & FLAG_PAUSE_ENABLED == 0 || scope == FLAG_PID_FILTER)
}

pub const DISCOVERY_KIND_FUNCTION_LIST_RETURN: u8 = 1;
pub const DISCOVERY_KIND_INTERFACE_LIST_ELEMENT_RETURN: u8 = 2;
pub const DISCOVERY_KIND_LOADER: u8 = 3;
pub const DISCOVERY_KIND_INTERFACE_RETURN: u8 = 4;
pub const DISCOVERY_KIND_EXEC: u8 = 5;
pub const DISCOVERY_KIND_LEADER_EXIT: u8 = 6;

pub const DISCOVERY_NAME_NA: u8 = 0;
pub const DISCOVERY_NAME_EXACT_STANDARD: u8 = 1;
pub const DISCOVERY_NAME_OTHER: u8 = 2;
pub const DISCOVERY_NAME_NULL: u8 = 3;
pub const DISCOVERY_NAME_UNREADABLE: u8 = 4;

pub const DISCOVERY_VERSION_NULL: u8 = 0;
pub const DISCOVERY_VERSION_UNREADABLE: u8 = 1;
pub const DISCOVERY_VERSION_V2_40: u8 = 2;
pub const DISCOVERY_VERSION_V3_0: u8 = 3;
pub const DISCOVERY_VERSION_V3_1: u8 = 4;
pub const DISCOVERY_VERSION_V3_2: u8 = 5;
pub const DISCOVERY_VERSION_OTHER: u8 = 6;

pub const DISCOVERY_STATUS_READ_FAILURE: u8 = 0x01;
pub const DISCOVERY_STATUS_COALESCED_NO_HELPER: u8 = 0x02;
pub const DISCOVERY_STATUS_LOADER_CONTEXT_INVALID: u8 = 0x04;

pub const DISCOVERY_COUNTER_RING_LOSS: u32 = 0;
pub const DISCOVERY_COUNTER_EXPORT_STATE_FAILURES: u32 = 1;
pub const DISCOVERY_COUNTER_EXPORT_BOUNDED_READ_FAILURES: u32 = 2;
pub const DISCOVERY_COUNTER_LOADER_HITS: u32 = 3;
pub const DISCOVERY_COUNTER_LOADER_STATE_READ_FAILURES: u32 = 4;
pub const DISCOVERY_COUNTER_CELLS: u32 = 5;

pub const PAUSE_ARMED: u64 = 1;
pub const PAUSE_REQUESTED: u64 = 2;
pub const COALESCED_NO_HELPER_RC: i64 = i64::MIN;

pub const DISCOVERY_POINTERS: usize = 104;
pub const DISCOVERY_INTERFACES: u8 = 16;
pub const TAIL_CALLS_INTERFACE_WORKER_SLOT: u32 = 0;
pub const TAIL_CALLS_TEMPLATE_SECOND_SLOT: u32 = 1;
#[cfg(not(feature = "small-discovery-ring"))]
pub const DISCOVERY_BYTES: u32 = 65_536;
#[cfg(feature = "small-discovery-ring")]
pub const DISCOVERY_BYTES: u32 = 4_096;

pub const LOADER_CONTEXT_ID_MASK: u64 = 0xff;
pub const LOADER_STATE_PRESENT: u64 = 1 << 8;
pub const LOADER_STATE_SHIFT: u32 = 9;
pub const LOADER_STATE_PAYLOAD_MASK: u64 = (1u64 << 55) - 1;
pub const LOADER_STATE_ABSENT_SENTINEL: u64 = 1;
pub const R_STATE_OFFSET: u64 = 24;
pub const STATE_DOMAIN_EXPORT: u64 = 1;
pub const STATE_DOMAIN_SELECTION: u64 = 2;

pub const fn discovery_table_slots(version_major: u8, version_minor: u8) -> u8 {
    match (version_major, version_minor) {
        (2, 0) => 67,
        (2, _) => 68,
        (3, 0 | 1) => 92,
        (3, 2..) => 104,
        _ => 0,
    }
}

pub const fn discovery_version_class(major: u8, minor: u8) -> u8 {
    match (major, minor) {
        (2, 40) => DISCOVERY_VERSION_V2_40,
        (3, 0) => DISCOVERY_VERSION_V3_0,
        (3, 1) => DISCOVERY_VERSION_V3_1,
        (3, 2) => DISCOVERY_VERSION_V3_2,
        _ => DISCOVERY_VERSION_OTHER,
    }
}

pub const fn discovery_usable_prefix(read_failed: bool, completed: u8) -> u8 {
    if read_failed {
        0
    } else {
        completed
    }
}

pub const fn valid_loader_cookie(cookie: u64) -> bool {
    let state_present = cookie & LOADER_STATE_PRESENT != 0;
    let payload = cookie >> LOADER_STATE_SHIFT;
    cookie != 0 && (state_present || payload == LOADER_STATE_ABSENT_SENTINEL)
}

pub const fn discovery_pause_enabled(eligible: bool, flags: u64, generation_token: u64) -> bool {
    eligible && flags & FLAG_PAUSE_ENABLED != 0 && generation_token != 0
}

pub const fn discovery_pause_coalesced(previous: u64, won: bool) -> bool {
    !won && previous == PAUSE_REQUESTED
}

pub const fn discovery_state_take_failed(state_present: bool, removed: bool) -> bool {
    !state_present || !removed
}

/// Pack the export identity, bounded interface-list count, and index.
/// Values above the ABI's u32 count saturate. Zero and oversized symbol IDs
/// fail closed because only 24 bits remain after the count and index.
pub const fn interface_continuation_pack(
    announced_count: u64,
    index: u8,
    symbol_id: u32,
) -> Option<u64> {
    if symbol_id == 0 || symbol_id > 0x00ff_ffff {
        return None;
    }
    let saturated_count = if announced_count > u32::MAX as u64 {
        u32::MAX
    } else {
        announced_count as u32
    };
    Some(((symbol_id as u64) << 40) | ((saturated_count as u64) << 8) | index as u64)
}

/// Decode a continuation only when its identity and finite bounds hold.
pub const fn interface_continuation_unpack(value: u64) -> Option<(u32, u8, u32)> {
    let symbol_id = (value >> 40) as u32;
    if symbol_id == 0 {
        return None;
    }
    let announced_count = ((value >> 8) & u32::MAX as u64) as u32;
    let index = value as u8;
    let active_count = if announced_count < DISCOVERY_INTERFACES as u32 {
        announced_count
    } else {
        DISCOVERY_INTERFACES as u32
    };
    if index >= DISCOVERY_INTERFACES || index as u32 >= active_count {
        None
    } else {
        Some((announced_count, index, symbol_id))
    }
}

/// Advance a valid continuation, or finish after its last bounded interface.
pub const fn interface_continuation_next(value: u64) -> Option<u64> {
    let Some((announced_count, index, symbol_id)) = interface_continuation_unpack(value) else {
        return None;
    };
    let next = index + 1;
    let active_count = if announced_count < DISCOVERY_INTERFACES as u32 {
        announced_count
    } else {
        DISCOVERY_INTERFACES as u32
    };
    if next as u32 >= active_count {
        None
    } else {
        interface_continuation_pack(announced_count as u64, next, symbol_id)
    }
}

#[repr(C)]
#[derive(Clone, Copy)]
pub struct DiscoveryRecord {
    pub hook_ts_ns: u64,
    pub pid_tgid: u64,
    pub table_ptr: u64,
    pub interface_flags: u64,
    pub pointers: [u64; DISCOVERY_POINTERS],
    pub kind: u8,
    pub case_id: u8,
    pub interface_index: u8,
    pub name_class: u8,
    pub status_flags: u8,
    pub usable_n: u8,
    pub pointers_attempted: u8,
    pub completed_prefix: u8,
    pub version_major: u8,
    pub version_minor: u8,
    pub selection_version_class: u8,
    pub reserved_zero: [u8; 1],
    pub symbol_id: u32,
    pub announced_count: u32,
    pub reserved_tail_zero: [u8; 4],
    pub send_signal_rc: i64,
    /// Full CK_RV for kind 4; zero is the successful outcome.
    pub return_rv: u64,
    /// Full request CK_FLAGS for kind 4.
    pub request_flags: u64,
    /// Full-width private selection binding id for kind 4.
    pub binding_id: u64,
}

#[repr(C)]
#[derive(Debug, Clone, Copy, Eq, PartialEq)]
pub struct StateKey {
    pub pid_tgid: u64,
    pub attach_cookie: u64,
    pub domain: u64,
}

#[repr(C)]
#[derive(Debug, Clone, Copy, Eq, PartialEq)]
pub struct StartState {
    pub arg0: u64,
    pub arg1: u64,
    pub arg2: u64,
}

#[repr(C)]
#[derive(Debug, Clone, Copy, Eq, PartialEq)]
pub struct PauseKey {
    pub tgid: u32,
    pub pad: u32,
    pub generation_token: u64,
}

fn zero_discovery_payload(record: &DiscoveryRecord) -> bool {
    record.table_ptr == 0
        && record.interface_flags == 0
        && record.pointers.iter().all(|pointer| *pointer == 0)
        && record.interface_index == 0
        && record.name_class == DISCOVERY_NAME_NA
        && record.usable_n == 0
        && record.pointers_attempted == 0
        && record.completed_prefix == 0
        && record.version_major == 0
        && record.version_minor == 0
        && record.selection_version_class == 0
        && record.symbol_id == 0
        && record.return_rv == 0
        && record.request_flags == 0
        && record.binding_id == 0
}

fn zero_selection_payload(record: &DiscoveryRecord) -> bool {
    record.return_rv == 0
        && record.request_flags == 0
        && record.binding_id == 0
        && record.selection_version_class == 0
}

fn valid_export_prefix(record: &DiscoveryRecord) -> bool {
    if record.pointers_attempted as usize > DISCOVERY_POINTERS
        || record.completed_prefix > record.pointers_attempted
        || record.usable_n > record.completed_prefix
        || (record.status_flags & DISCOVERY_STATUS_READ_FAILURE != 0 && record.usable_n != 0)
        || (record.status_flags & DISCOVERY_STATUS_READ_FAILURE == 0
            && record.usable_n != record.completed_prefix)
    {
        return false;
    }
    record.pointers[record.completed_prefix as usize..]
        .iter()
        .all(|pointer| *pointer == 0)
}

/// Structural validation owned by the raw transport. Loader registry and
/// process-generation agreement remain Task 6 responsibilities.
pub fn valid_discovery_record(record: &DiscoveryRecord) -> bool {
    if record.reserved_zero != [0; 1]
        || record.reserved_tail_zero != [0; 4]
        || (record.status_flags & DISCOVERY_STATUS_COALESCED_NO_HELPER != 0)
            != (record.send_signal_rc == COALESCED_NO_HELPER_RC)
        || (record.send_signal_rc != COALESCED_NO_HELPER_RC
            && record.send_signal_rc != i64::from(record.send_signal_rc as i32))
    {
        return false;
    }

    match record.kind {
        DISCOVERY_KIND_FUNCTION_LIST_RETURN => {
            record.status_flags <= 0x03
                && record.case_id == 0
                && record.interface_index == 0
                && record.name_class == DISCOVERY_NAME_NA
                && record.interface_flags == 0
                && record.symbol_id != 0
                && record.announced_count == 0
                && (record.table_ptr != 0
                    || record.status_flags & DISCOVERY_STATUS_READ_FAILURE != 0)
                && zero_selection_payload(record)
                && valid_export_prefix(record)
        }
        DISCOVERY_KIND_INTERFACE_LIST_ELEMENT_RETURN => {
            record.status_flags <= 0x03
                && record.case_id == 0
                && record.interface_index < DISCOVERY_INTERFACES
                && record.announced_count > u32::from(record.interface_index)
                && matches!(
                    record.name_class,
                    DISCOVERY_NAME_EXACT_STANDARD
                        | DISCOVERY_NAME_OTHER
                        | DISCOVERY_NAME_NULL
                        | DISCOVERY_NAME_UNREADABLE
                )
                && record.symbol_id != 0
                && zero_selection_payload(record)
                && valid_export_prefix(record)
                && (record.name_class == DISCOVERY_NAME_EXACT_STANDARD
                    || (record.usable_n == 0
                        && record.pointers_attempted == 0
                        && record.completed_prefix == 0
                        && record.version_major == 0
                        && record.version_minor == 0))
        }
        DISCOVERY_KIND_LOADER => {
            record.interface_flags == 0
                && record.pointers.iter().all(|pointer| *pointer == 0)
                && record.interface_index == 0
                && record.name_class == DISCOVERY_NAME_NA
                && record.usable_n == 0
                && record.pointers_attempted == 0
                && record.completed_prefix == 0
                && record.version_major == 0
                && record.version_minor == 0
                && record.symbol_id == 0
                && zero_selection_payload(record)
                && match record.status_flags {
                    0 | DISCOVERY_STATUS_COALESCED_NO_HELPER => {
                        record.table_ptr != 0 && record.announced_count <= 2
                    }
                    DISCOVERY_STATUS_LOADER_CONTEXT_INVALID => {
                        record.table_ptr == 0
                            && record.case_id == 0
                            && record.announced_count == 0
                            && record.send_signal_rc == 0
                    }
                    _ => false,
                }
        }
        DISCOVERY_KIND_INTERFACE_RETURN => {
            record.status_flags <= 0x03
                && matches!(
                    record.case_id,
                    DISCOVERY_NAME_EXACT_STANDARD
                        | DISCOVERY_NAME_OTHER
                        | DISCOVERY_NAME_NULL
                        | DISCOVERY_NAME_UNREADABLE
                )
                && record.interface_index <= DISCOVERY_VERSION_OTHER
                && record.symbol_id == 0
                && record.binding_id != 0
                && record.announced_count == 0
                && record.version_major == 0
                && record.version_minor == 0
                && record.selection_version_class <= DISCOVERY_VERSION_OTHER
                && valid_export_prefix(record)
                && if record.return_rv != 0 {
                    record.status_flags == 0
                        && record.table_ptr == 0
                        && record.interface_flags == 0
                        && record.pointers.iter().all(|pointer| *pointer == 0)
                        && record.name_class == DISCOVERY_NAME_NA
                        && record.selection_version_class == DISCOVERY_VERSION_NULL
                        && record.usable_n == 0
                        && record.pointers_attempted == 0
                        && record.completed_prefix == 0
                } else {
                    matches!(
                        record.name_class,
                        DISCOVERY_NAME_EXACT_STANDARD
                            | DISCOVERY_NAME_OTHER
                            | DISCOVERY_NAME_NULL
                            | DISCOVERY_NAME_UNREADABLE
                    ) && (record.name_class == DISCOVERY_NAME_EXACT_STANDARD
                        || (record.usable_n == 0
                            && record.pointers_attempted == 0
                            && record.completed_prefix == 0))
                        && (record.name_class != DISCOVERY_NAME_UNREADABLE
                            || record.status_flags & DISCOVERY_STATUS_READ_FAILURE != 0)
                        && (record.selection_version_class > DISCOVERY_VERSION_NULL
                            || (record.status_flags & DISCOVERY_STATUS_READ_FAILURE != 0
                                && record.table_ptr == 0))
                        && (record.selection_version_class == DISCOVERY_VERSION_NULL
                            || record.selection_version_class == DISCOVERY_VERSION_UNREADABLE
                            || record.table_ptr != 0)
                        && (record.selection_version_class != DISCOVERY_VERSION_UNREADABLE
                            || record.status_flags & DISCOVERY_STATUS_READ_FAILURE != 0)
                }
        }
        DISCOVERY_KIND_EXEC => {
            matches!(
                record.status_flags,
                0 | DISCOVERY_STATUS_COALESCED_NO_HELPER
            ) && record.case_id == 0
                && record.announced_count == 0
                && zero_discovery_payload(record)
        }
        DISCOVERY_KIND_LEADER_EXIT => {
            record.status_flags == 0
                && record.case_id == 0
                && record.announced_count == 0
                && record.send_signal_rc == 0
                && zero_discovery_payload(record)
        }
        _ => false,
    }
}

/// Per-slot aggregates. `entered - returned` is the in-flight count;
/// they are separate counters precisely so a call that never returns is
/// visible rather than silently absent.
#[repr(C)]
#[derive(Clone, Copy)]
pub struct SlotStats {
    pub entered: u64,
    pub returned: u64,
    pub errors: u64,
    pub total_ns: u64,
    pub max_ns: u64,
    pub buckets: [u64; LATENCY_BUCKETS],
}

impl SlotStats {
    pub const ZERO: Self = Self {
        entered: 0,
        returned: 0,
        errors: 0,
        total_ns: 0,
        max_ns: 0,
        buckets: [0; LATENCY_BUCKETS],
    };
}

/// Key for the in-flight start-timestamp map. `pid_tgid` is the raw
/// `bpf_get_current_pid_tgid()` value: distinct threads calling the same
/// function concurrently get distinct entries.
#[repr(C)]
#[derive(Clone, Copy)]
pub struct StartKey {
    pub pid_tgid: u64,
    pub slot: u32,
    pub _pad: u32,
}

/// Key for the CK_RV distribution map.
#[repr(C)]
#[derive(Clone, Copy)]
pub struct RvKey {
    pub slot: u32,
    pub _pad: u32,
    pub rv: u64,
}

/// Independent per-CPU evidence cells. No lossy path shares a counter.
pub const EVIDENCE_RING_LOSS: u32 = 0;
pub const EVIDENCE_START_INSERT_FAILURES: u32 = 1;
pub const EVIDENCE_UNMATCHED_RETURNS: u32 = 2;
pub const EVIDENCE_RV_UPDATE_FAILURES: u32 = 3;
pub const EVIDENCE_CGROUP_SCOPE_FAILURES: u32 = 4;
pub const EVIDENCE_SEMANTIC_CAPTURE_FAILURES: u32 = 5;
pub const EVIDENCE_TEMPLATE_TAIL_FAILURES: u32 = 6;
pub const EVIDENCE_UNREGISTERED_MECHANISMS: u32 = 7;
pub const EVIDENCE_CELLS: u32 = 8;

/// Hash-map capacities. The opt-in induced-gap build shrinks both maps so
/// their independent failure counters can be exercised deterministically.
#[cfg(not(feature = "small-state-maps"))]
pub const START_ENTRIES: u32 = 16_384;
#[cfg(feature = "small-state-maps")]
pub const START_ENTRIES: u32 = 1;
#[cfg(not(feature = "small-state-maps"))]
pub const RV_ENTRIES: u32 = 4_096;
#[cfg(feature = "small-state-maps")]
pub const RV_ENTRIES: u32 = 1;

/// Bucket index for a duration. Saturates into the last bucket so a
/// pathologically long call is still counted, never dropped.
pub const fn bucket_of(ns: u64) -> u32 {
    if ns == 0 {
        return 0;
    }
    let idx = 64 - ns.leading_zeros();
    if idx as usize >= LATENCY_BUCKETS {
        (LATENCY_BUCKETS - 1) as u32
    } else {
        idx
    }
}

#[cfg(feature = "user")]
unsafe impl aya::Pod for SlotStats {}
#[cfg(feature = "user")]
unsafe impl aya::Pod for StartKey {}
#[cfg(feature = "user")]
unsafe impl aya::Pod for RvKey {}
#[cfg(feature = "user")]
unsafe impl aya::Pod for SlotSemantics {}
#[cfg(feature = "user")]
unsafe impl aya::Pod for DiscoveryRecord {}
#[cfg(feature = "user")]
unsafe impl aya::Pod for StateKey {}
#[cfg(feature = "user")]
unsafe impl aya::Pod for StartState {}
#[cfg(feature = "user")]
unsafe impl aya::Pod for PauseKey {}

/// Mechanism parameter shape codes. Userspace maps the registry's shape
/// string to one of these and publishes it into MECH_SHAPE, keyed by
/// mechanism id; only shapes this phase decodes get a non-NONE code, and
/// an absent/unrecognized shape degrades to NONE (decode nothing) — the
/// Unknown shapes degrade to no parameter capture.
///
/// `GCM` is the *registry-level* code only: it is what `MECH_SHAPE` maps a
/// GCM-capable mechanism id to (`shapes::code_for`), and what
/// `decode_params` looks up to decide "attempt a GCM decode for this
/// mechanism." It is never the code an actual decoded `Event` carries —
/// `CK_GCM_PARAMS` has two incompatible struct layouts in the wild (see
/// `GCM_V220`/`GCM_V240`), and which one applied is only known once
/// `ulParameterLen` is read at decode time, so the decode result is
/// tagged with the specific layout, not the generic `GCM` code.
pub mod shape {
    pub const NONE: u32 = 0;
    pub const RSA_PKCS_PSS: u32 = 1;
    pub const GCM: u32 = 2;
    /// A `CK_GCM_PARAMS` decoded per the legacy PKCS#11 v2.20 layout:
    /// `pIv`@0 `ulIvLen`@8 `pAAD`@16 `ulAADLen`@24 `ulTagBits`@32, 40 bytes
    /// total (`ulParameterLen == 40`).
    pub const GCM_V220: u32 = 3;
    /// A `CK_GCM_PARAMS` decoded per the current v2.40/OASIS layout, which
    /// inserts `ulIvBits` at offset 16 and pushes the rest out: `pIv`@0
    /// `ulIvLen`@8 `ulIvBits`@16 `pAAD`@24 `ulAADLen`@32 `ulTagBits`@40, 48
    /// bytes total (`ulParameterLen == 48`) — what `cryptoki_sys::CK_GCM_PARAMS`
    /// actually is.
    pub const GCM_V240: u32 = 4;
}

/// MECH_SHAPE map capacity. 336 mechanisms are registered upstream today;
/// this covers that several times over.
pub const MAX_MECH_SHAPES: u32 = 1024;

/// Bit positions for policy-allowlisted boolean attributes in attr_bools bitmask.
/// Each bit represents whether that attribute was observed as true.
pub mod attr_bool {
    pub const TYPES_AND_BITS: [(u32, u32); 11] = [
        (0x01, 0),
        (0x02, 1),
        (0x103, 2),
        (0x104, 3),
        (0x105, 4),
        (0x106, 5),
        (0x107, 6),
        (0x108, 7),
        (0x10A, 8),
        (0x10C, 9),
        (0x162, 10),
    ];
    /// CKA_TOKEN (PKCS#11 type 0x01) — bit 0
    pub const TOKEN: u32 = 1 << 0;
    /// CKA_PRIVATE (PKCS#11 type 0x02) — bit 1
    pub const PRIVATE: u32 = 1 << 1;
    /// CKA_SENSITIVE (PKCS#11 type 0x103) — bit 2
    pub const SENSITIVE: u32 = 1 << 2;
    /// CKA_ENCRYPT (PKCS#11 type 0x104) — bit 3
    pub const ENCRYPT: u32 = 1 << 3;
    /// CKA_DECRYPT (PKCS#11 type 0x105) — bit 4
    pub const DECRYPT: u32 = 1 << 4;
    /// CKA_WRAP (PKCS#11 type 0x106) — bit 5
    pub const WRAP: u32 = 1 << 5;
    /// CKA_UNWRAP (PKCS#11 type 0x107) — bit 6
    pub const UNWRAP: u32 = 1 << 6;
    /// CKA_SIGN (PKCS#11 type 0x108) — bit 7
    pub const SIGN: u32 = 1 << 7;
    /// CKA_VERIFY (PKCS#11 type 0x10A) — bit 8
    pub const VERIFY: u32 = 1 << 8;
    /// CKA_DERIVE (PKCS#11 type 0x10C) — bit 9
    pub const DERIVE: u32 = 1 << 9;
    /// CKA_EXTRACTABLE (PKCS#11 type 0x162) — bit 10
    pub const EXTRACTABLE: u32 = 1 << 10;

    /// Map a PKCS#11 attribute type to its bit position, if allowlisted.
    /// Returns Some(bit_position) for recognized attributes, None otherwise.
    pub const fn bit_for_attr_type(attr_type: u64) -> Option<u32> {
        if attr_type > u32::MAX as u64 {
            return None;
        }
        let attr_type = attr_type as u32;
        let mut index = 0;
        while index < TYPES_AND_BITS.len() {
            if TYPES_AND_BITS[index].0 == attr_type {
                return Some(TYPES_AND_BITS[index].1);
            }
            index += 1;
        }
        None
    }
}

/// Sentinels. Zero is a legal PKCS#11 value for some of these, so absence
/// gets its own out-of-band marker.
pub const MECH_NONE: u64 = u64::MAX;
pub const SESSION_NONE: u64 = u64::MAX;
pub const USER_TYPE_NONE: u32 = u32::MAX;
pub const FUNCTION_NONE: u32 = u32::MAX;

/// Longest published standard function name in the 3.2 table.
pub const FUNCTION_NAME_MAX_BYTES: usize = 27;

/// Exact bounded C-string key for the immutable standard async catalog.
/// The extra zero byte avoids implicit tail padding in the 32-byte map key.
#[repr(C)]
#[derive(Debug, Clone, Copy, Default, Eq, Ord, PartialEq, PartialOrd)]
pub struct FunctionNameKey {
    pub len: u32,
    pub bytes: [u8; FUNCTION_NAME_MAX_BYTES + 1],
}

impl FunctionNameKey {
    pub fn from_bytes(snapshot: &[u8]) -> Option<Self> {
        if snapshot.len() > FUNCTION_NAME_MAX_BYTES + 2 {
            return None;
        }
        let len = snapshot.iter().position(|byte| *byte == 0)?;
        if len > FUNCTION_NAME_MAX_BYTES {
            return None;
        }
        let mut key = Self {
            len: len as u32,
            ..Self::default()
        };
        key.bytes[..len].copy_from_slice(&snapshot[..len]);
        Some(key)
    }
}

/// Only immediate success or pending means the provider accepted enough of a
/// mechanism-bearing request for safe return-time membership capture.
pub const fn return_allows_mechanism(rv: u64) -> bool {
    matches!(rv, 0 | 0x204)
}

pub mod event_type {
    pub const CALL: u32 = 0;
    pub const FORK: u32 = 1;
}

/// Capture-state bits stored in CallStart/Event. Pointer values themselves
/// never cross the boundary except C_OpenSession's temporary out-pointer.
pub mod capture {
    pub const MECHANISM_MASK: u32 = 0b11;
    pub const MECHANISM_NONE: u32 = 0;
    pub const MECHANISM_NULL: u32 = 1;
    pub const MECHANISM_UNREADABLE: u32 = 2;
    pub const MECHANISM_VALUE: u32 = 3;

    pub const OUTPUT_SHIFT: u32 = 2;
    pub const OUTPUT_MASK: u32 = 0b11 << OUTPUT_SHIFT;
    pub const OUTPUT_NONE: u32 = 0 << OUTPUT_SHIFT;
    pub const OUTPUT_NULL: u32 = 1 << OUTPUT_SHIFT;
    pub const OUTPUT_NON_NULL: u32 = 2 << OUTPUT_SHIFT;
    pub const OUTPUT_UNREADABLE: u32 = 3 << OUTPUT_SHIFT;

    pub const ARG_READ_FAILURE: u32 = 1 << 4;
    pub const ASYNC_SESSION: u32 = 1 << 5;
    pub const ASYNC_VALUE_UNREADABLE: u32 = 1 << 6;
}

/// Ring buffer capacity in bytes. Must be a power of two and page-aligned.
/// 256 KiB holds roughly 900 current 288-byte events. The `small-ring` feature
/// (off by default; the default build is unaffected) shrinks this to one page
/// so the induced-gap test (Task 7, `scripts/verify-induced-gaps.sh`) can force
/// ring-buffer loss deliberately with a high call rate.
#[cfg(not(feature = "small-ring"))]
pub const RING_BYTES: u32 = 256 * 1024;
#[cfg(feature = "small-ring")]
pub const RING_BYTES: u32 = 4096;

/// Maximum template attributes captured per event.
pub const MAX_ATTRS: usize = 8;

/// What the entry probe stashes until the matching return. Replaces the
/// bare timestamp Phase 1b stored.
#[repr(C)]
#[derive(Clone, Copy, Default)]
pub struct CallStart {
    pub ts_ns: u64,
    pub session: u64,
    pub slot_id: u64,
    pub mechanism: u64,
    /// Transient entry-time `pMechanism`; never copied to `Event`.
    pub mechanism_ptr: u64,
    pub flags: u64,
    /// `phSession` for C_OpenSession; 0 otherwise. Read only at return.
    pub out_ptr: u64,
    pub user_type: u32,
    /// Parameter shape decoded at entry (Phase 3), or `shape::NONE`.
    /// Decode happens in `p11_entry` since `pMechanism` is only live then;
    /// these fields carry the result to the return probe that builds
    /// `Event`.
    pub shape: u32,
    pub p0: u64,
    pub p1: u64,
    pub p2: u64,
    /// Async result/id scalar. Never rendered; only the state machine reads it.
    pub async_value: u64,
    /// Template attribute *types* only (never values), captured at entry
    /// since `pTemplate` is only guaranteed live then. See `Event` for the
    /// field-by-field meaning; these mirror it verbatim to the return probe.
    pub attr_types: [u64; MAX_ATTRS],
    pub attr_count: u32,
    pub attr_total: u32,
    pub attr_bools: u32,
    pub attr_bools_seen: u32,
    pub attr_types1: [u64; MAX_ATTRS],
    pub attr_count1: u32,
    pub attr_total1: u32,
    pub attr_bools1: u32,
    pub attr_bools_seen1: u32,
    pub capture: u32,
    pub target_function: u32,
    pub _pad: u64,
}

/// One completed call. Emitted at return only: a call with no return is
/// visible as in-flight in the aggregate maps, never as a partial event.
///
/// ## Decoded mechanism parameters
///
/// For mechanism shapes decoded in this phase, `shape` holds the shape code
/// (from the `shape` module) and `p0`, `p1`, `p2` hold shape-specific scalar
/// parameters:
///
/// - `RSA_PKCS_PSS`: p0 = hashAlg, p1 = mgf, p2 = sLen
/// - `GCM_V220`/`GCM_V240`: p0 = ulIvLen, p1 = ulAADLen, p2 = ulTagBits
///   (the shape code itself says which `CK_GCM_PARAMS` layout the decode
///   used; plain `GCM` never appears here, see the `shape` module docs)
///
/// For unknown or unhandled shapes, `shape` is `shape::NONE` and the `p*`
/// fields are meaningless.
#[repr(C)]
#[derive(Clone, Copy, Default)]
pub struct Event {
    pub ts_ns: u64,
    pub duration_ns: u64,
    pub pid_tgid: u64,
    pub cgroup_id: u64,
    /// Raw handle. Pseudonymized in userspace; never written to output.
    pub session: u64,
    pub slot_id: u64,
    pub mechanism: u64,
    pub flags: u64,
    pub rv: u64,
    pub p0: u64,
    pub p1: u64,
    pub p2: u64,
    /// Async result/id scalar. Never rendered; only the state machine reads it.
    pub async_value: u64,
    pub slot: u32,
    pub target_function: u32,
    pub user_type: u32,
    pub shape: u32,
    pub attr_types: [u64; MAX_ATTRS],
    pub attr_count: u32,
    pub attr_total: u32,
    pub attr_bools: u32,
    pub attr_bools_seen: u32,
    pub attr_types1: [u64; MAX_ATTRS],
    pub attr_count1: u32,
    pub attr_total1: u32,
    pub attr_bools1: u32,
    pub attr_bools_seen1: u32,
    pub capture: u32,
    pub event_type: u32,
}

#[cfg(feature = "user")]
unsafe impl aya::Pod for CallStart {}
#[cfg(feature = "user")]
unsafe impl aya::Pod for Event {}
#[cfg(feature = "user")]
unsafe impl aya::Pod for FunctionNameKey {}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn slot_semantics_is_a_padding_free_map_value() {
        assert_eq!(MAX_SLOTS, 512);
        assert_eq!(core::mem::size_of::<SlotSemantics>(), 18);
        assert_eq!(core::mem::align_of::<SlotSemantics>(), 2);
        assert_eq!(ARG_NONE, u8::MAX);
    }

    #[test]
    fn fork_offset_config_cell_is_exact_and_fail_closed() {
        assert_eq!(CFG_FORK_OFFSETS, 1);
        let packed = pack_fork_offsets(32, 56);
        assert_eq!(packed, (1u64 << 32) | (56u64 << 16) | 32);
        assert_eq!(unpack_fork_offsets(packed), Some((32, 56)));
        assert_eq!(unpack_fork_offsets(packed & !(1u64 << 32)), None);
        assert_eq!(unpack_fork_offsets(packed | (1u64 << 63)), None);
    }

    /// Mutation caught: treating the full cookie as a slot corrupts the
    /// existing aggregate-map keys when a descriptor is selected.
    #[test]
    fn slot_attach_cookie_keeps_slot_and_descriptor_in_separate_words() {
        assert_eq!(attach_cookie(0, 0), 0);
        assert_eq!(cookie_slot(attach_cookie(0, 0)), 0);
        assert_eq!(cookie_descriptor(attach_cookie(0, 0)), 0);

        let cookie = attach_cookie(0x1234_5678, 0x9abc_def0);
        assert_eq!(cookie, 0x9abc_def0_1234_5678);
        assert_eq!(cookie_slot(cookie), 0x1234_5678);
        assert_eq!(cookie_descriptor(cookie), 0x9abc_def0);

        let maximum = attach_cookie(u32::MAX, u32::MAX);
        assert_eq!(cookie_slot(maximum), u32::MAX);
        assert_eq!(cookie_descriptor(maximum), u32::MAX);
    }

    #[test]
    fn rv_and_evidence_abi_preserve_every_failure_class() {
        let key = RvKey {
            slot: 7,
            _pad: 0,
            rv: 0x1_0000_0001,
        };
        assert_eq!(key.rv, 0x1_0000_0001);
        assert_eq!(core::mem::size_of::<RvKey>(), 16);
        assert_eq!(core::mem::offset_of!(RvKey, rv), 8);

        let indices = [
            EVIDENCE_RING_LOSS,
            EVIDENCE_START_INSERT_FAILURES,
            EVIDENCE_UNMATCHED_RETURNS,
            EVIDENCE_RV_UPDATE_FAILURES,
            EVIDENCE_CGROUP_SCOPE_FAILURES,
            EVIDENCE_SEMANTIC_CAPTURE_FAILURES,
            EVIDENCE_TEMPLATE_TAIL_FAILURES,
            EVIDENCE_UNREGISTERED_MECHANISMS,
        ];
        for (position, index) in indices.iter().enumerate() {
            assert_eq!(*index as usize, position);
        }
        assert_eq!(EVIDENCE_CELLS, indices.len() as u32);
    }

    #[test]
    fn buckets_are_monotonic_and_saturating() {
        assert_eq!(bucket_of(0), 0);
        assert_eq!(bucket_of(1), 1);
        assert_eq!(bucket_of(2), 2);
        assert_eq!(bucket_of(3), 2);
        assert_eq!(bucket_of(4), 3);
        // Monotonic across the whole range.
        let mut prev = 0;
        let mut ns = 1u64;
        while ns < u64::MAX / 2 {
            let b = bucket_of(ns);
            assert!(b >= prev, "bucket went backwards at {ns}");
            prev = b;
            ns *= 2;
        }
        // Saturates, never indexes out of bounds.
        assert_eq!(bucket_of(u64::MAX), (LATENCY_BUCKETS - 1) as u32);
        assert!((bucket_of(u64::MAX) as usize) < LATENCY_BUCKETS);
    }

    #[test]
    fn event_and_callstart_have_no_implicit_padding() {
        // Both cross the kernel/userspace boundary as raw bytes; implicit
        // tail padding would read as uninitialized on one side.
        assert_eq!(core::mem::size_of::<CallStart>(), 272);
        assert_eq!(core::mem::size_of::<Event>(), 288);
        assert_eq!(core::mem::align_of::<CallStart>(), 8);
        assert_eq!(core::mem::align_of::<Event>(), 8);
        let call_start = CallStart::default();
        assert_eq!(
            core::mem::offset_of!(CallStart, _pad) + core::mem::size_of_val(&call_start._pad),
            core::mem::size_of::<CallStart>()
        );
    }

    #[test]
    fn vendor_attribute_high_bits_cannot_alias_the_boolean_allowlist() {
        assert_eq!(attr_bool::bit_for_attr_type(0x01), Some(0));
        assert_eq!(attr_bool::bit_for_attr_type(0x1_0000_0001), None);
    }

    #[test]
    fn ring_bytes_is_page_aligned_power_of_two() {
        assert!(RING_BYTES.is_power_of_two());
        assert_eq!(RING_BYTES % 4096, 0);
    }

    #[test]
    fn default_ring_bytes_is_256kib() {
        // Pins the default so the small-ring override (Cargo feature,
        // opt-in only) can never change it silently.
        #[cfg(not(feature = "small-ring"))]
        assert_eq!(RING_BYTES, 256 * 1024);
    }

    #[test]
    fn induced_gap_capacities_are_explicit() {
        #[cfg(not(feature = "small-state-maps"))]
        assert_eq!((START_ENTRIES, RV_ENTRIES), (16_384, 4_096));
        #[cfg(feature = "small-ring")]
        assert_eq!(RING_BYTES, 4_096);
        #[cfg(feature = "small-state-maps")]
        assert_eq!((START_ENTRIES, RV_ENTRIES), (1, 1));
    }

    #[test]
    fn sentinels_do_not_collide_with_real_values() {
        // CKM_SHA256 = 0x250, CKU_USER = 1, session handles are small.
        assert_ne!(MECH_NONE, 0x250);
        assert_ne!(USER_TYPE_NONE, 1);
        assert_ne!(SESSION_NONE, 0);
    }

    /// Mutation caught: any field reorder, type-width change, or tail reuse
    /// makes host and BPF disagree about the private discovery transport.
    #[test]
    fn discovery_transport_has_the_exact_frozen_layout() {
        assert_eq!(core::mem::size_of::<DiscoveryRecord>(), 920);
        assert_eq!(core::mem::align_of::<DiscoveryRecord>(), 8);
        assert_eq!(core::mem::offset_of!(DiscoveryRecord, hook_ts_ns), 0);
        assert_eq!(core::mem::offset_of!(DiscoveryRecord, pid_tgid), 8);
        assert_eq!(core::mem::offset_of!(DiscoveryRecord, table_ptr), 16);
        assert_eq!(core::mem::offset_of!(DiscoveryRecord, interface_flags), 24);
        assert_eq!(core::mem::offset_of!(DiscoveryRecord, pointers), 32);
        assert_eq!(core::mem::offset_of!(DiscoveryRecord, kind), 864);
        assert_eq!(core::mem::offset_of!(DiscoveryRecord, case_id), 865);
        assert_eq!(core::mem::offset_of!(DiscoveryRecord, interface_index), 866);
        assert_eq!(core::mem::offset_of!(DiscoveryRecord, name_class), 867);
        assert_eq!(core::mem::offset_of!(DiscoveryRecord, status_flags), 868);
        assert_eq!(core::mem::offset_of!(DiscoveryRecord, usable_n), 869);
        assert_eq!(
            core::mem::offset_of!(DiscoveryRecord, pointers_attempted),
            870
        );
        assert_eq!(
            core::mem::offset_of!(DiscoveryRecord, completed_prefix),
            871
        );
        assert_eq!(core::mem::offset_of!(DiscoveryRecord, version_major), 872);
        assert_eq!(core::mem::offset_of!(DiscoveryRecord, version_minor), 873);
        assert_eq!(
            core::mem::offset_of!(DiscoveryRecord, selection_version_class),
            874
        );
        assert_eq!(core::mem::offset_of!(DiscoveryRecord, reserved_zero), 875);
        assert_eq!(core::mem::offset_of!(DiscoveryRecord, symbol_id), 876);
        assert_eq!(core::mem::offset_of!(DiscoveryRecord, announced_count), 880);
        assert_eq!(
            core::mem::offset_of!(DiscoveryRecord, reserved_tail_zero),
            884
        );
        assert_eq!(core::mem::offset_of!(DiscoveryRecord, send_signal_rc), 888);
        assert_eq!(core::mem::offset_of!(DiscoveryRecord, return_rv), 896);
        assert_eq!(core::mem::offset_of!(DiscoveryRecord, request_flags), 904);
        assert_eq!(core::mem::offset_of!(DiscoveryRecord, binding_id), 912);

        assert_eq!(core::mem::offset_of!(StateKey, pid_tgid), 0);
        assert_eq!(core::mem::offset_of!(StateKey, attach_cookie), 8);
        assert_eq!(core::mem::offset_of!(StateKey, domain), 16);
        assert_eq!(core::mem::offset_of!(StartState, arg0), 0);
        assert_eq!(core::mem::offset_of!(StartState, arg1), 8);
        assert_eq!(core::mem::offset_of!(StartState, arg2), 16);
        assert_eq!(core::mem::offset_of!(PauseKey, tgid), 0);
        assert_eq!(core::mem::offset_of!(PauseKey, pad), 4);
        assert_eq!(core::mem::offset_of!(PauseKey, generation_token), 8);

        assert_eq!(core::mem::size_of::<StateKey>(), 24);
        assert_eq!(core::mem::size_of::<StartState>(), 24);
        assert_eq!(core::mem::size_of::<PauseKey>(), 16);
        for align in [
            core::mem::align_of::<StateKey>(),
            core::mem::align_of::<StartState>(),
            core::mem::align_of::<PauseKey>(),
        ] {
            assert_eq!(align, 8);
        }
        let key = PauseKey {
            tgid: 7,
            pad: 0,
            generation_token: 9,
        };
        assert_eq!(key.pad, 0);
    }

    #[test]
    fn discovery_producer_decisions_cover_the_finite_edges() {
        assert_eq!(discovery_table_slots(2, 0), 67);
        assert_eq!(discovery_table_slots(2, 40), 68);
        assert_eq!(discovery_table_slots(3, 1), 92);
        assert_eq!(discovery_table_slots(3, 2), 104);
        assert_eq!(discovery_table_slots(4, 0), 0);
        assert_eq!(discovery_usable_prefix(false, 104), 104);
        assert_eq!(discovery_usable_prefix(true, 67), 0);

        assert!(!valid_loader_cookie(0));
        assert!(!valid_loader_cookie(1));
        assert!(valid_loader_cookie((LOADER_STATE_ABSENT_SENTINEL << 9) | 7));
        assert!(valid_loader_cookie(LOADER_STATE_PRESENT | 7));

        assert!(!discovery_pause_enabled(false, FLAG_PAUSE_ENABLED, 7));
        assert!(!discovery_pause_enabled(true, 0, 7));
        assert!(!discovery_pause_enabled(true, FLAG_PAUSE_ENABLED, 0));
        assert!(discovery_pause_enabled(true, FLAG_PAUSE_ENABLED, 7));
        assert!(!discovery_pause_coalesced(PAUSE_ARMED, false));
        assert!(!discovery_pause_coalesced(PAUSE_REQUESTED, true));
        assert!(discovery_pause_coalesced(PAUSE_REQUESTED, false));

        assert!(!discovery_state_take_failed(true, true));
        assert!(discovery_state_take_failed(false, true));
        assert!(discovery_state_take_failed(true, false));
    }

    #[test]
    fn interface_continuation_packs_decodes_and_progresses() {
        assert_eq!(TAIL_CALLS_INTERFACE_WORKER_SLOT, 0);
        assert_eq!(TAIL_CALLS_TEMPLATE_SECOND_SLOT, 1);
        let symbol_id = 0x00ab_cdef;
        assert_eq!(
            interface_continuation_pack(1, 0, symbol_id),
            Some((u64::from(symbol_id) << 40) | (1u64 << 8))
        );
        assert_eq!(
            interface_continuation_pack(16, 15, symbol_id),
            Some((u64::from(symbol_id) << 40) | (16u64 << 8) | 15)
        );
        assert_eq!(
            interface_continuation_pack(17, 0, symbol_id),
            Some((u64::from(symbol_id) << 40) | (17u64 << 8))
        );
        assert_eq!(
            interface_continuation_pack(u64::from(u32::MAX), 0, symbol_id),
            Some((u64::from(symbol_id) << 40) | (u64::from(u32::MAX) << 8))
        );
        assert_eq!(
            interface_continuation_pack(u64::MAX, 15, symbol_id),
            Some((u64::from(symbol_id) << 40) | (u64::from(u32::MAX) << 8) | 15)
        );
        assert_eq!(interface_continuation_pack(1, 0, 0), None);
        assert_eq!(interface_continuation_pack(1, 0, 0x0100_0000), None);

        assert_eq!(
            interface_continuation_unpack(interface_continuation_pack(1, 0, symbol_id).unwrap()),
            Some((1, 0, symbol_id))
        );
        assert_eq!(
            interface_continuation_unpack(interface_continuation_pack(16, 15, symbol_id).unwrap()),
            Some((16, 15, symbol_id))
        );
        assert_eq!(
            interface_continuation_unpack(interface_continuation_pack(17, 15, symbol_id).unwrap()),
            Some((17, 15, symbol_id))
        );
        assert_eq!(
            interface_continuation_unpack(
                interface_continuation_pack(u64::MAX, 15, symbol_id).unwrap()
            ),
            Some((u32::MAX, 15, symbol_id))
        );
        assert_eq!(
            interface_continuation_unpack(interface_continuation_pack(1, 15, symbol_id).unwrap()),
            None
        );
        assert_eq!(
            interface_continuation_unpack(interface_continuation_pack(16, 16, symbol_id).unwrap()),
            None
        );
        assert_eq!(
            interface_continuation_unpack(interface_continuation_pack(0, 0, symbol_id).unwrap()),
            None
        );
        assert_eq!(interface_continuation_unpack(1u64 << 40), None);

        assert_eq!(
            interface_continuation_next(interface_continuation_pack(1, 0, symbol_id).unwrap()),
            None
        );
        assert_eq!(
            interface_continuation_next(interface_continuation_pack(16, 14, symbol_id).unwrap()),
            Some(interface_continuation_pack(16, 15, symbol_id).unwrap())
        );
        assert_eq!(
            interface_continuation_next(interface_continuation_pack(16, 15, symbol_id).unwrap()),
            None
        );
        assert_eq!(
            interface_continuation_next(interface_continuation_pack(17, 15, symbol_id).unwrap()),
            None
        );
    }

    /// Mutation caught: reordering a counter silently assigns one kernel loss
    /// class to the wrong userspace evidence owner.
    #[test]
    fn discovery_counter_and_status_values_are_frozen() {
        assert_eq!(DISCOVERY_KIND_FUNCTION_LIST_RETURN, 1);
        assert_eq!(DISCOVERY_KIND_INTERFACE_LIST_ELEMENT_RETURN, 2);
        assert_eq!(DISCOVERY_KIND_LOADER, 3);
        assert_eq!(DISCOVERY_KIND_INTERFACE_RETURN, 4);
        assert_eq!(DISCOVERY_KIND_EXEC, 5);
        assert_eq!(DISCOVERY_KIND_LEADER_EXIT, 6);
        assert_eq!(DISCOVERY_NAME_NA, 0);
        assert_eq!(DISCOVERY_NAME_EXACT_STANDARD, 1);
        assert_eq!(DISCOVERY_NAME_OTHER, 2);
        assert_eq!(DISCOVERY_NAME_NULL, 3);
        assert_eq!(DISCOVERY_NAME_UNREADABLE, 4);
        assert_eq!(DISCOVERY_STATUS_READ_FAILURE, 0x01);
        assert_eq!(DISCOVERY_STATUS_COALESCED_NO_HELPER, 0x02);
        assert_eq!(DISCOVERY_STATUS_LOADER_CONTEXT_INVALID, 0x04);
        assert_eq!(PAUSE_ARMED, 1);
        assert_eq!(PAUSE_REQUESTED, 2);
        assert_eq!(COALESCED_NO_HELPER_RC, i64::MIN);
        assert_eq!(DISCOVERY_COUNTER_RING_LOSS, 0);
        assert_eq!(DISCOVERY_COUNTER_EXPORT_STATE_FAILURES, 1);
        assert_eq!(DISCOVERY_COUNTER_EXPORT_BOUNDED_READ_FAILURES, 2);
        assert_eq!(DISCOVERY_COUNTER_LOADER_HITS, 3);
        assert_eq!(DISCOVERY_COUNTER_LOADER_STATE_READ_FAILURES, 4);
        assert_eq!(DISCOVERY_COUNTER_CELLS, 5);
    }

    fn discovery_record(kind: u8) -> DiscoveryRecord {
        let mut record: DiscoveryRecord = unsafe { core::mem::zeroed() };
        record.kind = kind;
        record
    }

    fn function_list_record() -> DiscoveryRecord {
        let mut record = discovery_record(DISCOVERY_KIND_FUNCTION_LIST_RETURN);
        record.table_ptr = 0x1000;
        record.symbol_id = 1;
        record
    }

    /// Mutation caught: a malformed private value or phase-owned field reaches
    /// Task 6 as if it were a structurally valid discovery fact.
    #[test]
    fn discovery_record_validation_is_finite_and_phase_local() {
        let mut export = function_list_record();
        export.version_major = 3;
        export.version_minor = 2;
        export.pointers[0] = 0x2000;
        export.usable_n = 1;
        export.pointers_attempted = 1;
        export.completed_prefix = 1;
        assert!(valid_discovery_record(&export));

        export.status_flags = DISCOVERY_STATUS_READ_FAILURE | DISCOVERY_STATUS_COALESCED_NO_HELPER;
        export.send_signal_rc = COALESCED_NO_HELPER_RC;
        export.usable_n = 0;
        assert!(valid_discovery_record(&export));
        export.send_signal_rc = 0;
        assert!(!valid_discovery_record(&export));
        export.send_signal_rc = COALESCED_NO_HELPER_RC;
        export.status_flags = DISCOVERY_STATUS_READ_FAILURE;
        assert!(!valid_discovery_record(&export));

        let mut non_loader_case = discovery_record(DISCOVERY_KIND_EXEC);
        non_loader_case.case_id = 1;
        assert!(!valid_discovery_record(&non_loader_case));

        let mut invalid_loader = discovery_record(DISCOVERY_KIND_LOADER);
        invalid_loader.status_flags = DISCOVERY_STATUS_LOADER_CONTEXT_INVALID;
        assert!(valid_discovery_record(&invalid_loader));
        invalid_loader.case_id = 1;
        assert!(!valid_discovery_record(&invalid_loader));

        let mut wrong_count = discovery_record(DISCOVERY_KIND_FUNCTION_LIST_RETURN);
        wrong_count.symbol_id = 1;
        wrong_count.announced_count = 1;
        assert!(!valid_discovery_record(&wrong_count));

        let mut interface = discovery_record(DISCOVERY_KIND_INTERFACE_LIST_ELEMENT_RETURN);
        interface.symbol_id = 2;
        interface.name_class = DISCOVERY_NAME_OTHER;
        interface.interface_index = 4;
        interface.announced_count = 4;
        assert!(!valid_discovery_record(&interface));
        interface.announced_count = 5;
        assert!(valid_discovery_record(&interface));

        let mut loader = discovery_record(DISCOVERY_KIND_LOADER);
        loader.table_ptr = 0x3000;
        loader.announced_count = 2;
        assert!(valid_discovery_record(&loader));
        loader.announced_count = 3;
        assert!(!valid_discovery_record(&loader));
    }

    /// Mutation caught: an arbitrary 64-bit private value is accepted as a
    /// helper return even though bpf_send_signal returns a signed 32-bit int.
    #[test]
    fn discovery_private_result_is_zero_sentinel_or_sign_extended_i32() {
        let mut record = function_list_record();
        for rc in [0, 1, -1, i64::from(i32::MAX), i64::from(i32::MIN)] {
            record.send_signal_rc = rc;
            assert!(valid_discovery_record(&record), "rc={rc}");
        }
        record.send_signal_rc = i64::from(i32::MAX) + 1;
        assert!(!valid_discovery_record(&record));
        record.send_signal_rc = i64::from(i32::MIN) - 1;
        assert!(!valid_discovery_record(&record));
        record.send_signal_rc = COALESCED_NO_HELPER_RC;
        assert!(!valid_discovery_record(&record));
        record.status_flags = DISCOVERY_STATUS_COALESCED_NO_HELPER;
        assert!(valid_discovery_record(&record));
    }

    #[test]
    fn selection_transport_round_trips_failures() {
        assert_eq!(
            [
                DISCOVERY_VERSION_NULL,
                DISCOVERY_VERSION_UNREADABLE,
                DISCOVERY_VERSION_V2_40,
                DISCOVERY_VERSION_V3_0,
                DISCOVERY_VERSION_V3_1,
                DISCOVERY_VERSION_V3_2,
                DISCOVERY_VERSION_OTHER,
            ],
            [0, 1, 2, 3, 4, 5, 6]
        );
        assert_eq!(discovery_version_class(3, 2), DISCOVERY_VERSION_V3_2);
        assert_eq!(discovery_version_class(0, 0), DISCOVERY_VERSION_OTHER);
        assert_eq!(discovery_version_class(9, 9), DISCOVERY_VERSION_OTHER);
        for request_name in [
            DISCOVERY_NAME_EXACT_STANDARD,
            DISCOVERY_NAME_OTHER,
            DISCOVERY_NAME_NULL,
            DISCOVERY_NAME_UNREADABLE,
        ] {
            for request_version in 0..=DISCOVERY_VERSION_OTHER {
                let mut record = discovery_record(DISCOVERY_KIND_INTERFACE_RETURN);
                record.binding_id = u64::MAX;
                record.case_id = request_name;
                record.interface_index = request_version;
                record.request_flags = u64::MAX;
                record.return_rv = u64::MAX;
                assert!(valid_discovery_record(&record));
            }
        }

        for result_name in [
            DISCOVERY_NAME_EXACT_STANDARD,
            DISCOVERY_NAME_OTHER,
            DISCOVERY_NAME_NULL,
            DISCOVERY_NAME_UNREADABLE,
        ] {
            let mut record = discovery_record(DISCOVERY_KIND_INTERFACE_RETURN);
            record.binding_id = u64::MAX;
            record.case_id = DISCOVERY_NAME_EXACT_STANDARD;
            record.interface_index = DISCOVERY_VERSION_V3_0;
            record.name_class = result_name;
            record.interface_flags = u64::MAX;
            record.table_ptr = 0x1000;
            record.selection_version_class = DISCOVERY_VERSION_V3_0;
            record.status_flags = if result_name == DISCOVERY_NAME_UNREADABLE {
                DISCOVERY_STATUS_READ_FAILURE
            } else {
                0
            };
            if result_name == DISCOVERY_NAME_UNREADABLE {
                record.selection_version_class = DISCOVERY_VERSION_UNREADABLE;
            }
            assert!(valid_discovery_record(&record));
        }

        for result_version in 0..=DISCOVERY_VERSION_OTHER {
            let mut record = discovery_record(DISCOVERY_KIND_INTERFACE_RETURN);
            record.binding_id = u64::MAX;
            record.case_id = DISCOVERY_NAME_EXACT_STANDARD;
            record.interface_index = DISCOVERY_VERSION_V3_0;
            record.name_class = DISCOVERY_NAME_EXACT_STANDARD;
            record.table_ptr = if result_version == DISCOVERY_VERSION_NULL {
                0
            } else {
                0x1000
            };
            record.selection_version_class = result_version;
            record.status_flags = if matches!(
                result_version,
                DISCOVERY_VERSION_NULL | DISCOVERY_VERSION_UNREADABLE
            ) {
                DISCOVERY_STATUS_READ_FAILURE
            } else {
                0
            };
            assert!(valid_discovery_record(&record));
        }

        let mut record = discovery_record(DISCOVERY_KIND_INTERFACE_RETURN);
        record.binding_id = u64::MAX;
        record.case_id = DISCOVERY_NAME_EXACT_STANDARD;
        record.interface_index = DISCOVERY_VERSION_V3_0;
        record.name_class = DISCOVERY_NAME_EXACT_STANDARD;
        record.table_ptr = 0x1000;
        record.selection_version_class = DISCOVERY_VERSION_V3_0;
        record.version_major = 3;
        record.version_minor = 0;
        assert!(!valid_discovery_record(&record));

        record.binding_id = 0;
        assert!(!valid_discovery_record(&record));

        let mut walked = discovery_record(DISCOVERY_KIND_INTERFACE_RETURN);
        walked.binding_id = 1;
        walked.case_id = DISCOVERY_NAME_EXACT_STANDARD;
        walked.interface_index = DISCOVERY_VERSION_V3_0;
        walked.name_class = DISCOVERY_NAME_EXACT_STANDARD;
        walked.table_ptr = 0x2000;
        walked.selection_version_class = DISCOVERY_VERSION_V3_0;
        walked.pointers_attempted = 92;
        walked.completed_prefix = 92;
        walked.usable_n = 92;
        for (index, pointer) in walked.pointers[..92].iter_mut().enumerate() {
            *pointer = 0x3000 + index as u64;
        }
        assert!(valid_discovery_record(&walked));

        let mut bad = walked;
        bad.return_rv = 1;
        assert!(!valid_discovery_record(&bad));
        bad = walked;
        bad.return_rv = 1;
        bad.name_class = DISCOVERY_NAME_OTHER;
        assert!(!valid_discovery_record(&bad));
        bad = walked;
        bad.name_class = DISCOVERY_NAME_UNREADABLE;
        assert!(!valid_discovery_record(&bad));
        bad = walked;
        bad.selection_version_class = DISCOVERY_VERSION_UNREADABLE;
        assert!(!valid_discovery_record(&bad));
        bad.status_flags = 0;
        bad.selection_version_class = DISCOVERY_VERSION_V3_0;
        bad.table_ptr = 0;
        assert!(!valid_discovery_record(&bad));
        bad = walked;
        bad.symbol_id = 1;
        assert!(!valid_discovery_record(&bad));
    }

    #[test]
    fn state_key_domains_separate_equal_pid_and_cookie() {
        let export = StateKey {
            pid_tgid: 7,
            attach_cookie: u64::MAX,
            domain: STATE_DOMAIN_EXPORT,
        };
        let selection = StateKey {
            domain: STATE_DOMAIN_SELECTION,
            ..export
        };
        assert_ne!(export, selection);
    }

    /// Mutation caught: a producer-owned field, finite status, prefix bound,
    /// or required zero is silently accepted for the wrong record kind.
    #[test]
    fn discovery_kind_fields_and_bounds_are_structurally_exact() {
        let mut record = function_list_record();
        for status in [
            0,
            DISCOVERY_STATUS_READ_FAILURE,
            DISCOVERY_STATUS_COALESCED_NO_HELPER,
            DISCOVERY_STATUS_READ_FAILURE | DISCOVERY_STATUS_COALESCED_NO_HELPER,
        ] {
            record.status_flags = status;
            record.send_signal_rc = if status & DISCOVERY_STATUS_COALESCED_NO_HELPER != 0 {
                COALESCED_NO_HELPER_RC
            } else {
                0
            };
            record.usable_n = 0;
            assert!(valid_discovery_record(&record), "status={status:#x}");
        }
        record.status_flags = DISCOVERY_STATUS_LOADER_CONTEXT_INVALID;
        record.send_signal_rc = 0;
        assert!(!valid_discovery_record(&record));

        let mut malformed = function_list_record();
        malformed.reserved_zero[0] = 1;
        assert!(!valid_discovery_record(&malformed));
        malformed = function_list_record();
        malformed.reserved_tail_zero[3] = 1;
        assert!(!valid_discovery_record(&malformed));
        for mutate in [
            |value: &mut DiscoveryRecord| value.case_id = 1,
            |value: &mut DiscoveryRecord| value.interface_index = 1,
            |value: &mut DiscoveryRecord| value.name_class = DISCOVERY_NAME_OTHER,
            |value: &mut DiscoveryRecord| value.interface_flags = 1,
            |value: &mut DiscoveryRecord| value.symbol_id = 0,
            |value: &mut DiscoveryRecord| value.announced_count = 1,
        ] {
            let mut value = function_list_record();
            mutate(&mut value);
            assert!(!valid_discovery_record(&value));
        }
        malformed = function_list_record();
        malformed.table_ptr = 0;
        assert!(!valid_discovery_record(&malformed));
        malformed.status_flags = DISCOVERY_STATUS_READ_FAILURE;
        assert!(valid_discovery_record(&malformed));

        malformed = function_list_record();
        malformed.pointers_attempted = 105;
        assert!(!valid_discovery_record(&malformed));
        malformed = function_list_record();
        malformed.pointers_attempted = 1;
        malformed.completed_prefix = 2;
        assert!(!valid_discovery_record(&malformed));
        malformed = function_list_record();
        malformed.pointers_attempted = 1;
        malformed.completed_prefix = 1;
        malformed.usable_n = 2;
        assert!(!valid_discovery_record(&malformed));
        malformed = function_list_record();
        malformed.pointers[1] = 7;
        assert!(!valid_discovery_record(&malformed));
        malformed = function_list_record();
        malformed.status_flags = DISCOVERY_STATUS_READ_FAILURE;
        malformed.usable_n = 1;
        malformed.pointers_attempted = 1;
        malformed.completed_prefix = 1;
        malformed.pointers[0] = 7;
        assert!(!valid_discovery_record(&malformed));

        let mut listed = discovery_record(DISCOVERY_KIND_INTERFACE_LIST_ELEMENT_RETURN);
        listed.symbol_id = 2;
        listed.name_class = DISCOVERY_NAME_OTHER;
        listed.interface_index = 15;
        listed.announced_count = 16;
        listed.interface_flags = 7;
        assert!(valid_discovery_record(&listed));
        listed.interface_index = 16;
        assert!(!valid_discovery_record(&listed));
        listed.interface_index = 15;
        listed.announced_count = 15;
        assert!(!valid_discovery_record(&listed));

        let mut direct = discovery_record(DISCOVERY_KIND_INTERFACE_RETURN);
        direct.symbol_id = 0;
        direct.binding_id = 1;
        direct.case_id = DISCOVERY_NAME_EXACT_STANDARD;
        direct.interface_index = DISCOVERY_VERSION_NULL;
        direct.name_class = DISCOVERY_NAME_NULL;
        direct.interface_flags = 9;
        direct.status_flags = DISCOVERY_STATUS_READ_FAILURE;
        assert!(valid_discovery_record(&direct));
        direct.interface_index = DISCOVERY_VERSION_OTHER + 1;
        assert!(!valid_discovery_record(&direct));
        direct.interface_index = 0;
        direct.announced_count = 1;
        assert!(!valid_discovery_record(&direct));

        let mut loader = discovery_record(DISCOVERY_KIND_LOADER);
        loader.table_ptr = 0x3000;
        loader.case_id = u8::MAX;
        for r_state in 0..=2 {
            loader.announced_count = r_state;
            assert!(valid_discovery_record(&loader));
        }
        loader.announced_count = 3;
        assert!(!valid_discovery_record(&loader));
        loader.announced_count = 0;
        loader.interface_flags = 1;
        assert!(!valid_discovery_record(&loader));

        let mut invalid_loader = discovery_record(DISCOVERY_KIND_LOADER);
        invalid_loader.status_flags = DISCOVERY_STATUS_LOADER_CONTEXT_INVALID;
        assert!(valid_discovery_record(&invalid_loader));
        for mutate in [
            |value: &mut DiscoveryRecord| value.table_ptr = 1,
            |value: &mut DiscoveryRecord| value.case_id = 1,
            |value: &mut DiscoveryRecord| value.announced_count = 1,
            |value: &mut DiscoveryRecord| value.send_signal_rc = 1,
        ] {
            let mut value = invalid_loader;
            mutate(&mut value);
            assert!(!valid_discovery_record(&value));
        }

        let mut exec = discovery_record(DISCOVERY_KIND_EXEC);
        assert!(valid_discovery_record(&exec));
        exec.status_flags = DISCOVERY_STATUS_COALESCED_NO_HELPER;
        exec.send_signal_rc = COALESCED_NO_HELPER_RC;
        assert!(valid_discovery_record(&exec));
        exec.table_ptr = 1;
        assert!(!valid_discovery_record(&exec));

        let mut exit = discovery_record(DISCOVERY_KIND_LEADER_EXIT);
        assert!(valid_discovery_record(&exit));
        exit.status_flags = DISCOVERY_STATUS_COALESCED_NO_HELPER;
        exit.send_signal_rc = COALESCED_NO_HELPER_RC;
        assert!(!valid_discovery_record(&exit));

        assert!(!valid_discovery_record(&discovery_record(0)));
        assert!(!valid_discovery_record(&discovery_record(7)));
    }

    /// Mutation caught: pause can be enabled for a cgroup or without the PID
    /// filter that supplies the exact nonzero generation token.
    #[test]
    fn pause_config_is_pid_only() {
        assert!(valid_config(
            FLAG_PID_FILTER | FLAG_POLICY_ALLOWLISTED | FLAG_PAUSE_ENABLED
        ));
        assert!(!valid_config(
            FLAG_CGROUP_FILTER | FLAG_POLICY_ALLOWLISTED | FLAG_PAUSE_ENABLED
        ));
        assert!(!valid_config(FLAG_PAUSE_ENABLED | FLAG_POLICY_ALLOWLISTED));
    }

    /// Mutation caught: one test-only ring feature accidentally shrinks the
    /// unrelated production event ring.
    #[test]
    fn discovery_ring_feature_changes_only_discovery() {
        #[cfg(not(feature = "small-discovery-ring"))]
        assert_eq!(DISCOVERY_BYTES, 65_536);
        #[cfg(feature = "small-discovery-ring")]
        {
            assert_eq!(DISCOVERY_BYTES, 4_096);
            assert_eq!(RING_BYTES, 262_144);
        }
    }
}

#[cfg(test)]
mod safe_capture {
    use super::*;

    #[test]
    fn mechanism_capture_is_allowed_only_after_ok_or_pending() {
        assert!(return_allows_mechanism(0));
        assert!(return_allows_mechanism(0x204));
        assert!(!return_allows_mechanism(0x7));
        assert!(!return_allows_mechanism(u64::MAX));
    }

    #[test]
    fn function_name_key_is_exact_zero_filled_and_bounded() {
        let expected = FunctionNameKey {
            len: 9,
            bytes: [
                b'C', b'_', b'E', b'n', b'c', b'r', b'y', b'p', b't', 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
                0, 0, 0, 0, 0, 0, 0, 0, 0,
            ],
        };
        assert_eq!(FunctionNameKey::from_bytes(b"C_Encrypt\0"), Some(expected));
        assert_eq!(FunctionNameKey::from_bytes(b"\0").unwrap().len, 0);
        assert_eq!(FunctionNameKey::from_bytes(b"C_Encrypt"), None);
        assert_eq!(
            FunctionNameKey::from_bytes(b"1234567890123456789012345678\0"),
            None
        );
        assert_eq!(core::mem::size_of::<FunctionNameKey>(), 32);
        assert_eq!(core::mem::align_of::<FunctionNameKey>(), 4);
    }

    #[test]
    fn exact_catalog_key_rejects_unknown_name_even_with_a_shared_candidate_id() {
        let exact = FunctionNameKey::from_bytes(b"C_Encrypt\0").unwrap();
        let unknown = FunctionNameKey::from_bytes(b"C_EncryptX\0").unwrap();
        let same_length_unknown = FunctionNameKey::from_bytes(b"C_Encrypu\0").unwrap();
        let catalog = [(exact, 30u32)];

        assert_eq!(
            catalog.iter().find(|(key, _)| *key == exact).map(|x| x.1),
            Some(30)
        );
        assert_eq!(
            catalog.iter().find(|(key, _)| *key == unknown).map(|x| x.1),
            None
        );
        assert_eq!(
            catalog
                .iter()
                .find(|(key, _)| *key == same_length_unknown)
                .map(|x| x.1),
            None
        );
    }

    #[test]
    fn full_width_mechanism_uses_capture_state_not_the_numeric_sentinel() {
        let event = Event {
            mechanism: u64::MAX,
            capture: capture::MECHANISM_VALUE,
            ..Event::default()
        };
        assert_eq!(event.mechanism, u64::MAX);
        assert_eq!(
            event.capture & capture::MECHANISM_MASK,
            capture::MECHANISM_VALUE
        );
    }
}
