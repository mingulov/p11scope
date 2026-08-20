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
/// CONFIG flag bits.
pub const FLAG_PID_FILTER: u64 = 1 << 0;
pub const FLAG_CGROUP_FILTER: u64 = 1 << 1;
pub const FLAG_POLICY_ALLOWLISTED: u64 = 1 << 2;
pub const FLAG_POLICY_UNSAFE_UNVALIDATED_METADATA: u64 = 1 << 3;
pub const FLAG_POLICY_AGGREGATE: u64 = 1 << 4;

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
        | FLAG_POLICY_AGGREGATE;
    matches!(scope, FLAG_PID_FILTER | FLAG_CGROUP_FILTER)
        && matches!(
            policy,
            FLAG_POLICY_ALLOWLISTED
                | FLAG_POLICY_UNSAFE_UNVALIDATED_METADATA
                | FLAG_POLICY_AGGREGATE
        )
        && flags & !known == 0
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
/// 256 KiB holds ~2700 events. The `small-ring` feature (off by default;
/// the default build is unaffected) shrinks this to one page so the
/// induced-gap test (Task 7, `scripts/verify-induced-gaps.sh`) can force
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
    pub _pad: u32,
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
