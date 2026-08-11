//! Types shared verbatim between the BPF programs and userspace. Every
//! type is `#[repr(C)]` with no padding surprises: both sides read the
//! same bytes out of the same map.
#![no_std]

/// Attach slots. One slot per unique {object, file_offset} target, not
/// per function name — aliased names share a slot by construction.
/// 256 covers the 92-entry 3.2 table several times over.
pub const MAX_SLOTS: u32 = 256;

/// Log2 latency buckets: bucket i holds durations in [2^(i-1), 2^i) ns,
/// bucket 0 holds 0ns, bucket 31 is a catch-all for >= 2^30 ns (~1.07s).
pub const LATENCY_BUCKETS: usize = 32;

/// CONFIG map indices.
pub const CFG_FLAGS: u32 = 0;
/// CONFIG flag bits.
pub const FLAG_PID_FILTER: u64 = 1 << 0;
pub const FLAG_CGROUP_FILTER: u64 = 1 << 1;

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
    pub rv: u32,
}

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

/// What a slot's function *is*, semantically. Userspace classifies each
/// slot from the manifest's names and publishes this into SLOT_KIND; the
/// BPF programs switch on it to decide which arguments are safe to read.
/// A plain u32 rather than a Rust enum: it crosses the map boundary, and
/// an unknown value must degrade to "no capture", never to UB.
pub mod fnkind {
    pub const OTHER: u32 = 0;
    /// (hSession, pMechanism) — read mechanism type from arg1.
    pub const INIT_WITH_MECH: u32 = 1;
    /// (slotID, flags, pApp, notify, phSession) — session via arg4 out-pointer.
    pub const OPEN_SESSION: u32 = 2;
    /// (hSession, ...) — session is arg0.
    pub const SESSION_ARG0: u32 = 3;
    /// (hSession, userType, pPin, ulPinLen) — userType from arg1. pPin is
    /// NEVER read, in any mode, at any privilege.
    pub const LOGIN: u32 = 4;
    /// (hSession, pTemplate, ulCount, ...) — session arg0, template arg1,
    /// count arg2. `C_FindObjectsInit`, `C_CreateObject`.
    pub const TEMPLATE_ARG1: u32 = 5;
    /// (hSession, pMechanism, pTemplate, ulCount, ...) — session arg0,
    /// template arg2, count arg3. `C_GenerateKey`.
    pub const TEMPLATE_ARG2: u32 = 6;
}

/// Mechanism parameter shape codes. Userspace maps the registry's shape
/// string to one of these and publishes it into MECH_SHAPE, keyed by
/// mechanism id; only shapes this phase decodes get a non-NONE code, and
/// an absent/unrecognized shape degrades to NONE (decode nothing) — the
/// same "unknown degrades to no capture" contract as `fnkind`.
pub mod shape {
    pub const NONE: u32 = 0;
    pub const RSA_PKCS_PSS: u32 = 1;
    pub const GCM: u32 = 2;
}

/// MECH_SHAPE map capacity. 336 mechanisms are registered upstream today;
/// this covers that several times over.
pub const MAX_MECH_SHAPES: u32 = 1024;

/// Bit positions for policy-allowlisted boolean attributes in attr_bools bitmask.
/// Each bit represents whether that attribute was observed as true.
pub mod attr_bool {
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
    pub const fn bit_for_attr_type(attr_type: u32) -> Option<u32> {
        match attr_type {
            0x01 => Some(0),   // CKA_TOKEN
            0x02 => Some(1),   // CKA_PRIVATE
            0x103 => Some(2),  // CKA_SENSITIVE
            0x104 => Some(3),  // CKA_ENCRYPT
            0x105 => Some(4),  // CKA_DECRYPT
            0x106 => Some(5),  // CKA_WRAP
            0x107 => Some(6),  // CKA_UNWRAP
            0x108 => Some(7),  // CKA_SIGN
            0x10A => Some(8),  // CKA_VERIFY
            0x10C => Some(9),  // CKA_DERIVE
            0x162 => Some(10), // CKA_EXTRACTABLE
            _ => None,
        }
    }
}

/// Sentinels. Zero is a legal PKCS#11 value for some of these, so absence
/// gets its own out-of-band marker.
pub const MECH_NONE: u64 = u64::MAX;
pub const SESSION_NONE: u64 = u64::MAX;
pub const USER_TYPE_NONE: u32 = u32::MAX;

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
#[derive(Clone, Copy)]
pub struct CallStart {
    pub ts_ns: u64,
    pub session: u64,
    pub mechanism: u64,
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
    /// Template attribute *types* only (never values), captured at entry
    /// since `pTemplate` is only guaranteed live then. See `Event` for the
    /// field-by-field meaning; these mirror it verbatim to the return probe.
    pub attr_types: [u32; MAX_ATTRS],
    pub attr_count: u32,
    pub attr_total: u32,
    pub attr_bools: u32,
    pub attr_bools_seen: u32,
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
/// - `GCM`: p0 = ulIvLen, p1 = ulAADLen, p2 = ulTagBits
///
/// For unknown or unhandled shapes, `shape` is `shape::NONE` and the `p*`
/// fields are meaningless.
#[repr(C)]
#[derive(Clone, Copy)]
pub struct Event {
    pub ts_ns: u64,
    pub duration_ns: u64,
    pub pid_tgid: u64,
    pub cgroup_id: u64,
    /// Raw handle. Pseudonymized in userspace; never written to output.
    pub session: u64,
    pub mechanism: u64,
    pub rv: u64,
    pub p0: u64,
    pub p1: u64,
    pub p2: u64,
    pub slot: u32,
    pub kind: u32,
    pub user_type: u32,
    pub shape: u32,
    pub attr_types: [u32; MAX_ATTRS],
    pub attr_count: u32,
    pub attr_total: u32,
    pub attr_bools: u32,
    pub attr_bools_seen: u32,
}

#[cfg(feature = "user")]
unsafe impl aya::Pod for CallStart {}
#[cfg(feature = "user")]
unsafe impl aya::Pod for Event {}

#[cfg(test)]
mod tests {
    use super::*;

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
        // CallStart: 7 u64 + 2 u32 (56 + 8 = 64) + [u32; 8] + 4 u32
        // (32 + 16 = 48) = 112 bytes (no padding needed: 112 % 8 == 0).
        assert_eq!(
            core::mem::size_of::<CallStart>(),
            8 * 7 + 4 * 2 + 4 * MAX_ATTRS + 4 * 4
        );
        // Event: 10 u64 + 4 u32 + [u32; 8] + 4 u32 = 80 + 16 + 32 + 16 = 144 bytes
        assert_eq!(core::mem::size_of::<Event>(), 8 * 10 + 4 * 8 + 32);
        assert_eq!(core::mem::align_of::<Event>(), 8);
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
    fn sentinels_do_not_collide_with_real_values() {
        // CKM_SHA256 = 0x250, CKU_USER = 1, session handles are small.
        assert_ne!(MECH_NONE, 0x250);
        assert_ne!(USER_TYPE_NONE, 1);
        assert_ne!(SESSION_NONE, 0);
    }
}
