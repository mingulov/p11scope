//! SPDX-License-Identifier: GPL-3.0-or-later
//! Shared wire records for positive caller/object Inventory evidence.
//!
//! Caller-use rows retain historical physical-use evidence, not process liveness,
//! call counts or logical publisher attribution. Endpoint records only bind an
//! endpoint to an object. Validation here checks the wire contract; the owner
//! must separately establish map/domain and object membership.

use crate::ImageIdentity;

pub mod entry;

/// A committed physical object; the logical publisher remains unresolved.
pub const ENDPOINT_OBJECT_COMMITTED_PHYSICAL: u32 = 1;
/// Positive physical-use evidence. No other flags are defined.
pub const CALLER_USE_POSITIVE: u32 = 1;
/// Caller-specific evidence is separate from global Inventory usage evidence.
pub const CALLER_EVIDENCE_CELLS: u32 = 4;
pub const CALLER_EVIDENCE_KNOWN_MASK: u64 = 0x0f;

/// CALLER_USE key. Object ID zero and exec ID zero are valid.
#[repr(C)]
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct CallerObjectKey {
    pub image: ImageIdentity,
    pub object_id: u32,
    pub reserved: u32,
}

impl CallerObjectKey {
    /// Reject unavailable identity and unknown wire fields. Native allocation
    /// policy is enforced by the identity domain, not by a key-value sentinel.
    #[inline(always)]
    pub const fn is_valid(self) -> bool {
        self.image.task_cookie != 0 && self.reserved == 0
    }
}

/// One positive physical-use witness for a caller/object pair.
#[repr(C)]
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct CallerObjectUse {
    /// Association timestamp, including zero; not the earliest call time.
    pub recorded_at_ns: u64,
    /// Must be zero while recency is disabled.
    pub recent_bucket: u64,
    pub host_tgid: u32,
    pub witness_endpoint: u32,
    pub flags: u32,
    pub reserved: u32,
}

impl CallerObjectUse {
    /// Validate against the explicit endpoint capacity of this Inventory domain.
    /// The positive flag, rather than a timestamp sentinel, establishes evidence.
    #[inline(always)]
    pub const fn is_valid(self, endpoint_capacity: u32) -> bool {
        self.flags == CALLER_USE_POSITIVE
            && self.recent_bucket == 0
            && self.host_tgid != 0
            && self.witness_endpoint < endpoint_capacity
            && self.reserved == 0
    }
}

/// ENDPOINT_OBJECT cell, published before its immutable endpoint is attached.
/// Class zero is uncommitted only when the entire record is zero. Class one is
/// committed physical object metadata, including object ID zero. All other classes
/// are unsupported and must not be treated as fresh cells or committed objects.
#[repr(C)]
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct EndpointObject {
    pub object_id: u32,
    pub class: u32,
}

impl EndpointObject {
    #[inline(always)]
    pub const fn is_uncommitted(self) -> bool {
        self.object_id == 0 && self.class == 0
    }

    #[inline(always)]
    pub const fn committed_object_id(self) -> Option<u32> {
        if self.class == ENDPOINT_OBJECT_COMMITTED_PHYSICAL {
            Some(self.object_id)
        } else {
            None
        }
    }
}

/// Closed caller-attribution failure categories. These indices and bits must
/// never be folded into global USAGE evidence or interpreted as call counts.
#[repr(u32)]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum CallerEvidence {
    InvalidEndpointObject = 0,
    IdentityUnavailable = 1,
    PairInsertFailure = 2,
    PairIntegrityFailure = 3,
}

impl CallerEvidence {
    #[inline(always)]
    pub const fn counter_index(self) -> u32 {
        self as u32
    }

    #[inline(always)]
    pub const fn sticky_mask(self) -> u64 {
        1 << self.counter_index()
    }

    #[inline(always)]
    pub const fn from_index(index: u32) -> Option<Self> {
        match index {
            0 => Some(Self::InvalidEndpointObject),
            1 => Some(Self::IdentityUnavailable),
            2 => Some(Self::PairInsertFailure),
            3 => Some(Self::PairIntegrityFailure),
            _ => None,
        }
    }
}

#[inline(always)]
pub const fn valid_caller_evidence_mask(bits: u64) -> bool {
    bits & !CALLER_EVIDENCE_KNOWN_MASK == 0
}

// SAFETY: These repr(C) records contain only integers, including ImageIdentity's
// two u64 fields, with no padding. Every bit pattern is representable; callers
// still need the validators above before interpreting records as evidence.
#[cfg(feature = "user")]
unsafe impl aya::Pod for CallerObjectKey {}
#[cfg(feature = "user")]
unsafe impl aya::Pod for CallerObjectUse {}
#[cfg(feature = "user")]
unsafe impl aya::Pod for EndpointObject {}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{ImageIdentity, IMAGE_IDENTITY_TICKET_LIMIT};
    use core::mem::{align_of, offset_of, size_of};

    fn positive_use() -> CallerObjectUse {
        CallerObjectUse {
            recorded_at_ns: 0,
            recent_bucket: 0,
            host_tgid: 17,
            witness_endpoint: 0,
            flags: 1,
            reserved: 0,
        }
    }

    #[test]
    fn wire_layouts_have_exact_sizes_alignments_and_offsets() {
        assert_eq!(size_of::<CallerObjectKey>(), 24);
        assert_eq!(align_of::<CallerObjectKey>(), 8);
        assert_eq!(offset_of!(CallerObjectKey, image), 0);
        assert_eq!(offset_of!(CallerObjectKey, object_id), 16);
        assert_eq!(offset_of!(CallerObjectKey, reserved), 20);

        assert_eq!(size_of::<CallerObjectUse>(), 32);
        assert_eq!(align_of::<CallerObjectUse>(), 8);
        assert_eq!(offset_of!(CallerObjectUse, recorded_at_ns), 0);
        assert_eq!(offset_of!(CallerObjectUse, recent_bucket), 8);
        assert_eq!(offset_of!(CallerObjectUse, host_tgid), 16);
        assert_eq!(offset_of!(CallerObjectUse, witness_endpoint), 20);
        assert_eq!(offset_of!(CallerObjectUse, flags), 24);
        assert_eq!(offset_of!(CallerObjectUse, reserved), 28);

        assert_eq!(size_of::<EndpointObject>(), 8);
        assert_eq!(align_of::<EndpointObject>(), 4);
        assert_eq!(offset_of!(EndpointObject, object_id), 0);
        assert_eq!(offset_of!(EndpointObject, class), 4);

        assert_eq!(size_of::<ImageIdentity>(), 16);
        assert_eq!(offset_of!(ImageIdentity, task_cookie), 0);
        assert_eq!(offset_of!(ImageIdentity, exec_id), 8);
        assert_eq!(IMAGE_IDENTITY_TICKET_LIMIT, 16_384);
    }

    #[test]
    fn key_requires_an_image_but_allows_zero_exec_and_object_ids() {
        assert!(!CallerObjectKey::default().is_valid());
        for task_cookie in [1, 16_384, u64::MAX] {
            for exec_id in [0, 1, u64::MAX] {
                for object_id in [0, 575, u32::MAX] {
                    let key = CallerObjectKey {
                        image: ImageIdentity {
                            task_cookie,
                            exec_id,
                        },
                        object_id,
                        reserved: 0,
                    };
                    assert!(key.is_valid(), "{key:?}");
                    assert!(!CallerObjectKey {
                        image: ImageIdentity {
                            task_cookie: 0,
                            exec_id,
                        },
                        ..key
                    }
                    .is_valid());
                    for bit in 0..32 {
                        assert!(!CallerObjectKey {
                            reserved: 1 << bit,
                            ..key
                        }
                        .is_valid());
                    }
                }
            }
        }
    }

    #[test]
    fn endpoint_zero_cell_and_committed_object_zero_are_distinct() {
        assert_eq!(ENDPOINT_OBJECT_COMMITTED_PHYSICAL, 1);
        let empty = EndpointObject::default();
        assert_eq!(empty.object_id, 0);
        assert_eq!(empty.class, 0);
        assert!(empty.is_uncommitted());
        assert_eq!(empty.committed_object_id(), None);
        for object_id in [0, 575, u32::MAX] {
            let committed = EndpointObject {
                object_id,
                class: 1,
            };
            assert!(!committed.is_uncommitted());
            assert_eq!(committed.committed_object_id(), Some(object_id));
        }
    }

    #[test]
    fn endpoint_classes_and_noncanonical_empty_cells_are_refused() {
        for object_id in [1, 575, u32::MAX] {
            let malformed_empty = EndpointObject {
                object_id,
                class: 0,
            };
            assert!(!malformed_empty.is_uncommitted());
            assert_eq!(malformed_empty.committed_object_id(), None);
        }
        for bit in 1..32 {
            for class in [1 << bit, 1 | (1 << bit)] {
                for object_id in [0, 575, u32::MAX] {
                    let unknown = EndpointObject { object_id, class };
                    assert!(!unknown.is_uncommitted());
                    assert_eq!(unknown.committed_object_id(), None);
                }
            }
        }
    }

    #[test]
    fn explicit_positive_flag_allows_zero_association_timestamp() {
        assert_eq!(CALLER_USE_POSITIVE, 1);
        assert!(!CallerObjectUse::default().is_valid(1));
        for recorded_at_ns in [0, 1, u64::MAX] {
            for host_tgid in [1, u32::MAX] {
                let value = CallerObjectUse {
                    recorded_at_ns,
                    host_tgid,
                    ..positive_use()
                };
                assert!(value.is_valid(1), "{value:?}");
            }
        }
        assert!(!CallerObjectUse {
            host_tgid: 0,
            ..positive_use()
        }
        .is_valid(1));
        assert!(!CallerObjectUse {
            flags: 0,
            ..positive_use()
        }
        .is_valid(1));
    }

    #[test]
    fn use_requires_disabled_recency_zero_reserved_and_exact_flags() {
        let value = positive_use();
        assert!(value.is_valid(1));
        for bit in 0..64 {
            assert!(!CallerObjectUse {
                recent_bucket: 1 << bit,
                ..value
            }
            .is_valid(1));
        }
        for bit in 0..32 {
            assert!(!CallerObjectUse {
                reserved: 1 << bit,
                ..value
            }
            .is_valid(1));
        }
        for bit in 1..32 {
            for flags in [1 << bit, 1 | (1 << bit)] {
                assert!(!CallerObjectUse { flags, ..value }.is_valid(1));
            }
        }
    }

    #[test]
    fn witness_is_bounded_by_the_explicit_capacity_not_legacy_slots() {
        for (witness_endpoint, capacity, expected) in [
            (0, 0, false),
            (0, 1, true),
            (1, 1, false),
            (511, 576, true),
            (512, 576, true),
            (575, 576, true),
            (576, 576, false),
            (u32::MAX - 1, u32::MAX, true),
            (u32::MAX, u32::MAX, false),
        ] {
            assert_eq!(
                CallerObjectUse {
                    witness_endpoint,
                    ..positive_use()
                }
                .is_valid(capacity),
                expected,
                "endpoint={witness_endpoint}, capacity={capacity}"
            );
        }
    }

    #[test]
    fn caller_evidence_has_four_separate_closed_categories() {
        assert_eq!(CALLER_EVIDENCE_CELLS, 4);
        assert_eq!(CALLER_EVIDENCE_KNOWN_MASK, 0x0f);
        for (kind, index, mask) in [
            (CallerEvidence::InvalidEndpointObject, 0, 0x01),
            (CallerEvidence::IdentityUnavailable, 1, 0x02),
            (CallerEvidence::PairInsertFailure, 2, 0x04),
            (CallerEvidence::PairIntegrityFailure, 3, 0x08),
        ] {
            assert_eq!(kind.counter_index(), index);
            assert_eq!(kind.sticky_mask(), mask);
            assert_eq!(CallerEvidence::from_index(index), Some(kind));
        }
        for index in [4, 5, 31, 32, u32::MAX] {
            assert_eq!(CallerEvidence::from_index(index), None);
        }
        for bits in 0..=0x0f {
            assert!(valid_caller_evidence_mask(bits));
            for bit in 4..64 {
                assert!(!valid_caller_evidence_mask(bits | (1 << bit)));
            }
        }
    }

    #[cfg(feature = "user")]
    #[test]
    fn integer_wire_records_are_aya_pod() {
        fn require_pod<T: aya::Pod>() {}
        require_pod::<CallerObjectKey>();
        require_pod::<CallerObjectUse>();
        require_pod::<EndpointObject>();
    }
}
