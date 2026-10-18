//! SPDX-License-Identifier: GPL-3.0-or-later
//! The initial one-entry std HashMap request on pinned Rust x86-64 Linux.
//! A requested entry is not one allocated bucket: the initial table has four
//! buckets, a control byte per bucket and one 16-byte control group. Round the
//! value area to max(value alignment, group alignment) before its control area.
//! Actual allocator tests below and the real admission-type tests guard this
//! implementation-specific envelope; this is not a portable HashMap promise.

pub(super) fn one_map_request<K, V>() -> Option<usize> {
    let size = std::mem::size_of::<(K, V)>();
    // Smaller items can select a larger minimum table in the pinned allocator.
    if size < 4 {
        return None;
    }
    let alignment = std::mem::align_of::<(K, V)>().max(16);
    let values = size.checked_mul(4)?;
    let controls = values.checked_add(alignment - 1)? & !(alignment - 1);
    controls.checked_add(4 + 16)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashMap;

    fn actual<K: std::hash::Hash + Eq, V>(key: K, value: V) {
        let expected = one_map_request::<K, V>().unwrap();
        let ((mut map, capacity), allocations, bytes) =
            crate::test_alloc::count_allocs_during(|| {
                let map = HashMap::<K, V>::with_capacity(1);
                let capacity = map.capacity();
                (map, capacity)
            });
        assert_eq!(capacity, 3, "one requested entry owns four actual buckets");
        assert_eq!(allocations, 1);
        assert_eq!(bytes, expected);
        let (_, allocations, bytes) = crate::test_alloc::count_allocs_during(|| {
            map.insert(key, value);
        });
        assert_eq!((allocations, bytes), (0, 0));
    }

    #[test]
    fn promotion_capacity_actual_initial_map_layouts() {
        actual(1_u32, 2_usize);
        actual(1_u32, [0_u64; 23]);
        actual(1_u64, [0_u8; 257]);
    }

    #[test]
    fn promotion_capacity_rejects_unproved_tiny_table_layouts() {
        assert_eq!(one_map_request::<(), ()>(), None);
        assert_eq!(one_map_request::<u8, u8>(), None);
    }
}
